package mytransfers

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/lifecycle"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/masterkey"
	"github.com/ed-fr/transteira/internal/masterkey/masterkeytest"
	"github.com/ed-fr/transteira/internal/notify"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/storage"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// The tests that run on every engine are not parallel inside an engine:
// each PostgreSQL engine holds its own connection pool, and make test runs
// every package at once against a server limited to 100 connections.

// Fixed values of the tests. Domains are fictitious.
const (
	hostA     = "transfer.entity-a.example.com"
	hostB     = "transfer.entity-b.example.com"
	hostC     = "transfer.entity-c.example.com"
	alice     = "Alice@Entity-A.example.com" // sender of tenant A, as typed
	aliceNorm = "alice@entity-a.example.com"
	bob       = "bob@entity-a.example.com" // another sender of tenant A
	carol     = "carol@customer.example.net"
	dave      = "dave@customer.example.net"
)

var (
	testStart = time.Date(2026, 10, 20, 9, 30, 0, 0, time.UTC)
	clientIP  = netip.MustParseAddr("203.0.113.7")
	otherIP   = netip.MustParseAddr("198.51.100.9")
	errBoom   = errors.New("injected fault")
)

// fakeClock is a settable clock.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// fakeQueue captures the jobs, after checking that they build; err fails
// Enqueue.
type fakeQueue struct {
	mu   sync.Mutex
	jobs []mail.Job
	err  error
}

func (q *fakeQueue) Enqueue(job mail.Job) error {
	if _, err := mail.Build(job.Settings, job.Message); err != nil {
		return err
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.err != nil {
		return q.err
	}
	q.jobs = append(q.jobs, job)
	return nil
}

func (q *fakeQueue) count() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.jobs)
}

func (q *fakeQueue) last(t testing.TB) mail.Job {
	t.Helper()
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.jobs) == 0 {
		t.Fatal("no mail queued")
	}
	return q.jobs[len(q.jobs)-1]
}

// syncBuffer is a bytes.Buffer safe for concurrent use.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// failingWriter fails every write.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errBoom }

// fakeEraser marks a transfer deleted in the store like the lifecycle
// sweeper would, without files. busy makes that many calls fail with
// lifecycle.ErrBusy first; err makes every call fail.
type fakeEraser struct {
	db    *store.DB
	mu    sync.Mutex
	calls int
	busy  int
	err   error
}

func (e *fakeEraser) EraseTransfer(ctx context.Context, tid tenant.ID, trfID string, mode lifecycle.EraseMode) (lifecycle.EraseResult, error) {
	e.mu.Lock()
	e.calls++
	busy := e.busy > 0
	if busy {
		e.busy--
	}
	err := e.err
	e.mu.Unlock()
	switch {
	case err != nil:
		return 0, err
	case busy:
		return 0, lifecycle.ErrBusy
	case mode != lifecycle.MarkDeleted:
		return 0, fmt.Errorf("unexpected mode %v", mode)
	}
	d, err := e.db.Transfers().Get(ctx, tid, trfID)
	if errors.Is(err, store.ErrNotFound) {
		return 0, fmt.Errorf("%w: %s", lifecycle.ErrNotFound, trfID)
	}
	if err != nil {
		return 0, err
	}
	if d.Status == store.TransferExpired || d.Status == store.TransferDeleted {
		return lifecycle.AlreadyEnded, nil
	}
	sc, err := e.db.Scoped(tid)
	if err != nil {
		return 0, err
	}
	err = sc.Tx(ctx, func(tx *store.ScopedTx) error {
		return endTransfer(ctx, e.db, tx, d, store.TransferDeleted)
	})
	return lifecycle.Erased, err
}

// endTransfer destroys the keys of d (data keys and sealed tokens, of the
// transfer or of its recipient links) and moves it to the terminal status
// to, inside tx.
func endTransfer(ctx context.Context, db *store.DB, tx *store.ScopedTx, d store.TransferDetails, to store.TransferStatus) error {
	if _, err := db.RecipientLinks().DestroyKeysTx(ctx, tx, d.ID); err != nil {
		return err
	}
	keys := []string{d.DownloadTokenKeyID}
	for _, f := range d.Files {
		keys = append(keys, f.DEKKeyID)
	}
	for _, k := range keys {
		if k == "" {
			continue
		}
		if err := db.WrappedKeys().DeleteTx(ctx, tx, k); err != nil {
			return err
		}
	}
	return db.Transfers().SetStatusTx(ctx, tx, d.ID, d.Status, to, time.Now())
}

// fakeFailures is a Failures that is locked when locked is set and
// records the failures.
type fakeFailures struct {
	mu     sync.Mutex
	locked bool
	keys   []string
}

func (f *fakeFailures) Locked(string) (bool, time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.locked, 7 * time.Minute
}

func (f *fakeFailures) Fail(key string) (bool, time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keys = append(f.keys, key)
	return false, 0
}

// faultKeys fails the MACs of the purposes in fail and delegates the
// others.
type faultKeys struct {
	Keys
	fail map[crypto.MACPurpose]bool
}

func (k faultKeys) MAC(p crypto.MACPurpose, parts ...[]byte) ([]byte, error) {
	if k.fail[p] {
		return nil, errBoom
	}
	return k.Keys.MAC(p, parts...)
}

func (k faultKeys) VerifyMAC(p crypto.MACPurpose, mac []byte, parts ...[]byte) (bool, error) {
	if k.fail[p] {
		return false, errBoom
	}
	return k.Keys.VerifyMAC(p, mac, parts...)
}

// failingAudit fails every audit write.
type failingAudit struct{}

func (failingAudit) RecordScoped(context.Context, tenant.ID, audit.Event) error { return errBoom }

// failingNotifier fails every mail build.
type failingNotifier struct{}

func (failingNotifier) MyTransfersLinkJob(context.Context, *tenant.Tenant, string, string, string, time.Duration) (mail.Job, error) {
	return mail.Job{}, errBoom
}

// call is one call recorded by a recRepo: the method and its arguments
// that do not depend on the address (the tenant).
type call struct {
	method string
	tenant tenant.ID
}

// recRepo records the calls of the service to its repo and fails the
// methods listed in errs.
type recRepo struct {
	repo
	mu    sync.Mutex
	calls []call
	errs  map[string]error
}

func (r *recRepo) note(method string, tid tenant.ID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, call{method, tid})
	return r.errs[method]
}

func (r *recRepo) recorded() []call {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]call(nil), r.calls...)
}

func (r *recRepo) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = nil
}

func (r *recRepo) smtp(ctx context.Context, tid tenant.ID) (store.SMTPConfig, error) {
	if err := r.note("smtp", tid); err != nil {
		return store.SMTPConfig{}, err
	}
	return r.repo.smtp(ctx, tid)
}

func (r *recRepo) recordRequest(ctx context.Context, tid tenant.ID, mac []byte, ip netip.Addr, now time.Time) (store.AccessRequestCounts, error) {
	if err := r.note("recordRequest", tid); err != nil {
		return store.AccessRequestCounts{}, err
	}
	return r.repo.recordRequest(ctx, tid, mac, ip, now)
}

func (r *recRepo) verified(ctx context.Context, tid tenant.ID, email string) (store.VerifiedAddress, error) {
	if err := r.note("verified", tid); err != nil {
		return store.VerifiedAddress{}, err
	}
	return r.repo.verified(ctx, tid, email)
}

func (r *recRepo) blocked(ctx context.Context, tid tenant.ID, email string) (bool, error) {
	if err := r.note("blocked", tid); err != nil {
		return false, err
	}
	return r.repo.blocked(ctx, tid, email)
}

func (r *recRepo) createLink(ctx context.Context, tid tenant.ID, hash []byte, email string, now, exp time.Time) (store.SenderAccessLink, error) {
	if err := r.note("createLink", tid); err != nil {
		return store.SenderAccessLink{}, err
	}
	return r.repo.createLink(ctx, tid, hash, email, now, exp)
}

func (r *recRepo) openSession(ctx context.Context, tid tenant.ID, linkHash, sessionHash []byte, now, exp time.Time) (store.SenderSession, error) {
	if err := r.note("openSession", tid); err != nil {
		return store.SenderSession{}, err
	}
	return r.repo.openSession(ctx, tid, linkHash, sessionHash, now, exp)
}

func (r *recRepo) session(ctx context.Context, tid tenant.ID, hash []byte, now time.Time) (store.SenderSession, error) {
	if err := r.note("session", tid); err != nil {
		return store.SenderSession{}, err
	}
	return r.repo.session(ctx, tid, hash, now)
}

func (r *recRepo) endSession(ctx context.Context, tid tenant.ID, hash []byte, now time.Time) error {
	if err := r.note("endSession", tid); err != nil {
		return err
	}
	return r.repo.endSession(ctx, tid, hash, now)
}

func (r *recRepo) list(ctx context.Context, tid tenant.ID, email, cursor string, limit int) (store.Page[store.SenderTransfer], error) {
	if err := r.note("list", tid); err != nil {
		return store.Page[store.SenderTransfer]{}, err
	}
	return r.repo.list(ctx, tid, email, cursor, limit)
}

func (r *recRepo) get(ctx context.Context, tid tenant.ID, trfID, email string) (store.SenderTransferDetail, error) {
	if err := r.note("get", tid); err != nil {
		return store.SenderTransferDetail{}, err
	}
	return r.repo.get(ctx, tid, trfID, email)
}

func (r *recRepo) status(ctx context.Context, tid tenant.ID, trfID, email string) (store.TransferStatus, error) {
	if err := r.note("status", tid); err != nil {
		return "", err
	}
	return r.repo.status(ctx, tid, trfID, email)
}

func (r *recRepo) extend(ctx context.Context, tid tenant.ID, trfID, email string, now time.Time,
	check func(store.SenderTransferDetail) (time.Time, error),
) (store.TransferExtension, store.SenderTransferDetail, error) {
	if err := r.note("extend", tid); err != nil {
		return store.TransferExtension{}, store.SenderTransferDetail{}, err
	}
	return r.repo.extend(ctx, tid, trfID, email, now, check)
}

// env is a service over a migrated database with tenants A and B (SMTP
// relays) and C (no SMTP settings).
type env struct {
	t       testing.TB
	db      *store.DB
	svc     *Service
	repo    *recRepo
	clock   *fakeClock
	queue   *fakeQueue
	seclog  *syncBuffer
	logs    *syncBuffer
	vault   *masterkey.Vault
	keys    *masterkey.Keyring
	eraser  *fakeEraser
	a, b, c *tenant.Tenant
}

// envOption customizes the options of the service of an env.
type envOption func(*Options)

// newEnv builds an env on engine e. The workers are not started: the tests
// run the queued requests with drain.
func newEnv(t testing.TB, e storetest.Engine, opts ...envOption) *env {
	t.Helper()
	ctx := t.Context()
	clock := &fakeClock{now: testStart}
	db, err := store.Open(ctx, e.Config(), store.WithClock(clock.Now))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	kr, err := masterkey.New(masterkeytest.Key(t, "mytransfers"), nil)
	if err != nil {
		t.Fatal(err)
	}
	ev := &env{
		t: t, db: db, clock: clock, queue: &fakeQueue{}, seclog: &syncBuffer{}, logs: &syncBuffer{},
		vault: masterkey.NewVault(db, kr, nil), keys: kr, eraser: &fakeEraser{db: db},
	}
	o := Options{
		Now: clock.Now, Logger: slog.New(slog.NewTextHandler(ev.logs, nil)), Audit: audit.New(db),
		BusyDelay: time.Millisecond,
	}
	for _, f := range opts {
		f(&o)
	}
	ev.svc, err = New(Deps{
		DB: db, Keys: kr, Notifier: notify.New(ev.vault, db.SMTPSettings(), nil, notify.Options{Now: clock.Now}),
		Mail: ev.queue, SecurityLog: securitylog.New(ev.seclog), Eraser: ev.eraser,
	}, o)
	if err != nil {
		t.Fatal(err)
	}
	ev.repo = &recRepo{repo: ev.svc.repo, errs: map[string]error{}}
	ev.svc.repo = ev.repo
	ev.a = ev.newTenant(hostA, "en")
	ev.b = ev.newTenant(hostB, "fr")
	ev.c = ev.newTenant(hostC, "en")
	for _, tn := range []*tenant.Tenant{ev.a, ev.b} {
		err := db.SMTPSettings().Put(ctx, tn.ID, store.SMTPConfig{
			Host: "smtp-relay", Port: 25, Security: store.SMTPSecurityNone, FromAddress: "noreply@" + strings.TrimPrefix(tn.FQDN, "transfer."),
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return ev
}

// newTenant creates a tenant directly in the store.
func (ev *env) newTenant(fqdn, lang string) *tenant.Tenant {
	ev.t.Helper()
	tn, err := ev.db.Tenants().Create(ev.t.Context(), &tenant.Tenant{
		Name: "Entity " + fqdn, FQDN: fqdn, DefaultLanguage: lang, MaxTransferBytes: 10 << 30, StorageQuotaBytes: 100 << 30,
	})
	if err != nil {
		ev.t.Fatalf("Create(%s): %v", fqdn, err)
	}
	return tn
}

// fail makes the repo methods fail with errBoom.
func (ev *env) fail(methods ...string) {
	for _, m := range methods {
		ev.repo.errs[m] = errBoom
	}
}

// verify stores email as verified in tn, last used now.
func (ev *env) verify(tn *tenant.Tenant, email string) {
	ev.t.Helper()
	sc, err := ev.db.Scoped(tn.ID)
	if err != nil {
		ev.t.Fatal(err)
	}
	now := ev.clock.Now()
	err = sc.Tx(ev.t.Context(), func(tx *store.ScopedTx) error {
		_, err := ev.db.VerifiedAddresses().UpsertTx(ev.t.Context(), tx, store.VerifiedAddress{
			Email: email, FirstVerifiedAt: now, FirstVerifiedIP: clientIP, LastUsedAt: now,
		})
		return err
	})
	if err != nil {
		ev.t.Fatalf("verify: %v", err)
	}
}

// drain processes the queued requests synchronously, as a worker would.
func (ev *env) drain() {
	for {
		select {
		case j := <-ev.svc.jobs:
			ev.svc.process(ev.t.Context(), j)
		default:
			return
		}
	}
}

var linkRe = regexp.MustCompile(`https://([a-z0-9.-]+)/me#(mta_[A-Za-z0-9]+)`)

// mustLink asks for a link for email in tn, processes it and returns the
// token of the mail.
func (ev *env) mustLink(tn *tenant.Tenant, email string) string {
	ev.t.Helper()
	before := ev.queue.count()
	if err := ev.svc.RequestLink(ev.t.Context(), tn, clientIP, "", email, ""); err != nil {
		ev.t.Fatalf("RequestLink: %v", err)
	}
	ev.drain()
	if ev.queue.count() != before+1 {
		ev.t.Fatal("no access link mail queued")
	}
	m := linkRe.FindStringSubmatch(ev.queue.last(ev.t).Message.Text)
	if m == nil || m[1] != tn.FQDN {
		ev.t.Fatal("no access link of the tenant in the mail")
	}
	return m[2]
}

// mustSession opens a session for email in tn through a mailed link.
func (ev *env) mustSession(tn *tenant.Tenant, email string) Session {
	ev.t.Helper()
	ev.verify(tn, email)
	s, err := ev.svc.StartSession(ev.t.Context(), tn, clientIP, ev.mustLink(tn, email))
	if err != nil {
		ev.t.Fatalf("StartSession: %v", err)
	}
	return s
}

// seedOptions shape a seeded transfer.
type seedOptions struct {
	sender       string
	status       store.TransferStatus
	perRecipient bool
	rules        *store.ConfidentialityRules
	maxDownloads *int
	deleteAfter  bool
	apiToken     bool
	created      time.Time
}

// seed stores a transfer of tn with one file to carol and dave, brought to
// o.status (uploading, scanning, available, expired or deleted) at the
// clock time, and returns its identifier.
func (ev *env) seed(tn *tenant.Tenant, o seedOptions) string {
	ev.t.Helper()
	ctx := ev.t.Context()
	if o.sender == "" {
		o.sender = alice
	}
	if o.status == "" {
		o.status = store.TransferAvailable
	}
	trfID := id.New(id.Transfer)
	sc, err := ev.db.Scoped(tn.ID)
	if err != nil {
		ev.t.Fatal(err)
	}
	now := ev.clock.Now()
	tokenID := ""
	if o.apiToken {
		tok, err := ev.db.APITokens().Create(ctx, tn.ID, store.APIToken{
			ID: id.New(id.APIToken), Name: "script", Prefix: "tt_AbCd", TokenHash: tokenHash(trfID), CreatedBy: "admin",
			AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
		})
		if err != nil {
			ev.t.Fatal(err)
		}
		tokenID = tok.ID
	}
	err = sc.Tx(ctx, func(tx *store.ScopedTx) error {
		wk, _, err := ev.vault.NewDEKTx(ctx, tx)
		if err != nil {
			return err
		}
		upl, err := id.NewUploadToken()
		if err != nil {
			return err
		}
		sum := sha256.Sum256([]byte(trfID))
		file := store.TransferFile{
			ID: id.New(id.File), Name: "plans.pdf", Size: 1000, MediaType: "application/pdf",
			DEKKeyID: wk, StorageName: storage.NewName(), UploadID: upl, SHA256: hex.EncodeToString(sum[:]),
			CiphertextSize: 1100, UploadedAt: now,
		}
		tr := store.Transfer{
			ID: trfID, SenderEmail: o.sender, SenderKind: store.DepositorInternal, ExpiryDays: 7, Language: "fr",
			Message: "Here are the plans", LinkMode: store.LinkModeShared, MaxDownloads: o.maxDownloads,
			DeleteAfterFirstDownload: o.deleteAfter, CreatedAt: o.created,
		}
		if o.rules != nil {
			tr.ConfidentialityLevel, tr.Rules = "secret", o.rules
			tr.ConfidentialityLabel = map[string]string{"fr": "Secret FR", "en": "Secret EN"}
		}
		if o.perRecipient {
			tr.LinkMode = store.LinkModePerRecipient
		}
		tr.APITokenID = tokenID
		trs := ev.db.Transfers()
		if err := trs.CreateTx(ctx, tx, tr, []string{carol, dave}, []store.TransferFile{file}); err != nil {
			return err
		}
		if o.status == store.TransferUploading {
			return nil
		}
		if err := trs.FinalizeTx(ctx, tx, trfID, now); err != nil {
			return err
		}
		if o.status == store.TransferScanning {
			return nil
		}
		if err := ev.db.TransferFiles().SetScanResultTx(ctx, tx, file.ID, store.ScanClean, "", now); err != nil {
			return err
		}
		if o.perRecipient {
			tokens := make([]store.LinkToken, 2)
			for i := range tokens {
				raw, err := id.NewDownloadToken()
				if err != nil {
					return err
				}
				wk, err := ev.vault.SealTx(ctx, tx, crypto.PurposeSecret, []byte(raw))
				if err != nil {
					return err
				}
				tokens[i] = store.LinkToken{Hash: tokenHash(raw), KeyID: wk}
			}
			if _, err := trs.MarkAvailableLinksTx(ctx, tx, trfID, tokens, now); err != nil {
				return err
			}
		} else {
			raw, err := id.NewDownloadToken()
			if err != nil {
				return err
			}
			wk, err := ev.vault.SealTx(ctx, tx, crypto.PurposeSecret, []byte(raw))
			if err != nil {
				return err
			}
			if err := trs.MarkAvailableTx(ctx, tx, trfID, tokenHash(raw), wk, now); err != nil {
				return err
			}
		}
		if o.status == store.TransferAvailable {
			return nil
		}
		d, err := trs.GetTx(ctx, tx, trfID)
		if err != nil {
			return err
		}
		return endTransfer(ctx, ev.db, tx, d, o.status)
	})
	if err != nil {
		ev.t.Fatalf("seed: %v", err)
	}
	return trfID
}

// transfer reads a transfer of tn whatever its status.
func (ev *env) transfer(tn *tenant.Tenant, trfID string) store.TransferDetails {
	ev.t.Helper()
	d, err := ev.db.Transfers().Get(ev.t.Context(), tn.ID, trfID)
	if err != nil {
		ev.t.Fatal(err)
	}
	return d
}

// auditEvents returns the audit events of tid with action.
func (ev *env) auditEvents(tid tenant.ID, action audit.Action) []store.AuditEvent {
	ev.t.Helper()
	page, err := ev.db.AuditEvents().List(ev.t.Context(), store.AuditFilter{
		TenantID: tid, Action: string(action), Limit: store.MaxPageSize,
	})
	if err != nil {
		ev.t.Fatal(err)
	}
	return page.Items
}

// details decodes the details of an audit event.
func details(t *testing.T, e store.AuditEvent) map[string]any {
	t.Helper()
	var m map[string]any
	if len(e.Details) == 0 {
		return m
	}
	if err := json.Unmarshal(e.Details, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// logLines returns the security log lines containing event.
func (ev *env) logLines(event string) []string {
	var out []string
	for _, l := range strings.Split(ev.seclog.String(), "\n") {
		if strings.Contains(l, "event="+event) {
			out = append(out, l)
		}
	}
	return out
}

// wantErr fails unless errors.Is(err, target).
func wantErr(t *testing.T, what string, err, target error) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Errorf("%s: err = %v, want %v", what, err, target)
	}
}

// wantInvalid fails unless err is an *InvalidError on field.
func wantInvalid(t *testing.T, what string, err error, field string) {
	t.Helper()
	var ie *InvalidError
	if !errors.As(err, &ie) || ie.Field != field || !errors.Is(err, ErrInvalid) {
		t.Errorf("%s: err = %v, want invalid %s", what, err, field)
	}
}
