package tenantops

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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/lifecycle"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/masterkey"
	"github.com/ed-fr/transteira/internal/masterkey/masterkeytest"
	"github.com/ed-fr/transteira/internal/notify"
	"github.com/ed-fr/transteira/internal/storage"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Test values.
const (
	hostA       = "transfer.entity-a.example.com"
	hostB       = "transfer.entity-b.example.com"
	alice       = "alice@entity-a.example.com"
	carol       = "carol@customer.example.net"
	dave        = "dave@partner.example.org"
	missingTen  = tenant.ID("ten_01JAB00000000000000000000Z")
	missingTrf  = "trf_01JAB00000000000000000000Z"
	missingInv  = "inv_01JAB00000000000000000000Z"
	missingBlk  = "blk_01JAB00000000000000000000Z"
	fingerprint = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
)

var (
	testStart = time.Date(2026, time.October, 22, 9, 0, 0, 0, time.UTC)
	clientIP  = netip.MustParseAddr("192.0.2.10")
	errBoom   = errors.New("boom")
)

// fakeClock is a manual clock.
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
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// eraseCall is one call of the fake eraser.
type eraseCall struct {
	tid         tenant.ID
	trfID       string
	mode        lifecycle.EraseMode
	cancellable bool
}

// fakeEraser marks a transfer deleted in the store like the lifecycle
// sweeper would, without files. busy makes that many calls fail with
// lifecycle.ErrBusy first; err makes every call fail.
type fakeEraser struct {
	db    *store.DB
	mu    sync.Mutex
	calls []eraseCall
	busy  int
	err   error
}

func (e *fakeEraser) EraseTransfer(ctx context.Context, tid tenant.ID, trfID string, mode lifecycle.EraseMode) (lifecycle.EraseResult, error) {
	e.mu.Lock()
	e.calls = append(e.calls, eraseCall{tid, trfID, mode, ctx.Done() != nil})
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

func (e *fakeEraser) count() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.calls)
}

// recNotifier delegates to a real notifier and records the links and
// views it was given (perLinks for PerRecipientJobs); err replaces the
// result.
type recNotifier struct {
	inner    Notifier
	mu       sync.Mutex
	links    []string
	perLinks [][]notify.RecipientLink
	views    []notify.TransferView
	err      error
}

func (n *recNotifier) PerRecipientJobs(ctx context.Context, t *tenant.Tenant, tr notify.TransferView, links []notify.RecipientLink) ([]mail.Job, error) {
	n.mu.Lock()
	n.perLinks = append(n.perLinks, links)
	n.views = append(n.views, tr)
	err := n.err
	n.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return n.inner.PerRecipientJobs(ctx, t, tr, links)
}

func (n *recNotifier) RecipientJobs(ctx context.Context, t *tenant.Tenant, tr notify.TransferView, link string) ([]mail.Job, error) {
	n.mu.Lock()
	n.links = append(n.links, link)
	n.views = append(n.views, tr)
	err := n.err
	n.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return n.inner.RecipientJobs(ctx, t, tr, link)
}

// fakeMailer records the queued jobs and their log attributes.
type fakeMailer struct {
	mu    sync.Mutex
	jobs  []mail.Job
	attrs []slog.Attr
}

func (m *fakeMailer) Send(_ context.Context, jobs []mail.Job, attrs ...slog.Attr) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.jobs = append(m.jobs, jobs...)
	m.attrs = append(m.attrs, attrs...)
}

func (m *fakeMailer) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.jobs)
}

// faultRepo wraps a repo and fails the methods named in errs.
type faultRepo struct {
	repo
	errs map[string]error
}

func (f *faultRepo) fail(method string) error { return f.errs[method] }

func (f *faultRepo) getTenant(ctx context.Context, tid tenant.ID) (*tenant.Tenant, error) {
	if err := f.fail("getTenant"); err != nil {
		return nil, err
	}
	return f.repo.getTenant(ctx, tid)
}

func (f *faultRepo) listTransfers(ctx context.Context, tid tenant.ID, fl store.AdminTransferFilter) (store.Page[store.AdminTransfer], error) {
	if err := f.fail("listTransfers"); err != nil {
		return store.Page[store.AdminTransfer]{}, err
	}
	return f.repo.listTransfers(ctx, tid, fl)
}

func (f *faultRepo) getTransfer(ctx context.Context, tid tenant.ID, trfID string) (store.TransferDetails, error) {
	if err := f.fail("getTransfer"); err != nil {
		return store.TransferDetails{}, err
	}
	return f.repo.getTransfer(ctx, tid, trfID)
}

func (f *faultRepo) listInvitations(ctx context.Context, tid tenant.ID, fl store.InvitationFilter) (store.Page[store.Invitation], error) {
	if err := f.fail("listInvitations"); err != nil {
		return store.Page[store.Invitation]{}, err
	}
	return f.repo.listInvitations(ctx, tid, fl)
}

func (f *faultRepo) getInvitation(ctx context.Context, tid tenant.ID, invID string) (store.Invitation, error) {
	if err := f.fail("getInvitation"); err != nil {
		return store.Invitation{}, err
	}
	return f.repo.getInvitation(ctx, tid, invID)
}

func (f *faultRepo) revokeInvitation(ctx context.Context, tid tenant.ID, invID string, now time.Time) error {
	if err := f.fail("revokeInvitation"); err != nil {
		return err
	}
	return f.repo.revokeInvitation(ctx, tid, invID, now)
}

func (f *faultRepo) listBlocklist(ctx context.Context, tid tenant.ID, fl store.BlocklistFilter) (store.Page[store.BlocklistEntry], error) {
	if err := f.fail("listBlocklist"); err != nil {
		return store.Page[store.BlocklistEntry]{}, err
	}
	return f.repo.listBlocklist(ctx, tid, fl)
}

func (f *faultRepo) getBlocklistEntry(ctx context.Context, tid tenant.ID, entryID string) (store.BlocklistEntry, error) {
	if err := f.fail("getBlocklistEntry"); err != nil {
		return store.BlocklistEntry{}, err
	}
	return f.repo.getBlocklistEntry(ctx, tid, entryID)
}

func (f *faultRepo) createBlocklistEntry(ctx context.Context, tid tenant.ID, e store.BlocklistEntry) (store.BlocklistEntry, error) {
	if err := f.fail("createBlocklistEntry"); err != nil {
		return store.BlocklistEntry{}, err
	}
	return f.repo.createBlocklistEntry(ctx, tid, e)
}

func (f *faultRepo) deleteBlocklistEntry(ctx context.Context, tid tenant.ID, entryID string) error {
	if err := f.fail("deleteBlocklistEntry"); err != nil {
		return err
	}
	return f.repo.deleteBlocklistEntry(ctx, tid, entryID)
}

func (f *faultRepo) listAbuseReports(ctx context.Context, tid tenant.ID, status store.AbuseReportStatus, limit int, cursor string) (store.Page[store.AbuseReport], error) {
	if err := f.fail("listAbuseReports"); err != nil {
		return store.Page[store.AbuseReport]{}, err
	}
	return f.repo.listAbuseReports(ctx, tid, status, limit, cursor)
}

func (f *faultRepo) getAbuseReport(ctx context.Context, tid tenant.ID, repID string) (store.AbuseReport, error) {
	if err := f.fail("getAbuseReport"); err != nil {
		return store.AbuseReport{}, err
	}
	return f.repo.getAbuseReport(ctx, tid, repID)
}

func (f *faultRepo) setAbuseReportStatus(ctx context.Context, tid tenant.ID, repID string, status store.AbuseReportStatus, by string, note *string, now time.Time) (store.AbuseReport, bool, error) {
	if err := f.fail("setAbuseReportStatus"); err != nil {
		return store.AbuseReport{}, false, err
	}
	return f.repo.setAbuseReportStatus(ctx, tid, repID, status, by, note, now)
}

// seedReport stores an open abuse report of tenant tn on a fresh transfer.
func (ev *env) seedReport(tn *tenant.Tenant) store.AbuseReport {
	ev.t.Helper()
	trf := ev.seed(tn, store.TransferAvailable, carol)
	r, err := ev.db.AbuseReports().Create(context.Background(), tn.ID, store.AbuseReport{
		TransferID: trf.id, SenderEmail: alice, Category: store.AbuseCategorySpam, Message: "suspicious",
		ReporterIP: clientIP,
	}, store.AbuseReportLimits{PerLinkPerDay: 1000, PerIPPerHour: 1000}, ev.clock.Now())
	if err != nil {
		ev.t.Fatal(err)
	}
	return r
}

func (f *faultRepo) listAudit(ctx context.Context, fl store.AuditFilter) (store.Page[store.AuditEvent], error) {
	if err := f.fail("listAudit"); err != nil {
		return store.Page[store.AuditEvent]{}, err
	}
	return f.repo.listAudit(ctx, fl)
}

func (f *faultRepo) recipientLinks(ctx context.Context, tid tenant.ID, trfID string) ([]store.RecipientLink, error) {
	if err := f.fail("recipientLinks"); err != nil {
		return nil, err
	}
	return f.repo.recipientLinks(ctx, tid, trfID)
}

func (f *faultRepo) tracking(ctx context.Context, tid tenant.ID, trfID string) ([]store.RecipientTracking, error) {
	if err := f.fail("tracking"); err != nil {
		return nil, err
	}
	return f.repo.tracking(ctx, tid, trfID)
}

func (f *faultRepo) openSecret(ctx context.Context, tid tenant.ID, wkID string) ([]byte, error) {
	if err := f.fail("openSecret"); err != nil {
		return nil, err
	}
	return f.repo.openSecret(ctx, tid, wkID)
}

func (f *faultRepo) audit(ctx context.Context, tid tenant.ID, ev audit.Event) error {
	if err := f.fail("audit"); err != nil {
		return err
	}
	return f.repo.audit(ctx, tid, ev)
}

// env is a service over a migrated database with tenants A and B, a super
// admin and a delegated admin of each tenant.
type env struct {
	t        *testing.T
	db       *store.DB
	svc      *Service
	clock    *fakeClock
	vault    *masterkey.Vault
	eraser   *fakeEraser
	notifier *recNotifier
	mailer   *fakeMailer
	logs     *bytes.Buffer
	a, b     *tenant.Tenant
	super    adminauth.Principal
	adminA   adminauth.Principal
	adminB   adminauth.Principal
}

// envOption customizes the options of the service of an env.
type envOption func(*Options)

// newEnv builds an env on engine e. Tenant A has SMTP settings, B none.
func newEnv(t *testing.T, e storetest.Engine, opts ...envOption) *env {
	t.Helper()
	ctx := context.Background()
	clock := &fakeClock{now: testStart}
	db, err := store.Open(ctx, e.Config(), store.WithClock(clock.Now))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	kr, err := masterkey.New(masterkeytest.Key(t, "tenantops"), nil)
	if err != nil {
		t.Fatal(err)
	}
	ev := &env{
		t: t, db: db, clock: clock, vault: masterkey.NewVault(db, kr, nil), eraser: &fakeEraser{db: db},
		mailer: &fakeMailer{}, logs: &bytes.Buffer{},
	}
	ev.notifier = &recNotifier{inner: notify.New(ev.vault, db.SMTPSettings(), nil, notify.Options{Now: clock.Now})}
	o := Options{
		Vault: ev.vault, Eraser: ev.eraser, Notifier: ev.notifier, Mailer: ev.mailer,
		Logger: slog.New(slog.NewTextHandler(ev.logs, nil)), Now: clock.Now, BusyDelay: time.Millisecond,
	}
	for _, f := range opts {
		f(&o)
	}
	ev.svc, err = New(db, o)
	if err != nil {
		t.Fatal(err)
	}
	ev.a = ev.newTenant("Entity A", hostA)
	ev.b = ev.newTenant("Entity B", hostB)
	err = db.SMTPSettings().Put(ctx, ev.a.ID, store.SMTPConfig{
		Host: "smtp-relay", Port: 25, Security: store.SMTPSecurityNone, FromAddress: "noreply@entity-a.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	ev.super = principal(store.RoleSuperAdmin, "root")
	ev.adminA = principal(store.RoleDelegatedAdmin, "alice.admin", ev.a.ID)
	ev.adminB = principal(store.RoleDelegatedAdmin, "bob.admin", ev.b.ID)
	return ev
}

// newTenant creates a tenant directly in the store.
func (ev *env) newTenant(name, fqdn string) *tenant.Tenant {
	ev.t.Helper()
	tn, err := ev.db.Tenants().Create(context.Background(), &tenant.Tenant{
		Name: name, FQDN: fqdn, DefaultLanguage: "en", MaxTransferBytes: 10 << 30, StorageQuotaBytes: 100 << 30,
	})
	if err != nil {
		ev.t.Fatalf("Create(%s): %v", fqdn, err)
	}
	return tn
}

// faults replaces the repo of the service with a faultRepo failing the
// given methods with errBoom.
func (ev *env) faults(methods ...string) *faultRepo {
	inner := ev.svc.repo
	if prev, ok := inner.(*faultRepo); ok {
		inner = prev.repo
	}
	f := &faultRepo{repo: inner, errs: map[string]error{}}
	for _, m := range methods {
		f.errs[m] = errBoom
	}
	ev.svc.repo = f
	return f
}

// seeded is a transfer stored by seed, with its raw download token when
// it became available (seedLinks: the raw token of each recipient link,
// by address).
type seeded struct {
	id     string
	token  string
	tokens map[string]string
}

// seed stores a transfer of tn from alice to the recipients, with two
// files, and brings it to status (uploading, scanning, available,
// expired or deleted). An available transfer has a sealed download token.
func (ev *env) seed(tn *tenant.Tenant, status store.TransferStatus, recipients ...string) seeded {
	ev.t.Helper()
	return ev.seedMode(tn, store.LinkModeShared, status, recipients...)
}

// seedLinks is seed for a transfer with one link per recipient: an
// available one has a sealed token per recipient link.
func (ev *env) seedLinks(tn *tenant.Tenant, status store.TransferStatus, recipients ...string) seeded {
	ev.t.Helper()
	return ev.seedMode(tn, store.LinkModePerRecipient, status, recipients...)
}

// seedMode is seed with the given link mode.
func (ev *env) seedMode(tn *tenant.Tenant, mode store.LinkMode, status store.TransferStatus, recipients ...string) seeded {
	ev.t.Helper()
	ctx := context.Background()
	out := seeded{id: id.New(id.Transfer)}
	sc, err := ev.db.Scoped(tn.ID)
	if err != nil {
		ev.t.Fatal(err)
	}
	now := ev.clock.Now()
	err = sc.Tx(ctx, func(tx *store.ScopedTx) error {
		files := make([]store.TransferFile, 2)
		for i := range files {
			wk, _, err := ev.vault.NewDEKTx(ctx, tx)
			if err != nil {
				return err
			}
			upl, err := id.NewUploadToken()
			if err != nil {
				return err
			}
			sum := sha256.Sum256([]byte{byte(i)})
			files[i] = store.TransferFile{
				ID: id.New(id.File), Name: fmt.Sprintf("plans-%d.pdf", i), Size: 1000, MediaType: "application/pdf",
				DEKKeyID: wk, StorageName: storage.NewName(), UploadID: upl, SHA256: hex.EncodeToString(sum[:]),
				CiphertextSize: 1100, UploadedAt: now,
			}
		}
		files[1].Path = "site-a/2026" // the second file is in a folder
		tr := store.Transfer{
			ID: out.id, SenderEmail: alice, SenderKind: store.DepositorInternal, ExpiryDays: 7,
			Message: "Here are the plans", SenderIP: netip.MustParseAddr("10.10.4.21"), LinkMode: mode,
		}
		trs := ev.db.Transfers()
		if err := trs.CreateTx(ctx, tx, tr, recipients, files); err != nil {
			return err
		}
		if status == store.TransferUploading {
			return nil
		}
		if err := trs.FinalizeTx(ctx, tx, out.id, now); err != nil {
			return err
		}
		if status == store.TransferScanning {
			return nil
		}
		for _, f := range files {
			if err := ev.db.TransferFiles().SetScanResultTx(ctx, tx, f.ID, store.ScanClean, "", now); err != nil {
				return err
			}
		}
		if mode == store.LinkModePerRecipient {
			if err := ev.makeLinks(ctx, tx, out.id, recipients, &out, now); err != nil {
				return err
			}
		} else {
			token, err := id.NewDownloadToken()
			if err != nil {
				return err
			}
			out.token = token
			wk, err := ev.vault.SealTx(ctx, tx, crypto.PurposeSecret, []byte(token))
			if err != nil {
				return err
			}
			hash := sha256.Sum256([]byte(token))
			if err := trs.MarkAvailableTx(ctx, tx, out.id, hash[:], wk, now); err != nil {
				return err
			}
		}
		if status == store.TransferAvailable {
			return nil
		}
		d, err := trs.GetTx(ctx, tx, out.id)
		if err != nil {
			return err
		}
		return endTransfer(ctx, ev.db, tx, d, status)
	})
	if err != nil {
		ev.t.Fatalf("seed %s: %v", status, err)
	}
	return out
}

// makeLinks makes the scanning transfer trfID available with one sealed
// token per recipient, recording the raw tokens in out by address.
func (ev *env) makeLinks(ctx context.Context, tx *store.ScopedTx, trfID string, recipients []string, out *seeded, now time.Time) error {
	tokens := make([]store.LinkToken, len(recipients))
	raw := make(map[string]string, len(recipients))
	for i := range recipients {
		token, err := id.NewDownloadToken()
		if err != nil {
			return err
		}
		wk, err := ev.vault.SealTx(ctx, tx, crypto.PurposeSecret, []byte(token))
		if err != nil {
			return err
		}
		hash := sha256.Sum256([]byte(token))
		tokens[i] = store.LinkToken{Hash: hash[:], KeyID: wk}
		raw[string(hash[:])] = token
	}
	links, err := ev.db.Transfers().MarkAvailableLinksTx(ctx, tx, trfID, tokens, now)
	if err != nil {
		return err
	}
	out.tokens = make(map[string]string, len(links))
	for _, l := range links {
		out.tokens[l.Email] = raw[string(l.TokenHash)]
	}
	return nil
}

// invite stores a pending invitation of dave issued by alice in tn.
func (ev *env) invite(tn *tenant.Tenant) string {
	ev.t.Helper()
	invID := id.New(id.Invitation)
	hash := sha256.Sum256([]byte(invID))
	err := ev.db.Invitations().Create(context.Background(), tn.ID, store.Invitation{
		ID: invID, TokenHash: hash[:], Email: dave, InvitedBy: alice,
	})
	if err != nil {
		ev.t.Fatalf("invite: %v", err)
	}
	return invID
}

// auditEvents returns the audit events of tenant tid with action.
func (ev *env) auditEvents(tid tenant.ID, action audit.Action) []store.AuditEvent {
	ev.t.Helper()
	page, err := ev.db.AuditEvents().List(context.Background(), store.AuditFilter{TenantID: tid, Action: string(action)})
	if err != nil {
		ev.t.Fatal(err)
	}
	return page.Items
}

// details decodes the details of an audit event and checks that they hold
// no mail address.
func (ev *env) details(e store.AuditEvent) map[string]any {
	ev.t.Helper()
	if strings.Contains(string(e.Details), "@") {
		ev.t.Fatalf("audit details hold an address: %s", e.Details)
	}
	var m map[string]any
	if len(e.Details) > 0 {
		if err := json.Unmarshal(e.Details, &m); err != nil {
			ev.t.Fatal(err)
		}
	}
	return m
}

// principal returns an authenticated principal.
func principal(role store.AdminRole, username string, tids ...tenant.ID) adminauth.Principal {
	return adminauth.Principal{
		SessionID: id.New(id.AdminSession), State: store.SessionAuthenticated,
		Admin: adminauth.Account{ID: id.New(id.Admin), Username: username, Role: role, TenantIDs: tids},
	}
}

// unauthenticated returns p in an intermediate login state.
func unauthenticated(p adminauth.Principal) adminauth.Principal {
	p.State = store.SessionTOTPRequired
	return p
}

// wantErr fails unless errors.Is(err, target).
func wantErr(t *testing.T, what string, err, target error) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("%s: got %v, want %v", what, err, target)
	}
}

// wantInvalid fails unless err is an *InvalidError on field.
func wantInvalid(t *testing.T, what string, err error, field string) {
	t.Helper()
	var ie *InvalidError
	if !errors.As(err, &ie) || !errors.Is(err, ErrInvalid) || ie.Field != field || ie.Error() == "" {
		t.Fatalf("%s: got %v, want an invalid %q", what, err, field)
	}
}

// mustNoErr fails on err.
func mustNoErr(t *testing.T, what string, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
}
