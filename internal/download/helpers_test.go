package download

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/id"
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

// The tests that run on every engine are deliberately not parallel: each
// PostgreSQL engine holds its own connection pool, and make test runs every
// package at once against a server limited to 100 connections.

// Fixed values of the tests. Domains are fictitious.
const (
	hostA    = "transfer.entity-a.example.com"
	hostB    = "transfer.entity-b.example.com"
	hostC    = "transfer.entity-c.example.com"
	alice    = "alice@entity-a.example.com" // sender
	dave     = "dave@customer.example.net"  // recipient
	password = "correct horse battery staple"
	grace    = 15 * time.Minute
	waitFor  = 10 * time.Second
)

var (
	errFault = errors.New("injected fault")
	ipOne    = netip.MustParseAddr("198.51.100.23")
	ipTwo    = netip.MustParseAddr("203.0.113.7")
	ipThree  = netip.MustParseAddr("192.0.2.44")
)

// passwordHash is the argon2id hash of password, computed once.
var passwordHash = sync.OnceValue(func() string {
	h, err := crypto.HashPassword([]byte(password))
	if err != nil {
		panic(err)
	}
	return h
})

// clock is a settable fake clock.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// faults fails named operations: count[name] times (forever when
// negative) with err[name], and runs hook[name] once at the next call.
type faults struct {
	mu    sync.Mutex
	count map[string]int
	err   map[string]error
	hook  map[string]func()
	calls map[string]int
}

func newFaults() *faults {
	return &faults{count: map[string]int{}, err: map[string]error{}, hook: map[string]func(){}, calls: map[string]int{}}
}

// set makes name fail n times (forever when n < 0) with err (errFault when
// nil).
func (f *faults) set(name string, n int, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err == nil {
		err = errFault
	}
	f.count[name], f.err[name] = n, err
}

func (f *faults) hit(name string) error {
	f.mu.Lock()
	f.calls[name]++
	hook := f.hook[name]
	delete(f.hook, name)
	f.mu.Unlock()
	if hook != nil {
		hook()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	n := f.count[name]
	if n == 0 {
		return nil
	}
	if n > 0 {
		f.count[name] = n - 1
	}
	return f.err[name]
}

func (f *faults) called(name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[name]
}

// faultRepo wraps a repo with faults.
type faultRepo struct {
	inner repo
	f     *faults
}

func (r faultRepo) byToken(ctx context.Context, tid tenant.ID, hash []byte) (store.TransferDetails, error) {
	if err := r.f.hit("byToken"); err != nil {
		return store.TransferDetails{}, err
	}
	return r.inner.byToken(ctx, tid, hash)
}

func (r faultRepo) reserve(ctx context.Context, tid tenant.ID, keys []store.FailureKey, now time.Time) (time.Time, store.FailureOutcome, error) {
	if err := r.f.hit("reserve"); err != nil {
		return time.Time{}, store.FailureOutcome{}, err
	}
	return r.inner.reserve(ctx, tid, keys, now)
}

func (r faultRepo) unlocked(ctx context.Context, tid tenant.ID, trf, ip store.FailureKey, at time.Time) error {
	if err := r.f.hit("unlocked"); err != nil {
		return err
	}
	return r.inner.unlocked(ctx, tid, trf, ip, at)
}

func (r faultRepo) refund(ctx context.Context, tid tenant.ID, keys []store.FailureKey, at time.Time) error {
	if err := r.f.hit("refund"); err != nil {
		return err
	}
	return r.inner.refund(ctx, tid, keys, at)
}

func (r faultRepo) transfer(ctx context.Context, tid tenant.ID, trfID string) (store.TransferDetails, error) {
	if err := r.f.hit("transfer"); err != nil {
		return store.TransferDetails{}, err
	}
	return r.inner.transfer(ctx, tid, trfID)
}

func (r faultRepo) markFirst(ctx context.Context, tid tenant.ID, trfID string, now, deleteAfter time.Time) (bool, error) {
	if err := r.f.hit("markFirst"); err != nil {
		return false, err
	}
	return r.inner.markFirst(ctx, tid, trfID, now, deleteAfter)
}

func (r faultRepo) started(ctx context.Context, tid tenant.ID, trfID, linkID, item string, now time.Time, ev audit.Event) error {
	if err := r.f.hit("started"); err != nil {
		return err
	}
	return r.inner.started(ctx, tid, trfID, linkID, item, now, ev)
}

func (r faultRepo) claim(ctx context.Context, tid tenant.ID, trfID, linkID, item string, now, deleteAfter time.Time, ev audit.Event) (int, error) {
	if err := r.f.hit("claim"); err != nil {
		return 0, err
	}
	return r.inner.claim(ctx, tid, trfID, linkID, item, now, deleteAfter, ev)
}

func (r faultRepo) linkByToken(ctx context.Context, tid tenant.ID, hash []byte) (store.RecipientLink, error) {
	if err := r.f.hit("linkByToken"); err != nil {
		return store.RecipientLink{}, err
	}
	return r.inner.linkByToken(ctx, tid, hash)
}

func (r faultRepo) link(ctx context.Context, tid tenant.ID, linkID string) (store.RecipientLink, error) {
	if err := r.f.hit("link"); err != nil {
		return store.RecipientLink{}, err
	}
	return r.inner.link(ctx, tid, linkID)
}

func (r faultRepo) completeItem(ctx context.Context, tid tenant.ID, linkID, item string, now time.Time) error {
	if err := r.f.hit("completeItem"); err != nil {
		return err
	}
	return r.inner.completeItem(ctx, tid, linkID, item, now)
}

func (r faultRepo) completeLink(ctx context.Context, tid tenant.ID, trfID, linkID string, now, deleteAfter time.Time) (bool, error) {
	if err := r.f.hit("completeLink"); err != nil {
		return false, err
	}
	return r.inner.completeLink(ctx, tid, trfID, linkID, now, deleteAfter)
}

func (r faultRepo) latestChallenge(ctx context.Context, tid tenant.ID, linkID string) (store.Challenge, error) {
	if err := r.f.hit("latestChallenge"); err != nil {
		return store.Challenge{}, err
	}
	return r.inner.latestChallenge(ctx, tid, linkID)
}

func (r faultRepo) createChallenge(ctx context.Context, tid tenant.ID, ch store.Challenge, since time.Time) (string, error) {
	if err := r.f.hit("createChallenge"); err != nil {
		return "", err
	}
	return r.inner.createChallenge(ctx, tid, ch, since)
}

func (r faultRepo) deleteChallenge(ctx context.Context, tid tenant.ID, chID string) error {
	if err := r.f.hit("deleteChallenge"); err != nil {
		return err
	}
	return r.inner.deleteChallenge(ctx, tid, chID)
}

func (r faultRepo) spend(ctx context.Context, tid tenant.ID, chID string, now time.Time) (int, error) {
	if err := r.f.hit("spend"); err != nil {
		return 0, err
	}
	return r.inner.spend(ctx, tid, chID, now)
}

func (r faultRepo) verified(ctx context.Context, tid tenant.ID, chID, linkID string, now time.Time, ev audit.Event) error {
	if err := r.f.hit("verified"); err != nil {
		return err
	}
	return r.inner.verified(ctx, tid, chID, linkID, now, ev)
}

// faultVault wraps the vault with the fault "open".
type faultVault struct {
	inner *masterkey.Vault
	f     *faults
}

func (v faultVault) Open(ctx context.Context, tid tenant.ID, p crypto.Purpose, wkID string) ([]byte, error) {
	if err := v.f.hit("open"); err != nil {
		return nil, err
	}
	return v.inner.Open(ctx, tid, p, wkID)
}

// faultFiles wraps the storage with the faults "openRead", "readState",
// "writeState" and "removeState".
type faultFiles struct {
	inner *storage.Store
	f     *faults
}

func (s faultFiles) OpenRead(tid tenant.ID, name string) (*os.File, int64, error) {
	if err := s.f.hit("openRead"); err != nil {
		return nil, 0, err
	}
	return s.inner.OpenRead(tid, name)
}

func (s faultFiles) ReadState(tid tenant.ID, name string) ([]byte, error) {
	if err := s.f.hit("readState"); err != nil {
		return nil, err
	}
	return s.inner.ReadState(tid, name)
}

func (s faultFiles) WriteState(tid tenant.ID, name string, data []byte) error {
	if err := s.f.hit("writeState"); err != nil {
		return err
	}
	return s.inner.WriteState(tid, name, data)
}

func (s faultFiles) RemoveState(tid tenant.ID, name string) error {
	if err := s.f.hit("removeState"); err != nil {
		return err
	}
	return s.inner.RemoveState(tid, name)
}

// faultKeys wraps the keyring with the faults "mac" and "verifyMAC".
type faultKeys struct {
	inner Keys
	f     *faults
}

func (k faultKeys) MAC(p crypto.MACPurpose, parts ...[]byte) ([]byte, error) {
	if err := k.f.hit("mac"); err != nil {
		return nil, err
	}
	return k.inner.MAC(p, parts...)
}

func (k faultKeys) VerifyMAC(p crypto.MACPurpose, mac []byte, parts ...[]byte) (bool, error) {
	if err := k.f.hit("verifyMAC"); err != nil {
		return false, err
	}
	return k.inner.VerifyMAC(p, mac, parts...)
}

// faultVerifier wraps the hasher with the fault "verify"; calls counts the
// password hashings.
type faultVerifier struct {
	inner *crypto.PasswordHasher
	f     *faults
}

func (v faultVerifier) VerifyPassword(ctx context.Context, encoded string, pw []byte) (bool, error) {
	if err := v.f.hit("verify"); err != nil {
		return false, err
	}
	return v.inner.VerifyPassword(ctx, encoded, pw)
}

// faultNotifier wraps the notifier with the faults "firstDownload" and
// "codeMail", and records the deletion times, the recipients named by the
// first download mails and the codes it was given.
type faultNotifier struct {
	inner *notify.Notifier
	f     *faults

	mu         sync.Mutex
	deleteAts  []time.Time
	recipients []string
	codes      []string
}

func (n *faultNotifier) FirstDownloadBy(ctx context.Context, t *tenant.Tenant, tr notify.TransferView, at, d time.Time, recipient string) (mail.Job, error) {
	n.mu.Lock()
	n.deleteAts = append(n.deleteAts, d)
	n.recipients = append(n.recipients, recipient)
	n.mu.Unlock()
	if err := n.f.hit("firstDownload"); err != nil {
		return mail.Job{}, err
	}
	return n.inner.FirstDownloadBy(ctx, t, tr, at, d, recipient)
}

func (n *faultNotifier) RecipientVerificationCode(ctx context.Context, t *tenant.Tenant, tr notify.TransferView, to, code string) (mail.Job, error) {
	n.mu.Lock()
	n.codes = append(n.codes, code)
	n.mu.Unlock()
	if err := n.f.hit("codeMail"); err != nil {
		return mail.Job{}, err
	}
	return n.inner.RecipientVerificationCode(ctx, t, tr, to, code)
}

// lastCode returns the last code mailed.
func (n *faultNotifier) lastCode(t *testing.T) string {
	t.Helper()
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.codes) == 0 {
		t.Fatal("no code mailed")
	}
	return n.codes[len(n.codes)-1]
}

// fakeQueue captures the jobs; errs are returned by the next Enqueue
// calls, in order.
type fakeQueue struct {
	mu   sync.Mutex
	jobs []mail.Job
	errs []error
}

func (q *fakeQueue) Enqueue(j mail.Job) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.errs) > 0 {
		err := q.errs[0]
		q.errs = q.errs[1:]
		if err != nil {
			return err
		}
	}
	q.jobs = append(q.jobs, j)
	return nil
}

func (q *fakeQueue) snapshot() []mail.Job {
	q.mu.Lock()
	defer q.mu.Unlock()
	return slices.Clone(q.jobs)
}

// fakeSeclog captures the security events; err is returned by Log.
type fakeSeclog struct {
	mu     sync.Mutex
	events []securitylog.Event
	err    error
}

func (l *fakeSeclog) Log(ev securitylog.Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, ev)
	return l.err
}

// count returns the number of events of type typ.
func (l *fakeSeclog) count(typ securitylog.EventType) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, e := range l.events {
		if e.Type == typ {
			n++
		}
	}
	return n
}

func (l *fakeSeclog) all() []securitylog.Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.events)
}

// logCapture is a slog handler keeping every record as text.
type logCapture struct {
	mu      sync.Mutex
	records []string
}

func (h *logCapture) Enabled(context.Context, slog.Level) bool { return true }
func (h *logCapture) WithAttrs([]slog.Attr) slog.Handler       { return h }
func (h *logCapture) WithGroup(string) slog.Handler            { return h }

func (h *logCapture) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	b.WriteString(r.Level.String() + " " + r.Message)
	r.Attrs(func(a slog.Attr) bool {
		fmt.Fprintf(&b, " %s=%v", a.Key, a.Value)
		return true
	})
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, b.String())
	return nil
}

// count returns the number of records containing msg.
func (h *logCapture) count(msg string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, r := range h.records {
		if strings.Contains(r, msg) {
			n++
		}
	}
	return n
}

func (h *logCapture) all() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return strings.Join(h.records, "\n")
}

// env is a service over a migrated database with tenants A and B (with
// SMTP settings) and C (without), real storage and keys, a fake clock, a
// fake mail queue and a fake security log.
type env struct {
	t        *testing.T
	db       *store.DB
	vault    *masterkey.Vault
	keyring  *masterkey.Keyring
	files    *storage.Store
	queue    *fakeQueue
	seclog   *fakeSeclog
	logs     *logCapture
	f        *faults
	clock    *clock
	notifier *faultNotifier
	usage    *fakeUsage
	svc      *Service
	a, b, c  *tenant.Tenant
	// secrets are the tokens and file names that must never be logged.
	secrets []string
}

// newEnv builds an env on engine e; tune adjusts the options.
func newEnv(t *testing.T, e storetest.Engine, tune func(*Options)) *env {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, e.Config())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	kr, err := masterkey.New(masterkeytest.Key(t, "download"), nil)
	if err != nil {
		t.Fatal(err)
	}
	vault := masterkey.NewVault(db, kr, nil)
	files, err := storage.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = files.Close() })
	ev := &env{
		t: t, db: db, vault: vault, keyring: kr, files: files, queue: &fakeQueue{}, seclog: &fakeSeclog{},
		logs: &logCapture{}, f: newFaults(), usage: &fakeUsage{},
		clock: &clock{t: time.Now().UTC().Truncate(time.Millisecond)},
	}
	ev.a = ev.newTenant(hostA, true)
	ev.b = ev.newTenant(hostB, true)
	ev.c = ev.newTenant(hostC, false)
	ev.notifier = &faultNotifier{inner: notify.New(vault, db.SMTPSettings(), nil, notify.Options{
		Now: ev.clock.now, Overrides: notify.StoreOverrides(db.TenantEmailTemplates()),
	}), f: ev.f}
	opts := Options{
		Grace: grace, RetryMin: 2 * time.Millisecond, RetryMax: 8 * time.Millisecond,
		Now: ev.clock.now, Logger: slog.New(ev.logs),
	}
	if tune != nil {
		tune(&opts)
	}
	ev.svc = New(Deps{
		DB: db, Vault: faultVault{inner: vault, f: ev.f}, Files: faultFiles{inner: files, f: ev.f},
		Keys: faultKeys{inner: kr, f: ev.f}, Passwords: faultVerifier{inner: crypto.NewPasswordHasher(2), f: ev.f},
		Notifier: ev.notifier, Mail: ev.queue, SecurityLog: ev.seclog, Usage: ev.usage,
	}, opts)
	ev.svc.repo = faultRepo{inner: ev.svc.repo, f: ev.f}
	// Every new range is written at once, unless a test says otherwise.
	ev.svc.flushBytes = 1
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), waitFor)
		defer cancel()
		if err := ev.svc.Close(ctx); err != nil {
			t.Errorf("Close: %v", err)
		}
		ev.checkLogs()
	})
	return ev
}

// checkLogs verifies that no address, token or file name was logged.
func (ev *env) checkLogs() {
	all := ev.logs.all()
	if strings.Contains(all, "@") || strings.Contains(all, "dl_") || strings.Contains(all, "dg_") {
		ev.t.Errorf("logs hold an address or a token:\n%s", all)
	}
	for _, s := range ev.secrets {
		if strings.Contains(all, s) {
			ev.t.Errorf("logs hold a secret %q:\n%s", s, all)
		}
	}
}

// newTenant creates a tenant, with SMTP settings when smtp is set.
func (ev *env) newTenant(fqdn string, smtp bool) *tenant.Tenant {
	ev.t.Helper()
	ctx := context.Background()
	tn, err := ev.db.Tenants().Create(ctx, &tenant.Tenant{
		Name: "Entity " + fqdn, FQDN: fqdn, DefaultLanguage: "en",
		MaxTransferBytes: 1 << 30, StorageQuotaBytes: 10 << 30,
	})
	if err != nil {
		ev.t.Fatalf("Create(%s): %v", fqdn, err)
	}
	if smtp {
		err := ev.db.SMTPSettings().Put(ctx, tn.ID, store.SMTPConfig{
			Host: "smtp." + fqdn, Port: 25, Security: store.SMTPSecurityNone, FromAddress: "noreply@" + fqdn,
		})
		if err != nil {
			ev.t.Fatal(err)
		}
	}
	return tn
}

// spec describes a transfer to publish.
type spec struct {
	// contents are the clear files; names and statuses default to
	// "file-<i>.bin" and clean.
	contents [][]byte
	names    []string
	statuses []store.ScanStatus
	// sizes override the recorded sizes (0 keeps the content length).
	sizes       map[int]int64
	password    bool
	deleteAfter bool
	// maxDownloads is the download limit, 0 for none.
	maxDownloads int
	// level sets a confidentiality level.
	level bool
	// recipients are the recipients (dave when empty).
	recipients []string
	// perRecipient gives each recipient their own link (since 1.1), and
	// verify requires the recipient verification on top.
	perRecipient, verify bool
}

// random returns n random bytes.
func random(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// published is a transfer made available.
type published struct {
	tn    *tenant.Tenant
	id    string
	token string
	files []store.TransferFile
	// tokens and links are the recipient links of a per-recipient
	// transfer, by position (token is then tokens[0]).
	tokens []string
	links  []store.RecipientLink
}

// link returns the published transfer p used through its recipient link i.
func (p published) link(i int) published {
	q := p
	q.token = p.tokens[i]
	return q
}

// publish stores sp as an available transfer of tn from alice to dave (or
// sp.recipients), its files encrypted on disk like the upload engine does,
// and returns it with its download token, or its recipient links.
func (ev *env) publish(tn *tenant.Tenant, sp spec) published {
	ev.t.Helper()
	ctx := context.Background()
	p := published{tn: tn, id: id.New(id.Transfer)}
	recipients := sp.recipients
	if len(recipients) == 0 {
		recipients = []string{dave}
	}
	n := 1
	if sp.perRecipient {
		n = len(recipients)
	}
	for range n {
		token, err := id.NewDownloadToken()
		if err != nil {
			ev.t.Fatal(err)
		}
		p.tokens = append(p.tokens, token)
		ev.secrets = append(ev.secrets, token)
	}
	p.token = p.tokens[0]
	if !sp.perRecipient {
		p.tokens = nil
	}
	s, err := ev.db.Scoped(tn.ID)
	if err != nil {
		ev.t.Fatal(err)
	}
	now := ev.clock.now()
	err = s.Tx(ctx, func(tx *store.ScopedTx) error {
		var files []store.TransferFile
		for i, c := range sp.contents {
			f, err := ev.storeFile(ctx, tx, tn, c)
			if err != nil {
				return err
			}
			f.Name = fmt.Sprintf("file-%d.bin", i)
			if i < len(sp.names) {
				f.Name = sp.names[i]
			}
			if sz, ok := sp.sizes[i]; ok {
				f.Size = sz
			}
			ev.secrets = append(ev.secrets, f.Name)
			files = append(files, f)
		}
		tr := store.Transfer{
			ID: p.id, SenderEmail: alice, SenderKind: store.DepositorInternal, ExpiryDays: 7,
			Message: "Here are the plans", DeleteAfterFirstDownload: sp.deleteAfter,
		}
		if sp.password {
			tr.PasswordHash = passwordHash()
		}
		if sp.perRecipient {
			tr.LinkMode, tr.RecipientVerification = store.LinkModePerRecipient, sp.verify
		}
		if sp.maxDownloads > 0 {
			tr.MaxDownloads = &sp.maxDownloads
		}
		if sp.level {
			tr.ConfidentialityLevel = "confidential"
			tr.ConfidentialityLabel = map[string]string{"fr": "Restreint", "en": "Confidential"}
			tr.Rules = &store.ConfidentialityRules{ExpiryDaysMask: store.ExpiryMaskAll, RequirePassword: true}
		}
		if err := ev.db.Transfers().CreateTx(ctx, tx, tr, recipients, files); err != nil {
			return err
		}
		if err := ev.db.Transfers().FinalizeTx(ctx, tx, p.id, now); err != nil {
			return err
		}
		for i, f := range files {
			st := store.ScanClean
			if i < len(sp.statuses) {
				st = sp.statuses[i]
			}
			sig := ""
			if st == store.ScanInfected {
				sig = "Eicar-Signature"
			}
			if err := ev.db.TransferFiles().SetScanResultTx(ctx, tx, f.ID, st, sig, now); err != nil {
				return err
			}
		}
		raw := p.tokens
		if len(raw) == 0 {
			raw = []string{p.token}
		}
		var tokens []store.LinkToken
		for _, token := range raw {
			wk, err := ev.vault.SealTx(ctx, tx, crypto.PurposeSecret, []byte(token))
			if err != nil {
				return err
			}
			hash := sha256.Sum256([]byte(token))
			tokens = append(tokens, store.LinkToken{Hash: hash[:], KeyID: wk})
		}
		if !sp.perRecipient {
			return ev.db.Transfers().MarkAvailableTx(ctx, tx, p.id, tokens[0].Hash, tokens[0].KeyID, now)
		}
		var err error
		p.links, err = ev.db.Transfers().MarkAvailableLinksTx(ctx, tx, p.id, tokens, now)
		return err
	})
	if err != nil {
		ev.t.Fatalf("publish: %v", err)
	}
	p.files = ev.get(p).Files
	return p
}

// storeFile encrypts c to a new stored file of tn and returns its
// completed row.
func (ev *env) storeFile(ctx context.Context, tx *store.ScopedTx, tn *tenant.Tenant, c []byte) (store.TransferFile, error) {
	wk, dek, err := ev.vault.NewDEKTx(ctx, tx)
	if err != nil {
		return store.TransferFile{}, err
	}
	fid := id.New(id.File)
	storageName := storage.NewName()
	out, err := ev.files.Create(tn.ID, storageName)
	if err != nil {
		return store.TransferFile{}, err
	}
	cw, err := crypto.NewWriter(out, dek, tn.ID.String(), fid, crypto.WithChunkSize(4096))
	if err != nil {
		return store.TransferFile{}, err
	}
	if _, err := io.Copy(cw, bytes.NewReader(c)); err != nil {
		return store.TransferFile{}, err
	}
	if err := cw.Close(); err != nil {
		return store.TransferFile{}, err
	}
	size, err := out.Seek(0, io.SeekEnd)
	if err != nil {
		return store.TransferFile{}, err
	}
	if err := out.Close(); err != nil {
		return store.TransferFile{}, err
	}
	upl, err := id.NewUploadToken()
	if err != nil {
		return store.TransferFile{}, err
	}
	sum := sha256.Sum256(c)
	return store.TransferFile{
		ID: fid, Size: int64(len(c)), MediaType: "application/octet-stream", DEKKeyID: wk, StorageName: storageName,
		UploadID: upl, SHA256: hex.EncodeToString(sum[:]), CiphertextSize: size, UploadedAt: ev.clock.now(),
	}, nil
}

// get returns the transfer p as stored.
func (ev *env) get(p published) store.TransferDetails {
	ev.t.Helper()
	d, err := ev.db.Transfers().Get(context.Background(), p.tn.ID, p.id)
	if err != nil {
		ev.t.Fatal(err)
	}
	return d
}

// setStatus moves the transfer p from available to st, destroying its
// keys first as the store requires (T-110); its files stay on disk.
func (ev *env) setStatus(p published, st store.TransferStatus) {
	ev.t.Helper()
	s, err := ev.db.Scoped(p.tn.ID)
	if err != nil {
		ev.t.Fatal(err)
	}
	ctx := context.Background()
	err = s.Tx(ctx, func(tx *store.ScopedTx) error {
		d, err := ev.db.Transfers().GetTx(ctx, tx, p.id)
		if err != nil {
			return err
		}
		if _, err := ev.db.RecipientLinks().DestroyKeysTx(ctx, tx, p.id); err != nil {
			return err
		}
		keys := []string{d.DownloadTokenKeyID}
		for _, f := range d.Files {
			keys = append(keys, f.DEKKeyID)
		}
		for _, wk := range keys {
			if wk == "" {
				continue
			}
			if err := ev.db.WrappedKeys().DeleteTx(ctx, tx, wk); err != nil {
				return err
			}
		}
		return ev.db.Transfers().SetStatusTx(ctx, tx, p.id, store.TransferAvailable, st, time.Time{})
	})
	if err != nil {
		ev.t.Fatal(err)
	}
}

// unlock unlocks p with the right password from ipOne and returns the
// grant cookie.
func (ev *env) unlock(p published, cookie string) string {
	ev.t.Helper()
	c, err := ev.svc.Unlock(context.Background(), p.tn, p.token, ipOne, password, Cookies{Grant: cookie})
	if err != nil {
		ev.t.Fatalf("Unlock: %v", err)
	}
	return c
}

// fetch reads length bytes of the file fileID of p from off (to the end
// when length < 0), reports the response as delivered when delivered is
// set, closes the content and returns what was read.
func (ev *env) fetch(p published, cookie, fileID string, off, length int64, delivered bool) []byte {
	ev.t.Helper()
	f, err := ev.svc.OpenFile(context.Background(), p.tn, p.token, ipOne, Cookies{Grant: cookie}, fileID)
	if err != nil {
		ev.t.Fatalf("OpenFile: %v", err)
	}
	if _, err := f.Content.Seek(off, io.SeekStart); err != nil {
		ev.t.Fatal(err)
	}
	var r io.Reader = f.Content
	if length >= 0 {
		r = io.LimitReader(f.Content, length)
	}
	var buf bytes.Buffer
	if _, err := io.CopyBuffer(struct{ io.Writer }{&buf}, struct{ io.Reader }{r}, make([]byte, 1000)); err != nil {
		ev.t.Fatal(err)
	}
	if delivered {
		f.Content.Delivered()
	}
	if err := f.Content.Close(context.Background()); err != nil {
		ev.t.Fatal(err)
	}
	return buf.Bytes()
}

// state returns the served range state of p, nil when there is none.
func (ev *env) state(p published) served {
	ev.t.Helper()
	b, err := ev.files.ReadState(p.tn.ID, storage.StateName(p.id))
	if errors.Is(err, storage.ErrNotFound) {
		return nil
	}
	if err != nil {
		ev.t.Fatal(err)
	}
	st, err := decodeServed(b)
	if err != nil {
		ev.t.Fatal(err)
	}
	return st
}

// firstDownloads returns the first download mails enqueued.
func (ev *env) firstDownloads() []mail.Job {
	var out []mail.Job
	for _, j := range ev.queue.snapshot() {
		if j.Template == mail.TemplateFirstDownload {
			out = append(out, j)
		}
	}
	return out
}

// waitUntil waits until cond holds.
func (ev *env) waitUntil(what string, cond func() bool) {
	ev.t.Helper()
	deadline := time.Now().Add(waitFor)
	for !cond() {
		if time.Now().After(deadline) {
			ev.t.Fatalf("timeout waiting for %s\nlogs:\n%s", what, ev.logs.all())
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// wantErr fails unless errors.Is(err, want).
func wantErr(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("error %v, want %v", err, want)
	}
}

// wantInternal fails unless err is a failure that maps to no client error.
func wantInternal(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("no error")
	}
	for _, e := range []error{ErrNotFound, ErrGone, ErrDownloadLocked, ErrWrongPassword, ErrLocked, ErrInvalid} {
		if errors.Is(err, e) {
			t.Fatalf("error %v maps to %v, want an internal failure", err, e)
		}
	}
}
