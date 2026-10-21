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

// faultNotifier wraps the notifier with the fault "firstDownload" and
// records the deletion times it was given.
type faultNotifier struct {
	inner *notify.Notifier
	f     *faults

	mu        sync.Mutex
	deleteAts []time.Time
}

func (n *faultNotifier) FirstDownload(ctx context.Context, t *tenant.Tenant, tr notify.TransferView, at, d time.Time) (mail.Job, error) {
	n.mu.Lock()
	n.deleteAts = append(n.deleteAts, d)
	n.mu.Unlock()
	if err := n.f.hit("firstDownload"); err != nil {
		return mail.Job{}, err
	}
	return n.inner.FirstDownload(ctx, t, tr, at, d)
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
		logs: &logCapture{}, f: newFaults(),
		clock: &clock{t: time.Now().UTC().Truncate(time.Millisecond)},
	}
	ev.a = ev.newTenant(hostA, true)
	ev.b = ev.newTenant(hostB, true)
	ev.c = ev.newTenant(hostC, false)
	ev.notifier = &faultNotifier{inner: notify.New(vault, db.SMTPSettings(), nil, notify.Options{Now: ev.clock.now}), f: ev.f}
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
		Notifier: ev.notifier, Mail: ev.queue, SecurityLog: ev.seclog,
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
}

// publish stores sp as an available transfer of tn from alice to dave,
// its files encrypted on disk like the upload engine does, and returns it
// with its download token.
func (ev *env) publish(tn *tenant.Tenant, sp spec) published {
	ev.t.Helper()
	ctx := context.Background()
	p := published{tn: tn, id: id.New(id.Transfer)}
	token, err := id.NewDownloadToken()
	if err != nil {
		ev.t.Fatal(err)
	}
	p.token = token
	ev.secrets = append(ev.secrets, token)
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
		if err := ev.db.Transfers().CreateTx(ctx, tx, tr, []string{dave}, files); err != nil {
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
		wk, err := ev.vault.SealTx(ctx, tx, crypto.PurposeSecret, []byte(token))
		if err != nil {
			return err
		}
		hash := sha256.Sum256([]byte(token))
		return ev.db.Transfers().MarkAvailableTx(ctx, tx, p.id, hash[:], wk, now)
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

// setStatus moves the transfer p from available to st.
func (ev *env) setStatus(p published, st store.TransferStatus) {
	ev.t.Helper()
	s, err := ev.db.Scoped(p.tn.ID)
	if err != nil {
		ev.t.Fatal(err)
	}
	err = s.Tx(context.Background(), func(tx *store.ScopedTx) error {
		return ev.db.Transfers().SetStatusTx(context.Background(), tx, p.id, store.TransferAvailable, st, time.Time{})
	})
	if err != nil {
		ev.t.Fatal(err)
	}
}

// unlock unlocks p with the right password from ipOne and returns the
// grant cookie.
func (ev *env) unlock(p published, cookie string) string {
	ev.t.Helper()
	c, err := ev.svc.Unlock(context.Background(), p.tn, p.token, ipOne, password, cookie)
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
	f, err := ev.svc.OpenFile(context.Background(), p.tn, p.token, ipOne, cookie, fileID)
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
