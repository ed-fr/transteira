package scan

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
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/antivirus"
	"github.com/ed-fr/transteira/internal/antivirus/antivirustest"
	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/masterkey"
	"github.com/ed-fr/transteira/internal/masterkey/masterkeytest"
	"github.com/ed-fr/transteira/internal/notify"
	"github.com/ed-fr/transteira/internal/storage"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/upload"
)

// The tests that run on every engine are deliberately not parallel: each
// PostgreSQL engine holds its own connection pool, and make test runs every
// package at once against a server limited to 100 connections.

// Fixed values of the tests. Domains are fictitious.
const (
	hostA    = "transfer.entity-a.example.com"
	hostB    = "transfer.entity-b.example.com"
	hostC    = "transfer.entity-c.example.com"
	smtpA    = "smtp-a.example.com"
	smtpB    = "smtp-b.example.com"
	alice    = "alice@entity-a.example.com" // sender
	dave     = "dave@customer.example.net"  // recipient
	erin     = "erin@partner.example.org"   // recipient
	waitFor  = 15 * time.Second
	retryMin = 20 * time.Millisecond
	retryMax = 80 * time.Millisecond
)

var errFault = errors.New("injected fault")

// faults fails named operations: fail[name] times (or forever when
// negative) with err[name].
type faults struct {
	mu    sync.Mutex
	count map[string]int
	err   map[string]error
	hook  map[string]func()
	skip  map[string]int
	calls map[string]int
}

func newFaults() *faults {
	return &faults{count: map[string]int{}, err: map[string]error{}, hook: map[string]func(){}, skip: map[string]int{}, calls: map[string]int{}}
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

// failAfter makes name fail once with errFault after skip successful
// calls.
func (f *faults) failAfter(name string, skip int) {
	f.set(name, 1, nil)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.skip[name] = skip
}

// onCall runs fn at the next call of name, before the failure check.
func (f *faults) onCall(name string, fn func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hook[name] = fn
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
	if f.skip[name] > 0 {
		f.skip[name]--
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

func (r faultRepo) tenant(ctx context.Context, tid tenant.ID) (*tenant.Tenant, error) {
	if err := r.f.hit("tenant"); err != nil {
		return nil, err
	}
	return r.inner.tenant(ctx, tid)
}

func (r faultRepo) transfer(ctx context.Context, tid tenant.ID, trfID string) (store.TransferDetails, error) {
	if err := r.f.hit("transfer"); err != nil {
		return store.TransferDetails{}, err
	}
	return r.inner.transfer(ctx, tid, trfID)
}

func (r faultRepo) setScanning(ctx context.Context, tid tenant.ID, fileID string) error {
	if err := r.f.hit("setScanning"); err != nil {
		return err
	}
	return r.inner.setScanning(ctx, tid, fileID)
}

func (r faultRepo) setResult(ctx context.Context, tid tenant.ID, fileID string, s store.ScanStatus, sig string, now time.Time) error {
	if err := r.f.hit("setResult"); err != nil {
		return err
	}
	return r.inner.setResult(ctx, tid, fileID, s, sig, now)
}

func (r faultRepo) countAttempt(ctx context.Context, tid tenant.ID, fileID string) (int, error) {
	if err := r.f.hit("countAttempt"); err != nil {
		return 0, err
	}
	return r.inner.countAttempt(ctx, tid, fileID)
}

func (r faultRepo) reject(ctx context.Context, tid tenant.ID, trfID string) error {
	if err := r.f.hit("reject"); err != nil {
		return err
	}
	return r.inner.reject(ctx, tid, trfID)
}

func (r faultRepo) makeAvailable(ctx context.Context, tid tenant.ID, trfID, token string, now time.Time) error {
	if err := r.f.hit("makeAvailable"); err != nil {
		return err
	}
	return r.inner.makeAvailable(ctx, tid, trfID, token, now)
}

func (r faultRepo) sweep(ctx context.Context) ([]store.TenantTransfer, error) {
	if err := r.f.hit("sweep"); err != nil {
		return nil, err
	}
	return r.inner.sweep(ctx)
}

// faultVault wraps the vault with faults "open" and "seal".
type faultVault struct {
	inner *masterkey.Vault
	f     *faults
}

func (v faultVault) Open(ctx context.Context, tid tenant.ID, p crypto.Purpose, wkID string) ([]byte, error) {
	if p == crypto.PurposeDEK {
		if err := v.f.hit("open"); err != nil {
			return nil, err
		}
	}
	return v.inner.Open(ctx, tid, p, wkID)
}

func (v faultVault) SealTx(ctx context.Context, tx *store.ScopedTx, p crypto.Purpose, b []byte) (string, error) {
	if err := v.f.hit("seal"); err != nil {
		return "", err
	}
	return v.inner.SealTx(ctx, tx, p, b)
}

// faultFiles wraps the storage with the fault "openRead".
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

// headerFiles serves an empty file instead of the stored file broken, so
// that its header cannot be read.
type headerFiles struct {
	inner  *storage.Store
	broken string
	empty  string
}

func (s headerFiles) OpenRead(tid tenant.ID, name string) (*os.File, int64, error) {
	if name == s.broken {
		name = s.empty
	}
	return s.inner.OpenRead(tid, name)
}

// faultRemover wraps the upload engine with the fault "remove".
type faultRemover struct {
	inner *upload.Engine
	f     *faults
}

func (r faultRemover) RemoveFiles(ctx context.Context, tid tenant.ID, files []store.TransferFile) error {
	if err := r.f.hit("remove"); err != nil {
		return err
	}
	return r.inner.RemoveFiles(ctx, tid, files)
}

// faultNotifier wraps the notifier with the faults "recipients", "confirm",
// "problems" and "notScanned".
type faultNotifier struct {
	inner *notify.Notifier
	f     *faults
}

func (n faultNotifier) RecipientJobs(ctx context.Context, t *tenant.Tenant, tr notify.TransferView, link string) ([]mail.Job, error) {
	if err := n.f.hit("recipients"); err != nil {
		return nil, err
	}
	return n.inner.RecipientJobs(ctx, t, tr, link)
}

func (n faultNotifier) SenderConfirmation(ctx context.Context, t *tenant.Tenant, tr notify.TransferView, link string) (mail.Job, error) {
	if err := n.f.hit("confirm"); err != nil {
		return mail.Job{}, err
	}
	return n.inner.SenderConfirmation(ctx, t, tr, link)
}

func (n faultNotifier) FileProblems(ctx context.Context, t *tenant.Tenant, tr notify.TransferView) (mail.Job, error) {
	if err := n.f.hit("problems"); err != nil {
		return mail.Job{}, err
	}
	return n.inner.FileProblems(ctx, t, tr)
}

func (n faultNotifier) FileNotScanned(ctx context.Context, t *tenant.Tenant, tr notify.TransferView) (mail.Job, error) {
	if err := n.f.hit("notScanned"); err != nil {
		return mail.Job{}, err
	}
	return n.inner.FileNotScanned(ctx, t, tr)
}

// testScanner wraps the clamd client: "scan" faults replace the result
// (after draining the reader), result overrides a successful verdict, and
// block, when set, makes the first scan signal entered and wait.
type testScanner struct {
	inner *antivirus.Client
	f     *faults

	mu      sync.Mutex
	calls   int
	result  *antivirus.Result
	entered chan struct{}
	block   chan struct{}
}

func (s *testScanner) Scan(ctx context.Context, r io.Reader, size int64) (antivirus.Result, error) {
	s.mu.Lock()
	s.calls++
	block, entered := s.block, s.entered
	s.block, s.entered = nil, nil
	res := s.result
	s.mu.Unlock()
	if entered != nil {
		close(entered)
	}
	if block != nil {
		<-block
	}
	if err := s.f.hit("scan"); err != nil {
		_, _ = io.Copy(io.Discard, r)
		return antivirus.Result{}, err
	}
	if res != nil {
		_, _ = io.Copy(io.Discard, r)
		return *res, nil
	}
	return s.inner.Scan(ctx, r, size)
}

// Ping pings clamd, after the "ping" fault.
func (s *testScanner) Ping(ctx context.Context) error {
	if err := s.f.hit("ping"); err != nil {
		return err
	}
	return s.inner.Ping(ctx)
}

func (s *testScanner) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// blockNext makes the next scan wait until the returned release is closed;
// entered is closed when it starts.
func (s *testScanner) blockNext() (entered, release chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entered, s.block = make(chan struct{}), make(chan struct{})
	return s.entered, s.block
}

// fakeQueue captures the jobs; errs are returned by the next Enqueue calls,
// in order.
type fakeQueue struct {
	mu   sync.Mutex
	jobs []mail.Job
	errs []error
	// failAll, when set, is returned by every call.
	failAll error
	calls   int
}

func (q *fakeQueue) Enqueue(j mail.Job) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.calls++
	if q.failAll != nil {
		return q.failAll
	}
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

// logRecord is one captured log line.
type logRecord struct {
	level slog.Level
	msg   string
	text  string
}

// logCapture is a slog handler keeping every record.
type logCapture struct {
	mu      sync.Mutex
	records []logRecord
}

func (h *logCapture) Enabled(context.Context, slog.Level) bool { return true }
func (h *logCapture) WithAttrs([]slog.Attr) slog.Handler       { return h }
func (h *logCapture) WithGroup(string) slog.Handler            { return h }

func (h *logCapture) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	b.WriteString(r.Message)
	r.Attrs(func(a slog.Attr) bool {
		fmt.Fprintf(&b, " %s=%v", a.Key, a.Value)
		return true
	})
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, logRecord{level: r.Level, msg: r.Message, text: b.String()})
	return nil
}

// count returns the number of records whose message contains msg.
func (h *logCapture) count(msg string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, r := range h.records {
		if strings.Contains(r.msg, msg) {
			n++
		}
	}
	return n
}

// all returns every record as text.
func (h *logCapture) all() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var b strings.Builder
	for _, r := range h.records {
		b.WriteString(r.level.String() + " " + r.text + "\n")
	}
	return b.String()
}

// env is a worker over a migrated database with tenants A and B (with SMTP
// settings) and C (without), a fake clamd and real storage and keys.
type env struct {
	t       *testing.T
	db      *store.DB
	vault   *masterkey.Vault
	files   *storage.Store
	uploads *upload.Engine
	clamd   *antivirustest.Server
	client  *antivirus.Client
	queue   *fakeQueue
	logs    *logCapture
	f       *faults
	scanner *testScanner
	w       *Worker
	a, b, c *tenant.Tenant
}

// newEnv builds an env on engine e; opts tunes the worker (short backoffs by
// default).
func newEnv(t *testing.T, e storetest.Engine, opts Options) *env {
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
	kr, err := masterkey.New(masterkeytest.Key(t, "scan"), nil)
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
		t: t, db: db, vault: vault, files: files, uploads: upload.New(db, vault, files, upload.Options{}),
		clamd: antivirustest.New(t), queue: &fakeQueue{}, logs: &logCapture{}, f: newFaults(),
	}
	ev.client = antivirus.NewClient(ev.clamd.Network(), ev.clamd.Addr(),
		antivirus.WithScanTimeout(10*time.Second), antivirus.WithIdleTimeout(5*time.Second))
	ev.scanner = &testScanner{inner: ev.client, f: ev.f}
	ev.a = ev.newTenant(hostA, "en", smtpA)
	ev.b = ev.newTenant(hostB, "fr", smtpB)
	ev.c = ev.newTenant(hostC, "en", "")
	if opts.Workers == 0 {
		opts.Workers = 2
	}
	if opts.RetryMin == 0 {
		opts.RetryMin, opts.RetryMax = retryMin, retryMax
	}
	opts.Logger = slog.New(ev.logs)
	notifier := notify.New(vault, db.SMTPSettings(), nil, notify.Options{})
	ev.w = New(Deps{
		DB: db, Vault: faultVault{inner: vault, f: ev.f}, Files: faultFiles{inner: files, f: ev.f},
		Scanner: ev.scanner, Remover: faultRemover{inner: ev.uploads, f: ev.f},
		Notifier: faultNotifier{inner: notifier, f: ev.f}, Mail: ev.queue,
	}, opts)
	ev.w.repo = faultRepo{inner: ev.w.repo, f: ev.f}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), waitFor)
		defer cancel()
		if err := ev.w.Close(ctx); err != nil {
			t.Errorf("Close: %v", err)
		}
		ev.checkLogs()
	})
	return ev
}

// checkLogs verifies that no address and no token was logged.
func (ev *env) checkLogs() {
	all := ev.logs.all()
	if strings.Contains(all, "@") || strings.Contains(all, "dl_") {
		ev.t.Errorf("logs hold an address or a token:\n%s", all)
	}
}

// newTenant creates a tenant, with SMTP settings on smtpHost unless empty.
func (ev *env) newTenant(fqdn, lang, smtpHost string) *tenant.Tenant {
	ev.t.Helper()
	ctx := context.Background()
	tn, err := ev.db.Tenants().Create(ctx, &tenant.Tenant{
		Name: "Entity " + fqdn, FQDN: fqdn, DefaultLanguage: lang,
		MaxTransferBytes: 1 << 30, StorageQuotaBytes: 10 << 30,
	})
	if err != nil {
		ev.t.Fatalf("Create(%s): %v", fqdn, err)
	}
	if smtpHost != "" {
		err := ev.db.SMTPSettings().Put(ctx, tn.ID, store.SMTPConfig{
			Host: smtpHost, Port: 25, Security: store.SMTPSecurityNone, FromAddress: "noreply@" + fqdn,
		})
		if err != nil {
			ev.t.Fatal(err)
		}
	}
	return tn
}

// start starts the worker.
func (ev *env) start() {
	ev.t.Helper()
	if err := ev.w.Start(context.Background()); err != nil {
		ev.t.Fatalf("Start: %v", err)
	}
}

// clean returns n bytes of random content (never the EICAR string).
func clean(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// scanning stores a finalized transfer of tn (status scanning) from alice
// to dave and erin, with one file per content, encrypted on disk like the
// upload engine does.
func (ev *env) scanning(tn *tenant.Tenant, contents ...[]byte) string {
	ev.t.Helper()
	ctx := context.Background()
	trfID := id.New(id.Transfer)
	s, err := ev.db.Scoped(tn.ID)
	if err != nil {
		ev.t.Fatal(err)
	}
	err = s.Tx(ctx, func(tx *store.ScopedTx) error {
		var files []store.TransferFile
		for i, c := range contents {
			f, err := ev.storeFile(ctx, tx, tn, c)
			if err != nil {
				return err
			}
			f.Name = fmt.Sprintf("file-%d.bin", i)
			files = append(files, f)
		}
		tr := store.Transfer{ID: trfID, SenderEmail: alice, SenderKind: store.DepositorInternal, ExpiryDays: 7}
		if err := ev.db.Transfers().CreateTx(ctx, tx, tr, []string{dave, erin}, files); err != nil {
			return err
		}
		return ev.db.Transfers().FinalizeTx(ctx, tx, trfID, time.Now())
	})
	if err != nil {
		ev.t.Fatalf("scanning transfer: %v", err)
	}
	return trfID
}

// storeFile encrypts c to a new stored file of tn and returns its
// completed row.
func (ev *env) storeFile(ctx context.Context, tx *store.ScopedTx, tn *tenant.Tenant, c []byte) (store.TransferFile, error) {
	wk, dek, err := ev.vault.NewDEKTx(ctx, tx)
	if err != nil {
		return store.TransferFile{}, err
	}
	fid := id.New(id.File)
	name := make([]byte, 16)
	_, _ = rand.Read(name)
	storageName := hex.EncodeToString(name)
	out, err := ev.files.Create(tn.ID, storageName)
	if err != nil {
		return store.TransferFile{}, err
	}
	cw, err := crypto.NewWriter(out, dek, tn.ID.String(), fid)
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
		ID: fid, Size: int64(len(c)), DEKKeyID: wk, StorageName: storageName, UploadID: upl,
		SHA256: hex.EncodeToString(sum[:]), CiphertextSize: size, UploadedAt: time.Now(),
	}, nil
}

// get returns the transfer trfID of tn.
func (ev *env) get(tn *tenant.Tenant, trfID string) store.TransferDetails {
	ev.t.Helper()
	d, err := ev.db.Transfers().Get(context.Background(), tn.ID, trfID)
	if err != nil {
		ev.t.Fatal(err)
	}
	return d
}

// waitStatus waits until the transfer trfID of tn has status s.
func (ev *env) waitStatus(tn *tenant.Tenant, trfID string, s store.TransferStatus) store.TransferDetails {
	ev.t.Helper()
	deadline := time.Now().Add(waitFor)
	for {
		d := ev.get(tn, trfID)
		if d.Status == s {
			return d
		}
		if time.Now().After(deadline) {
			ev.t.Fatalf("transfer status %s, want %s\nlogs:\n%s", d.Status, s, ev.logs.all())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// waitUntil waits until cond holds.
func (ev *env) waitUntil(what string, cond func() bool) {
	ev.t.Helper()
	deadline := time.Now().Add(waitFor)
	for !cond() {
		if time.Now().After(deadline) {
			ev.t.Fatalf("timeout waiting for %s\nlogs:\n%s", what, ev.logs.all())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// waitJobs waits until the queue holds n jobs, and checks it holds no more
// a little later.
func (ev *env) waitJobs(n int) []mail.Job {
	ev.t.Helper()
	ev.waitUntil(fmt.Sprintf("%d mail jobs", n), func() bool { return len(ev.queue.snapshot()) >= n })
	ev.waitIdle()
	jobs := ev.queue.snapshot()
	if len(jobs) != n {
		ev.t.Fatalf("%d mail jobs, want %d", len(jobs), n)
	}
	return jobs
}

// waitIdle waits until the worker has nothing queued, running or pending.
func (ev *env) waitIdle() {
	ev.t.Helper()
	ev.waitUntil("idle worker", func() bool {
		ev.w.mu.Lock()
		defer ev.w.mu.Unlock()
		return len(ev.w.fifo) == 0 && ev.w.running == 0 && len(ev.w.known) == 0 && len(ev.w.timers) == 0 && ev.w.mails.Pending() == 0
	})
}

// templates returns the template of each job, sorted.
func templates(jobs []mail.Job) []string {
	out := make([]string, 0, len(jobs))
	for _, j := range jobs {
		out = append(out, j.Template)
	}
	slices.Sort(out)
	return out
}

// byTemplate returns the jobs of template name.
func byTemplate(jobs []mail.Job, name string) []mail.Job {
	var out []mail.Job
	for _, j := range jobs {
		if j.Template == name {
			out = append(out, j)
		}
	}
	return out
}
