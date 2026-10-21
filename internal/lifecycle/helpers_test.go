package lifecycle

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/masterkey"
	"github.com/ed-fr/transteira/internal/masterkey/masterkeytest"
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
	hostA   = "transfer.entity-a.example.com"
	hostB   = "transfer.entity-b.example.com"
	alice   = "alice@entity-a.example.com" // sender
	dave    = "dave@customer.example.net"  // recipient
	grace   = 15 * time.Minute
	waitFor = 15 * time.Second
)

// t0 is the time of the first downloads.
var t0 = time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC)

var errFault = errors.New("injected fault")

// faults fails named operations: count[name] times (forever when negative)
// with err[name]; hook[name] runs once, at the next call, before the check.
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

// onCall runs fn at the next call of name.
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

// faultRepo wraps a repo with the faults "due", "transfer", "finish" and
// "scrub".
type faultRepo struct {
	inner repo
	f     *faults
}

func (r faultRepo) due(ctx context.Context, now time.Time) ([]store.TenantTransfer, error) {
	if err := r.f.hit("due"); err != nil {
		return nil, err
	}
	return r.inner.due(ctx, now)
}

func (r faultRepo) transfer(ctx context.Context, tid tenant.ID, trfID string) (store.TransferDetails, error) {
	if err := r.f.hit("transfer"); err != nil {
		return store.TransferDetails{}, err
	}
	return r.inner.transfer(ctx, tid, trfID)
}

func (r faultRepo) finish(ctx context.Context, tid tenant.ID, trfID string, now time.Time) error {
	if err := r.f.hit("finish"); err != nil {
		return err
	}
	return r.inner.finish(ctx, tid, trfID, now)
}

func (r faultRepo) scrub(ctx context.Context) error {
	if err := r.f.hit("scrub"); err != nil {
		return err
	}
	return r.inner.scrub(ctx)
}

// faultVault wraps the vault with the fault "destroy".
type faultVault struct {
	inner *masterkey.Vault
	f     *faults
}

func (v faultVault) DestroyTx(ctx context.Context, tx *store.ScopedTx, wkID string) error {
	if err := v.f.hit("destroy"); err != nil {
		return err
	}
	return v.inner.DestroyTx(ctx, tx, wkID)
}

// faultRemover wraps the upload engine with the faults "lock", "remove"
// (fails before erasing anything), "removeAfter" (fails after the real
// erasure, like a file that could not be removed) and "removeNoop"
// (succeeds without erasing anything).
type faultRemover struct {
	inner *upload.Engine
	f     *faults
}

func (r faultRemover) LockFiles(fileIDs []string) (func(), error) {
	if err := r.f.hit("lock"); err != nil {
		return nil, err
	}
	return r.inner.LockFiles(fileIDs)
}

func (r faultRemover) RemoveFiles(ctx context.Context, tid tenant.ID, files []store.TransferFile) error {
	if err := r.f.hit("remove"); err != nil {
		return err
	}
	if r.f.hit("removeNoop") != nil {
		return nil
	}
	err := r.inner.RemoveFiles(ctx, tid, files)
	if ferr := r.f.hit("removeAfter"); ferr != nil {
		return ferr
	}
	return err
}

// faultStates wraps the storage with the fault "state".
type faultStates struct {
	inner *storage.Store
	f     *faults
}

func (s faultStates) RemoveState(tid tenant.ID, name string) error {
	if err := s.f.hit("state"); err != nil {
		return err
	}
	return s.inner.RemoveState(tid, name)
}

// clock is a settable fake clock.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = t
}

// logCapture is a slog handler keeping every record as text.
type logCapture struct {
	mu    sync.Mutex
	lines []string
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
	h.lines = append(h.lines, b.String())
	return nil
}

// count returns the number of lines containing s.
func (h *logCapture) count(s string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, l := range h.lines {
		if strings.Contains(l, s) {
			n++
		}
	}
	return n
}

func (h *logCapture) all() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return strings.Join(h.lines, "\n")
}

// fakeTicker replaces the real ticker: the test sends the ticks.
type fakeTicker struct {
	c       chan time.Time
	stopped chan struct{}
	period  time.Duration
}

func newFakeTicker() *fakeTicker {
	return &fakeTicker{c: make(chan time.Time), stopped: make(chan struct{})}
}

func (ft *fakeTicker) new(d time.Duration) (<-chan time.Time, func()) {
	ft.period = d
	return ft.c, func() { close(ft.stopped) }
}

// sweepResult is the outcome of a periodic sweep.
type sweepResult struct {
	st  Stats
	err error
}

// env is a sweeper over a migrated database with tenants A and B, real
// storage, keys and upload engine, wrapped with faults.
type env struct {
	t       *testing.T
	db      *store.DB
	vault   *masterkey.Vault
	files   *storage.Store
	uploads *upload.Engine
	logs    *logCapture
	f       *faults
	clock   *clock
	s       *Sweeper
	a, b    *tenant.Tenant
}

// newEnv builds an env on engine e, with the clock after the grace period
// of transfers downloaded at t0.
func newEnv(t *testing.T, e storetest.Engine) *env {
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
	kr, err := masterkey.New(masterkeytest.Key(t, "lifecycle"), nil)
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
		logs: &logCapture{}, f: newFaults(), clock: &clock{now: t0.Add(grace + time.Minute)},
	}
	ev.a = ev.newTenant(hostA)
	ev.b = ev.newTenant(hostB)
	ev.s = New(Deps{
		DB: db, Vault: faultVault{inner: vault, f: ev.f},
		Remover: faultRemover{inner: ev.uploads, f: ev.f}, States: faultStates{inner: files, f: ev.f},
	}, Options{Now: ev.clock.Now, Logger: slog.New(ev.logs)})
	ev.s.repo = faultRepo{inner: ev.s.repo, f: ev.f}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), waitFor)
		defer cancel()
		if err := ev.s.Close(ctx); err != nil {
			t.Errorf("Close: %v", err)
		}
		if all := ev.logs.all(); strings.Contains(all, "@") || strings.Contains(all, "dl_") {
			t.Errorf("logs hold an address or a token:\n%s", all)
		}
	})
	return ev
}

func (ev *env) newTenant(fqdn string) *tenant.Tenant {
	ev.t.Helper()
	tn, err := ev.db.Tenants().Create(context.Background(), &tenant.Tenant{
		Name: "Entity " + fqdn, FQDN: fqdn, DefaultLanguage: "en",
		MaxTransferBytes: 1 << 30, StorageQuotaBytes: 10 << 30,
	})
	if err != nil {
		ev.t.Fatalf("Create(%s): %v", fqdn, err)
	}
	return tn
}

// tx runs fn in a write transaction of tn.
func (ev *env) tx(tn *tenant.Tenant, fn func(*store.ScopedTx) error) {
	ev.t.Helper()
	s, err := ev.db.Scoped(tn.ID)
	if err != nil {
		ev.t.Fatal(err)
	}
	if err := s.Tx(context.Background(), fn); err != nil {
		ev.t.Fatal(err)
	}
}

// fixture is a stored transfer.
type fixture struct {
	tn        *tenant.Tenant
	id        string
	tokenHash []byte
}

// available stores an available transfer of tn with nFiles encrypted files
// on disk and the "delete after the first download" option when deleteOpt
// is set.
func (ev *env) available(tn *tenant.Tenant, nFiles int, deleteOpt bool) fixture {
	ev.t.Helper()
	ctx := context.Background()
	trfID := id.New(id.Transfer)
	token, err := id.NewDownloadToken()
	if err != nil {
		ev.t.Fatal(err)
	}
	hash := sha256.Sum256([]byte(token))
	ev.tx(tn, func(tx *store.ScopedTx) error {
		files := make([]store.TransferFile, 0, nFiles)
		for i := range nFiles {
			f, err := ev.storeFile(ctx, tx, tn)
			if err != nil {
				return err
			}
			f.Name = fmt.Sprintf("file-%d.bin", i)
			files = append(files, f)
		}
		tr := store.Transfer{
			ID: trfID, SenderEmail: alice, SenderKind: store.DepositorInternal, ExpiryDays: 7,
			DeleteAfterFirstDownload: deleteOpt,
		}
		if err := ev.db.Transfers().CreateTx(ctx, tx, tr, []string{dave}, files); err != nil {
			return err
		}
		if err := ev.db.Transfers().FinalizeTx(ctx, tx, trfID, t0.Add(-time.Hour)); err != nil {
			return err
		}
		wk, err := ev.vault.SealTx(ctx, tx, crypto.PurposeSecret, []byte(token))
		if err != nil {
			return err
		}
		return ev.db.Transfers().MarkAvailableTx(ctx, tx, trfID, hash[:], wk, t0.Add(-time.Hour))
	})
	return fixture{tn: tn, id: trfID, tokenHash: hash[:]}
}

// storeFile writes random bytes to a new stored file of tn and returns its
// completed row with a new data key.
func (ev *env) storeFile(ctx context.Context, tx *store.ScopedTx, tn *tenant.Tenant) (store.TransferFile, error) {
	wk, _, err := ev.vault.NewDEKTx(ctx, tx)
	if err != nil {
		return store.TransferFile{}, err
	}
	name := make([]byte, 16)
	_, _ = rand.Read(name)
	storageName := hex.EncodeToString(name)
	out, err := ev.files.Create(tn.ID, storageName)
	if err != nil {
		return store.TransferFile{}, err
	}
	content := make([]byte, 64)
	_, _ = rand.Read(content)
	_, err = out.Write(content)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return store.TransferFile{}, err
	}
	upl, err := id.NewUploadToken()
	if err != nil {
		return store.TransferFile{}, err
	}
	sum := sha256.Sum256(content)
	return store.TransferFile{
		ID: id.New(id.File), Size: int64(len(content)), DEKKeyID: wk, StorageName: storageName, UploadID: upl,
		SHA256: hex.EncodeToString(sum[:]), CiphertextSize: int64(len(content)), UploadedAt: t0.Add(-2 * time.Hour),
	}, nil
}

// due stores an available transfer of tn with the option, downloaded at t0
// (due at t0 + grace), with a download state file.
func (ev *env) due(tn *tenant.Tenant, nFiles int) fixture {
	ev.t.Helper()
	fx := ev.available(tn, nFiles, true)
	ev.download(fx, t0, t0.Add(grace))
	if err := ev.files.WriteState(tn.ID, storage.StateName(fx.id), []byte(`{"ranges":[]}`)); err != nil {
		ev.t.Fatal(err)
	}
	return fx
}

// download records the first download of fx at at, due at deleteAfter
// (zero for a transfer without the option).
func (ev *env) download(fx fixture, at, deleteAfter time.Time) {
	ev.t.Helper()
	ev.tx(fx.tn, func(tx *store.ScopedTx) error {
		first, err := ev.db.Transfers().MarkFirstDownloadTx(context.Background(), tx, fx.id, at, deleteAfter)
		if err == nil && !first {
			err = errors.New("first download already recorded")
		}
		return err
	})
}

// get returns the transfer fx.
func (ev *env) get(fx fixture) store.TransferDetails {
	ev.t.Helper()
	d, err := ev.db.Transfers().Get(context.Background(), fx.tn.ID, fx.id)
	if err != nil {
		ev.t.Fatal(err)
	}
	return d
}

// deleteOutside deletes fx without the sweeper, as another component
// would: keys first, then the deleted status.
func (ev *env) deleteOutside(fx fixture) {
	ev.t.Helper()
	ctx := context.Background()
	d := ev.get(fx)
	if err := ev.uploads.RemoveFiles(ctx, fx.tn.ID, d.Files); err != nil {
		ev.t.Fatal(err)
	}
	ev.tx(fx.tn, func(tx *store.ScopedTx) error {
		if err := ev.vault.DestroyTx(ctx, tx, d.DownloadTokenKeyID); err != nil {
			return err
		}
		return ev.db.Transfers().MarkDeletedTx(ctx, tx, fx.id)
	})
}

// sweep runs a sweep and checks its stats.
func (ev *env) sweep(want Stats) {
	ev.t.Helper()
	st, err := ev.s.Sweep(context.Background())
	if err != nil {
		ev.t.Fatalf("Sweep: %v\nlogs:\n%s", err, ev.logs.all())
	}
	if st != want {
		ev.t.Fatalf("Sweep stats = %+v, want %+v\nlogs:\n%s", st, want, ev.logs.all())
	}
}

// keyExists reports whether the wrapped key wkID of tn exists.
func (ev *env) keyExists(tn *tenant.Tenant, wkID string) bool {
	ev.t.Helper()
	_, err := ev.db.WrappedKeys().Get(context.Background(), tn.ID, wkID)
	if errors.Is(err, store.ErrNotFound) {
		return false
	}
	if err != nil {
		ev.t.Fatal(err)
	}
	return true
}

// fileExists reports whether the stored file name of tn exists.
func (ev *env) fileExists(tn *tenant.Tenant, name string) bool {
	ev.t.Helper()
	f, _, err := ev.files.OpenRead(tn.ID, name)
	if errors.Is(err, storage.ErrNotFound) {
		return false
	}
	if err != nil {
		ev.t.Fatal(err)
	}
	_ = f.Close()
	return true
}

// stateExists reports whether the download state of fx exists.
func (ev *env) stateExists(fx fixture) bool {
	ev.t.Helper()
	_, err := ev.files.ReadState(fx.tn.ID, storage.StateName(fx.id))
	if errors.Is(err, storage.ErrNotFound) {
		return false
	}
	if err != nil {
		ev.t.Fatal(err)
	}
	return true
}

// assertDeleted checks that before (read before the sweep) was fully
// erased: deleted status, every key destroyed, files and state gone, token
// hash kept.
func (ev *env) assertDeleted(fx fixture, before store.TransferDetails) {
	ev.t.Helper()
	d := ev.get(fx)
	if d.Status != store.TransferDeleted {
		ev.t.Fatalf("status = %s, want deleted", d.Status)
	}
	if d.DownloadTokenKeyID != "" || ev.keyExists(fx.tn, before.DownloadTokenKeyID) {
		ev.t.Fatal("download token key not destroyed")
	}
	for i, f := range d.Files {
		if f.DEKKeyID != "" {
			ev.t.Fatalf("file %d keeps its data key", i)
		}
		if before.Files[i].DEKKeyID != "" && ev.keyExists(fx.tn, before.Files[i].DEKKeyID) {
			ev.t.Fatalf("file %d data key still stored", i)
		}
		if ev.fileExists(fx.tn, f.StorageName) {
			ev.t.Fatalf("file %d still on disk", i)
		}
	}
	if ev.stateExists(fx) {
		ev.t.Fatal("download state still on disk")
	}
	byToken, err := ev.db.Transfers().GetByDownloadTokenHash(context.Background(), fx.tn.ID, fx.tokenHash)
	if err != nil || byToken.ID != fx.id || byToken.Status != store.TransferDeleted {
		ev.t.Fatalf("token lookup = %s %s, %v; want the deleted transfer (410)", byToken.ID, byToken.Status, err)
	}
}

// assertIntact checks that fx is still available with its keys and files.
func (ev *env) assertIntact(fx fixture) {
	ev.t.Helper()
	d := ev.get(fx)
	if d.Status != store.TransferAvailable || !ev.keyExists(fx.tn, d.DownloadTokenKeyID) {
		ev.t.Fatalf("transfer %s / token key: not intact", d.Status)
	}
	for i, f := range d.Files {
		if f.DEKKeyID == "" || !ev.keyExists(fx.tn, f.DEKKeyID) || !ev.fileExists(fx.tn, f.StorageName) {
			ev.t.Fatalf("file %d not intact", i)
		}
	}
}
