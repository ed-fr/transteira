package lifecycle

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
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

// faultRepo wraps a repo with a fault per method: "due" (the deletion
// listing), "dueExpirations", "rejectedKeyed", "abandoned", "transfer", "finish", "scrub",
// "tenantIDs", "listEnded", "deleteEnded", "purge:<name>", "purgeSystem:<name>", "storageRefs",
// "availableIDs", "backup", and "backupUnsupported" (any fault makes
// backupSupported false). refsHook, when set, edits the storage refs
// returned.
type faultRepo struct {
	inner    repo
	f        *faults
	refsHook func(map[string]store.StorageRef)
}

func (r *faultRepo) dueDeletions(ctx context.Context, now time.Time, page store.SweepPage) ([]store.TenantTransfer, error) {
	if err := r.f.hit("due"); err != nil {
		return nil, err
	}
	return r.inner.dueDeletions(ctx, now, page)
}

func (r *faultRepo) dueExpirations(ctx context.Context, now time.Time, scanningMaxAge time.Duration, page store.SweepPage) ([]store.TenantTransfer, error) {
	if err := r.f.hit("dueExpirations"); err != nil {
		return nil, err
	}
	return r.inner.dueExpirations(ctx, now, scanningMaxAge, page)
}

func (r *faultRepo) rejectedKeyed(ctx context.Context, page store.SweepPage) ([]store.TenantTransfer, error) {
	if err := r.f.hit("rejectedKeyed"); err != nil {
		return nil, err
	}
	return r.inner.rejectedKeyed(ctx, page)
}

func (r *faultRepo) abandonedUploads(ctx context.Context, createdBefore time.Time, page store.SweepPage) ([]store.TenantTransfer, error) {
	if err := r.f.hit("abandoned"); err != nil {
		return nil, err
	}
	return r.inner.abandonedUploads(ctx, createdBefore, page)
}

func (r *faultRepo) transfer(ctx context.Context, tid tenant.ID, trfID string) (store.TransferDetails, error) {
	if err := r.f.hit("transfer"); err != nil {
		return store.TransferDetails{}, err
	}
	return r.inner.transfer(ctx, tid, trfID)
}

func (r *faultRepo) finish(ctx context.Context, k kind, tid tenant.ID, trfID string, now time.Time, stillDue func(store.Transfer) bool) error {
	if err := r.f.hit("finish"); err != nil {
		return err
	}
	return r.inner.finish(ctx, k, tid, trfID, now, stillDue)
}

func (r *faultRepo) scrub(ctx context.Context) error {
	if err := r.f.hit("scrub"); err != nil {
		return err
	}
	return r.inner.scrub(ctx)
}

func (r *faultRepo) tenantIDs(ctx context.Context) ([]tenant.ID, error) {
	if err := r.f.hit("tenantIDs"); err != nil {
		return nil, err
	}
	return r.inner.tenantIDs(ctx)
}

func (r *faultRepo) listEnded(ctx context.Context, tid tenant.ID, endedBefore time.Time, limit int) ([]string, error) {
	if err := r.f.hit("listEnded"); err != nil {
		return nil, err
	}
	return r.inner.listEnded(ctx, tid, endedBefore, limit)
}

func (r *faultRepo) deleteEnded(ctx context.Context, tid tenant.ID, trfID string) error {
	if err := r.f.hit("deleteEnded"); err != nil {
		return err
	}
	return r.inner.deleteEnded(ctx, tid, trfID)
}

func (r *faultRepo) purge(ctx context.Context, p rowPurge, tid tenant.ID, now time.Time) (int64, error) {
	if err := r.f.hit("purge:" + p.name); err != nil {
		return 0, err
	}
	return r.inner.purge(ctx, p, tid, now)
}

func (r *faultRepo) purgeSystem(ctx context.Context, p systemPurge, now time.Time) (int64, error) {
	if err := r.f.hit("purgeSystem:" + p.name); err != nil {
		return 0, err
	}
	return r.inner.purgeSystem(ctx, p, now)
}

func (r *faultRepo) storageRefs(ctx context.Context, tid tenant.ID) (map[string]store.StorageRef, error) {
	if err := r.f.hit("storageRefs"); err != nil {
		return nil, err
	}
	refs, err := r.inner.storageRefs(ctx, tid)
	if r.refsHook != nil && err == nil {
		r.refsHook(refs)
	}
	return refs, err
}

func (r *faultRepo) availableIDs(ctx context.Context, tid tenant.ID) ([]string, error) {
	if err := r.f.hit("availableIDs"); err != nil {
		return nil, err
	}
	return r.inner.availableIDs(ctx, tid)
}

func (r *faultRepo) backupSupported() bool {
	return r.f.hit("backupUnsupported") == nil && r.inner.backupSupported()
}

func (r *faultRepo) backup(ctx context.Context, path string) error {
	if err := r.f.hit("backup"); err != nil {
		return err
	}
	return r.inner.backup(ctx, path)
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
// erasure, like a file that could not be removed), "removeNoop"
// (succeeds without erasing anything) and "activity".
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

func (r faultRemover) TransferActivity(ctx context.Context, tid tenant.ID, files []store.TransferFile, createdAt time.Time) (time.Time, time.Time, error) {
	if err := r.f.hit("activity"); err != nil {
		return time.Time{}, time.Time{}, err
	}
	return r.inner.TransferActivity(ctx, tid, files, createdAt)
}

// faultFiles wraps the storage with the faults "tenantDirs", "list",
// "removeData", "removeCheckpoint", "state" and "removeTemp".
type faultFiles struct {
	inner *storage.Store
	f     *faults
}

func (s faultFiles) TenantDirs() ([]tenant.ID, error) {
	if err := s.f.hit("tenantDirs"); err != nil {
		return nil, err
	}
	return s.inner.TenantDirs()
}

func (s faultFiles) List(tid tenant.ID) ([]storage.Entry, error) {
	if err := s.f.hit("list"); err != nil {
		return nil, err
	}
	return s.inner.List(tid)
}

func (s faultFiles) Remove(tid tenant.ID, name string) error {
	if err := s.f.hit("removeData"); err != nil {
		return err
	}
	return s.inner.Remove(tid, name)
}

func (s faultFiles) RemoveCheckpoint(tid tenant.ID, name string) error {
	if err := s.f.hit("removeCheckpoint"); err != nil {
		return err
	}
	return s.inner.RemoveCheckpoint(tid, name)
}

func (s faultFiles) RemoveState(tid tenant.ID, name string) error {
	if err := s.f.hit("state"); err != nil {
		return err
	}
	return s.inner.RemoveState(tid, name)
}

func (s faultFiles) RemoveTemp(tid tenant.ID, file string) error {
	if err := s.f.hit("removeTemp"); err != nil {
		return err
	}
	return s.inner.RemoveTemp(tid, file)
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

// fakeTimers replaces the real timers: the test fires them per task.
type fakeTimers struct {
	mu      sync.Mutex
	c       map[Task]chan time.Time
	delays  map[Task][]time.Duration
	stopped map[Task]int
	// created receives the task of every timer created.
	created chan Task
}

func newFakeTimers() *fakeTimers {
	ft := &fakeTimers{
		c: map[Task]chan time.Time{}, delays: map[Task][]time.Duration{}, stopped: map[Task]int{},
		created: make(chan Task, 64),
	}
	for _, t := range allTasks {
		ft.c[t] = make(chan time.Time)
	}
	return ft
}

func (ft *fakeTimers) new(t Task, d time.Duration) (<-chan time.Time, func()) {
	ft.mu.Lock()
	ft.delays[t] = append(ft.delays[t], d)
	ft.mu.Unlock()
	ft.created <- t
	return ft.c[t], func() {
		ft.mu.Lock()
		defer ft.mu.Unlock()
		ft.stopped[t]++
	}
}

// lastDelay returns the delay of the last timer of t.
func (ft *fakeTimers) lastDelay(t Task) time.Duration {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	d := ft.delays[t]
	if len(d) == 0 {
		return -1
	}
	return d[len(d)-1]
}

func (ft *fakeTimers) stops(t Task) int {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	return ft.stopped[t]
}

// allTasks are the tasks in their order.
var allTasks = []Task{TaskDeleteAfterDownload, TaskExpire, TaskAbandonedUploads, TaskPurgeRows, TaskOrphans, TaskBackup}

// runResult is the outcome of a scheduled run.
type runResult struct {
	task Task
	err  error
}

// env is a sweeper over a migrated database with tenants A and B, real
// storage, keys and upload engine, wrapped with faults.
type env struct {
	t       *testing.T
	e       storetest.Engine
	db      *store.DB
	vault   *masterkey.Vault
	root    string
	files   *storage.Store
	uploads *upload.Engine
	logs    *logCapture
	f       *faults
	clock   *clock
	repo    *faultRepo
	s       *Sweeper
	a, b    *tenant.Tenant
}

// newEnv builds an env on engine e, with the clock after the grace period
// of transfers downloaded at t0. The store uses the same clock.
func newEnv(t *testing.T, e storetest.Engine) *env {
	t.Helper()
	ctx := context.Background()
	clk := &clock{now: t0.Add(grace + time.Minute)}
	db, err := store.Open(ctx, e.Config(), store.WithClock(clk.Now))
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
	root := t.TempDir()
	files, err := storage.New(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = files.Close() })
	ev := &env{
		t: t, e: e, db: db, vault: vault, root: root, files: files,
		uploads: upload.New(db, vault, files, upload.Options{}),
		logs:    &logCapture{}, f: newFaults(), clock: clk,
	}
	ev.a = ev.newTenant(hostA)
	ev.b = ev.newTenant(hostB)
	ev.s = ev.newSweeper(Options{})
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

// newSweeper returns a sweeper over the env with opts, its clock, its
// logger and its faults.
func (ev *env) newSweeper(opts Options) *Sweeper {
	opts.Now, opts.Logger = ev.clock.Now, slog.New(ev.logs)
	s := New(Deps{
		DB: ev.db, Vault: faultVault{inner: ev.vault, f: ev.f},
		Remover: faultRemover{inner: ev.uploads, f: ev.f}, Files: faultFiles{inner: ev.files, f: ev.f},
	}, opts)
	ev.repo = &faultRepo{inner: s.repo, f: ev.f}
	s.repo = ev.repo
	return s
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

// sweep runs the deletion sweep (TaskDeleteAfterDownload) and checks its
// stats.
func (ev *env) sweep(want stats) {
	ev.t.Helper()
	ev.sweepKind(kindDelete, want)
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
// erased and deleted.
func (ev *env) assertDeleted(fx fixture, before store.TransferDetails) {
	ev.t.Helper()
	ev.assertErased(fx, before, store.TransferDeleted)
}

// assertErased checks that before (read before the run) was fully erased:
// status want, every key destroyed, files, checkpoints and state gone,
// token hash kept (410).
func (ev *env) assertErased(fx fixture, before store.TransferDetails, want store.TransferStatus) {
	ev.t.Helper()
	d := ev.get(fx)
	if d.Status != want {
		ev.t.Fatalf("status = %s, want %s", d.Status, want)
	}
	if d.DownloadTokenKeyID != "" || (before.DownloadTokenKeyID != "" && ev.keyExists(fx.tn, before.DownloadTokenKeyID)) {
		ev.t.Fatal("download token key not destroyed")
	}
	if want != store.TransferRejected && d.EndedAt.IsZero() {
		ev.t.Fatal("EndedAt not set")
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
		if ev.exists(fx.tn, f.StorageName+".ckpt") {
			ev.t.Fatalf("file %d checkpoint still on disk", i)
		}
	}
	if ev.stateExists(fx) {
		ev.t.Fatal("download state still on disk")
	}
	if fx.tokenHash == nil {
		return
	}
	byToken, err := ev.db.Transfers().GetByDownloadTokenHash(context.Background(), fx.tn.ID, fx.tokenHash)
	if err != nil || byToken.ID != fx.id || byToken.Status != want {
		ev.t.Fatalf("token lookup = %s %s, %v; want the %s transfer (410)", byToken.ID, byToken.Status, err, want)
	}
}

// path returns the path of the entry file of the directory of tn.
func (ev *env) path(tn *tenant.Tenant, file string) string {
	return filepath.Join(ev.root, string(tn.ID), file)
}

// exists reports whether the entry file of the directory of tn exists.
func (ev *env) exists(tn *tenant.Tenant, file string) bool {
	ev.t.Helper()
	_, err := os.Lstat(ev.path(tn, file))
	if errors.Is(err, fs.ErrNotExist) {
		return false
	}
	if err != nil {
		ev.t.Fatal(err)
	}
	return true
}

// write creates the entry file of the directory of tn with a modification
// time of mod.
func (ev *env) write(tn *tenant.Tenant, file string, mod time.Time) {
	ev.t.Helper()
	p := ev.path(tn, file)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		ev.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		ev.t.Fatal(err)
	}
	ev.touch(tn, file, mod)
}

// touch sets the modification time of the entry file of tn.
func (ev *env) touch(tn *tenant.Tenant, file string, mod time.Time) {
	ev.t.Helper()
	if err := os.Chtimes(ev.path(tn, file), mod, mod); err != nil {
		ev.t.Fatal(err)
	}
}

// sweepKind runs the erasure task of kind k and checks its stats; the run
// must fail exactly when a transfer was left for the next run.
func (ev *env) sweepKind(k kind, want stats) {
	ev.t.Helper()
	st, err := ev.runSweep(context.Background(), k)
	switch {
	case want.failed > 0 && (err == nil || !strings.Contains(err.Error(), "left for the next run")):
		ev.t.Fatalf("sweep %s = %v, want the transfers left for the next run\nlogs:\n%s", k.task(), err, ev.logs.all())
	case want.failed == 0 && err != nil:
		ev.t.Fatalf("sweep %s: %v\nlogs:\n%s", k.task(), err, ev.logs.all())
	case st != want:
		ev.t.Fatalf("sweep %s stats = %+v, want %+v\nlogs:\n%s", k.task(), st, want, ev.logs.all())
	}
}

// runSweep runs the erasure task of kind k as RunTask does (recording
// LastRun on success) and returns its stats.
func (ev *env) runSweep(ctx context.Context, k kind) (stats, error) {
	var st stats
	err := ev.s.run(ctx, k.task(), func(ctx context.Context) error {
		var err error
		st, err = ev.s.sweepTask(ctx, k)
		return err
	})
	return st, err
}

// runTask runs the task name and fails on error.
func (ev *env) runTask(name Task) {
	ev.t.Helper()
	if err := ev.s.RunTask(context.Background(), name); err != nil {
		ev.t.Fatalf("RunTask(%s): %v\nlogs:\n%s", name, err, ev.logs.all())
	}
}

// usedBytes returns the quota used by tn.
func (ev *env) usedBytes(tn *tenant.Tenant) int64 {
	ev.t.Helper()
	var n int64
	ev.tx(tn, func(tx *store.ScopedTx) error {
		var err error
		n, err = ev.db.Transfers().UsedBytesTx(context.Background(), tx)
		return err
	})
	return n
}

// uploading stores a transfer of tn still uploading, created at createdAt,
// with nDone completed files and nOpen incomplete ones; each incomplete
// file has a checkpoint modified at checkpointAt.
func (ev *env) uploading(tn *tenant.Tenant, nDone, nOpen int, createdAt, checkpointAt time.Time) fixture {
	ev.t.Helper()
	ctx := context.Background()
	trfID := id.New(id.Transfer)
	var open []string
	ev.tx(tn, func(tx *store.ScopedTx) error {
		files := make([]store.TransferFile, 0, nDone+nOpen)
		for i := range nDone + nOpen {
			f, err := ev.storeFile(ctx, tx, tn)
			if err != nil {
				return err
			}
			f.Name = fmt.Sprintf("file-%d.bin", i)
			f.UploadedAt = createdAt
			if i >= nDone {
				f.UploadedAt, f.SHA256, f.CiphertextSize = time.Time{}, "", 0
				open = append(open, f.StorageName)
			}
			files = append(files, f)
		}
		tr := store.Transfer{
			ID: trfID, SenderEmail: alice, SenderKind: store.DepositorInternal, ExpiryDays: 7, CreatedAt: createdAt,
		}
		return ev.db.Transfers().CreateTx(ctx, tx, tr, []string{dave}, files)
	})
	for _, name := range open {
		ev.write(tn, name+".ckpt", checkpointAt)
	}
	return fixture{tn: tn, id: trfID}
}

// scanning stores a transfer of tn finalized at finalizedAt, still
// scanning, with nFiles files.
func (ev *env) scanning(tn *tenant.Tenant, nFiles int, finalizedAt time.Time) fixture {
	ev.t.Helper()
	fx := ev.uploading(tn, nFiles, 0, finalizedAt.Add(-time.Hour), time.Time{})
	ev.tx(tn, func(tx *store.ScopedTx) error {
		return ev.db.Transfers().FinalizeTx(context.Background(), tx, fx.id, finalizedAt)
	})
	return fx
}

// rejected stores a rejected transfer of tn whose nFiles files keep their
// data key (scan_error), rejected at the current time of the clock.
func (ev *env) rejected(tn *tenant.Tenant, nFiles int) fixture {
	ev.t.Helper()
	fx := ev.scanning(tn, nFiles, t0.Add(-time.Hour))
	ev.tx(tn, func(tx *store.ScopedTx) error {
		return ev.db.Transfers().MarkRejectedTx(context.Background(), tx, fx.id)
	})
	return fx
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
