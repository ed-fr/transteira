package upload

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
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
)

// errBoom is the error injected by the fault hooks.
var errBoom = errors.New("boom")

// hookFunc decides whether the operation op fails.
type hookFunc func(op string) error

// faults holds a hook shared by the fault-injecting wrappers.
type faults struct {
	mu   sync.Mutex
	hook hookFunc
}

// set replaces the hook (nil disables the faults).
func (f *faults) set(h hookFunc) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hook = h
}

// fault returns the error injected for op, if any.
func (f *faults) fault(op string) error {
	f.mu.Lock()
	h := f.hook
	f.mu.Unlock()
	if h == nil {
		return nil
	}
	return h(op)
}

// failOn returns a hook failing every call of the given operations.
func failOn(ops ...string) hookFunc {
	return func(op string) error {
		for _, o := range ops {
			if o == op {
				return errBoom
			}
		}
		return nil
	}
}

// failNth returns a hook failing the n-th call (from 1) of op only.
func failNth(op string, n int) hookFunc {
	var mu sync.Mutex
	calls := 0
	return func(o string) error {
		if o != op {
			return nil
		}
		mu.Lock()
		defer mu.Unlock()
		calls++
		if calls == n {
			return errBoom
		}
		return nil
	}
}

// faultFiles wraps the file store with fault injection.
type faultFiles struct {
	fileStore
	*faults
}

func (f faultFiles) Create(tid tenant.ID, name string) (*os.File, error) {
	if err := f.fault("create"); err != nil {
		return nil, err
	}
	return f.fileStore.Create(tid, name)
}

func (f faultFiles) OpenAppend(tid tenant.ID, name string) (*os.File, int64, error) {
	if err := f.fault("openappend"); err != nil {
		return nil, 0, err
	}
	return f.fileStore.OpenAppend(tid, name)
}

func (f faultFiles) Remove(tid tenant.ID, name string) error {
	if err := f.fault("remove"); err != nil {
		return err
	}
	return f.fileStore.Remove(tid, name)
}

func (f faultFiles) WriteCheckpoint(tid tenant.ID, name string, data []byte) error {
	if err := f.fault("writeckpt"); err != nil {
		return err
	}
	return f.fileStore.WriteCheckpoint(tid, name, data)
}

func (f faultFiles) ReadCheckpoint(tid tenant.ID, name string) ([]byte, time.Time, error) {
	if err := f.fault("readckpt"); err != nil {
		return nil, time.Time{}, err
	}
	return f.fileStore.ReadCheckpoint(tid, name)
}

func (f faultFiles) CheckpointModTime(tid tenant.ID, name string) (time.Time, error) {
	if err := f.fault("ckpttime"); err != nil {
		return time.Time{}, err
	}
	return f.fileStore.CheckpointModTime(tid, name)
}

func (f faultFiles) RemoveCheckpoint(tid tenant.ID, name string) error {
	if err := f.fault("removeckpt"); err != nil {
		return err
	}
	return f.fileStore.RemoveCheckpoint(tid, name)
}

func (f faultFiles) Sync(file *os.File) error {
	if err := f.fault("sync"); err != nil {
		return err
	}
	return f.fileStore.Sync(file)
}

func (f faultFiles) SyncDir(tid tenant.ID) error {
	if err := f.fault("syncdir"); err != nil {
		return err
	}
	return f.fileStore.SyncDir(tid)
}

// faultMeta wraps the metadata store with fault injection; mutate, when
// set, alters the uploads it returns.
type faultMeta struct {
	metaStore
	*faults
	mutate *func(*store.FileUpload)
}

func (m faultMeta) GetByUploadID(ctx context.Context, tid tenant.ID, uploadID string) (store.FileUpload, error) {
	if err := m.fault("get"); err != nil {
		return store.FileUpload{}, err
	}
	u, err := m.metaStore.GetByUploadID(ctx, tid, uploadID)
	if err == nil && *m.mutate != nil {
		(*m.mutate)(&u)
	}
	return u, err
}

func (m faultMeta) ListByTransfer(ctx context.Context, tid tenant.ID, trfID string) ([]store.TransferFile, error) {
	if err := m.fault("list"); err != nil {
		return nil, err
	}
	return m.metaStore.ListByTransfer(ctx, tid, trfID)
}

func (m faultMeta) CompleteUpload(ctx context.Context, tid tenant.ID, fileID, sha string, size int64, now time.Time) error {
	if err := m.fault("complete"); err != nil {
		return err
	}
	return m.metaStore.CompleteUpload(ctx, tid, fileID, sha, size, now)
}

func (m faultMeta) ReplaceDEKTx(ctx context.Context, tx *store.ScopedTx, fileID, keyID, name string) error {
	if err := m.fault("replacedek"); err != nil {
		return err
	}
	return m.metaStore.ReplaceDEKTx(ctx, tx, fileID, keyID, name)
}

func (m faultMeta) DeleteTx(ctx context.Context, tx *store.ScopedTx, fileID string) error {
	if err := m.fault("deletefile"); err != nil {
		return err
	}
	return m.metaStore.DeleteTx(ctx, tx, fileID)
}

// faultVault wraps the vault with fault injection.
type faultVault struct {
	keyVault
	*faults
}

func (v faultVault) Open(ctx context.Context, tid tenant.ID, p crypto.Purpose, wkID string) ([]byte, error) {
	if err := v.fault("open"); err != nil {
		return nil, err
	}
	return v.keyVault.Open(ctx, tid, p, wkID)
}

func (v faultVault) NewDEKTx(ctx context.Context, tx *store.ScopedTx) (string, []byte, error) {
	if err := v.fault("newdek"); err != nil {
		return "", nil, err
	}
	return v.keyVault.NewDEKTx(ctx, tx)
}

func (v faultVault) DestroyTx(ctx context.Context, tx *store.ScopedTx, wkID string) error {
	if err := v.fault("destroy"); err != nil {
		return err
	}
	return v.keyVault.DestroyTx(ctx, tx, wkID)
}

func (v faultVault) Scrub(ctx context.Context) error {
	if err := v.fault("scrub"); err != nil {
		return err
	}
	return v.keyVault.Scrub(ctx)
}

// syncBuffer is a bytes.Buffer safe for concurrent use (log output).
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

// failWriter fails every write once more than limit bytes were written.
type failWriter struct {
	w     io.Writer
	limit int64
	n     int64
}

func (f *failWriter) Write(p []byte) (int, error) {
	if f.n+int64(len(p)) > f.limit {
		return 0, errBoom
	}
	n, err := f.w.Write(p)
	f.n += int64(n)
	return n, err
}

// smallChunks is crypto.NewWriter with the smallest chunk size, so that
// KiB-sized test files span several chunks.
func smallChunks(dst io.Writer, dek []byte, tenantID, fileID string, _ ...crypto.Option) (*crypto.Writer, error) {
	return crypto.NewWriter(dst, dek, tenantID, fileID, crypto.WithChunkSize(crypto.MinChunkSize))
}

// env is an engine over a migrated database and a data directory, with
// tenants a and b, and fault injection on every dependency.
type env struct {
	db     *store.DB
	vault  *masterkey.Vault
	dir    string
	faults *faults
	mutate func(*store.FileUpload)
	eng    *Engine
	logs   *syncBuffer
	a, b   tenant.ID
}

// newEnv builds an env on engine e.
func newEnv(t *testing.T, e storetest.Engine) *env {
	t.Helper()
	ctx := t.Context()
	db, err := store.Open(ctx, e.Config())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	kr, err := masterkey.New(masterkeytest.Key(t, "upload"), nil)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	files, err := storage.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = files.Close() })
	ev := &env{db: db, vault: masterkey.NewVault(db, kr, nil), dir: dir, faults: &faults{}, logs: &syncBuffer{}}
	base := New(db, ev.vault, files, Options{})
	ev.eng = newEngine(
		faultMeta{metaStore: base.meta, faults: ev.faults, mutate: &ev.mutate},
		faultVault{keyVault: ev.vault, faults: ev.faults},
		faultFiles{fileStore: files, faults: ev.faults},
		Options{CheckpointEvery: 1 << 20, Logger: slog.New(slog.NewTextHandler(ev.logs, nil))},
	)
	ev.eng.newWriter = smallChunks
	ev.a = ev.newTenant(t, "transfer.entity-a.example.com")
	ev.b = ev.newTenant(t, "transfer.entity-b.example.com")
	return ev
}

// newTenant creates a tenant served by fqdn.
func (ev *env) newTenant(t *testing.T, fqdn string) tenant.ID {
	t.Helper()
	tn, err := ev.db.Tenants().Create(t.Context(), &tenant.Tenant{
		Name: "Entity " + fqdn, FQDN: fqdn, DefaultLanguage: "en",
		MaxTransferBytes: 1 << 30, StorageQuotaBytes: 100 << 30,
	})
	if err != nil {
		t.Fatalf("Create(%s): %v", fqdn, err)
	}
	return tn.ID
}

// internal is the principal of the internal sender of the tests.
var internal = Principal{Email: "Alice@Entity-A.example.com", Kind: store.DepositorInternal}

// external returns an external principal holding a new invitation of tid.
func (ev *env) external(t *testing.T, tid tenant.ID) Principal {
	t.Helper()
	inv := store.Invitation{
		ID: id.New(id.Invitation), TokenHash: randomBytes(t, store.TokenHashSize),
		Email: "bob@partner.example.org", InvitedBy: "alice@entity-a.example.com",
	}
	if err := ev.db.Invitations().Create(t.Context(), tid, inv); err != nil {
		t.Fatalf("Invitations.Create: %v", err)
	}
	return Principal{Email: "bob@partner.example.org", Kind: store.DepositorExternal, InvitationID: inv.ID}
}

// token returns the principal of a new usable API token of tid (its
// transfers are sent as alice, the address of internal).
func (ev *env) token(t *testing.T, tid tenant.ID) Principal {
	t.Helper()
	tok := store.APIToken{
		ID: id.New(id.APIToken), Name: "scanner", Prefix: "tt_test", TokenHash: randomBytes(t, store.TokenHashSize),
		AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}, CreatedBy: "admin",
	}
	if _, err := ev.db.APITokens().Create(t.Context(), tid, tok); err != nil {
		t.Fatalf("APITokens.Create: %v", err)
	}
	return Principal{Kind: store.DepositorInternal, APITokenID: tok.ID}
}

// randomBytes returns n random bytes.
func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// upl is an upload created by the tests.
type upl struct {
	tid      tenant.ID
	id       string
	fileID   string
	transfer string
	p        Principal
	size     int64
}

// newUpload creates a transfer of tid sent by p with one incomplete file of
// size bytes, created at createdAt (now when zero).
func (ev *env) newUpload(t *testing.T, tid tenant.ID, p Principal, size int64, createdAt time.Time) upl {
	t.Helper()
	return ev.newTransfer(t, tid, p, []int64{size}, createdAt)[0]
}

// newTransfer creates a transfer of tid sent by p with one incomplete file
// per size, created at createdAt (now when zero), and returns its uploads.
func (ev *env) newTransfer(t *testing.T, tid tenant.ID, p Principal, sizes []int64, createdAt time.Time) []upl {
	t.Helper()
	ctx := t.Context()
	if createdAt.IsZero() {
		createdAt = time.Now()
	}
	trfID := id.New(id.Transfer)
	ups := make([]upl, len(sizes))
	for i, size := range sizes {
		uploadID, err := id.NewUploadToken()
		if err != nil {
			t.Fatal(err)
		}
		ups[i] = upl{tid: tid, id: uploadID, fileID: id.New(id.File), transfer: trfID, p: p, size: size}
	}
	s, err := ev.db.Scoped(tid)
	if err != nil {
		t.Fatal(err)
	}
	err = s.Tx(ctx, func(tx *store.ScopedTx) error {
		files := make([]store.TransferFile, len(ups))
		for i, u := range ups {
			wk, dek, err := ev.vault.NewDEKTx(ctx, tx)
			if err != nil {
				return err
			}
			clear(dek)
			files[i] = store.TransferFile{
				ID: u.fileID, Name: "data.bin", Size: u.size, DEKKeyID: wk, StorageName: storage.NewName(), UploadID: u.id,
			}
		}
		sender := p.Email
		if p.APITokenID != "" {
			sender = internal.Email
		}
		tr := store.Transfer{
			ID: trfID, SenderEmail: sender, SenderKind: p.Kind, InvitationID: p.InvitationID,
			APITokenID: p.APITokenID, ExpiryDays: 7, CreatedAt: createdAt,
		}
		return ev.db.Transfers().CreateTx(ctx, tx, tr, []string{"carol@partner.example.org"}, files)
	})
	if err != nil {
		t.Fatalf("create transfer: %v", err)
	}
	return ups
}

// file returns the current row of the file of u.
func (ev *env) file(t *testing.T, u upl) store.TransferFile {
	t.Helper()
	fu, err := ev.db.TransferFiles().GetByUploadID(t.Context(), u.tid, u.id)
	if err != nil {
		t.Fatalf("GetByUploadID: %v", err)
	}
	return fu.File
}

// path returns the path of the encrypted file of f, with extension ext.
func (ev *env) path(tid tenant.ID, f store.TransferFile, ext string) string {
	return filepath.Join(ev.dir, string(tid), f.StorageName+ext)
}

// decrypt returns the plaintext of the completed file of u.
func (ev *env) decrypt(t *testing.T, u upl) []byte {
	t.Helper()
	f := ev.file(t, u)
	if !f.Completed() {
		t.Fatal("file not completed")
	}
	dek, err := ev.vault.Open(t.Context(), u.tid, crypto.PurposeDEK, f.DEKKeyID)
	if err != nil {
		t.Fatalf("Vault.Open: %v", err)
	}
	src, err := os.Open(ev.path(u.tid, f, ".ttef"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = src.Close() }()
	info, err := src.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != f.CiphertextSize {
		t.Fatalf("ciphertext size on disk %d, recorded %d", info.Size(), f.CiphertextSize)
	}
	r, err := crypto.NewReader(src, dek, string(u.tid), f.ID)
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	plain, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	return plain
}

// appendOK appends data at offset and fails the test on error.
func (ev *env) appendOK(t *testing.T, u upl, offset int64, data []byte) Status {
	t.Helper()
	st, err := ev.eng.Append(t.Context(), u.tid, u.p, u.id, offset, bytes.NewReader(data))
	if err != nil {
		t.Fatalf("Append(offset %d, %d bytes): %v", offset, len(data), err)
	}
	return st
}

// statusOK returns the status of u and fails the test on error.
func (ev *env) statusOK(t *testing.T, u upl) Status {
	t.Helper()
	st, err := ev.eng.Status(t.Context(), u.tid, u.p, u.id)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	return st
}

// pieceReader returns at most n bytes per Read.
type pieceReader struct {
	r io.Reader
	n int
}

func (p *pieceReader) Read(b []byte) (int, error) {
	if len(b) > p.n {
		b = b[:p.n]
	}
	return p.r.Read(b)
}

// errReader returns err on every Read.
type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }

// run runs fn as a sub-test on every engine with a fresh env.
func run(t *testing.T, fn func(t *testing.T, ev *env)) {
	t.Helper()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		fn(t, newEnv(t, e))
	})
}

// expectErr fails the test unless errors.Is(err, want).
func expectErr(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
}
