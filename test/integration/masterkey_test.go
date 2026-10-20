package integration_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/app"
	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/masterkey"
	"github.com/ed-fr/transteira/internal/masterkey/masterkeytest"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// End-to-end tests of the encryption at rest and of the master key life
// cycle (CLAUDE.md section 16.1; threat model T-28 to T-37, T-116): the
// startup check of app.Run, the resumable rotation (interrupted, then
// resumed by the real rotate-master-key command), the crypto-erase and a
// resumable encrypted upload on a real file.

// keyFile is a master key file written for a test.
type keyFile struct {
	path string
	id   string
	// leaks are the encodings of the key that must never appear in an error,
	// a log line or a command output.
	leaks []string
}

// newKeyFile writes a deterministic master key derived from label into a
// new directory, outside every data volume (CLAUDE.md section 16.1).
func newKeyFile(t *testing.T, label string) keyFile {
	t.Helper()
	path, keyID := masterkeytest.WriteLabeledKeyFile(t, t.TempDir(), label)
	raw := masterkeytest.Raw(label)
	return keyFile{path: path, id: keyID, leaks: []string{
		masterkeytest.Text(label), base64.RawURLEncoding.EncodeToString(raw[:]), base64.RawStdEncoding.EncodeToString(raw[:]),
		hex.EncodeToString(raw[:]), strings.ToUpper(hex.EncodeToString(raw[:])), string(raw[:16]),
	}}
}

// assertNoKeyMaterial fails when s contains an encoding of one of keys.
func assertNoKeyMaterial(t *testing.T, what, s string, keys ...keyFile) {
	t.Helper()
	for _, k := range keys {
		for _, leak := range k.leaks {
			if strings.Contains(s, leak) {
				t.Errorf("%s contains the bytes of master key %s", what, k.id)
			}
		}
	}
}

// withKeys returns a copy of env using current as TT_MASTER_KEY_FILE and,
// when not nil, next as TT_MASTER_KEY_NEW_FILE.
func withKeys(env map[string]string, current keyFile, next *keyFile) map[string]string {
	out := make(map[string]string, len(env)+1)
	for k, v := range env {
		out[k] = v
	}
	out[config.EnvMasterKeyFile] = current.path
	delete(out, config.EnvMasterKeyNewFile)
	if next != nil {
		out[config.EnvMasterKeyNewFile] = next.path
	}
	return out
}

// runningApp is an app.Run started by startApp.
type runningApp struct {
	log    *watchBuffer
	cancel context.CancelFunc
	done   chan error
}

// startApp runs app.Run with env. When the server starts it returns the
// running app; when app.Run fails at start-up it returns the application
// log and the error.
func startApp(t *testing.T, env map[string]string) (*runningApp, string, error) {
	t.Helper()
	cfg := loadConfig(t, env)
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &runningApp{log: newWatchBuffer(), cancel: cancel, done: make(chan error, 1)}
	go func() { r.done <- app.Run(ctx, cfg, app.WithListener(ln), app.WithLogOutput(r.log)) }()
	select {
	case <-r.log.wait("HTTP server listening"):
		t.Cleanup(func() { r.stop(t) })
		return r, r.log.String(), nil
	case err := <-r.done:
		cancel()
		if err == nil {
			t.Fatalf("app.Run returned nil before listening\napp log:\n%s", r.log)
		}
		return nil, r.log.String(), err
	case <-time.After(waitTimeout):
		cancel()
		t.Fatalf("app.Run neither started nor failed within %s\napp log:\n%s", waitTimeout, r.log)
		return nil, "", nil
	}
}

// stop shuts the app down and asserts a clean exit. It is idempotent.
func (r *runningApp) stop(t *testing.T) {
	t.Helper()
	if r.done == nil {
		return
	}
	r.cancel()
	select {
	case err := <-r.done:
		if err != nil {
			t.Errorf("app.Run = %v after shutdown, want nil\napp log:\n%s", err, r.log)
		}
	case <-time.After(waitTimeout):
		t.Errorf("app.Run did not return within %s", waitTimeout)
	}
	r.done = nil
}

// mustStart starts the app with env and fails the test if it is refused.
func mustStart(t *testing.T, what string, env map[string]string) *runningApp {
	t.Helper()
	r, log, err := startApp(t, env)
	if err != nil {
		t.Fatalf("%s: app.Run refused to start: %v\napp log:\n%s", what, err, log)
	}
	return r
}

// mustRefuse starts the app with env, expects a master key check refusal
// for reason naming wantKeyID, and checks that neither the error nor the
// log carries key material.
func mustRefuse(t *testing.T, what string, env map[string]string, reason masterkey.CheckReason, wantKeyID string, keys ...keyFile) {
	t.Helper()
	r, log, err := startApp(t, env)
	if err == nil {
		r.stop(t)
		t.Fatalf("%s: app.Run started, want a master key check refusal", what)
	}
	var ce *masterkey.CheckError
	if !errors.As(err, &ce) || !errors.Is(err, masterkey.ErrKeyCheck) {
		t.Fatalf("%s: app.Run = %v, want a *masterkey.CheckError", what, err)
	}
	if ce.Reason != reason || !slices.Contains(ce.KeyIDs, wantKeyID) {
		t.Errorf("%s: refusal reason %q for %v, want %q naming %s", what, ce.Reason, ce.KeyIDs, reason, wantKeyID)
	}
	if !strings.Contains(err.Error(), wantKeyID) || !strings.Contains(err.Error(), masterkey.DocLink) {
		t.Errorf("%s: error %q does not name %s and the documentation", what, err, wantKeyID)
	}
	assertNoKeyMaterial(t, what+": error", err.Error(), keys...)
	assertNoKeyMaterial(t, what+": app log", log, keys...)
}

// keyStore opens the engine's database (already migrated) with the keyring
// made of current and, when not nil, next.
type keyStore struct {
	db    *store.DB
	kr    *masterkey.Keyring
	vault *masterkey.Vault
}

func openKeyStore(t *testing.T, e storetest.Engine, current keyFile, next *keyFile) *keyStore {
	t.Helper()
	cfg := e.Config()
	cfg.MasterKeyFile = current.path
	if next != nil {
		cfg.MasterKeyNewFile = next.path
	}
	kr, err := masterkey.Load(cfg)
	if err != nil {
		t.Fatalf("masterkey.Load: %v", err)
	}
	t.Cleanup(kr.Close)
	db, err := store.Open(context.Background(), cfg)
	if err != nil {
		t.Fatalf("store.Open(%s): %v", e.Name, err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return &keyStore{db: db, kr: kr, vault: masterkey.NewVault(db, kr, nil)}
}

// encryptedFile is a data key of a tenant and a file encrypted with it.
type encryptedFile struct {
	tid        tenant.ID
	wkID       string
	fileID     string
	ciphertext []byte
	plaintext  []byte
}

// newEncryptedFile creates a data key for tid through the vault and
// encrypts a distinct plaintext with it.
func newEncryptedFile(t *testing.T, ks *keyStore, tid tenant.ID, n int) encryptedFile {
	t.Helper()
	wkID, dek, err := ks.vault.NewDEK(context.Background(), tid)
	if err != nil {
		t.Fatalf("NewDEK(%s): %v", tid, err)
	}
	defer clear(dek)
	f := encryptedFile{tid: tid, wkID: wkID, fileID: id.New(id.File)}
	f.plaintext = bytes.Repeat([]byte("file "+f.fileID+" of "+string(tid)+"; "), 50+n)
	var buf bytes.Buffer
	w, err := crypto.NewWriter(&buf, dek, string(tid), f.fileID, crypto.WithChunkSize(crypto.MinChunkSize))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(f.plaintext); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	f.ciphertext = buf.Bytes()
	return f
}

// assertDecrypts checks that every file still decrypts with its data key
// opened through ks.
func assertDecrypts(t *testing.T, what string, ks *keyStore, files []encryptedFile) {
	t.Helper()
	for _, f := range files {
		dek, err := ks.vault.Open(context.Background(), f.tid, crypto.PurposeDEK, f.wkID)
		if err != nil {
			t.Errorf("%s: Open(%s) = %v", what, f.wkID, err)
			continue
		}
		r, err := crypto.NewReader(bytes.NewReader(f.ciphertext), dek, string(f.tid), f.fileID)
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(r)
		if err != nil || !bytes.Equal(got, f.plaintext) {
			t.Errorf("%s: file %s does not decrypt to its plaintext: %v", what, f.fileID, err)
		}
		clear(dek)
	}
}

// keyIDOf returns the master key the row wkID of tid is wrapped under.
func keyIDOf(t *testing.T, ks *keyStore, tid tenant.ID, wkID string) string {
	t.Helper()
	row, err := ks.db.WrappedKeys().Get(context.Background(), tid, wkID)
	if err != nil {
		t.Fatalf("WrappedKeys.Get(%s): %v", wkID, err)
	}
	return row.KeyID
}

// runRotateCommand runs "transteira rotate-master-key" with env (and no
// other TT_ variable of the test process) and returns its exit code and
// outputs.
func runRotateCommand(t *testing.T, bin string, env map[string]string, args ...string) (int, string, string) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), bin, append([]string{"rotate-master-key"}, args...)...)
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(strings.ToUpper(kv), "TT_") {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		return 0, stdout.String(), stderr.String()
	case errors.As(err, &exitErr):
		return exitErr.ExitCode(), stdout.String(), stderr.String()
	default:
		t.Fatalf("run rotate-master-key: %v", err)
		return -1, "", ""
	}
}

// TestMasterKeyLifecycle walks the whole life of a master key with the real
// server start-up (app.Run) and the real rotate-master-key command:
//
//  1. the server starts with K1 and data keys are created for two tenants;
//  2. a restart with K2 alone is refused, naming K1, without key bytes;
//  3. the server starts with K1 and TT_MASTER_KEY_NEW_FILE=K2, and keeps
//     serving while a rotation is interrupted mid-way (context canceled
//     after the first batch), then resumed and completed by the command;
//  4. a restart with K1 is refused (rotation completed), a restart with K2
//     alone succeeds, and every data key opens and decrypts its file.
func TestMasterKeyLifecycle(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the transteira binary")
	}
	t.Parallel()
	bin := buildBinary(t, t.TempDir())
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		k1, k2 := newKeyFile(t, "K1"), newKeyFile(t, "K2")
		a, b := createTenants(t, e)
		base := testEnv(t, e, serverOptions{clamd: fakeClamd(t)})
		envK1 := withKeys(base, k1, nil)

		// 1. First start with K1 registers it as the active key.
		mustStart(t, "first start with K1", envK1).stop(t)
		ks1 := openKeyStore(t, e, k1, nil)
		if active, err := ks1.db.MasterKeys().Active(ctx); err != nil || active != k1.id {
			t.Fatalf("active master key after the first start = %q, %v; want K1 %s", active, err, k1.id)
		}
		var files []encryptedFile
		for i := range 4 {
			files = append(files, newEncryptedFile(t, ks1, a.ID, i), newEncryptedFile(t, ks1, b.ID, i))
		}
		secretA, err := ks1.vault.Seal(ctx, a.ID, crypto.PurposeSecret, []byte("smtp password of entity A"))
		if err != nil {
			t.Fatal(err)
		}
		underK1 := int64(len(files) + 1)

		// 2. K2 alone: the wrapped keys need K1.
		mustRefuse(t, "restart with K2 only", withKeys(base, k2, nil), masterkey.ReasonMissingKey, k1.id, k1, k2)

		// 3. K1 current, K2 new: the server starts and new keys go under K2.
		envRotating := withKeys(base, k1, &k2)
		srv := mustStart(t, "start with K1 and new key K2", envRotating)
		ks12 := openKeyStore(t, e, k1, &k2)
		duringA := newEncryptedFile(t, ks12, a.ID, 10)
		duringB := newEncryptedFile(t, ks12, b.ID, 11)
		for _, f := range []encryptedFile{duringA, duringB} {
			if got := keyIDOf(t, ks12, f.tid, f.wkID); got != k2.id {
				t.Errorf("key created during the rotation is wrapped under %s, want K2 %s", got, k2.id)
			}
		}
		files = append(files, duringA, duringB)

		// Interrupted rotation: cancel the context once the first batch is
		// committed.
		rotCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		const batch = 3
		rot, err := masterkey.Rotate(rotCtx, ks12.db, ks12.kr, nil, masterkey.Options{
			BatchSize: batch,
			OnProgress: func(r store.Rotation) {
				if r.RewrappedKeys > 0 {
					cancel()
				}
			},
		})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("interrupted Rotate = %+v, %v; want context.Canceled", rot, err)
		}
		running, err := ks12.db.KeyRotations().Running(ctx)
		if err != nil {
			t.Fatalf("no running rotation after the interruption: %v", err)
		}
		if running.ID != rot.ID || running.FromKeyID != k1.id || running.ToKeyID != k2.id ||
			running.TotalKeys != underK1 || running.RewrappedKeys != batch {
			t.Errorf("running rotation = %+v; want %s from K1 to K2, %d total, %d rewrapped", running, rot.ID, underK1, batch)
		}
		if left, err := ks12.db.WrappedKeys().CountByKey(ctx, k1.id); err != nil || left != underK1-batch {
			t.Errorf("keys left under K1 = %d, %v; want %d", left, err, underK1-batch)
		}
		// Mid-rotation, every key opens with one key or the other ...
		assertDecrypts(t, "mid-rotation", ks12, files)
		// ... and dropping either key is refused.
		mustRefuse(t, "mid-rotation restart with K1 only", envK1, masterkey.ReasonRotationMismatch, k2.id, k1, k2)
		mustRefuse(t, "mid-rotation restart with K2 only", withKeys(base, k2, nil), masterkey.ReasonMissingKey, k1.id, k1, k2)

		// Resume with the real command while the server keeps running.
		code, out, errOut := runRotateCommand(t, bin, envRotating, "-batch-size", "2")
		if code != 0 {
			t.Fatalf("rotate-master-key (resume) exit %d\nstdout: %s\nstderr: %s", code, out, errOut)
		}
		if !strings.Contains(out, "Rotation "+rot.ID+" completed") || !strings.Contains(errOut, "resuming master key rotation") {
			t.Errorf("rotate-master-key did not resume rotation %s\nstdout: %s\nstderr: %s", rot.ID, out, errOut)
		}
		assertNoKeyMaterial(t, "rotate-master-key output", out+errOut, k1, k2)
		srv.stop(t)

		done, err := ks12.db.KeyRotations().Get(ctx, rot.ID)
		if err != nil || done.Status != store.RotationCompleted || done.RewrappedKeys != underK1 || done.TotalKeys != underK1 {
			t.Errorf("rotation after resume = %+v, %v; want completed with %d keys", done, err, underK1)
		}
		if left, err := ks12.db.WrappedKeys().CountByKey(ctx, k1.id); err != nil || left != 0 {
			t.Errorf("keys left under K1 after the rotation = %d, %v", left, err)
		}
		keys, err := ks12.db.MasterKeys().List(ctx)
		if err != nil {
			t.Fatal(err)
		}
		status := map[string]store.MasterKeyStatus{}
		for _, k := range keys {
			status[k.ID] = k.Status
		}
		if len(keys) != 2 || status[k1.id] != store.MasterKeyRetired || status[k2.id] != store.MasterKeyActive {
			t.Errorf("master keys after the rotation = %+v; want K1 retired, K2 active", keys)
		}

		// 4. K1 is refused, K2 alone starts.
		mustRefuse(t, "restart with K1 after the rotation", envK1, masterkey.ReasonRotationCompleted, k2.id, k1, k2)
		mustRefuse(t, "restart with K1 and K2 after the rotation", envRotating, masterkey.ReasonRotationCompleted, k2.id, k1, k2)
		envK2 := withKeys(base, k2, nil)
		mustStart(t, "restart with K2 after the rotation", envK2).stop(t)

		ks2 := openKeyStore(t, e, k2, nil)
		assertDecrypts(t, "after the rotation, with K2 only", ks2, files)
		if got, err := ks2.vault.Open(ctx, a.ID, crypto.PurposeSecret, secretA); err != nil || string(got) != "smtp password of entity A" {
			t.Errorf("secret after the rotation = %q, %v", got, err)
		}
		// The rotation preserved the tenant isolation of the keys.
		if _, err := ks2.vault.Open(ctx, b.ID, crypto.PurposeDEK, files[0].wkID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("B opens A's rewrapped key: %v", err)
		}

		// Running the command again is refused: the rotation is completed.
		code, out, errOut = runRotateCommand(t, bin, envRotating)
		if code != 1 || !strings.Contains(errOut, "is completed") {
			t.Errorf("rotate-master-key after completion: exit %d\nstdout: %s\nstderr: %s", code, out, errOut)
		}
	})
}

// TestCryptoErase checks the cryptographic erasure (CLAUDE.md sections
// 16.1 and 20): once its data key is destroyed through the Vault, a file
// encrypted on disk can no longer be decrypted from the live system, and
// deleting a tenant erases every wrapped key it owns, and only those.
func TestCryptoErase(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		k1 := newKeyFile(t, "K1")
		a, b := createTenants(t, e)
		ks := openKeyStore(t, e, k1, nil)
		dir := t.TempDir()

		// Encrypt a file of A on disk with a fresh data key.
		wkID, dek, err := ks.vault.NewDEK(ctx, a.ID)
		if err != nil {
			t.Fatal(err)
		}
		fileID := id.New(id.File)
		path := filepath.Join(dir, string(a.ID), fileID)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		plaintext := bytes.Repeat([]byte("personal data to erase; "), 3000)
		writeEncrypted(t, path, dek, string(a.ID), fileID, plaintext)
		clear(dek)

		// Before the erasure, the key reopens and the file decrypts.
		reopened, err := ks.vault.Open(ctx, a.ID, crypto.PurposeDEK, wkID)
		if err != nil {
			t.Fatal(err)
		}
		if got := readEncrypted(t, path, reopened, string(a.ID), fileID); !bytes.Equal(got, plaintext) {
			t.Fatal("the file does not decrypt before the erasure")
		}
		clear(reopened)

		if err := ks.vault.Destroy(ctx, a.ID, wkID); err != nil {
			t.Fatalf("Destroy: %v", err)
		}
		if got, err := ks.vault.Open(ctx, a.ID, crypto.PurposeDEK, wkID); !errors.Is(err, store.ErrNotFound) || got != nil {
			t.Fatalf("Open after Destroy = %d bytes, %v; want store.ErrNotFound", len(got), err)
		}
		// The ciphertext is still on disk (a backup copy, say) but nothing in
		// the database can decrypt it any more.
		if _, err := os.Stat(path); err != nil {
			t.Fatal(err)
		}
		if n, err := ks.db.WrappedKeys().CountByKey(ctx, k1.id); err != nil || n != 0 {
			t.Errorf("wrapped keys left after the erasure = %d, %v", n, err)
		}

		// Deleting a tenant cascades to its wrapped keys, and only to them.
		var keysA, keysB []string
		for range 3 {
			wa, err := ks.vault.Seal(ctx, a.ID, crypto.PurposeDEK, bytes.Repeat([]byte{0xA}, crypto.DEKSize))
			if err != nil {
				t.Fatal(err)
			}
			wb, err := ks.vault.Seal(ctx, b.ID, crypto.PurposeDEK, bytes.Repeat([]byte{0xB}, crypto.DEKSize))
			if err != nil {
				t.Fatal(err)
			}
			keysA, keysB = append(keysA, wa), append(keysB, wb)
		}
		secretA, err := ks.vault.Seal(ctx, a.ID, crypto.PurposeSecret, []byte("smtp password of entity A"))
		if err != nil {
			t.Fatal(err)
		}
		keysA = append(keysA, secretA)
		if err := ks.db.Tenants().Delete(ctx, a.ID); err != nil {
			t.Fatalf("Tenants.Delete(A): %v", err)
		}
		if n, err := ks.db.WrappedKeys().CountByKey(ctx, k1.id); err != nil || n != int64(len(keysB)) {
			t.Errorf("wrapped keys after deleting A = %d, %v; want B's %d", n, err, len(keysB))
		}
		for _, w := range keysA {
			p := crypto.PurposeDEK
			if w == secretA {
				p = crypto.PurposeSecret
			}
			if _, err := ks.vault.Open(ctx, a.ID, p, w); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("Open(deleted tenant's %s) = %v, want store.ErrNotFound", w, err)
			}
		}
		for _, w := range keysB {
			if got, err := ks.vault.Open(ctx, b.ID, crypto.PurposeDEK, w); err != nil || !bytes.Equal(got, bytes.Repeat([]byte{0xB}, crypto.DEKSize)) {
				t.Errorf("B's key %s after deleting A: %v", w, err)
			}
		}
	})
}

// writeEncrypted encrypts plaintext into a new file at path.
func writeEncrypted(t *testing.T, path string, dek []byte, tenantID, fileID string, plaintext []byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	w, err := crypto.NewWriter(f, dek, tenantID, fileID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(plaintext); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

// readEncrypted decrypts the file at path entirely.
func readEncrypted(t *testing.T, path string, dek []byte, tenantID, fileID string) []byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	r, err := crypto.NewReader(f, dek, tenantID, fileID)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("decrypt %s: %v", filepath.Base(path), err)
	}
	return got
}

// streamSize is the plaintext size of the resumable upload test.
const streamSize = 8 << 20

// writeRandomly writes p to w in pieces of pseudo-random sizes (1 byte to
// 200 KiB), like the PATCH requests of a tus client.
func writeRandomly(t *testing.T, w io.Writer, p []byte, rng *rand.Rand) {
	t.Helper()
	for len(p) > 0 {
		n := min(len(p), 1+rng.IntN(200<<10))
		m, err := w.Write(p[:n])
		if err != nil || m != n {
			t.Fatalf("Write(%d bytes) = %d, %v", n, m, err)
		}
		p = p[n:]
	}
}

// persistState writes st to path, as the upload handler persists the
// checkpoint before acknowledging a PATCH.
func persistState(t *testing.T, path string, st *crypto.State) {
	t.Helper()
	b, err := st.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// reopenForResume reopens the encrypted file and its persisted checkpoint
// after a crash: the file is positioned at its end and existingSize comes
// from Stat, as the upload handler will do.
func reopenForResume(t *testing.T, path, statePath string) (*os.File, *crypto.State, int64) {
	t.Helper()
	b, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	st, err := crypto.UnmarshalState(b)
	if err != nil {
		t.Fatalf("UnmarshalState: %v", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		t.Fatal(err)
	}
	fi, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	return f, st, fi.Size()
}

// TestResumableEncryptedUploadOnDisk encrypts an 8 MiB stream to a real
// file with pseudo-random write sizes, crashing twice after a checkpoint
// and resuming from the file on disk, then checks the SHA-256 of the
// decrypted file and the exact encrypted size. A checkpoint that no longer
// matches the file (data written after it, or data lost) is refused.
func TestResumableEncryptedUploadOnDisk(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		a, _ := createTenants(t, e)
		ks := openKeyStore(t, e, newKeyFile(t, "K1"), nil)
		wkID, dek, err := ks.vault.NewDEK(ctx, a.ID)
		if err != nil {
			t.Fatal(err)
		}
		tid := string(a.ID)
		rng := rand.New(rand.NewPCG(20261020, 16)) // deterministic
		plaintext := make([]byte, streamSize)
		for i := range plaintext {
			plaintext[i] = byte(rng.Uint32())
		}
		want := sha256.Sum256(plaintext)
		dir := t.TempDir()

		t.Run("crash and resume twice", func(t *testing.T) {
			fileID := id.New(id.File)
			path, statePath := filepath.Join(dir, fileID), filepath.Join(dir, fileID+".state")
			// Cut points not aligned on chunks.
			cuts := []int{3*crypto.DefaultChunkSize + 12345, 6<<20 + 777, streamSize}

			f, err := os.Create(path)
			if err != nil {
				t.Fatal(err)
			}
			w, err := crypto.NewWriter(f, dek, tid, fileID)
			if err != nil {
				t.Fatal(err)
			}
			offset := 0
			for i, cut := range cuts {
				writeRandomly(t, w, plaintext[offset:cut], rng)
				offset = cut
				if i == len(cuts)-1 {
					break
				}
				st, err := w.Checkpoint(nil)
				if err != nil {
					t.Fatal(err)
				}
				if st.PlaintextSize() != int64(cut) {
					t.Fatalf("checkpoint covers %d bytes, want %d", st.PlaintextSize(), cut)
				}
				persistState(t, statePath, st)
				// Crash: the writer is abandoned without Close.
				if err := f.Close(); err != nil {
					t.Fatal(err)
				}
				var size int64
				var resumedState *crypto.State
				f, resumedState, size = reopenForResume(t, path, statePath)
				if size != st.CiphertextSize() {
					t.Fatalf("file holds %d bytes after the crash, checkpoint says %d", size, st.CiphertextSize())
				}
				if w, _, err = crypto.ResumeWriter(f, dek, tid, fileID, resumedState, size); err != nil {
					t.Fatalf("ResumeWriter at %d: %v", cut, err)
				}
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}

			fi, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if want := crypto.EncryptedSize(streamSize, crypto.DefaultChunkSize); fi.Size() != want {
				t.Errorf("encrypted file is %d bytes, want %d", fi.Size(), want)
			}
			// Decrypt with the key reopened from the database.
			reopened, err := ks.vault.Open(ctx, a.ID, crypto.PurposeDEK, wkID)
			if err != nil {
				t.Fatal(err)
			}
			src, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = src.Close() }()
			r, err := crypto.NewReader(src, reopened, tid, fileID)
			if err != nil {
				t.Fatal(err)
			}
			h := sha256.New()
			if n, err := io.CopyBuffer(h, r, make([]byte, 37<<10)); err != nil || n != streamSize {
				t.Fatalf("decrypted %d bytes, %v; want %d", n, err, streamSize)
			}
			if got := h.Sum(nil); !bytes.Equal(got, want[:]) {
				t.Errorf("SHA-256 of the decrypted file = %x, want %x", got, want)
			}
		})

		t.Run("stale checkpoint refused", func(t *testing.T) {
			fileID := id.New(id.File)
			path, statePath := filepath.Join(dir, fileID), filepath.Join(dir, fileID+".state")
			f, err := os.Create(path)
			if err != nil {
				t.Fatal(err)
			}
			w, err := crypto.NewWriter(f, dek, tid, fileID)
			if err != nil {
				t.Fatal(err)
			}
			cut := 2<<20 + 99
			writeRandomly(t, w, plaintext[:cut], rng)
			st, err := w.Checkpoint(nil)
			if err != nil {
				t.Fatal(err)
			}
			persistState(t, statePath, st)
			// Data written after the checkpoint (not acknowledged), crossing
			// chunk boundaries, then a crash.
			writeRandomly(t, w, plaintext[cut:cut+3*crypto.DefaultChunkSize], rng)
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}

			f, persisted, size := reopenForResume(t, path, statePath)
			if size <= persisted.CiphertextSize() {
				t.Fatalf("file is %d bytes, want more than the checkpoint's %d", size, persisted.CiphertextSize())
			}
			if _, _, err := crypto.ResumeWriter(f, dek, tid, fileID, persisted, size); !errors.Is(err, crypto.ErrStaleCheckpoint) {
				t.Errorf("resume over a longer file = %v, want crypto.ErrStaleCheckpoint", err)
			}
			// A file that lost data is refused too.
			if err := f.Truncate(persisted.CiphertextSize() - 1); err != nil {
				t.Fatal(err)
			}
			fi, err := f.Stat()
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := crypto.ResumeWriter(f, dek, tid, fileID, persisted, fi.Size()); !errors.Is(err, crypto.ErrStaleCheckpoint) {
				t.Errorf("resume over a shorter file = %v, want crypto.ErrStaleCheckpoint", err)
			}
			// The refusals wrote nothing.
			if after, err := f.Stat(); err != nil || after.Size() != fi.Size() {
				t.Errorf("file size after the refusals = %d, %v; want %d", after.Size(), err, fi.Size())
			}
		})
	})
}
