package lifecycle

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/storage"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/tte2"
)

// secretFile is the metadata (base64url) of the files of the test secrets.
var secretFile = strings.Repeat("meta_", 6)

// secretIn returns a valid link secret of alice, with a file when
// withFile (pending, until its upload completes at step 3).
func secretIn(now time.Time, withFile bool) store.CreateSecret {
	var kp, p [32]byte
	_, _ = rand.Read(kp[:])
	_, _ = rand.Read(p[:])
	kv, v := sha256.Sum256(kp[:]), sha256.Sum256(p[:])
	in := store.CreateSecret{
		CreatorKind: store.SecretCreatorInternal, SenderEmail: alice, Delivery: store.SecretDeliveryLink,
		Verifier: v[:], KeyVerifier: kv[:], SealedText: strings.Repeat("sealed-text_", 5),
		Duration: tenant.SecretDuration1h, Now: now,
	}
	if withFile {
		in.FileSize, in.FileMetadata, in.FileStorageName = 1024, secretFile, storage.NewName()
	}
	return in
}

// newSecret stores a secret of tn, with its file on disk when withFile.
func (ev *env) newSecret(tn *tenant.Tenant, withFile bool) store.CreatedSecret {
	ev.t.Helper()
	in := secretIn(ev.clock.Now(), withFile)
	cs, err := ev.db.Secrets(ev.vault).Create(context.Background(), tn.ID, in)
	if err != nil {
		ev.t.Fatalf("Secrets.Create: %v", err)
	}
	if withFile {
		dir := filepath.Join(ev.root, string(tn.ID), "secrets")
		if err := os.MkdirAll(dir, 0o750); err != nil {
			ev.t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, in.FileStorageName), []byte("ciphertext"), 0o600); err != nil {
			ev.t.Fatal(err)
		}
	}
	return cs
}

// secretFiles counts the files left in the secret directory of tn.
func (ev *env) secretFiles(tn *tenant.Tenant) int {
	ev.t.Helper()
	ents, err := os.ReadDir(filepath.Join(ev.root, string(tn.ID), "secrets"))
	if errors.Is(err, os.ErrNotExist) {
		return 0
	}
	if err != nil {
		ev.t.Fatal(err)
	}
	return len(ents)
}

// secretCount returns how many secret rows tn holds.
func (ev *env) secretCount(tn *tenant.Tenant) int {
	ev.t.Helper()
	page, err := ev.db.Secrets(nil).ListByTenant(context.Background(), tn.ID, store.SecretListOptions{Limit: store.MaxPageSize})
	if err != nil {
		ev.t.Fatal(err)
	}
	return len(page.Items)
}

// TestSecretSweeps covers the three sweeps: the expiry (TaskExpire), the
// pending purge (TaskAbandonedUploads) and the tombstone purge
// (TaskPurgeRows), per tenant, with the hook of the receipts.
func TestSecretSweeps(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		var expired []store.EndedSecret
		ev.s = ev.newSweeper(Options{SecretExpired: func(_ context.Context, e store.EndedSecret) { expired = append(expired, e) }})
		sa, sb := ev.newSecret(ev.a, false), ev.newSecret(ev.b, false)
		pending := ev.newSecret(ev.a, true)
		if ev.secretFiles(ev.a) != 1 {
			t.Fatal("fixture file missing")
		}
		repo := ev.db.Secrets(nil)

		// Not due yet: nothing changes.
		ev.runTask(TaskExpire)
		ev.runTask(TaskAbandonedUploads)
		if len(expired) != 0 || ev.secretCount(ev.a) != 2 {
			t.Fatalf("early sweeps: %d expired, %d rows", len(expired), ev.secretCount(ev.a))
		}

		ev.clock.set(ev.clock.Now().Add(2 * time.Hour))
		ev.runTask(TaskExpire)
		if len(expired) != 2 {
			t.Fatalf("expired hook called %d times, want 2", len(expired))
		}
		for _, id := range []string{sa.Secret.ID, sb.Secret.ID} {
			tid := ev.a.ID
			if id == sb.Secret.ID {
				tid = ev.b.ID
			}
			got, err := repo.Get(context.Background(), tid, id)
			if err != nil || got.State != store.SecretExpired {
				t.Fatalf("secret %s = %+v, %v; want expired", id, got, err)
			}
		}
		if got := ev.tenantAudit(ev.a.ID, "secret.expired"); len(got) != 1 || got[0].ObjectID != sa.Secret.ID || got[0].Actor != SystemActor {
			t.Errorf("secret.expired events of A = %+v", got)
		}
		if n := ev.keyCount(ev.b); n != 0 {
			t.Errorf("%d keys left for B after the expiry", n)
		}

		ev.runTask(TaskAbandonedUploads)
		if _, err := repo.Get(context.Background(), ev.a.ID, pending.Secret.ID); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("pending secret after the purge: %v", err)
		}
		if ev.secretFiles(ev.a) != 0 {
			t.Error("the file of the purged pending secret is left")
		}

		// The tombstones are kept 30 days, then purged with the rows.
		ev.runTask(TaskPurgeRows)
		if ev.secretCount(ev.a) != 1 || ev.secretCount(ev.b) != 1 {
			t.Fatal("tombstones purged too early")
		}
		ev.clock.set(ev.clock.Now().Add(store.SecretTombstoneRetention + time.Hour))
		ev.runTask(TaskPurgeRows)
		if ev.secretCount(ev.a) != 0 || ev.secretCount(ev.b) != 0 {
			t.Fatal("tombstones kept after 30 days")
		}
	})
}

// keyCount returns how many wrapped keys tn holds.
func (ev *env) keyCount(tn *tenant.Tenant) int {
	ev.t.Helper()
	ids, err := ev.db.WrappedKeys().ListIDs(context.Background(), tn.ID, "", 0)
	if err != nil {
		ev.t.Fatal(err)
	}
	return len(ids)
}

// TestSecretSweepFailures covers the failures: a failed sweep is returned
// after the transfer sweep ran, a file left on disk is logged only.
func TestSecretSweepFailures(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		ev.newSecret(ev.a, true)
		ev.clock.set(ev.clock.Now().Add(2 * time.Hour))

		ev.f.set("purgePendingSecrets", 1, errFault)
		if err := ev.s.RunTask(ctx, TaskAbandonedUploads); !errors.Is(err, errFault) {
			t.Fatalf("pending purge = %v, want the fault", err)
		}
		ev.f.set("removeSecretFile", 1, errFault)
		ev.runTask(TaskAbandonedUploads) // the row and key are gone: only a warning
		if ev.secretFiles(ev.a) != 1 || !strings.Contains(ev.logs.all(), "secret file left on disk") {
			t.Fatalf("file left: %d\nlogs:\n%s", ev.secretFiles(ev.a), ev.logs.all())
		}

		ev.newSecret(ev.b, false)
		ev.clock.set(ev.clock.Now().Add(2 * time.Hour))
		ev.f.set("expireSecrets", 1, errFault)
		if err := ev.s.RunTask(ctx, TaskExpire); !errors.Is(err, errFault) {
			t.Fatalf("expiry = %v, want the fault", err)
		}
		ev.runTask(TaskExpire)
		if ev.secretCount(ev.b) != 1 {
			t.Fatal("the secret was not expired on the retry")
		}
		// A failing audit write is logged and does not undo the expiry.
		ev.newSecret(ev.b, false)
		ev.clock.set(ev.clock.Now().Add(2 * time.Hour))
		ev.f.set("audit", 1, errFault)
		ev.runTask(TaskExpire)
		if !strings.Contains(ev.logs.all(), "audit write failed") {
			t.Fatalf("audit failure not logged:\n%s", ev.logs.all())
		}

		// A canceled context stops the loop before any sweep.
		cctx, cancel := context.WithCancel(ctx)
		cancel()
		if _, err := ev.s.sweepSecrets(cctx, "test", nil); !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled sweep = %v", err)
		}
	})
}

// TestSweepSecretsPaging covers the loop over the pages: it goes on while
// the store reports more and makes progress, and stops on a page where
// every secret changed meanwhile.
func TestSweepSecretsPaging(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		one := []store.EndedSecret{{Secret: store.Secret{TenantID: ev.a.ID}}}
		pages := [][]store.EndedSecret{one, one, nil, one}
		calls := 0
		got, err := ev.s.sweepSecrets(context.Background(), "test", func(context.Context) ([]store.EndedSecret, bool, error) {
			calls++
			return pages[calls-1], true, nil
		})
		if err != nil || len(got) != 2 || calls != 3 {
			t.Fatalf("sweep = %d secrets in %d calls, %v; want 2 in 3", len(got), calls, err)
		}
		// An error after progress keeps the secrets already ended.
		calls = 0
		got, err = ev.s.sweepSecrets(context.Background(), "test", func(context.Context) ([]store.EndedSecret, bool, error) {
			calls++
			if calls == 2 {
				return nil, false, errFault
			}
			return one, true, nil
		})
		if !errors.Is(err, errFault) || len(got) != 1 {
			t.Fatalf("failing sweep = %d secrets, %v", len(got), err)
		}
	})
}

// TestEraseTenantSecrets checks that the erasure of a tenant deletes its
// secrets, keys and files before destroying its other keys, resumes after a
// failure, and leaves the other tenants alone.
func TestEraseTenantSecrets(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		live := ev.newSecret(ev.a, false)
		ev.newSecret(ev.a, true)
		other := ev.newSecret(ev.b, true)
		ev.startDeletion(ev.a)

		ev.f.set("deleteTenantSecrets", 1, errFault)
		if err := ev.s.EraseTenant(ctx, ev.a.ID); !errors.Is(err, errFault) || !strings.Contains(err.Error(), "secrets") {
			t.Fatalf("EraseTenant = %v, want the secrets step to fail", err)
		}
		if _, err := ev.db.Secrets(nil).Get(ctx, ev.a.ID, live.Secret.ID); err != nil {
			t.Fatalf("secret after the failed step: %v", err)
		}
		if err := ev.s.EraseTenant(ctx, ev.a.ID); err != nil {
			t.Fatalf("EraseTenant: %v\nlogs:\n%s", err, ev.logs.all())
		}
		if _, err := ev.db.Tenants().Get(ctx, ev.a.ID); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("tenant row: %v", err)
		}
		if ev.keyCount(ev.a) != 0 {
			t.Error("keys left for the erased tenant")
		}
		if _, err := ev.db.Secrets(nil).Get(ctx, ev.b.ID, other.Secret.ID); err != nil || ev.secretFiles(ev.b) != 1 {
			t.Fatalf("tenant B secret: %v, %d files", err, ev.secretFiles(ev.b))
		}
	})
}

// revealedFileSecret stores a secret of tn with an uploaded file and
// reveals it: its one-time grant is pending.
func (ev *env) revealedFileSecret(tn *tenant.Tenant) (store.CreatedSecret, store.RevealedSecret) {
	ev.t.Helper()
	ctx := context.Background()
	var kp, p [32]byte
	_, _ = rand.Read(kp[:])
	_, _ = rand.Read(p[:])
	kv, v := sha256.Sum256(kp[:]), sha256.Sum256(p[:])
	key, _ := tte2.NewKey()
	var buf bytes.Buffer
	w, _ := tte2.NewWriter(&buf, key, 0)
	_, _ = w.Write([]byte("file content"))
	_ = w.Close()
	in := secretIn(ev.clock.Now(), true)
	in.Verifier, in.KeyVerifier, in.FileSize = v[:], kv[:], int64(buf.Len())
	repo := ev.db.Secrets(ev.vault)
	cs, err := repo.Create(ctx, tn.ID, in)
	if err != nil {
		ev.t.Fatal(err)
	}
	actor := store.SecretActor{Email: alice, Kind: store.SecretCreatorInternal}
	if _, err := repo.UploadFile(ctx, tn.ID, cs.Secret.ID, actor, ev.files, &buf, nil); err != nil {
		ev.t.Fatal(err)
	}
	rv, err := repo.Reveal(ctx, tn.ID, cs.Token, kp, p, ev.clock.Now())
	if err != nil {
		ev.t.Fatal(err)
	}
	return cs, rv
}

// TestSecretGrantSweep checks that TaskExpire ends the expired file grants:
// the file and its key go, the tombstone stays; a failure of the grant
// sweep is returned after the expiry sweep ran.
func TestSecretGrantSweep(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		cs, rv := ev.revealedFileSecret(ev.a)
		if ev.secretFiles(ev.a) != 1 || ev.keyCount(ev.a) != 1 {
			t.Fatalf("fixture: %d files, %d keys", ev.secretFiles(ev.a), ev.keyCount(ev.a))
		}
		ev.runTask(TaskExpire)
		if ev.secretFiles(ev.a) != 1 {
			t.Fatal("grant swept before its expiry")
		}
		ev.clock.set(rv.FileGrantExpiresAt)
		ev.f.set("expireSecretGrants", 1, errFault)
		if err := ev.s.RunTask(ctx, TaskExpire); !errors.Is(err, errFault) {
			t.Fatalf("grant sweep = %v, want the fault", err)
		}
		ev.runTask(TaskExpire)
		if ev.secretFiles(ev.a) != 0 || ev.keyCount(ev.a) != 0 {
			t.Fatalf("after the sweep: %d files, %d keys", ev.secretFiles(ev.a), ev.keyCount(ev.a))
		}
		got, err := ev.db.Secrets(nil).Get(ctx, ev.a.ID, cs.Secret.ID)
		if err != nil || got.State != store.SecretRead || got.FileStorageName != "" || !got.FileDownloadedAt.IsZero() {
			t.Fatalf("tombstone = %+v, %v", got, err)
		}
	})
}

// TestSecretOrphanFiles covers the orphan sweep of the secrets
// subdirectory: a file no secret names, or whose secret lost its key, goes
// past the grace period; a referenced, young or unknown entry stays.
func TestSecretOrphanFiles(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		old := ev.clock.Now().Add(-OrphanGrace - time.Minute)
		_, rv := ev.revealedFileSecret(ev.a) // referenced, keyed
		kept := filepath.Join("secrets", rv.Secret.FileStorageName)
		ev.touch(ev.a, kept, old)
		pend := ev.newSecret(ev.a, true) // referenced, no key yet (not uploaded)
		keyless := filepath.Join("secrets", pend.Secret.FileStorageName)
		ev.touch(ev.a, keyless, old)
		stray := filepath.Join("secrets", storage.NewName())
		ev.write(ev.a, stray, old)
		young := filepath.Join("secrets", storage.NewName())
		ev.write(ev.a, young, ev.clock.Now())
		unknown := filepath.Join("secrets", "junk")
		ev.write(ev.a, unknown, old)

		for _, fault := range []string{"listSecretFiles", "secretFileRefs", "removeSecretFile"} {
			ev.f.set(fault, 1, errFault)
			if err := ev.s.RunTask(ctx, TaskOrphans); !errors.Is(err, errFault) {
				t.Fatalf("%s: %v", fault, err)
			}
		}
		ev.runTask(TaskOrphans)
		for file, want := range map[string]bool{kept: true, keyless: false, stray: false, young: true, unknown: true} {
			if ev.exists(ev.a, file) != want {
				t.Errorf("%s exists = %v, want %v", file, !want, want)
			}
		}
		if !strings.Contains(ev.logs.all(), "secrets=") || !strings.Contains(ev.logs.all(), "unknown entry left in the secrets directory") {
			t.Errorf("logs:\n%s", ev.logs.all())
		}
		// Too many rows: the secret files are skipped with a warning.
		ev.f.set("secretFileRefs", 1, store.ErrTooManyRows)
		ev.write(ev.a, stray, old)
		ev.runTask(TaskOrphans)
		if !ev.exists(ev.a, stray) || !strings.Contains(ev.logs.all(), "secret files skipped by the orphan removal") {
			t.Fatalf("too many rows: logs:\n%s", ev.logs.all())
		}
	})
}
