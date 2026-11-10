package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// fakeSecretKeys implements SecretKeys over the wrapped_keys table without
// a master key: the "wrapped" blob is the data key itself. Tests only.
type fakeSecretKeys struct {
	db                         *DB
	newErr, openErr, dstrErr   error
	shortKey, wrongKey         bool
	opened, created, destroyed atomic.Int64
}

func (f *fakeSecretKeys) NewDEKTx(ctx context.Context, tx *ScopedTx) (string, []byte, error) {
	if f.newErr != nil {
		return "", nil, f.newErr
	}
	dek := make([]byte, 32)
	_, _ = rand.Read(dek)
	wk := id.New(id.WrappedKey)
	if err := f.db.WrappedKeys().CreateTx(ctx, tx, WrappedKey{ID: wk, Purpose: KeyPurposeDEK, KeyID: testMK1, Blob: bytes.Clone(dek)}); err != nil {
		return "", nil, err
	}
	f.created.Add(1)
	if f.shortKey {
		return wk, dek[:5], nil
	}
	return wk, dek, nil
}

func (f *fakeSecretKeys) OpenTx(ctx context.Context, tx *ScopedTx, p crypto.Purpose, wkID string) ([]byte, error) {
	if f.openErr != nil {
		return nil, f.openErr
	}
	k, err := f.db.WrappedKeys().GetTx(ctx, tx, wkID)
	if err != nil {
		return nil, err
	}
	if k.Purpose != string(p) {
		return nil, errors.New("purpose mismatch")
	}
	f.opened.Add(1)
	if f.wrongKey {
		return make([]byte, 32), nil
	}
	return k.Blob, nil
}

func (f *fakeSecretKeys) DestroyTx(ctx context.Context, tx *ScopedTx, wkID string) error {
	if f.dstrErr != nil {
		return f.dstrErr
	}
	f.destroyed.Add(1)
	return f.db.WrappedKeys().DeleteTx(ctx, tx, wkID)
}

// secretFixture is a migrated database with tenants a and b, a master key
// and a secret repository over fakeSecretKeys.
type secretFixture struct {
	db   *DB
	a, b tenant.ID
	keys *fakeSecretKeys
	repo *Secrets
	now  time.Time
}

func newSecretFixtureDB(t *testing.T, db *DB) *secretFixture {
	t.Helper()
	ctx := context.Background()
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := db.MasterKeys().EnsureActive(ctx, testMK1, time.Now()); err != nil {
		t.Fatal(err)
	}
	f := &secretFixture{db: db, keys: &fakeSecretKeys{db: db}, now: time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC)}
	f.a = newTestTenant(ctx, t, db, "a.example.com")
	f.b = newTestTenant(ctx, t, db, "b.example.com")
	// The test tenants have a 1-byte quota: room for the secret files.
	if err := rawExecArgs(ctx, t, db, `UPDATE tenants SET storage_quota_bytes = ?`, int64(1<<40)); err != nil {
		t.Fatal(err)
	}
	f.repo = db.Secrets(f.keys)
	return f
}

func newSecretFixture(t *testing.T, e storetest.Engine) *secretFixture {
	t.Helper()
	return newSecretFixtureDB(t, openMigratedEngine(t, e))
}

// proofs is a key proof and a proof with their verifiers.
type proofs struct{ key, proof [32]byte }

func newProofs() proofs {
	var p proofs
	_, _ = rand.Read(p.key[:])
	_, _ = rand.Read(p.proof[:])
	return p
}

func (p proofs) verifiers() (kv, v []byte) {
	a, b := sha256.Sum256(p.key[:]), sha256.Sum256(p.proof[:])
	return a[:], b[:]
}

// sealedText is a valid sealed text string of the test secrets.
var sealedText = strings.Repeat("TTE2sealed-text_", 4)

// input returns a valid link secret without file of an internal creator.
func (f *secretFixture) input(p proofs) CreateSecret {
	kv, v := p.verifiers()
	return CreateSecret{
		CreatorKind: SecretCreatorInternal, SenderEmail: "Alice@A.example.com", Delivery: SecretDeliveryLink,
		Verifier: v, KeyVerifier: kv, SealedText: sealedText, Duration: tenant.SecretDuration1h, Now: f.now,
	}
}

func (f *secretFixture) create(ctx context.Context, t *testing.T, tid tenant.ID, c CreateSecret) CreatedSecret {
	t.Helper()
	cs, err := f.repo.Create(ctx, tid, c)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return cs
}

// orphanKeys counts the dek rows referenced by no secret and no transfer
// file: none may ever remain.
func (f *secretFixture) orphanKeys(t *testing.T) int64 {
	t.Helper()
	return rawInt(context.Background(), t, f.db, `SELECT count(*) FROM wrapped_keys w WHERE purpose = 'dek'
		AND NOT EXISTS (SELECT 1 FROM secrets s WHERE s.text_key_id = w.id OR s.file_key_id = w.id)
		AND NOT EXISTS (SELECT 1 FROM transfer_files tf WHERE tf.dek_key_id = w.id)`)
}

func (f *secretFixture) assertNoOrphanKeys(t *testing.T, step string) {
	t.Helper()
	if n := f.orphanKeys(t); n != 0 {
		t.Errorf("%s: %d unreferenced data keys", step, n)
	}
}

func gone(t *testing.T, err error, want SecretEndReason) {
	t.Helper()
	var g *SecretGoneError
	if !errors.As(err, &g) || g.Reason != want || !errors.Is(err, ErrSecretGone) {
		t.Errorf("err = %v, want gone (%s)", err, want)
	}
}

// TestSecretsCreateAndReveal covers the link secret from creation to the
// reveal, the key proof and the counted wrong proofs, on both engines.
func TestSecretsCreateAndReveal(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		f := newSecretFixture(t, e)
		p := newProofs()
		cs := f.create(ctx, t, f.a, f.input(p))
		s := cs.Secret
		if !id.SecretTokenValid(cs.Token) || !id.Valid(id.Secret, s.ID) || s.TenantID != f.a {
			t.Fatalf("created %+v token %q", s, cs.Token)
		}
		if s.State != SecretActive || s.SenderEmail != "alice@a.example.com" || !s.ExpiresAt.Equal(f.now.Add(time.Hour)) ||
			!s.ActivatedAt.Equal(f.now) || s.HasPassphrase() || s.FailedProofs != 0 || s.Delivery != SecretDeliveryLink {
			t.Fatalf("created secret = %+v", s)
		}
		// Encrypted at rest: the stored blob is not the sealed text.
		if n := rawInt(ctx, t, f.db, `SELECT count(*) FROM secrets WHERE text_sealed = '`+sealedText+`'`); n != 0 {
			t.Error("text stored in clear")
		}
		got, err := f.repo.Get(ctx, f.a, s.ID)
		if err != nil || got.ID != s.ID {
			t.Fatalf("Get = %+v, %v", got, err)
		}
		st, err := f.repo.StatusByToken(ctx, f.a, cs.Token, f.now)
		if err != nil || st.State != SecretActive || st.ID != s.ID {
			t.Fatalf("StatusByToken = %+v, %v", st, err)
		}

		// Wrong key proof: refused, not counted.
		wrongKey := p
		wrongKey.key[0] ^= 1
		if _, err := f.repo.Reveal(ctx, f.a, cs.Token, wrongKey.key, p.proof, f.now); !errors.Is(err, ErrSecretKeyProof) {
			t.Fatalf("wrong key proof: %v", err)
		}
		// Wrong proof: counted.
		wrong := p
		wrong.proof[0] ^= 1
		_, err = f.repo.Reveal(ctx, f.a, cs.Token, p.key, wrong.proof, f.now)
		var pe *SecretProofError
		if !errors.As(err, &pe) || pe.Remaining != 4 || !errors.Is(err, ErrSecretProof) || pe.Error() == "" {
			t.Fatalf("wrong proof: %v", err)
		}
		if got, _ := f.repo.Get(ctx, f.a, s.ID); got.FailedProofs != 1 {
			t.Fatalf("failed proofs = %d, want 1", got.FailedProofs)
		}
		// Right proofs.
		rev, err := f.repo.Reveal(ctx, f.a, cs.Token, p.key, p.proof, f.now.Add(time.Minute))
		if err != nil {
			t.Fatalf("Reveal: %v", err)
		}
		if rev.SealedText != sealedText || rev.FileMetadata != "" || rev.Secret.State != SecretRead ||
			rev.Secret.EndReason != SecretEndRead || rev.Secret.FailedProofs != 1 || rev.Secret.ReadAt.IsZero() {
			t.Fatalf("revealed = %+v", rev)
		}
		f.assertNoOrphanKeys(t, "reveal")
		if n := rawInt(ctx, t, f.db, `SELECT count(*) FROM wrapped_keys`); n != 0 {
			t.Errorf("%d keys left after the reveal", n)
		}
		// Second reveal and status: gone (read).
		_, err = f.repo.Reveal(ctx, f.a, cs.Token, p.key, p.proof, f.now)
		gone(t, err, SecretEndRead)
		if st, err := f.repo.StatusByToken(ctx, f.a, cs.Token, f.now); err != nil || st.State != SecretRead {
			t.Fatalf("status after reveal = %+v, %v", st, err)
		}
		if g := (&SecretGoneError{Reason: SecretEndRead}); g.Error() == "" {
			t.Error("empty message")
		}
	})
}

// TestSecretsLock locks a secret after five wrong passphrase proofs.
func TestSecretsLock(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		f := newSecretFixture(t, e)
		p := newProofs()
		in := f.input(p)
		in.KDFSalt = bytes.Repeat([]byte{7}, SecretKDFSaltLen)
		cs := f.create(ctx, t, f.a, in)
		if !cs.Secret.HasPassphrase() || cs.Secret.KDFIterations != SecretKDFIterations {
			t.Fatalf("passphrase = %+v", cs.Secret)
		}
		wrong := p
		wrong.proof[3] ^= 1
		for want := 4; want >= 0; want-- {
			_, err := f.repo.Reveal(ctx, f.a, cs.Token, p.key, wrong.proof, f.now)
			var pe *SecretProofError
			if !errors.As(err, &pe) || pe.Remaining != want || pe.RemovedFile != "" {
				t.Fatalf("attempt for %d left: %v", want, err)
			}
		}
		s, err := f.repo.Get(ctx, f.a, cs.Secret.ID)
		if err != nil || s.State != SecretLocked || s.FailedProofs != 5 || s.EndReason != SecretEndLocked || s.HasPassphrase() {
			t.Fatalf("locked secret = %+v, %v", s, err)
		}
		_, err = f.repo.Reveal(ctx, f.a, cs.Token, p.key, p.proof, f.now)
		gone(t, err, SecretEndLocked)
		f.assertNoOrphanKeys(t, "lock")
		if n := rawInt(ctx, t, f.db, `SELECT count(*) FROM wrapped_keys`); n != 0 {
			t.Errorf("%d keys left after the lock", n)
		}
	})
}

// TestSecretsConcurrentReveal runs 50 wrong and 1 right reveals in
// parallel: at most 5 proofs are compared and at most one reveal wins.
func TestSecretsConcurrentReveal(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		f := newSecretFixture(t, e)
		p := newProofs()
		cs := f.create(ctx, t, f.a, f.input(p))
		var c atomic.Int64
		proofCounters.Store(cs.Secret.ID, &c)
		wrong := p
		wrong.proof[0] ^= 1
		var (
			wg        sync.WaitGroup
			successes atomic.Int64
			others    atomic.Int64
		)
		for i := range 51 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				proof := wrong.proof
				if i == 25 {
					proof = p.proof
				}
				_, err := f.repo.Reveal(ctx, f.a, cs.Token, p.key, proof, f.now)
				switch {
				case err == nil:
					successes.Add(1)
				case errors.Is(err, ErrSecretProof), errors.Is(err, ErrSecretGone):
				default:
					others.Add(1)
					t.Errorf("Reveal: %v", err)
				}
			}()
		}
		wg.Wait()
		if n := c.Load(); n > SecretMaxFailedProofs || n == 0 {
			t.Errorf("%d proofs compared, want 1 to %d", n, SecretMaxFailedProofs)
		}
		s, err := f.repo.Get(ctx, f.a, cs.Secret.ID)
		if err != nil {
			t.Fatal(err)
		}
		switch successes.Load() {
		case 1:
			if s.State != SecretRead {
				t.Errorf("state = %s after a success", s.State)
			}
		case 0:
			if s.State != SecretLocked {
				t.Errorf("state = %s without success", s.State)
			}
		default:
			t.Errorf("%d successful reveals", successes.Load())
		}
		f.assertNoOrphanKeys(t, "concurrent reveal")
	})
}

// TestSecretsConcurrentRightReveals runs N reveals with the right key
// proof and the right proof in parallel (threat model T-353), on both
// engines: exactly one returns the content, every other one is gone with
// the reason read, the failed proofs are untouched and the data key is
// destroyed.
func TestSecretsConcurrentRightReveals(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		f := newSecretFixture(t, e)
		p := newProofs()
		files := newFiles(t)
		stream := tte2Stream(t, 1000)
		for _, file := range []bool{false, true} {
			in := f.input(p)
			if file {
				in = withFile(in, int64(len(stream)))
			}
			cs := f.create(ctx, t, f.a, in)
			if file {
				if _, err := f.repo.UploadFile(ctx, f.a, cs.Secret.ID, alice, files, bytes.NewReader(stream), f.clock); err != nil {
					t.Fatal(err)
				}
			}
			const reveals = 32
			var (
				wg       sync.WaitGroup
				winners  atomic.Int64
				grants   atomic.Int64
				contents sync.Map
			)
			for range reveals {
				wg.Add(1)
				go func() {
					defer wg.Done()
					rev, err := f.repo.Reveal(ctx, f.a, cs.Token, p.key, p.proof, f.now)
					var g *SecretGoneError
					switch {
					case err == nil:
						winners.Add(1)
						contents.Store(rev.SealedText, true)
						if rev.FileGrant != "" {
							grants.Add(1)
						}
					case errors.As(err, &g) && g.Reason == SecretEndRead:
					default:
						t.Errorf("Reveal: %v", err)
					}
				}()
			}
			wg.Wait()
			if winners.Load() != 1 {
				t.Fatalf("file %v: %d successful reveals, want exactly 1", file, winners.Load())
			}
			if _, ok := contents.Load(sealedText); !ok {
				t.Errorf("file %v: the winner did not get the content", file)
			}
			if file != (grants.Load() == 1) {
				t.Errorf("file %v: %d file grants", file, grants.Load())
			}
			s, err := f.repo.Get(ctx, f.a, cs.Secret.ID)
			if err != nil || s.State != SecretRead || s.FailedProofs != 0 {
				t.Errorf("file %v: secret after the race = %+v, %v", file, s, err)
			}
			if left := rawInt(ctx, t, f.db, `SELECT count(*) FROM secrets WHERE id = '`+cs.Secret.ID+`'
				AND (text_sealed IS NOT NULL OR text_key_id IS NOT NULL OR verifier IS NOT NULL)`); left != 0 {
				t.Errorf("file %v: content left after the race", file)
			}
			f.assertNoOrphanKeys(t, "concurrent right reveals")
		}
	})
}

// TestSecretsSupervisionCounts checks the per-tenant secret figures of the
// supervision on both engines: created, read and locked since a date and
// the bytes of the stored files, each tenant counting only its own rows.
func TestSecretsSupervisionCounts(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		f := newSecretFixture(t, e)
		since := f.now.Add(-24 * time.Hour)
		if got, err := f.db.Secrets(nil).SupervisionCounts(ctx, since); err != nil || len(got) != 0 {
			t.Fatalf("empty = %+v, %v", got, err)
		}
		p := newProofs()
		read := f.create(ctx, t, f.a, f.input(p))
		if _, err := f.repo.Reveal(ctx, f.a, read.Token, p.key, p.proof, f.now); err != nil {
			t.Fatal(err)
		}
		in := f.input(p)
		in.KDFSalt = bytes.Repeat([]byte{7}, SecretKDFSaltLen)
		locked := f.create(ctx, t, f.a, in)
		wrong := p.proof
		wrong[0] ^= 1
		for range SecretMaxFailedProofs {
			_, _ = f.repo.Reveal(ctx, f.a, locked.Token, p.key, wrong, f.now)
		}
		f.create(ctx, t, f.a, withFile(f.input(p), 300))
		old := f.input(p)
		old.Now = f.now.Add(-48 * time.Hour)
		f.create(ctx, t, f.a, old)
		f.create(ctx, t, f.b, withFile(f.input(p), 20))

		got, err := f.db.Secrets(nil).SupervisionCounts(ctx, since)
		want := []TenantSecretCounts{
			{TenantID: f.a, CreatedSince: 3, ReadSince: 1, LockedSince: 1, FileBytes: 300},
			{TenantID: f.b, CreatedSince: 1, FileBytes: 20},
		}
		if f.b < f.a {
			want[0], want[1] = want[1], want[0]
		}
		if err != nil || len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
			t.Errorf("counts = %+v, %v; want %+v", got, err, want)
		}
		_ = f.db.Close()
		if _, err := f.db.Secrets(nil).SupervisionCounts(ctx, since); err == nil {
			t.Error("counts on a closed database")
		}
	})
}

// proofCounters maps a secret ID to the counter of its compared proofs
// (TestSecretsConcurrentReveal).
var proofCounters sync.Map

// The hook is installed before any test runs (no race with the reveals of
// the parallel tests) and counts only the registered secrets.
func init() {
	secretRevealHook = func(stage, secID string) {
		switch stage {
		case revealStageCompare:
			if c, ok := proofCounters.Load(secID); ok {
				c.(*atomic.Int64).Add(1)
			}
		case revealStageClaim:
			if fn, ok := claimHooks.Load(secID); ok {
				fn.(func())()
			}
		}
	}
}

// claimHooks maps a secret ID to a function run between the key proof
// check and the claim of a reveal (TestSecretsRevealRace).
var claimHooks sync.Map

// TestSecretsStatusAndExpiry checks the expiry seen on read and the
// expiry sweep.
func TestSecretsStatusAndExpiry(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		f := newSecretFixture(t, e)
		p := newProofs()
		in := f.input(p)
		in.KDFSalt = bytes.Repeat([]byte{1}, SecretKDFSaltLen)
		cs := f.create(ctx, t, f.a, in)
		later := f.now.Add(2 * time.Hour)
		st, err := f.repo.StatusByToken(ctx, f.a, cs.Token, later)
		if err != nil || st.State != SecretExpired || st.EndReason != SecretEndExpired || st.HasPassphrase() || !st.EndedAt.Equal(cs.Secret.ExpiresAt) {
			t.Fatalf("status past expiry = %+v, %v", st, err)
		}
		_, err = f.repo.Reveal(ctx, f.a, cs.Token, p.key, p.proof, later)
		gone(t, err, SecretEndExpired)
		// Unknown, malformed and pending tokens.
		for _, tok := range []string{"tts_x", "tts_" + strings.Repeat("a", 43)} {
			if _, err := f.repo.StatusByToken(ctx, f.a, tok, f.now); !errors.Is(err, ErrNotFound) {
				t.Errorf("status %q: %v", tok, err)
			}
			if _, err := f.repo.Reveal(ctx, f.a, tok, p.key, p.proof, f.now); !errors.Is(err, ErrNotFound) {
				t.Errorf("reveal %q: %v", tok, err)
			}
		}
		// A pending secret (e-mail delivery) is unknown to the public.
		mail := f.input(newProofs())
		mail.Delivery, mail.RecipientEmail = SecretDeliveryEmail, "Bob@example.org"
		pending := f.create(ctx, t, f.a, mail)
		if pending.Secret.State != SecretPending || !pending.Secret.ExpiresAt.IsZero() || pending.Secret.RecipientEmail != "bob@example.org" {
			t.Fatalf("e-mail secret = %+v", pending.Secret)
		}
		if _, err := f.repo.StatusByToken(ctx, f.a, pending.Token, f.now); !errors.Is(err, ErrSecretPending) {
			t.Errorf("pending status: %v", err)
		}
		if _, err := f.repo.Reveal(ctx, f.a, pending.Token, p.key, p.proof, f.now); !errors.Is(err, ErrSecretPending) {
			t.Errorf("pending reveal: %v", err)
		}

		// The sweep: nothing due before the expiry, then the secret.
		if out, more, err := f.repo.ExpireDue(ctx, f.now, 10); err != nil || len(out) != 0 || more {
			t.Fatalf("ExpireDue(now) = %v, %v, %v", out, more, err)
		}
		if _, _, err := f.repo.ExpireDue(ctx, later, 0); !errors.Is(err, ErrInvalid) {
			t.Errorf("limit 0: %v", err)
		}
		out, more, err := f.repo.ExpireDue(ctx, later, 1)
		if err != nil || len(out) != 1 || !more || out[0].Secret.State != SecretExpired || out[0].RemovedFile != "" ||
			out[0].Secret.ID != cs.Secret.ID {
			t.Fatalf("ExpireDue = %+v, %v, %v", out, more, err)
		}
		if out, _, err := f.repo.ExpireDue(ctx, later, 1); err != nil || len(out) != 0 {
			t.Fatalf("second ExpireDue = %+v, %v", out, err)
		}
		f.assertNoOrphanKeys(t, "expiry")
		_, err = f.repo.Reveal(ctx, f.a, cs.Token, p.key, p.proof, f.now)
		gone(t, err, SecretEndExpired)
	})
}

// TestSecretsDeletion checks the creator identity rules and the admin
// deletion.
func TestSecretsDeletion(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		f := newSecretFixture(t, e)
		remote := f.input(newProofs())
		remote.CreatorKind = SecretCreatorInternalRemote
		s1 := f.create(ctx, t, f.a, remote).Secret
		tok := f.apiToken(t, f.a)
		viaToken := f.input(newProofs())
		viaToken.CreatorKind, viaToken.APITokenID = SecretCreatorAPIToken, tok
		s2 := f.create(ctx, t, f.a, viaToken).Secret

		for name, actor := range map[string]SecretActor{
			"other address":  {Email: "bob@a.example.com", Kind: SecretCreatorInternalRemote},
			"other kind":     {Email: "alice@a.example.com", Kind: SecretCreatorInternal},
			"token":          {APITokenID: tok},
			"no identity":    {},
			"invalid e-mail": {Email: "not an address"},
		} {
			if _, err := f.repo.DeleteByCreator(ctx, f.a, s1.ID, actor, f.now); !errors.Is(err, ErrNotFound) {
				t.Errorf("%s deletes: %v", name, err)
			}
		}
		for name, actor := range map[string]SecretActor{
			"session":      {Email: "alice@a.example.com", Kind: SecretCreatorInternal},
			"my transfers": {Email: "alice@a.example.com"},
			"other token":  {APITokenID: "tok_other"},
		} {
			if actor.Owns(s2) {
				t.Errorf("%s owns the token secret", name)
			}
		}
		if !(SecretActor{APITokenID: tok}).Owns(s2) {
			t.Error("the token does not own its secret")
		}
		// "My transfers" acts on every session kind of the address.
		ended, err := f.repo.DeleteByCreator(ctx, f.a, s1.ID, SecretActor{Email: "ALICE@a.example.com"}, f.now)
		if err != nil || ended.Secret.State != SecretDeleted || ended.Secret.EndReason != SecretEndDeletedByCreator ||
			ended.RemovedFile != "" || !ended.Secret.EndedAt.Equal(f.now) {
			t.Fatalf("DeleteByCreator = %+v, %v", ended, err)
		}
		_, err = f.repo.DeleteByCreator(ctx, f.a, s1.ID, SecretActor{Email: "alice@a.example.com"}, f.now)
		gone(t, err, SecretEndDeletedByCreator)
		ended, err = f.repo.DeleteByAdmin(ctx, f.a, s2.ID, f.now)
		if err != nil || ended.Secret.EndReason != SecretEndDeletedByAdmin {
			t.Fatalf("DeleteByAdmin = %+v, %v", ended, err)
		}
		// A pending secret can be deleted too.
		mail := f.input(newProofs())
		mail.Delivery, mail.RecipientEmail = SecretDeliveryEmail, "bob@example.org"
		s3 := f.create(ctx, t, f.a, mail).Secret
		if ended, err := f.repo.DeleteByAdmin(ctx, f.a, s3.ID, f.now); err != nil || ended.Secret.State != SecretDeleted {
			t.Fatalf("delete pending = %+v, %v", ended, err)
		}
		for _, bad := range []string{"", "sec_x", id.New(id.Secret)} {
			if _, err := f.repo.DeleteByAdmin(ctx, f.a, bad, f.now); !errors.Is(err, ErrNotFound) {
				t.Errorf("delete %q: %v", bad, err)
			}
			if _, err := f.repo.Get(ctx, f.a, bad); !errors.Is(err, ErrNotFound) {
				t.Errorf("get %q: %v", bad, err)
			}
		}
		f.assertNoOrphanKeys(t, "deletion")
		if n := rawInt(ctx, t, f.db, `SELECT count(*) FROM wrapped_keys`); n != 0 {
			t.Errorf("%d keys left", n)
		}
	})
}

// apiToken creates a usable API token of tid and returns its ID.
func (f *secretFixture) apiToken(t *testing.T, tid tenant.ID) string {
	t.Helper()
	tokID := id.New(id.APIToken)
	hash := sha256.Sum256([]byte(tokID))
	_, err := f.db.APITokens().Create(context.Background(), tid, APIToken{
		ID: tokID, Name: "ci", Prefix: "tt_Ab", TokenHash: hash[:], CreatedBy: "root", CreatedAt: f.now.Add(-time.Hour),
		AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
	})
	if err != nil {
		t.Fatalf("APITokens.Create: %v", err)
	}
	return tokID
}

// TestSecretsLimits checks the creator limits per address and per token.
func TestSecretsLimits(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		f := newSecretFixture(t, e)
		in := f.input(newProofs())
		var ids []string
		for round := range SecretMaxDaily / SecretMaxOpen {
			for range SecretMaxOpen {
				ids = append(ids, f.create(ctx, t, f.a, in).Secret.ID)
			}
			if round == 0 {
				if _, err := f.repo.Create(ctx, f.a, in); !errors.Is(err, ErrSecretOpenLimit) || !errors.Is(err, ErrLimitReached) {
					t.Fatalf("51st open secret: %v", err)
				}
				// Another address and an API token have their own limits;
				// another tenant too.
				other := in
				other.SenderEmail = "carol@a.example.com"
				f.create(ctx, t, f.a, other)
				tokIn := in
				tokIn.CreatorKind, tokIn.APITokenID = SecretCreatorAPIToken, f.apiToken(t, f.a)
				f.create(ctx, t, f.a, tokIn)
				f.create(ctx, t, f.b, in)
			}
			for _, secID := range ids {
				if _, err := f.repo.DeleteByAdmin(ctx, f.a, secID, f.now); err != nil {
					t.Fatal(err)
				}
			}
			ids = nil
		}
		if _, err := f.repo.Create(ctx, f.a, in); !errors.Is(err, ErrSecretDailyLimit) {
			t.Fatalf("201st secret of the day: %v", err)
		}
		in.Now = f.now.Add(SecretDailyWindow)
		f.create(ctx, t, f.a, in)
	})
}

// TestSecretsSettingsRefusals checks the tenant settings at creation.
func TestSecretsSettingsRefusals(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		f := newSecretFixture(t, e)
		set := func(mod func(*tenant.SecretSettings)) {
			t.Helper()
			s := tenant.DefaultSecretSettings()
			mod(&s)
			if _, err := f.db.Tenants().SetSecretSettings(ctx, f.a, s); err != nil {
				t.Fatal(err)
			}
		}
		withFile := func(c CreateSecret) CreateSecret {
			c.FileSize, c.FileMetadata, c.FileStorageName = 2<<20, "bWV0YQ", strings.Repeat("ab", 16)
			return c
		}
		mail := func(c CreateSecret) CreateSecret {
			c.Delivery, c.RecipientEmail = SecretDeliveryEmail, "bob@example.org"
			return c
		}
		base := f.input(newProofs())
		cases := []struct {
			name string
			mod  func(*tenant.SecretSettings)
			in   CreateSecret
			want error
		}{
			{"disabled", func(s *tenant.SecretSettings) { s.Enabled = false }, base, ErrSecretsDisabled},
			{"duration", func(*tenant.SecretSettings) {}, func() CreateSecret { c := base; c.Duration = tenant.SecretDuration30d; return c }(), ErrSecretDurationNotOffered},
			{"file not allowed", func(s *tenant.SecretSettings) { s.FileAllowed = false }, withFile(base), ErrSecretFileNotAllowed},
			{"file too large", func(s *tenant.SecretSettings) { s.FileMaxBytes = 1 << 20 }, withFile(base), ErrSecretFileTooLarge},
			{"e-mail", func(s *tenant.SecretSettings) { s.EmailAllowed = false }, mail(base), ErrSecretEmailNotAllowed},
			{"passphrase", func(s *tenant.SecretSettings) { s.EmailRequiresPassphrase = true }, mail(base), ErrSecretPassphraseRequired},
		}
		for _, c := range cases {
			set(c.mod)
			if _, err := f.repo.Create(ctx, f.a, c.in); !errors.Is(err, c.want) || !errors.Is(err, ErrSecretPolicy) {
				t.Errorf("%s: %v, want %v", c.name, err, c.want)
			}
		}
		// The passphrase rule accepts a salted e-mail secret, and a file
		// within the limit starts pending.
		salted := mail(base)
		salted.KDFSalt = bytes.Repeat([]byte{2}, SecretKDFSaltLen)
		if cs := f.create(ctx, t, f.a, salted); cs.Secret.State != SecretPending {
			t.Errorf("salted e-mail secret = %+v", cs.Secret)
		}
		set(func(*tenant.SecretSettings) {})
		if cs := f.create(ctx, t, f.a, withFile(base)); cs.Secret.State != SecretPending || cs.Secret.FileSize != 2<<20 ||
			cs.Secret.FileStorageName != strings.Repeat("ab", 16) {
			t.Errorf("file secret = %+v", cs.Secret)
		}
		// A tenant being deleted creates nothing.
		if err := f.db.Tenants().SetStatus(ctx, f.a, tenant.StatusDeleting); err != nil {
			t.Fatal(err)
		}
		if _, err := f.repo.Create(ctx, f.a, base); !errors.Is(err, ErrNotFound) {
			t.Errorf("deleting tenant: %v", err)
		}
		f.assertNoOrphanKeys(t, "refusals")
	})
}

// TestSecretsExternalCreator forces the e-mail delivery to the inviter.
func TestSecretsExternalCreator(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		f := newSecretFixture(t, e)
		inv := f.invitation(t, f.a, "guest@example.org", "alice@a.example.com")
		in := f.input(newProofs())
		in.CreatorKind, in.InvitationID, in.SenderEmail = SecretCreatorExternal, inv, "guest@example.org"
		in.Delivery, in.RecipientEmail = SecretDeliveryLink, "ignored@example.org"
		s := f.create(ctx, t, f.a, in).Secret
		if s.Delivery != SecretDeliveryEmail || s.RecipientEmail != "alice@a.example.com" || s.InvitationID != inv ||
			s.State != SecretPending {
			t.Fatalf("external secret = %+v", s)
		}
		in.SenderEmail = "intruder@example.org"
		if _, err := f.repo.Create(ctx, f.a, in); !errors.Is(err, ErrInvalid) {
			t.Errorf("invitation of another address: %v", err)
		}
		in.SenderEmail, in.InvitationID = "guest@example.org", id.New(id.Invitation)
		if _, err := f.repo.Create(ctx, f.a, in); !errors.Is(err, ErrNotFound) {
			t.Errorf("unknown invitation: %v", err)
		}
		// Another tenant's invitation is unknown.
		in.InvitationID = inv
		if _, err := f.repo.Create(ctx, f.b, in); !errors.Is(err, ErrNotFound) {
			t.Errorf("invitation of tenant a used in b: %v", err)
		}
		tokIn := f.input(newProofs())
		tokIn.CreatorKind, tokIn.APITokenID = SecretCreatorAPIToken, id.New(id.APIToken)
		if _, err := f.repo.Create(ctx, f.a, tokIn); !errors.Is(err, ErrNotFound) {
			t.Errorf("unknown token: %v", err)
		}
	})
}

// invitation stores an invitation of tid for email issued by inviter.
func (f *secretFixture) invitation(t *testing.T, tid tenant.ID, email, inviter string) string {
	t.Helper()
	invID := id.New(id.Invitation)
	hash := sha256.Sum256([]byte(invID))
	err := rawExecArgs(context.Background(), t, f.db, `INSERT INTO invitations (id, tenant_id, token_hash, email, invited_by,
		created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)`, invID, string(tid), hash[:], email, inviter,
		toMillis(f.now.Add(-time.Hour)), toMillis(f.now.Add(24*time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	return invID
}

// TestSecretsLists checks the pagination and the sender filter.
func TestSecretsLists(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		f := newSecretFixture(t, e)
		in := f.input(newProofs())
		var want []string
		for i := range 3 {
			in.Now = f.now.Add(time.Duration(i) * time.Second)
			want = append([]string{f.create(ctx, t, f.a, in).Secret.ID}, want...)
		}
		tokIn := f.input(newProofs())
		tokIn.CreatorKind, tokIn.APITokenID = SecretCreatorAPIToken, f.apiToken(t, f.a)
		tokIn.Now = f.now.Add(time.Minute)
		tokSecret := f.create(ctx, t, f.a, tokIn).Secret
		f.create(ctx, t, f.b, f.input(newProofs()))

		var got []string
		cursor := ""
		for {
			page, err := f.repo.ListByTenant(ctx, f.a, SecretListOptions{Cursor: cursor, Limit: 1})
			if err != nil {
				t.Fatal(err)
			}
			for _, s := range page.Items {
				got = append(got, s.ID)
			}
			if cursor = page.NextCursor; cursor == "" {
				break
			}
		}
		if len(got) != 4 || got[0] != tokSecret.ID || strings.Join(got[1:], ",") != strings.Join(want, ",") {
			t.Fatalf("ListByTenant = %v, want %s then %v", got, tokSecret.ID, want)
		}
		page, err := f.repo.ListBySender(ctx, f.a, "ALICE@a.example.com", SecretListOptions{})
		if err != nil || len(page.Items) != 3 || page.NextCursor != "" {
			t.Fatalf("ListBySender = %+v, %v", page, err)
		}
		if _, err := f.repo.ListByTenant(ctx, f.a, SecretListOptions{Cursor: "bad"}); !errors.Is(err, ErrInvalid) {
			t.Errorf("bad cursor: %v", err)
		}
		if _, err := f.repo.ListBySender(ctx, f.a, "bad", SecretListOptions{}); !errors.Is(err, ErrInvalid) {
			t.Errorf("bad address: %v", err)
		}

		// The administration listing filters by state and creator, API tokens
		// included.
		for name, c := range map[string]struct {
			f    SecretFilter
			want int
		}{
			"all": {SecretFilter{}, 4}, "active": {SecretFilter{State: SecretActive}, 4},
			"pending": {SecretFilter{State: SecretPending}, 0}, "unknown state": {SecretFilter{State: "nope"}, 0},
			"sender": {SecretFilter{Sender: "ALICE@a.example.com"}, 4}, "other sender": {SecretFilter{Sender: "bob@a.example.com"}, 0},
			"both": {SecretFilter{State: SecretActive, Sender: "alice@a.example.com"}, 4},
		} {
			page, err := f.repo.ListFiltered(ctx, f.a, c.f, SecretListOptions{})
			if err != nil || len(page.Items) != c.want {
				t.Errorf("ListFiltered(%s) = %d items, %v; want %d", name, len(page.Items), err, c.want)
			}
		}
		if _, err := f.repo.ListFiltered(ctx, f.a, SecretFilter{Sender: "bad"}, SecretListOptions{}); !errors.Is(err, ErrInvalid) {
			t.Errorf("filter with a bad address: %v", err)
		}
		if _, err := f.repo.ListFiltered(ctx, f.a, SecretFilter{}, SecretListOptions{Cursor: "bad"}); !errors.Is(err, ErrInvalid) {
			t.Errorf("filter with a bad cursor: %v", err)
		}
	})
}

// TestSecretsPurges checks the pending purge and the tombstone purge.
func TestSecretsPurges(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		f := newSecretFixture(t, e)
		mail := f.input(newProofs())
		mail.Delivery, mail.RecipientEmail = SecretDeliveryEmail, "bob@example.org"
		mail.FileSize, mail.FileMetadata, mail.FileStorageName = 10, "bWV0YQ", strings.Repeat("cd", 16)
		old := f.create(ctx, t, f.a, mail).Secret
		mail.Now, mail.FileStorageName = f.now.Add(SecretPendingRetention), strings.Repeat("ef", 16)
		recent := f.create(ctx, t, f.b, mail).Secret
		at := f.now.Add(SecretPendingRetention + time.Minute)
		out, more, err := f.repo.PurgePending(ctx, at, 10)
		if err != nil || more || len(out) != 1 || out[0].Secret.ID != old.ID || out[0].RemovedFile != old.FileStorageName {
			t.Fatalf("PurgePending = %+v, %v, %v", out, more, err)
		}
		if _, err := f.repo.Get(ctx, f.a, old.ID); !errors.Is(err, ErrNotFound) {
			t.Errorf("purged pending secret: %v", err)
		}
		if _, err := f.repo.Get(ctx, f.b, recent.ID); err != nil {
			t.Errorf("recent pending secret: %v", err)
		}
		f.assertNoOrphanKeys(t, "pending purge")

		// Tombstones: kept 30 days after their end.
		live := f.create(ctx, t, f.a, f.input(newProofs())).Secret
		if _, err := f.repo.DeleteByAdmin(ctx, f.a, live.ID, f.now); err != nil {
			t.Fatal(err)
		}
		if n, err := f.repo.PurgeTombstones(ctx, f.a, f.now.Add(SecretTombstoneRetention-time.Second)); err != nil || n != 0 {
			t.Fatalf("early tombstone purge = %d, %v", n, err)
		}
		if n, err := f.repo.PurgeTombstones(ctx, f.a, f.now.Add(SecretTombstoneRetention)); err != nil || n != 1 {
			t.Fatalf("tombstone purge = %d, %v", n, err)
		}
		if _, err := f.repo.PurgeTombstones(ctx, "bad", f.now); err == nil {
			t.Error("bad tenant accepted")
		}
	})
}

// TestSecretsErasure deletes the secrets of an address, as sender and as
// recipient, before its invitations.
func TestSecretsErasure(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		f := newSecretFixture(t, e)
		const addr = "guest@example.org"
		inv := f.invitation(t, f.a, addr, "alice@a.example.com")
		ext := f.input(newProofs())
		ext.CreatorKind, ext.InvitationID, ext.SenderEmail = SecretCreatorExternal, inv, addr
		ext.FileSize, ext.FileMetadata, ext.FileStorageName = 10, "bWV0YQ", strings.Repeat("9f", 16)
		f.create(ctx, t, f.a, ext)
		toAddr := f.input(newProofs())
		toAddr.Delivery, toAddr.RecipientEmail = SecretDeliveryEmail, addr
		f.create(ctx, t, f.a, toAddr)
		kept := f.create(ctx, t, f.a, f.input(newProofs())).Secret
		other := f.create(ctx, t, f.b, toAddr).Secret

		if n, err := f.repo.CountByAddress(ctx, f.a, "Guest@example.org"); err != nil || n != 2 {
			t.Fatalf("CountByAddress = %d, %v", n, err)
		}
		if _, err := f.repo.CountByAddress(ctx, f.a, "bad"); !errors.Is(err, ErrInvalid) {
			t.Errorf("bad address: %v", err)
		}
		// The invitation cannot go first.
		err := writeScoped(ctx, f.db, f.a, "erase", func(tx *ScopedTx) error {
			_, err := f.db.Invitations().DeleteByEmailTx(ctx, tx, addr)
			return err
		})
		if err == nil {
			t.Fatal("invitation deleted before its secrets")
		}
		rep, err := f.repo.DeleteByAddress(ctx, f.a, addr)
		if err != nil || rep.Deleted != 2 || len(rep.RemovedFiles) != 1 || rep.RemovedFiles[0] != strings.Repeat("9f", 16) {
			t.Fatalf("DeleteByAddress = %+v, %v", rep, err)
		}
		if _, err := f.repo.DeleteByAddress(ctx, f.a, "bad"); !errors.Is(err, ErrInvalid) {
			t.Errorf("bad address: %v", err)
		}
		err = writeScoped(ctx, f.db, f.a, "erase", func(tx *ScopedTx) error {
			_, err := f.db.Invitations().DeleteByEmailTx(ctx, tx, addr)
			return err
		})
		if err != nil {
			t.Fatalf("invitation after its secrets: %v", err)
		}
		if _, err := f.repo.Get(ctx, f.a, kept.ID); err != nil {
			t.Errorf("unrelated secret: %v", err)
		}
		if _, err := f.repo.Get(ctx, f.b, other.ID); err != nil {
			t.Errorf("other tenant's secret: %v", err)
		}
		f.assertNoOrphanKeys(t, "erasure")
	})
}

// TestSecretsDeleteTenant deletes every secret of a tenant before the
// tenant itself.
func TestSecretsDeleteTenant(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		f := newSecretFixture(t, e)
		f.db.purgeBatch = 2
		in := f.input(newProofs())
		for range 3 {
			f.create(ctx, t, f.a, in)
		}
		file := in
		file.Delivery, file.RecipientEmail = SecretDeliveryEmail, "bob@example.org"
		file.FileSize, file.FileMetadata, file.FileStorageName = 10, "bWV0YQ", strings.Repeat("0a", 16)
		f.create(ctx, t, f.a, file)
		ended := f.create(ctx, t, f.a, in).Secret
		if _, err := f.repo.DeleteByAdmin(ctx, f.a, ended.ID, f.now); err != nil {
			t.Fatal(err)
		}
		kept := f.create(ctx, t, f.b, in).Secret
		if err := f.db.Tenants().Delete(ctx, f.a); !errors.Is(err, ErrKeysRemain) {
			t.Fatalf("Tenants.Delete with live secrets: %v", err)
		}
		files, err := f.repo.DeleteTenant(ctx, f.a)
		if err != nil || len(files) != 1 || files[0] != file.FileStorageName {
			t.Fatalf("DeleteTenant = %v, %v", files, err)
		}
		f.assertNoOrphanKeys(t, "tenant deletion")
		if err := f.db.Tenants().Delete(ctx, f.a); err != nil {
			t.Fatalf("Tenants.Delete: %v", err)
		}
		if _, err := f.repo.Get(ctx, f.b, kept.ID); err != nil {
			t.Errorf("other tenant's secret: %v", err)
		}
	})
}

// TestSecretsIsolation attacks tenant a's secret from tenant b.
func TestSecretsIsolation(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		f := newSecretFixture(t, e)
		p := newProofs()
		cs := f.create(ctx, t, f.a, f.input(p))
		if _, err := f.repo.Get(ctx, f.b, cs.Secret.ID); !errors.Is(err, ErrNotFound) {
			t.Errorf("Get from b: %v", err)
		}
		if _, err := f.repo.StatusByToken(ctx, f.b, cs.Token, f.now); !errors.Is(err, ErrNotFound) {
			t.Errorf("StatusByToken from b: %v", err)
		}
		if _, err := f.repo.Reveal(ctx, f.b, cs.Token, p.key, p.proof, f.now); !errors.Is(err, ErrNotFound) {
			t.Errorf("Reveal from b: %v", err)
		}
		if _, err := f.repo.DeleteByAdmin(ctx, f.b, cs.Secret.ID, f.now); !errors.Is(err, ErrNotFound) {
			t.Errorf("DeleteByAdmin from b: %v", err)
		}
		if _, err := f.repo.DeleteByCreator(ctx, f.b, cs.Secret.ID, SecretActor{Email: "alice@a.example.com"}, f.now); !errors.Is(err, ErrNotFound) {
			t.Errorf("DeleteByCreator from b: %v", err)
		}
		if page, err := f.repo.ListByTenant(ctx, f.b, SecretListOptions{}); err != nil || len(page.Items) != 0 {
			t.Errorf("ListByTenant(b) = %+v, %v", page, err)
		}
		if page, err := f.repo.ListBySender(ctx, f.b, "alice@a.example.com", SecretListOptions{}); err != nil || len(page.Items) != 0 {
			t.Errorf("ListBySender(b) = %+v, %v", page, err)
		}
		if n, err := f.repo.CountByAddress(ctx, f.b, "alice@a.example.com"); err != nil || n != 0 {
			t.Errorf("CountByAddress(b) = %d, %v", n, err)
		}
		if rep, err := f.repo.DeleteByAddress(ctx, f.b, "alice@a.example.com"); err != nil || rep.Deleted != 0 {
			t.Errorf("DeleteByAddress(b) = %+v, %v", rep, err)
		}
		if files, err := f.repo.DeleteTenant(ctx, f.b); err != nil || len(files) != 0 {
			t.Errorf("DeleteTenant(b) = %v, %v", files, err)
		}
		if n, err := f.repo.PurgeTombstones(ctx, f.b, f.now.Add(1000*time.Hour)); err != nil || n != 0 {
			t.Errorf("PurgeTombstones(b) = %d, %v", n, err)
		}
		// Tenant a still reads and reveals it.
		if _, err := f.repo.Reveal(ctx, f.a, cs.Token, p.key, p.proof, f.now); err != nil {
			t.Fatalf("Reveal from a: %v", err)
		}
	})
}

// TestSecretsFileRows covers the paths of a row carrying a file, which
// step 3 activates (simulated here with raw SQL).
func TestSecretsFileRows(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		f := newSecretFixture(t, e)
		activate := func(name string) (CreatedSecret, proofs) {
			t.Helper()
			p := newProofs()
			in := f.input(p)
			in.FileSize, in.FileMetadata, in.FileStorageName = 10, "bWV0YQ", name
			cs := f.create(ctx, t, f.a, in)
			var wk string
			err := writeScoped(ctx, f.db, f.a, "file key", func(tx *ScopedTx) error {
				var err error
				wk, _, err = f.keys.NewDEKTx(ctx, tx)
				return err
			})
			if err != nil {
				t.Fatal(err)
			}
			err = rawExecArgs(ctx, t, f.db, `UPDATE secrets SET state = 'active', activated_at = ?, expires_at = ?,
				file_uploaded_at = ?, file_key_id = ? WHERE id = ?`, toMillis(f.now), toMillis(f.now.Add(time.Hour)),
				toMillis(f.now), wk, cs.Secret.ID)
			if err != nil {
				t.Fatal(err)
			}
			return cs, p
		}
		cs, _ := activate(strings.Repeat("1a", 16))
		ended, err := f.repo.DeleteByAdmin(ctx, f.a, cs.Secret.ID, f.now)
		if err != nil || ended.RemovedFile != strings.Repeat("1a", 16) || ended.Secret.FileStorageName != "" || ended.Secret.FileSize != 10 {
			t.Fatalf("delete file secret = %+v, %v", ended, err)
		}
		cs, _ = activate(strings.Repeat("2b", 16))
		out, _, err := f.repo.ExpireDue(ctx, f.now.Add(time.Hour), 10)
		if err != nil || len(out) != 1 || out[0].RemovedFile != strings.Repeat("2b", 16) {
			t.Fatalf("expire file secret = %+v, %v", out, err)
		}
		cs, _ = activate(strings.Repeat("3c", 16))
		if err := rawExecArgs(ctx, t, f.db, `UPDATE secrets SET failed_proofs = 5 WHERE id = ?`, cs.Secret.ID); err != nil {
			t.Fatal(err)
		}
		var removed string
		if err := writeScoped(ctx, f.db, f.a, "lock", func(tx *ScopedTx) error {
			var err error
			removed, err = f.repo.lockTx(ctx, tx, cs.Secret.ID, f.now)
			return err
		}); err != nil || removed != strings.Repeat("3c", 16) {
			t.Fatalf("lock file secret: %q, %v", removed, err)
		}
		if s, _ := f.repo.Get(ctx, f.a, cs.Secret.ID); s.State != SecretLocked || s.FileStorageName != "" {
			t.Errorf("locked file secret = %+v", s)
		}
		f.assertNoOrphanKeys(t, "file rows")
		if n := rawInt(ctx, t, f.db, `SELECT count(*) FROM wrapped_keys`); n != 0 {
			t.Errorf("%d keys left", n)
		}
	})
}

// TestNormalizeCreateSecret checks the input validation.
func TestNormalizeCreateSecret(t *testing.T) {
	t.Parallel()
	f := &secretFixture{now: time.Now()}
	ok := f.input(newProofs())
	if _, err := normalizeCreateSecret(ok); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(c *CreateSecret){
		"kind":             func(c *CreateSecret) { c.CreatorKind = "drop_link" },
		"token of session": func(c *CreateSecret) { c.APITokenID = "tok_x" },
		"token kind":       func(c *CreateSecret) { c.CreatorKind = SecretCreatorAPIToken },
		"invitation":       func(c *CreateSecret) { c.InvitationID = "inv_x" },
		"external":         func(c *CreateSecret) { c.CreatorKind = SecretCreatorExternal },
		"sender":           func(c *CreateSecret) { c.SenderEmail = "x" },
		"link recipient":   func(c *CreateSecret) { c.RecipientEmail = "bob@example.org" },
		"mail recipient":   func(c *CreateSecret) { c.Delivery = SecretDeliveryEmail },
		"delivery":         func(c *CreateSecret) { c.Delivery = "sms" },
		"verifier":         func(c *CreateSecret) { c.Verifier = []byte{1} },
		"key verifier":     func(c *CreateSecret) { c.KeyVerifier = nil },
		"salt":             func(c *CreateSecret) { c.KDFSalt = []byte{1} },
		"short text":       func(c *CreateSecret) { c.SealedText = "abc" },
		"long text":        func(c *CreateSecret) { c.SealedText = strings.Repeat("a", MaxSecretSealedTextLen+1) },
		"text alphabet":    func(c *CreateSecret) { c.SealedText = strings.Repeat("a=", 30) },
		"duration":         func(c *CreateSecret) { c.Duration = "2d" },
		"negative file":    func(c *CreateSecret) { c.FileSize = -1 },
		"huge file":        func(c *CreateSecret) { c.FileSize = tenant.MaxSecretFileBytes + 1 },
		"metadata alone":   func(c *CreateSecret) { c.FileMetadata = "abc" },
		"storage alone":    func(c *CreateSecret) { c.FileStorageName = strings.Repeat("a", 32) },
		"no metadata":      func(c *CreateSecret) { c.FileSize, c.FileStorageName = 1, strings.Repeat("a", 32) },
		"bad storage name": func(c *CreateSecret) { c.FileSize, c.FileMetadata, c.FileStorageName = 1, "abc", "ABC" },
		"metadata alphabet": func(c *CreateSecret) {
			c.FileSize, c.FileMetadata, c.FileStorageName = 1, "a b", strings.Repeat("a", 32)
		},
	}
	for name, mod := range cases {
		c := ok
		mod(&c)
		if _, err := normalizeCreateSecret(c); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestSecretsWithoutKeys checks the operations that need the key vault.
func TestSecretsWithoutKeys(t *testing.T) {
	t.Parallel()
	f := newSecretFixtureDB(t, openMigratedEngine(t, storetest.SQLite(t)))
	ctx := context.Background()
	r := f.db.Secrets(nil)
	var zero [32]byte
	checks := map[string]error{}
	_, checks["Create"] = r.Create(ctx, f.a, f.input(newProofs()))
	_, checks["Reveal"] = r.Reveal(ctx, f.a, "tts_x", zero, zero, f.now)
	_, checks["DeleteByAdmin"] = r.DeleteByAdmin(ctx, f.a, id.New(id.Secret), f.now)
	_, _, checks["PurgePending"] = r.PurgePending(ctx, f.now, 1)
	_, checks["DeleteTenant"] = r.DeleteTenant(ctx, f.a)
	_, checks["DeleteByAddress"] = r.DeleteByAddress(ctx, f.a, "a@example.org")
	for name, err := range checks {
		if !errors.Is(err, errSecretNoKeys) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := r.Get(ctx, f.a, id.New(id.Secret)); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get: %v", err)
	}
}

// TestSecretsFaults injects failures of the key vault and of the database
// on SQLite: every failure rolls the operation back and leaves no
// unreferenced key.
func TestSecretsFaults(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, plan := openFault(t)
	f := newSecretFixtureDB(t, db)
	errKey := errors.New("vault down")

	// Vault failures.
	f.keys.newErr = errKey
	if _, err := f.repo.Create(ctx, f.a, f.input(newProofs())); !errors.Is(err, errKey) {
		t.Errorf("NewDEKTx failure: %v", err)
	}
	f.keys.newErr = nil
	p := newProofs()
	cs := f.create(ctx, t, f.a, f.input(p))
	f.keys.openErr = errKey
	if _, err := f.repo.Reveal(ctx, f.a, cs.Token, p.key, p.proof, f.now); !errors.Is(err, errKey) {
		t.Errorf("OpenTx failure: %v", err)
	}
	f.keys.openErr, f.keys.dstrErr = nil, errKey
	if _, err := f.repo.Reveal(ctx, f.a, cs.Token, p.key, p.proof, f.now); !errors.Is(err, errKey) {
		t.Errorf("DestroyTx failure at reveal: %v", err)
	}
	if _, err := f.repo.DeleteByAdmin(ctx, f.a, cs.Secret.ID, f.now); !errors.Is(err, errKey) {
		t.Errorf("DestroyTx failure at deletion: %v", err)
	}
	if _, err := f.repo.DeleteTenant(ctx, f.a); !errors.Is(err, errKey) {
		t.Errorf("DestroyTx failure at tenant deletion: %v", err)
	}
	if _, err := f.repo.DeleteByAddress(ctx, f.a, "alice@a.example.com"); !errors.Is(err, errKey) {
		t.Errorf("DestroyTx failure at erasure: %v", err)
	}
	if _, _, err := f.repo.ExpireDue(ctx, f.now.Add(2*time.Hour), 10); !errors.Is(err, errKey) {
		t.Errorf("DestroyTx failure at expiry: %v", err)
	}
	wrong := p
	wrong.proof[0] ^= 1
	for range SecretMaxFailedProofs - 1 {
		if _, err := f.repo.Reveal(ctx, f.a, cs.Token, p.key, wrong.proof, f.now); !errors.Is(err, ErrSecretProof) {
			t.Fatalf("wrong proof: %v", err)
		}
	}
	if _, err := f.repo.Reveal(ctx, f.a, cs.Token, p.key, wrong.proof, f.now); !errors.Is(err, errKey) {
		t.Errorf("DestroyTx failure at lock: %v", err)
	}
	f.keys.dstrErr = nil
	// The secret is intact: 4 counted failures, still readable.
	if _, err := f.repo.Reveal(ctx, f.a, cs.Token, p.key, p.proof, f.now); err != nil {
		t.Fatalf("Reveal after the faults: %v", err)
	}
	f.assertNoOrphanKeys(t, "vault faults")

	// Database failures.
	mail := f.input(newProofs())
	mail.Delivery, mail.RecipientEmail = SecretDeliveryEmail, "bob@example.org"
	pending := f.create(ctx, t, f.a, mail)
	p2 := newProofs()
	live := f.create(ctx, t, f.a, f.input(p2))
	steps := []struct {
		op, match string
		after     int
		run       func() error
	}{
		{faultQuery, "AND state IN ('pending', 'active')", 0, func() error {
			_, err := f.repo.Create(ctx, f.a, f.input(newProofs()))
			return err
		}},
		{faultQuery, "AND created_at > ?", 0, func() error {
			_, err := f.repo.Create(ctx, f.a, f.input(newProofs()))
			return err
		}},
		{faultExec, "INSERT INTO secrets", 0, func() error {
			_, err := f.repo.Create(ctx, f.a, f.input(newProofs()))
			return err
		}},
		{faultQuery, "JOIN tenants n", 0, func() error {
			_, err := f.repo.Create(ctx, f.a, f.input(newProofs()))
			return err
		}},
		{faultQuery, "FROM secrets WHERE tenant_id = ? AND id = ?", 0, func() error {
			_, err := f.repo.Create(ctx, f.a, f.input(newProofs()))
			return err
		}},
		{faultQuery, "key_verifier FROM secrets", 0, func() error {
			_, err := f.repo.Reveal(ctx, f.a, live.Token, p2.key, p2.proof, f.now)
			return err
		}},
		{faultExec, "failed_proofs = failed_proofs + 1", 0, func() error {
			_, err := f.repo.Reveal(ctx, f.a, live.Token, p2.key, p2.proof, f.now)
			return err
		}},
		{faultQuery, "SELECT failed_proofs, verifier", 0, func() error {
			_, err := f.repo.Reveal(ctx, f.a, live.Token, p2.key, p2.proof, f.now)
			return err
		}},
		{faultExec, "SET state = 'read'", 0, func() error {
			_, err := f.repo.Reveal(ctx, f.a, live.Token, p2.key, p2.proof, f.now)
			return err
		}},
		{faultQuery, "FROM secrets WHERE tenant_id = ? AND id = ?", 1, func() error {
			_, err := f.repo.Reveal(ctx, f.a, live.Token, p2.key, p2.proof, f.now)
			return err
		}},
		{faultQuery, "FROM secrets WHERE tenant_id = ? AND id = ?", 0, func() error {
			_, err := f.repo.DeleteByAdmin(ctx, f.a, live.Secret.ID, f.now)
			return err
		}},
		{faultExec, "SET state = 'deleted'", 0, func() error {
			_, err := f.repo.DeleteByAdmin(ctx, f.a, live.Secret.ID, f.now)
			return err
		}},
		{faultQuery, "FROM secrets WHERE tenant_id = ? AND id = ?", 1, func() error {
			_, err := f.repo.DeleteByAdmin(ctx, f.a, live.Secret.ID, f.now)
			return err
		}},
		{faultQuery, "FROM secrets WHERE tenant_id = ? AND token_hash = ?", 0, func() error {
			_, err := f.repo.StatusByToken(ctx, f.a, live.Token, f.now)
			return err
		}},
		{faultQuery, "ORDER BY created_at DESC", 0, func() error {
			_, err := f.repo.ListByTenant(ctx, f.a, SecretListOptions{})
			return err
		}},
		{faultQuery, "WHERE state = 'pending'", 0, func() error {
			_, _, err := f.repo.PurgePending(ctx, f.now.Add(2*time.Hour), 10)
			return err
		}},
		{faultQuery, "FROM secrets WHERE tenant_id = ? AND id = ?", 0, func() error {
			_, _, err := f.repo.PurgePending(ctx, f.now.Add(2*time.Hour), 10)
			return err
		}},
		{faultExec, "AND state = 'pending' AND created_at", 0, func() error {
			_, _, err := f.repo.PurgePending(ctx, f.now.Add(2*time.Hour), 10)
			return err
		}},
		{faultQuery, "FROM secrets WHERE tenant_id = ? AND id = ?", 0, func() error {
			_, _, err := f.repo.ExpireDue(ctx, f.now.Add(2*time.Hour), 10)
			return err
		}},
		{faultExec, "SET state = 'expired'", 0, func() error {
			_, _, err := f.repo.ExpireDue(ctx, f.now.Add(2*time.Hour), 10)
			return err
		}},
		{faultQuery, "ORDER BY id LIMIT ?", 0, func() error {
			_, err := f.repo.DeleteTenant(ctx, f.a)
			return err
		}},
		{faultExec, "DELETE FROM secrets WHERE tenant_id = ? AND id = ?", 0, func() error {
			_, err := f.repo.DeleteTenant(ctx, f.a)
			return err
		}},
		{faultQuery, "AND sender_email = ? ORDER BY id", 0, func() error {
			_, err := f.repo.DeleteByAddress(ctx, f.a, "alice@a.example.com")
			return err
		}},
		{faultExec, "DELETE FROM secrets WHERE tenant_id = ? AND id = ?", 0, func() error {
			_, err := f.repo.DeleteByAddress(ctx, f.a, "alice@a.example.com")
			return err
		}},
	}
	for i, s := range steps {
		plan.add(s.op, s.match, s.after)
		if err := s.run(); !errors.Is(err, errInjected) {
			t.Errorf("step %d (%s %q): %v", i, s.op, s.match, err)
		}
		plan.reset()
	}
	// Everything is still in place.
	if _, err := f.repo.Get(ctx, f.a, pending.Secret.ID); err != nil {
		t.Errorf("pending secret: %v", err)
	}
	if _, err := f.repo.Reveal(ctx, f.a, live.Token, p2.key, p2.proof, f.now); err != nil {
		t.Errorf("reveal after the faults: %v", err)
	}
	f.assertNoOrphanKeys(t, "database faults")
}

// TestSecretTextAtRest checks the at-rest encryption helpers.
func TestSecretTextAtRest(t *testing.T) {
	t.Parallel()
	dek := bytes.Repeat([]byte{9}, 32)
	sealed, err := sealSecretText(dek, "ten_a", "sec_a", sealedText)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := openSecretText(dek, "ten_a", "sec_a", sealed); err != nil || got != sealedText {
		t.Fatalf("open = %q, %v", got, err)
	}
	for name, open := range map[string]func() (string, error){
		"other secret": func() (string, error) { return openSecretText(dek, "ten_a", "sec_b", sealed) },
		"other tenant": func() (string, error) { return openSecretText(dek, "ten_b", "sec_a", sealed) },
		"truncated":    func() (string, error) { return openSecretText(dek, "ten_a", "sec_a", sealed[:20]) },
		"bad header":   func() (string, error) { return openSecretText(dek, "ten_a", "sec_a", []byte("x")) },
	} {
		if _, err := open(); err == nil {
			t.Errorf("%s opened", name)
		}
	}
	if _, err := sealSecretText([]byte{1}, "ten_a", "sec_a", "x"); err == nil {
		t.Error("short key accepted")
	}
}

// TestSecretsRevealRace changes the secret between the key proof check and
// the claim: the claim finds no live row and answers with its state.
func TestSecretsRevealRace(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		f := newSecretFixture(t, e)
		p := newProofs()
		cs := f.create(ctx, t, f.a, f.input(p))
		claimHooks.Store(cs.Secret.ID, func() {
			if _, err := f.repo.DeleteByAdmin(ctx, f.a, cs.Secret.ID, f.now); err != nil {
				t.Error(err)
			}
		})
		_, err := f.repo.Reveal(ctx, f.a, cs.Token, p.key, p.proof, f.now)
		gone(t, err, SecretEndDeletedByAdmin)
		// Expired between the two steps: the claim's guard refuses it.
		cs = f.create(ctx, t, f.a, f.input(p))
		_, err = f.repo.Reveal(ctx, f.a, cs.Token, p.key, p.proof, cs.Secret.ExpiresAt.Add(-time.Millisecond))
		if err != nil {
			t.Fatalf("Reveal before expiry: %v", err)
		}
	})
}

// TestSecretsMoreFaults covers the remaining failure paths on SQLite.
func TestSecretsMoreFaults(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, plan := openFault(t)
	f := newSecretFixtureDB(t, db)

	bad := f.input(newProofs())
	bad.SealedText = "x"
	if _, err := f.repo.Create(ctx, f.a, bad); !errors.Is(err, ErrInvalid) {
		t.Errorf("invalid input: %v", err)
	}
	r := f.db.Secrets(f.keys)
	r.newToken = func() (string, error) { return "", errInjected }
	if _, err := r.Create(ctx, f.a, f.input(newProofs())); !errors.Is(err, errInjected) {
		t.Errorf("token failure: %v", err)
	}
	newID := f.db.newID
	f.db.newID = func(id.Prefix) (string, error) { return "", errInjected }
	if _, err := f.repo.Create(ctx, f.a, f.input(newProofs())); !errors.Is(err, errInjected) {
		t.Errorf("id failure: %v", err)
	}
	f.db.newID = newID
	f.keys.shortKey = true
	if _, err := f.repo.Create(ctx, f.a, f.input(newProofs())); err == nil {
		t.Error("short data key accepted")
	}
	f.keys.shortKey = false
	f.assertNoOrphanKeys(t, "creation failures")

	// A key that does not open the text.
	p := newProofs()
	cs := f.create(ctx, t, f.a, f.input(p))
	f.keys.wrongKey = true
	if _, err := f.repo.Reveal(ctx, f.a, cs.Token, p.key, p.proof, f.now); err == nil {
		t.Error("text opened with the wrong key")
	}
	f.keys.wrongKey = false

	// The row read after a failed claim.
	claimHooks.Store(cs.Secret.ID, func() {
		plan.add(faultExec, "failed_proofs = failed_proofs + 1", 0)
	})
	if _, err := f.repo.Reveal(ctx, f.a, cs.Token, p.key, p.proof, f.now); !errors.Is(err, errInjected) {
		t.Errorf("claim failure: %v", err)
	}
	plan.reset()
	claimHooks.Store(cs.Secret.ID, func() {
		if err := rawExecArgs(ctx, t, f.db, `UPDATE secrets SET activated_at = activated_at - 10, expires_at = activated_at - 9 WHERE id = ?`, cs.Secret.ID); err != nil {
			t.Error(err)
		}
		plan.add(faultQuery, "FROM secrets WHERE tenant_id = ? AND id = ?", 0)
	})
	if _, err := f.repo.Reveal(ctx, f.a, cs.Token, p.key, p.proof, f.now); !errors.Is(err, errInjected) {
		t.Errorf("read after a failed claim: %v", err)
	}
	plan.reset()
	claimHooks.Delete(cs.Secret.ID)

	// The lock: reading the row, then the update.
	p = newProofs()
	cs = f.create(ctx, t, f.a, f.input(p))
	wrong := p
	wrong.proof[0] ^= 1
	for range SecretMaxFailedProofs - 1 {
		if _, err := f.repo.Reveal(ctx, f.a, cs.Token, p.key, wrong.proof, f.now); !errors.Is(err, ErrSecretProof) {
			t.Fatal(err)
		}
	}
	for _, s := range []struct {
		op, match string
		after     int
	}{
		{faultQuery, "FROM secrets WHERE tenant_id = ? AND id = ?", 1},
		{faultExec, "SET state = 'locked'", 0},
	} {
		plan.add(s.op, s.match, s.after)
		if _, err := f.repo.Reveal(ctx, f.a, cs.Token, p.key, wrong.proof, f.now); !errors.Is(err, errInjected) {
			t.Errorf("lock fault %q: %v", s.match, err)
		}
		plan.reset()
	}

	// A guarded update that matches nothing.
	err := writeScoped(ctx, f.db, f.a, "end", func(tx *ScopedTx) error {
		row, err := scanSecret(tx.QueryRow(ctx, qSecretGet, cs.Secret.ID), f.a)
		if err != nil {
			return err
		}
		_, err = f.repo.endTx(ctx, tx, row, qSecretExpire, toMillis(f.now), cs.Secret.ID, toMillis(f.now))
		return err
	})
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("endTx on a secret not due: %v", err)
	}
	if ignoreNotFound(ErrNotFound) != nil || !errors.Is(ignoreNotFound(errInjected), errInjected) {
		t.Error("ignoreNotFound")
	}

	// A failing tenant lock (PostgreSQL only).
	d := *f.db.dialect
	d.lockTenant = "SELECT bogus("
	f.db.dialect = &d
	if _, err := f.repo.Create(ctx, f.a, f.input(newProofs())); err == nil {
		t.Error("Create with a failing lock succeeded")
	}
	f.assertNoOrphanKeys(t, "more faults")
}

// TestTenantSecretSettings checks the secret settings of the tenants.
func TestTenantSecretSettings(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		f := newSecretFixture(t, e)
		tenants := f.db.Tenants()
		tn, err := tenants.Get(ctx, f.a)
		if err != nil || tn.Secrets != tenant.DefaultSecretSettings() {
			t.Fatalf("defaults = %+v, %v", tn.Secrets, err)
		}
		created, err := tenants.Create(ctx, &tenant.Tenant{
			SetupState: tenant.SetupStateActive, Name: "C", FQDN: "c.example.com", DefaultLanguage: "en",
			MaxTransferBytes: 1, StorageQuotaBytes: 1, Secrets: tenant.SecretSettings{FileMaxBytes: 7},
		})
		if err != nil || created.Secrets != tenant.DefaultSecretSettings() {
			t.Fatalf("created = %+v, %v", created, err)
		}
		// A creation (the import of a configuration) may give the settings.
		custom := tenant.SecretSettings{
			Enabled: true, Durations: 1 << 3, DefaultDuration: "", FileAllowed: true,
			FileMaxBytes: tenant.MinSecretFileBytes, EmailRequiresPassphrase: true,
		}
		created, err = tenants.Create(ctx, &tenant.Tenant{
			SetupState: tenant.SetupStateActive, Name: "D", FQDN: "d.example.com", DefaultLanguage: "en",
			MaxTransferBytes: 1, StorageQuotaBytes: 1, Secrets: custom,
		})
		if err != nil || created.Secrets != custom {
			t.Fatalf("created with settings = %+v, %v", created, err)
		}
		if tn, err := tenants.Get(ctx, created.ID); err != nil || tn.Secrets != custom {
			t.Fatalf("read back = %+v, %v", tn, err)
		}
		custom.FileMaxBytes = 1
		if _, err = tenants.Create(ctx, &tenant.Tenant{
			SetupState: tenant.SetupStateActive, Name: "E", FQDN: "e.example.com", DefaultLanguage: "en",
			MaxTransferBytes: 1, StorageQuotaBytes: 1, Secrets: custom,
		}); !errors.Is(err, ErrInvalid) {
			t.Fatalf("created with invalid settings: %v", err)
		}

		durations, _ := tenant.NewSecretDurationSet(tenant.SecretDuration30d, tenant.SecretDuration1h, tenant.SecretDuration12h)
		want := tenant.SecretSettings{
			Enabled: false, Durations: durations, DefaultDuration: tenant.SecretDuration30d, FileAllowed: false,
			FileMaxBytes: tenant.MaxSecretFileBytes, EmailAllowed: false, EmailRequiresPassphrase: true,
		}
		got, err := tenants.SetSecretSettings(ctx, f.a, want)
		if err != nil || got.Secrets != want {
			t.Fatalf("SetSecretSettings = %+v, %v", got, err)
		}
		if n := rawInt(ctx, t, f.db, `SELECT count(*) FROM tenants WHERE secret_durations = '1h,12h,30d'`); n != 1 {
			t.Errorf("stored durations not sorted")
		}
		for _, read := range []func() (*tenant.Tenant, error){
			func() (*tenant.Tenant, error) { return tenants.Get(ctx, f.a) },
			func() (*tenant.Tenant, error) { return tenants.TenantByFQDN(ctx, "a.example.com") },
		} {
			if tn, err := read(); err != nil || tn.Secrets != want {
				t.Errorf("read back = %+v, %v", tn, err)
			}
		}
		page, err := tenants.List(ctx, TenantListOptions{})
		if err != nil || len(page.Items) != 4 {
			t.Fatalf("List = %v, %v", page, err)
		}
		// A default that is no longer offered is reset.
		short, _ := tenant.NewSecretDurationSet(tenant.SecretDuration1d)
		want.Durations = short
		got, err = tenants.SetSecretSettings(ctx, f.a, want)
		if err != nil || got.Secrets.DefaultDuration != "" || got.Secrets.EffectiveDefaultDuration() != tenant.SecretDuration1d {
			t.Fatalf("reset default = %+v, %v", got, err)
		}
		// Through UpdateWithPolicies, with the general fields.
		got.Secrets.FileMaxBytes = tenant.MinSecretFileBytes
		got, err = tenants.UpdateWithPolicies(ctx, got, TenantParts{General: true, Secrets: true})
		if err != nil || got.Secrets.FileMaxBytes != tenant.MinSecretFileBytes {
			t.Fatalf("UpdateWithPolicies = %+v, %v", got, err)
		}
		for name, s := range map[string]tenant.SecretSettings{
			"no duration":     {FileMaxBytes: tenant.MinSecretFileBytes},
			"unknown default": {Durations: short, DefaultDuration: "2d", FileMaxBytes: tenant.MinSecretFileBytes},
			"small file":      {Durations: short, FileMaxBytes: tenant.MinSecretFileBytes - 1},
			"large file":      {Durations: short, FileMaxBytes: tenant.MaxSecretFileBytes + 1},
			"unknown code":    {Durations: 1 << 7, FileMaxBytes: tenant.MinSecretFileBytes},
		} {
			if _, err := tenants.SetSecretSettings(ctx, f.a, s); !errors.Is(err, ErrInvalid) {
				t.Errorf("%s: %v", name, err)
			}
		}
		valid := tenant.DefaultSecretSettings()
		if _, err := tenants.SetSecretSettings(ctx, "bad", valid); !errors.Is(err, ErrNotFound) {
			t.Errorf("bad id: %v", err)
		}
		if _, err := tenants.SetSecretSettings(ctx, tenant.ID(id.New(id.Tenant)), valid); !errors.Is(err, ErrNotFound) {
			t.Errorf("unknown tenant: %v", err)
		}
		if err := tenants.SetStatus(ctx, f.b, tenant.StatusDeleting); err != nil {
			t.Fatal(err)
		}
		if _, err := tenants.SetSecretSettings(ctx, f.b, valid); !errors.Is(err, ErrNotFound) {
			t.Errorf("deleting tenant: %v", err)
		}
	})
}

// TestInvitationPurgeKeepsSecretInvitations checks that the invitation purge
// skips an invitation that a secret (a tombstone included) still
// references, instead of failing on the foreign key, on both engines.
func TestInvitationPurgeKeepsSecretInvitations(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		f := newSecretFixture(t, e)
		const addr = "guest@example.org"
		inv := f.invitation(t, f.a, addr, "alice@a.example.com")
		free := f.invitation(t, f.a, addr, "alice@a.example.com")
		in := f.input(newProofs())
		in.CreatorKind, in.InvitationID, in.SenderEmail = SecretCreatorExternal, inv, addr
		s := f.create(ctx, t, f.a, in).Secret
		for _, i := range []string{inv, free} {
			if err := rawExecArgs(ctx, t, f.db, `UPDATE invitations SET revoked_at = ? WHERE id = ?`, toMillis(f.now), i); err != nil {
				t.Fatal(err)
			}
		}
		later := f.now.Add(2 * time.Hour)
		// The secret holds its invitation: only the free one goes.
		if n, err := f.db.Invitations().Purge(ctx, f.a, later); err != nil || n != 1 {
			t.Fatalf("Purge = %d, %v; want 1", n, err)
		}
		if _, err := f.db.Invitations().Get(ctx, f.a, inv); err != nil {
			t.Fatalf("referenced invitation purged: %v", err)
		}
		// Once the secret row is gone, the invitation goes.
		if err := rawExecArgs(ctx, t, f.db, `DELETE FROM secrets WHERE id = ?`, s.ID); err != nil {
			t.Fatal(err)
		}
		if n, err := f.db.Invitations().Purge(ctx, f.a, later); err != nil || n != 1 {
			t.Fatalf("Purge after the secret deletion = %d, %v; want 1", n, err)
		}
	})
}

// TestSecretsSupervisionCountsFault makes the supervision query fail and
// checks that the error surfaces.
func TestSecretsSupervisionCountsFault(t *testing.T) {
	t.Parallel()
	db, plan := openFault(t)
	plan.add(faultQuery, "end_reason = 'locked' AND ended_at", 0)
	if _, err := db.Secrets(nil).SupervisionCounts(context.Background(), time.Now()); !errors.Is(err, errInjected) {
		t.Errorf("query fault: %v", err)
	}
}
