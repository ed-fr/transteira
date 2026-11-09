package isolation_test

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/masterkey"
	"github.com/ed-fr/transteira/internal/masterkey/masterkeytest"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// secretFixture is a one-time secret of a tenant with its proofs.
type secretFixture struct {
	created         store.CreatedSecret
	keyProof, proof [32]byte
}

// secretNow is the clock of the secret cases.
var secretNow = time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC)

// createSecret stores an active link secret of tid sent by sender through
// the real vault.
func createSecret(t *testing.T, repo *store.Secrets, tid tenant.ID, sender string) secretFixture {
	t.Helper()
	var f secretFixture
	_, _ = rand.Read(f.keyProof[:])
	_, _ = rand.Read(f.proof[:])
	kv, v := sha256.Sum256(f.keyProof[:]), sha256.Sum256(f.proof[:])
	cs, err := repo.Create(t.Context(), tid, store.CreateSecret{
		CreatorKind: store.SecretCreatorInternal, SenderEmail: sender, Delivery: store.SecretDeliveryLink,
		Verifier: v[:], KeyVerifier: kv[:], SealedText: strings.Repeat("sealed-text_", 5),
		Duration: tenant.SecretDuration1d, Now: secretNow,
	})
	if err != nil {
		t.Fatalf("Secrets.Create(%s): %v", tid, err)
	}
	f.created = cs
	return f
}

// newSecretsRepo returns the secret repository of db over a real vault.
func newSecretsRepo(t *testing.T, db *store.DB) *store.Secrets {
	t.Helper()
	kr, err := masterkey.New(masterkeytest.Key(t, "K1"), nil)
	if err != nil {
		t.Fatalf("masterkey.New: %v", err)
	}
	return db.Secrets(masterkey.NewVault(db, kr, nil))
}

// TestSecretsIsolation attacks A's one-time secret from tenant B through
// every repository method: B never reads, finds by token, reveals, deletes,
// lists, counts, erases or purges it, and A's secret stays readable.
func TestSecretsIsolation(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := t.Context()
		f := newFixture(t, e)
		repo := newSecretsRepo(t, f.db)
		const sender = "alice@entity-a.example.com"
		sa := createSecret(t, repo, f.a.ID, sender)
		sb := createSecret(t, repo, f.b.ID, sender)
		secA := sa.created.Secret

		_, err := repo.Get(ctx, f.b.ID, secA.ID)
		assertNotFound(t, "Get", err)
		_, err = repo.StatusByToken(ctx, f.b.ID, sa.created.Token, secretNow)
		assertNotFound(t, "StatusByToken", err)
		_, err = repo.Reveal(ctx, f.b.ID, sa.created.Token, sa.keyProof, sa.proof, secretNow)
		assertNotFound(t, "Reveal", err)
		_, err = repo.DeleteByAdmin(ctx, f.b.ID, secA.ID, secretNow)
		assertNotFound(t, "DeleteByAdmin", err)
		_, err = repo.DeleteByCreator(ctx, f.b.ID, secA.ID, store.SecretActor{Email: sender}, secretNow)
		assertNotFound(t, "DeleteByCreator", err)
		for name, list := range map[string]func() (store.Page[store.Secret], error){
			"ListByTenant": func() (store.Page[store.Secret], error) {
				return repo.ListByTenant(ctx, f.b.ID, store.SecretListOptions{})
			},
			"ListBySender": func() (store.Page[store.Secret], error) {
				return repo.ListBySender(ctx, f.b.ID, sender, store.SecretListOptions{})
			},
			"ListFiltered": func() (store.Page[store.Secret], error) {
				return repo.ListFiltered(ctx, f.b.ID, store.SecretFilter{State: store.SecretActive, Sender: sender}, store.SecretListOptions{})
			},
		} {
			page, err := list()
			if err != nil || len(page.Items) != 1 || page.Items[0].ID != sb.created.Secret.ID {
				t.Errorf("%s(B) = %+v, %v; want B's secret only", name, page.Items, err)
			}
		}
		if n, err := repo.CountByAddress(ctx, f.b.ID, sender); err != nil || n != 1 {
			t.Errorf("CountByAddress(B) = %d, %v", n, err)
		}
		// B erases its own secrets: A's stays.
		if rep, err := repo.DeleteByAddress(ctx, f.b.ID, sender); err != nil || rep.Deleted != 1 {
			t.Errorf("DeleteByAddress(B) = %+v, %v", rep, err)
		}
		if _, err := repo.DeleteTenant(ctx, f.b.ID); err != nil {
			t.Errorf("DeleteTenant(B): %v", err)
		}
		if n, err := repo.PurgeTombstones(ctx, f.b.ID, secretNow.Add(1000*time.Hour)); err != nil || n != 0 {
			t.Errorf("PurgeTombstones(B) = %d, %v", n, err)
		}
		// A's text key cannot be opened nor destroyed from B either.
		vault := masterkey.NewVault(f.db, mustKeyring(t), nil)
		sc, err := f.db.Scoped(f.b.ID)
		if err != nil {
			t.Fatal(err)
		}
		keysA := secretKeyIDs(t, e, f.a.ID, secA.ID)
		_ = sc.Tx(ctx, func(tx *store.ScopedTx) error {
			for _, k := range keysA {
				if _, err := vault.OpenTx(ctx, tx, crypto.PurposeDEK, k); !errors.Is(err, store.ErrNotFound) {
					t.Errorf("OpenTx of A's key from B = %v", err)
				}
			}
			return nil
		})

		rev, err := repo.Reveal(ctx, f.a.ID, sa.created.Token, sa.keyProof, sa.proof, secretNow)
		if err != nil || rev.SealedText != strings.Repeat("sealed-text_", 5) {
			t.Fatalf("A's reveal after the attacks = %+v, %v", rev, err)
		}
	})
}

// mustKeyring returns the keyring of the secret cases.
func mustKeyring(t *testing.T) *masterkey.Keyring {
	t.Helper()
	kr, err := masterkey.New(masterkeytest.Key(t, "K1"), nil)
	if err != nil {
		t.Fatal(err)
	}
	return kr
}

// secretKeyIDs returns the text key ID of the secret secID of tenant tid,
// read with a raw connection (in the scope of tid on PostgreSQL).
func secretKeyIDs(t *testing.T, e storetest.Engine, tid tenant.ID, secID string) []string {
	t.Helper()
	raw := rawDB(t, e)
	q, scope := `SELECT text_key_id FROM secrets WHERE id = ?`, (*string)(nil)
	if e.Driver == "postgres" {
		s := string(tid)
		q, scope = `SELECT text_key_id FROM secrets WHERE id = $1`, &s
	}
	var k sql.NullString
	err := inTenantTx(t.Context(), t, raw, scope, func(tx *sql.Tx) error {
		return tx.QueryRowContext(t.Context(), q, secID).Scan(&k)
	})
	if err != nil || !k.Valid {
		t.Fatalf("read the text key of %s: %v", secID, err)
	}
	return []string{k.String}
}

// TestRLSSecretsCrossTenantRawSQL bypasses the application layer: a raw
// transaction scoped to A aims SELECT, UPDATE, DELETE and INSERT statements
// at B's secret. Row-level security alone must stop them.
func TestRLSSecretsCrossTenantRawSQL(t *testing.T) {
	t.Parallel()
	f, raw := pgFixture(t)
	ctx := t.Context()
	repo := newSecretsRepo(t, f.db)
	secA := createSecret(t, repo, f.a.ID, "alice@entity-a.example.com")
	secB := createSecret(t, repo, f.b.ID, "bob@entity-b.example.org")
	a, b := string(f.a.ID), string(f.b.ID)
	bID, bHash := secB.created.Secret.ID, id.HashToken(secB.created.Token)

	_ = inTenantTx(ctx, t, raw, &a, func(tx *sql.Tx) error {
		for _, c := range []struct {
			query string
			args  []any
			want  int
		}{
			{`SELECT count(*) FROM secrets WHERE tenant_id = $1`, []any{b}, 0},
			{`SELECT count(*) FROM secrets`, nil, 1},
			{`SELECT count(*) FROM secrets WHERE id = $1`, []any{bID}, 0},
			{`SELECT count(*) FROM secrets WHERE token_hash = $1`, []any{bHash}, 0},
			{`SELECT count(*) FROM secrets WHERE true OR tenant_id = $1`, []any{b}, 1},
		} {
			if n := countRows(ctx, t, tx, c.query, c.args...); n != c.want {
				t.Errorf("%s = %d, want %d", c.query, n, c.want)
			}
		}
		for _, s := range []struct {
			stmt string
			args []any
		}{
			{`UPDATE secrets SET failed_proofs = failed_proofs + 1 WHERE id = $1`, []any{bID}},
			{`UPDATE secrets SET duration_code = '30d' WHERE tenant_id = $1`, []any{b}},
			{`DELETE FROM secrets WHERE id = $1`, []any{bID}},
			{`DELETE FROM secrets WHERE tenant_id = $1`, []any{b}},
		} {
			if n := affected(ctx, t, tx, s.stmt, s.args...); n != 0 {
				t.Errorf("%s affected %d rows", s.stmt, n)
			}
		}
		return nil
	})
	for _, v := range []struct {
		name, stmt string
		args       []any
	}{
		{
			"insert a secret for B", `INSERT INTO secrets (id, tenant_id, token_hash, state, creator_kind, sender_email,
			delivery, verifier, key_verifier, text_sealed, text_key_id, duration_code, created_at)
			SELECT $1, $2, $3, 'pending', 'internal', 'x@example.net', 'link', verifier, key_verifier, text_sealed,
			NULL, '1h', 0 FROM secrets WHERE id = $4`,
			[]any{id.New(id.Secret), b, id.HashToken("tts_insert"), secA.created.Secret.ID},
		},
		{"move A's secret to B", `UPDATE secrets SET tenant_id = $1`, []any{b}},
	} {
		t.Run(v.name, func(t *testing.T) {
			err := inTenantTx(ctx, t, raw, &a, func(tx *sql.Tx) error {
				_, err := tx.ExecContext(ctx, v.stmt, v.args...)
				return err
			})
			var pe *pgconn.PgError
			if !errors.As(err, &pe) || pe.Code != pgInsufficientPrivilege {
				t.Errorf("%s: err = %v, want SQLSTATE %s", v.name, err, pgInsufficientPrivilege)
			}
		})
	}
	// Both secrets are intact.
	for _, s := range []struct {
		tid tenant.ID
		f   secretFixture
	}{{f.a.ID, secA}, {f.b.ID, secB}} {
		if _, err := repo.Reveal(ctx, s.tid, s.f.created.Token, s.f.keyProof, s.f.proof, secretNow); err != nil {
			t.Errorf("reveal after the attacks: %v", err)
		}
	}
}
