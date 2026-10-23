package isolation_test

import (
	"crypto/sha256"
	"database/sql"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// apiTokenHash returns the SHA-256 of a fictitious token secret (the
// secrets themselves never appear in the tests).
func apiTokenHash(label string) []byte {
	h := sha256.Sum256([]byte("api token " + label))
	return h[:]
}

// createAPIToken stores a token of tid whose secret hashes to
// apiTokenHash(label).
func createAPIToken(t *testing.T, db *store.DB, tid tenant.ID, label string) store.APIToken {
	t.Helper()
	tok, err := db.APITokens().Create(t.Context(), tid, store.APIToken{
		ID: id.New(id.APIToken), Name: "Export " + label, Prefix: "tt_Ab12", TokenHash: apiTokenHash(label),
		AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}, CreatedBy: "admin." + label,
	})
	if err != nil {
		t.Fatalf("APITokens.Create: %v", err)
	}
	return tok
}

// TestAPITokensIsolation attacks A's token from tenant B through every
// repository method (T-69): B never reads, changes, revokes or touches it,
// cannot attach it to its own transfers, and every attempt reads as a
// plain not-found.
func TestAPITokensIsolation(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := t.Context()
		db := openDB(t, e)
		a, b := newTenant(t, db, fqdnA), newTenant(t, db, fqdnB)
		tokA := createAPIToken(t, db, a.ID, "a")
		tokB := createAPIToken(t, db, b.ID, "b")
		tokens := db.APITokens()

		if _, err := tokens.Get(ctx, b.ID, tokA.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get(A's token) from B = %v", err)
		}
		if _, err := tokens.GetByHash(ctx, b.ID, apiTokenHash("a")); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GetByHash(A's secret) from B = %v", err)
		}
		if list, err := tokens.List(ctx, b.ID); err != nil || len(list) != 1 || list[0].ID != tokB.ID {
			t.Errorf("List(B) = %+v, %v", list, err)
		}
		if _, err := tokens.Update(ctx, b.ID, tokA.ID, store.APITokenUpdate{Name: "Stolen"}); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Update(A's token) from B = %v", err)
		}
		if _, _, err := tokens.Revoke(ctx, b.ID, tokA.ID, time.Time{}); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Revoke(A's token) from B = %v", err)
		}
		if err := tokens.TouchLastUsed(ctx, b.ID, tokA.ID, time.Now()); err != nil {
			t.Errorf("TouchLastUsed(A's token) from B = %v", err)
		}
		got, err := tokens.Get(ctx, a.ID, tokA.ID)
		if err != nil || got.Name != tokA.Name || got.Revoked() || !got.LastUsedAt.IsZero() {
			t.Errorf("A's token after B's attempts = %+v, %v", got, err)
		}

		// B cannot create a transfer on A's token.
		tr := store.Transfer{
			ID: id.New(id.Transfer), SenderEmail: "alice@entity-a.example.com", SenderKind: store.DepositorInternal,
			ExpiryDays: 7, APITokenID: tokA.ID,
		}
		fl := newTransferFile(t, db, b.ID)
		s, err := db.Scoped(b.ID)
		if err != nil {
			t.Fatal(err)
		}
		err = s.Tx(ctx, func(tx *store.ScopedTx) error {
			return db.Transfers().CreateTx(ctx, tx, tr, []string{"bob@partner.example.net"}, []store.TransferFile{fl})
		})
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("CreateTx in B with A's token = %v, want ErrNotFound", err)
		}
		// Neither reaches the open transfers of the other's token.
		err = s.Tx(ctx, func(tx *store.ScopedTx) error {
			n, err := db.Transfers().CountUploadingByTokenTx(ctx, tx, tokA.ID, time.Time{})
			if err != nil || n != 0 {
				t.Errorf("CountUploadingByTokenTx(A's token) from B = %d, %v", n, err)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}

		// Deleting a tenant removes its tokens only.
		c := newTenant(t, db, "transfer.entity-c.example.com")
		createAPIToken(t, db, c.ID, "c")
		if err := db.Tenants().Delete(ctx, c.ID); err != nil {
			t.Fatalf("Delete(C): %v", err)
		}
		if n := rawCount(t, e, "api_tokens", "tenant_id", c.ID); n != 0 {
			t.Errorf("api_tokens holds %d rows of deleted C", n)
		}
		if n := rawCount(t, e, "api_tokens", "tenant_id", a.ID); n != 1 {
			t.Errorf("api_tokens holds %d rows of A, want 1", n)
		}
	})
}

// TestRLSAPITokensCrossTenantRawSQL bypasses the application layer: a raw
// transaction scoped to A aims SELECT, UPDATE, DELETE and INSERT statements
// at B's API token. Row-level security alone must stop them.
func TestRLSAPITokensCrossTenantRawSQL(t *testing.T) {
	t.Parallel()
	f, raw := pgFixture(t)
	ctx := t.Context()
	createAPIToken(t, f.db, f.a.ID, "a")
	tokB := createAPIToken(t, f.db, f.b.ID, "b")
	a, b := string(f.a.ID), string(f.b.ID)

	_ = inTenantTx(ctx, t, raw, &a, func(tx *sql.Tx) error {
		for _, c := range []struct {
			query string
			args  []any
			want  int
		}{
			{`SELECT count(*) FROM api_tokens WHERE tenant_id = $1`, []any{b}, 0},
			{`SELECT count(*) FROM api_tokens`, nil, 1},
			{`SELECT count(*) FROM api_tokens WHERE token_hash = $1`, []any{apiTokenHash("b")}, 0},
			{`SELECT count(*) FROM api_tokens WHERE true OR tenant_id = $1`, []any{b}, 1},
		} {
			if n := countRows(ctx, t, tx, c.query, c.args...); n != c.want {
				t.Errorf("%s = %d, want %d", c.query, n, c.want)
			}
		}
		for _, s := range []struct {
			stmt string
			args []any
		}{
			{`UPDATE api_tokens SET revoked_at = 1 WHERE tenant_id = $1`, []any{b}},
			{`UPDATE api_tokens SET allowed_cidrs = '["0.0.0.0/0"]' WHERE id = $1`, []any{tokB.ID}},
			{`DELETE FROM api_tokens WHERE tenant_id = $1`, []any{b}},
		} {
			if n := affected(ctx, t, tx, s.stmt, s.args...); n != 0 {
				t.Errorf("%s affected %d rows", s.stmt, n)
			}
		}
		return nil
	})

	for _, v := range []struct {
		name string
		stmt string
		args []any
	}{
		{
			"insert a token for B", `INSERT INTO api_tokens (id, tenant_id, name, prefix, token_hash, allowed_cidrs, created_by,
			created_at) VALUES ($1, $2, 'x', 'tt_x', $3, '["0.0.0.0/0"]', 'x', 0)`,
			[]any{id.New(id.APIToken), b, apiTokenHash("forged")},
		},
		{"move A's token to B", `UPDATE api_tokens SET tenant_id = $1`, []any{b}},
	} {
		t.Run(v.name, func(t *testing.T) {
			err := inTenantTx(ctx, t, raw, &a, func(tx *sql.Tx) error {
				_, err := tx.ExecContext(ctx, v.stmt, v.args...)
				return err
			})
			assertRLSViolation(t, v.name, err)
		})
	}
	got, err := f.db.APITokens().Get(ctx, f.b.ID, tokB.ID)
	if err != nil || got.Revoked() || len(got.AllowedCIDRs) != 1 || got.AllowedCIDRs[0].String() != "192.0.2.0/24" {
		t.Errorf("B's token after the attacks = %+v, %v", got, err)
	}
}
