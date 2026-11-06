package isolation_test

import (
	"database/sql"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Fictitious addresses of the drop link cases (CLAUDE.md section 25):
// dropSharedRecipient is a recipient of a link in both tenants.
const (
	dropSharedRecipient = "accounting@shared.example.net"
	dropDepositor       = "supplier@partner.example.org"
)

// pgForeignKeyViolation is the SQLSTATE of a foreign key violation.
const pgForeignKeyViolation = "23503"

// dropLinkFixture is a drop link created for the cases, with its token.
type dropLinkFixture struct {
	link  store.DropLink
	token string
}

// createDropLink stores an enabled drop link of tid for dropSharedRecipient
// and returns it with its token.
func createDropLink(t *testing.T, db *store.DB, tid tenant.ID, label string) dropLinkFixture {
	t.Helper()
	tok, err := id.NewDropToken()
	if err != nil {
		t.Fatal(err)
	}
	l, err := db.DropLinks().Create(t.Context(), tid, store.DropLink{
		ID: id.New(id.DropLink), TokenHash: id.HashToken(tok), Label: label,
		Recipients: []string{dropSharedRecipient}, ValidityDays: 7, Enabled: true, CreatedBy: "admin",
	})
	if err != nil {
		t.Fatalf("DropLinks.Create(%s): %v", tid, err)
	}
	return dropLinkFixture{link: l, token: tok}
}

// TestDropLinksIsolation attacks A's drop links from tenant B through every
// repository method (T-01, T-3xx of the drop links): B never reads, finds
// by token, changes, rotates, revokes, touches, purges or erases them, its
// counts never include them, and no deposit session or verification code
// of B can be bound to a link of A.
func TestDropLinksIsolation(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := t.Context()
		db := openDB(t, e)
		a, b := newTenant(t, db, fqdnA), newTenant(t, db, fqdnB)
		linkA := createDropLink(t, db, a.ID, "Invoices of A")
		revokedA := createDropLink(t, db, a.ID, "Old link of A")
		linkB := createDropLink(t, db, b.ID, "Invoices of B")
		links := db.DropLinks()
		if _, _, err := links.Revoke(ctx, a.ID, revokedA.link.ID, epoch); err != nil {
			t.Fatalf("Revoke(A's old link): %v", err)
		}

		_, err := links.Get(ctx, b.ID, linkA.link.ID)
		assertNotFound(t, "Get(A's link) from B", err)
		err = scopedTx(t, db, b.ID, func(tx *store.ScopedTx) error {
			_, err := links.GetTx(ctx, tx, linkA.link.ID)
			return err
		})
		assertNotFound(t, "GetTx(A's link) from B", err)
		_, err = links.GetByTokenHash(ctx, b.ID, id.HashToken(linkA.token), time.Time{})
		assertNotFound(t, "GetByTokenHash(A's token) from B", err)
		if list, err := links.List(ctx, b.ID); err != nil || len(list) != 1 || list[0].ID != linkB.link.ID {
			t.Errorf("List(B) = %+v, %v", list, err)
		}
		_, _, err = links.Update(ctx, b.ID, linkA.link.ID, store.DropLinkUpdate{
			Label: "Stolen", Recipients: []string{"thief@example.net"}, Enabled: new(false),
		}, epoch.Add(time.Hour))
		assertNotFound(t, "Update(A's link) from B", err)
		newTok, err := id.NewDropToken()
		if err != nil {
			t.Fatal(err)
		}
		_, err = links.Rotate(ctx, b.ID, linkA.link.ID, id.HashToken(newTok), epoch.Add(time.Hour))
		assertNotFound(t, "Rotate(A's link) from B", err)
		_, _, err = links.Revoke(ctx, b.ID, linkA.link.ID, epoch.Add(time.Hour))
		assertNotFound(t, "Revoke(A's link) from B", err)
		if err := links.TouchLastUsed(ctx, b.ID, linkA.link.ID, epoch.Add(time.Hour)); err != nil {
			t.Errorf("TouchLastUsed(A's link) from B = %v, want no error and no change", err)
		}
		if n, err := links.Purge(ctx, b.ID, epoch.Add(24*365*time.Hour)); err != nil || n != 0 {
			t.Errorf("Purge(B) = %d, %v, want 0", n, err)
		}
		if n, err := links.CountByRecipient(ctx, b.ID, dropSharedRecipient); err != nil || n != 1 {
			t.Errorf("CountByRecipient(B) = %d, %v, want 1 (B's link only)", n, err)
		}
		var erased store.DropLinkErasure
		err = scopedTx(t, db, b.ID, func(tx *store.ScopedTx) error {
			var err error
			erased, err = links.RemoveRecipientTx(ctx, tx, dropSharedRecipient, epoch.Add(time.Hour))
			return err
		})
		if err != nil || erased.Updated != 1 || erased.Disabled != 1 {
			t.Errorf("RemoveRecipientTx(B) = %+v, %v, want B's link only", erased, err)
		}

		// No row of B can point at A's link: the composite foreign keys
		// keep the link in the tenant.
		now := time.Now().UTC().Truncate(time.Millisecond)
		err = db.DepositSessions().Create(ctx, b.ID, store.DepositSession{
			ID: id.New(id.DepositSession), TokenHash: id.HashToken("ds_isolation"), Email: dropDepositor,
			Kind: store.DepositorDropLink, DropLinkID: linkA.link.ID, CreatedAt: now, ExpiresAt: now.Add(time.Hour),
		})
		if err == nil {
			t.Error("DepositSessions.Create in B bound to A's link succeeded")
		}
		chID, err := id.NewToken("vch", 16)
		if err != nil {
			t.Fatal(err)
		}
		err = db.Challenges().Create(ctx, b.ID, store.Challenge{
			ID: chID, Email: dropDepositor, CodeMAC: []byte("mac"), AttemptsRemaining: 2,
			DropLinkID: linkA.link.ID, ClientIP: netip.MustParseAddr("192.0.2.7"), CreatedAt: now, ExpiresAt: now.Add(15 * time.Minute),
		})
		if err == nil {
			t.Error("Challenges.Create in B bound to A's link succeeded")
		}
		for _, table := range []string{"deposit_sessions", "verification_challenges"} {
			if n := rawCount(t, e, table, "drop_link_id", tenant.ID(linkA.link.ID)); n != 0 {
				t.Errorf("%s holds %d rows bound to A's link", table, n)
			}
		}

		// A's links are untouched.
		got, err := links.Get(ctx, a.ID, linkA.link.ID)
		if err != nil || got.Label != linkA.link.Label || !got.Usable(epoch) || !got.LastUsedAt.IsZero() ||
			!slices.Equal(got.Recipients, []string{dropSharedRecipient}) || !got.UpdatedAt.Equal(linkA.link.UpdatedAt) {
			t.Errorf("A's link after B's attempts = %+v, %v", got, err)
		}
		if got, err := links.GetByTokenHash(ctx, a.ID, id.HashToken(linkA.token), time.Time{}); err != nil || got.ID != linkA.link.ID {
			t.Errorf("A's token after B's attempts = %+v, %v", got, err)
		}
		if got, err := links.Get(ctx, a.ID, revokedA.link.ID); err != nil || !got.Revoked() {
			t.Errorf("A's revoked link after B's purge = %+v, %v", got, err)
		}
		if n, err := links.CountByRecipient(ctx, a.ID, dropSharedRecipient); err != nil || n != 2 {
			t.Errorf("CountByRecipient(A) = %d, %v, want 2", n, err)
		}
		// And B's link never answers under A.
		_, err = links.GetByTokenHash(ctx, a.ID, id.HashToken(linkB.token), time.Time{})
		assertNotFound(t, "GetByTokenHash(B's token) from A", err)

		// Deleting a tenant removes its links only.
		if err := db.Tenants().Delete(ctx, b.ID); err != nil {
			t.Fatalf("Delete(B): %v", err)
		}
		if n := rawCount(t, e, "drop_links", "tenant_id", b.ID); n != 0 {
			t.Errorf("drop_links holds %d rows of deleted B", n)
		}
		if n := rawCount(t, e, "drop_links", "tenant_id", a.ID); n != 2 {
			t.Errorf("drop_links holds %d rows of A, want 2", n)
		}
	})
}

// TestRLSDropLinksCrossTenantRawSQL bypasses the application layer: a raw
// transaction scoped to A aims SELECT, UPDATE, DELETE and INSERT statements
// at B's drop link and binds a verification code of A to it. Row-level
// security (and the composite foreign key) alone must stop them.
func TestRLSDropLinksCrossTenantRawSQL(t *testing.T) {
	t.Parallel()
	f, raw := pgFixture(t)
	ctx := t.Context()
	linkA := createDropLink(t, f.db, f.a.ID, "Invoices of A")
	linkB := createDropLink(t, f.db, f.b.ID, "Invoices of B")
	a, b := string(f.a.ID), string(f.b.ID)

	_ = inTenantTx(ctx, t, raw, &a, func(tx *sql.Tx) error {
		for _, c := range []struct {
			query string
			args  []any
			want  int
		}{
			{`SELECT count(*) FROM drop_links WHERE tenant_id = $1`, []any{b}, 0},
			{`SELECT count(*) FROM drop_links`, nil, 1},
			{`SELECT count(*) FROM drop_links WHERE id = $1`, []any{linkB.link.ID}, 0},
			{`SELECT count(*) FROM drop_links WHERE token_hash = $1`, []any{id.HashToken(linkB.token)}, 0},
			{`SELECT count(*) FROM drop_links WHERE true OR tenant_id = $1`, []any{b}, 1},
		} {
			if n := countRows(ctx, t, tx, c.query, c.args...); n != c.want {
				t.Errorf("%s = %d, want %d", c.query, n, c.want)
			}
		}
		for _, s := range []struct {
			stmt string
			args []any
		}{
			{`UPDATE drop_links SET enabled = false WHERE tenant_id = $1`, []any{b}},
			{`UPDATE drop_links SET token_hash = $2 WHERE id = $1`, []any{linkB.link.ID, id.HashToken("ttd_forged")}},
			{`UPDATE drop_links SET revoked_at = 1 WHERE id = $1`, []any{linkB.link.ID}},
			{`DELETE FROM drop_links WHERE tenant_id = $1`, []any{b}},
			{`DELETE FROM drop_links WHERE id = $1`, []any{linkB.link.ID}},
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
		code string
	}{
		{
			"insert a drop link for B", `INSERT INTO drop_links (id, tenant_id, token_hash, label, recipients, validity_days,
			enabled, created_by, created_at, updated_at) VALUES ($1, $2, $3, 'x', '["x@example.net"]', 7, true, 'x', 0, 0)`,
			[]any{id.New(id.DropLink), b, id.HashToken("ttd_insert")},
			pgInsufficientPrivilege,
		},
		{"move A's link to B", `UPDATE drop_links SET tenant_id = $1`, []any{b}, pgInsufficientPrivilege},
		{
			"bind a code of A to B's link", `INSERT INTO verification_challenges (id, tenant_id, email, code_mac,
			attempts_remaining, client_ip, created_at, expires_at, drop_link_id) VALUES ($1, $2, 'x@example.net', '\x00', 2,
			'192.0.2.1', 0, 1, $3)`,
			[]any{"vch_AAAAAAAAAAAAAAAAAAAAAA", a, linkB.link.ID},
			pgForeignKeyViolation,
		},
		{
			"bind a session of A to B's link", `INSERT INTO deposit_sessions (id, tenant_id, token_hash, email, kind,
			created_at, expires_at, drop_link_id) VALUES ($1, $2, $3, 'x@example.net', 'drop_link', 0, 1, $4)`,
			[]any{id.New(id.DepositSession), a, id.HashToken("ds_insert"), linkB.link.ID},
			pgForeignKeyViolation,
		},
	} {
		t.Run(v.name, func(t *testing.T) {
			err := inTenantTx(ctx, t, raw, &a, func(tx *sql.Tx) error {
				_, err := tx.ExecContext(ctx, v.stmt, v.args...)
				return err
			})
			var pe *pgconn.PgError
			if !errors.As(err, &pe) || pe.Code != v.code {
				t.Errorf("%s: err = %v, want SQLSTATE %s", v.name, err, v.code)
			}
		})
	}
	for _, l := range []dropLinkFixture{linkA, linkB} {
		tid := f.a.ID
		if l.link.ID == linkB.link.ID {
			tid = f.b.ID
		}
		got, err := f.db.DropLinks().GetByTokenHash(ctx, tid, id.HashToken(l.token), time.Time{})
		if err != nil || got.ID != l.link.ID || !got.Usable(epoch) {
			t.Errorf("link %s after the attacks = %+v, %v", l.link.ID, got, err)
		}
	}
}
