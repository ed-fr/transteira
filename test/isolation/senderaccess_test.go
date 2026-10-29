package isolation_test

import (
	"bytes"
	"database/sql"
	"net/netip"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Addresses of the "my transfers" scenarios: alice is the sender of
// perRecipientTransfer, bob another address of the same tenant.
const (
	meAlice = "alice@entity-a.example.com"
	meBob   = "bob@entity-a.example.com"
)

// meIP is the client IP of the access link requests.
var meIP = netip.MustParseAddr("192.0.2.7")

// meRows are the "my transfers" rows of one tenant for alice: two access
// link requests (address MAC mac), an access link and a session.
type meRows struct {
	mac, link, session []byte
}

// seedMe stores meRows for alice in tid at epoch, valid for an hour.
func seedMe(t *testing.T, db *store.DB, tid tenant.ID, mac []byte) meRows {
	t.Helper()
	ctx := t.Context()
	sa := db.SenderAccess()
	r := meRows{mac: mac, link: downloadHash(t), session: downloadHash(t)}
	for range 2 {
		if _, err := sa.RecordRequest(ctx, tid, mac, meIP, epoch); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := sa.CreateLink(ctx, tid, r.link, meAlice, epoch, epoch.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	s, err := db.Scoped(tid)
	if err != nil {
		t.Fatal(err)
	}
	err = s.Tx(ctx, func(tx *store.ScopedTx) error {
		_, err := sa.CreateSessionTx(ctx, tx, r.session, meAlice, epoch, epoch.Add(time.Hour))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestSenderAccessIsolation attacks A's "my transfers" rows and transfers
// from tenant B, and from another address of tenant A: B never counts,
// consumes, reads, ends, erases or purges A's rows, and neither B nor
// another sender of A lists, reads, extends or probes alice's transfers.
// Every attempt reads as a plain not-found (or an empty result).
func TestSenderAccessIsolation(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := t.Context()
		db := openDB(t, e)
		a, b := newTenant(t, db, fqdnA), newTenant(t, db, fqdnB)
		sa, transfers := db.SenderAccess(), db.Transfers()
		mac := bytes.Repeat([]byte{5}, store.AddressMACSize)
		ra := seedMe(t, db, a.ID, mac)
		la := perRecipientTransfer(t, db, a.ID)
		perRecipientTransfer(t, db, b.ID) // B has a transfer of alice's address too
		sb, err := db.Scoped(b.ID)
		if err != nil {
			t.Fatal(err)
		}
		inB := func(fn func(tx *store.ScopedTx) error) error { return sb.Tx(ctx, fn) }
		now := epoch.Add(time.Minute)

		// Access link requests: B's counts ignore A's rows, B's erasure and
		// purge leave them.
		if c, err := sa.RecordRequest(ctx, b.ID, mac, meIP, now); err != nil || c != (store.AccessRequestCounts{}) {
			t.Errorf("RecordRequest(B) = %+v, %v", c, err)
		}
		_ = inB(func(tx *store.ScopedTx) error {
			if n, err := sa.DeleteRequestsByMACTx(ctx, tx, mac); err != nil || n != 1 {
				t.Errorf("DeleteRequestsByMACTx(B) = %d, %v, want B's own row only", n, err)
			}
			if n, err := sa.DeleteByEmailTx(ctx, tx, meAlice); err != nil || n != 0 {
				t.Errorf("DeleteByEmailTx(B) = %d, %v", n, err)
			}
			return nil
		})
		if _, err := sa.Purge(ctx, b.ID, epoch.Add(24*time.Hour)); err != nil {
			t.Fatal(err)
		}

		// Links and sessions: B neither consumes, reads nor ends them.
		assertNotFound(t, "ConsumeLinkTx", inB(func(tx *store.ScopedTx) error {
			_, err := sa.ConsumeLinkTx(ctx, tx, ra.link, now)
			return err
		}))
		_, err = sa.GetSession(ctx, b.ID, ra.session, now)
		assertNotFound(t, "GetSession", err)
		assertNotFound(t, "EndSession", sa.EndSession(ctx, b.ID, ra.session, now))
		// A hash of A cannot be reused in B.
		_, err = sa.CreateLink(ctx, b.ID, ra.link, meAlice, now, now.Add(time.Hour))
		if err == nil {
			t.Error("CreateLink(B) reused A's link hash")
		}

		// Transfers: B and bob see nothing of alice's transfers in A.
		for name, c := range map[string]struct {
			tid   tenant.ID
			email string
		}{"tenant B": {b.ID, meAlice}, "other address": {a.ID, meBob}} {
			p, err := transfers.ListBySender(ctx, c.tid, c.email, "", 0)
			if err != nil {
				t.Fatal(err)
			}
			for _, it := range p.Items {
				if it.ID == la.ID {
					t.Errorf("ListBySender(%s) lists A's transfer", name)
				}
			}
			_, err = transfers.GetBySender(ctx, c.tid, la.ID, c.email)
			assertNotFound(t, "GetBySender("+name+")", err)
			_, err = transfers.SenderStatus(ctx, c.tid, la.ID, c.email)
			assertNotFound(t, "SenderStatus("+name+")", err)
			s, err := db.Scoped(c.tid)
			if err != nil {
				t.Fatal(err)
			}
			assertNotFound(t, "ExtendTx("+name+")", s.Tx(ctx, func(tx *store.ScopedTx) error {
				_, err := transfers.ExtendTx(ctx, tx, la.ID, c.email, la.ExpiresAt.Add(24*time.Hour), now)
				return err
			}))
			assertNotFound(t, "GetBySenderTx("+name+")", s.Tx(ctx, func(tx *store.ScopedTx) error {
				_, err := transfers.GetBySenderTx(ctx, tx, la.ID, c.email)
				return err
			}))
		}
		if p, err := transfers.ListBySender(ctx, b.ID, meAlice, "", 0); err != nil || len(p.Items) != 1 {
			t.Errorf("ListBySender(B, alice) = %+v, %v, want B's own transfer only", p, err)
		}

		// A is intact.
		if c, err := sa.RecordRequest(ctx, a.ID, mac, meIP, now); err != nil || c != (store.AccessRequestCounts{ByAddress: 2, ByIP: 2}) {
			t.Errorf("A's counts = %+v, %v", c, err)
		}
		if s, err := sa.GetSession(ctx, a.ID, ra.session, now); err != nil || s.Email != meAlice {
			t.Errorf("A's session = %+v, %v", s, err)
		}
		sA, err := db.Scoped(a.ID)
		if err != nil {
			t.Fatal(err)
		}
		err = sA.Tx(ctx, func(tx *store.ScopedTx) error {
			l, err := sa.ConsumeLinkTx(ctx, tx, ra.link, now)
			if err == nil && l.Email != meAlice {
				t.Errorf("A's link = %+v", l)
			}
			return err
		})
		if err != nil {
			t.Errorf("A's link: %v", err)
		}
		if d, err := transfers.Get(ctx, a.ID, la.ID); err != nil || d.ExtensionCount != 0 || !d.ExpiresAt.Equal(la.ExpiresAt) {
			t.Errorf("A's transfer changed: %+v, %v", d.Transfer, err)
		}
		if p, err := transfers.ListBySender(ctx, a.ID, meAlice, "", 0); err != nil || len(p.Items) != 1 || p.Items[0].ID != la.ID {
			t.Errorf("ListBySender(A, alice) = %+v, %v", p, err)
		}
	})
}

// FuzzSenderAccessTokens looks up arbitrary token hashes, and the hashes
// of tenant A, in the scope of tenant B: no access link or session of A is
// ever found, and in A's own scope only A's exact hashes are.
func FuzzSenderAccessTokens(f *testing.F) {
	f.Add(bytes.Repeat([]byte{0}, store.TokenHashSize))
	f.Add(bytes.Repeat([]byte{0xff}, store.TokenHashSize))
	f.Add([]byte("short"))
	ctx := f.Context()
	db, err := store.Open(ctx, storetest.SQLite(f).Config(), store.WithClock(steppingClock()))
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { _ = db.Close() })
	if _, err := db.Migrate(ctx); err != nil {
		f.Fatal(err)
	}
	mk := func(fqdn string) tenant.ID {
		tn, err := db.Tenants().Create(ctx, &tenant.Tenant{
			Name: fqdn, FQDN: fqdn, DefaultLanguage: "fr", MaxTransferBytes: 1 << 30, StorageQuotaBytes: 1 << 30,
		})
		if err != nil {
			f.Fatal(err)
		}
		return tn.ID
	}
	a, b := mk(fqdnA), mk(fqdnB)
	sa := db.SenderAccess()
	link, session := bytes.Repeat([]byte{0x11}, store.TokenHashSize), bytes.Repeat([]byte{0x22}, store.TokenHashSize)
	if _, err := sa.CreateLink(ctx, a, link, meAlice, epoch, epoch.Add(time.Hour)); err != nil {
		f.Fatal(err)
	}
	sA, err := db.Scoped(a)
	if err != nil {
		f.Fatal(err)
	}
	if err := sA.Tx(ctx, func(tx *store.ScopedTx) error {
		_, err := sa.CreateSessionTx(ctx, tx, session, meAlice, epoch, epoch.Add(time.Hour))
		return err
	}); err != nil {
		f.Fatal(err)
	}
	f.Add(link)
	f.Add(session)
	sB, err := db.Scoped(b)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, hash []byte) {
		now := epoch.Add(time.Minute)
		if s, err := sa.GetSession(ctx, b, hash, now); err == nil {
			t.Fatalf("GetSession(B, %x) found %+v", hash, s)
		}
		_ = sB.Tx(ctx, func(tx *store.ScopedTx) error {
			if l, err := sa.ConsumeLinkTx(ctx, tx, hash, now); err == nil {
				t.Fatalf("ConsumeLinkTx(B, %x) found %+v", hash, l)
			}
			return nil
		})
		if s, err := sa.GetSession(ctx, a, hash, now); (err == nil) != bytes.Equal(hash, session) {
			t.Fatalf("GetSession(A, %x) = %+v, %v", hash, s, err)
		}
		// A's link is looked up without being consumed (rolled back).
		_ = sA.Tx(ctx, func(tx *store.ScopedTx) error {
			if _, err := sa.ConsumeLinkTx(ctx, tx, hash, now); (err == nil) != bytes.Equal(hash, link) {
				t.Fatalf("ConsumeLinkTx(A, %x) = %v", hash, err)
			}
			return store.ErrConflict
		})
	})
}

// TestRLSSenderAccess checks on PostgreSQL that raw SQL in the scope of
// tenant A neither sees, changes nor adds "my transfers" rows of tenant B.
func TestRLSSenderAccess(t *testing.T) {
	t.Parallel()
	f, raw := pgFixture(t)
	ctx := t.Context()
	a, b := string(f.a.ID), string(f.b.ID)
	macA, macB := bytes.Repeat([]byte{1}, store.AddressMACSize), bytes.Repeat([]byte{2}, store.AddressMACSize)
	seedMe(t, f.db, f.a.ID, macA)
	rb := seedMe(t, f.db, f.b.ID, macB)

	_ = inTenantTx(ctx, t, raw, &a, func(tx *sql.Tx) error {
		for _, c := range []struct {
			query string
			args  []any
			want  int
		}{
			{`SELECT count(*) FROM access_link_requests WHERE tenant_id = $1`, []any{b}, 0},
			{`SELECT count(*) FROM access_link_requests WHERE address_mac = $1`, []any{macB}, 0},
			{`SELECT count(*) FROM access_link_requests`, nil, 2},
			{`SELECT count(*) FROM sender_access_links WHERE tenant_id = $1`, []any{b}, 0},
			{`SELECT count(*) FROM sender_access_links WHERE token_hash = $1`, []any{rb.link}, 0},
			{`SELECT count(*) FROM sender_access_links WHERE email = $1`, []any{meAlice}, 1},
			{`SELECT count(*) FROM sender_sessions WHERE tenant_id = $1`, []any{b}, 0},
			{`SELECT count(*) FROM sender_sessions WHERE token_hash = $1`, []any{rb.session}, 0},
			{`SELECT count(*) FROM sender_sessions`, nil, 1},
		} {
			if n := countRows(ctx, t, tx, c.query, c.args...); n != c.want {
				t.Errorf("%s = %d, want %d", c.query, n, c.want)
			}
		}
		for _, s := range []struct {
			stmt string
			args []any
		}{
			{`UPDATE access_link_requests SET created_at = 0 WHERE tenant_id = $1`, []any{b}},
			{`DELETE FROM access_link_requests WHERE address_mac = $1`, []any{macB}},
			{`UPDATE sender_access_links SET expires_at = expires_at + 86400000 WHERE token_hash = $1`, []any{rb.link}},
			{`UPDATE sender_access_links SET email = 'mallory@example.net' WHERE tenant_id = $1`, []any{b}},
			{`DELETE FROM sender_access_links WHERE tenant_id = $1`, []any{b}},
			{`UPDATE sender_sessions SET expires_at = expires_at + 86400000 WHERE token_hash = $1`, []any{rb.session}},
			{`UPDATE sender_sessions SET email = 'mallory@example.net' WHERE tenant_id = $1`, []any{b}},
			{`DELETE FROM sender_sessions WHERE tenant_id = $1`, []any{b}},
		} {
			if n := affected(ctx, t, tx, s.stmt, s.args...); n != 0 {
				t.Errorf("%s affected %d rows of B", s.stmt, n)
			}
		}
		return nil
	})

	for _, v := range []struct {
		name string
		stmt string
		args []any
	}{
		{"insert request for B", `INSERT INTO access_link_requests (tenant_id, id, address_mac, client_ip, created_at)
			VALUES ($1, $2, $3, '192.0.2.1', 0)`, []any{b, id.New(id.AccessLinkRequest), macA}},
		{"insert link for B", `INSERT INTO sender_access_links (id, tenant_id, token_hash, email, created_at, expires_at)
			VALUES ($1, $2, $3, 'mallory@example.net', 0, 1)`, []any{id.New(id.SenderAccessLink), b, bytes.Repeat([]byte{8}, 32)}},
		{"insert session for B", `INSERT INTO sender_sessions (id, tenant_id, token_hash, email, created_at, expires_at)
			VALUES ($1, $2, $3, 'mallory@example.net', 0, 1)`, []any{id.New(id.SenderSession), b, bytes.Repeat([]byte{9}, 32)}},
		{"move A's requests to B", `UPDATE access_link_requests SET tenant_id = $1`, []any{b}},
		{"move A's links to B", `UPDATE sender_access_links SET tenant_id = $1`, []any{b}},
		{"move A's sessions to B", `UPDATE sender_sessions SET tenant_id = $1`, []any{b}},
	} {
		t.Run(v.name, func(t *testing.T) {
			err := inTenantTx(ctx, t, raw, &a, func(tx *sql.Tx) error {
				_, err := tx.ExecContext(ctx, v.stmt, v.args...)
				return err
			})
			assertRLSViolation(t, v.name, err)
		})
	}

	// B is intact.
	if s, err := f.db.SenderAccess().GetSession(ctx, f.b.ID, rb.session, epoch); err != nil || s.Email != meAlice {
		t.Errorf("B's session = %+v, %v", s, err)
	}
	if c, err := f.db.SenderAccess().RecordRequest(ctx, f.b.ID, macB, meIP, epoch); err != nil || c.ByAddress != 2 {
		t.Errorf("B's request counts = %+v, %v", c, err)
	}
}
