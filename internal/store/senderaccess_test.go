package store_test

import (
	"bytes"
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// badTenant is a malformed tenant ID.
const badTenant = tenant.ID("ten_x")

// addressMAC returns a well-formed address MAC filled with b.
func addressMAC(b byte) []byte { return bytes.Repeat([]byte{b}, store.AddressMACSize) }

func TestSenderAccessRequests(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		sa := db.SenderAccess()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")
		ip1, ip2 := netip.MustParseAddr("192.0.2.7"), netip.MustParseAddr("::ffff:198.51.100.9")
		macX, macY := addressMAC(1), addressMAC(2)

		// Invalid input writes nothing.
		_, err := sa.RecordRequest(ctx, a.ID, macX[:31], ip1, fixedNow)
		wantErr(t, "short mac", err, store.ErrInvalid)
		_, err = sa.RecordRequest(ctx, a.ID, macX, netip.Addr{}, fixedNow)
		wantErr(t, "zero ip", err, store.ErrInvalid)
		_, err = sa.RecordRequest(ctx, badTenant, macX, ip1, fixedNow)
		wantErr(t, "bad tenant", err, store.ErrInvalid)

		record := func(tid tenant.ID, mac []byte, ip netip.Addr, at time.Time) store.AccessRequestCounts {
			t.Helper()
			c, err := sa.RecordRequest(ctx, tid, mac, ip, at)
			if err != nil {
				t.Fatalf("RecordRequest: %v", err)
			}
			return c
		}
		// A request older than the window is not counted.
		record(a.ID, macX, ip1, fixedNow.Add(-store.AccessRateWindow-time.Millisecond))
		if c := record(a.ID, macX, ip1, fixedNow); c != (store.AccessRequestCounts{}) {
			t.Errorf("first request counts = %+v, want zero", c)
		}
		// The window boundary is included.
		record(a.ID, macY, ip1, fixedNow.Add(-store.AccessRateWindow))
		if c := record(a.ID, macX, ip2, fixedNow); c != (store.AccessRequestCounts{ByAddress: 1, ByIP: 0}) {
			t.Errorf("same address, other ip = %+v", c)
		}
		if c := record(a.ID, macY, ip1, fixedNow); c != (store.AccessRequestCounts{ByAddress: 1, ByIP: 2}) {
			t.Errorf("other address, same ip = %+v", c)
		}
		// Another tenant counts its own requests only.
		if c := record(b.ID, macX, ip1, fixedNow); c != (store.AccessRequestCounts{}) {
			t.Errorf("tenant B counts = %+v, want zero", c)
		}
		// RecordRequestTx: same counts, inside the caller's transaction,
		// rolled back with it.
		err = inTxCtx(ctx, t, db, a.ID, func(tx *store.ScopedTx) error {
			c, err := sa.RecordRequestTx(ctx, tx, macX, ip2, fixedNow)
			if err != nil || c != (store.AccessRequestCounts{ByAddress: 2, ByIP: 1}) {
				t.Errorf("RecordRequestTx = %+v, %v", c, err)
			}
			_, err = sa.RecordRequestTx(ctx, tx, nil, ip2, fixedNow)
			wantErr(t, "RecordRequestTx(nil mac)", err, store.ErrInvalid)
			return store.ErrConflict // roll back
		})
		wantErr(t, "rollback", err, store.ErrConflict)

		// Erasure by MAC: A's rows of X only.
		err = inTxCtx(ctx, t, db, a.ID, func(tx *store.ScopedTx) error {
			if _, err := sa.DeleteRequestsByMACTx(ctx, tx, []byte{1}); err == nil {
				t.Error("DeleteRequestsByMACTx(short mac) succeeded")
			}
			n, err := sa.DeleteRequestsByMACTx(ctx, tx, macX)
			if err != nil || n != 3 {
				t.Errorf("DeleteRequestsByMACTx = %d, %v, want 3", n, err)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if c := record(a.ID, macX, ip1, fixedNow); c != (store.AccessRequestCounts{ByAddress: 0, ByIP: 2}) {
			t.Errorf("after erasure = %+v", c)
		}
		if c := record(b.ID, macX, ip1, fixedNow); c != (store.AccessRequestCounts{ByAddress: 1, ByIP: 1}) {
			t.Errorf("tenant B after A's erasure = %+v", c)
		}
	})
}

// TestSenderAccessRequestsPerIPLimit checks that a request refused by the
// per-IP limit is not recorded (no row, no budget of its address used) and
// that an IPv6 client is keyed by its /64.
func TestSenderAccessRequestsPerIPLimit(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		sa := db.SenderAccess()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		record := func(mac []byte, ip netip.Addr) store.AccessRequestCounts {
			t.Helper()
			c, err := sa.RecordRequest(ctx, a.ID, mac, ip, fixedNow)
			if err != nil {
				t.Fatalf("RecordRequest: %v", err)
			}
			return c
		}

		// IPv6: two addresses of one /64 are one client, another /64 is
		// another client.
		v6a, v6b := netip.MustParseAddr("2001:db8:1:2::1"), netip.MustParseAddr("2001:db8:1:2:ffff:ffff:ffff:fffe%eth0")
		other := netip.MustParseAddr("2001:db8:1:3::1")
		record(addressMAC(10), v6a)
		if c := record(addressMAC(11), v6b); c.ByIP != 1 {
			t.Errorf("same /64: ByIP = %d, want 1", c.ByIP)
		}
		if c := record(addressMAC(12), other); c.ByIP != 0 {
			t.Errorf("other /64: ByIP = %d, want 0", c.ByIP)
		}

		// IPv4: the requests beyond the limit are counted but not
		// recorded.
		ip := netip.MustParseAddr("192.0.2.50")
		for i := range store.AccessRequestsPerIP {
			if c := record(addressMAC(byte(20+i)), ip); c.ByIP != i {
				t.Fatalf("request %d: ByIP = %d", i, c.ByIP)
			}
		}
		victim := addressMAC(99)
		for range 3 {
			if c := record(victim, ip); c != (store.AccessRequestCounts{ByIP: store.AccessRequestsPerIP}) {
				t.Errorf("refused request counts = %+v, want ByIP %d only", c, store.AccessRequestsPerIP)
			}
		}
		// The refused requests left no row: the victim's budget is intact.
		if c := record(victim, netip.MustParseAddr("192.0.2.51")); c != (store.AccessRequestCounts{}) {
			t.Errorf("victim after the refused requests = %+v, want zero", c)
		}
		err := inTxCtx(ctx, t, db, a.ID, func(tx *store.ScopedTx) error {
			n, err := sa.DeleteRequestsByMACTx(ctx, tx, victim)
			if err != nil || n != 1 {
				t.Errorf("victim rows = %d, %v, want 1", n, err)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	})
}

func TestSenderAccessLinks(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		sa := db.SenderAccess()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")
		exp := fixedNow.Add(15 * time.Minute)

		// Invalid links.
		h := randomHash(t)
		_, err := sa.CreateLink(ctx, a.ID, h, "not an address", fixedNow, exp)
		wantErr(t, "bad address", err, store.ErrInvalid)
		_, err = sa.CreateLink(ctx, a.ID, h[:16], "alice@entity-a.example.com", fixedNow, exp)
		wantErr(t, "short hash", err, store.ErrInvalid)
		_, err = sa.CreateLink(ctx, a.ID, h, "alice@entity-a.example.com", fixedNow, fixedNow)
		wantErr(t, "no validity", err, store.ErrInvalid)
		_, err = sa.CreateLink(ctx, badTenant, h, "alice@entity-a.example.com", fixedNow, exp)
		wantErr(t, "bad tenant", err, store.ErrInvalid)

		l, err := sa.CreateLink(ctx, a.ID, h, "Alice@Entity-A.example.com", fixedNow, exp)
		if err != nil {
			t.Fatalf("CreateLink: %v", err)
		}
		if l.ID == "" || l.Email != "alice@entity-a.example.com" || !l.CreatedAt.Equal(fixedNow) || !l.ExpiresAt.Equal(exp) ||
			!l.ConsumedAt.IsZero() {
			t.Errorf("CreateLink = %+v", l)
		}
		// A hash is unique across tenants.
		_, err = sa.CreateLink(ctx, b.ID, h, "alice@entity-a.example.com", fixedNow, exp)
		wantErr(t, "duplicate hash", err, store.ErrConflict)

		consume := func(tid tenant.ID, hash []byte, at time.Time) (store.SenderAccessLink, error) {
			var got store.SenderAccessLink
			err := inTxCtx(ctx, t, db, tid, func(tx *store.ScopedTx) error {
				var err error
				got, err = sa.ConsumeLinkTx(ctx, tx, hash, at)
				return err
			})
			return got, err
		}
		_, err = consume(a.ID, h[:5], fixedNow)
		wantErr(t, "consume short hash", err, store.ErrInvalid)
		_, err = consume(a.ID, randomHash(t), fixedNow)
		wantErr(t, "consume unknown", err, store.ErrNotFound)
		_, err = consume(b.ID, h, fixedNow)
		wantErr(t, "consume from another tenant", err, store.ErrNotFound)
		_, err = consume(a.ID, h, exp)
		wantErr(t, "consume at expiry", err, store.ErrNotFound)
		at := fixedNow.Add(time.Minute)
		got, err := consume(a.ID, h, at)
		if err != nil || got.ID != l.ID || got.Email != l.Email || !got.ConsumedAt.Equal(at.Truncate(time.Millisecond)) ||
			!got.ExpiresAt.Equal(exp.Truncate(time.Millisecond)) || !got.CreatedAt.Equal(fixedNow.Truncate(time.Millisecond)) {
			t.Errorf("ConsumeLinkTx = %+v, %v", got, err)
		}
		_, err = consume(a.ID, h, at)
		wantErr(t, "consume twice", err, store.ErrNotFound)

		// CreateLinkTx, rolled back with the transaction.
		h2 := randomHash(t)
		err = inTxCtx(ctx, t, db, a.ID, func(tx *store.ScopedTx) error {
			if _, err := sa.CreateLinkTx(ctx, tx, h2, "bob@entity-a.example.com", fixedNow, exp); err != nil {
				t.Errorf("CreateLinkTx: %v", err)
			}
			_, err := sa.CreateLinkTx(ctx, tx, nil, "bob@entity-a.example.com", fixedNow, exp)
			wantErr(t, "CreateLinkTx(nil hash)", err, store.ErrInvalid)
			return store.ErrConflict
		})
		wantErr(t, "rollback", err, store.ErrConflict)
		_, err = consume(a.ID, h2, fixedNow)
		wantErr(t, "rolled back link", err, store.ErrNotFound)
	})
}

func TestSenderSessions(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		sa := db.SenderAccess()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")
		exp := fixedNow.Add(time.Hour)
		create := func(tid tenant.ID, hash []byte, email string, end time.Time) (store.SenderSession, error) {
			var s store.SenderSession
			err := inTxCtx(ctx, t, db, tid, func(tx *store.ScopedTx) error {
				var err error
				s, err = sa.CreateSessionTx(ctx, tx, hash, email, fixedNow, end)
				return err
			})
			return s, err
		}
		h := randomHash(t)
		_, err := create(a.ID, h, "nope", exp)
		wantErr(t, "bad address", err, store.ErrInvalid)
		_, err = create(a.ID, h[:1], "alice@entity-a.example.com", exp)
		wantErr(t, "short hash", err, store.ErrInvalid)
		_, err = create(a.ID, h, "alice@entity-a.example.com", fixedNow.Add(-time.Second))
		wantErr(t, "expired at creation", err, store.ErrInvalid)

		s, err := create(a.ID, h, "ALICE@entity-a.example.com", exp)
		if err != nil || s.ID == "" || s.Email != "alice@entity-a.example.com" || !s.ExpiresAt.Equal(exp) {
			t.Fatalf("CreateSessionTx = %+v, %v", s, err)
		}
		_, err = create(b.ID, h, "alice@entity-a.example.com", exp)
		wantErr(t, "duplicate hash", err, store.ErrConflict)

		// Lookups.
		got, err := sa.GetSession(ctx, a.ID, h, fixedNow)
		if err != nil || got.ID != s.ID || got.Email != s.Email || !got.CreatedAt.Equal(fixedNow.Truncate(time.Millisecond)) ||
			!got.ExpiresAt.Equal(exp.Truncate(time.Millisecond)) {
			t.Errorf("GetSession = %+v, %v", got, err)
		}
		_, err = sa.GetSession(ctx, b.ID, h, fixedNow)
		wantErr(t, "other tenant", err, store.ErrNotFound)
		_, err = sa.GetSession(ctx, a.ID, randomHash(t), fixedNow)
		wantErr(t, "unknown", err, store.ErrNotFound)
		_, err = sa.GetSession(ctx, a.ID, h, exp)
		wantErr(t, "expired", err, store.ErrNotFound)
		_, err = sa.GetSession(ctx, a.ID, h[:3], fixedNow)
		wantErr(t, "short hash", err, store.ErrInvalid)
		_, err = sa.GetSession(ctx, badTenant, h, fixedNow)
		wantErr(t, "bad tenant", err, store.ErrInvalid)

		// End.
		wantErr(t, "end short hash", sa.EndSession(ctx, a.ID, h[:3], fixedNow), store.ErrInvalid)
		wantErr(t, "end bad tenant", sa.EndSession(ctx, badTenant, h, fixedNow), store.ErrInvalid)
		wantErr(t, "end from other tenant", sa.EndSession(ctx, b.ID, h, fixedNow), store.ErrNotFound)
		wantErr(t, "end expired", sa.EndSession(ctx, a.ID, h, exp), store.ErrNotFound)
		if err := sa.EndSession(ctx, a.ID, h, fixedNow); err != nil {
			t.Fatalf("EndSession: %v", err)
		}
		wantErr(t, "end twice", sa.EndSession(ctx, a.ID, h, fixedNow), store.ErrNotFound)
		_, err = sa.GetSession(ctx, a.ID, h, fixedNow)
		wantErr(t, "ended", err, store.ErrNotFound)
	})
}

func TestSenderAccessDeleteByEmail(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		sa := db.SenderAccess()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")
		exp := fixedNow.Add(time.Hour)
		const alice, bob = "alice@entity-a.example.com", "bob@entity-a.example.com"
		hashes := map[string][]byte{}
		seed := func(tid tenant.ID, email, key string) {
			t.Helper()
			hashes[key+"/link"], hashes[key+"/session"] = randomHash(t), randomHash(t)
			if _, err := sa.CreateLink(ctx, tid, hashes[key+"/link"], email, fixedNow, exp); err != nil {
				t.Fatal(err)
			}
			err := inTxCtx(ctx, t, db, tid, func(tx *store.ScopedTx) error {
				_, err := sa.CreateSessionTx(ctx, tx, hashes[key+"/session"], email, fixedNow, exp)
				return err
			})
			if err != nil {
				t.Fatal(err)
			}
		}
		seed(a.ID, alice, "a-alice")
		seed(a.ID, alice, "a-alice-2")
		seed(a.ID, bob, "a-bob")
		seed(b.ID, alice, "b-alice")

		err := inTxCtx(ctx, t, db, a.ID, func(tx *store.ScopedTx) error {
			_, err := sa.DeleteByEmailTx(ctx, tx, "not an address")
			wantErr(t, "bad address", err, store.ErrInvalid)
			n, err := sa.DeleteByEmailTx(ctx, tx, "Alice@Entity-A.example.com")
			if err != nil || n != 4 {
				t.Errorf("DeleteByEmailTx = %d, %v, want 4", n, err)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		for key, tid := range map[string]tenant.ID{"a-alice": a.ID, "a-alice-2": a.ID} {
			_, err := sa.GetSession(ctx, tid, hashes[key+"/session"], fixedNow)
			wantErr(t, key+" session", err, store.ErrNotFound)
		}
		// Bob in A and Alice in B keep their link and session.
		for key, tid := range map[string]tenant.ID{"a-bob": a.ID, "b-alice": b.ID} {
			if _, err := sa.GetSession(ctx, tid, hashes[key+"/session"], fixedNow); err != nil {
				t.Errorf("%s session: %v", key, err)
			}
			err := inTxCtx(ctx, t, db, tid, func(tx *store.ScopedTx) error {
				_, err := sa.ConsumeLinkTx(ctx, tx, hashes[key+"/link"], fixedNow)
				return err
			})
			if err != nil {
				t.Errorf("%s link: %v", key, err)
			}
		}
		err = inTxCtx(ctx, t, db, a.ID, func(tx *store.ScopedTx) error {
			_, err := sa.ConsumeLinkTx(ctx, tx, hashes["a-alice/link"], fixedNow)
			return err
		})
		wantErr(t, "erased link", err, store.ErrNotFound)
	})
}

func TestSenderAccessPurge(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		sa := db.SenderAccess()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")
		now := fixedNow
		ip := netip.MustParseAddr("192.0.2.7")
		mac := addressMAC(7)

		// Requests: one just past the window (purged), one at its start
		// (kept, still counted).
		for _, at := range []time.Time{now.Add(-store.AccessRateWindow - time.Millisecond), now.Add(-store.AccessRateWindow)} {
			for _, tid := range []tenant.ID{a.ID, b.ID} {
				if _, err := sa.RecordRequest(ctx, tid, mac, ip, at); err != nil {
					t.Fatal(err)
				}
			}
		}
		// Links: expired (purged), expired and consumed (purged), valid
		// and consumed (kept until its expiry), valid (kept).
		link := func(created, expires, consumed time.Time) []byte {
			t.Helper()
			h := randomHash(t)
			if _, err := sa.CreateLink(ctx, a.ID, h, "alice@entity-a.example.com", created, expires); err != nil {
				t.Fatal(err)
			}
			if !consumed.IsZero() {
				err := inTxCtx(ctx, t, db, a.ID, func(tx *store.ScopedTx) error {
					_, err := sa.ConsumeLinkTx(ctx, tx, h, consumed)
					return err
				})
				if err != nil {
					t.Fatal(err)
				}
			}
			return h
		}
		link(now.Add(-time.Hour), now, time.Time{})
		link(now.Add(-time.Hour), now.Add(-time.Minute), now.Add(-30*time.Minute))
		link(now.Add(-time.Minute), now.Add(time.Minute), now.Add(-time.Second))
		kept := link(now.Add(-time.Minute), now.Add(time.Minute), time.Time{})
		// Sessions: expired (purged), ended an hour ago (purged), ended
		// recently (kept), active (kept).
		session := func(created, expires, ended time.Time) []byte {
			t.Helper()
			h := randomHash(t)
			err := inTxCtx(ctx, t, db, a.ID, func(tx *store.ScopedTx) error {
				_, err := sa.CreateSessionTx(ctx, tx, h, "alice@entity-a.example.com", created, expires)
				return err
			})
			if err != nil {
				t.Fatal(err)
			}
			if !ended.IsZero() {
				if err := sa.EndSession(ctx, a.ID, h, ended); err != nil {
					t.Fatal(err)
				}
			}
			return h
		}
		session(now.Add(-2*time.Hour), now, time.Time{})
		session(now.Add(-2*time.Hour), now.Add(time.Hour), now.Add(-store.SenderSessionEndedRetention))
		session(now.Add(-2*time.Hour), now.Add(time.Hour), now.Add(-time.Minute))
		active := session(now.Add(-time.Minute), now.Add(time.Hour), time.Time{})

		n, err := sa.Purge(ctx, a.ID, now)
		if err != nil || n != 5 {
			t.Fatalf("Purge(A) = %d, %v, want 5 (1 request, 2 links, 2 sessions)", n, err)
		}
		if n, err := sa.Purge(ctx, a.ID, now); err != nil || n != 0 {
			t.Errorf("Purge(A) again = %d, %v", n, err)
		}
		// The request at the start of the window is still counted, in A
		// and in B (whose purge has not run).
		if c, err := sa.RecordRequest(ctx, a.ID, mac, ip, now); err != nil || c.ByAddress != 1 {
			t.Errorf("A's counts after purge = %+v, %v", c, err)
		}
		if n, err := sa.Purge(ctx, b.ID, now); err != nil || n != 1 {
			t.Errorf("Purge(B) = %d, %v, want 1", n, err)
		}
		if _, err := sa.GetSession(ctx, a.ID, active, now); err != nil {
			t.Errorf("active session purged: %v", err)
		}
		err = inTxCtx(ctx, t, db, a.ID, func(tx *store.ScopedTx) error {
			_, err := sa.ConsumeLinkTx(ctx, tx, kept, now)
			return err
		})
		if err != nil {
			t.Errorf("valid link purged: %v", err)
		}
		// A minute later, the two consumed links have expired, and the
		// request at the start of the window has left it.
		if n, err := sa.Purge(ctx, a.ID, now.Add(time.Minute)); err != nil || n != 3 {
			t.Errorf("Purge(A) later = %d, %v, want 3 (2 links, 1 request)", n, err)
		}

		_, err = sa.Purge(ctx, badTenant, now)
		wantErr(t, "bad tenant", err, store.ErrInvalid)
	})
}
