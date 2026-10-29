package datasubject

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// meHashes are the token hashes of the "my transfers" link and session of
// one address in one tenant.
type meHashes struct {
	link, session []byte
}

// addressMAC returns the access-rate MAC of the normalized address addr.
func (ev *env) addressMAC(addr string) []byte {
	ev.t.Helper()
	mac, err := ev.keys.MAC(crypto.MACPurposeAccessRate, []byte(addr))
	if err != nil {
		ev.t.Fatal(err)
	}
	return mac
}

// meRows stores, in tn for addr, an access link, a session and one access
// link request, all valid for an hour from now.
func (ev *env) meRows(tn *tenant.Tenant, addr string) meHashes {
	ev.t.Helper()
	ctx := context.Background()
	now := ev.clock.Now()
	sa := ev.db.SenderAccess()
	link, session := sha256.Sum256([]byte(rand.Text())), sha256.Sum256([]byte(rand.Text()))
	if _, err := sa.RecordRequest(ctx, tn.ID, ev.addressMAC(addr), clientIP, now); err != nil {
		ev.t.Fatal(err)
	}
	if _, err := sa.CreateLink(ctx, tn.ID, link[:], addr, now, now.Add(time.Hour)); err != nil {
		ev.t.Fatal(err)
	}
	sc, err := ev.db.Scoped(tn.ID)
	if err != nil {
		ev.t.Fatal(err)
	}
	err = sc.Tx(ctx, func(tx *store.ScopedTx) error {
		_, err := sa.CreateSessionTx(ctx, tx, session[:], addr, now, now.Add(time.Hour))
		return err
	})
	if err != nil {
		ev.t.Fatal(err)
	}
	return meHashes{link: link[:], session: session[:]}
}

// requests returns how many access link requests of addr tn counts now.
func (ev *env) requests(tn *tenant.Tenant, addr string) int {
	ev.t.Helper()
	sc, err := ev.db.Scoped(tn.ID)
	if err != nil {
		ev.t.Fatal(err)
	}
	var n int
	_ = sc.Tx(context.Background(), func(tx *store.ScopedTx) error {
		c, err := ev.db.SenderAccess().RecordRequestTx(context.Background(), tx, ev.addressMAC(addr), clientIP, ev.clock.Now())
		if err != nil {
			ev.t.Fatal(err)
		}
		n = c.ByAddress
		return errBoom // roll back: counting does not record
	})
	return n
}

// hasSession reports whether the session of h is active in tn.
func (ev *env) hasSession(tn *tenant.Tenant, h meHashes) bool {
	ev.t.Helper()
	_, err := ev.db.SenderAccess().GetSession(context.Background(), tn.ID, h.session, ev.clock.Now())
	return err == nil
}

// TestEraseSenderAccess checks the erasure of the "my transfers" rows of
// the address (data model 5.2): its access links and sessions, and the
// access link requests counted for its MAC, in the erased tenant only.
func TestEraseSenderAccess(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		carolA, daveA, carolB := ev.meRows(ev.a, carol), ev.meRows(ev.a, dave), ev.meRows(ev.b, carol)
		ev.meRows(ev.a, carol) // a second link and session

		rep := ev.erase(ev.a, subjectInput)
		if rep != (EraseReport{AccessLinks: 4}) {
			t.Fatalf("Erase = %+v, want 4 access links and sessions", rep)
		}
		if ev.hasSession(ev.a, carolA) || ev.requests(ev.a, carol) != 0 {
			t.Error("carol's access rows remain in A")
		}
		if !ev.hasSession(ev.a, daveA) || ev.requests(ev.a, dave) != 1 {
			t.Error("dave's access rows in A were erased")
		}
		if !ev.hasSession(ev.b, carolB) || ev.requests(ev.b, carol) != 1 {
			t.Error("carol's access rows in B were erased")
		}
		_, err := ev.db.SenderAccess().CreateLink(context.Background(), ev.a.ID, carolA.link, carol,
			ev.clock.Now(), ev.clock.Now().Add(time.Minute))
		if err != nil {
			t.Errorf("carol's link hash still used in A: %v", err)
		}
	})
}

// failingKeys fails every MAC.
type failingKeys struct{}

func (failingKeys) MAC(crypto.MACPurpose, ...[]byte) ([]byte, error) { return nil, errBoom }

// TestEraseSenderAccessKeys checks the erasure without keys (the requests
// stay until the purge) and with failing keys (the erasure stops).
func TestEraseSenderAccessKeys(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		h := ev.meRows(ev.a, carol)

		s, err := New(ev.db, Options{Eraser: ev.eraser, Keys: failingKeys{}, Now: ev.clock.Now})
		if err != nil {
			t.Fatal(err)
		}
		_, err = s.Erase(context.Background(), ev.super, clientIP, ev.a.ID, carol)
		wantErr(t, "failing keys", err, errBoom)
		if !ev.hasSession(ev.a, h) {
			t.Error("the session was erased although the erasure stopped before")
		}

		s, err = New(ev.db, Options{Eraser: ev.eraser, Now: ev.clock.Now})
		if err != nil {
			t.Fatal(err)
		}
		rep, err := s.Erase(context.Background(), ev.super, clientIP, ev.a.ID, carol)
		if err != nil || rep.AccessLinks != 2 {
			t.Fatalf("Erase without keys = %+v, %v", rep, err)
		}
		if ev.hasSession(ev.a, h) || ev.requests(ev.a, carol) != 1 {
			t.Error("without keys, the links and sessions go and the requests stay")
		}
	})
}

// TestEraseVerifiedBeforeSenderAccess checks the order of step 1: the
// verified address is deleted before the "my transfers" access rows, so
// that an erasure stopped between the two leaves no address an access
// link could open a session for.
func TestEraseVerifiedBeforeSenderAccess(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ev.depositRows(ev.a, carol, "")
		h := ev.meRows(ev.a, carol)
		ev.faults("deleteSenderAccess")
		_, err := ev.svc.Erase(context.Background(), ev.super, clientIP, ev.a.ID, carol)
		wantErr(t, "Erase", err, errBoom)
		_, err = ev.db.VerifiedAddresses().Get(context.Background(), ev.a.ID, carol)
		wantErr(t, "verified address", err, store.ErrNotFound)
		if !ev.hasSession(ev.a, h) {
			t.Error("the access rows were erased although their step failed")
		}
	})
}
