package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// dropSession creates, in tenant tid, a drop link session of link opened
// at opened and ending 4 hours later, and returns it.
func dropSession(ctx context.Context, t *testing.T, db *store.DB, tid tenant.ID, link string, opened time.Time) store.DepositSession {
	t.Helper()
	s := newSession(t, "supplier@partner.example.org")
	s.Kind, s.DropLinkID, s.CreatedAt, s.ExpiresAt = store.DepositorDropLink, link, opened, opened.Add(4*time.Hour)
	if err := db.DepositSessions().Create(ctx, tid, s); err != nil {
		t.Fatalf("create drop link session: %v", err)
	}
	return s
}

// useSession marks the drop link session s of link used at at in tenant tid.
func useSession(ctx context.Context, t *testing.T, db *store.DB, tid tenant.ID, s store.DepositSession, link string, at time.Time) error {
	t.Helper()
	return inTxCtx(ctx, t, db, tid, func(tx *store.ScopedTx) error {
		return db.DropLinks().UseSessionTx(ctx, tx, s.ID, link, at)
	})
}

func TestDropLinkUseSession(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")
		l := mustDropLink(t, db, a.ID)
		other := mustDropLink(t, db, a.ID)
		inB := mustDropLink(t, db, b.ID)
		s := dropSession(ctx, t, db, a.ID, l.ID, fixedNow)
		sB := dropSession(ctx, t, db, b.ID, inB.ID, fixedNow)

		// Another link, or a session of another tenant: not found.
		wantErr(t, "use(other link)", useSession(ctx, t, db, a.ID, s, other.ID, fixedNow), store.ErrNotFound)
		wantErr(t, "use(session of B from A)", useSession(ctx, t, db, a.ID, sB, inB.ID, fixedNow), store.ErrNotFound)
		// Once only.
		if err := useSession(ctx, t, db, a.ID, s, l.ID, fixedNow); err != nil {
			t.Fatalf("use: %v", err)
		}
		wantErr(t, "use(again)", useSession(ctx, t, db, a.ID, s, l.ID, fixedNow), store.ErrNotFound)
		// Malformed identifiers.
		wantErr(t, "use(malformed session)", useSession(ctx, t, db, a.ID, store.DepositSession{ID: "ds_x"}, l.ID, fixedNow), store.ErrInvalid)
		wantErr(t, "use(malformed link)", useSession(ctx, t, db, a.ID, s, "drl_x", fixedNow), store.ErrInvalid)
	})
}

func TestDropLinkUsageSince(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")
		l := mustDropLink(t, db, a.ID)
		other := mustDropLink(t, db, a.ID)
		inB := mustDropLink(t, db, b.ID)
		first := fixedNow.Add(-50 * time.Minute).Truncate(time.Millisecond)
		opened := fixedNow.Add(-3 * time.Hour)
		for _, at := range []time.Time{fixedNow.Add(-2 * time.Hour), first, fixedNow.Add(-10 * time.Minute)} {
			if err := useSession(ctx, t, db, a.ID, dropSession(ctx, t, db, a.ID, l.ID, opened), l.ID, at); err != nil {
				t.Fatal(err)
			}
		}
		dropSession(ctx, t, db, a.ID, l.ID, opened) // not used: not counted
		// Expires one minute after now.
		if err := useSession(ctx, t, db, a.ID, dropSession(ctx, t, db, a.ID, other.ID, fixedNow.Add(-4*time.Hour+time.Minute)), other.ID, fixedNow); err != nil {
			t.Fatal(err)
		}
		if err := useSession(ctx, t, db, b.ID, dropSession(ctx, t, db, b.ID, inB.ID, opened), inB.ID, fixedNow); err != nil {
			t.Fatal(err)
		}
		since := fixedNow.Add(-time.Hour)

		// Every use in the window counts; older ones and other links do not.
		u, err := db.DropLinks().UsageSince(ctx, a.ID, l.ID, since)
		if err != nil || u.Count != 2 || !u.Oldest.Equal(first) {
			t.Errorf("UsageSince = %+v, %v; want 2 since %v", u, err, first)
		}
		var utx store.DropLinkUsage
		err = inTxCtx(ctx, t, db, a.ID, func(tx *store.ScopedTx) error {
			var err error
			utx, err = db.DropLinks().UsageSinceTx(ctx, tx, l.ID, since)
			return err
		})
		if err != nil || utx != u {
			t.Errorf("UsageSinceTx = %+v, %v; want %+v", utx, err, u)
		}
		// None: zero oldest.
		if u, err := db.DropLinks().UsageSince(ctx, a.ID, l.ID, fixedNow.Add(time.Minute)); err != nil || u != (store.DropLinkUsage{}) {
			t.Errorf("UsageSince(none) = %+v, %v", u, err)
		}
		// The link of B is not seen from A.
		if u, err := db.DropLinks().UsageSince(ctx, a.ID, inB.ID, since); err != nil || u.Count != 0 {
			t.Errorf("UsageSince(link of B from A) = %+v, %v", u, err)
		}
		_, err = db.DropLinks().UsageSince(ctx, a.ID, "drl_x", since)
		wantErr(t, "UsageSince(malformed link)", err, store.ErrInvalid)
		_, err = db.DropLinks().UsageSince(ctx, "bogus", l.ID, since)
		wantErr(t, "UsageSince(bad tenant)", err, store.ErrInvalid)
		err = inTxCtx(ctx, t, db, a.ID, func(tx *store.ScopedTx) error {
			_, err := db.DropLinks().UsageSinceTx(ctx, tx, "drl_x", since)
			return err
		})
		wantErr(t, "UsageSinceTx(malformed link)", err, store.ErrInvalid)

		// The cleanup keeps an expired session used less than an hour ago,
		// so that it still counts, and deletes it afterwards.
		if n, err := db.DepositSessions().Purge(ctx, a.ID, fixedNow.Add(30*time.Minute)); err != nil || n != 0 {
			t.Errorf("purge 30 minutes after the use = %d, %v; want 0", n, err)
		}
		if u, err := db.DropLinks().UsageSince(ctx, a.ID, other.ID, since); err != nil || u.Count != 1 {
			t.Errorf("after the first purge: %+v, %v; want 1", u, err)
		}
		if _, err := db.DepositSessions().Purge(ctx, a.ID, fixedNow.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		if u, err := db.DropLinks().UsageSince(ctx, a.ID, other.ID, since); err != nil || u.Count != 0 {
			t.Errorf("after the purge one hour after the use: %+v, %v; want 0", u, err)
		}
	})
}

func TestDropLinkUsageRetryAfter(t *testing.T) {
	t.Parallel()
	now := fixedNow
	for name, tc := range map[string]struct {
		u    store.DropLinkUsage
		want time.Duration
	}{
		"none":     {store.DropLinkUsage{}, time.Hour},
		"oldest":   {store.DropLinkUsage{Count: 3, Oldest: now.Add(-40 * time.Minute)}, 20 * time.Minute},
		"elapsed":  {store.DropLinkUsage{Count: 3, Oldest: now.Add(-2 * time.Hour)}, time.Second},
		"just now": {store.DropLinkUsage{Count: 1, Oldest: now}, time.Hour},
	} {
		if got := tc.u.RetryAfter(now); got != tc.want {
			t.Errorf("%s: RetryAfter = %v, want %v", name, got, tc.want)
		}
	}
	if (store.DropLinkUsage{Count: 2}).Full(3) || !(store.DropLinkUsage{Count: 3}).Full(3) {
		t.Error("Full is wrong around the cap")
	}
}
