package store_test

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

func TestAdminLoginKeys(t *testing.T) {
	t.Parallel()
	ip := netip.MustParseAddr("192.0.2.10")
	if k := store.AdminLoginIPKey(ip); k.Scope != store.AdminLoginScopeIP || k.Key != "192.0.2.10" {
		t.Errorf("AdminLoginIPKey = %+v", k)
	}
	if k := store.AdminLoginIPKey(netip.MustParseAddr("2001:db8:1:2::5")); k.Key != "2001:db8:1:2::/64" {
		t.Errorf("AdminLoginIPKey(v6) = %+v", k)
	}
	k1, k2 := store.AdminLoginUserIPKey(" Admin ", ip), store.AdminLoginUserIPKey("admin", ip)
	if k1 != k2 || k1.Scope != store.AdminLoginScopeUserIP || len(k1.Key) != 64 {
		t.Errorf("AdminLoginUserIPKey = %+v, %+v", k1, k2)
	}
	if k3 := store.AdminLoginUserIPKey("admin", netip.MustParseAddr("192.0.2.11")); k3 == k1 {
		t.Error("two IPs share a username counter")
	}
	if k := store.AdminLoginUserIPKey("admin", netip.Addr{}); k.Key != "" {
		t.Errorf("AdminLoginUserIPKey(zero ip) = %+v", k)
	}
	adminID := id.New(id.Admin)
	if k := store.AdminLoginTOTPKey(adminID); k.Scope != store.AdminLoginScopeTOTP || k.Key != adminID {
		t.Errorf("AdminLoginTOTPKey = %+v", k)
	}
}

func TestAdminLoginFailures(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		repo := db.AdminLoginFailures()
		ip := netip.MustParseAddr("192.0.2.10")
		user, ipKey := store.AdminLoginUserIPKey("admin", ip), store.AdminLoginIPKey(ip)
		const window, lock = 15 * time.Minute, 15 * time.Minute
		rules := []store.AdminLoginRule{
			{Key: user, MaxFailures: 5, Window: window, LockDuration: lock},
			{Key: ipKey, MaxFailures: 20, Window: window, LockDuration: lock},
		}
		keys := []store.AdminLoginKey{user, ipKey}

		if until, err := repo.Check(ctx, keys, msNow); err != nil || !until.IsZero() {
			t.Fatalf("Check(empty) = %v, %v", until, err)
		}
		for i := 1; i <= 4; i++ {
			out, err := repo.RecordFailure(ctx, rules, msNow.Add(time.Duration(i)*time.Second))
			if err != nil || out.Remaining != 5-i || !out.LockedUntil.IsZero() {
				t.Fatalf("RecordFailure %d = %+v, %v", i, out, err)
			}
		}
		fifth := msNow.Add(5 * time.Second)
		out, err := repo.RecordFailure(ctx, rules, fifth)
		if err != nil || out.Remaining != 0 || !out.LockedUntil.Equal(fifth.Add(lock)) {
			t.Fatalf("RecordFailure 5 = %+v, %v", out, err)
		}
		if until, err := repo.Check(ctx, keys, fifth.Add(time.Minute)); err != nil || !until.Equal(fifth.Add(lock)) {
			t.Errorf("Check(locked) = %v, %v", until, err)
		}
		if until, _ := repo.Check(ctx, []store.AdminLoginKey{ipKey}, fifth); !until.IsZero() {
			t.Errorf("the IP counter is locked after 5 failures: %v", until)
		}
		// While locked, a failure changes nothing.
		out, err = repo.RecordFailure(ctx, rules, fifth.Add(time.Minute))
		if err != nil || out.Remaining != 0 || !out.LockedUntil.Equal(fifth.Add(lock)) {
			t.Errorf("RecordFailure(locked) = %+v, %v", out, err)
		}
		// Another username from the same IP is not locked.
		other := store.AdminLoginUserIPKey("other", ip)
		if until, _ := repo.Check(ctx, []store.AdminLoginKey{other, ipKey}, fifth); !until.IsZero() {
			t.Errorf("another username is locked: %v", until)
		}
		// The second factor counter of an administrator has its own scope.
		totp := store.AdminLoginTOTPKey(id.New(id.Admin))
		out, err = repo.RecordFailure(ctx, []store.AdminLoginRule{{Key: totp, MaxFailures: 1, Window: window, LockDuration: lock}}, fifth)
		if err != nil || !out.LockedUntil.Equal(fifth.Add(lock)) {
			t.Errorf("RecordFailure(totp) = %+v, %v", out, err)
		}
		if until, err := repo.Check(ctx, []store.AdminLoginKey{totp}, fifth); err != nil || !until.Equal(fifth.Add(lock)) {
			t.Errorf("Check(totp) = %v, %v", until, err)
		}
		if err := repo.Reset(ctx, []store.AdminLoginKey{totp}); err != nil {
			t.Fatal(err)
		}
		// After the lock, the old failures are out of the window.
		after := fifth.Add(lock)
		if until, _ := repo.Check(ctx, keys, after); !until.IsZero() {
			t.Errorf("Check(lock over) = %v", until)
		}
		out, err = repo.RecordFailure(ctx, rules, after)
		if err != nil || out.Remaining != 4 || !out.LockedUntil.IsZero() {
			t.Errorf("RecordFailure(after the lock) = %+v, %v", out, err)
		}

		// Refund: the failure counted before a right password is withdrawn.
		at := after.Add(time.Second)
		if _, err := repo.RecordFailure(ctx, rules, at); err != nil {
			t.Fatal(err)
		}
		if err := repo.Refund(ctx, rules, at); err != nil {
			t.Fatalf("Refund = %v", err)
		}
		if err := repo.Refund(ctx, rules, at.Add(time.Hour)); err != nil {
			t.Errorf("Refund(nothing at that time) = %v", err)
		}
		out, _ = repo.RecordFailure(ctx, rules[:1], at.Add(time.Second))
		if out.Remaining != 3 {
			t.Errorf("remaining after a refund = %d, want 3", out.Remaining)
		}
		// A refund of the failure that set the lock clears it.
		quick := []store.AdminLoginRule{{Key: other, MaxFailures: 1, Window: window, LockDuration: lock}}
		if out, _ := repo.RecordFailure(ctx, quick, at); out.LockedUntil.IsZero() {
			t.Fatal("a 1-failure rule did not lock")
		}
		if err := repo.Refund(ctx, quick, at); err != nil {
			t.Fatal(err)
		}
		if until, _ := repo.Check(ctx, []store.AdminLoginKey{other}, at); !until.IsZero() {
			t.Errorf("lock kept after the refund of its failure: %v", until)
		}

		// Reset deletes the counters.
		if err := repo.Reset(ctx, keys); err != nil {
			t.Fatalf("Reset = %v", err)
		}
		out, _ = repo.RecordFailure(ctx, rules, at.Add(2*time.Second))
		if out.Remaining != 4 {
			t.Errorf("remaining after Reset = %d", out.Remaining)
		}

		// Purge: the counters are stale one window after the last failure; the
		// counter emptied by its refund is stale at once.
		if n, err := repo.Purge(ctx, at.Add(2*time.Second+window-time.Millisecond), window); err != nil || n != 1 {
			t.Errorf("Purge(too early) = %d, %v; want 1", n, err)
		}
		if n, err := repo.Purge(ctx, at.Add(2*time.Second+window), window); err != nil || n != 2 {
			t.Errorf("Purge = %d, %v; want 2", n, err)
		}

		// Validation.
		badKeys := map[string][]store.AdminLoginKey{
			"none":      nil,
			"too many":  make([]store.AdminLoginKey, store.MaxAdminLoginKeys+1),
			"duplicate": {user, user},
			"scope":     {{Scope: "bogus", Key: "x"}},
			"ip":        {{Scope: store.AdminLoginScopeIP, Key: "not-an-ip"}},
			"user":      {{Scope: store.AdminLoginScopeUserIP, Key: "ABCD"}},
			"totp":      {store.AdminLoginTOTPKey("root")},
			"zero ip":   {store.AdminLoginUserIPKey("admin", netip.Addr{})},
		}
		for name, ks := range badKeys {
			if _, err := repo.Check(ctx, ks, msNow); !errors.Is(err, store.ErrInvalid) {
				t.Errorf("Check(%s) err = %v", name, err)
			}
			if err := repo.Reset(ctx, ks); !errors.Is(err, store.ErrInvalid) {
				t.Errorf("Reset(%s) err = %v", name, err)
			}
		}
		badRules := map[string]store.AdminLoginRule{
			"max 0":   {Key: user, MaxFailures: 0, Window: window, LockDuration: lock},
			"max 21":  {Key: user, MaxFailures: store.MaxAdminLoginFailures + 1, Window: window, LockDuration: lock},
			"window":  {Key: user, MaxFailures: 5, LockDuration: lock},
			"lock":    {Key: user, MaxFailures: 5, Window: window},
			"bad key": {Key: store.AdminLoginKey{}, MaxFailures: 5, Window: window, LockDuration: lock},
		}
		for name, r := range badRules {
			if _, err := repo.RecordFailure(ctx, []store.AdminLoginRule{r}, msNow); !errors.Is(err, store.ErrInvalid) {
				t.Errorf("RecordFailure(%s) err = %v", name, err)
			}
			if err := repo.Refund(ctx, []store.AdminLoginRule{r}, msNow); !errors.Is(err, store.ErrInvalid) {
				t.Errorf("Refund(%s) err = %v", name, err)
			}
		}
		if _, err := repo.Purge(ctx, msNow, 0); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("Purge(0) err = %v", err)
		}

		// The limit of 20 works for the IP scope.
		ip2 := store.AdminLoginIPKey(netip.MustParseAddr("198.51.100.1"))
		big := []store.AdminLoginRule{{Key: ip2, MaxFailures: 20, Window: window, LockDuration: lock}}
		for i := range 20 {
			out, err := repo.RecordFailure(ctx, big, msNow.Add(time.Duration(i)*time.Second))
			if err != nil || (i < 19) != out.LockedUntil.IsZero() || out.Remaining != 19-i {
				t.Fatalf("RecordFailure(ip %d) = %+v, %v", i, out, err)
			}
		}
	})
}
