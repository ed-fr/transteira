package download

import (
	"context"
	"encoding/binary"
	"errors"
	"math"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/masterkey"
	"github.com/ed-fr/transteira/internal/masterkey/masterkeytest"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// wantWrong fails unless err is a *WrongPasswordError with remaining
// attempts.
func wantWrong(t *testing.T, err error, remaining int) {
	t.Helper()
	var we *WrongPasswordError
	if !errors.As(err, &we) || !errors.Is(err, ErrWrongPassword) || we.Remaining != remaining {
		t.Fatalf("error %v, want a wrong password with %d remaining", err, remaining)
	}
}

// wantLocked fails unless err is a *LockedError of retry.
func wantLocked(t *testing.T, err error, retry time.Duration) {
	t.Helper()
	var le *LockedError
	if !errors.As(err, &le) || !errors.Is(err, ErrLocked) || le.RetryAfter != retry {
		t.Fatalf("error %v, want a lock retrying after %s", err, retry)
	}
}

func TestUnlockInput(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		ctx := context.Background()
		p := ev.publish(ev.a, spec{contents: [][]byte{random(10)}, password: true})
		for _, pw := range []string{strings.Repeat("é", MaxPasswordRunes+1), "\xff\xfe", strings.Repeat("a", MaxPasswordBytes+1)} {
			_, err := ev.svc.Unlock(ctx, ev.a, p.token, ipOne, pw, "")
			wantErr(t, err, ErrInvalid)
			if errors.Is(err, ErrPasswordRequired) {
				t.Fatal("a malformed password reported as missing")
			}
		}
		_, err := ev.svc.Unlock(ctx, ev.a, p.token, ipOne, "", "")
		wantErr(t, err, ErrPasswordRequired)
		wantErr(t, err, ErrInvalid)
		_, err = ev.svc.Unlock(ctx, ev.a, "dl_bad", ipOne, password, "")
		wantErr(t, err, ErrNotFound)
		_, err = ev.svc.Unlock(ctx, ev.a, p.token, netip.Addr{}, password, "")
		wantErr(t, err, ErrNoClientIP)

		// Without password: nothing to do, no hashing.
		q := ev.publish(ev.a, spec{contents: [][]byte{random(10)}})
		c, err := ev.svc.Unlock(ctx, ev.a, q.token, netip.Addr{}, "anything", "dg_x")
		if err != nil || c != "" {
			t.Fatalf("Unlock without password = %q, %v", c, err)
		}
		if n := ev.f.called("verify"); n != 0 {
			t.Fatalf("%d password hashings, want 0", n)
		}
	})
}

func TestUnlockPerTransfer(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		ctx := context.Background()
		p := ev.publish(ev.a, spec{contents: [][]byte{random(10)}, password: true})
		_, err := ev.svc.Unlock(ctx, ev.a, p.token, ipOne, "wrong-1", "")
		wantWrong(t, err, 2)
		_, err = ev.svc.Unlock(ctx, ev.a, p.token, ipTwo, "wrong-2", "")
		wantWrong(t, err, 1)
		ev.clock.advance(time.Minute)
		_, err = ev.svc.Unlock(ctx, ev.a, p.token, ipThree, "wrong-3", "")
		wantLocked(t, err, store.PasswordLockDuration)
		// Locked for everyone, even with the right password, without hashing.
		hashed := ev.f.called("verify")
		ev.clock.advance(10*time.Minute + 500*time.Millisecond)
		_, err = ev.svc.Unlock(ctx, ev.a, p.token, netip.MustParseAddr("192.0.2.200"), password, "")
		wantLocked(t, err, 5*time.Minute)
		if n := ev.f.called("verify"); n != hashed {
			t.Fatalf("a locked attempt hashed the password")
		}
		if n := ev.seclog.count(securitylog.TransferPasswordInvalid); n != 3 {
			t.Fatalf("%d transfer_password_invalid events, want 3", n)
		}
		if n := ev.seclog.count(securitylog.RateLimited); n != 1 {
			t.Fatalf("%d rate_limited events, want 1", n)
		}
		for _, ev := range ev.seclog.all() {
			if ev.Tenant != hostA || !ev.IP.IsValid() || ev.Fields[0].Key != "transfer" || ev.Fields[0].Value != p.id[:transferIDLogLen] {
				t.Fatalf("event %+v", ev)
			}
		}
		// The lock expires.
		ev.clock.advance(5 * time.Minute)
		cookie := ev.unlock(p, "")
		if !strings.HasPrefix(cookie, GrantCookiePrefix) {
			t.Fatalf("cookie %q", cookie)
		}
		if _, err := ev.svc.OpenFile(ctx, ev.a, p.token, ipOne, cookie, p.files[0].ID); err != nil {
			t.Fatal(err)
		}
	})
}

func TestUnlockPerIP(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		ctx := context.Background()
		var ps []published
		for range 4 {
			ps = append(ps, ev.publish(ev.a, spec{contents: [][]byte{random(10)}, password: true}))
		}
		_, err := ev.svc.Unlock(ctx, ev.a, ps[0].token, ipOne, "wrong", "")
		wantWrong(t, err, 2)
		_, err = ev.svc.Unlock(ctx, ev.a, ps[1].token, ipOne, "wrong", "")
		wantWrong(t, err, 1)
		_, err = ev.svc.Unlock(ctx, ev.a, ps[2].token, ipOne, "wrong", "")
		wantLocked(t, err, store.PasswordLockDuration)
		// The IP is locked on every transfer of the tenant...
		_, err = ev.svc.Unlock(ctx, ev.a, ps[3].token, ipOne, password, "")
		wantLocked(t, err, store.PasswordLockDuration)
		// ...but another IP may unlock them.
		if _, err := ev.svc.Unlock(ctx, ev.a, ps[3].token, ipTwo, password, ""); err != nil {
			t.Fatal(err)
		}
		// The IP is not locked in another tenant.
		q := ev.publish(ev.b, spec{contents: [][]byte{random(10)}, password: true})
		if _, err := ev.svc.Unlock(ctx, ev.b, q.token, ipOne, password, ""); err != nil {
			t.Fatal(err)
		}
	})
}

func TestUnlockResetAndFailures(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		ctx := context.Background()
		p := ev.publish(ev.a, spec{contents: [][]byte{random(10)}, password: true})
		_, err := ev.svc.Unlock(ctx, ev.a, p.token, ipOne, "wrong", "")
		wantWrong(t, err, 2)
		_, err = ev.svc.Unlock(ctx, ev.a, p.token, ipOne, "wrong", "")
		wantWrong(t, err, 1)
		ev.unlock(p, "")
		// The right password cleared the transfer counter: another client
		// starts afresh on the transfer...
		_, err = ev.svc.Unlock(ctx, ev.a, p.token, ipTwo, "wrong", "")
		wantWrong(t, err, 2)
		// ...but the client keeps its two earlier failures (only the right
		// attempt was refunded): its third one locks it.
		_, err = ev.svc.Unlock(ctx, ev.a, p.token, ipOne, "wrong", "")
		wantLocked(t, err, store.PasswordLockDuration)
		ev.clock.advance(store.PasswordLockDuration)
		ev.unlock(p, "")

		// A failing security log does not change the answer.
		ev.seclog.err = errFault
		_, err = ev.svc.Unlock(ctx, ev.a, p.token, ipThree, "wrong", "")
		wantWrong(t, err, 2)
		if ev.logs.count("security log write failed") != 1 {
			t.Fatal("security log failure not logged")
		}
		ev.seclog.err = nil
		ev.unlock(p, "")

		for i, fault := range []string{"reserve", "verify", "unlocked", "mac"} {
			ev.f.set(fault, 1, nil)
			ip := netip.AddrFrom4([4]byte{192, 0, 2, byte(100 + i)})
			_, err := ev.svc.Unlock(ctx, ev.a, p.token, ip, password, "")
			wantInternal(t, err)
		}
		if _, err := ev.svc.Unlock(ctx, ev.a, p.token, ipThree, password, ""); err != nil {
			t.Fatal(err)
		}
	})
}

func TestUnlockUnverifiedRefund(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		p := ev.publish(ev.a, spec{contents: [][]byte{random(10)}, password: true})
		// Attempts whose password was not verified, the request being
		// canceled meanwhile, cost nothing on either counter.
		for range store.MaxPasswordFailures {
			ctx, cancel := context.WithCancel(context.Background())
			ev.f.hook["verify"] = cancel
			ev.f.set("verify", 1, context.Canceled)
			_, err := ev.svc.Unlock(ctx, ev.a, p.token, ipOne, "wrong", "")
			wantErr(t, err, context.Canceled)
		}
		_, err := ev.svc.Unlock(context.Background(), ev.a, p.token, ipOne, "wrong", "")
		wantWrong(t, err, 2)
		// A refund that fails is logged; the attempt stays counted.
		ev.f.set("verify", 1, nil)
		ev.f.set("refund", 1, nil)
		_, err = ev.svc.Unlock(context.Background(), ev.a, p.token, ipOne, "wrong", "")
		wantInternal(t, err)
		if ev.logs.count("unverified password attempt not refunded") != 1 {
			t.Fatal("refund failure not logged")
		}
		_, err = ev.svc.Unlock(context.Background(), ev.a, p.token, ipOne, "wrong", "")
		wantLocked(t, err, store.PasswordLockDuration)
	})
}

func TestStoreRepoErrors(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		ctx := context.Background()
		r := storeRepo{db: ev.db}
		bad := tenant.ID("bad")
		keys := []store.FailureKey{store.TransferFailureKey(id.New(id.Transfer))}
		if _, _, err := r.reserve(ctx, bad, keys, time.Now()); err == nil {
			t.Error("reserve on an invalid tenant")
		}
		if _, _, err := r.reserve(ctx, ev.a.ID, nil, time.Now()); err == nil {
			t.Error("reserve without keys")
		}
		trf, ip := store.TransferFailureKey(id.New(id.Transfer)), store.IPFailureKey(ipOne)
		if err := r.unlocked(ctx, bad, trf, ip, time.Now()); err == nil {
			t.Error("unlocked on an invalid tenant")
		}
		if err := r.unlocked(ctx, ev.a.ID, store.FailureKey{}, ip, time.Now()); err == nil {
			t.Error("unlocked with an invalid transfer key")
		}
		if err := r.unlocked(ctx, ev.a.ID, trf, store.FailureKey{}, time.Now()); err == nil {
			t.Error("unlocked with an invalid IP key")
		}
		if err := r.refund(ctx, bad, []store.FailureKey{trf, ip}, time.Now()); err == nil {
			t.Error("refund on an invalid tenant")
		}
		if _, err := r.markFirst(ctx, bad, id.New(id.Transfer), time.Now(), time.Time{}); err == nil {
			t.Error("markFirst on an invalid tenant")
		}
	})
}

// grantService is a service with keys only, for the cookie tests.
func grantService(t *testing.T, label string) *Service {
	t.Helper()
	kr, err := masterkey.New(masterkeytest.Key(t, label), nil)
	if err != nil {
		t.Fatal(err)
	}
	return &Service{keys: kr}
}

func TestGrantCookie(t *testing.T) {
	s := grantService(t, "grant")
	now := time.Unix(1_800_000_000, 0)
	tidA, tidB := tenant.ID("tnt_01JA0000000000000000000000"), tenant.ID("tnt_01JB0000000000000000000000")
	trf := id.New(id.Transfer)
	other := id.New(id.Transfer)
	granted := func(cookie string, tid tenant.ID, trfID string, at time.Time) bool {
		t.Helper()
		ok, err := s.granted(cookie, tid, trfID, at)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	cookie, err := s.grant("", tidA, trf, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(cookie) != len(GrantCookiePrefix)+grantEntryLen {
		t.Fatalf("cookie length %d", len(cookie))
	}
	if !granted(cookie, tidA, trf, now) || !granted(cookie, tidA, trf, now.Add(GrantTTL-time.Second)) {
		t.Fatal("own grant refused")
	}
	if granted(cookie, tidA, trf, now.Add(GrantTTL)) {
		t.Error("expired grant accepted")
	}
	if granted(cookie, tidB, trf, now) {
		t.Error("grant accepted in another tenant")
	}
	if granted(cookie, tidA, other, now) {
		t.Error("grant accepted for another transfer")
	}
	if granted(cookie, tidA, trf, now.Add(-2*time.Hour)) {
		t.Error("grant issued too far ahead accepted")
	}
	tampered := []byte(cookie)
	i := len(tampered) - 10
	if tampered[i] == 'A' {
		tampered[i] = 'B'
	} else {
		tampered[i] = 'A'
	}
	if granted(string(tampered), tidA, trf, now) {
		t.Error("tampered grant accepted")
	}
	if granted(grantService(t, "other key").mustGrant(t, tidA, trf, now), tidA, trf, now) {
		t.Error("grant of another master key accepted")
	}

	// Unlocking again replaces the entry; other entries are kept, expired
	// ones dropped, and the cookie keeps the latest GrantMaxEntries.
	again, err := s.grant(cookie, tidA, trf, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(again, grantSep) != 0 {
		t.Fatalf("re-unlock duplicated the entry: %q", again)
	}
	c := cookie
	var trfs []string
	for i := range GrantMaxEntries + 2 {
		trfs = append(trfs, id.New(id.Transfer))
		if c, err = s.grant(c, tidA, trfs[i], now.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(parseGrants(c)); n != GrantMaxEntries || len(c) > MaxGrantCookieLen {
		t.Fatalf("%d entries, %d bytes", n, len(c))
	}
	at := now.Add(time.Minute)
	if granted(c, tidA, trf, at) || granted(c, tidA, trfs[0], at) || granted(c, tidA, trfs[1], at) {
		t.Error("the oldest grants were kept")
	}
	if !granted(c, tidA, trfs[2], at) || !granted(c, tidA, trfs[GrantMaxEntries+1], at) {
		t.Error("recent grants lost")
	}
	expired, err := s.grant(cookie, tidA, other, now.Add(2*GrantTTL))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(expired, grantSep) {
		t.Error("an expired entry was kept")
	}
}

// mustGrant returns a cookie holding one grant.
func (s *Service) mustGrant(t *testing.T, tid tenant.ID, trfID string, now time.Time) string {
	t.Helper()
	c, err := s.grant("", tid, trfID, now)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestParseGrants(t *testing.T) {
	entry := func(fill byte) string {
		b := make([]byte, grantRawLen)
		for i := range b {
			b[i] = fill
		}
		return grantEncoding.EncodeToString(b)
	}
	e1, e2 := entry(1), entry(2)
	cases := map[string]int{
		"":                                      0,
		e1:                                      0, // no prefix
		GrantCookiePrefix + e1:                  1,
		GrantCookiePrefix + e1 + "." + e1:       1, // duplicate
		GrantCookiePrefix + e1 + ".short." + e2: 2,
		GrantCookiePrefix + strings.Repeat("*", grantEntryLen):     0, // not base64
		GrantCookiePrefix + e1[:grantEntryLen-1] + "_":             0, // trailing bits set
		GrantCookiePrefix + strings.Repeat(e1+".", 30)[:1020]:      1,
		GrantCookiePrefix + strings.Repeat("x", MaxGrantCookieLen): 0, // too long
	}
	for raw, want := range cases {
		if got := len(parseGrants(raw)); got != want {
			t.Errorf("parseGrants(%.40q...) = %d entries, want %d", raw, got, want)
		}
	}
	var many []string
	for i := range GrantMaxEntries + 3 {
		many = append(many, entry(byte(10+i)))
	}
	if got := len(parseGrants(GrantCookiePrefix + strings.Join(many, "."))); got != GrantMaxEntries {
		t.Errorf("%d entries, want %d", got, GrantMaxEntries)
	}
}

func TestGrantLive(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	e := make([]byte, grantRawLen)
	binary.BigEndian.PutUint64(e, math.MaxUint64)
	if live(e, now) {
		t.Error("expiry beyond int64 accepted")
	}
	binary.BigEndian.PutUint64(e, uint64(now.Unix()+1))
	if !live(e, now) {
		t.Error("live entry refused")
	}
}

func TestGrantKeyFailures(t *testing.T) {
	kr, err := masterkey.New(masterkeytest.Key(t, "grant"), nil)
	if err != nil {
		t.Fatal(err)
	}
	f := newFaults()
	s := &Service{keys: faultKeys{inner: kr, f: f}}
	now := time.Unix(1_800_000_000, 0)
	tid := tenant.ID("tnt_01JA0000000000000000000000")
	cookie, err := s.grant("", tid, id.New(id.Transfer), now)
	if err != nil {
		t.Fatal(err)
	}
	f.set("verifyMAC", 1, nil)
	if _, err := s.grant(cookie, tid, id.New(id.Transfer), now); err == nil {
		t.Error("grant ignored a failing key")
	}
	f.set("verifyMAC", 1, nil)
	if _, err := s.granted(cookie, tid, id.New(id.Transfer), now); err == nil {
		t.Error("granted ignored a failing key")
	}
	f.set("mac", 1, nil)
	if _, err := s.grant(cookie, tid, id.New(id.Transfer), now); err == nil {
		t.Error("grant ignored a failing MAC")
	}
}

func TestRetryAfterAndErrors(t *testing.T) {
	now := time.Unix(1000, 0)
	for d, want := range map[time.Duration]time.Duration{
		-time.Second: time.Second, 0: time.Second, time.Millisecond: time.Second,
		time.Second: time.Second, 1500 * time.Millisecond: 2 * time.Second, 15 * time.Minute: 15 * time.Minute,
	} {
		if got := retryAfter(now.Add(d), now); got != want {
			t.Errorf("retryAfter(%s) = %s, want %s", d, got, want)
		}
	}
	if !strings.Contains((&WrongPasswordError{Remaining: 2}).Error(), "2 attempt") {
		t.Error("wrong password message")
	}
	if !strings.Contains((&LockedError{RetryAfter: time.Minute}).Error(), "1m0s") {
		t.Error("locked message")
	}
	if errors.Is(&LockedError{}, ErrWrongPassword) || errors.Is(&WrongPasswordError{}, ErrLocked) {
		t.Error("errors match the wrong sentinel")
	}
}
