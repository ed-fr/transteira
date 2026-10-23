package apitoken

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// Client IPs of the authentication tests.
var (
	inside  = netip.MustParseAddr("192.0.2.50")
	inside6 = netip.MustParseAddr("2001:db8::7")
	outside = netip.MustParseAddr("198.51.100.1")
)

// mustCreate creates a token of tenant A allowed from 192.0.2.0/24 and
// 2001:db8::/32 and returns its secret and record.
func mustCreate(t *testing.T, ev *env, in CreateInput) Created {
	t.Helper()
	if in.Name == "" {
		in.Name = "Script"
	}
	if in.AllowedCIDRs == nil {
		in.AllowedCIDRs = []string{"192.0.2.0/24", "2001:db8::/32"}
	}
	c, err := ev.svc.Create(context.Background(), ev.super, ev.a.ID, in, adminIP)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestAuthenticate(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		ev := newEnv(t, e)
		svc := ev.svc
		c := mustCreate(t, ev, CreateInput{ExpiresAt: testStart.Add(time.Hour)})
		header := "Bearer " + c.Secret

		for _, ip := range []netip.Addr{inside, inside6, netip.MustParseAddr("::ffff:192.0.2.51")} {
			p, err := svc.Authenticate(ctx, ev.a.ID, header, ip)
			if err != nil || p.TokenID != c.Token.ID || p.Name != "Script" || len(p.AllowedCIDRs) != 2 {
				t.Errorf("Authenticate from %s = %+v, %v", ip, p, err)
			}
		}
		if _, err := svc.Authenticate(ctx, ev.a.ID, "bearer "+c.Secret, inside); err != nil {
			t.Errorf("Authenticate(lowercase scheme) = %v", err)
		}

		// Outside the ranges: refused with the principal; the zero IP
		// never matches.
		for _, ip := range []netip.Addr{outside, {}} {
			p, err := svc.Authenticate(ctx, ev.a.ID, header, ip)
			if !errors.Is(err, ErrIPNotAllowed) || p.TokenID != c.Token.ID {
				t.Errorf("Authenticate from %v = %+v, %v; want ErrIPNotAllowed", ip, p, err)
			}
		}

		// Missing, malformed, unknown, of another tenant: the same answer
		// whatever the IP (the token is checked first).
		for _, ip := range []netip.Addr{inside, outside} {
			if _, err := svc.Authenticate(ctx, ev.a.ID, "", ip); !errors.Is(err, ErrMissing) {
				t.Errorf("Authenticate(no header) = %v", err)
			}
			if _, err := svc.Authenticate(ctx, ev.a.ID, "Basic abc", ip); !errors.Is(err, ErrMissing) {
				t.Errorf("Authenticate(basic) = %v", err)
			}
			for _, h := range []string{"Bearer", "Bearer " + c.Secret + "x", "Bearer " + testSecret('q'), "Bearer  " + c.Secret} {
				if p, err := svc.Authenticate(ctx, ev.a.ID, h, ip); !errors.Is(err, ErrInvalid) || p.TokenID != "" {
					t.Errorf("Authenticate(%.12q) = %+v, %v; want ErrInvalid", h, p, err)
				}
			}
			if _, err := svc.Authenticate(ctx, ev.b.ID, header, ip); !errors.Is(err, ErrInvalid) {
				t.Errorf("Authenticate on B = %v, want ErrInvalid", err)
			}
			if _, err := svc.Authenticate(ctx, "bogus", header, ip); !errors.Is(err, ErrInvalid) {
				t.Errorf("Authenticate on a malformed tenant = %v, want ErrInvalid", err)
			}
		}

		// Expired at its expiry instant.
		ev.clock.Advance(time.Hour)
		for _, ip := range []netip.Addr{inside, outside} {
			if _, err := svc.Authenticate(ctx, ev.a.ID, header, ip); !errors.Is(err, ErrInvalid) {
				t.Errorf("Authenticate(expired) from %s = %v, want ErrInvalid", ip, err)
			}
		}

		// Revoked: refused at once, whatever the IP.
		r := mustCreate(t, ev, CreateInput{})
		if _, err := svc.Authenticate(ctx, ev.a.ID, "Bearer "+r.Secret, inside); err != nil {
			t.Fatal(err)
		}
		if err := svc.Revoke(ctx, ev.super, ev.a.ID, r.Token.ID, adminIP); err != nil {
			t.Fatal(err)
		}
		for _, ip := range []netip.Addr{inside, outside} {
			if _, err := svc.Authenticate(ctx, ev.a.ID, "Bearer "+r.Secret, ip); !errors.Is(err, ErrInvalid) {
				t.Errorf("Authenticate(revoked) = %v, want ErrInvalid", err)
			}
		}
	})
}

func TestAuthenticateLastUse(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ev := newEnv(t, storetest.SQLite(t))
	svc := ev.svc
	c := mustCreate(t, ev, CreateInput{})
	header := "Bearer " + c.Secret
	lastUsed := func() time.Time {
		t.Helper()
		list, err := svc.List(ctx, ev.super, ev.a.ID)
		if err != nil {
			t.Fatal(err)
		}
		for _, k := range list {
			if k.ID == c.Token.ID {
				return k.LastUsedAt
			}
		}
		t.Fatal("token not listed")
		return time.Time{}
	}
	auth := func(ip netip.Addr) {
		t.Helper()
		_, _ = svc.Authenticate(ctx, ev.a.ID, header, ip)
	}

	auth(outside) // a refused request is no use
	if ev.repo.touchCount() != 0 || !lastUsed().IsZero() {
		t.Fatal("refused request recorded as a use")
	}
	auth(inside)
	if ev.repo.touchCount() != 1 || !lastUsed().Equal(testStart) {
		t.Fatalf("first use: %d writes, last used %v", ev.repo.touchCount(), lastUsed())
	}
	// Within the interval: no write, whatever the number of requests.
	for range 50 {
		ev.clock.Advance(time.Second)
		auth(inside)
	}
	if ev.repo.touchCount() != 1 {
		t.Fatalf("%d writes within a minute, want 1", ev.repo.touchCount())
	}
	ev.clock.Advance(10 * time.Second) // 60 s after the first write
	auth(inside)
	if ev.repo.touchCount() != 2 || !lastUsed().Equal(testStart.Add(time.Minute)) {
		t.Fatalf("after a minute: %d writes, last used %v", ev.repo.touchCount(), lastUsed())
	}
	// A clock moving backwards records again (the store keeps the latest).
	ev.clock.Advance(-time.Hour)
	auth(inside)
	if ev.repo.touchCount() != 3 || !lastUsed().Equal(testStart.Add(time.Minute)) {
		t.Fatalf("clock backwards: %d writes, last used %v", ev.repo.touchCount(), lastUsed())
	}

	// A failing write is logged, never returned.
	ev.clock.Advance(2 * time.Hour)
	ev.repo.touchErr = errBoom
	if _, err := svc.Authenticate(ctx, ev.a.ID, header, inside); err != nil {
		t.Fatalf("Authenticate with a failing last-use write = %v", err)
	}
	if logs := ev.logs.String(); !strings.Contains(logs, "api token last use not recorded") || !strings.Contains(logs, c.Token.ID) ||
		strings.Contains(logs, c.Secret) {
		t.Errorf("logs = %s", logs)
	}
	ev.repo.touchErr = nil

	// Revoking forgets the throttling of the token.
	svc.mu.Lock()
	_, tracked := svc.touched[c.Token.ID]
	svc.mu.Unlock()
	if !tracked {
		t.Fatal("token not tracked")
	}
	if err := svc.Revoke(ctx, ev.super, ev.a.ID, c.Token.ID, adminIP); err != nil {
		t.Fatal(err)
	}
	svc.mu.Lock()
	_, tracked = svc.touched[c.Token.ID]
	svc.mu.Unlock()
	if tracked {
		t.Error("revoked token still tracked")
	}
}

func TestDueBounded(t *testing.T) {
	s := newService(nil, Options{MaxTracked: 3, TouchInterval: time.Minute})
	t0 := testStart
	for i, k := range []string{"a", "b", "c"} {
		if !s.due(k, t0.Add(time.Duration(i)*time.Second)) {
			t.Fatalf("first use of %s not due", k)
		}
	}
	// Full, nothing stale: the memory is cleared to admit the new token.
	if !s.due("d", t0.Add(5*time.Second)) || len(s.touched) != 1 {
		t.Fatalf("full map: %v", s.touched)
	}
	if s.due("d", t0.Add(6*time.Second)) {
		t.Fatal("d due again within the interval")
	}
	s.due("e", t0.Add(10*time.Second))
	s.due("f", t0.Add(70*time.Second))
	// Full: d and e are stale at 75 s and dropped, f is kept.
	if !s.due("g", t0.Add(75*time.Second)) || len(s.touched) != 2 {
		t.Fatalf("stale entries not dropped: %v", s.touched)
	}
	if _, ok := s.touched["f"]; !ok {
		t.Fatalf("fresh entry dropped: %v", s.touched)
	}
	// A known token is never evicted for itself.
	if s.due("f", t0.Add(80*time.Second)) {
		t.Fatal("f due again within the interval")
	}
}

func TestAuthenticateStoreFailures(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ev := newEnv(t, storetest.SQLite(t))
	c := mustCreate(t, ev, CreateInput{})
	header := "Bearer " + c.Secret

	ev.repo.hashErr = errBoom
	if _, err := ev.svc.Authenticate(ctx, ev.a.ID, header, inside); !errors.Is(err, errBoom) || errors.Is(err, ErrInvalid) {
		t.Errorf("Authenticate with a failing store = %v", err)
	}
	ev.repo.hashErr = store.ErrNotFound
	if _, err := ev.svc.Authenticate(ctx, ev.a.ID, header, inside); !errors.Is(err, ErrInvalid) {
		t.Errorf("Authenticate(not found) = %v", err)
	}
	// A record whose hash differs from the presented one is refused.
	ev.repo.hashErr, ev.repo.hashOverride = nil, make([]byte, store.TokenHashSize)
	if _, err := ev.svc.Authenticate(ctx, ev.a.ID, header, inside); !errors.Is(err, ErrInvalid) {
		t.Errorf("Authenticate(hash mismatch) = %v", err)
	}
	ev.repo.hashOverride = nil
	if _, err := ev.svc.Authenticate(ctx, ev.a.ID, header, inside); err != nil {
		t.Errorf("Authenticate = %v", err)
	}
	if !id.Valid(id.APIToken, c.Token.ID) {
		t.Error("malformed token id")
	}
}
