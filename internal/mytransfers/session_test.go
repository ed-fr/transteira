package mytransfers

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

func TestSessionFlow(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		ev := newEnv(t, e)
		ev.verify(ev.a, alice)
		link := ev.mustLink(ev.a, alice)

		s, err := ev.svc.StartSession(ctx, ev.a, clientIP, link)
		if err != nil {
			t.Fatalf("StartSession: %v", err)
		}
		if !validToken(SessionTokenPrefix, s.Token) || s.Email != aliceNorm || !strings.HasPrefix(s.ID, "mts_") ||
			!s.ExpiresAt.Equal(ev.clock.Now().Add(SessionTTL)) || !strings.HasPrefix(s.CSRFToken, CSRFPrefix) {
			t.Fatalf("session = %+v", s)
		}
		evs := ev.auditEvents(ev.a.ID, audit.ActionMyTransfersSignedIn)
		if len(evs) != 1 || evs[0].Actor != aliceNorm || evs[0].ObjectKind != audit.ObjectSenderSession ||
			evs[0].ObjectID != s.ID || evs[0].IP != clientIP {
			t.Errorf("audit = %+v", evs)
		}

		// The cookie resolves to the session, with the same CSRF token.
		info, err := ev.svc.Session(ctx, ev.a, s.Token)
		if err != nil || info != s.SessionInfo {
			t.Fatalf("Session = %+v, %v, want %+v", info, err, s.SessionInfo)
		}
		if !ev.svc.CheckCSRF(s.Token, s.CSRFToken) {
			t.Error("CheckCSRF refused the token of the session")
		}

		// The link is single use.
		_, err = ev.svc.StartSession(ctx, ev.a, clientIP, link)
		wantErr(t, "reused link", err, ErrAccessLinkInvalid)
		if lines := ev.logLines(string(securitylog.AccessLinkInvalid)); len(lines) != 1 || strings.Contains(lines[0], "mta_") {
			t.Errorf("security log = %q", ev.seclog.String())
		}

		// The session is bound to its tenant.
		_, err = ev.svc.Session(ctx, ev.b, s.Token)
		wantErr(t, "other tenant", err, ErrUnauthenticated)
		wantErr(t, "end in other tenant", ev.svc.End(ctx, ev.b, s.Token), ErrUnauthenticated)

		// End, then the session is gone.
		if err := ev.svc.End(ctx, ev.a, s.Token); err != nil {
			t.Fatalf("End: %v", err)
		}
		_, err = ev.svc.Session(ctx, ev.a, s.Token)
		wantErr(t, "ended", err, ErrUnauthenticated)
		wantErr(t, "end again", ev.svc.End(ctx, ev.a, s.Token), ErrUnauthenticated)
	})
}

func TestSessionLinkInvalid(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		ev := newEnv(t, e)
		ev.verify(ev.a, alice)
		ev.verify(ev.b, alice)
		linkA := ev.mustLink(ev.a, alice)
		unknown, err := id.NewToken(id.AccessLinkTokenPrefix, id.AccessLinkTokenBytes)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range []struct{ name, token string }{
			{"malformed", "mta_short"},
			{"other prefix", "ms_" + strings.Repeat("a", 43)},
			{"empty", ""},
			{"unknown", unknown},
			{"other tenant", linkA},
		} {
			before := len(ev.logLines(string(securitylog.AccessLinkInvalid)))
			_, err := ev.svc.StartSession(ctx, ev.b, otherIP, c.token)
			wantErr(t, c.name, err, ErrAccessLinkInvalid)
			if n := len(ev.logLines(string(securitylog.AccessLinkInvalid))); n != before+1 {
				t.Errorf("%s: %d access_link_invalid lines, want %d", c.name, n, before+1)
			}
		}
		if !strings.Contains(ev.seclog.String(), "tenant="+hostB) || strings.Contains(ev.seclog.String(), linkA) {
			t.Errorf("security log = %q", ev.seclog.String())
		}
		// The link of A still works in A, until it expires.
		if _, err := ev.svc.StartSession(ctx, ev.a, clientIP, linkA); err != nil {
			t.Fatalf("link of A in A: %v", err)
		}
		late := ev.mustLink(ev.a, alice)
		ev.clock.Advance(LinkTTL)
		_, err = ev.svc.StartSession(ctx, ev.a, clientIP, late)
		wantErr(t, "expired link", err, ErrAccessLinkInvalid)
	})
}

func TestSessionExpiry(t *testing.T) {
	t.Parallel()
	ev := newEnv(t, storetest.SQLite(t))
	ctx := context.Background()
	s := ev.mustSession(ev.a, alice)
	ev.clock.Advance(SessionTTL - time.Millisecond)
	if _, err := ev.svc.Session(ctx, ev.a, s.Token); err != nil {
		t.Fatalf("before the expiry: %v", err)
	}
	ev.clock.Advance(time.Millisecond)
	_, err := ev.svc.Session(ctx, ev.a, s.Token)
	wantErr(t, "expired", err, ErrUnauthenticated)
	wantErr(t, "end expired", ev.svc.End(ctx, ev.a, s.Token), ErrUnauthenticated)
	for _, tok := range []string{"", "ms_x", "ds_" + strings.Repeat("a", 43), s.CSRFToken} {
		_, err := ev.svc.Session(ctx, ev.a, tok)
		wantErr(t, "malformed "+tok, err, ErrUnauthenticated)
		wantErr(t, "end malformed "+tok, ev.svc.End(ctx, ev.a, tok), ErrUnauthenticated)
	}
}

func TestSessionLockout(t *testing.T) {
	t.Parallel()

	t.Run("window", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		ev := newEnv(t, storetest.SQLite(t))
		ev.verify(ev.a, alice)
		for range SessionFailureLimit {
			_, err := ev.svc.StartSession(ctx, ev.a, clientIP, "mta_bad")
			wantErr(t, "failure", err, ErrAccessLinkInvalid)
		}
		// Locked: even a valid link is refused, without being consumed.
		link := ev.mustLink(ev.a, alice)
		_, err := ev.svc.StartSession(ctx, ev.a, clientIP, link)
		var rl *RateLimitError
		if !errors.As(err, &rl) || rl.RetryAfter <= 0 || rl.RetryAfter > SessionLockout {
			t.Fatalf("locked = %v", err)
		}
		lines := ev.logLines(string(securitylog.RateLimited))
		if len(lines) != 1 || !strings.Contains(lines[0], `scope="`+ScopeSessionIP+`"`) {
			t.Errorf("security log = %q", ev.seclog.String())
		}
		// Another client is not locked; the lock ends.
		if _, err := ev.svc.StartSession(ctx, ev.a, otherIP, link); err != nil {
			t.Fatalf("other client: %v", err)
		}
		ev.clock.Advance(SessionLockout)
		_, err = ev.svc.StartSession(ctx, ev.a, clientIP, ev.mustLink(ev.a, alice))
		if err != nil {
			t.Errorf("after the lockout: %v", err)
		}
	})
	t.Run("injected", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		f := &fakeFailures{locked: true}
		ev := newEnv(t, storetest.SQLite(t), func(o *Options) { o.Failures = f })
		_, err := ev.svc.StartSession(ctx, ev.a, netip.MustParseAddr("2001:db8:1:2:3:4:5:6"), "mta_bad")
		var rl *RateLimitError
		if !errors.As(err, &rl) || rl.RetryAfter != 7*time.Minute || len(f.keys) != 0 {
			t.Fatalf("locked = %v, failures %v", err, f.keys)
		}
		f.locked = false
		_, _ = ev.svc.StartSession(ctx, ev.a, netip.MustParseAddr("2001:db8:1:2:3:4:5:6"), "mta_bad")
		if len(f.keys) != 1 || f.keys[0] != "2001:db8:1:2::/64" {
			t.Errorf("failure keys = %v", f.keys)
		}
	})
}

func TestClientKey(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"203.0.113.7":          "203.0.113.7",
		"::ffff:203.0.113.7":   "203.0.113.7",
		"2001:db8:1:2:3:4:5:6": "2001:db8:1:2::/64",
		"fe80::1%eth0":         "fe80::/64",
	} {
		if got := clientKey(netip.MustParseAddr(in)); got != want {
			t.Errorf("clientKey(%s) = %s, want %s", in, got, want)
		}
	}
	if got := clientKey(netip.Addr{}); got != "invalid" {
		t.Errorf("clientKey(invalid) = %s", got)
	}
}

func TestCheckCSRF(t *testing.T) {
	t.Parallel()
	ev := newEnv(t, storetest.SQLite(t))
	s := ev.mustSession(ev.a, alice)
	other, err := ev.svc.csrfToken("ms_" + strings.Repeat("b", 43))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, token, header string
	}{
		{"other session", s.Token, other},
		{"no prefix", s.Token, strings.TrimPrefix(s.CSRFToken, CSRFPrefix)},
		{"bad base64", s.Token, CSRFPrefix + "!!"},
		{"empty token", "", s.CSRFToken},
		{"empty header", s.Token, ""},
	} {
		if ev.svc.CheckCSRF(c.token, c.header) {
			t.Errorf("%s: accepted", c.name)
		}
	}
	// A deposit CSRF token of the same session token is never valid.
	mac, err := ev.keys.MAC(crypto.MACPurposeCSRF, []byte(s.Token))
	if err != nil {
		t.Fatal(err)
	}
	if ev.svc.CheckCSRF(s.Token, CSRFPrefix+base64.RawURLEncoding.EncodeToString(mac)) {
		t.Error("a deposit CSRF token was accepted")
	}
	ev.svc.keys = faultKeys{Keys: ev.keys, fail: map[crypto.MACPurpose]bool{crypto.MACPurposeMeCSRF: true}}
	if ev.svc.CheckCSRF(s.Token, s.CSRFToken) {
		t.Error("accepted with a failing MAC")
	}
}

func TestSessionFailures(t *testing.T) {
	t.Parallel()
	t.Run("token", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		ev := newEnv(t, storetest.SQLite(t))
		ev.verify(ev.a, alice)
		link := ev.mustLink(ev.a, alice)
		ev.svc.newToken = func(string, int) (string, error) { return "", errBoom }
		if _, err := ev.svc.StartSession(ctx, ev.a, clientIP, link); !errors.Is(err, errBoom) {
			t.Errorf("StartSession = %v", err)
		}
	})
	t.Run("csrf", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		ev := newEnv(t, storetest.SQLite(t))
		s := ev.mustSession(ev.a, alice)
		ev.verify(ev.a, alice)
		link := ev.mustLink(ev.a, alice)
		ev.svc.keys = faultKeys{Keys: ev.keys, fail: map[crypto.MACPurpose]bool{crypto.MACPurposeMeCSRF: true}}
		if _, err := ev.svc.StartSession(ctx, ev.a, clientIP, link); !errors.Is(err, errBoom) {
			t.Errorf("StartSession = %v", err)
		}
		if _, err := ev.svc.Session(ctx, ev.a, s.Token); !errors.Is(err, errBoom) {
			t.Errorf("Session = %v", err)
		}
		// The link was not consumed by the failed attempt.
		ev.svc.keys = ev.keys
		if _, err := ev.svc.StartSession(ctx, ev.a, clientIP, link); err != nil {
			t.Errorf("StartSession after the failure: %v", err)
		}
	})
	t.Run("storage", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		ev := newEnv(t, storetest.SQLite(t))
		s := ev.mustSession(ev.a, alice)
		link := ev.mustLink(ev.a, alice)
		ev.fail("openSession", "session", "endSession")
		if _, err := ev.svc.StartSession(ctx, ev.a, clientIP, link); !errors.Is(err, errBoom) || errors.Is(err, ErrAccessLinkInvalid) {
			t.Errorf("StartSession = %v", err)
		}
		if _, err := ev.svc.Session(ctx, ev.a, s.Token); !errors.Is(err, errBoom) {
			t.Errorf("Session = %v", err)
		}
		if err := ev.svc.End(ctx, ev.a, s.Token); !errors.Is(err, errBoom) {
			t.Errorf("End = %v", err)
		}
	})
	t.Run("session conflict", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		// Two sessions drawing the same cookie token: the second opening
		// fails in its transaction, and its link stays unused.
		ev := newEnv(t, storetest.SQLite(t))
		ev.verify(ev.a, alice)
		first, second := ev.mustLink(ev.a, alice), ev.mustLink(ev.a, alice)
		fixed := "ms_" + strings.Repeat("c", 43)
		ev.svc.newToken = func(p string, n int) (string, error) {
			if p == SessionTokenPrefix {
				return fixed, nil
			}
			return id.NewToken(p, n)
		}
		if _, err := ev.svc.StartSession(ctx, ev.a, clientIP, first); err != nil {
			t.Fatal(err)
		}
		_, err := ev.svc.StartSession(ctx, ev.a, clientIP, second)
		if err == nil || errors.Is(err, ErrAccessLinkInvalid) {
			t.Fatalf("conflicting session = %v", err)
		}
		ev.svc.newToken = id.NewToken
		if _, err := ev.svc.StartSession(ctx, ev.a, clientIP, second); err != nil {
			t.Errorf("link after the rolled back opening: %v", err)
		}
	})
	t.Run("scoped", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		// The transactional methods of the store repo refuse an empty
		// tenant before opening a transaction.
		ev := newEnv(t, storetest.SQLite(t))
		r := storeRepo{db: ev.db}
		if _, err := r.openSession(ctx, "", tokenHash("a"), tokenHash("b"), testStart, testStart.Add(time.Hour)); err == nil {
			t.Error("openSession accepted an empty tenant")
		}
	})
}

// TestSessionAddressRevoked checks L1: a link mailed to an address that is
// erased, no longer active or blocklisted before it is opened gives the
// same answer as an invalid link, and is consumed all the same.
func TestSessionAddressRevoked(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		ev := newEnv(t, e)
		block := func(kind store.BlocklistKind, value string) func() {
			return func() {
				if _, err := ev.db.Blocklist().Create(ctx, ev.a.ID, store.BlocklistEntry{Kind: kind, Value: value, CreatedBy: "admin"}); err != nil {
					t.Fatal(err)
				}
			}
		}
		for _, c := range []struct {
			name, email string
			revoke      func()
		}{
			{"erased", "erased@entity-a.example.com", func() {
				if _, err := ev.db.VerifiedAddresses().Delete(ctx, ev.a.ID, "erased@entity-a.example.com"); err != nil {
					t.Fatal(err)
				}
			}},
			{"inactive", "idle@entity-a.example.com", func() {
				old := ev.clock.Now().AddDate(0, -store.VerifiedRetentionMonths, -1)
				if err := ev.db.VerifiedAddresses().Touch(ctx, ev.a.ID, "idle@entity-a.example.com", old); err != nil {
					t.Fatal(err)
				}
			}},
			{"blocked address", "blocked@entity-a.example.com", block(store.BlockEmail, "blocked@entity-a.example.com")},
			{"blocked domain", "carol@entity-c.example.com", block(store.BlockDomain, "entity-c.example.com")},
		} {
			ev.verify(ev.a, c.email)
			link := ev.mustLink(ev.a, c.email)
			c.revoke()
			before := len(ev.logLines(string(securitylog.AccessLinkInvalid)))
			_, err := ev.svc.StartSession(ctx, ev.a, clientIP, link)
			wantErr(t, c.name, err, ErrAccessLinkInvalid)
			if n := len(ev.logLines(string(securitylog.AccessLinkInvalid))); n != before+1 {
				t.Errorf("%s: %d access_link_invalid lines, want %d", c.name, n, before+1)
			}
			// The link was consumed: verified again, the address still
			// cannot use it.
			ev.verify(ev.a, c.email)
			if c.name == "blocked address" || c.name == "blocked domain" {
				continue // still blocked
			}
			_, err = ev.svc.StartSession(ctx, ev.a, clientIP, link)
			wantErr(t, c.name+" (again)", err, ErrAccessLinkInvalid)
		}
		if evs := ev.auditEvents(ev.a.ID, audit.ActionMyTransfersSignedIn); len(evs) != 0 {
			t.Errorf("signed in: %+v", evs)
		}
	})
}

// TestOpenSessionStoreFaults checks that a failure of the address checks
// of openSession surfaces as an error, not as an invalid link, and rolls
// the consumption back.
func TestOpenSessionStoreFaults(t *testing.T) {
	t.Parallel()
	for _, c := range []struct{ name, fault string }{
		{"verified", `DROP TABLE verified_addresses`},
		{"blocklist", `DROP TABLE blocklist_entries`},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			e := storetest.SQLite(t)
			ev := newEnv(t, e)
			ev.verify(ev.a, alice)
			link := ev.mustLink(ev.a, alice)
			raw, err := sql.Open("sqlite", e.DSN)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = raw.Close() })
			if _, err := raw.ExecContext(ctx, `PRAGMA foreign_keys = OFF; `+c.fault); err != nil {
				t.Fatal(err)
			}
			_, err = ev.svc.StartSession(ctx, ev.a, clientIP, link)
			if err == nil || errors.Is(err, ErrAccessLinkInvalid) {
				t.Errorf("StartSession = %v, want a storage error", err)
			}
		})
	}
}
