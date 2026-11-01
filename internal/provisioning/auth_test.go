package provisioning

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/store/storetest"
)

func TestAuthenticate(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		in := goodCreate()
		capBytes := int64(5 << 30)
		in.MaxTransferBytes = &capBytes
		in.AllowedCIDRs = []string{"198.51.100.0/24", "2001:db8::/32"}
		tok := ev.mustToken(t, in)

		// Every refusal is the same error; only the log reason differs.
		body := strings.Repeat("A", 43)
		for name, c := range map[string]struct {
			raw    string
			ip     netip.Addr
			reason string
		}{
			"empty":          {"", mspIP, ReasonMalformed},
			"tenant token":   {"tt_" + body, mspIP, ReasonMalformed},
			"short":          {tok.Secret[:46], mspIP, ReasonMalformed},
			"unknown":        {"ttp_" + body, mspIP, ReasonUnknown},
			"other ip":       {tok.Secret, otherIP, ReasonIPNotAllowed},
			"invalid ip":     {tok.Secret, netip.Addr{}, ReasonIPNotAllowed},
			"ipv6 elsewhere": {tok.Secret, netip.MustParseAddr("2001:db9::1"), ReasonIPNotAllowed},
		} {
			_, err := ev.svc.Authenticate(ctx, c.raw, c.ip)
			wantReason(t, name, err, c.reason)
		}

		// Accepted from either range, an IPv4-mapped address included.
		for _, ip := range []netip.Addr{mspIP, netip.MustParseAddr("2001:db8::7"), netip.MustParseAddr("::ffff:198.51.100.9")} {
			p, err := ev.svc.Authenticate(ctx, tok.Secret, ip)
			if err != nil || p.TokenID != tok.ID || p.Name != tok.Name || p.Prefix != tok.Prefix || p.MaxTenants != 5 ||
				p.MaxTransferBytes != capBytes || p.MaxStorageQuotaBytes != 1<<40 ||
				len(p.AllowedFQDNSuffixes) != 1 || p.AllowedFQDNSuffixes[0] != ".transfer.example.com" {
				t.Fatalf("Authenticate(%s) = %+v, %v", ip, p, err)
			}
		}

		// The last use is recorded at most once a minute.
		lastUsed := func() time.Time {
			t.Helper()
			got, err := ev.db.ProvisioningTokens().Get(ctx, tok.ID)
			if err != nil {
				t.Fatal(err)
			}
			return got.LastUsedAt
		}
		if !lastUsed().Equal(testStart) {
			t.Errorf("LastUsedAt = %v, want %v", lastUsed(), testStart)
		}
		ev.clock.Advance(30 * time.Second)
		ev.mustAuth(t, tok.Secret)
		if !lastUsed().Equal(testStart) {
			t.Errorf("LastUsedAt moved within a minute: %v", lastUsed())
		}
		ev.clock.Advance(31 * time.Second)
		ev.mustAuth(t, tok.Secret)
		if want := testStart.Add(61 * time.Second); !lastUsed().Equal(want) {
			t.Errorf("LastUsedAt = %v, want %v", lastUsed(), want)
		}

		// Expired.
		expires := ev.clock.Now().Add(time.Hour)
		short := goodCreate()
		short.ExpiresAt = &expires
		exp := ev.mustToken(t, short)
		ev.mustAuth(t, exp.Secret)
		ev.clock.Advance(time.Hour)
		_, err := ev.svc.Authenticate(ctx, exp.Secret, mspIP)
		wantReason(t, "expired", err, ReasonExpired)
		var ae *AuthError
		if errors.As(err, &ae) && ae.TokenID != exp.ID {
			t.Errorf("TokenID of the refusal = %q", ae.TokenID)
		}
	})
}

func TestAuthenticateFailures(t *testing.T) {
	ctx := context.Background()
	ev := newEnv(t, storetest.SQLite(t))
	tok := ev.mustToken(t, goodCreate())

	// A store failure is not a refusal of the token, but fails anyway.
	ev.faults("tokenByHash")
	_, err := ev.svc.Authenticate(ctx, tok.Secret, mspIP)
	if err == nil || errors.Is(err, ErrInvalidToken) || !errors.Is(err, errBoom) {
		t.Errorf("store failure = %v", err)
	}
	// A row whose hash differs from the presented one (collation).
	f := ev.faults()
	f.hash = make([]byte, 32)
	_, err = ev.svc.Authenticate(ctx, tok.Secret, mspIP)
	wantReason(t, "hash mismatch", err, ReasonUnknown)
	// The last use cannot be written: logged, the request passes.
	ev.faults("touch")
	if _, err := ev.svc.Authenticate(ctx, tok.Secret, mspIP); err != nil {
		t.Errorf("touch failure refused the request: %v", err)
	}
	if !strings.Contains(ev.logs.String(), "last use not recorded") {
		t.Errorf("touch failure not logged: %s", ev.logs)
	}
}
