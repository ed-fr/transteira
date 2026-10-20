package integration_test

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/app"
	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// ipCase is one request whose client IP is observed through the ip token of
// the unknown_fqdn line it produces.
type ipCase struct {
	name    string
	headers http.Header
	want    string
}

// observeIP sends each case with a distinct unknown host and checks the ip
// token of the resulting security log line.
func observeIP(t *testing.T, s *server, cases []ipCase) {
	t.Helper()
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			host := fmt.Sprintf("ip-probe-%d.example.net", i)
			resp := s.do(t, request{host: host, path: "/api/v1/version", headers: tc.headers})
			expectProblem(t, resp, http.StatusMisdirectedRequest, "unknown-tenant")
			got := withHost(eventsOf(t, s.securityLines(t), "unknown_fqdn"), quote(host))
			if len(got) != 1 {
				t.Fatalf("want exactly one line for %s, got %d", host, len(got))
			}
			if got[0].ip != tc.want {
				t.Errorf("ip = %s, want %s (line %q)", got[0].ip, tc.want, got[0].raw)
			}
		})
	}
}

// TestForwardingHeadersIgnoredWithoutTrustedProxy covers T-05 and T-07:
// with TT_TRUSTED_PROXIES unset, X-Forwarded-For and X-Real-IP are ignored
// and the ip token is always the TCP peer.
func TestForwardingHeadersIgnoredWithoutTrustedProxy(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		s := startServer(t, e, serverOptions{})
		observeIP(t, s, []ipCase{
			{"XFF", http.Header{"X-Forwarded-For": {"203.0.113.7"}}, "127.0.0.1"},
			{"X-Real-IP", http.Header{"X-Real-Ip": {"203.0.113.8"}}, "127.0.0.1"},
			{"both", http.Header{"X-Forwarded-For": {"203.0.113.7"}, "X-Real-Ip": {"203.0.113.8"}}, "127.0.0.1"},
			{"internal-looking", http.Header{"X-Forwarded-For": {"10.0.0.1, 192.168.1.1"}}, "127.0.0.1"},
			{"Forwarded", http.Header{"Forwarded": {"for=203.0.113.9"}}, "127.0.0.1"},
			{"True-Client-IP", http.Header{"True-Client-Ip": {"203.0.113.10"}, "Cf-Connecting-Ip": {"203.0.113.11"}}, "127.0.0.1"},
		})
	})
}

// TestForwardingHeadersFromTrustedProxy covers T-05 with the loopback
// declared as a trusted proxy (plus 10.0.0.0/8 for multi-hop chains): the
// right-most untrusted X-Forwarded-For entry is the client. When the
// trusted proxy sends no valid forwarded address (missing, malformed or
// ambiguous headers), the client IP is unknown (ip=-): the proxy's own
// address is never taken for the client's.
func TestForwardingHeadersFromTrustedProxy(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		s := startServer(t, e, serverOptions{trustedProxies: "127.0.0.1, 10.0.0.0/8"})
		observeIP(t, s, []ipCase{
			{"single entry", http.Header{"X-Forwarded-For": {"203.0.113.7"}}, "203.0.113.7"},
			{"spoofed left entry ignored", http.Header{"X-Forwarded-For": {"198.51.100.1, 203.0.113.7"}}, "203.0.113.7"},
			{"multi-hop through trusted proxies", http.Header{"X-Forwarded-For": {"198.51.100.1, 203.0.113.7, 10.1.2.3, 10.9.9.9"}}, "203.0.113.7"},
			{"several header lines", http.Header{"X-Forwarded-For": {"198.51.100.1", "203.0.113.7, 10.1.2.3"}}, "203.0.113.7"},
			{"empty entries", http.Header{"X-Forwarded-For": {" , 203.0.113.7 ,, "}}, "203.0.113.7"},
			{"entry with port", http.Header{"X-Forwarded-For": {"203.0.113.7:51234"}}, "203.0.113.7"},
			{"IPv6 with port", http.Header{"X-Forwarded-For": {"[2001:db8::1]:443"}}, "2001:db8::1"},
			{"IPv4-mapped IPv6", http.Header{"X-Forwarded-For": {"::ffff:203.0.113.5"}}, "203.0.113.5"},
			{"IPv6 zone dropped", http.Header{"X-Forwarded-For": {"fe80::1%eth0"}}, "fe80::1"},
			{"all trusted gives no client IP", http.Header{"X-Forwarded-For": {"10.0.0.1, 10.0.0.2"}}, "-"},
			{"malformed right-most gives no client IP", http.Header{"X-Forwarded-For": {"203.0.113.7, not-an-ip"}}, "-"},
			{"malformed behind trusted hop gives no client IP", http.Header{"X-Forwarded-For": {"203.0.113.7, garbage, 10.1.2.3"}}, "-"},
			{"malformed left of the client is never reached", http.Header{"X-Forwarded-For": {"garbage, 203.0.113.7"}}, "203.0.113.7"},
			{"injected ip token", http.Header{"X-Forwarded-For": {"203.0.113.7 ip=1.2.3.4"}}, "-"},
			{"over-long entry", http.Header{"X-Forwarded-For": {"2001:db8::1%" + strings.Repeat("a", 60)}}, "-"},
			{"X-Real-IP when no XFF", http.Header{"X-Real-Ip": {"203.0.113.9"}}, "203.0.113.9"},
			{"X-Real-IP when XFF is blank", http.Header{"X-Forwarded-For": {" "}, "X-Real-Ip": {"203.0.113.9"}}, "203.0.113.9"},
			{"XFF wins over X-Real-IP", http.Header{"X-Forwarded-For": {"203.0.113.7"}, "X-Real-Ip": {"203.0.113.9"}}, "203.0.113.7"},
			{"duplicated X-Real-IP gives no client IP", http.Header{"X-Real-Ip": {"203.0.113.9", "203.0.113.10"}}, "-"},
			{"malformed X-Real-IP gives no client IP", http.Header{"X-Real-Ip": {"203.0.113.9, 203.0.113.10"}}, "-"},
			{"no header gives no client IP", nil, "-"},
		})
	})
}

// TestTrustedProxyRateLimitKey checks that, behind a trusted proxy, the
// unknown-host limiter keys on the real client IP: two clients do not share
// a budget (T-100: the proxy itself is never throttled as one client).
func TestTrustedProxyRateLimitKey(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		s := startServer(t, e, serverOptions{trustedProxies: "127.0.0.1"})
		const burst = 10
		send := func(client string, i int) int {
			return s.do(t, request{
				host: fmt.Sprintf("k-%s-%d.example.net", client, i), path: "/api/v1/version",
				headers: http.Header{"X-Forwarded-For": {client}},
			}).status
		}
		for i := range burst {
			if st := send("203.0.113.1", i); st != http.StatusMisdirectedRequest {
				t.Fatalf("client 1 request %d: %d, want 421", i, st)
			}
		}
		if st := send("203.0.113.1", burst); st != http.StatusTooManyRequests {
			t.Fatalf("client 1 over the burst: %d, want 429", st)
		}
		if st := send("203.0.113.2", 0); st != http.StatusMisdirectedRequest {
			t.Errorf("client 2 is throttled with client 1's budget: %d, want 421", st)
		}
		rl := eventsOf(t, s.securityLines(t), "rate_limited")
		if len(rl) != 1 || rl[0].ip != "203.0.113.1" {
			t.Errorf("rate_limited lines = %+v, want one for 203.0.113.1", rl)
		}
	})
}

// TestStartupRefusesUniversalTrustedProxy covers T-08: config.Load refuses
// a TT_TRUSTED_PROXIES list that is too broad (a prefix shorter than /8 for
// IPv4 or /32 for IPv6, or a union covering a whole family), and app.Run
// refuses such a list in a configuration built by hand.
func TestStartupRefusesUniversalTrustedProxy(t *testing.T) {
	t.Parallel()
	for _, value := range []string{
		"0.0.0.0/0", "::/0", "::ffff:0.0.0.0/96", "127.0.0.1, 0.0.0.0/0", "0.0.0.0/1,128.0.0.0/1",
	} {
		t.Run(value, func(t *testing.T) {
			env := testEnv(t, storetest.SQLite(t), serverOptions{trustedProxies: value, clamd: "127.0.0.1:1"})
			_, err := config.Load(func(k string) string { return env[k] })
			if !errors.Is(err, config.ErrTrustedProxiesTooBroad) {
				t.Fatalf("config.Load = %v, want ErrTrustedProxiesTooBroad", err)
			}
		})
	}
	t.Run("app.Run", func(t *testing.T) {
		cfg := loadConfig(t, testEnv(t, storetest.SQLite(t), serverOptions{clamd: "127.0.0.1:1"}))
		cfg.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/1"), netip.MustParsePrefix("128.0.0.0/1")}
		err := app.Run(t.Context(), cfg, app.WithLogOutput(newWatchBuffer()))
		if !errors.Is(err, config.ErrTrustedProxiesTooBroad) {
			t.Fatalf("app.Run = %v, want config.ErrTrustedProxiesTooBroad", err)
		}
	})
}
