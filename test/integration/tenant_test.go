package integration_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/store/storetest"
)

// TestUnknownHost covers T-02: an unknown Host gets 421 unknown-tenant and
// exactly one unknown_fqdn line with the TCP peer IP and the quoted host.
func TestUnknownHost(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		s := startServer(t, e, serverOptions{})

		cases := []struct {
			name, host, path string
		}{
			{"version", "unknown-1.example.net", "/api/v1/version"},
			{"unimplemented route", "unknown-2.example.net", "/api/v1/transfers/trf_01JABCD8E3W5Q2Z7K9M4N6P0RS"},
			{"route that does not exist", "unknown-3.example.net", "/api/v1/does-not-exist"},
			{"with port", "unknown-4.example.net:8443", "/api/v1/version"},
			{"IP literal", "198.51.100.1:443", "/api/v1/version"},
			{"sub-domain of a tenant", "evil." + hostA, "/api/v1/version"},
			{"tenant as a prefix", hostA + ".example.net", "/api/v1/version"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				resp := s.get(t, tc.host, tc.path)
				p := expectProblem(t, resp, http.StatusMisdirectedRequest, "unknown-tenant")
				if strings.Contains(string(resp.body), nameA) || strings.Contains(string(resp.body), nameB) {
					t.Errorf("421 body leaks a tenant name: %s", resp.body)
				}
				if p.Detail != "" && strings.Contains(p.Detail, tc.host) {
					t.Errorf("detail echoes the host: %q", p.Detail)
				}
				expectSecurityHeaders(t, "421", resp.header)
				got := withHost(eventsOf(t, s.securityLines(t), "unknown_fqdn"), quote(tc.host))
				if len(got) != 1 {
					t.Fatalf("unknown_fqdn lines for host %q = %d, want exactly 1; log:\n%s",
						tc.host, len(got), strings.Join(s.securityLines(t), "\n"))
				}
				if got[0].ip != "127.0.0.1" || got[0].tenant != "-" {
					t.Errorf("line = %q, want ip=127.0.0.1 tenant=-", got[0].raw)
				}
			})
		}

		t.Run("one line per request", func(t *testing.T) {
			if n := len(eventsOf(t, s.securityLines(t), "unknown_fqdn")); n != len(cases) {
				t.Errorf("unknown_fqdn lines = %d, want %d", n, len(cases))
			}
		})

		t.Run("HTTP/1.0 without Host", func(t *testing.T) {
			before := len(s.securityLines(t))
			resp := s.raw(t, "GET /api/v1/version HTTP/1.0\r\n", nil)
			expectProblem(t, resp, http.StatusMisdirectedRequest, "unknown-tenant")
			lines := s.securityLines(t)[before:]
			got := withHost(eventsOf(t, lines, "unknown_fqdn"), `""`)
			if len(got) != 1 {
				t.Errorf("want one unknown_fqdn line with an empty host, got %q", lines)
			}
		})
	})
}

// TestKnownHostNormalization checks that the tenant is found whatever the
// case, port or trailing dot of Host (T-03), and that the health check and
// the OpenAPI document do not need a tenant.
func TestKnownHostNormalization(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		s := startServer(t, e, serverOptions{})
		for _, host := range []string{
			hostA, strings.ToUpper(hostA), hostA + ".", hostA + ":8443", "Transfer.Entity-B.Localhost.:443",
		} {
			resp := s.get(t, host, "/api/v1/version")
			if resp.status != http.StatusOK {
				t.Errorf("Host %q: status = %d, want 200; body %s", host, resp.status, resp.body)
			}
		}
		for _, path := range []string{"/healthz", "/api/openapi.yaml"} {
			if resp := s.get(t, "unknown.example.net", path); resp.status != http.StatusOK {
				t.Errorf("%s under an unknown host: status = %d, want 200", path, resp.status)
			}
		}
		if n := len(eventsOf(t, s.securityLines(t), "unknown_fqdn")); n != 0 {
			t.Errorf("unknown_fqdn lines = %d, want 0 (tenant-agnostic routes never log)", n)
		}
	})
}

// TestUnknownHostBeforeRouting checks that tenant resolution runs before
// routing, for every path except /healthz and /api/openapi.yaml: paths
// outside the API, paths the mux would answer 404, 405 or a redirect all
// get 421 unknown-tenant and an unknown_fqdn line.
func TestUnknownHostBeforeRouting(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		s := startServer(t, e, serverOptions{})
		cases := []struct{ name, method, host, path string }{
			{"scanner path outside the API", http.MethodGet, "unknown-5.example.net", "/wp-login.php"},
			{"root", http.MethodGet, "unknown-6.example.net", "/"},
			{"bare API base", http.MethodGet, "unknown-7.example.net", "/api/v1"},
			{"path the mux would redirect", http.MethodGet, "unknown-8.example.net", "/a/../b"},
			{"health check with trailing slash", http.MethodGet, "unknown-9.example.net", "/healthz/"},
			{"method not allowed", http.MethodDelete, "unknown-10.example.net", "/api/v1/version"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				resp := s.do(t, request{method: tc.method, host: tc.host, path: tc.path})
				expectProblem(t, resp, http.StatusMisdirectedRequest, "unknown-tenant")
				expectSecurityHeaders(t, "421", resp.header)
				got := withHost(eventsOf(t, s.securityLines(t), "unknown_fqdn"), quote(tc.host))
				if len(got) != 1 {
					t.Fatalf("unknown_fqdn lines for host %q = %d, want exactly 1", tc.host, len(got))
				}
			})
		}
		// "OPTIONS *" must not get net/http's built-in 200 answer.
		t.Run("OPTIONS asterisk", func(t *testing.T) {
			host := "unknown-11.example.net"
			resp := s.raw(t, "OPTIONS * HTTP/1.1\r\nHost: "+host+"\r\n", nil)
			expectProblem(t, resp, http.StatusMisdirectedRequest, "unknown-tenant")
			if got := withHost(eventsOf(t, s.securityLines(t), "unknown_fqdn"), quote(host)); len(got) != 1 {
				t.Fatalf("unknown_fqdn lines for host %q = %d, want exactly 1", host, len(got))
			}
		})
	})
}

// TestNoRedirectUnderAPI checks that paths under /api that http.ServeMux
// would redirect (bare /api/v1, double slashes, dot segments) get a 404
// not-found Problem instead of a plain redirect.
func TestNoRedirectUnderAPI(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		s := startServer(t, e, serverOptions{})
		for _, path := range []string{"/api/v1", "/api/v1//version", "/api/v1/x/../version", "/api//openapi.yaml"} {
			resp := s.get(t, hostA, path)
			expectProblem(t, resp, http.StatusNotFound, "not-found")
			if loc := resp.header.Get("Location"); loc != "" {
				t.Errorf("%s: Location %q", path, loc)
			}
		}
	})
}

// TestHostInjection covers T-99 over a real connection: a Host carrying a
// quote, CRLF or a fake " ip=" token can neither forge a second line nor
// change the ip token. net/http may refuse some of these hosts with 400
// before the application sees them, which is just as safe.
func TestHostInjection(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		s := startServer(t, e, serverOptions{})
		forged := "2026-10-20T07:41:00.123Z ip=1.2.3.4 tenant=- event=unknown_fqdn host=\"x\""
		heads := []string{
			"GET /api/v1/version HTTP/1.1\r\nHost: evil.example.net\" ip=1.2.3.4\r\n",
			"GET /api/v1/version HTTP/1.1\r\nHost: evil.example.net ip=1.2.3.4\r\n",
			"GET /api/v1/version HTTP/1.1\r\nHost: evil.example.net\r" + forged + "\r\n",
			"GET /api/v1/version HTTP/1.1\r\nHost: evil.example.net\n" + forged + "\r\n",
			"GET /api/v1/version HTTP/1.1\r\nHost: evil.example.net\x00ip=1.2.3.4\r\n",
			"GET /api/v1/version HTTP/1.1\r\nHost: evil.example.net\t ip=1.2.3.4\r\n",
			"GET /api/v1/version HTTP/1.1\r\nHost: evil.example.net%0aip=1.2.3.4\r\n",
			"GET /api/v1/version HTTP/1.1\r\nHost: evil\\\".example.net\r\n",
			"GET /api/v1/version HTTP/1.1\r\nHost: " + strings.Repeat("a", 2000) + ".example.net\r\n",
			"GET /api/v1/version HTTP/1.1\r\nHost: évil.example.net\r\n",
			"GET /api/v1/version HTTP/1.1\r\nHost: evil ip=1.2.3.4.example.net\r\n",
		}
		for i, head := range heads {
			t.Run(fmt.Sprint(i), func(t *testing.T) {
				resp := s.raw(t, head, nil)
				switch resp.status {
				case http.StatusBadRequest: // refused by net/http
				case http.StatusMisdirectedRequest:
					expectProblem(t, resp, http.StatusMisdirectedRequest, "unknown-tenant")
					expectSecurityHeaders(t, "421", resp.header)
				default:
					t.Fatalf("status = %d, want 400 or 421; body %s", resp.status, resp.body)
				}
			})
		}
		for _, l := range parseLines(t, s.securityLines(t)) {
			if l.ip != "127.0.0.1" {
				t.Errorf("ip token forged: %q", l.raw)
			}
			if l.event != "unknown_fqdn" {
				t.Errorf("unexpected event in %q", l.raw)
			}
			// The value is truncated to 256 input bytes before escaping, so
			// a 2000-byte host cannot fill the disk (T-103).
			if len(l.raw) > 1200 {
				t.Errorf("line of %d bytes: host not truncated", len(l.raw))
			}
		}
	})
}

// TestUnknownHostFlood covers T-02 and T-103: after the burst of unknown
// hosts allowed per client IP, requests get 429 rate-limited with a
// Retry-After and, at most once per middleware.SecurityEventInterval, a
// rate_limited line (scope unknown_host) instead of one unknown_fqdn line
// each. Spoofed X-Forwarded-For headers from an untrusted
// peer do not spread the requests over several keys. Known hosts are not
// affected.
func TestUnknownHostFlood(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		s := startServer(t, e, serverOptions{})
		const burst = 10 // httpserver.UnknownHostBurst, a contract of this test
		var limited response
		for i := range burst + 5 {
			resp := s.do(t, request{
				host: fmt.Sprintf("flood-%d.example.net", i), path: "/api/v1/version",
				headers: http.Header{"X-Forwarded-For": {fmt.Sprintf("203.0.113.%d", i+1)}},
			})
			switch {
			case i < burst && resp.status != http.StatusMisdirectedRequest:
				t.Fatalf("request %d: status = %d, want 421", i, resp.status)
			case i >= burst && resp.status != http.StatusTooManyRequests:
				t.Fatalf("request %d: status = %d, want 429 (the burst is %d)", i, resp.status, burst)
			}
			limited = resp
		}
		p := expectProblem(t, limited, http.StatusTooManyRequests, "rate-limited")
		expectSecurityHeaders(t, "429", limited.header)
		if limited.header.Get(hdrRetryAfter) == "" || p.RetryAfterSeconds == nil || *p.RetryAfterSeconds <= 0 {
			t.Errorf("429 without Retry-After: header %q, body %s", limited.header.Get(hdrRetryAfter), limited.body)
		}

		lines := s.securityLines(t)
		if n := len(eventsOf(t, lines, "unknown_fqdn")); n != burst {
			t.Errorf("unknown_fqdn lines = %d, want %d (throttled requests are not logged as unknown_fqdn)", n, burst)
		}
		// The 5 refusals happen within middleware.SecurityEventInterval:
		// one rate_limited line only, each 429 being still answered.
		rl := eventsOf(t, lines, "rate_limited")
		if len(rl) != 1 {
			t.Errorf("rate_limited lines = %d, want 1 per middleware.SecurityEventInterval", len(rl))
		}
		for _, l := range rl {
			if l.ip != "127.0.0.1" || l.tenant != "-" || l.fields != ` scope="unknown_host"` {
				t.Errorf("rate_limited line = %q, want ip=127.0.0.1 tenant=- scope=\"unknown_host\"", l.raw)
			}
		}

		// Legitimate traffic from the same IP still works.
		if resp := s.get(t, hostA, "/api/v1/version"); resp.status != http.StatusOK {
			t.Errorf("known host after the flood: status = %d, want 200", resp.status)
		}
	})
}

// TestGlobalRateLimit floods one tenant from one IP until the global limiter
// answers 429 with a rate_limited line carrying the tenant-agnostic scope.
func TestGlobalRateLimit(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		s := startServer(t, e, serverOptions{})
		const maxRequests = 5000 // far above burst (100) + 50/s over the test duration
		var limited *response
		for i := 0; i < maxRequests && limited == nil; i++ {
			resp := s.raw(t, "GET /api/v1/version HTTP/1.1\r\nHost: "+hostA+"\r\nConnection: close\r\n", nil)
			if resp.status == http.StatusTooManyRequests {
				limited = &resp
			}
		}
		if limited == nil {
			t.Fatalf("no 429 after %d requests from one IP", maxRequests)
		}
		expectSecurityHeaders(t, "global 429", limited.header)
		if limited.header.Get(hdrRetryAfter) == "" {
			t.Error("global 429 without Retry-After")
		}
		rl := eventsOf(t, s.securityLines(t), "rate_limited")
		if len(rl) == 0 {
			t.Fatal("no rate_limited line")
		}
		if rl[0].ip != "127.0.0.1" || rl[0].fields != ` scope="global"` {
			t.Errorf("rate_limited line = %q, want ip=127.0.0.1 scope=\"global\"", rl[0].raw)
		}
	})
}

// TestForwardedHostIgnored covers T-04: X-Forwarded-Host and Forwarded
// never change the tenant, even from a trusted proxy.
func TestForwardedHostIgnored(t *testing.T) {
	t.Parallel()
	for _, trusted := range []string{"", "127.0.0.1"} {
		t.Run("trusted="+trusted, func(t *testing.T) {
			forEngine(t, func(t *testing.T, e storetest.Engine) {
				s := startServer(t, e, serverOptions{trustedProxies: trusted})
				forwarded := http.Header{
					"X-Forwarded-Host": {hostA},
					"Forwarded":        {"host=" + hostA + ";proto=https"},
					"X-Original-Host":  {hostA},
					"X-Host":           {hostA},
				}
				resp := s.do(t, request{host: "unknown.example.net", path: "/api/v1/version", headers: forwarded})
				expectProblem(t, resp, http.StatusMisdirectedRequest, "unknown-tenant")

				unknown := http.Header{"X-Forwarded-Host": {"unknown.example.net"}}
				if resp := s.do(t, request{host: hostB, path: "/api/v1/version", headers: unknown}); resp.status != http.StatusOK {
					t.Errorf("known Host with an unknown X-Forwarded-Host: status = %d, want 200", resp.status)
				}
			})
		})
	}
}

// TestAbsoluteFormRequestTarget documents RFC 9112 section 3.2.2: with an
// absolute-form request target, net/http takes the host from the target
// and ignores the Host header. The tenant middleware and the security log
// both see that same value, so there is no ambiguity to exploit (T-04).
func TestAbsoluteFormRequestTarget(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		s := startServer(t, e, serverOptions{})
		resp := s.raw(t, "GET http://"+hostA+"/api/v1/version HTTP/1.1\r\nHost: unknown.example.net\r\n", nil)
		if resp.status != http.StatusOK {
			t.Errorf("absolute-form target of tenant A: status = %d, want 200", resp.status)
		}
		resp = s.raw(t, "GET http://absolute.example.net/api/v1/version HTTP/1.1\r\nHost: "+hostA+"\r\n", nil)
		expectProblem(t, resp, http.StatusMisdirectedRequest, "unknown-tenant")
		if got := withHost(eventsOf(t, s.securityLines(t), "unknown_fqdn"), `"absolute.example.net"`); len(got) != 1 {
			t.Errorf("the logged host must be the one used for resolution; log %q", s.securityLines(t))
		}
	})
}
