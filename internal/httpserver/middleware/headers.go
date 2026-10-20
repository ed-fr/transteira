package middleware

import (
	"net/http"
	"strings"
)

// DefaultCSP is the Content-Security-Policy of the API: nothing may be
// loaded, framed, used as a base URI or submitted to.
const DefaultCSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"

// DefaultPermissionsPolicy denies the powerful browser features TransTeira
// never uses, and opts out of interest-based advertising APIs.
const DefaultPermissionsPolicy = "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=(), browsing-topics=()"

// securityConfig is the configuration of SecurityHeaders.
type securityConfig struct {
	csp           string
	noStorePrefix string
}

// SecurityOption configures [SecurityHeaders].
type SecurityOption func(*securityConfig)

// WithCSP replaces [DefaultCSP], for example for the web interface. An
// empty value is ignored: a Content-Security-Policy is always sent.
func WithCSP(csp string) SecurityOption {
	return func(c *securityConfig) {
		if csp != "" {
			c.csp = csp
		}
	}
}

// WithNoStorePrefix sets the path prefix under which responses get
// "Cache-Control: no-store" (default "/api"). The prefix matches the path
// itself and any path below it ("/api" matches "/api" and "/api/v1/x" but
// not "/apix"). An empty prefix disables the header.
func WithNoStorePrefix(prefix string) SecurityOption {
	return func(c *securityConfig) { c.noStorePrefix = strings.TrimSuffix(prefix, "/") }
}

// SecurityHeaders sets the HTTP security headers of CLAUDE.md section 16.2
// on every response: Content-Security-Policy, X-Content-Type-Options,
// Referrer-Policy, X-Frame-Options, Permissions-Policy,
// Cross-Origin-Opener-Policy and Cross-Origin-Resource-Policy, plus
// Cache-Control: no-store under the API prefix. HSTS is left to the reverse
// proxy.
//
// The headers are set before the next handler runs, so they are present on
// every response, including errors and recovered panics; a handler may
// still override one deliberately.
func SecurityHeaders(opts ...SecurityOption) func(http.Handler) http.Handler {
	cfg := securityConfig{csp: DefaultCSP, noStorePrefix: "/api"}
	for _, opt := range opts {
		opt(&cfg)
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("Content-Security-Policy", cfg.csp)
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("Referrer-Policy", "no-referrer")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Permissions-Policy", DefaultPermissionsPolicy)
			h.Set("Cross-Origin-Opener-Policy", "same-origin")
			h.Set("Cross-Origin-Resource-Policy", "same-origin")
			if cfg.noStorePrefix != "" && underPrefix(r.URL.Path, cfg.noStorePrefix) {
				h.Set("Cache-Control", "no-store")
			}
			next.ServeHTTP(w, r)
		})
	}
}

// underPrefix reports whether path is prefix or lies below it.
func underPrefix(path, prefix string) bool {
	rest, ok := strings.CutPrefix(path, prefix)
	return ok && (rest == "" || rest[0] == '/')
}
