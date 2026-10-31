package httpserver

import (
	"net/http"

	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/tenant"
)

// tusOptionsPattern is the route pattern of the tus capabilities
// (getTusCapabilities), answered without body like the other tus
// operations.
const tusOptionsPattern = http.MethodOptions + " " + APIBaseURL + "/uploads"

// setupAllowed is the closed list of the route patterns (as set in
// Request.Pattern by the API router) served on the host of a tenant that is
// still being configured (threat model T-260): the public information of the
// tenant, its branding images and its legal texts, which the "being
// configured" page needs, and the instance version, which holds no tenant
// data. Every other operation of the tenant API router is refused, the
// future ones included (refusal by default). The administration and the
// routes outside any tenant (health check, metrics, status, certificate
// check, OpenAPI document) are not served by this router.
var setupAllowed = map[string]struct{}{
	http.MethodGet + " " + APIBaseURL + "/tenant":                  {},
	http.MethodGet + " " + APIBaseURL + "/tenant/assets/{asset}":   {},
	http.MethodGet + " " + APIBaseURL + "/tenant/legal/{document}": {},
	http.MethodGet + " " + APIBaseURL + "/version":                 {},
}

// setupMiddleware refuses with 503 every operation of the tenant API router
// but those of setupAllowed while the tenant of the request is not active:
// deposits, verification codes, invitations, transfers and uploads, API
// token deposits, downloads, replies and "my transfers" (no transfer can
// exist in a tenant still in setup, since there is no way back to it). A
// tenant whose state is unknown, or a request without tenant, is refused
// too (fail closed); a stored tenant always has a state. The tus operations (HEAD, PATCH, DELETE and the
// OPTIONS capabilities) get a bodyless 503 with Tus-Resumable; the others
// a tenant-in-setup Problem, without Retry-After (the end of the setup
// depends on its administrators).
//
// It runs as a per-operation middleware of the API router right after the
// maintenance middleware (maintenance wins) and before the API token,
// session and CSRF checks, the body limit and any read of the body: an API
// token is therefore refused by this 503 before it is verified, as a
// deposit session is. The state is read from the tenant already resolved
// for the request (no query); the completion of the setup invalidates the
// resolution cache.
func setupMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, allowed := setupAllowed[r.Pattern]; allowed {
			next.ServeHTTP(w, r)
			return
		}
		// No tenant in the context (a wiring error: the tenant router always
		// resolves one) is refused like a tenant in setup (fail closed).
		if t, ok := tenant.FromContext(r.Context()); ok && t.SetupState == tenant.SetupStateActive {
			next.ServeHTTP(w, r)
			return
		}
		if r.Pattern == tusOptionsPattern || policyOf(r).tus {
			w.Header().Set(headerTusResumable, tusVersion)
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		writeProblem(w, r, problem.New(problem.CodeTenantInSetup))
	})
}
