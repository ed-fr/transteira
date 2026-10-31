package httpserver

import (
	"context"
	"net/http"
	"net/netip"
	"strings"

	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/httpserver/middleware"
)

// ProvisioningAuthenticator authenticates the provisioning tokens of the
// provisioning operations (OpenAPI security scheme provisioningToken,
// since API 1.2). It is the only credential of those operations: session
// cookies and CSRF tokens are never read there.
type ProvisioningAuthenticator interface {
	// AuthenticateProvisioning checks rawToken (the value after "Bearer ")
	// presented from client and returns ctx carrying the provisioning
	// principal the handlers read. Any error refuses the request with 401
	// provisioning-token-invalid: an unknown, revoked or expired token, a
	// client outside the allowed ranges of the token, or a failure.
	AuthenticateProvisioning(ctx context.Context, rawToken string, client netip.Addr) (context.Context, error)
}

// provisioningAuth refuses every provisioning operation (route patterns
// under ProvisioningPrefix) that does not carry a provisioning token
// accepted by auth, before any handler: 401 unauthenticated without an
// Authorization Bearer header, 401 provisioning-token-invalid otherwise.
// A nil auth accepts no token at all (fail closed), which is the state of
// a server without provisioning service. Other routes pass through.
func provisioningAuth(auth ProvisioningAuthenticator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !isProvisioningPattern(r.Pattern) {
				next.ServeHTTP(w, r)
				return
			}
			raw, ok := bearerToken(r.Header.Get("Authorization"))
			if !ok {
				w.Header().Set("WWW-Authenticate", challengeBearer)
				writeProblem(w, r, problem.New(problem.CodeUnauthenticated))
				return
			}
			if auth == nil {
				refuseProvisioning(w, r)
				return
			}
			ctx, err := auth.AuthenticateProvisioning(r.Context(), raw, middleware.ClientIP(r.Context()))
			if err != nil {
				refuseProvisioning(w, r)
				return
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// refuseProvisioning answers 401 provisioning-token-invalid.
func refuseProvisioning(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("WWW-Authenticate", challengeInvalidToken)
	writeProblem(w, r, problem.New(problem.CodeProvisioningTokenInvalid))
}

// bearerToken returns the token of an Authorization header of the Bearer
// scheme (case-insensitive scheme name), and whether there is a non-empty
// one.
func bearerToken(header string) (string, bool) {
	scheme, token, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, bearerScheme) {
		return "", false
	}
	token = strings.TrimSpace(token)
	return token, token != ""
}
