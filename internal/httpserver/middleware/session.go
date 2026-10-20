package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"github.com/ed-fr/transteira/internal/api/problem"
)

// DepositCookie is the name of the deposit session cookie (OpenAPI security
// scheme depositSession). The __Host- prefix makes browsers require Secure,
// Path=/ and no Domain attribute, so that the cookie is bound to the exact
// FQDN of the tenant.
const DepositCookie = "__Host-tt_deposit"

// HeaderCSRFToken is the request header carrying the CSRF token (OpenAPI
// security scheme csrfToken).
const HeaderCSRFToken = "X-CSRF-Token" //nolint:gosec // G101 false positive: a header name, not a credential.

// SessionResolver resolves the deposit session cookie and checks CSRF
// tokens. The httpserver package adapts internal/deposit.Service to it.
type SessionResolver interface {
	// ResolveSession returns the session whose cookie token is rawToken, in
	// the tenant carried by ctx. ok is false when there is no valid session
	// (malformed, unknown, ended, expired or of another tenant); err reports
	// an internal failure.
	ResolveSession(ctx context.Context, rawToken string) (session any, ok bool, err error)
	// CheckCSRF reports, in constant time, whether header is the CSRF token
	// of the session token rawToken.
	CheckCSRF(rawToken, header string) bool
}

// sessionValue is what [DepositSession] stores in the request context.
type sessionValue struct {
	session any
	token   string
}

// sessionKey is the context key of the deposit session.
type sessionKey struct{}

// DepositSession authenticates the requests for which required returns true
// with the deposit session cookie: the cookie is resolved through resolver,
// and the session and its raw token are stored in the request context (see
// [SessionFrom] and [SessionToken]). A missing or invalid cookie gets a 401
// unauthenticated Problem; a resolver failure gets a 500 internal-error
// Problem, logged on logger (nil discards). Other requests pass untouched.
//
// It runs as a per-operation middleware of the API router, after tenant
// resolution and before the body is read.
func DepositSession(resolver SessionResolver, required func(*http.Request) bool, logger *slog.Logger) func(http.Handler) http.Handler {
	logger = orDiscard(logger)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !required(r) {
				next.ServeHTTP(w, r)
				return
			}
			c, err := r.Cookie(DepositCookie)
			if err != nil || c.Value == "" {
				writeProblem(w, r, problem.CodeUnauthenticated)
				return
			}
			session, ok, err := resolver.ResolveSession(r.Context(), c.Value)
			if err != nil {
				logger.ErrorContext(r.Context(), "deposit session lookup failed",
					slog.String("request_id", requestIDOf(w, r)),
					slog.String("error", err.Error()))
				writeProblem(w, r, problem.CodeInternalError)
				return
			}
			if !ok {
				writeProblem(w, r, problem.CodeUnauthenticated)
				return
			}
			ctx := context.WithValue(r.Context(), sessionKey{}, sessionValue{session: session, token: c.Value})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// SessionFrom returns the deposit session stored by [DepositSession], when
// there is one of type S.
func SessionFrom[S any](ctx context.Context) (S, bool) {
	v, _ := ctx.Value(sessionKey{}).(sessionValue)
	s, ok := v.session.(S)
	return s, ok
}

// SessionToken returns the raw cookie token of the deposit session stored
// by [DepositSession], or "" and false when there is none.
func SessionToken(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(sessionKey{}).(sessionValue)
	return v.token, ok && v.token != ""
}

// CSRF protects the cookie-authenticated requests for which required
// returns true, when their method is unsafe (anything but GET, HEAD,
// OPTIONS and TRACE). It must run inside [DepositSession]. Such a request
// passes only when:
//
//   - its Sec-Fetch-Site header, when present, is "same-origin";
//   - its Origin header, when present, is exactly https://<Host>, compared
//     case-insensitively and ignoring an explicit :443 port;
//   - its X-CSRF-Token header is the CSRF token of the session token in the
//     context, checked in constant time by checker.
//
// Any failure gets a 403 csrf-invalid Problem. The Origin rule always
// requires the https scheme, even though r.TLS is nil behind the reverse
// proxy that terminates TLS: TransTeira is only served over https in
// production, and accepting a plain http Origin would require a dedicated
// insecure development option, which does not exist. Clients that send no
// Origin (scripts, tests) are checked on the token alone.
func CSRF(checker SessionResolver, required func(*http.Request) bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isSafeMethod(r.Method) || !required(r) {
				next.ServeHTTP(w, r)
				return
			}
			token, ok := SessionToken(r.Context())
			if !ok || !sameSite(r) || !sameOrigin(r) || !checker.CheckCSRF(token, r.Header.Get(HeaderCSRFToken)) {
				writeProblem(w, r, problem.CodeCSRFInvalid)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// isSafeMethod reports whether method is safe in the sense of RFC 9110.
func isSafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	default:
		return false
	}
}

// sameSite applies the Sec-Fetch-Site rule: absent, or "same-origin".
func sameSite(r *http.Request) bool {
	v := r.Header.Values("Sec-Fetch-Site")
	return len(v) == 0 || (len(v) == 1 && v[0] == "same-origin")
}

// sameOrigin applies the Origin rule: absent, or https://<Host>.
func sameOrigin(r *http.Request) bool {
	v := r.Header.Values("Origin")
	if len(v) == 0 {
		return true
	}
	if len(v) != 1 {
		return false
	}
	host, ok := strings.CutPrefix(v[0], "https://")
	// r.Host passed tenant resolution, so it holds no path, userinfo or
	// query: an Origin equal to it cannot carry any either.
	return ok && host != "" && strings.EqualFold(stripHTTPSPort(host), stripHTTPSPort(r.Host))
}

// stripHTTPSPort removes an explicit default https port from host.
func stripHTTPSPort(host string) string {
	return strings.TrimSuffix(host, ":443")
}
