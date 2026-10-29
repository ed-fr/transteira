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

// AdminCookie is the name of the admin session cookie (OpenAPI security
// scheme adminSession). It is only set on the admin host: its __Host-
// prefix binds it to that exact host, so a browser never sends it to a
// tenant FQDN.
const AdminCookie = "__Host-tt_admin"

// MyTransfersCookie is the name of the "my transfers" session cookie
// (OpenAPI security scheme myTransfersSession, since 1.1). Like
// DepositCookie, its __Host- prefix binds it to the exact FQDN of the
// tenant.
const MyTransfersCookie = "__Host-tt_me"

// HeaderCSRFToken is the request header carrying the CSRF token (OpenAPI
// security scheme csrfToken).
const HeaderCSRFToken = "X-CSRF-Token" //nolint:gosec // G101 false positive: a header name, not a credential.

// SessionResolver resolves a session cookie and checks CSRF tokens. The
// httpserver package adapts internal/deposit.Service (deposit sessions),
// internal/mytransfers.Service ("my transfers" sessions) and
// internal/adminauth.Service (admin sessions) to it.
type SessionResolver interface {
	// ResolveSession returns the session whose cookie token is rawToken (for
	// a deposit session, in the tenant carried by ctx). ok is false when
	// there is no valid session (malformed, unknown, ended, expired or of
	// another tenant); err reports an internal failure.
	ResolveSession(ctx context.Context, rawToken string) (session any, ok bool, err error)
	// CheckCSRF reports, in constant time, whether header is the CSRF token
	// of the session token rawToken.
	CheckCSRF(rawToken, header string) bool
}

// sessionValue is what [DepositSession] and [AdminSession] store in the
// request context.
type sessionValue struct {
	session any
	token   string
}

// sessionKey is the context key of the deposit session.
type sessionKey struct{}

// adminSessionKey is the context key of the admin session.
type adminSessionKey struct{}

// myTransfersSessionKey is the context key of the "my transfers" session.
type myTransfersSessionKey struct{}

// cookieSpec describes one cookie-authenticated session scheme.
type cookieSpec struct {
	// cookie is the name of the session cookie.
	cookie string
	// key is the context key the session is stored under.
	key any
	// what names the scheme in the logs.
	what string
	// clearInvalid expires a cookie that no longer resolves to a session,
	// in the 401 answer.
	clearInvalid bool
}

// DepositSession authenticates the requests for which required returns true
// with the deposit session cookie: the cookie is resolved through resolver,
// and the session and its raw token are stored in the request context (see
// [SessionFrom] and [SessionToken]). A missing or invalid cookie gets a 401
// unauthenticated Problem; a resolver failure gets a 500 internal-error
// Problem, logged on logger (nil discards) at Error level, or at Debug level
// when the client went away ([ClientGone]). Other requests pass untouched.
//
// It runs as a per-operation middleware of the API router, after tenant
// resolution and before the body is read.
func DepositSession(resolver SessionResolver, required func(*http.Request) bool, logger *slog.Logger) func(http.Handler) http.Handler {
	return cookieSession(cookieSpec{cookie: DepositCookie, key: sessionKey{}, what: "deposit"}, resolver, required, logger)
}

// AdminSession authenticates the requests for which required returns true
// with the admin session cookie ([AdminCookie]), like [DepositSession]: the
// session and its raw token are stored in the request context (see
// [AdminSessionFrom] and [AdminSessionToken]). A missing cookie gets a 401
// unauthenticated Problem; a cookie that resolves to no session also gets
// it, with a Set-Cookie header expiring the cookie. A resolver failure gets
// a 500 internal-error Problem, logged on logger (nil discards) at Error
// level, or at Debug level when the client went away ([ClientGone]).
//
// The resolver decides which sessions are valid; the login state of the
// session (authenticated, or an intermediate step) is enforced by the
// operations.
func AdminSession(resolver SessionResolver, required func(*http.Request) bool, logger *slog.Logger) func(http.Handler) http.Handler {
	spec := cookieSpec{cookie: AdminCookie, key: adminSessionKey{}, what: "admin", clearInvalid: true}
	return cookieSession(spec, resolver, required, logger)
}

// MyTransfersSession authenticates the requests for which required returns
// true with the "my transfers" session cookie ([MyTransfersCookie]), like
// [AdminSession]: the session and its raw token are stored in the request
// context (see [MyTransfersSessionFrom] and [MyTransfersSessionToken]); a
// missing cookie gets a 401 unauthenticated Problem, and a cookie that
// resolves to no session (expired after its hour, ended, of another
// tenant) also gets it, with a Set-Cookie header expiring the cookie.
func MyTransfersSession(resolver SessionResolver, required func(*http.Request) bool, logger *slog.Logger) func(http.Handler) http.Handler {
	spec := cookieSpec{cookie: MyTransfersCookie, key: myTransfersSessionKey{}, what: "my transfers", clearInvalid: true}
	return cookieSession(spec, resolver, required, logger)
}

// cookieSession implements [DepositSession], [AdminSession] and
// [MyTransfersSession].
func cookieSession(spec cookieSpec, resolver SessionResolver, required func(*http.Request) bool, logger *slog.Logger) func(http.Handler) http.Handler {
	logger = orDiscard(logger)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !required(r) {
				next.ServeHTTP(w, r)
				return
			}
			c, err := r.Cookie(spec.cookie)
			if err != nil || c.Value == "" {
				writeProblem(w, r, problem.CodeUnauthenticated)
				return
			}
			session, ok, err := resolver.ResolveSession(r.Context(), c.Value)
			if err != nil {
				logger.Log(r.Context(), failureLevel(r.Context(), err), spec.what+" session lookup failed",
					slog.String("request_id", requestIDOf(w, r)),
					slog.String("error", err.Error()))
				writeProblem(w, r, problem.CodeInternalError)
				return
			}
			if !ok {
				if spec.clearInvalid {
					w.Header().Add("Set-Cookie", ExpiredCookie(spec.cookie))
				}
				writeProblem(w, r, problem.CodeUnauthenticated)
				return
			}
			ctx := context.WithValue(r.Context(), spec.key, sessionValue{session: session, token: c.Value})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ExpiredCookie returns the Set-Cookie value deleting the technical cookie
// name: an empty value, Max-Age=0, and the same Path=/, Secure, HttpOnly
// and SameSite=Strict attributes as when it was set, as the __Host- prefix
// requires.
func ExpiredCookie(name string) string {
	c := http.Cookie{
		Name: name, Value: "", Path: "/", MaxAge: -1,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	}
	return c.String()
}

// SessionFrom returns the deposit session stored by [DepositSession], when
// there is one of type S.
func SessionFrom[S any](ctx context.Context) (S, bool) {
	return sessionFrom[S](ctx, sessionKey{})
}

// SessionToken returns the raw cookie token of the deposit session stored
// by [DepositSession], or "" and false when there is none.
func SessionToken(ctx context.Context) (string, bool) {
	return sessionToken(ctx, sessionKey{})
}

// AdminSessionFrom returns the admin session stored by [AdminSession], when
// there is one of type S.
func AdminSessionFrom[S any](ctx context.Context) (S, bool) {
	return sessionFrom[S](ctx, adminSessionKey{})
}

// AdminSessionToken returns the raw cookie token of the admin session
// stored by [AdminSession], or "" and false when there is none.
func AdminSessionToken(ctx context.Context) (string, bool) {
	return sessionToken(ctx, adminSessionKey{})
}

// MyTransfersSessionFrom returns the "my transfers" session stored by
// [MyTransfersSession], when there is one of type S.
func MyTransfersSessionFrom[S any](ctx context.Context) (S, bool) {
	return sessionFrom[S](ctx, myTransfersSessionKey{})
}

// MyTransfersSessionToken returns the raw cookie token of the "my
// transfers" session stored by [MyTransfersSession], or "" and false when
// there is none.
func MyTransfersSessionToken(ctx context.Context) (string, bool) {
	return sessionToken(ctx, myTransfersSessionKey{})
}

// sessionFrom returns the session of type S stored under key.
func sessionFrom[S any](ctx context.Context, key any) (S, bool) {
	v, _ := ctx.Value(key).(sessionValue)
	s, ok := v.session.(S)
	return s, ok
}

// sessionToken returns the raw token of the session stored under key.
func sessionToken(ctx context.Context, key any) (string, bool) {
	v, ok := ctx.Value(key).(sessionValue)
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
	return csrf(SessionToken, checker, required)
}

// AdminCSRF is [CSRF] for the admin session: it must run inside
// [AdminSession] and checks the X-CSRF-Token header against the token of
// the admin session in the context.
func AdminCSRF(checker SessionResolver, required func(*http.Request) bool) func(http.Handler) http.Handler {
	return csrf(AdminSessionToken, checker, required)
}

// MyTransfersCSRF is [CSRF] for the "my transfers" session: it must run
// inside [MyTransfersSession] and checks the X-CSRF-Token header against
// the token of the "my transfers" session in the context.
func MyTransfersCSRF(checker SessionResolver, required func(*http.Request) bool) func(http.Handler) http.Handler {
	return csrf(MyTransfersSessionToken, checker, required)
}

// csrf implements [CSRF], [AdminCSRF] and [MyTransfersCSRF]; tokenOf
// returns the session token of the request.
func csrf(tokenOf func(context.Context) (string, bool), checker SessionResolver, required func(*http.Request) bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isSafeMethod(r.Method) || !required(r) {
				next.ServeHTTP(w, r)
				return
			}
			token, ok := tokenOf(r.Context())
			if !ok || !sameSite(r) || !sameOrigin(r) || !checker.CheckCSRF(token, r.Header.Get(HeaderCSRFToken)) {
				writeProblem(w, r, problem.CodeCSRFInvalid)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// SameOrigin applies the Sec-Fetch-Site and Origin rules of [CSRF],
// without any token, to the unsafe requests for which required returns
// true: operations that need no session but must not be triggered
// cross-site (the unlock of a download, whose failures count against the
// client IP; the "my transfers" access link request and session opening).
// A failure gets a 403 csrf-invalid Problem.
func SameOrigin(required func(*http.Request) bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !isSafeMethod(r.Method) && required(r) && (!sameSite(r) || !sameOrigin(r)) {
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
	// r.Host passed tenant resolution or matched an admin host, so it holds
	// no path, userinfo or query: an Origin equal to it cannot carry any
	// either.
	return ok && host != "" && strings.EqualFold(stripHTTPSPort(host), stripHTTPSPort(r.Host))
}

// stripHTTPSPort removes an explicit default https port from host.
func stripHTTPSPort(host string) string {
	return strings.TrimSuffix(host, ":443")
}
