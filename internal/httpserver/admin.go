package httpserver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/api/admin"
	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/httpserver/middleware"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Admin host settings.
const (
	// AdminPrefix is the prefix of the administration operations, served
	// on the admin hosts only (404 on tenant hosts).
	AdminPrefix = APIBaseURL + "/admin"
	// ScopeAdminAuth is the rate-limit scope of the per-IP limit of the
	// admin login steps (setup, password, second factor, activation).
	ScopeAdminAuth = "admin_auth"
	// AdminAuthInterval is the interval at which one client IP regains a
	// token of the admin login steps (20 per minute).
	AdminAuthInterval = 3 * time.Second
	// AdminAuthBurst is the number of admin login steps one client IP may
	// make at once. It is a coarse flood guard in front of the password
	// hashing; the precise lockouts (5 failures per username and IP, 20 per
	// IP, 5 wrong second factors per admin) are kept in the database by
	// internal/adminauth.
	AdminAuthBurst = 20
)

// Route patterns of the admin router (as set in Request.Pattern).
const (
	adminSetupStatusPattern = http.MethodGet + " " + AdminPrefix + "/setup"
	adminSetupPattern       = http.MethodPost + " " + AdminPrefix + "/setup"
	adminLoginPattern       = http.MethodPost + " " + AdminPrefix + "/auth/login"
	adminTOTPPattern        = http.MethodPost + " " + AdminPrefix + "/auth/totp"
	adminTOTPConfirmPattern = http.MethodPost + " " + AdminPrefix + "/me/totp/confirm"
	adminActivationPattern  = http.MethodPost + " " + AdminPrefix + "/activation"
	adminVersionPattern     = http.MethodGet + " " + APIBaseURL + "/version"
)

// adminOpenRoutes are the operations of the admin router served without an
// admin session (OpenAPI security []): every other one requires it, and
// its CSRF token on unsafe methods. The unsafe ones among them (setup,
// login, activation) get the Origin and Sec-Fetch-Site checks instead: a
// cross-site page must not be able to drive a login (login CSRF) nor burn
// the failure counters of a victim's IP.
var adminOpenRoutes = map[string]bool{
	adminSetupStatusPattern: true,
	adminSetupPattern:       true,
	adminLoginPattern:       true,
	adminActivationPattern:  true,
	adminVersionPattern:     true,
}

// adminAuthRoutes are the login steps, and the TOTP enrollment
// confirmation (a second factor check), limited per client IP
// (ScopeAdminAuth), on top of the global limit.
var adminAuthRoutes = map[string]bool{
	adminSetupPattern:       true,
	adminLoginPattern:       true,
	adminTOTPPattern:        true,
	adminTOTPConfirmPattern: true,
	adminActivationPattern:  true,
}

// adminSessionRequired reports whether the matched admin operation
// requires the admin session.
func adminSessionRequired(r *http.Request) bool { return !adminOpenRoutes[r.Pattern] }

// adminOpenRoute reports whether the matched admin operation is served
// without a session.
func adminOpenRoute(r *http.Request) bool { return adminOpenRoutes[r.Pattern] }

// adminAuthRoute reports whether the matched admin operation is a login
// step.
func adminAuthRoute(r *http.Request) bool { return adminAuthRoutes[r.Pattern] }

// AdminSessions is the part of the admin authentication service used by
// the admin session and CSRF middlewares. *adminauth.Service implements
// it.
type AdminSessions interface {
	Resolve(ctx context.Context, rawToken string) (adminauth.Principal, error)
	CheckCSRF(rawToken, header string) bool
}

// Compile-time check that the authentication service fits.
var _ AdminSessions = (*adminauth.Service)(nil)

// adminSessionResolver adapts AdminSessions to middleware.SessionResolver.
// The session is an adminauth.Principal.
type adminSessionResolver struct {
	svc AdminSessions
}

// Compile-time check of the middleware interface.
var _ middleware.SessionResolver = adminSessionResolver{}

// ResolveSession implements middleware.SessionResolver.
func (a adminSessionResolver) ResolveSession(ctx context.Context, rawToken string) (any, bool, error) {
	p, err := a.svc.Resolve(ctx, rawToken)
	switch {
	case errors.Is(err, adminauth.ErrUnauthenticated):
		return nil, false, nil
	case err != nil:
		return nil, false, err
	}
	return p, true, nil
}

// CheckCSRF implements middleware.SessionResolver.
func (a adminSessionResolver) CheckCSRF(rawToken, header string) bool {
	return a.svc.CheckCSRF(rawToken, header)
}

// hostSet is the set of the admin hosts, normalized like the tenant FQDNs.
type hostSet map[string]bool

// newHostSet normalizes hosts. It panics on a malformed host, which is a
// wiring error (config.Load validates TT_ADMIN_HOSTS).
func newHostSet(hosts []string) hostSet {
	set := hostSet{}
	for _, h := range hosts {
		n, err := tenant.NormalizeHost(h)
		if err != nil {
			panic(fmt.Sprintf("httpserver: invalid admin host %q: %v", h, err))
		}
		set[n] = true
	}
	return set
}

// match reports whether the raw Host header of a request names an admin
// host. Like the tenant resolution, it reads r.Host only, never
// X-Forwarded-Host or Forwarded (T-04).
func (s hostSet) match(rawHost string) bool {
	if len(s) == 0 {
		return false
	}
	n, err := tenant.NormalizeHost(rawHost)
	return err == nil && s[n]
}

// noStore sets Cache-Control: no-store on every response of the admin
// host: nothing it serves may be kept by a browser or a proxy cache.
func noStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// newAdminHandler builds the router of the admin hosts: the admin
// operations under AdminPrefix, the version and the interactive API
// documentation (adminDocsHandler); any other path goes to the admin web
// interface (webUI.adminHandler), which answers a 404 Problem under /api. No
// tenant is resolved. The per-operation middlewares, from outermost to
// innermost, are: deadlines, the per-IP limit of the login
// steps, the admin session cookie (401), the Origin and Sec-Fetch-Site
// checks of the open login steps and the CSRF checks of the session
// operations (403), the body limit (413) and the JSON media type (415),
// all before the body is read.
func newAdminHandler(deps Deps, ui *webUI, eh errorHandlers, events middleware.SecurityEvents, limiter middleware.Limiter, logger *slog.Logger) http.Handler {
	api := deps.AdminAPI
	if api == nil {
		api = admin.NewServer()
	}
	sessions := middleware.SessionResolver(noSessions{})
	if deps.AdminSessions != nil {
		sessions = adminSessionResolver{svc: deps.AdminSessions}
	}
	strict := gen.NewStrictHandlerWithOptions(api, nil,
		gen.StrictHTTPServerOptions{
			RequestErrorHandlerFunc:  eh.requestError,
			ResponseErrorHandlerFunc: eh.responseError,
		})
	apiMux := http.NewServeMux()
	gen.HandlerWithOptions(strict, gen.StdHTTPServerOptions{
		BaseURL:    APIBaseURL,
		BaseRouter: apiMux,
		// The last middleware is the outermost one.
		Middlewares: []gen.MiddlewareFunc{
			middleware.RequireJSON(func(r *http.Request) bool { return policyOf(r).rawBody }),
			middleware.BodyLimitFunc(bodyLimitOf),
			middleware.AdminCSRF(sessions, adminSessionRequired),
			middleware.SameOrigin(adminOpenRoute),
			middleware.AdminSession(sessions, adminSessionRequired, logger),
			middleware.RateLimitIf(limiter, events, ScopeAdminAuth, adminAuthRoute),
			deadlineMiddleware(logger),
		},
		ErrorHandlerFunc: eh.paramError,
	})
	api404 := withProblemFallback(apiMux)
	mux := http.NewServeMux()
	mux.Handle(AdminPrefix+"/", api404)
	mux.Handle(APIBaseURL+"/version", api404)
	docs := adminDocsHandler(sessions, logger)
	mux.Handle(DocsPath, docs)
	mux.Handle(DocsPath+"/", docs)
	// The bare prefix would otherwise be redirected by the mux.
	mux.Handle(AdminPrefix, http.HandlerFunc(notFound))
	// The web interface overrides the Cache-Control: no-store set by noStore
	// on its fingerprinted assets only.
	mux.Handle("/", middleware.Chain(ui.adminHandler(), fixedDeadline(RequestDeadline, logger)))
	return middleware.Chain(withProblemFallback(mux), noStore, rejectUncleanAPIPaths)
}
