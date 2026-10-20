// Package httpserver assembles the HTTP handler of TransTeira: the common
// middleware chain, the routes that do not belong to a tenant (health check
// and OpenAPI document) and the tenant-scoped API generated from
// api/openapi.yaml.
//
// Order of the layers, from outermost to innermost (see
// internal/httpserver/middleware):
//
//  1. panic recovery;
//  2. request identifier;
//  3. real client IP (trusted proxies only);
//  4. security headers;
//  5. global rate limit per client IP;
//  6. routes outside any tenant: exactly /healthz and /api/openapi.yaml;
//  7. tenant resolution from the Host header, for every other path, before
//     any routing (an unknown host gets 421 whatever the path, including
//     paths that would be 404, 405 or a redirect);
//  8. per-operation middlewares of the API router, before any body is read,
//     all driven by the route policy table [routePolicies]: read and write
//     deadlines (except streaming routes), maintenance mode (deposit
//     operations get 503), deposit session cookie (401) and CSRF protection
//     of unsafe methods (403), body limit (413) and JSON media type (415).
//
// Every error is an RFC 9457 Problem whose instance is the request
// identifier, except the bodyless answers of the tus PATCH operation.
package httpserver

import (
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"path"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"

	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/api/public"
	"github.com/ed-fr/transteira/internal/health"
	"github.com/ed-fr/transteira/internal/httpserver/middleware"
	"github.com/ed-fr/transteira/internal/ratelimit"
	"github.com/ed-fr/transteira/internal/securitylog"
)

// Rate limits applied by New. They are deliberately generous for legitimate
// use (a browser loads a page with a handful of API calls) and are not
// configurable yet.
const (
	// GlobalRate is the sustained number of requests per second allowed for
	// one client IP, on every route.
	GlobalRate rate.Limit = 50
	// GlobalBurst is the burst allowed for one client IP.
	GlobalBurst = 100
	// UnknownHostInterval is the interval at which one client IP regains a
	// token for requests carrying an unknown Host (5 per minute).
	UnknownHostInterval = 12 * time.Second
	// UnknownHostBurst is the number of unknown-host requests one client IP
	// may make at once before being throttled.
	UnknownHostBurst = 10
)

// Per-request deadlines. The http.Server has no global ReadTimeout or
// WriteTimeout, which would cut tus uploads and file downloads of several
// gigabytes; every other API operation gets these deadlines, set when the
// operation is matched, so that a slow client cannot hold a connection
// indefinitely.
const (
	// RequestDeadline bounds reading the request body and writing the
	// response of an ordinary (JSON) API operation.
	RequestDeadline = 30 * time.Second
	// ImageDeadline bounds reading or writing a branding image (up to
	// middleware.ImageBodyLimit bytes), which may take longer on a slow
	// link.
	ImageDeadline = 2 * time.Minute
)

// Route prefixes.
const (
	// APIBaseURL is the prefix of the versioned, tenant-scoped API.
	APIBaseURL = "/api/v1"
	// SpecPath is the path of the OpenAPI document (outside any tenant).
	SpecPath = "/api/openapi.yaml"
	// HealthPath is the path of the health check (outside any tenant).
	HealthPath = "/healthz"
	// ScopeGlobal is the rate-limit scope of the global per-IP limiter.
	ScopeGlobal = "global"
)

// apiPrefix is the prefix under which every answer must be a Problem rather
// than a plain redirect.
const apiPrefix = "/api"

// routePolicy tells the per-operation middlewares how to treat a route.
type routePolicy struct {
	// bodyLimit is the request body limit in bytes, or
	// middleware.NoBodyLimit.
	bodyLimit int64
	// rawBody is set for operations whose body is not JSON: the JSON media
	// type check is skipped.
	rawBody bool
	// deadline is the read and write deadline of the request; zero means
	// none, for streaming routes.
	deadline time.Duration
	// depositSession requires the deposit session cookie (OpenAPI security
	// scheme depositSession as the only alternative).
	depositSession bool
	// csrf requires the CSRF checks on unsafe methods (OpenAPI security
	// scheme csrfToken); it implies depositSession.
	csrf bool
}

// defaultPolicy applies to every operation absent from routePolicies.
var defaultPolicy = routePolicy{bodyLimit: middleware.DefaultJSONBodyLimit, deadline: RequestDeadline}

// sessionPolicy is defaultPolicy for an operation authenticated by the
// deposit session cookie, with the CSRF checks when csrf is set.
func sessionPolicy(csrf bool) routePolicy {
	p := defaultPolicy
	p.depositSession, p.csrf = true, csrf
	return p
}

// routePolicies is the single place declaring the routes that depart from
// defaultPolicy, keyed by the pattern set in Request.Pattern by the API
// router (more robust than matching the raw path). The streaming routes,
// without deadline, are the tus PATCH upload (also without body limit: it
// enforces the declared Upload-Length itself) and the file and ZIP
// downloads.
//
// The authentication flags mirror the security requirements of the
// OpenAPI document for the implemented operations (a test checks it); the
// cookie-authenticated operations that are still stubs get theirs when
// they are implemented.
var routePolicies = map[string]routePolicy{
	tusUploadPattern: {bodyLimit: middleware.NoBodyLimit, rawBody: true},
	http.MethodGet + " " + APIBaseURL + "/downloads/{linkToken}/files/{fileId}": {bodyLimit: middleware.DefaultJSONBodyLimit},
	http.MethodGet + " " + APIBaseURL + "/downloads/{linkToken}/archive":        {bodyLimit: middleware.DefaultJSONBodyLimit},
	http.MethodPut + " " + APIBaseURL + "/admin/tenants/{tenantId}/branding/{asset}": {
		bodyLimit: middleware.ImageBodyLimit, rawBody: true, deadline: ImageDeadline,
	},
	http.MethodGet + " " + APIBaseURL + "/tenant/assets/{asset}": {
		bodyLimit: middleware.DefaultJSONBodyLimit, deadline: ImageDeadline,
	},
	http.MethodGet + " " + APIBaseURL + "/deposit-sessions/current":    sessionPolicy(false),
	http.MethodDelete + " " + APIBaseURL + "/deposit-sessions/current": sessionPolicy(true),
	http.MethodPost + " " + APIBaseURL + "/invitations":                sessionPolicy(true),
}

// policyOf returns the policy of the operation matched for r.
func policyOf(r *http.Request) routePolicy {
	if p, ok := routePolicies[r.Pattern]; ok {
		return p
	}
	return defaultPolicy
}

// Deps are the dependencies of the handler built by New.
type Deps struct {
	// TrustedProxy reports whether a peer address is a trusted reverse
	// proxy, allowed to set X-Forwarded-For and X-Real-IP (typically
	// config.Config.IsTrustedProxy). Nil trusts no proxy.
	TrustedProxy func(netip.Addr) bool
	// Resolver maps the Host header to a tenant. Required.
	Resolver middleware.TenantResolver
	// SecurityLog receives the security events (unknown host, rate limit).
	// Required.
	SecurityLog *securitylog.Logger
	// Health is the service behind /healthz. Required.
	Health *health.Service
	// Maintenance is the maintenance flag; nil means never in maintenance.
	Maintenance *atomic.Bool
	// API implements the operations; nil uses public.NewServer().
	API gen.StrictServerInterface
	// Sessions resolves the deposit session cookies and checks the CSRF
	// tokens (*deposit.Service); nil authenticates no session.
	Sessions DepositSessions
	// Spec is the OpenAPI document served at SpecPath (api.OpenAPISpec).
	Spec []byte
	// Logger is the application logger; nil discards.
	Logger *slog.Logger
}

// Option customizes New.
type Option func(*options)

type options struct {
	globalLimiter      middleware.Limiter
	unknownHostLimiter middleware.Limiter
}

// WithGlobalLimiter replaces the global per-IP limiter (GlobalRate and
// GlobalBurst), for tests.
func WithGlobalLimiter(l middleware.Limiter) Option {
	return func(o *options) { o.globalLimiter = l }
}

// WithUnknownHostLimiter replaces the per-IP limiter of unknown-host
// requests (UnknownHostInterval and UnknownHostBurst), for tests.
func WithUnknownHostLimiter(l middleware.Limiter) Option {
	return func(o *options) { o.unknownHostLimiter = l }
}

// New builds the HTTP handler of the application. It panics when a
// required dependency is missing, which is a wiring error.
func New(deps Deps, opts ...Option) http.Handler {
	if deps.Resolver == nil || deps.SecurityLog == nil || deps.Health == nil {
		panic("httpserver: New requires a resolver, a security log and a health service")
	}
	o := options{
		globalLimiter:      ratelimit.New(GlobalRate, GlobalBurst),
		unknownHostLimiter: ratelimit.New(rate.Every(UnknownHostInterval), UnknownHostBurst),
	}
	for _, opt := range opts {
		opt(&o)
	}
	logger := deps.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	trusted := deps.TrustedProxy
	if trusted == nil {
		trusted = func(netip.Addr) bool { return false }
	}
	maintenance := deps.Maintenance
	if maintenance == nil {
		maintenance = new(atomic.Bool)
	}
	api := deps.API
	if api == nil {
		api = public.NewServer()
	}
	sessions := middleware.SessionResolver(noSessions{})
	if deps.Sessions != nil {
		sessions = sessionResolver{svc: deps.Sessions}
	}
	events := NewSecurityEvents(deps.SecurityLog, logger)
	eh := errorHandlers{logger: logger}

	strict := gen.NewStrictHandlerWithOptions(api,
		nil,
		gen.StrictHTTPServerOptions{
			RequestErrorHandlerFunc:  eh.requestError,
			ResponseErrorHandlerFunc: eh.responseError,
		})
	apiMux := http.NewServeMux()
	gen.HandlerWithOptions(strict, gen.StdHTTPServerOptions{
		BaseURL:    APIBaseURL,
		BaseRouter: apiMux,
		// The last middleware is the outermost one: deadlines, maintenance,
		// deposit session and CSRF, then the body limit and the JSON media
		// type check, all before the body is decoded.
		Middlewares: []gen.MiddlewareFunc{
			middleware.RequireJSON(func(r *http.Request) bool { return policyOf(r).rawBody }),
			middleware.BodyLimitFunc(func(r *http.Request) int64 { return policyOf(r).bodyLimit }),
			middleware.CSRF(sessions, func(r *http.Request) bool { return policyOf(r).csrf }),
			middleware.DepositSession(sessions, func(r *http.Request) bool {
				p := policyOf(r)
				return p.depositSession || p.csrf
			}, logger),
			maintenanceMiddleware(maintenance),
			deadlineMiddleware(logger),
		},
		ErrorHandlerFunc: eh.paramError,
	})

	// Routes outside any tenant. They are matched on the exact path, before
	// tenant resolution: the health check must answer for probes that do
	// not send a tenant FQDN (Docker, Uptime Kuma), and the OpenAPI document
	// is identical for every tenant. Nothing else is served without a known
	// Host.
	freeMux := http.NewServeMux()
	freeMux.Handle(HealthPath, health.Handler(deps.Health, maintenance.Load))
	freeMux.Handle(http.MethodGet+" "+SpecPath, public.SpecHandler(deps.Spec))
	tenantFree := withProblemFallback(freeMux)

	// Tenant-scoped routes. The bare APIBaseURL would otherwise be
	// redirected by the mux to APIBaseURL + "/".
	tenantMux := http.NewServeMux()
	tenantMux.Handle(APIBaseURL+"/", withProblemFallback(apiMux))
	tenantMux.Handle(APIBaseURL, http.HandlerFunc(notFound))
	tenantScoped := middleware.Chain(withProblemFallback(tenantMux),
		middleware.Tenant(deps.Resolver, events, o.unknownHostLimiter, logger),
		rejectUncleanAPIPaths,
	)

	dispatch := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isTenantFree(r.URL.Path) {
			tenantFree.ServeHTTP(w, r)
			return
		}
		tenantScoped.ServeHTTP(w, r)
	})

	return middleware.Chain(dispatch,
		middleware.Recover(logger),
		middleware.AssignRequestID,
		middleware.RealIP(trusted),
		middleware.SecurityHeaders(),
		middleware.RateLimit(o.globalLimiter, events, ScopeGlobal),
	)
}

// isTenantFree reports whether p is one of the paths served without a
// tenant (exact match, no cleaning).
func isTenantFree(p string) bool {
	return p == HealthPath || p == SpecPath
}

// rejectUncleanAPIPaths answers a 404 not-found Problem for a path that is
// under apiPrefix once cleaned but differs from its clean form (double
// slashes, dot segments): http.ServeMux would otherwise answer a plain 301
// redirect, which an API client does not expect. Paths outside the API keep
// the mux's redirect.
func rejectUncleanAPIPaths(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		clean := cleanPath(p)
		if clean != p && (clean == apiPrefix || strings.HasPrefix(clean, apiPrefix+"/")) {
			notFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// cleanPath returns the canonical form of p, as http.ServeMux computes it:
// rooted, without dot segments or double slashes, keeping a trailing slash.
func cleanPath(p string) string {
	if p == "" {
		return "/"
	}
	if p[0] != '/' {
		p = "/" + p
	}
	np := path.Clean(p)
	if p[len(p)-1] == '/' && np != "/" {
		np += "/"
	}
	return np
}

// notFound answers a 404 not-found Problem.
func notFound(w http.ResponseWriter, r *http.Request) {
	writeProblem(w, r, problem.New(problem.CodeNotFound))
}

// deadlineMiddleware sets the read and write deadlines of the matched
// operation (see routePolicies) on the connection; streaming routes get
// none. A writer that does not support deadlines (http.ErrNotSupported, as
// in tests) is accepted silently; any other failure is logged at debug
// level and the request proceeds.
func deadlineMiddleware(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if d := policyOf(r).deadline; d > 0 {
				deadline := time.Now().Add(d)
				rc := http.NewResponseController(w)
				for _, err := range []error{rc.SetReadDeadline(deadline), rc.SetWriteDeadline(deadline)} {
					if err != nil && !errors.Is(err, http.ErrNotSupported) {
						logger.DebugContext(r.Context(), "cannot set request deadline",
							slog.String("request_id", middleware.RequestID(r.Context())),
							slog.String("route", r.Pattern),
							slog.String("error", err.Error()))
					}
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// withProblemFallback serves mux, except when no route matches: the plain
// text 404 and 405 answers of http.ServeMux are replaced by a 404
// not-found or a 405 method-not-allowed Problem, the latter keeping the
// Allow header computed by the mux.
func withProblemFallback(mux *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h, pattern := mux.Handler(r)
		if pattern != "" { // a route or a redirect
			mux.ServeHTTP(w, r)
			return
		}
		// Let the mux's own fallback tell 404 from 405, discarding its body.
		probe := &headerProbe{header: http.Header{}, status: http.StatusOK}
		h.ServeHTTP(probe, r)
		if probe.status == http.StatusMethodNotAllowed {
			if allow := probe.header.Values("Allow"); len(allow) > 0 {
				w.Header()["Allow"] = allow
			}
			writeProblem(w, r, problem.New(problem.CodeMethodNotAllowed))
			return
		}
		notFound(w, r)
	})
}

// headerProbe is a ResponseWriter recording the status and headers of the
// mux fallback handlers and discarding their body.
type headerProbe struct {
	header http.Header
	status int
}

func (p *headerProbe) Header() http.Header         { return p.header }
func (p *headerProbe) Write(b []byte) (int, error) { return len(b), nil }
func (p *headerProbe) WriteHeader(status int)      { p.status = status }
