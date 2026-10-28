// Package httpserver assembles the HTTP handler of TransTeira: the common
// middleware chain, the routes that do not belong to a tenant (health check
// and OpenAPI document), the router of the admin hosts and the
// tenant-scoped API generated from api/openapi.yaml.
//
// Order of the layers, from outermost to innermost (see
// internal/httpserver/middleware):
//
//  1. panic recovery;
//  2. request identifier;
//  3. default read and write deadlines (RequestDeadline), so that a request
//     refused before its operation is chosen (421, 429, 404, 405) cannot be
//     read slowly forever; the matched operation replaces them, and the
//     streaming routes clear them;
//  4. real client IP (trusted proxies only);
//     4b. response counter by status code (Deps.Requests), right after the
//     client IP so that it sees every response of the layers below,
//     404 and 429 included;
//  5. security headers;
//  6. rate limit per client IP: the asset limit for the build files of
//     the web interface (GET and HEAD under /assets/, any Host), the
//     global limit for every other request;
//  7. routes outside any tenant: exactly /healthz, /api/openapi.yaml,
//     /metrics and /status (the last two answer a 404 Problem until they
//     are implemented, as when TT_METRICS_TOKEN is unset);
//  8. routing by the raw Host header (never X-Forwarded-Host):
//     - an admin host (TT_ADMIN_HOSTS) goes to the admin router, without
//     tenant resolution: it serves /api/v1/admin/* and /api/v1/version,
//     and the interactive API documentation (/api/docs) to an
//     authenticated admin session, and the admin web interface: / redirects
//     to /admin/, /admin/ and below serve the admin application, any other
//     path outside /api serves it with 404, and /api paths are 404
//     Problems (see newAdminHandler and webUI.adminHandler);
//     - any other host goes through tenant resolution, before any routing
//     (an unknown host gets 421 whatever the path, including paths that
//     would be 404, 405 or a redirect); a known tenant host answers 404
//     for /api/v1/admin and below, before any admin logic, and, with
//     TT_API_DOCS_PUBLIC, serves the interactive API documentation
//     without authentication (without it, /api/docs is an ordinary
//     unknown path); every other path is the public web interface (see
//     webUI.tenantHandler): a 404 Problem under /api, a 405 Problem for a
//     method other than GET and HEAD, the build files, and the public
//     application (200 on its routes, 404 elsewhere);
//  9. per-operation middlewares of the API router, before any body is read,
//     all driven by the route policy table [routePolicies]: read and write
//     deadlines (except streaming routes), maintenance mode (deposit
//     operations get 503), API token of the operations accepting one when
//     the request carries a Bearer Authorization header (401, 403, 429; see
//     tokenAuth.middleware), otherwise deposit session cookie (401) and
//     CSRF protection of unsafe methods (403), body limit (413) and JSON
//     media type (415).
//     The admin router has its own chain: deadlines, per-IP limit of the
//     login steps (429), admin session cookie (401), CSRF and Origin
//     checks (403), body limit and JSON media type.
//
// Every error is an RFC 9457 Problem whose instance is the request
// identifier, except the bodyless answers of the tus PATCH operation.
package httpserver

import (
	"io/fs"
	"log/slog"
	"net/http"
	"net/netip"
	"path"
	"strings"
	"time"

	"golang.org/x/time/rate"

	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/api/public"
	"github.com/ed-fr/transteira/internal/branding"
	"github.com/ed-fr/transteira/internal/health"
	"github.com/ed-fr/transteira/internal/httpserver/middleware"
	"github.com/ed-fr/transteira/internal/ratelimit"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/web"
)

// Rate limits applied by New. They are deliberately generous for legitimate
// use (a browser loads a page with a handful of API calls) and are not
// configurable yet.
const (
	// GlobalRate is the sustained number of requests per second allowed for
	// one client IP, on every route except the build files of the web
	// interface (GET and HEAD under AssetsPrefix, see isAssetRequest), which
	// are charged to the separate asset limiter (AssetRate and AssetBurst):
	// a cold page load fetches dozens of script chunks, which would exhaust
	// the bucket of a few users sharing one NAT address.
	GlobalRate rate.Limit = 50
	// GlobalBurst is the burst allowed for one client IP, on the same
	// routes as GlobalRate.
	GlobalBurst = 100
	// AssetRate is the sustained number of requests per second allowed for
	// one client IP on the build files of the web interface (GET and HEAD
	// under AssetsPrefix, on any Host, see isAssetRequest). It is ten times
	// GlobalRate, so that page loads behind a shared NAT address are not
	// throttled, yet still bounded: an asset request with an unknown Host
	// goes through tenant resolution (a database lookup on a cache miss)
	// before the unknown-host limiter, and must not be an unthrottled way
	// to force such lookups. Volumetric protection beyond this belongs to
	// the reverse proxy and to fail2ban or CrowdSec.
	AssetRate rate.Limit = 500
	// AssetBurst is the burst allowed for one client IP, on the same
	// requests as AssetRate.
	AssetBurst = 1000
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
// indefinitely. Before that, every request gets RequestDeadline as soon as
// it is received, which the operation then replaces.
const (
	// RequestDeadline bounds reading the request body and writing the
	// response of an ordinary (JSON) API operation.
	RequestDeadline = 30 * time.Second
	// ImageDeadline bounds reading or writing a branding image (up to
	// middleware.ImageBodyLimit bytes), which may take longer on a slow
	// link.
	ImageDeadline = 2 * time.Minute
	// AdminLongDeadline bounds the admin operations that wait on a slow
	// party: the SMTP test (up to TT_SMTP_TIMEOUT, at most 5 minutes) and
	// the deletion of a tenant (erasure of all its transfers). The erasure
	// runs detached from the request context: a deletion whose response is
	// cut short by this deadline or by the client goes on server side, and
	// one interrupted otherwise resumes when repeated or at the hourly run.
	AdminLongDeadline = 6 * time.Minute
)

// Route prefixes.
const (
	// APIBaseURL is the prefix of the versioned, tenant-scoped API.
	APIBaseURL = "/api/v1"
	// SpecPath is the path of the OpenAPI document (outside any tenant).
	SpecPath = "/api/openapi.yaml"
	// HealthPath is the path of the health check (outside any tenant).
	HealthPath = "/healthz"
	// MetricsPath is the path of the Prometheus metrics (outside any
	// tenant, since API 1.1).
	MetricsPath = "/metrics"
	// StatusPath is the path of the JSON instance status (outside any
	// tenant, since API 1.1).
	StatusPath = "/status"
	// ScopeGlobal is the rate-limit scope of the global per-IP limiter.
	ScopeGlobal = "global"
	// ScopeAssets is the rate-limit scope of the per-IP limiter of the
	// build files of the web interface (AssetRate and AssetBurst).
	ScopeAssets = "assets"
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
	// scheme depositSession).
	depositSession bool
	// csrf requires the CSRF checks on unsafe methods (OpenAPI security
	// scheme csrfToken); it implies depositSession.
	csrf bool
	// apiToken accepts an API token as the alternative of the deposit
	// session (OpenAPI security scheme apiToken): a request carrying a
	// Bearer Authorization header is authenticated by the token only,
	// without session nor CSRF checks (tokenAuth.middleware).
	apiToken bool
	// tus applies the tus protocol rules (tusMiddleware): Tus-Resumable on
	// every response, 412 and 415 checks, bodyless error responses.
	tus bool
	// idleBody reads the request body with an idle read timeout
	// (idleBodyHandler) instead of a deadline.
	idleBody bool
	// sameOrigin applies the Origin and Sec-Fetch-Site checks of the CSRF
	// protection, without session nor token (middleware.SameOrigin).
	sameOrigin bool
	// idleWrite writes the response with an idle write timeout
	// (idleWriteMiddleware) instead of a deadline.
	idleWrite bool
	// assetBody limits the body to the size limit of the branding image
	// named by the {asset} path value (5 MiB for a logo, 10 MiB for a
	// background), bodyLimit for an unknown name.
	assetBody bool
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

// tokenPolicy is sessionPolicy for an operation that also accepts an API
// token.
func tokenPolicy(csrf bool) routePolicy {
	p := sessionPolicy(csrf)
	p.apiToken = true
	return p
}

// tusPolicy is tokenPolicy for a tus operation on an upload resource.
func tusPolicy(csrf bool) routePolicy {
	p := tokenPolicy(csrf)
	p.tus = true
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
// OpenAPI document (a test checks it). The transfer and upload operations
// accept the deposit session or an API token: a request with a Bearer
// Authorization header takes the token path, any other one the session
// path (401 unauthenticated without the cookie).
//
// The tus PATCH reads its body with an idle read timeout
// (Deps.UploadIdleTimeout) rather than a deadline.
var routePolicies = map[string]routePolicy{
	tusUploadPattern: {
		bodyLimit: middleware.NoBodyLimit, rawBody: true, depositSession: true, csrf: true, apiToken: true, tus: true,
		idleBody: true,
	},
	tusHeadPattern:   tusPolicy(false),
	tusDeletePattern: tusPolicy(true),
	http.MethodPost + " " + APIBaseURL + "/transfers":                           tokenPolicy(true),
	http.MethodGet + " " + APIBaseURL + "/transfers/{transferId}":               tokenPolicy(false),
	http.MethodDelete + " " + APIBaseURL + "/transfers/{transferId}":            tokenPolicy(true),
	http.MethodPost + " " + APIBaseURL + "/transfers/{transferId}/finalize":     tokenPolicy(true),
	http.MethodGet + " " + APIBaseURL + "/downloads/{linkToken}/files/{fileId}": {bodyLimit: middleware.DefaultJSONBodyLimit, idleWrite: true},
	http.MethodGet + " " + APIBaseURL + "/downloads/{linkToken}/archive":        {bodyLimit: middleware.DefaultJSONBodyLimit, idleWrite: true},
	// The unlock of a download needs no session, but its wrong passwords
	// count against the client IP: it must not be triggered cross-site
	// (RequireJSON already refuses the bodies a form can send).
	http.MethodPost + " " + APIBaseURL + "/downloads/{linkToken}/unlock": {
		bodyLimit: middleware.DefaultJSONBodyLimit, deadline: RequestDeadline, sameOrigin: true,
	},
	http.MethodPut + " " + APIBaseURL + "/admin/tenants/{tenantId}/branding/{asset}": {
		bodyLimit: middleware.ImageBodyLimit, rawBody: true, deadline: ImageDeadline, assetBody: true,
	},
	http.MethodPost + " " + APIBaseURL + "/admin/tenants/{tenantId}/smtp/test": {
		bodyLimit: middleware.DefaultJSONBodyLimit, deadline: AdminLongDeadline,
	},
	http.MethodDelete + " " + APIBaseURL + "/admin/tenants/{tenantId}": {
		bodyLimit: middleware.DefaultJSONBodyLimit, deadline: AdminLongDeadline,
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
	return policyOfPattern(r.Pattern)
}

// bodyLimitOf returns the body limit of the operation matched for r.
func bodyLimitOf(r *http.Request) int64 {
	p := policyOf(r)
	if p.assetBody {
		if kind, err := branding.ParseKind(r.PathValue("asset")); err == nil {
			return kind.MaxBytes()
		}
	}
	return p.bodyLimit
}

// policyOfPattern returns the policy of the route pattern.
func policyOfPattern(pattern string) routePolicy {
	if p, ok := routePolicies[pattern]; ok {
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
	// Maintenance is the maintenance mode (*maintenance.Mode); nil means
	// never in maintenance.
	Maintenance MaintenanceMode
	// API implements the operations; nil uses public.NewServer().
	API gen.StrictServerInterface
	// Sessions resolves the deposit session cookies and checks the CSRF
	// tokens (*deposit.Service); nil authenticates no session.
	Sessions DepositSessions
	// APITokens authenticates the API tokens of the operations accepting
	// one (*apitoken.Service); nil refuses every token (401).
	APITokens APITokens
	// AdminHosts are the dedicated hosts of the administration
	// (config.Config.AdminHosts). Empty, no host serves it: the admin
	// operations then answer 404 everywhere.
	AdminHosts []string
	// AdminAPI implements the admin operations served on the admin hosts;
	// nil uses admin.NewServer().
	AdminAPI gen.StrictServerInterface
	// AdminSessions resolves the admin session cookies and checks their
	// CSRF tokens (*adminauth.Service); nil authenticates no session.
	AdminSessions AdminSessions
	// UploadIdleTimeout is the idle read timeout of a tus PATCH body
	// (TT_UPLOAD_IDLE_TIMEOUT); DefaultUploadIdleTimeout when zero.
	UploadIdleTimeout time.Duration
	// DownloadIdleTimeout is the idle write timeout of a download response
	// (TT_DOWNLOAD_IDLE_TIMEOUT); DefaultDownloadIdleTimeout when zero.
	DownloadIdleTimeout time.Duration
	// Spec is the OpenAPI document served at SpecPath (api.OpenAPISpec).
	Spec []byte
	// APIDocsPublic serves the interactive API documentation (DocsPath)
	// without authentication on every host but the admin hosts
	// (TT_API_DOCS_PUBLIC). False, only an authenticated admin session on
	// an admin host gets it.
	APIDocsPublic bool
	// WebUI is the build of the web interface (web/dist, see package web):
	// public/index.html, admin/index.html, assets/* and the root files. Nil
	// uses web.Dist(). It is loaded in memory by New; a missing entry page
	// is logged at warning level and answered by a 503 fallback page.
	WebUI fs.FS
	// Requests counts every response by status code (*metrics.Counters);
	// nil disables the counting.
	Requests RequestCounter
	// Streams tracks the file and archive downloads in progress
	// (*metrics.Counters); nil disables the gauge.
	Streams StreamCounter
	// Metrics and Status serve /metrics and /status (metrics.Handlers),
	// outside any tenant like /healthz. Nil leaves the path to the 404
	// fallback.
	Metrics, Status http.Handler
	// Logger is the application logger; nil discards.
	Logger *slog.Logger
}

// Option customizes New.
type Option func(*options)

type options struct {
	globalLimiter      middleware.Limiter
	assetLimiter       middleware.Limiter
	unknownHostLimiter middleware.Limiter
	adminAuthLimiter   middleware.Limiter
	tokenFailures      TokenFailures
	// defaultDeadline is the read and write deadline set on every request
	// before tenant resolution, rate limiting and routing.
	defaultDeadline time.Duration
}

// withDefaultDeadline replaces the default deadline of the requests
// (RequestDeadline), for tests.
func withDefaultDeadline(d time.Duration) Option {
	return func(o *options) { o.defaultDeadline = d }
}

// WithGlobalLimiter replaces the global per-IP limiter (GlobalRate and
// GlobalBurst), for tests.
func WithGlobalLimiter(l middleware.Limiter) Option {
	return func(o *options) { o.globalLimiter = l }
}

// WithAssetLimiter replaces the per-IP limiter of the build files of the
// web interface (AssetRate and AssetBurst), for tests.
func WithAssetLimiter(l middleware.Limiter) Option {
	return func(o *options) { o.assetLimiter = l }
}

// WithUnknownHostLimiter replaces the per-IP limiter of unknown-host
// requests (UnknownHostInterval and UnknownHostBurst), for tests.
func WithUnknownHostLimiter(l middleware.Limiter) Option {
	return func(o *options) { o.unknownHostLimiter = l }
}

// WithAdminAuthLimiter replaces the per-IP limiter of the admin login
// steps (AdminAuthInterval and AdminAuthBurst), for tests.
func WithAdminAuthLimiter(l middleware.Limiter) Option {
	return func(o *options) { o.adminAuthLimiter = l }
}

// WithAPITokenFailures replaces the per-IP counter of invalid API tokens
// (APITokenFailureLimit, APITokenFailureWindow and APITokenLockout), for
// tests.
func WithAPITokenFailures(f TokenFailures) Option {
	return func(o *options) { o.tokenFailures = f }
}

// New builds the HTTP handler of the application. It panics when a
// required dependency is missing or an admin host is malformed, which are
// wiring errors.
func New(deps Deps, opts ...Option) http.Handler {
	if deps.Resolver == nil || deps.SecurityLog == nil || deps.Health == nil {
		panic("httpserver: New requires a resolver, a security log and a health service")
	}
	o := options{
		globalLimiter:      ratelimit.New(GlobalRate, GlobalBurst),
		assetLimiter:       ratelimit.New(AssetRate, AssetBurst),
		unknownHostLimiter: ratelimit.New(rate.Every(UnknownHostInterval), UnknownHostBurst),
		adminAuthLimiter:   ratelimit.New(rate.Every(AdminAuthInterval), AdminAuthBurst),
		tokenFailures:      newTokenFailures(),
		defaultDeadline:    RequestDeadline,
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
		maintenance = noMaintenance{}
	}
	api := deps.API
	if api == nil {
		api = public.NewServer()
	}
	idle := deps.UploadIdleTimeout
	if idle <= 0 {
		idle = DefaultUploadIdleTimeout
	}
	idleDownload := deps.DownloadIdleTimeout
	if idleDownload <= 0 {
		idleDownload = DefaultDownloadIdleTimeout
	}
	sessions := middleware.SessionResolver(noSessions{})
	if deps.Sessions != nil {
		sessions = sessionResolver{svc: deps.Sessions}
	}
	webFS := deps.WebUI
	if webFS == nil {
		webFS = web.Dist()
	}
	ui, err := newWebUI(webFS)
	logWebUILoad(logger, err)
	events := NewSecurityEvents(deps.SecurityLog, logger)
	eh := errorHandlers{logger: logger}
	tokens := newTokenAuth(deps.APITokens, o.tokenFailures, events, logger)

	// RequestMiddleware gives the operations the HTTP request (the download
	// operations read the grant cookie and serve the files with
	// http.ServeContent).
	strict := gen.NewStrictHandlerWithOptions(api,
		[]gen.StrictMiddlewareFunc{public.RequestMiddleware},
		gen.StrictHTTPServerOptions{
			RequestErrorHandlerFunc:  eh.requestError,
			ResponseErrorHandlerFunc: eh.responseError,
		})
	apiMux := http.NewServeMux()
	gen.HandlerWithOptions(strict, gen.StdHTTPServerOptions{
		BaseURL:    APIBaseURL,
		BaseRouter: apiMux,
		// The last middleware is the outermost one: the tus protocol rules,
		// deadlines, maintenance, API token (which, when it authenticates
		// the request, turns the session, CSRF and Origin checks off),
		// deposit session and CSRF, then the body
		// limit and the JSON media type check, all before the body is
		// decoded. The idle read timeout of the tus PATCH is set even
		// earlier, around the router (idleBodyHandler).
		Middlewares: []gen.MiddlewareFunc{
			middleware.RequireJSON(func(r *http.Request) bool { return policyOf(r).rawBody }),
			middleware.BodyLimitFunc(bodyLimitOf),
			middleware.CSRF(sessions, func(r *http.Request) bool { return policyOf(r).csrf && !tokenAuthenticated(r) }),
			middleware.SameOrigin(func(r *http.Request) bool { return policyOf(r).sameOrigin && !tokenAuthenticated(r) }),
			middleware.DepositSession(sessions, func(r *http.Request) bool {
				p := policyOf(r)
				return (p.depositSession || p.csrf) && !tokenAuthenticated(r)
			}, logger),
			tokens.middleware,
			maintenanceMiddleware(maintenance),
			idleWriteMiddleware(idleDownload, logger),
			streamGaugeMiddleware(deps.Streams),
			deadlineMiddleware(logger),
			tusMiddleware,
		},
		ErrorHandlerFunc: eh.paramError,
	})

	// Routes outside any tenant. They are matched on the exact path, before
	// tenant resolution: the health check must answer for probes that do
	// not send a tenant FQDN (Docker, Uptime Kuma), and the OpenAPI document
	// is identical for every tenant. MetricsPath and StatusPath are served
	// here when their handlers are set (they answer 404 themselves while
	// TT_METRICS_TOKEN is unset), otherwise by the 404 Problem of the
	// fallback, whatever the Host. Nothing else is served without a known
	// Host.
	freeMux := http.NewServeMux()
	freeMux.Handle(HealthPath, health.Handler(deps.Health, maintenance.Active))
	freeMux.Handle(http.MethodGet+" "+SpecPath, public.SpecHandler(deps.Spec))
	if deps.Metrics != nil {
		freeMux.Handle(MetricsPath, deps.Metrics)
	}
	if deps.Status != nil {
		freeMux.Handle(StatusPath, deps.Status)
	}
	tenantFree := withProblemFallback(freeMux)

	// Tenant-scoped routes. The bare APIBaseURL would otherwise be
	// redirected by the mux to APIBaseURL + "/".
	tenantMux := http.NewServeMux()
	tenantMux.Handle(APIBaseURL+"/", tokenRobots(idleBodyHandler(apiMux, withProblemFallback(apiMux), idle, logger)))
	tenantMux.Handle(APIBaseURL, http.HandlerFunc(notFound))
	// The administration is never served on a tenant host: its whole
	// prefix answers 404 before any admin middleware or handler.
	tenantMux.Handle(AdminPrefix+"/", http.HandlerFunc(notFound))
	tenantMux.Handle(AdminPrefix, http.HandlerFunc(notFound))
	// The public API documentation is served on known tenant hosts only:
	// an unknown host keeps its 421 and its unknown_fqdn event.
	if deps.APIDocsPublic {
		docs := publicDocsHandler(logger)
		tenantMux.Handle(DocsPath, docs)
		tenantMux.Handle(DocsPath+"/", docsPathsOnly(docs))
	}
	// Every other path, whatever the method, goes to the public web
	// interface (404 Problem under /api, 405 Problem for a method other
	// than GET and HEAD), on known tenant hosts only.
	tenantMux.Handle("/", middleware.Chain(ui.tenantHandler(), fixedDeadline(RequestDeadline, logger)))
	tenantScoped := middleware.Chain(withProblemFallback(tenantMux),
		middleware.Tenant(deps.Resolver, events, o.unknownHostLimiter, logger),
		rejectUncleanAPIPaths,
	)

	adminHosts := newHostSet(deps.AdminHosts)
	adminScoped := newAdminHandler(deps, ui, eh, events, o.adminAuthLimiter, logger)

	dispatch := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case isTenantFree(r.URL.Path):
			tenantFree.ServeHTTP(w, r)
		case adminHosts.match(r.Host):
			adminScoped.ServeHTTP(w, r)
		default:
			tenantScoped.ServeHTTP(w, r)
		}
	})

	return middleware.Chain(dispatch,
		middleware.Recover(logger),
		middleware.AssignRequestID,
		// Default deadlines (threat T-123), set before tenant resolution,
		// rate limiting and routing: a request refused before its
		// operation is chosen (421, 429, 404, 405) leaves its body unread,
		// and net/http drains up to 256 KiB of it after the handler, under
		// this read deadline. They also replace the deadlines a previous
		// request left on a keep-alive connection. The matched operation
		// then sets its own (deadlineMiddleware, idleBodyHandler,
		// idleWriteMiddleware, fixedDeadline), and the streaming routes
		// clear them, so that this default never cuts an upload or a
		// download.
		fixedDeadline(o.defaultDeadline, logger),
		middleware.RealIP(trusted),
		requestCountMiddleware(deps.Requests),
		middleware.SecurityHeaders(),
		// Every request is charged to exactly one of the two limiters:
		// the asset limiter for the build files of the web interface, the
		// global limiter for everything else.
		middleware.RateLimitIf(o.globalLimiter, events, ScopeGlobal, func(r *http.Request) bool {
			return !isAssetRequest(r)
		}),
		middleware.RateLimitIf(o.assetLimiter, events, ScopeAssets, isAssetRequest),
	)
}

// isAssetRequest reports whether r is charged to the asset limiter rather
// than to the global per-IP limiter: a GET or HEAD request for a build file
// of the web interface, on any Host, whose path starts with AssetsPrefix
// and is already clean (an unclean path, such as /assets/../x, is
// redirected or resolved elsewhere and stays under the global limiter).
// Such files, unknown names included (a 404), are answered from memory.
// Everything else, entry pages, API and documentation included, is charged
// to the global limiter.
func isAssetRequest(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	p := r.URL.Path
	return strings.HasPrefix(p, AssetsPrefix) && cleanPath(p) == p
}

// isTenantFree reports whether p is one of the paths served without a
// tenant (exact match, no cleaning).
func isTenantFree(p string) bool {
	return p == HealthPath || p == SpecPath || p == MetricsPath || p == StatusPath
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
// operation (see routePolicies) on the connection, replacing the default
// deadlines set on every request by New. Streaming routes get none: their
// deadlines are cleared (the default, and any deadline that net/http left
// from an earlier request on a keep-alive connection). A
// writer that does not support deadlines (http.ErrNotSupported, as in
// tests) is accepted silently; any other failure is logged at debug level
// and the request proceeds.
func deadlineMiddleware(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := policyOf(r)
			var deadline time.Time
			if p.deadline > 0 {
				deadline = time.Now().Add(p.deadline)
			}
			rc := http.NewResponseController(w)
			// The read deadline of an idle-timeout body belongs to
			// idleBodyHandler.
			if !p.idleBody {
				logDeadlineError(r, logger, rc.SetReadDeadline(deadline))
			}
			logDeadlineError(r, logger, rc.SetWriteDeadline(deadline))
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
