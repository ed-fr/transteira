package metrics

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"golang.org/x/time/rate"

	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/httpserver/middleware"
	"github.com/ed-fr/transteira/internal/ratelimit"
)

// Monitoring token failure settings, mirroring the API tokens
// (httpserver.APITokenFailureLimit and following): TokenFailureLimit
// invalid tokens from one client IP (an IPv6 client per /64) within
// TokenFailureWindow lock that IP out for TokenLockout. The token is a
// random secret of at least 32 characters (T-193), so the lockout is a
// guard against floods and log noise; fail2ban and CrowdSec ban for longer
// on the metrics_token_invalid events.
//
// A locked-out IP presenting the valid token is still served; only its
// other requests get 429, without counting a new failure.
const (
	// ScopeMetricsToken is the rate-limit scope of the per-IP lockout after
	// invalid monitoring tokens.
	ScopeMetricsToken = "metrics_token"
	// TokenFailureLimit is the number of invalid tokens one client IP may
	// present within TokenFailureWindow before being locked out.
	TokenFailureLimit = 10
	// TokenFailureWindow is the sliding window of the failure count.
	TokenFailureWindow = 10 * time.Minute
	// TokenLockout is the duration of the lockout.
	TokenLockout = 15 * time.Minute
)

// bearerScheme is the authentication scheme of the monitoring token (RFC
// 6750), compared case-insensitively.
const bearerScheme = "Bearer"

// WWW-Authenticate challenges of the 401 answers.
const (
	challengeBearer       = bearerScheme
	challengeInvalidToken = bearerScheme + ` error="invalid_token"`
)

// SecurityEvents writes the security log events of the endpoints
// (*httpserver.SecurityEvents implements it).
type SecurityEvents interface {
	// MetricsTokenInvalid records a wrong monitoring token from ip.
	MetricsTokenInvalid(ctx context.Context, ip netip.Addr)
	// RateLimited records a refused request of a locked-out ip; tenantFQDN
	// is empty (the endpoints are outside any tenant).
	RateLimited(ctx context.Context, ip netip.Addr, tenantFQDN, scope string)
}

// TokenFailures counts the invalid tokens per key and locks a key out
// (*ratelimit.Window).
type TokenFailures interface {
	// Locked reports whether key is locked out and for how long.
	Locked(key string) (locked bool, retryAfter time.Duration)
	// Fail records one failure of key.
	Fail(key string) (locked bool, retryAfter time.Duration)
}

// HandlerOptions configures [NewHandler].
type HandlerOptions struct {
	// Token is TT_METRICS_TOKEN; when unset, both endpoints answer 404.
	Token config.Secret
	// AllowedIPs is TT_METRICS_ALLOWED_IPS; when not empty, a client
	// outside these networks gets 404.
	AllowedIPs []netip.Prefix
	// Collector provides the snapshot and the counters. Required when
	// Token is set (a nil Collector answers 500).
	Collector *Collector
	// Events receives the security events (none written when nil).
	Events SecurityEvents
	// ClientIP returns the real client IP of a request (by default
	// middleware.ClientIP of the request context, set by the trusted
	// proxy middleware).
	ClientIP func(*http.Request) netip.Addr
	// Failures counts the invalid tokens (by default a ratelimit.Window
	// with TokenFailureLimit, TokenFailureWindow and TokenLockout).
	Failures TokenFailures
	// Logger receives the internal errors (discarded when nil). The token
	// is never logged.
	Logger *slog.Logger
	// Now is the clock of the default Failures and of the event throttle
	// (time.Now when nil).
	Now func() time.Time
}

// Handlers are the HTTP handlers of the supervision endpoints.
type Handlers struct {
	// Metrics serves /metrics (Prometheus text format 0.0.4).
	Metrics http.Handler
	// Status serves /status (InstanceStatus JSON).
	Status http.Handler
}

// guard holds the access control shared by both endpoints.
type guard struct {
	enabled   bool
	digest    [sha256.Size]byte
	allowed   []netip.Prefix
	collector *Collector
	events    SecurityEvents
	clientIP  func(*http.Request) netip.Addr
	failures  TokenFailures
	throttle  *ratelimit.Limiter
	logger    *slog.Logger
}

// NewHandler returns the /metrics and /status handlers. The access checks
// run in this order (OpenAPI getMetrics, threats T-191 to T-193):
//
//  1. Token unset: 404 not-found, as for an unknown path.
//  2. Client IP outside AllowedIPs (when set): 404 not-found.
//  3. Method other than GET and HEAD: 405 method-not-allowed.
//  4. Valid Bearer token: served, even from a locked-out IP.
//  5. Locked-out IP: 429 rate-limited with Retry-After and a throttled
//     rate_limited event (scope metrics_token), no new failure.
//  6. No Authorization header with the Bearer scheme: 401 unauthenticated
//     with a Bearer challenge (no event: nothing was guessed).
//  7. Wrong token: 401 invalid-credentials with an invalid_token challenge,
//     a metrics_token_invalid event and one failure of the IP.
//
// The token is read from the Authorization header only, never from the
// URL, and compared in constant time on the SHA-256 of both values.
// Answers are never cached.
func NewHandler(opts HandlerOptions) Handlers {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	g := &guard{
		enabled:   opts.Token.IsSet(),
		digest:    sha256.Sum256([]byte(opts.Token.Reveal())),
		allowed:   opts.AllowedIPs,
		collector: opts.Collector,
		events:    opts.Events,
		clientIP:  opts.ClientIP,
		failures:  opts.Failures,
		throttle:  ratelimit.New(rate.Every(middleware.SecurityEventInterval), 1, ratelimit.WithClock(now)),
		logger:    opts.Logger,
	}
	if g.clientIP == nil {
		g.clientIP = func(r *http.Request) netip.Addr { return middleware.ClientIP(r.Context()) }
	}
	if g.failures == nil {
		g.failures = ratelimit.NewWindow(TokenFailureLimit, TokenFailureWindow,
			ratelimit.WithLockout(TokenLockout), ratelimit.WithClock(now))
	}
	if g.logger == nil {
		g.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return Handlers{
		Metrics: g.wrap(serveMetrics),
		Status:  g.wrap(serveStatus),
	}
}

// body renders the answer of an endpoint from a snapshot and the counters:
// its content type and body, or an error.
type body func(s *snapshot, v countersView) (contentType string, b []byte, err error)

// serveMetrics renders /metrics.
func serveMetrics(s *snapshot, v countersView) (string, []byte, error) {
	var b bytes.Buffer
	renderMetrics(&b, s, v)
	return ContentType, b.Bytes(), nil
}

// marshalJSON encodes the /status answer, replaceable in tests.
var marshalJSON = json.Marshal

// serveStatus renders /status.
func serveStatus(s *snapshot, _ countersView) (string, []byte, error) {
	b, err := marshalJSON(buildStatus(s))
	return "application/json", b, err
}

// wrap returns the handler of an endpoint rendering with render.
func (g *guard) wrap(render body) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if !g.authorize(w, r) {
			return
		}
		ctx := r.Context()
		var s *snapshot
		if g.collector != nil {
			s = g.collector.snapshot()
		}
		if s == nil {
			g.logger.ErrorContext(ctx, "metrics: no snapshot to serve",
				slog.String("request_id", middleware.RequestID(ctx)))
			writeProblem(w, r, problem.New(problem.CodeInternalError))
			return
		}
		contentType, b, err := render(s, g.collector.counters.view())
		if err != nil {
			g.logger.ErrorContext(ctx, "metrics: failed to render the answer",
				slog.String("request_id", middleware.RequestID(ctx)),
				slog.String("error", err.Error()))
			writeProblem(w, r, problem.New(problem.CodeInternalError))
			return
		}
		h := w.Header()
		h.Set("Content-Type", contentType)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Content-Length", strconv.Itoa(len(b)))
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			_, _ = w.Write(b)
		}
	})
}

// authorize runs the access checks of NewHandler and writes the refusal;
// it returns true when the request may be served.
func (g *guard) authorize(w http.ResponseWriter, r *http.Request) bool {
	if !g.enabled {
		writeProblem(w, r, problem.New(problem.CodeNotFound))
		return false
	}
	ctx := r.Context()
	ip := g.clientIP(r)
	if len(g.allowed) > 0 && !g.isAllowed(ip) {
		writeProblem(w, r, problem.New(problem.CodeNotFound))
		return false
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeProblem(w, r, problem.New(problem.CodeMethodNotAllowed))
		return false
	}
	token, bearer := bearerToken(r)
	if bearer && g.valid(token) {
		return true
	}
	key := middleware.RateLimitKey(ip)
	if locked, retry := g.failures.Locked(key); locked {
		if ok, _ := g.throttle.Allow(key); ok && g.events != nil {
			g.events.RateLimited(ctx, ip, "", ScopeMetricsToken)
		}
		writeProblem(w, r, problem.New(problem.CodeRateLimited, problem.WithRetryAfter(retry)))
		return false
	}
	if !bearer {
		w.Header().Set("WWW-Authenticate", challengeBearer)
		writeProblem(w, r, problem.New(problem.CodeUnauthenticated))
		return false
	}
	if g.events != nil {
		g.events.MetricsTokenInvalid(ctx, ip)
	}
	g.failures.Fail(key)
	w.Header().Set("WWW-Authenticate", challengeInvalidToken)
	writeProblem(w, r, problem.New(problem.CodeInvalidCredentials))
	return false
}

// isAllowed reports whether ip belongs to one of the allowed networks. An
// IPv4-mapped IPv6 address is matched as IPv4.
func (g *guard) isAllowed(ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, p := range g.allowed {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// valid compares token with the configured one in constant time, on their
// SHA-256 so that the length does not leak either.
func (g *guard) valid(token string) bool {
	got := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(g.digest[:], got[:]) == 1
}

// bearerToken returns the token of the Authorization header and whether a
// header with the Bearer scheme is present. Several Authorization headers
// are ambiguous: the token is then empty (thus invalid).
func bearerToken(r *http.Request) (token string, bearer bool) {
	values := r.Header.Values("Authorization")
	for _, v := range values {
		scheme, _, _ := strings.Cut(v, " ")
		if strings.EqualFold(scheme, bearerScheme) {
			bearer = true
		}
	}
	if bearer && len(values) == 1 {
		_, token, _ = strings.Cut(values[0], " ")
		token = strings.TrimSpace(token)
	}
	return token, bearer
}

// writeProblem writes p with the request identifier as instance, like the
// problems of internal/httpserver.
func writeProblem(w http.ResponseWriter, r *http.Request, p *problem.Problem) {
	if id := middleware.RequestID(r.Context()); id != "" {
		p.Instance = id
	}
	problem.Write(w, p)
}
