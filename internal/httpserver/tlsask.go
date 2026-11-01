package httpserver

import (
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"

	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/httpserver/middleware"
	"github.com/ed-fr/transteira/internal/metrics"
	"github.com/ed-fr/transteira/internal/tenant"
)

// maxTLSAskDomain is the longest domain /tls/ask looks up (a DNS name is
// at most 253 bytes, OpenAPI askTls).
const maxTLSAskDomain = 253

// relayHeaders are the headers a reverse proxy adds when it relays a
// client request (canonical form). The ask call of the proxy itself
// carries none of them; a configuration that strips X-Forwarded-For
// usually still sends one of the others.
var relayHeaders = []string{"X-Forwarded-For", "X-Real-Ip", "Forwarded", "X-Forwarded-Host", "X-Forwarded-Proto", "Via"}

// TLSAskCounter counts the answers of /tls/ask per result
// (*metrics.Counters implements it).
type TLSAskCounter interface {
	TLSAsk(result string)
}

// tlsAskHandler answers the permission asked by a reverse proxy before it
// obtains an on-demand certificate (OpenAPI askTls, threats T-277 to
// T-280, decision P53).
type tlsAskHandler struct {
	allowed    []netip.Prefix
	limiter    middleware.Limiter
	resolver   middleware.TenantResolver
	adminHosts hostSet
	counter    TLSAskCounter
	logger     *slog.Logger
}

// newTLSAskHandler returns the handler of TLSAskPath. allowed is
// TT_TLS_ASK_ALLOWED_IPS: empty, every request gets 404. limiter bounds
// the lookups per allowed peer (TLSAskRate and TLSAskBurst). counter may
// be nil.
func newTLSAskHandler(allowed []netip.Prefix, limiter middleware.Limiter, resolver middleware.TenantResolver, adminHosts hostSet, counter TLSAskCounter, logger *slog.Logger) http.Handler {
	return &tlsAskHandler{allowed: allowed, limiter: limiter, resolver: resolver, adminHosts: adminHosts, counter: counter, logger: logger}
}

// ServeHTTP answers 200 with an empty body when the domain query parameter
// is the FQDN of a tenant, whatever its setup state, and an identical 404
// otherwise. Before the domain is looked up, the request is refused with
// the same 404 when the endpoint is disabled, when the direct peer address
// (r.RemoteAddr, never X-Forwarded-For) is outside the allowed list, when
// a relay header is present (a public request relayed by the same proxy
// comes from an allowed address but always carries one), or for a method
// other than GET and HEAD. Nothing is written to the security log: unknown
// names come from certificate scanners and would flood it (T-279). The
// domain is resolved through the tenant resolver and its cache, so a
// deleted tenant gets 404 as soon as its cache entry is invalidated.
func (h *tlsAskHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	peer, ok := h.permitted(r)
	if !ok {
		h.answer(w, http.StatusNotFound, metrics.TLSAskRefused)
		return
	}
	// The request escapes the global per-IP limit, whose bucket for a
	// trusted proxy without X-Forwarded-For is shared by every such
	// request (the zero Addr): a flood of random server names could
	// otherwise empty it and refuse the ask of a new tenant. No security
	// event: banning the proxy would cut every site (T-279).
	if allowed, retry := h.limiter.Allow("tlsask:" + peer.String()); !allowed {
		writeProblem(w, r, problem.New(problem.CodeRateLimited, problem.WithRetryAfter(retry)))
		return
	}
	domain, ok := askedDomain(r)
	if !ok || h.adminHosts.match(domain) {
		h.answer(w, http.StatusNotFound, metrics.TLSAskUnknown)
		return
	}
	t, err := h.resolver.Resolve(r.Context(), domain)
	switch {
	case err == nil && t != nil:
		h.answer(w, http.StatusOK, metrics.TLSAskAllowed)
	case errors.Is(err, tenant.ErrUnknownTenant), errors.Is(err, tenant.ErrInvalidHost):
		h.answer(w, http.StatusNotFound, metrics.TLSAskUnknown)
	default:
		h.logger.ErrorContext(r.Context(), "tls ask: tenant resolution failed", "error", err)
		writeProblem(w, r, problem.New(problem.CodeInternalError))
	}
}

// permitted reports whether r may ask at all: endpoint enabled, direct
// peer in the allowed list, GET or HEAD, and no relay header. It returns
// the direct peer address.
func (h *tlsAskHandler) permitted(r *http.Request) (netip.Addr, bool) {
	if len(h.allowed) == 0 || (r.Method != http.MethodGet && r.Method != http.MethodHead) {
		return netip.Addr{}, false
	}
	for _, name := range relayHeaders {
		if _, present := r.Header[name]; present {
			return netip.Addr{}, false
		}
	}
	peer, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}, false
	}
	ip := peer.Addr().Unmap().WithZone("")
	for _, p := range h.allowed {
		if p.Contains(ip) {
			return ip, true
		}
	}
	return netip.Addr{}, false
}

// askedDomain returns the single domain query parameter of r. A missing,
// repeated, empty or too long value, or one with a port, is refused: the
// proxy sends the bare server name it is about to get a certificate for.
func askedDomain(r *http.Request) (string, bool) {
	values := r.URL.Query()["domain"]
	if len(values) != 1 {
		return "", false
	}
	d := values[0]
	if d == "" || len(d) > maxTLSAskDomain || strings.ContainsAny(d, ":[]") {
		return "", false
	}
	return d, true
}

// answer writes an empty response with status and counts it as result.
// Only 200 and 404 are counted: a database error (500 Problem) and the
// global rate limit (429 Problem) are not. 200 and 404 carry the same headers (Cache-Control: no-store, set by
// ServeHTTP, and the security headers of the common chain).
func (h *tlsAskHandler) answer(w http.ResponseWriter, status int, result string) {
	if h.counter != nil {
		h.counter.TLSAsk(result)
	}
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(status)
}
