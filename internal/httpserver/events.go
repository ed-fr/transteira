package httpserver

import (
	"context"
	"log/slog"
	"net/netip"

	"github.com/ed-fr/transteira/internal/httpserver/middleware"
	"github.com/ed-fr/transteira/internal/securitylog"
)

// SecurityEvents writes the events raised by the middlewares to the
// security log consumed by fail2ban and CrowdSec. It implements
// middleware.SecurityEvents.
type SecurityEvents struct {
	log    *securitylog.Logger
	logger *slog.Logger
}

// Compile-time check of the middleware interface.
var _ middleware.SecurityEvents = (*SecurityEvents)(nil)

// NewSecurityEvents returns an adapter writing to log. Write failures are
// reported on logger (nil discards): a security event must never fail the
// request.
func NewSecurityEvents(log *securitylog.Logger, logger *slog.Logger) *SecurityEvents {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &SecurityEvents{log: log, logger: logger}
}

// UnknownFQDN records an unknown_fqdn event with the offending host.
func (s *SecurityEvents) UnknownFQDN(ctx context.Context, ip netip.Addr, host string) {
	s.write(ctx, securitylog.Event{
		Type:   securitylog.UnknownFQDN,
		IP:     ip,
		Fields: []securitylog.Field{{Key: securitylog.KeyHost, Value: host}},
	})
}

// RateLimited records a rate_limited event with the limiter scope.
func (s *SecurityEvents) RateLimited(ctx context.Context, ip netip.Addr, tenantFQDN, scope string) {
	s.write(ctx, securitylog.Event{
		Type:   securitylog.RateLimited,
		IP:     ip,
		Tenant: tenantFQDN,
		Fields: []securitylog.Field{{Key: securitylog.KeyScope, Value: scope}},
	})
}

// APITokenInvalid records an api_token_invalid event: an empty,
// malformed, unknown, revoked or expired API token. The token itself is
// never written.
func (s *SecurityEvents) APITokenInvalid(ctx context.Context, ip netip.Addr, tenantFQDN string) {
	s.write(ctx, securitylog.Event{Type: securitylog.APITokenInvalid, IP: ip, Tenant: tenantFQDN})
}

// MetricsTokenInvalid records a metrics_token_invalid event: a wrong
// monitoring token on /metrics or /status, outside any tenant. The token
// itself is never written.
func (s *SecurityEvents) MetricsTokenInvalid(ctx context.Context, ip netip.Addr) {
	s.write(ctx, securitylog.Event{Type: securitylog.MetricsTokenInvalid, IP: ip})
}

// DepositRefused records a deposit_refused event with its reason (one of
// the securitylog Reason* deposit values).
func (s *SecurityEvents) DepositRefused(ctx context.Context, ip netip.Addr, tenantFQDN, reason string) {
	s.write(ctx, securitylog.Event{
		Type:   securitylog.DepositRefused,
		IP:     ip,
		Tenant: tenantFQDN,
		Fields: []securitylog.Field{{Key: securitylog.KeyReason, Value: reason}},
	})
}

func (s *SecurityEvents) write(ctx context.Context, ev securitylog.Event) {
	if err := s.log.Log(ev); err != nil {
		s.logger.ErrorContext(ctx, "security log write failed",
			slog.String("event", string(ev.Type)),
			slog.String("request_id", middleware.RequestID(ctx)),
			slog.String("error", err.Error()))
	}
}
