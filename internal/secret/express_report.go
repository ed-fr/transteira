package secret

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"time"
	"unicode/utf8"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/textsafe"
)

// Abuse reports on the express secrets (since 2.3, threat model T-407),
// with the limits and the security log scopes of the transfer reports.
const (
	// MaxReportMessageRunes bounds the message of an abuse report, in
	// characters, after sanitizing (OpenAPI AbuseReportCreate.message).
	MaxReportMessageRunes = store.MaxAbuseReportTextLen
	// ScopeReportsPerLink is the rate_limited scope of the reports on one
	// secret (3 per day), as for one transfer link; the event carries the
	// truncated "sec_" identifier in its transfer field.
	ScopeReportsPerLink = "abuse_report_link"
	// ScopeReportsPerIP is the rate_limited scope of the reports of one
	// client IP (5 per hour), shared with the transfer reports.
	ScopeReportsPerIP = "abuse_report_ip"
	// keyTransfer is the security log field of the truncated identifier
	// of the reported object, and objectIDLogLen its length: the prefix
	// and the time part of the ULID, enough to correlate with the audit.
	keyTransfer    = "transfer"
	objectIDLogLen = 14
)

// errNoAbuseReports reports a Service built without Options.AbuseReports:
// a wiring error, answered 500.
var errNoAbuseReports = errors.New("secret: no abuse report store")

// AbuseReportStore stores the abuse reports. *store.AbuseReports
// implements it ([store.AbuseReports.Create]).
type AbuseReportStore interface {
	Create(ctx context.Context, tid tenant.ID, rep store.AbuseReport, limits store.AbuseReportLimits, now time.Time) (store.AbuseReport, error)
}

// AbuseNotifier alerts the administrators of a tenant of a new abuse
// report on an express secret (mail and webhooks, naming the "sec_"
// identifier only). It is best effort, must not block, and records no
// audit event.
type AbuseNotifier interface {
	SecretAbuseReported(ctx context.Context, t *tenant.Tenant, r store.AbuseReport)
}

// noAbuseNotifier is the AbuseNotifier of a Service without
// Options.AbuseNotifier.
type noAbuseNotifier struct{}

func (noAbuseNotifier) SecretAbuseReported(context.Context, *tenant.Tenant, store.AbuseReport) {}

// AbuseReportRequest is the body of a report (OpenAPI AbuseReportCreate).
type AbuseReportRequest struct {
	// Category is an OpenAPI AbuseReportCategory.
	Category string
	// Message is the optional plain-text message of the reporter.
	Message string
}

// ReportAbuse records, for the client ip, an abuse report on the express
// secret of tenant t whose link carries token (reportSecretAbuse, since
// 2.3, threat model T-407). It is not blocked by a closed express service
// (kill switch or anonymous mode off): reporting stays possible when the
// administrators closed the service in reaction to an abuse. In order:
//
//   - the limits of the client on the secret links (*RateLimitError,
//     rate_limited of scope secret_link_ip or secret_link);
//   - an unknown token: ErrNotFound with secret_invalid and a failure of
//     the client; the token of a 2.1 secret (not express, pending
//     included): ErrNotFound alone (the token is real);
//   - an express secret that is neither active nor read: a *GoneError
//     with its reason (an active one past its expiry is expired);
//   - the body: a *ValidationError on FieldCategory (unknown category) or
//     FieldMessage (not UTF-8, or longer than MaxReportMessageRunes
//     characters once sanitized with textsafe.SanitizeMessage);
//   - the reports of the client on the express secrets of the tenant in
//     the sliding last hour, counted in memory per client key (IPv4
//     address or IPv6 /64, Options.ReportsPerIP): beyond
//     store.DefaultAbuseReportsPerIP, a *RateLimitError written as
//     rate_limited (scope ScopeReportsPerIP), so that rotating addresses
//     within a /64 does not multiply the alerts (threat model T-407); a
//     new client refused because the limiter of the tenant is saturated
//     gets a *RateLimitError without security event (not its fault);
//   - the store, which counts the reports on the secret over the last day
//     (3) and those of the exact client IP over the last hour (5, transfer
//     reports included): a *RateLimitError written as rate_limited (scope
//     ScopeReportsPerLink with the truncated "sec_" identifier, or
//     ScopeReportsPerIP).
//
// The report names the secret, never its token nor its content; it has no
// sender and an unverified reporter. It is audited as abuse.reported
// (details.secretId, the actor being the link, as for a transfer
// report), then the administrators are alerted through
// Options.AbuseNotifier, detached from the cancellation of ctx. Nothing
// happens to the secret.
func (s *Service) ReportAbuse(ctx context.Context, t *tenant.Tenant, ip netip.Addr, token string, req AbuseReportRequest) error {
	key, err := s.admit(ctx, t, ip)
	if err != nil {
		return err
	}
	now := s.now()
	sec, err := s.repo.LookupByToken(ctx, t.ID, token)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return s.unknown(ctx, t, ip, key, err)
	case err != nil:
		return fmt.Errorf("secret: report abuse: %w", err)
	case !sec.Express:
		return ErrNotFound
	case sec.State == store.SecretActive && !now.Before(sec.ExpiresAt):
		return &GoneError{Reason: ReasonExpired}
	case sec.State != store.SecretActive && sec.State != store.SecretRead:
		return &GoneError{Reason: APIReason(sec.EndReason)}
	}
	cat, message, err := checkReport(req)
	if err != nil {
		return err
	}
	if s.reports == nil {
		return errNoAbuseReports
	}
	switch ok, retry, saturated := s.reportsPerIP.Allow(string(t.ID), key, store.DefaultAbuseReportsPerIP); {
	case saturated:
		s.logger.WarnContext(ctx, "abuse report refused: the per-client limiter of the tenant is saturated",
			slog.String("tenant", string(t.ID)))
		return &RateLimitError{RetryAfter: retry}
	case !ok:
		s.throttledEvent(ctx, t, ip, key, securitylog.RateLimited, securitylog.KeyScope, ScopeReportsPerIP)
		return &RateLimitError{RetryAfter: retry}
	}
	stored, err := s.reports.Create(ctx, t.ID, store.AbuseReport{
		SecretID: sec.ID, ReporterIP: ip, Category: cat, Message: message,
	}, store.DefaultAbuseReportLimits(), now)
	switch {
	case errors.Is(err, store.ErrAbuseReportLinkLimit):
		s.throttledEvent(ctx, t, ip, key, securitylog.RateLimited, securitylog.KeyScope, ScopeReportsPerLink,
			securitylog.Field{Key: keyTransfer, Value: sec.ID[:min(len(sec.ID), objectIDLogLen)]})
		return &RateLimitError{RetryAfter: store.AbuseReportLinkWindow}
	case errors.Is(err, store.ErrAbuseReportIPLimit):
		s.throttledEvent(ctx, t, ip, key, securitylog.RateLimited, securitylog.KeyScope, ScopeReportsPerIP)
		return &RateLimitError{RetryAfter: store.AbuseReportIPWindow}
	case errors.Is(err, store.ErrNotFound):
		// The tombstone was purged or the tenant deletion started since
		// the lookup.
		return ErrNotFound
	case err != nil:
		return fmt.Errorf("secret: record abuse report: %w", err)
	}
	s.record(ctx, t, audit.Event{
		ActorKind: store.ActorRecipient, Actor: linkActor, IP: ip, Action: audit.ActionAbuseReported,
		ObjectKind: audit.ObjectAbuseReport, ObjectID: stored.ID,
		Details: map[string]any{"secretId": sec.ID, "category": string(cat), "verified": false},
	})
	s.reportAlerts.SecretAbuseReported(context.WithoutCancel(ctx), t, stored)
	return nil
}

// checkReport validates the body of a report and returns its category and
// its sanitized message.
func checkReport(req AbuseReportRequest) (store.AbuseCategory, string, error) {
	var v validator
	cat := store.AbuseCategory(req.Category)
	switch {
	case cat == "":
		v.add(FieldCategory, CodeRequired)
	case !cat.Valid():
		v.add(FieldCategory, CodeInvalidFormat)
	}
	message := req.Message
	if !utf8.ValidString(message) {
		v.add(FieldMessage, CodeInvalidFormat)
	} else if message = textsafe.SanitizeMessage(message); utf8.RuneCountInString(message) > MaxReportMessageRunes {
		v.add(FieldMessage, CodeTooLong)
	}
	if len(v.errs) > 0 {
		return "", "", &ValidationError{Fields: v.errs}
	}
	return cat, message, nil
}
