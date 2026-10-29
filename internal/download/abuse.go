package download

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"unicode/utf8"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/textsafe"
)

// Abuse reports (spec 10, threat model T-220, decision P36).
const (
	// MaxReportMessageRunes bounds the message of an abuse report, in
	// characters, after sanitizing (OpenAPI AbuseReportCreate.message).
	MaxReportMessageRunes = store.MaxAbuseReportTextLen
	// scopeReportsPerLink names the budget of abuse reports per link in the
	// rate_limited events.
	scopeReportsPerLink = "abuse_report_link"
	// scopeReportsPerIP names the budget of abuse reports per client IP in
	// the rate_limited events.
	scopeReportsPerIP = "abuse_report_ip"
)

// AbuseAlerter alerts the administrators of a tenant of a new abuse
// report. *abuse.Detector implements it.
type AbuseAlerter interface {
	// Reported alerts the delegated admins of the stored report r (mail
	// and webhooks). It is best effort and records no audit event.
	Reported(ctx context.Context, t *tenant.Tenant, r store.AbuseReport)
}

// ReportAbuse records an abuse report on the transfer of the download
// token rawToken of tenant t (reportAbuse), filed from the client IP
// clientIP. category is an OpenAPI AbuseReportCategory; message is the
// optional plain-text message of the reporter. verificationCookie is the
// raw value of the VerificationCookieName cookie, "" when absent.
//
// Any known link of an available transfer may report, whatever its
// password or recipient verification: no unlock nor verification is
// needed, and a transfer whose download limit is reached stays reportable.
// The reporter address is recorded (reporterVerified) only when the
// verification cookie holds a valid entry of this very recipient link;
// otherwise the report only names the link and the position of its
// recipient, or neither for a shared V1 link. The message is cleaned with
// textsafe.SanitizeMessage (control, invisible and bidirectional
// characters removed).
//
// The report, the sender snapshot and the abuse.reported audit event are
// written in one transaction, which first counts the reports of the link
// over the last day and those of the client IP over the last hour
// (store.DefaultAbuseReportLimits). The administrators are then alerted
// through Options.Abuse, detached from the cancellation of ctx. Nothing
// happens to the transfer, and its sender is never told (P36).
//
// Errors: ErrNoClientIP for an invalid clientIP; ErrNotFound and ErrGone
// as Resolve does; ErrInvalidCategory for an unknown category;
// ErrInvalidMessage for a message that is not UTF-8 or longer than
// MaxReportMessageRunes characters once sanitized; a *RateLimitError
// (ErrRateLimited) over a budget, written to the security log as
// rate_limited with scope abuse_report_link or abuse_report_ip.
func (s *Service) ReportAbuse(ctx context.Context, t *tenant.Tenant, rawToken string, clientIP netip.Addr, verificationCookie, category, message string) error {
	if !clientIP.IsValid() {
		return ErrNoClientIP
	}
	a, err := s.resolve(ctx, t, rawToken, Cookies{Verification: verificationCookie}, false)
	if err != nil {
		return err
	}
	cat := store.AbuseCategory(category)
	if !cat.Valid() {
		return ErrInvalidCategory
	}
	if !utf8.ValidString(message) {
		return ErrInvalidMessage
	}
	if message = textsafe.SanitizeMessage(message); utf8.RuneCountInString(message) > MaxReportMessageRunes {
		return ErrInvalidMessage
	}
	now := s.now()
	r := store.AbuseReport{
		ID: id.New(id.AbuseReport), TransferID: a.d.ID, SenderEmail: a.d.SenderEmail,
		ReporterIP: clientIP, Category: cat, Message: message,
	}
	if a.link != nil {
		pos := a.link.Position
		r.RecipientLinkID, r.RecipientPosition = a.link.ID, &pos
		// Any recipient link may hold a verification, with or without the
		// option of the transfer (a reply verifies the recipient too).
		verified := a.verified
		if !a.verify {
			if verified, err = s.holds(verificationSpec, verificationCookie, t.ID, a.link.ID, now); err != nil {
				return err
			}
		}
		if verified {
			r.ReporterEmail, r.ReporterVerified = a.link.Email, true
		}
	}
	ev := reportEvent(r, a.link)
	stored, err := s.repo.report(ctx, t.ID, r, store.DefaultAbuseReportLimits(), now, ev)
	switch {
	case errors.Is(err, store.ErrAbuseReportLinkLimit):
		s.logEvent(ctx, t, clientIP, a.d.ID, securitylog.RateLimited, securitylog.Field{Key: securitylog.KeyScope, Value: scopeReportsPerLink})
		return &RateLimitError{RetryAfter: store.AbuseReportLinkWindow}
	case errors.Is(err, store.ErrAbuseReportIPLimit):
		s.logEvent(ctx, t, clientIP, a.d.ID, securitylog.RateLimited, securitylog.Field{Key: securitylog.KeyScope, Value: scopeReportsPerIP})
		return &RateLimitError{RetryAfter: store.AbuseReportIPWindow}
	case err != nil:
		return fmt.Errorf("download: record abuse report: %w", err)
	}
	if s.opts.Abuse != nil {
		s.opts.Abuse.Reported(context.WithoutCancel(ctx), t, stored)
	}
	return nil
}

// reportEvent is the abuse.reported audit event of the report r filed
// through the recipient link l (nil for a shared link): the verified
// reporter names themself, any other reporter is the link, as for a
// download. It never holds the message.
func reportEvent(r store.AbuseReport, l *store.RecipientLink) audit.Event {
	actor := linkActor
	if r.ReporterVerified {
		actor = r.ReporterEmail
	}
	details := map[string]any{"transferId": r.TransferID, "category": string(r.Category), "verified": r.ReporterVerified}
	if l != nil {
		details["link"] = l.ID
	}
	return audit.Event{
		ActorKind: store.ActorRecipient, Actor: actor, IP: r.ReporterIP,
		Action: audit.ActionAbuseReported, ObjectKind: audit.ObjectAbuseReport, ObjectID: r.ID,
		Details: details,
	}
}
