package deposit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/ed-fr/transteira/internal/i18n"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/netpolicy"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// DropLinkCodesFactor bounds the verification codes sent through one drop
// link in RateWindow: this factor times the hourly deposit cap of the link
// (threat model T-310). The codes are counted whatever their address or
// IP, so that rotating addresses cannot use a link to mail codes in bulk.
const DropLinkCodesFactor = 3

// PublicDropLink is what the landing page of a permanent drop link shows
// (OpenAPI PublicDropLink, since 2.0): never the recipients.
type PublicDropLink struct {
	// Label is the label of the link.
	Label string
	// ValidityDays is the lifetime of the transfers deposited through it.
	ValidityDays int
	// Level is the confidentiality level applied to these transfers (the
	// level of the link, else the default level of the tenant), nil when
	// the tenant has none.
	Level *DropLinkLevel
}

// DropLinkLevel is the confidentiality level of a drop link as the landing
// page shows it (OpenAPI ConfidentialityLevelRef).
type DropLinkLevel struct {
	// Key is the key of the level.
	Key string
	// Label is its label in the negotiated language.
	Label string
	// Rules are its current rules: the depositor follows them (for
	// example, a password required by the level).
	Rules store.ConfidentialityRules
}

// PublicDropLink returns what the landing page of the drop link token
// rawToken shows (OpenAPI getPublicDropLink), the level label in the
// language negotiated from acceptLanguage and the tenant default. A
// malformed token, an unknown one (including one of another tenant), and
// the token of a disabled, revoked or expired link all give the same
// ErrDropLinkInvalid, with a drop_link_invalid security event carrying
// clientIP and the tenant.
func (s *Service) PublicDropLink(ctx context.Context, t *tenant.Tenant, clientIP netip.Addr, acceptLanguage, rawToken string) (PublicDropLink, error) {
	l, err := s.dropLinkByToken(ctx, t, clientIP, rawToken)
	if err != nil {
		return PublicDropLink{}, err
	}
	out := PublicDropLink{Label: l.Label, ValidityDays: l.ValidityDays}
	levels, err := s.repo.levels(ctx, t.ID)
	if err != nil {
		return PublicDropLink{}, fmt.Errorf("deposit: read confidentiality levels: %w", err)
	}
	for _, lv := range levels {
		if (l.ConfidentialityLevel == "" && lv.IsDefault) || (l.ConfidentialityLevel != "" && lv.Key == l.ConfidentialityLevel) {
			lang := i18n.Negotiate(acceptLanguage, t.DefaultLanguage)
			out.Level = &DropLinkLevel{
				Key: lv.Key, Label: store.LevelLabel(lv.Labels, lang, t.DefaultLanguage, "en"), Rules: lv.Rules,
			}
			break
		}
	}
	return out, nil
}

// StartDropLink identifies a third party depositing through the permanent
// drop link rawToken of tenant t (OpenAPI startDepositSession with
// dropLinkToken, since 2.0), from clientIP, the real client IP; email and
// acceptLanguage are as for [Service.Start].
//
// The code is required at every use, whoever the depositor is: no
// recognition cookie is read or set, and the challenge records the link,
// so that [Service.Confirm] opens a session of kind KindDropLink bound to
// it after checking again that the link is usable. Checks, in order: the
// address syntax (*InvalidError); a client IP (ErrForbidden otherwise,
// deposit_refused with reason ip); the link (ErrDropLinkInvalid for a
// malformed, unknown, disabled, revoked or expired link, logged as
// drop_link_invalid); the blocklist (ErrForbidden, deposit_refused with
// reason blocklist); the hourly deposit cap of the link (*RateLimitError
// with the time until the window frees a slot, logged as rate_limited
// with scope drop_link), before any code is sent, so that a busy link
// cannot be used to mail codes to third parties. The code is then sent as
// for any depositor, with the same rate limits (*RateLimitError) and
// ErrMailUnavailable, plus a cap on the codes sent through the link in the
// last hour, all addresses and IPs together: DropLinkCodesFactor times its
// hourly deposit cap (*RateLimitError with RateWindow, logged as
// rate_limited with scope drop_link; threat model T-310), counted in the
// transaction that records the code. A link whose recipients are no longer
// all internal is refused like a disabled one (T-312).
func (s *Service) StartDropLink(ctx context.Context, t *tenant.Tenant, clientIP netip.Addr, acceptLanguage, email, rawToken string) (Challenge, error) {
	addr, err := parseEmail(email)
	if err != nil {
		return Challenge{}, err
	}
	if !clientIP.IsValid() {
		return Challenge{}, s.refuse(ctx, t, clientIP, securitylog.ReasonIP)
	}
	l, err := s.dropLinkByToken(ctx, t, clientIP, rawToken)
	if err != nil {
		return Challenge{}, err
	}
	if err := s.checkBlocklist(ctx, t, clientIP, addr.normalized); err != nil {
		return Challenge{}, err
	}
	now := s.now()
	u, err := s.repo.dropLinkUsage(ctx, t.ID, l.ID, now.Add(-store.DropLinkWindow))
	switch {
	case err != nil:
		return Challenge{}, fmt.Errorf("deposit: count drop link transfers: %w", err)
	case u.Full(l.MaxDepositsPerHour):
		s.logEvent(ctx, t, clientIP, securitylog.RateLimited,
			securitylog.Field{Key: securitylog.KeyScope, Value: scopeDropLink})
		return Challenge{}, &RateLimitError{RetryAfter: u.RetryAfter(now)}
	}
	return s.sendCode(ctx, t, clientIP, acceptLanguage, addr,
		codeBinding{dropLinkID: l.ID, maxDropLinkCodes: DropLinkCodesFactor * l.MaxDepositsPerHour}, false)
}

// dropLinkByToken returns the usable drop link of tenant t whose token is
// rawToken, or ErrDropLinkInvalid, logged as drop_link_invalid, for a
// malformed, unknown, disabled, revoked or expired one.
func (s *Service) dropLinkByToken(ctx context.Context, t *tenant.Tenant, clientIP netip.Addr, rawToken string) (store.DropLink, error) {
	if !id.DropTokenValid(rawToken) {
		return store.DropLink{}, s.invalidDropLink(ctx, t, clientIP)
	}
	now := s.now()
	l, err := s.repo.dropLinkByHash(ctx, t.ID, id.HashToken(rawToken), now)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return store.DropLink{}, s.invalidDropLink(ctx, t, clientIP)
	case err != nil:
		return store.DropLink{}, fmt.Errorf("deposit: read drop link: %w", err)
	case !l.Usable(now):
		// The store only returns usable links: kept as a safety net.
		return store.DropLink{}, s.invalidDropLink(ctx, t, clientIP)
	}
	return s.internalRecipients(ctx, t, clientIP, l)
}

// internalRecipients returns l when every recipient of the drop link l of
// tenant t still has an internal mail domain of t, read again at every use
// (threat model T-312): otherwise the link answers like a disabled one,
// ErrDropLinkInvalid logged as drop_link_invalid.
func (s *Service) internalRecipients(ctx context.Context, t *tenant.Tenant, clientIP netip.Addr, l store.DropLink) (store.DropLink, error) {
	rules, err := s.repo.networkRules(ctx, t.ID)
	if err != nil {
		return store.DropLink{}, fmt.Errorf("deposit: read network rules: %w", err)
	}
	if !netpolicy.AllDomainsInternal(netpolicy.Rules{Domains: rules.Domains}, l.Recipients) {
		return store.DropLink{}, s.invalidDropLink(ctx, t, clientIP)
	}
	return l, nil
}

// usableDropLink returns the drop link linkID of tenant t when it is still
// usable, or ErrDropLinkInvalid, logged as drop_link_invalid, when it is
// disabled, revoked, expired or gone.
func (s *Service) usableDropLink(ctx context.Context, t *tenant.Tenant, clientIP netip.Addr, linkID string) (store.DropLink, error) {
	l, err := s.repo.dropLink(ctx, t.ID, linkID)
	switch {
	case errors.Is(err, store.ErrNotFound) || (err == nil && !l.Usable(s.now())):
		return store.DropLink{}, s.invalidDropLink(ctx, t, clientIP)
	case err != nil:
		return store.DropLink{}, fmt.Errorf("deposit: read drop link: %w", err)
	}
	return s.internalRecipients(ctx, t, clientIP, l)
}

// invalidDropLink logs a drop_link_invalid event and returns
// ErrDropLinkInvalid.
func (s *Service) invalidDropLink(ctx context.Context, t *tenant.Tenant, clientIP netip.Addr) error {
	s.logEvent(ctx, t, clientIP, securitylog.DropLinkInvalid)
	return ErrDropLinkInvalid
}

// touchDropLink records the use of the drop link linkID, best effort: a
// failure is only reported on the application log.
func (s *Service) touchDropLink(ctx context.Context, t *tenant.Tenant, linkID string) {
	if err := s.repo.touchDropLink(context.WithoutCancel(ctx), t.ID, linkID, s.now()); err != nil {
		s.logger.ErrorContext(ctx, "deposit: recording the use of a drop link failed",
			slog.String("tenant", t.FQDN), slog.String("error", err.Error()))
	}
}
