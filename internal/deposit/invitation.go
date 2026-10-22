package deposit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"time"
	"unicode/utf8"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/i18n"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/textsafe"
)

// InvitationStatus is the state of an invitation (OpenAPI InvitationStatus).
type InvitationStatus string

// InvitationPending is the status of a new invitation.
const InvitationPending InvitationStatus = "pending"

// Invitation is a newly created invitation (OpenAPI Invitation).
type Invitation struct {
	// ID is the invitation record ("inv_" + ULID), distinct from the link
	// token, which only the invited person receives.
	ID string
	// Email is the invited address, normalized.
	Email string
	// InvitedBy is the address of the inviter, normalized.
	InvitedBy string
	// Status is InvitationPending.
	Status InvitationStatus
	// Language is the language of the invitation mail.
	Language string
	// CreatedAt is the creation time.
	CreatedAt time.Time
	// ExpiresAt is when the unused invitation expires.
	ExpiresAt time.Time
}

// PublicInvitation is what the invitation landing page shows (OpenAPI
// PublicInvitation).
type PublicInvitation struct {
	// Email is the invited address.
	Email string
	// InvitedBy is the address of the inviter.
	InvitedBy string
	// Message is the message of the inviter, "" for none.
	Message string
	// ExpiresAt is the end of validity of the invitation.
	ExpiresAt time.Time
}

// Invite lets the internal depositor of session invite email to deposit
// files for them (OpenAPI createInvitation), from clientIP. The invitation
// mail is written in language when given, otherwise in the language
// negotiated from acceptLanguage and the tenant default. message is an
// optional text for the invited person: its hidden characters (control
// characters except line feed and tab, line separators, format and
// invisible characters) are removed (textsafe.SanitizeMessage), then it
// must hold at most
// MaxMessageRunes characters.
//
// Checks, in order: the session is internal; the address, message and
// language are well formed; neither the inviter nor the invited address
// (nor their domains) is blocklisted; the inviter still satisfies the
// internal rule from clientIP; the inviter issued fewer than
// MaxInvitationsPerInviter invitations in the tenant over the last
// RateWindow (counted in the transaction that creates the invitation).
// The mail is prepared before the transaction (a tenant without SMTP
// settings gets ErrMailUnavailable with nothing written) and queued after
// the commit; when the queue refuses it, the invitation is deleted, best
// effort, so that it does not count against the inviter limit.
//
// Errors: ErrForbidden when the session is not internal, when the inviter
// is blocklisted or no longer satisfies the network rule, and when the
// invited address is blocklisted; *InvalidError (ErrInvalid) for a malformed
// address, message or language; *RateLimitError (ErrRateLimited) when the
// inviter is over the limit or the mail queue is full; ErrMailUnavailable
// when the tenant cannot send mail.
func (s *Service) Invite(ctx context.Context, t *tenant.Tenant, session SessionInfo, clientIP netip.Addr, acceptLanguage, email, message, language string) (Invitation, error) {
	if session.Kind != KindInternal {
		return Invitation{}, ErrForbidden
	}
	addr, err := parseEmail(email)
	if err != nil {
		return Invitation{}, err
	}
	if !utf8.ValidString(message) {
		return Invitation{}, invalid(FieldMessage)
	}
	if message = textsafe.SanitizeMessage(message); utf8.RuneCountInString(message) > MaxMessageRunes {
		return Invitation{}, invalid(FieldMessage)
	}
	if language == "" {
		language = i18n.Negotiate(acceptLanguage, t.DefaultLanguage)
	} else if !i18n.IsSupported(language) {
		return Invitation{}, invalid(FieldLanguage)
	}
	if err := s.checkBlocklist(ctx, t, clientIP, session.Email); err != nil {
		return Invitation{}, err
	}
	if err := s.checkBlocklist(ctx, t, clientIP, addr.normalized); err != nil {
		return Invitation{}, err
	}
	if err := s.checkInternal(ctx, t, clientIP, session.Email); err != nil {
		return Invitation{}, err
	}

	token, err := s.newToken(id.InvitationTokenPrefix, id.InvitationTokenBytes)
	if err != nil {
		return Invitation{}, fmt.Errorf("deposit: new invitation token: %w", err)
	}
	invID, err := s.newID(id.Invitation)
	if err != nil {
		return Invitation{}, fmt.Errorf("deposit: new invitation id: %w", err)
	}
	now := s.now()
	rec := store.Invitation{
		ID: invID, TokenHash: tokenHash(token), Email: addr.normalized, InvitedBy: session.Email,
		Message: message, Language: language, CreatedAt: now, ExpiresAt: store.InvitationExpiry(now),
	}
	job, err := s.prepareMail(ctx, t, mail.TemplateInvitation, language, addr.mailbox, mail.InvitationData{
		TenantName: t.Name, InviterEmail: session.Email, Message: message,
		Link: invitationLink(t, token), ExpiresAt: rec.ExpiresAt,
	})
	if err != nil {
		return Invitation{}, err
	}
	err = s.repo.tx(ctx, t.ID, func(tx txRepo) error {
		n, err := tx.countInvitations(ctx, session.Email, now.Add(-RateWindow))
		if err != nil {
			return fmt.Errorf("deposit: count invitations: %w", err)
		}
		if n >= MaxInvitationsPerInviter {
			return errLimited
		}
		if err := tx.createInvitation(ctx, rec); err != nil {
			return fmt.Errorf("deposit: create invitation: %w", err)
		}
		return nil
	})
	if errors.Is(err, errLimited) {
		s.logEvent(ctx, t, clientIP, securitylog.RateLimited, securitylog.Field{Key: securitylog.KeyScope, Value: scopeInvitations})
		return Invitation{}, &RateLimitError{RetryAfter: RateWindow}
	}
	if err != nil {
		return Invitation{}, err
	}
	if err := s.enqueue(job); err != nil {
		if rerr := s.repo.deleteInvitation(context.WithoutCancel(ctx), t.ID, rec.ID); rerr != nil {
			s.logger.ErrorContext(ctx, "deposit: deleting an unsent invitation failed",
				slog.String("tenant", t.FQDN), slog.String("error", rerr.Error()))
		}
		return Invitation{}, err
	}
	s.record(ctx, t, clientIP, session.Email, audit.ActionInvitationCreated, audit.ObjectInvitation, rec.ID,
		map[string]any{"language": rec.Language})
	return Invitation{
		ID: rec.ID, Email: rec.Email, InvitedBy: rec.InvitedBy, Status: InvitationPending,
		Language: rec.Language, CreatedAt: rec.CreatedAt, ExpiresAt: rec.ExpiresAt,
	}, nil
}

// invitationLink returns the absolute invitation URL, built from the FQDN
// registered for the tenant and never from the request Host (threat T-03).
func invitationLink(t *tenant.Tenant, token string) string {
	return "https://" + t.FQDN + InvitationPath + token
}

// PublicInvitation returns what the landing page of the invitation link
// token rawToken shows (OpenAPI getInvitation). It returns ErrNotFound for
// a malformed or unknown token (including one of another tenant) and
// ErrInvitationGone for an expired or revoked invitation.
func (s *Service) PublicInvitation(ctx context.Context, t *tenant.Tenant, rawToken string) (PublicInvitation, error) {
	if !validToken(id.InvitationTokenPrefix, rawToken) {
		return PublicInvitation{}, ErrNotFound
	}
	inv, err := s.repo.invitationByHash(ctx, t.ID, tokenHash(rawToken))
	switch {
	case errors.Is(err, store.ErrNotFound):
		return PublicInvitation{}, ErrNotFound
	case err != nil:
		return PublicInvitation{}, fmt.Errorf("deposit: read invitation: %w", err)
	case !inv.Active(s.now()):
		return PublicInvitation{}, ErrInvitationGone
	}
	return PublicInvitation{Email: inv.Email, InvitedBy: inv.InvitedBy, Message: inv.Message, ExpiresAt: inv.ExpiresAt}, nil
}
