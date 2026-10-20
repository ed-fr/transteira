package deposit

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/netpolicy"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// address is a validated mail address in its two forms.
type address struct {
	// mailbox is the form mail is sent to (domain lowercased).
	mailbox string
	// normalized is the form the store keeps and compares (lowercase).
	normalized string
}

// parseEmail validates a mail address with the restricted syntax of
// mail.ParseAddress, then normalizes it like the store. It returns an
// *InvalidError on FieldEmail otherwise. Both checks run because each one
// refuses what the other accepts: mail.ParseAddress refuses what cannot be
// written safely in a header or an SMTP command, store.NormalizeEmail what
// the store cannot keep (IP literals, numeric top-level labels, malformed
// punycode).
func parseEmail(raw string) (address, error) {
	mailbox, err := mail.ParseAddress(strings.TrimSpace(raw))
	if err != nil {
		return address{}, invalid(FieldEmail)
	}
	normalized, err := store.NormalizeEmail(mailbox)
	if err != nil {
		return address{}, invalid(FieldEmail)
	}
	return address{mailbox: mailbox, normalized: normalized}, nil
}

// checkBlocklist refuses an address (or its domain) on the tenant
// blocklist, logging a deposit_refused event.
func (s *Service) checkBlocklist(ctx context.Context, t *tenant.Tenant, ip netip.Addr, email string) error {
	blocked, err := s.repo.blocked(ctx, t.ID, email)
	if err != nil {
		return fmt.Errorf("deposit: check blocklist: %w", err)
	}
	if blocked {
		return s.refuse(ctx, t, ip, securitylog.ReasonBlocklist)
	}
	return nil
}

// checkInternal applies the internal rule (spec 6.2, package netpolicy):
// ip in one of the tenant CIDR ranges and the domain of email among the
// tenant domains. A failure is logged as deposit_refused with reason ip
// (checked first) or domain, and returns ErrForbidden.
func (s *Service) checkInternal(ctx context.Context, t *tenant.Tenant, ip netip.Addr, email string) error {
	rules, err := s.repo.networkRules(ctx, t.ID)
	if err != nil {
		return fmt.Errorf("deposit: read network rules: %w", err)
	}
	v := netpolicy.Evaluate(netpolicy.Rules{CIDRs: rules.CIDRs, Domains: rules.Domains}, ip, email)
	switch {
	case !v.IPOK:
		return s.refuse(ctx, t, ip, securitylog.ReasonIP)
	case !v.DomainOK:
		return s.refuse(ctx, t, ip, securitylog.ReasonDomain)
	}
	return nil
}

// checkInvitation returns the invitation whose link token is rawToken,
// provided it is active and invites email. An unknown or malformed token
// and an address mismatch give ErrForbidden; an expired or revoked
// invitation gives ErrInvitationGone. Every refusal is logged with reason
// invitation.
func (s *Service) checkInvitation(ctx context.Context, t *tenant.Tenant, ip netip.Addr, rawToken, email string) (store.Invitation, error) {
	if !validToken(id.InvitationTokenPrefix, rawToken) {
		return store.Invitation{}, s.refuse(ctx, t, ip, securitylog.ReasonInvitation)
	}
	inv, err := s.repo.invitationByHash(ctx, t.ID, tokenHash(rawToken))
	switch {
	case errors.Is(err, store.ErrNotFound):
		return store.Invitation{}, s.refuse(ctx, t, ip, securitylog.ReasonInvitation)
	case err != nil:
		return store.Invitation{}, fmt.Errorf("deposit: read invitation: %w", err)
	case !inv.Active(s.now()):
		_ = s.refuse(ctx, t, ip, securitylog.ReasonInvitation)
		return store.Invitation{}, ErrInvitationGone
	case inv.Email != email:
		return store.Invitation{}, s.refuse(ctx, t, ip, securitylog.ReasonInvitation)
	}
	return inv, nil
}

// activeInvitation returns the invitation invID when it is still active,
// ErrInvitationGone when it is expired, revoked or deleted.
func (s *Service) activeInvitation(ctx context.Context, tid tenant.ID, invID string) (store.Invitation, error) {
	inv, err := s.repo.invitation(ctx, tid, invID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return store.Invitation{}, ErrInvitationGone
	case err != nil:
		return store.Invitation{}, fmt.Errorf("deposit: read invitation: %w", err)
	case !inv.Active(s.now()):
		return store.Invitation{}, ErrInvitationGone
	}
	return inv, nil
}
