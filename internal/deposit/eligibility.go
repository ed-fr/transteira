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
// (checked first) or domain, and returns ErrForbidden. It never accepts a
// depositor from outside: the actions reserved to the internal network
// (invitations, threat T-213) use it rather than [Service.checkDepositor].
func (s *Service) checkInternal(ctx context.Context, t *tenant.Tenant, ip netip.Addr, email string) error {
	v, err := s.evaluate(ctx, t, ip, email)
	if err != nil {
		return err
	}
	switch {
	case !v.IPOK:
		return s.refuse(ctx, t, ip, securitylog.ReasonIP)
	case !v.DomainOK:
		return s.refuse(ctx, t, ip, securitylog.ReasonDomain)
	}
	return nil
}

// checkDepositor returns the kind of a depositor without invitation (the
// caller checked the blocklist first):
//
//   - KindInternal when the internal rule holds (spec 6.2);
//   - KindInternalRemote when the client IP is outside the tenant ranges
//     but the domain of email is one of the tenant domains, the tenant
//     allows the deposit from outside (spec 6.4,
//     tenant.Tenant.AllowRemoteInternalDeposit) and email is a verified,
//     still active address whose internal verification is recorded.
//
// A depositor inside the ranges whose domain is not a tenant domain is
// refused (deposit_refused with reason domain, ErrForbidden). A depositor
// from outside who fails the remote rule, whatever the reason (foreign
// domain, address unknown, inactive or never verified internally), gets
// deposit_refused with reason ip and then:
//
//   - ErrForbidden when the tenant option is off: every outsider is refused
//     alike, which reveals nothing the public features.remoteInternalDeposit
//     flag does not already say;
//   - errDecoy when the option is on (threat T-215): the caller answers as
//     for an eligible depositor, with a decoy challenge whose code is never
//     sent (see [Service.Start] and [Service.Confirm]), so that the answer
//     does not tell which addresses are eligible and no genuine code mail
//     reaches the owner of a probed address.
//
// The verified address is read for every depositor from outside, whatever
// its domain and even when the option is off, so that the eligible and the
// decoy cases cost the same.
func (s *Service) checkDepositor(ctx context.Context, t *tenant.Tenant, ip netip.Addr, email string) (Kind, error) {
	v, err := s.evaluate(ctx, t, ip, email)
	if err != nil {
		return "", err
	}
	switch {
	case v.IPOK && v.DomainOK:
		return KindInternal, nil
	case v.IPOK:
		return "", s.refuse(ctx, t, ip, securitylog.ReasonDomain)
	}
	addr, active, err := s.verifiedAddress(ctx, t.ID, email)
	if err != nil {
		return "", err
	}
	if !v.DomainOK || !t.AllowRemoteInternalDeposit || !active || addr.InternalVerifiedAt.IsZero() {
		err := s.refuse(ctx, t, ip, securitylog.ReasonIP)
		if t.AllowRemoteInternalDeposit {
			return "", errDecoy
		}
		return "", err
	}
	return KindInternalRemote, nil
}

// evaluate applies the network rules of tenant t to ip and email.
func (s *Service) evaluate(ctx context.Context, t *tenant.Tenant, ip netip.Addr, email string) (netpolicy.Verdict, error) {
	rules, err := s.repo.networkRules(ctx, t.ID)
	if err != nil {
		return netpolicy.Verdict{}, fmt.Errorf("deposit: read network rules: %w", err)
	}
	return netpolicy.Evaluate(netpolicy.Rules{CIDRs: rules.CIDRs, Domains: rules.Domains}, ip, email), nil
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
