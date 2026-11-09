package secret

import (
	"context"
	"fmt"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/netpolicy"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/transfer"
)

// Directory reads the tenant data the service needs besides the secrets:
// the tenant itself (for the receipts of the lifecycle task), its
// recipient domain rules and its blocklist. [StoreDirectory] implements it.
type Directory interface {
	// Tenant returns the tenant tid.
	Tenant(ctx context.Context, tid tenant.ID) (*tenant.Tenant, error)
	// RecipientRules returns the recipient domain rules of tenant tid.
	RecipientRules(ctx context.Context, tid tenant.ID) (store.RecipientRuleSet, error)
	// Blocked reports whether the address email, or its domain, is on the
	// blocklist of tenant tid.
	Blocked(ctx context.Context, tid tenant.ID, email string) (bool, error)
}

// StoreDirectory is the [Directory] of a database.
type StoreDirectory struct {
	// DB is the database.
	DB *store.DB
}

// Tenant implements Directory.
func (d StoreDirectory) Tenant(ctx context.Context, tid tenant.ID) (*tenant.Tenant, error) {
	return d.DB.Tenants().Get(ctx, tid)
}

// RecipientRules implements Directory.
func (d StoreDirectory) RecipientRules(ctx context.Context, tid tenant.ID) (store.RecipientRuleSet, error) {
	return d.DB.RecipientRules().Get(ctx, tid)
}

// Blocked implements Directory.
func (d StoreDirectory) Blocked(ctx context.Context, tid tenant.ID, email string) (bool, error) {
	entries, err := d.DB.Blocklist().Match(ctx, tid, email, "")
	return len(entries) > 0, err
}

// Details of the refusal of a recipient.
const (
	// originInternal and originAPI name the creator in the details of the
	// refusal, with the values of the transfers.
	originInternal = "internal"
	originAPI      = "api"
	// reasonDomainRules and reasonBlocklist tell which rule refused the
	// recipient.
	reasonDomainRules = "domain-rules"
	reasonBlocklist   = "blocklist"
)

// checkRecipient applies to the recipient of an e-mail secret created by
// sender (normalized address email) the rules a transfer applies to its
// recipients (CLAUDE.md section 8.4, threat model T-340 and T-364): the
// blocklist of tenant t (address or domain), then its recipient domain
// rules. A refusal is ErrRecipientRefused (403 recipient-domain-refused,
// field /recipient domain-denied), audited as a transfer refusal
// (transfer.recipient_refused, object the tenant, with the refused domain
// only, details.object "secret" and details.reason) and never written to
// the security log: it is a policy refusal, not a sign of attack. The
// caller skips the imposed recipient of an invited external (its inviter),
// as a transfer does.
func (s *Service) checkRecipient(ctx context.Context, t *tenant.Tenant, sender transfer.Sender, email, recipient string) error {
	blocked, err := s.dir.Blocked(ctx, t.ID, recipient)
	if err != nil {
		return fmt.Errorf("secret: check recipient blocklist: %w", err)
	}
	domain, reason := domainOf(recipient), reasonBlocklist
	if !blocked {
		set, err := s.dir.RecipientRules(ctx, t.ID)
		if err != nil {
			return fmt.Errorf("secret: read recipient rules: %w", err)
		}
		if netpolicy.RecipientDomainAllowed(domain, set.Allowed, set.Denied) {
			return nil
		}
		reason = reasonDomainRules
	}
	if d, err := netpolicy.NormalizeDomain(domain); err == nil {
		domain = d
	}
	ev := audit.Event{
		ActorKind: store.ActorDepositor, Actor: email, IP: sender.ClientIP, Action: audit.ActionTransferRecipientRefused,
		ObjectKind: audit.ObjectTenant, ObjectID: t.ID.String(),
		Details: map[string]any{
			"domains": []string{domain}, "origin": originInternal, "object": audit.ObjectSecret, "reason": reason,
		},
	}
	if sender.APITokenID != "" {
		ev.ActorKind, ev.Actor, ev.Details["origin"] = store.ActorAPIToken, sender.APITokenID, originAPI
	}
	s.record(ctx, t, ev)
	return ErrRecipientRefused
}
