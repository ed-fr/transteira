package tenantadmin

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/netpolicy"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// RecipientRules are the allowed and denied recipient domains of a tenant
// (OpenAPI RecipientRules), normalized and sorted.
type RecipientRules struct {
	Allowed []string
	Denied  []string
}

// recipientRulesOf converts a stored rule set, with empty lists rather
// than nil.
func recipientRulesOf(set store.RecipientRuleSet) RecipientRules {
	return RecipientRules{Allowed: append([]string{}, set.Allowed...), Denied: append([]string{}, set.Denied...)}
}

// GetRecipientRules returns the recipient domain rules of tenant tid.
func (s *Service) GetRecipientRules(ctx context.Context, p adminauth.Principal, tid tenant.ID) (RecipientRules, error) {
	if _, err := s.readable(ctx, p, tid); err != nil {
		return RecipientRules{}, err
	}
	set, err := s.repo.recipientRules(ctx, tid)
	if err != nil {
		return RecipientRules{}, fmt.Errorf("tenantadmin: get recipient rules: %w", err)
	}
	return recipientRulesOf(set), nil
}

// UpdateRecipientRules replaces the recipient domain rules of tenant tid
// atomically and returns them normalized (lower case, punycode, without
// trailing dot, sorted). Each list holds at most [store.MaxRecipientRules]
// domains, without duplicate once normalized. A malformed or repeated
// entry is an *InvalidError naming its index, checked only once access to
// the tenant is granted.
func (s *Service) UpdateRecipientRules(ctx context.Context, p adminauth.Principal, tid tenant.ID, allowed, denied []string, ip netip.Addr) (RecipientRules, error) {
	if _, err := s.writable(ctx, p, tid); err != nil {
		return RecipientRules{}, err
	}
	a, err := normalizeRecipientDomains(FieldAllowedDomains, allowed)
	if err != nil {
		return RecipientRules{}, err
	}
	d, err := normalizeRecipientDomains(FieldDeniedDomains, denied)
	if err != nil {
		return RecipientRules{}, err
	}
	set, err := s.repo.replaceRecipientRules(ctx, tid, store.RecipientRuleSet{Allowed: a, Denied: d}, s.now())
	switch {
	case errors.Is(err, store.ErrNotFound):
		return RecipientRules{}, ErrNotFound
	case errors.Is(err, store.ErrInvalid):
		// The checks above mirror the store's, so this cannot happen
		// unless they drift apart.
		return RecipientRules{}, invalid(FieldAllowedDomains, "invalid recipient rules")
	case err != nil:
		return RecipientRules{}, fmt.Errorf("tenantadmin: replace recipient rules: %w", err)
	}
	out := recipientRulesOf(set)
	s.record(ctx, p, ip, tid, ActionTenantRecipientRulesUpdated, map[string]any{
		"allowed": out.Allowed, "denied": out.Denied,
	})
	return out, nil
}

// normalizeRecipientDomains normalizes the domains of the list at pointer
// field.
func normalizeRecipientDomains(field string, domains []string) ([]string, error) {
	if len(domains) > store.MaxRecipientRules {
		return nil, invalid(field, "at most %d domains", store.MaxRecipientRules)
	}
	out := make([]string, len(domains))
	seen := make(map[string]bool, len(domains))
	for i, raw := range domains {
		at := field + "/" + strconv.Itoa(i)
		n, err := netpolicy.NormalizeDomain(raw)
		if err != nil {
			return nil, invalid(at, "must be a mail domain")
		}
		if seen[n] {
			return nil, invalid(at, "must not repeat a domain of the list")
		}
		seen[n] = true
		out[i] = n
	}
	return out, nil
}

// HasRecipientRules reports whether tenant t restricts the domains of the
// recipients, for the public configuration (OpenAPI
// TenantFeatures.recipientRestrictions); the domains are not disclosed.
func (s *Service) HasRecipientRules(ctx context.Context, t *tenant.Tenant) (bool, error) {
	set, err := s.repo.recipientRules(ctx, t.ID)
	if err != nil {
		return false, fmt.Errorf("tenantadmin: get recipient rules: %w", err)
	}
	return len(set.Allowed)+len(set.Denied) > 0, nil
}
