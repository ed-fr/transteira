package tenantadmin

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/netpolicy"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Bounds of the network rules (OpenAPI NetworkRules).
const (
	// MaxInternalCIDRs bounds the internal IP ranges of a tenant.
	MaxInternalCIDRs = 500
	// MaxInternalDomains bounds the internal mail domains of a tenant.
	MaxInternalDomains = 100
)

// NetworkRules are the internal IP ranges and mail domains of a tenant
// (OpenAPI NetworkRules), normalized and sorted.
type NetworkRules struct {
	CIDRs   []string
	Domains []string
}

// rulesOf converts a stored rule set.
func rulesOf(set store.NetworkRuleSet) NetworkRules {
	out := NetworkRules{CIDRs: make([]string, len(set.CIDRs)), Domains: append([]string{}, set.Domains...)}
	for i, p := range set.CIDRs {
		out.CIDRs[i] = p.String()
	}
	return out
}

// GetNetworkRules returns the network rules of tenant tid.
func (s *Service) GetNetworkRules(ctx context.Context, p adminauth.Principal, tid tenant.ID) (NetworkRules, error) {
	if _, err := s.readable(ctx, p, tid); err != nil {
		return NetworkRules{}, err
	}
	set, err := s.repo.networkRules(ctx, tid)
	if err != nil {
		return NetworkRules{}, fmt.Errorf("tenantadmin: get network rules: %w", err)
	}
	return rulesOf(set), nil
}

// UpdateNetworkRules replaces the network rules of tenant tid atomically
// and returns them normalized. The ranges follow the rules of the
// installation configuration ([netpolicy.ParsePrefix]): a bare address is
// a single host, host bits must be zero, IPv6 zones are refused and
// IPv4-mapped prefixes become IPv4. Domains are lowercased host names (punycode for international
// ones). A malformed value is an *InvalidError naming its index, checked
// only once access to the tenant is granted.
func (s *Service) UpdateNetworkRules(ctx context.Context, p adminauth.Principal, tid tenant.ID, cidrs, domains []string, ip netip.Addr) (NetworkRules, error) {
	if _, err := s.writable(ctx, p, tid); err != nil {
		return NetworkRules{}, err
	}
	if len(cidrs) > MaxInternalCIDRs {
		return NetworkRules{}, invalid(FieldInternalCIDRs, "at most %d ranges", MaxInternalCIDRs)
	}
	if len(domains) > MaxInternalDomains {
		return NetworkRules{}, invalid(FieldInternalDomains, "at most %d domains", MaxInternalDomains)
	}
	prefixes := make([]netip.Prefix, len(cidrs))
	for i, raw := range cidrs {
		pfx, err := netpolicy.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			return NetworkRules{}, invalid(FieldInternalCIDRs+"/"+strconv.Itoa(i), "%v", err)
		}
		prefixes[i] = pfx
	}
	norm := make([]string, len(domains))
	for i, raw := range domains {
		d, err := normalizeDomain(raw)
		if err != nil {
			return NetworkRules{}, invalid(FieldInternalDomains+"/"+strconv.Itoa(i), "must be a mail domain")
		}
		norm[i] = d
	}
	set, err := s.repo.replaceNetworkRules(ctx, tid, prefixes, norm)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return NetworkRules{}, ErrNotFound
	case err != nil:
		return NetworkRules{}, fmt.Errorf("tenantadmin: replace network rules: %w", err)
	}
	out := rulesOf(set)
	s.record(ctx, p, ip, tid, ActionTenantNetworkUpdated, map[string]any{
		"cidrs": len(out.CIDRs), "domains": len(out.Domains),
	})
	return out, nil
}

// errDomainSyntax reports a malformed mail domain; it never quotes the
// value.
var errDomainSyntax = errors.New("not a mail domain")

// normalizeDomain validates a mail domain and returns it normalized.
func normalizeDomain(raw string) (string, error) {
	d := strings.TrimSpace(raw)
	if strings.ContainsAny(d, ":@/[] ") {
		return "", errDomainSyntax
	}
	return tenant.NormalizeHost(d)
}
