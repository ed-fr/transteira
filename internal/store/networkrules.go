package store

import (
	"context"
	"database/sql"
	"net/netip"
	"slices"
	"strings"

	"github.com/ed-fr/transteira/internal/tenant"
)

// MaxNetworkRules bounds the number of CIDR ranges, and separately of
// domains, of one tenant.
const MaxNetworkRules = 1000

// Network rule kinds, as stored in tenant_network_rules.kind.
const (
	ruleKindCIDR   = "cidr"
	ruleKindDomain = "domain"
)

// Statements of the NetworkRules repository.
var (
	qRulesList = tenantQuery(
		`SELECT kind, value FROM tenant_network_rules WHERE tenant_id = ?`)
	qRulesDelete = tenantQuery(
		`DELETE FROM tenant_network_rules WHERE tenant_id = ?`)
	qRuleInsert = tenantQuery(
		`INSERT INTO tenant_network_rules (tenant_id, kind, value) VALUES (?, ?, ?)`)
)

// NetworkRuleSet holds the rules identifying the internal users of a tenant
// (spec 6.2): a user is internal when the client IP belongs to one of the
// CIDR ranges and the mail domain is one of the domains.
type NetworkRuleSet struct {
	// CIDRs are the internal IP ranges, masked to their prefix length.
	CIDRs []netip.Prefix
	// Domains are the internal mail domains, normalized.
	Domains []string
}

// NetworkRules is the tenant-scoped repository of internal IP ranges and
// mail domains. Obtain it with [DB.NetworkRules].
type NetworkRules struct {
	db *DB
}

// NetworkRules returns the network rules repository.
func (db *DB) NetworkRules() *NetworkRules { return &NetworkRules{db: db} }

// normalizeDomain validates a mail domain and returns its normalized form
// (lowercase, punycode, no trailing dot).
func normalizeDomain(s string) (string, error) {
	if strings.ContainsAny(s, ":@/[]") {
		return "", invalid("malformed domain")
	}
	d, err := tenant.NormalizeHost(s)
	if err != nil {
		return "", invalid("malformed domain")
	}
	return d, nil
}

// normalizeRules validates, masks, normalizes, sorts and de-duplicates the
// rules.
func normalizeRules(cidrs []netip.Prefix, domains []string) (NetworkRuleSet, error) {
	if len(cidrs) > MaxNetworkRules || len(domains) > MaxNetworkRules {
		return NetworkRuleSet{}, invalid("at most %d ranges and %d domains", MaxNetworkRules, MaxNetworkRules)
	}
	set := NetworkRuleSet{CIDRs: make([]netip.Prefix, 0, len(cidrs)), Domains: make([]string, 0, len(domains))}
	for _, p := range cidrs {
		if !p.IsValid() {
			return NetworkRuleSet{}, invalid("malformed ip range")
		}
		set.CIDRs = append(set.CIDRs, p.Masked())
	}
	for _, raw := range domains {
		d, err := normalizeDomain(raw)
		if err != nil {
			return NetworkRuleSet{}, err
		}
		set.Domains = append(set.Domains, d)
	}
	sortRules(&set)
	set.CIDRs = slices.Compact(set.CIDRs)
	set.Domains = slices.Compact(set.Domains)
	return set, nil
}

// sortRules sorts the ranges by textual form and the domains, so that equal
// sets always compare equal.
func sortRules(set *NetworkRuleSet) {
	slices.SortFunc(set.CIDRs, func(a, b netip.Prefix) int { return strings.Compare(a.String(), b.String()) })
	slices.Sort(set.Domains)
}

// Get returns the rules of tenant tid (empty when none, or when the tenant
// does not exist).
func (r *NetworkRules) Get(ctx context.Context, tid tenant.ID) (NetworkRuleSet, error) {
	s, err := r.db.Scoped(tid)
	if err != nil {
		return NetworkRuleSet{}, err
	}
	set := NetworkRuleSet{CIDRs: []netip.Prefix{}, Domains: []string{}}
	err = s.ReadTx(ctx, func(tx *ScopedTx) error {
		rows, err := tx.Query(ctx, qRulesList)
		if err != nil {
			return err
		}
		type rule struct{ kind, value string }
		rules, err := collect(rows, func(r *sql.Rows) (rule, error) {
			var x rule
			err := r.Scan(&x.kind, &x.value)
			return x, err
		})
		if err != nil {
			return err
		}
		for _, x := range rules {
			if x.kind == ruleKindDomain {
				set.Domains = append(set.Domains, x.value)
				continue
			}
			p, err := netip.ParsePrefix(x.value)
			if err != nil {
				return invalid("stored ip range is malformed")
			}
			set.CIDRs = append(set.CIDRs, p)
		}
		// Sort in Go: PostgreSQL collations may order text differently.
		sortRules(&set)
		return nil
	})
	if err != nil {
		return NetworkRuleSet{}, wrap("get network rules", err)
	}
	return set, nil
}

// Replace atomically replaces every rule of tenant tid and returns the
// stored, normalized set. Concurrent replaces of the same tenant are
// serialized: the final rules are exactly those of one of them. Invalid values yield ErrInvalid (nothing is
// changed); a missing tenant yields ErrNotFound when at least one rule is
// given.
func (r *NetworkRules) Replace(ctx context.Context, tid tenant.ID, cidrs []netip.Prefix, domains []string) (NetworkRuleSet, error) {
	s, err := r.db.Scoped(tid)
	if err != nil {
		return NetworkRuleSet{}, err
	}
	set, err := normalizeRules(cidrs, domains)
	if err != nil {
		return NetworkRuleSet{}, err
	}
	err = s.Tx(ctx, func(tx *ScopedTx) error {
		// Concurrent replaces of the same tenant would otherwise both
		// delete, then collide on insert (PostgreSQL, READ COMMITTED).
		if err := tx.lock(ctx); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, qRulesDelete); err != nil {
			return err
		}
		for _, p := range set.CIDRs {
			if _, err := tx.Exec(ctx, qRuleInsert, ruleKindCIDR, p.String()); err != nil {
				return err
			}
		}
		for _, d := range set.Domains {
			if _, err := tx.Exec(ctx, qRuleInsert, ruleKindDomain, d); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return NetworkRuleSet{}, wrap("replace network rules", err)
	}
	return set, nil
}
