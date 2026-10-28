package store

import (
	"context"
	"database/sql"
	"slices"
	"strings"
	"time"

	"github.com/ed-fr/transteira/internal/tenant"
)

// Limits of the recipient domain rules (spec 8.4).
const (
	// MaxRecipientRules bounds the allowed domains, and separately the
	// denied domains, of one tenant.
	MaxRecipientRules = 500
	// MaxRecipientDomainLen bounds a recipient domain, in bytes.
	MaxRecipientDomainLen = 253
)

// Recipient rule kinds, as stored in recipient_domain_rules.kind.
const (
	recipientRuleAllow = "allow"
	recipientRuleDeny  = "deny"
)

// Statements of the RecipientRules repository.
var (
	qRecipientRulesList = tenantQuery(
		`SELECT kind, domain FROM recipient_domain_rules WHERE tenant_id = ?`)
	qRecipientRulesDelete = tenantQuery(
		`DELETE FROM recipient_domain_rules WHERE tenant_id = ?`)
	qRecipientRuleInsert = tenantQuery(
		`INSERT INTO recipient_domain_rules (tenant_id, kind, domain, created_at) VALUES (?, ?, ?, ?)`)
)

// RecipientRuleSet holds the recipient domain rules of a tenant (spec
// 8.4): a rule for a domain also matches its subdomains, a denied domain
// wins over an allowed one, and a non-empty allow list accepts only its
// domains. Each domain is a lower-case A-label (punycode) without leading
// or trailing dot: callers normalize what the administrator typed
// (internal/netpolicy) before storing it.
type RecipientRuleSet struct {
	// Allowed are the allowed recipient domains, sorted.
	Allowed []string
	// Denied are the denied recipient domains, sorted.
	Denied []string
}

// RecipientRules is the tenant-scoped repository of the recipient domain
// rules. Obtain it with [DB.RecipientRules].
type RecipientRules struct {
	db *DB
}

// RecipientRules returns the recipient domain rules repository.
func (db *DB) RecipientRules() *RecipientRules { return &RecipientRules{db: db} }

// validRecipientDomain reports whether d is a stored-form domain: 1 to
// MaxRecipientDomainLen bytes of lower-case ASCII letters, digits, hyphens
// and dots, without empty label (no leading, trailing or double dot).
func validRecipientDomain(d string) bool {
	if d == "" || len(d) > MaxRecipientDomainLen || d[0] == '.' || d[len(d)-1] == '.' || strings.Contains(d, "..") {
		return false
	}
	return strings.Trim(d, "abcdefghijklmnopqrstuvwxyz0123456789-.") == ""
}

// normalizeRecipientDomains validates one kind of rules and returns a
// sorted copy. Duplicates are refused.
func normalizeRecipientDomains(domains []string) ([]string, error) {
	if len(domains) > MaxRecipientRules {
		return nil, invalid("at most %d domains per kind", MaxRecipientRules)
	}
	out := slices.Clone(domains)
	if out == nil {
		out = []string{}
	}
	for _, d := range out {
		if !validRecipientDomain(d) {
			return nil, invalid("recipient domain must be a lower-case ascii domain of at most %d bytes", MaxRecipientDomainLen)
		}
	}
	slices.Sort(out)
	if len(slices.Compact(slices.Clone(out))) != len(out) {
		return nil, invalid("duplicate recipient domain")
	}
	return out, nil
}

// readRecipientRules reads the rules of the tenant tx is bound to, sorted.
func readRecipientRules(ctx context.Context, tx *ScopedTx) (RecipientRuleSet, error) {
	rows, err := tx.Query(ctx, qRecipientRulesList)
	if err != nil {
		return RecipientRuleSet{}, err
	}
	type rule struct{ kind, domain string }
	rules, err := collect(rows, func(r *sql.Rows) (rule, error) {
		var x rule
		err := r.Scan(&x.kind, &x.domain)
		return x, err
	})
	if err != nil {
		return RecipientRuleSet{}, err
	}
	set := RecipientRuleSet{Allowed: []string{}, Denied: []string{}}
	for _, x := range rules {
		if x.kind == recipientRuleAllow {
			set.Allowed = append(set.Allowed, x.domain)
		} else {
			set.Denied = append(set.Denied, x.domain)
		}
	}
	// Sort in Go: PostgreSQL collations may order text differently.
	slices.Sort(set.Allowed)
	slices.Sort(set.Denied)
	return set, nil
}

// Get returns the recipient domain rules of tenant tid (empty lists, never
// nil, when none or for an unknown tenant).
func (r *RecipientRules) Get(ctx context.Context, tid tenant.ID) (RecipientRuleSet, error) {
	return readScoped(ctx, r.db, tid, "get recipient rules", func(tx *ScopedTx) (RecipientRuleSet, error) {
		return readRecipientRules(ctx, tx)
	})
}

// GetTx is Get inside tx, for the tenant tx is bound to: a transfer
// creation checks its recipients in its own transaction. After an error,
// the caller must abort the transaction.
func (r *RecipientRules) GetTx(ctx context.Context, tx *ScopedTx) (RecipientRuleSet, error) {
	set, err := readRecipientRules(ctx, tx)
	if err != nil {
		return RecipientRuleSet{}, wrap("get recipient rules", err)
	}
	return set, nil
}

// Replace atomically replaces the recipient domain rules of tenant tid
// with rules, recorded at now (the store's clock when zero), and returns
// the stored, sorted set. It returns ErrInvalid, changing nothing, for
// more than MaxRecipientRules domains of a kind, a duplicate within a kind
// or a domain not in stored form (see [RecipientRuleSet]); ErrNotFound
// when the tenant does not exist and at least one rule is given.
// Concurrent replaces of a tenant are serialized.
func (r *RecipientRules) Replace(ctx context.Context, tid tenant.ID, rules RecipientRuleSet, now time.Time) (RecipientRuleSet, error) {
	s, err := r.db.Scoped(tid)
	if err != nil {
		return RecipientRuleSet{}, err
	}
	allowed, err := normalizeRecipientDomains(rules.Allowed)
	if err != nil {
		return RecipientRuleSet{}, err
	}
	denied, err := normalizeRecipientDomains(rules.Denied)
	if err != nil {
		return RecipientRuleSet{}, err
	}
	created := toMillis(r.db.orNow(now))
	err = s.Tx(ctx, func(tx *ScopedTx) error {
		// Concurrent replaces would otherwise both delete, then collide on
		// insert (PostgreSQL, READ COMMITTED).
		if err := tx.lock(ctx); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, qRecipientRulesDelete); err != nil {
			return err
		}
		for _, k := range []struct {
			kind    string
			domains []string
		}{{recipientRuleAllow, allowed}, {recipientRuleDeny, denied}} {
			for _, d := range k.domains {
				if _, err := tx.Exec(ctx, qRecipientRuleInsert, k.kind, d, created); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		return RecipientRuleSet{}, wrap("replace recipient rules", err)
	}
	return RecipientRuleSet{Allowed: allowed, Denied: denied}, nil
}
