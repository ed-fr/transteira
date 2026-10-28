// Package netpolicy applies the internal-user rule of a tenant (CLAUDE.md
// section 6.2): a depositor is internal when the client IP belongs to one of
// the tenant's internal CIDR ranges AND the domain of their mail address is
// one of the tenant's internal mail domains.
//
// The rule is evaluated whenever an action relies on it: opening a deposit
// session, confirming a verification code, creating an invitation and (step
// 6) creating a transfer, so that a session opened at the office does not
// keep its rights from outside. The rule is pure: callers load the rules
// of the tenant (store.NetworkRules) and log the refusals.
//
// The package also holds the other network policies of the application:
// [ParsePrefix], the parsing of an IP range shared by the installation
// configuration and the tenant settings, and [DialGuard], which keeps every
// connection to a tenant SMTP server (mail queue and SMTP test) out of the
// denied networks (TT_SMTP_DENY_NETWORKS, threat model P21) and every
// webhook delivery out of the webhook egress policy
// ([WebhookDenyNetworks], threat model T-181 and P30).
package netpolicy

import (
	"net/netip"
	"slices"
	"strings"

	"github.com/ed-fr/transteira/internal/tenant"
)

// Rules are the internal IP ranges and mail domains of one tenant.
type Rules struct {
	// CIDRs are the internal IP ranges.
	CIDRs []netip.Prefix
	// Domains are the internal mail domains. They are compared after
	// normalization (lowercase, punycode, no trailing dot); an entry that
	// does not normalize never matches.
	Domains []string
}

// Verdict is the outcome of the internal rule, condition by condition, so
// that callers can log which one failed.
type Verdict struct {
	// IPOK is true when the client IP is in one of the ranges.
	IPOK bool
	// DomainOK is true when the domain of the address is one of the
	// domains.
	DomainOK bool
}

// Internal reports whether both conditions hold.
func (v Verdict) Internal() bool { return v.IPOK && v.DomainOK }

// Evaluate applies rules to a client IP and a mail address. An invalid IP
// never matches; an IPv4-mapped IPv6 address is compared as IPv4 and a zone
// is ignored. The domain is the part after the last "@" of email,
// normalized like a host name; an address without "@" or with a malformed
// domain never matches.
func Evaluate(rules Rules, ip netip.Addr, email string) Verdict {
	return Verdict{IPOK: IPInternal(rules, ip), DomainOK: DomainInternal(rules, email)}
}

// IPInternal reports whether ip belongs to one of the internal ranges.
func IPInternal(rules Rules, ip netip.Addr) bool {
	return Contains(rules.CIDRs, ip)
}

// DomainInternal reports whether the domain of email is one of the internal
// domains.
func DomainInternal(rules Rules, email string) bool {
	at := strings.LastIndexByte(email, '@')
	if at < 0 {
		return false
	}
	domain, ok := normalizeDomain(email[at+1:])
	if !ok {
		return false
	}
	return slices.ContainsFunc(rules.Domains, func(d string) bool {
		n, ok := normalizeDomain(d)
		return ok && n == domain
	})
}

// normalizeDomain returns the canonical form of a mail domain, refusing any
// character that has no place in one (a port, a path, brackets).
func normalizeDomain(d string) (string, bool) {
	if strings.ContainsAny(d, ":/[]@") {
		return "", false
	}
	n, err := tenant.NormalizeHost(d)
	return n, err == nil
}
