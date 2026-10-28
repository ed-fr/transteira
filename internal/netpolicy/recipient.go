package netpolicy

import (
	"errors"
	"strings"
)

// ErrInvalidDomain reports a string that is not an acceptable mail domain.
var ErrInvalidDomain = errors.New("netpolicy: invalid domain")

// NormalizeDomain returns the canonical form of a mail domain: trimmed,
// lower-case, without one trailing dot, internationalised labels converted
// to punycode (A-labels). It rejects an empty value, a leading dot, a name
// longer than 253 bytes, invalid labels, IP literals and anything carrying a
// port, path, bracket or "@". Errors wrap [ErrInvalidDomain]. The output is a
// fixed point: NormalizeDomain(out) == out.
func NormalizeDomain(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || strings.HasPrefix(s, ".") {
		return "", ErrInvalidDomain
	}
	n, ok := normalizeDomain(s)
	if !ok {
		return "", ErrInvalidDomain
	}
	return n, nil
}

// EmailDomain extracts the domain of a mail address (the part after the last
// "@") and normalizes it with [NormalizeDomain]. An address without "@" or
// with a malformed domain returns an error wrapping [ErrInvalidDomain].
func EmailDomain(email string) (string, error) {
	at := strings.LastIndexByte(email, '@')
	if at < 0 {
		return "", ErrInvalidDomain
	}
	return NormalizeDomain(email[at+1:])
}

// RecipientDomainAllowed applies the recipient domain rules of a tenant to
// the domain of a recipient address. allowed and denied hold domains already
// normalized with [NormalizeDomain]; emailDomain is normalized here. Without any
// rule every domain is accepted as is (recipients accepted before the rules
// existed stay accepted); once a rule exists, a domain that does not
// normalize is refused.
//
// A rule for example.com matches example.com and every subdomain
// (a.example.com), never a domain that merely ends with the same characters
// (badexample.com). A deny match always wins. A non-empty allowed list
// accepts only the matching domains; an empty one accepts every domain that
// is not denied.
func RecipientDomainAllowed(emailDomain string, allowed, denied []string) bool {
	if len(allowed) == 0 && len(denied) == 0 {
		return true
	}
	d, err := NormalizeDomain(emailDomain)
	if err != nil {
		return false
	}
	for _, r := range denied {
		if domainMatches(d, r) {
			return false
		}
	}
	if len(allowed) == 0 {
		return true
	}
	for _, r := range allowed {
		if domainMatches(d, r) {
			return true
		}
	}
	return false
}

// domainMatches reports whether domain equals rule or is a subdomain of it.
func domainMatches(domain, rule string) bool {
	if rule == "" {
		return false
	}
	return domain == rule || strings.HasSuffix(domain, "."+rule)
}
