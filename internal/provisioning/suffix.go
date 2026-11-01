package provisioning

import (
	"errors"
	"strings"

	"github.com/ed-fr/transteira/internal/tenant"
)

// Errors of the FQDN and suffix normalization; they never quote the value.
var (
	// errMalformedHost reports a value that is not a host name: port, IP
	// literal, wildcard, path, user information, invalid characters.
	errMalformedHost = errors.New("provisioning: malformed host name")
	// errSuffixDot reports a suffix that does not start with a dot.
	errSuffixDot = errors.New("provisioning: a suffix starts with a dot")
	// errSuffixAdminHost reports a suffix equal to an admin host or to a
	// parent domain of one.
	errSuffixAdminHost = errors.New("provisioning: a suffix may not cover an admin host")
)

// NormalizeFQDN normalizes the FQDN of a tenant exactly as the tenant
// administration and the tenant resolution do (T-01, T-276): lower case,
// trailing dot removed, international names in their ASCII form (A-label);
// a port, an IP literal, a wildcard or any character outside a host name
// is refused, as a single-label name.
func NormalizeFQDN(raw string) (string, error) {
	if strings.ContainsAny(raw, ":/@ []") {
		return "", errMalformedHost
	}
	fqdn, err := tenant.NormalizeHost(raw)
	if err != nil {
		return "", errMalformedHost
	}
	return fqdn, nil
}

// NormalizeSuffix validates an FQDN suffix of a provisioning token and
// returns its stored form: a leading dot followed by a name normalized by
// [NormalizeFQDN], with at least two labels (".transfer.example.com", never
// ".com" nor "example.com"). A suffix equal to one of adminHosts
// (normalized host names) or to a parent domain of one (an admin host
// ending with the suffix) is refused, so that no tenant can be created
// under the administration names (T-276).
func NormalizeSuffix(raw string, adminHosts []string) (string, error) {
	name, ok := strings.CutPrefix(raw, ".")
	if !ok {
		return "", errSuffixDot
	}
	norm, err := NormalizeFQDN(name)
	if err != nil {
		return "", err
	}
	// NormalizeFQDN refuses a single-label name, a numeric top label and a
	// name above 253 bytes: the suffix has at least two labels and matches
	// the OpenAPI syntax, which the store checks again.
	suffix := "." + norm
	for _, h := range adminHosts {
		if h == norm || strings.HasSuffix(h, suffix) {
			return "", errSuffixAdminHost
		}
	}
	return suffix, nil
}

// MatchSuffix reports whether the normalized FQDN fqdn ends with one of the
// normalized suffixes on a label boundary, with at least one more label in
// front of it: "entity-c.transfer.example.com" matches
// ".transfer.example.com", but neither "transfer.example.com" (the suffix
// itself) nor "eviltransfer.example.com" does. A suffix without its leading
// dot never matches.
func MatchSuffix(fqdn string, suffixes []string) bool {
	for _, s := range suffixes {
		if !strings.HasPrefix(s, ".") || len(s) < 2 {
			continue
		}
		front, ok := strings.CutSuffix(fqdn, s)
		if ok && front != "" && !strings.HasSuffix(front, ".") && !strings.HasPrefix(front, ".") {
			return true
		}
	}
	return false
}
