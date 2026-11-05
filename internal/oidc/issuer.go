package oidc

import (
	"net/url"
	"strings"
	"unicode"
)

// Bounds of an issuer, as in TenantSso.issuer and the database.
const (
	MinIssuerLength = 9
	MaxIssuerLength = 512
)

// entraHosts are the sign-in hosts of Microsoft Entra ID (public, US
// government and China clouds, and the older v1 hosts).
var entraHosts = map[string]bool{
	"login.microsoftonline.com":        true,
	"login.microsoftonline.us":         true,
	"login-us.microsoftonline.com":     true,
	"login.microsoftonline.de":         true,
	"login.partner.microsoftonline.cn": true,
	"login.chinacloudapi.cn":           true,
	"login.windows.net":                true,
	"login.microsoft.com":              true,
	"sts.windows.net":                  true,
	"sts.chinacloudapi.cn":             true,
}

// entraMultiTenant are the path segments of the Entra ID issuers that
// accept the users of any tenant.
var entraMultiTenant = map[string]bool{"common": true, "organizations": true, "consumers": true}

// CheckIssuer validates an issuer URL: https, a host, no credentials,
// query or fragment, no space or control character, 9 to 512 characters
// ([ErrIssuerInvalid] otherwise). A template issuer (a path holding "{" or
// "}", such as Entra's {tenantid}) and a Microsoft Entra ID multi-tenant
// issuer (an Entra host whose path holds the segment common, organizations
// or consumers) are refused with [ErrIssuerNotAllowed] (T-288).
func CheckIssuer(issuer string) error {
	u, err := parseIssuer(issuer)
	if err != nil {
		return err
	}
	if strings.ContainsAny(issuer, "{}") || strings.ContainsAny(u.Path, "{}") {
		return ErrIssuerNotAllowed
	}
	if entraHosts[issuerHost(u)] {
		for seg := range strings.SplitSeq(u.Path, "/") {
			if entraMultiTenant[strings.ToLower(seg)] {
				return ErrIssuerNotAllowed
			}
		}
	}
	return nil
}

// parseIssuer checks the syntax rules of [CheckIssuer] and returns the
// parsed URL.
func parseIssuer(issuer string) (*url.URL, error) {
	if len(issuer) < MinIssuerLength || len(issuer) > MaxIssuerLength || !strings.HasPrefix(issuer, "https://") {
		return nil, ErrIssuerInvalid
	}
	for _, r := range issuer {
		if unicode.IsSpace(r) || unicode.IsControl(r) || r == '#' || r == '?' {
			return nil, ErrIssuerInvalid
		}
	}
	u, err := url.Parse(issuer)
	if err != nil || u.Hostname() == "" || u.User != nil {
		return nil, ErrIssuerInvalid
	}
	return u, nil
}

// issuerHost returns the lower-case host name of u without a final dot.
func issuerHost(u *url.URL) string {
	return strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
}

// IsEntraTenantIssuer reports whether issuer is a valid ([CheckIssuer])
// Microsoft Entra ID issuer of one tenant: an Entra host whose first path
// segment is a tenant ID (a GUID), such as
// https://login.microsoftonline.com/<tenant id>/v2.0. For such an issuer
// only, preferred_username is accepted as the e-mail address when the ID
// token has no email_verified claim (decision A6 of T-286): Entra never
// sends email_verified, and preferred_username is set by the tenant's
// administrators.
func IsEntraTenantIssuer(issuer string) bool {
	_, ok := entraTenantID(issuer)
	return ok
}

// entraTenantID returns the tenant ID (the GUID, lower case) of a
// Microsoft Entra ID issuer of one tenant ([IsEntraTenantIssuer]), and
// false for any other issuer.
func entraTenantID(issuer string) (string, bool) {
	if CheckIssuer(issuer) != nil {
		return "", false
	}
	u, _ := url.Parse(issuer)
	if !entraHosts[issuerHost(u)] {
		return "", false
	}
	first, _, _ := strings.Cut(strings.TrimPrefix(u.Path, "/"), "/")
	if !isGUID(first) {
		return "", false
	}
	return strings.ToLower(first), true
}

// isGUID reports whether s is a GUID in its 8-4-4-4-12 hexadecimal form.
func isGUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, r := range s {
		switch i {
		case 8, 13, 18, 23:
			if r != '-' {
				return false
			}
		default:
			if !strings.ContainsRune("0123456789abcdefABCDEF", r) {
				return false
			}
		}
	}
	return true
}

// checkEndpoint validates an endpoint of a discovery document: an
// absolute https URL with a host, without credentials or fragment, of at
// most 2048 characters. A query is allowed (OpenID Connect Discovery).
func checkEndpoint(raw string) bool {
	if raw == "" || len(raw) > 2048 || strings.ContainsAny(raw, "#\x00") {
		return false
	}
	for _, r := range raw {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return false
		}
	}
	u, err := url.Parse(raw)
	return err == nil && strings.HasPrefix(raw, "https://") && u.Hostname() != "" && u.User == nil
}
