package tenant

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"golang.org/x/net/idna"
)

// DNS length limits (RFC 1035).
const (
	maxLabelLen   = 63
	maxDNSNameLen = 253
)

// maxRawHostLen bounds the raw input processed by NormalizeHost, so that a
// huge header cannot make the IDNA conversion expensive. A Unicode name
// whose punycode form fits in 253 bytes is always well below this limit.
const maxRawHostLen = 1024

// maxPortLen is the number of digits of the largest TCP port.
const maxPortLen = 5

// errMsgMaxLen bounds the length of user input echoed in error messages.
const errMsgMaxLen = 64

// toASCII converts a host name to its ASCII (punycode) form with the IDNA
// lookup profile. It is a variable so that tests can exercise the
// re-normalisation guard of NormalizeHost.
var toASCII = idna.Lookup.ToASCII

// ErrInvalidHost reports a Host header value that is not an acceptable
// tenant host name.
var ErrInvalidHost = errors.New("tenant: invalid host")

// NormalizeHost turns a raw HTTP Host header value into the canonical form
// used to identify a tenant: a lower-case ASCII fully qualified domain name,
// without port or trailing dot, with internationalised labels converted to
// punycode.
//
// It rejects empty values, IP literals (IPv4 and IPv6), user information,
// invalid characters, labels longer than 63 bytes or starting or ending with
// a hyphen, names longer than 253 bytes, single-label names and names whose
// top-level label is neither alphabetic nor punycode. Errors wrap
// [ErrInvalidHost]. NormalizeHost never panics and its output is a fixed
// point: NormalizeHost(out) == out.
func NormalizeHost(host string) (string, error) {
	out, err := normalize(host)
	if err != nil {
		return "", err
	}
	again, err := normalize(out)
	if err != nil || again != out {
		return "", invalidHost(host, "unstable normalisation")
	}
	return out, nil
}

// normalize performs one normalisation pass.
func normalize(raw string) (string, error) {
	if raw == "" {
		return "", invalidHost(raw, "empty")
	}
	if len(raw) > maxRawHostLen {
		return "", invalidHost(raw, "too long")
	}
	if strings.ContainsRune(raw, '@') {
		return "", invalidHost(raw, "user information not allowed")
	}
	h, err := stripPort(raw)
	if err != nil {
		return "", err
	}
	h = strings.TrimSuffix(h, ".")
	if h == "" {
		return "", invalidHost(raw, "empty")
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return "", invalidHost(raw, "IP literal not allowed")
	}
	ascii, err := toASCII(h)
	if err != nil {
		return "", invalidHost(raw, "invalid internationalised name")
	}
	if err := checkDNSName(ascii); err != nil {
		return "", invalidHost(raw, err.Error())
	}
	return ascii, nil
}

// stripPort removes an optional ":port" suffix. Bracketed or bare IPv6
// literals are rejected.
func stripPort(raw string) (string, error) {
	if strings.HasPrefix(raw, "[") {
		return "", invalidHost(raw, "IP literal not allowed")
	}
	i := strings.LastIndexByte(raw, ':')
	if i < 0 {
		return raw, nil
	}
	h, port := raw[:i], raw[i+1:]
	if strings.ContainsRune(h, ':') {
		return "", invalidHost(raw, "IP literal not allowed")
	}
	if len(port) > maxPortLen {
		return "", invalidHost(raw, "invalid port")
	}
	for _, c := range []byte(port) {
		if c < '0' || c > '9' {
			return "", invalidHost(raw, "invalid port")
		}
	}
	return h, nil
}

// reasonError is a plain error carrying a validation reason.
type reasonError string

func (e reasonError) Error() string { return string(e) }

// checkDNSName validates an ASCII host name label by label.
func checkDNSName(name string) error {
	if len(name) > maxDNSNameLen {
		return reasonError("name longer than 253 bytes")
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return reasonError("name must contain a dot")
	}
	for _, l := range labels {
		if err := checkLabel(l); err != nil {
			return err
		}
	}
	if !isTLD(labels[len(labels)-1]) {
		return reasonError("invalid top-level label")
	}
	return nil
}

// checkLabel validates one ASCII label: 1 to 63 bytes of [a-z0-9-], not
// starting or ending with a hyphen.
func checkLabel(l string) error {
	if l == "" || len(l) > maxLabelLen {
		return reasonError("invalid label length")
	}
	if l[0] == '-' || l[len(l)-1] == '-' {
		return reasonError("label starts or ends with a hyphen")
	}
	for i := 0; i < len(l); i++ {
		c := l[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return reasonError("invalid character")
		}
	}
	return nil
}

// isTLD reports whether l is an acceptable top-level label: alphabetic and at
// least two letters long, or punycode. Excluding digits also rules out
// numeric forms that some resolvers read as IPv4 addresses (e.g. "127.1").
func isTLD(l string) bool {
	if strings.HasPrefix(l, "xn--") {
		return true
	}
	if len(l) < 2 {
		return false
	}
	for i := 0; i < len(l); i++ {
		if l[i] < 'a' || l[i] > 'z' {
			return false
		}
	}
	return true
}

// invalidHost builds an ErrInvalidHost error without echoing huge inputs.
func invalidHost(raw, reason string) error {
	return fmt.Errorf("%w: %s: %q", ErrInvalidHost, reason, truncate(raw))
}

// truncate shortens s for inclusion in error messages.
func truncate(s string) string {
	if len(s) <= errMsgMaxLen {
		return s
	}
	return s[:errMsgMaxLen] + "..."
}
