package mail

import (
	"errors"
	"fmt"
	netmail "net/mail"
	"strings"
)

// Address limits (RFC 5321 section 4.5.3.1).
const (
	maxAddressLen = 254
	maxLocalLen   = 64
	maxLabelLen   = 63
)

// Sentinel errors of the package.
var (
	// ErrInvalidAddress: an e-mail address is malformed or outside the
	// restricted syntax accepted by TransTeira.
	ErrInvalidAddress = errors.New("mail: invalid address")
	// ErrInvalidSettings: the SMTP settings are incomplete or invalid.
	ErrInvalidSettings = errors.New("mail: invalid SMTP settings")
	// ErrInvalidMessage: the message cannot be built (header injection
	// attempt, missing body, oversized field...).
	ErrInvalidMessage = errors.New("mail: invalid message")
	// ErrStartTLSUnavailable: the server did not offer STARTTLS while the
	// settings require it.
	ErrStartTLSUnavailable = errors.New("mail: server does not offer STARTTLS")
	// ErrAuthUnavailable: a username is configured but the server does not
	// offer AUTH.
	ErrAuthUnavailable = errors.New("mail: server does not offer AUTH")
	// ErrAuthFailed: the server rejected the credentials.
	ErrAuthFailed = errors.New("mail: SMTP authentication failed")
	// ErrSMTP: the SMTP exchange failed (connection, TLS, protocol or a
	// rejection by the server).
	ErrSMTP = errors.New("mail: SMTP delivery failed")
	// ErrUnknownTemplate: no template has the requested name.
	ErrUnknownTemplate = errors.New("mail: unknown template")
	// ErrQueueFull: the mail queue is full; the caller should answer 429.
	ErrQueueFull = errors.New("mail: queue full")
	// ErrQueueClosed: the mail queue no longer accepts jobs.
	ErrQueueClosed = errors.New("mail: queue closed")
)

// ParseAddress validates a bare e-mail address ("user@entity-a.example.com",
// without display name or angle brackets) and returns it with its domain in
// lowercase.
//
// The accepted syntax is a deliberately restricted subset of RFC 5322
// (threat T-80): the address must parse with net/mail and also be a
// dot-atom local part of at most 64 characters, an "@" and a domain of at
// least two LDH labels. Quoted local parts, comments, IP literals,
// internationalized addresses and any whitespace or control character are
// refused, so that an accepted address can be written in a header or an SMTP
// command without escaping.
func ParseAddress(s string) (string, error) {
	if s == "" || len(s) > maxAddressLen {
		return "", fmt.Errorf("%w: empty or too long", ErrInvalidAddress)
	}
	if hasControl(s) {
		return "", fmt.Errorf("%w: control character", ErrInvalidAddress)
	}
	parsed, err := netmail.ParseAddress(s)
	if err != nil || parsed.Name != "" || parsed.Address != s {
		return "", fmt.Errorf("%w: not a bare address", ErrInvalidAddress)
	}
	at := strings.LastIndexByte(s, '@')
	local, domain := s[:at], s[at+1:]
	if !validLocal(local) {
		return "", fmt.Errorf("%w: local part", ErrInvalidAddress)
	}
	if !validDomain(domain) {
		return "", fmt.Errorf("%w: domain", ErrInvalidAddress)
	}
	return local + "@" + strings.ToLower(domain), nil
}

// validLocal checks a dot-atom local part (RFC 5322 section 3.2.3).
func validLocal(local string) bool {
	if local == "" || len(local) > maxLocalLen {
		return false
	}
	for atom := range strings.SplitSeq(local, ".") {
		if atom == "" {
			return false
		}
		for i := range len(atom) {
			if !isAtext(atom[i]) {
				return false
			}
		}
	}
	return true
}

// isAtext reports whether c is an RFC 5322 atext character.
func isAtext(c byte) bool {
	if isAlnum(c) {
		return true
	}
	return strings.IndexByte("!#$%&'*+-/=?^_`{|}~", c) >= 0
}

// isAlnum reports whether c is an ASCII letter or digit.
func isAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// validDomain checks a domain of at least two LDH labels.
func validDomain(domain string) bool {
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if l == "" || len(l) > maxLabelLen || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := range len(l) {
			if !isAlnum(l[i]) && l[i] != '-' {
				return false
			}
		}
	}
	return true
}

// domainOf returns the domain of an address already validated by
// [ParseAddress].
func domainOf(addr string) string {
	return addr[strings.LastIndexByte(addr, '@')+1:]
}
