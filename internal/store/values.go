package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	netmail "net/mail"
	"net/netip"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// TokenHashSize is the size of the token hashes the store keeps for deposit
// sessions and invitations: a SHA-256 digest of the bearer token, computed
// by the caller. The store never sees a raw token.
const TokenHashSize = sha256.Size

// MaxMACBytes bounds the size of a verification code MAC (HMAC-SHA256
// produces 32 bytes).
const MaxMACBytes = 64

// NormalizeEmail validates a mail address and returns the form the store
// keeps and compares: trimmed and lower-case, with a normalized domain
// (punycode, no trailing dot). It returns ErrInvalid otherwise; the error
// never quotes the address. Every repository normalizes the addresses it
// receives with it, so callers may pass them as typed.
func NormalizeEmail(s string) (string, error) {
	return BlockEmail.Normalize(s)
}

// validTokenHash reports whether h has the size of a token hash.
func validTokenHash(h []byte) bool {
	return len(h) == TokenHashSize
}

// validText reports whether s is valid UTF-8 of at most maxRunes
// characters. With singleLine, control characters (CR, LF, tab...) and the
// Unicode line and paragraph separators are refused too, so that the value
// can never inject a mail header (the rule of internal/mail).
func validText(s string, maxRunes int, singleLine bool) bool {
	if !utf8.ValidString(s) || utf8.RuneCountInString(s) > maxRunes {
		return false
	}
	return !singleLine || strings.IndexFunc(s, isLineBreakOrControl) < 0
}

// isLineBreakOrControl reports whether r is a control character or a
// Unicode line or paragraph separator.
func isLineBreakOrControl(r rune) bool {
	return unicode.IsControl(r) || r == 0x2028 || r == 0x2029
}

// Limits of a mail address (RFC 5321 section 4.5.3.1), as internal/mail
// enforces them.
const (
	maxMailboxLen = 254
	maxLocalLen   = 64
	maxLabelLen   = 63
)

// validMailbox reports whether s is a bare mail address in the restricted
// syntax of mail.ParseAddress (threat T-80): it parses with net/mail as
// itself, without display name; its local part is a dot-atom of at most 64
// characters; its domain has at least two LDH labels; no whitespace or
// control character. It duplicates that check because the store cannot
// import internal/mail; a cross-package test in internal/deposit keeps the
// two in agreement.
func validMailbox(s string) bool {
	if s == "" || len(s) > maxMailboxLen || strings.ContainsFunc(s, isLineBreakOrControl) {
		return false
	}
	parsed, err := netmail.ParseAddress(s)
	if err != nil || parsed.Name != "" || parsed.Address != s {
		return false
	}
	at := strings.LastIndexByte(s, '@')
	return validLocalPart(s[:at]) && validMailDomain(s[at+1:])
}

// validLocalPart checks a dot-atom local part (RFC 5322 section 3.2.3).
func validLocalPart(local string) bool {
	if local == "" || len(local) > maxLocalLen {
		return false
	}
	for atom := range strings.SplitSeq(local, ".") {
		if atom == "" || strings.Trim(atom, atext) != "" {
			return false
		}
	}
	return true
}

// atext lists the RFC 5322 atext characters.
const atext = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&'*+-/=?^_`{|}~"

// validMailDomain checks a domain of at least two LDH labels.
func validMailDomain(domain string) bool {
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if l == "" || len(l) > maxLabelLen || l[0] == '-' || l[len(l)-1] == '-' ||
			strings.Trim(l, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-") != "" {
			return false
		}
	}
	return true
}

// ipText returns the canonical text form of a client IP, an IPv4-mapped
// IPv6 address being stored as IPv4. It returns ErrInvalid for the zero
// Addr.
func ipText(ip netip.Addr) (string, error) {
	if !ip.IsValid() {
		return "", invalid("malformed client ip")
	}
	return ip.Unmap().WithZone("").String(), nil
}

// parseIP reads a stored client IP; a malformed value yields the zero Addr.
func parseIP(s string) netip.Addr {
	ip, _ := netip.ParseAddr(s)
	return ip
}

// orNow returns t, or the store's clock when t is zero.
func (db *DB) orNow(t time.Time) time.Time {
	if t.IsZero() {
		return db.now()
	}
	return t
}

// nullText maps "" to SQL NULL.
func nullText(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// nullMillis reads an optional timestamp: the zero time for SQL NULL.
func nullMillis(v sql.NullInt64) time.Time {
	if !v.Valid {
		return time.Time{}
	}
	return fromMillis(v.Int64)
}

// upsert runs update and, when it affected no row, insert, both in tx. The
// tenant lock serializes concurrent upserts of the tenant on PostgreSQL, so
// that two transactions cannot both miss the row and insert it.
func upsert(ctx context.Context, tx *ScopedTx, update TenantQuery, updateArgs []any, insert TenantQuery, insertArgs []any) error {
	if err := tx.lock(ctx); err != nil {
		return err
	}
	res, err := tx.Exec(ctx, update, updateArgs...)
	if err != nil {
		return err
	}
	if err := expectOne(res); !errors.Is(err, ErrNotFound) {
		return err
	}
	_, err = tx.Exec(ctx, insert, insertArgs...)
	return err
}

// PseudonymPrefix starts the pseudonym that replaces the address of an
// erased data subject (GDPR erasure): "erased-" followed by
// PseudonymHexLen lowercase hexadecimal characters.
const PseudonymPrefix = "erased-"

// PseudonymHexLen is the number of hexadecimal characters of a pseudonym
// after PseudonymPrefix.
const PseudonymHexLen = 16

// IsPseudonym reports whether s is a well-formed pseudonym of an erased
// data subject: PseudonymPrefix followed by PseudonymHexLen lowercase
// hexadecimal characters.
func IsPseudonym(s string) bool {
	rest, ok := strings.CutPrefix(s, PseudonymPrefix)
	return ok && isLowerHex(rest, PseudonymHexLen)
}
