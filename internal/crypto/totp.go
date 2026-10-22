package crypto

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // HMAC-SHA1 is mandated by RFC 6238 authenticator apps; HMAC does not rely on SHA-1 collision resistance.
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"strings"
	"time"
)

const (
	// TOTPSecretSize is the size in bytes of a TOTP secret (160 bits, the
	// HMAC-SHA1 output size recommended by RFC 4226).
	TOTPSecretSize = 20
	// TOTPDigits is the number of digits of a TOTP code.
	TOTPDigits = 6
	// TOTPPeriod is the TOTP time step in seconds (T0 = 0).
	TOTPPeriod = 30

	// totpModulo is 10^TOTPDigits.
	totpModulo = 1_000_000
	// totpSkew is the number of time steps accepted on each side of the
	// current one.
	totpSkew = 1
)

// totpEncoding is the base32 alphabet of RFC 4648, uppercase, unpadded, as
// expected by authenticator apps.
var totpEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateTOTPSecret returns a new random TOTP secret of TOTPSecretSize bytes
// read from crypto/rand.
func GenerateTOTPSecret() ([]byte, error) {
	secret := make([]byte, TOTPSecretSize)
	if err := randomBytes(secret); err != nil {
		return nil, err
	}
	return secret, nil
}

// EncodeTOTPSecret returns secret in uppercase RFC 4648 base32 without
// padding, the form typed into or scanned by authenticator apps.
func EncodeTOTPSecret(secret []byte) string {
	return totpEncoding.EncodeToString(secret)
}

// TOTPCode returns the HOTP value (RFC 4226) of secret for counter:
// HMAC-SHA1 of the big-endian counter, dynamic truncation, modulo 10^6,
// left-padded with zeros to TOTPDigits digits.
func TOTPCode(secret []byte, counter uint64) string {
	mac := hmac.New(sha1.New, secret)
	mac.Write(binary.BigEndian.AppendUint64(nil, counter))
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	value %= totpModulo
	var code [TOTPDigits]byte
	for i := TOTPDigits - 1; i >= 0; i-- {
		code[i] = byte('0' + value%10)
		value /= 10
	}
	return string(code[:])
}

// TOTPCounter returns the TOTP time step of t (RFC 6238, T0 = 0, step
// TOTPPeriod seconds). Instants before the Unix epoch map to step 0.
func TOTPCounter(t time.Time) uint64 {
	sec := t.Unix()
	if sec < 0 {
		return 0
	}
	return uint64(sec) / TOTPPeriod
}

// ValidTOTPCode reports whether code is exactly TOTPDigits ASCII digits
// (^[0-9]{6}$), the format of a TOTP code (OpenAPI TotpCode.code).
func ValidTOTPCode(code string) bool {
	if len(code) != TOTPDigits {
		return false
	}
	for i := range len(code) {
		if code[i] < '0' || code[i] > '9' {
			return false
		}
	}
	return true
}

// VerifyTOTP checks code against secret at instant now. It accepts the time
// steps now-1, now and now+1 (RFC 6238 section 5.2, one step of clock drift
// on each side) and, when haveLast is true, refuses every step lower than or
// equal to lastCounter, the step of the last accepted code: a code is never
// accepted twice, nor is an older one once a newer one was used (threat
// T-60). On success it returns the matched step, to be stored as the new
// lastCounter; when several steps match, the latest one is returned.
//
// The format ^[0-9]{6}$ is checked before any computation and an empty
// secret is refused. All candidate steps are always computed and compared in
// constant time, and the result is selected without branching on the
// comparisons, so the timing does not reveal which step matched.
func VerifyTOTP(secret []byte, code string, now time.Time, lastCounter uint64, haveLast bool) (counter uint64, ok bool) {
	if len(secret) == 0 || !ValidTOTPCode(code) {
		return 0, false
	}
	current := TOTPCounter(now)
	var matched uint64
	found := 0
	// There is no step before step 0; the bounds depend only on public time.
	first := current - min(current, totpSkew)
	for c := first; c <= current+totpSkew; c++ {
		eq := subtle.ConstantTimeCompare([]byte(TOTPCode(secret, c)), []byte(code))
		fresh := 1
		if haveLast && c <= lastCounter {
			fresh = 0 // public data: steps and the last counter are not secret
		}
		hit := eq & fresh
		mask := -uint64(hit) //nolint:gosec // hit is 0 or 1: the mask is all zeros or all ones.
		matched = c&mask | matched&^mask
		found |= hit
	}
	if found == 0 {
		return 0, false
	}
	return matched, true
}

// uriUnreserved is the RFC 3986 unreserved set, the only bytes left as they
// are by escapeURIComponent.
const uriUnreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"

// escapeURIComponent percent-encodes every byte of s outside the RFC 3986
// unreserved set, with uppercase hexadecimal digits. Unlike url.PathEscape it
// also encodes ':' and '@', and unlike url.QueryEscape it encodes a space as
// "%20" rather than '+', so the result is valid both in the label and in the
// query of an otpauth URI.
func escapeURIComponent(s string) string {
	const hexDigits = "0123456789ABCDEF"
	var b strings.Builder
	b.Grow(len(s))
	for i := range len(s) {
		c := s[i]
		if strings.IndexByte(uriUnreserved, c) >= 0 {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hexDigits[c>>4])
		b.WriteByte(hexDigits[c&0x0f])
	}
	return b.String()
}

// TOTPURI returns the otpauth key URI of secret, for a QR code shown during
// enrollment:
//
//	otpauth://totp/<issuer>:<account>?secret=<base32>&issuer=<issuer>&algorithm=SHA1&digits=6&period=30
//
// issuer and account are percent-encoded (every byte outside the RFC 3986
// unreserved set, including ':', '@', '&', '?', '#', '/' and spaces as
// "%20"), so that neither can break the label separator or the query.
func TOTPURI(issuer, account string, secret []byte) string {
	iss := escapeURIComponent(issuer)
	return "otpauth://totp/" + iss + ":" + escapeURIComponent(account) +
		"?secret=" + EncodeTOTPSecret(secret) +
		"&issuer=" + iss +
		"&algorithm=SHA1&digits=6&period=30"
}
