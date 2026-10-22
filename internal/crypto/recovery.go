package crypto

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"strings"
)

const (
	// RecoveryCodePrefix starts every recovery code.
	RecoveryCodePrefix = "rc-"
	// MaxRecoveryCodes bounds the number of codes generated at once.
	MaxRecoveryCodes = 64

	// recoveryAlphabet is Crockford's base32 alphabet without I, L, O and U:
	// 32 symbols, 5 bits each, none of which can be mistaken for another.
	recoveryAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	// recoveryGroups and recoveryGroupLen shape the body of a code: three
	// groups of four symbols, 12 symbols in all.
	recoveryGroups   = 3
	recoveryGroupLen = 4
	recoverySymbols  = recoveryGroups * recoveryGroupLen
	// maxRecoveryInput bounds the input accepted by NormalizeRecoveryCode.
	maxRecoveryInput = 64
)

// ErrRecoveryCodeCount is returned by GenerateRecoveryCodes for a count
// outside 1 to MaxRecoveryCodes.
var ErrRecoveryCodeCount = errors.New("crypto: recovery code count must be between 1 and 64")

// GenerateRecoveryCodes returns n new random recovery codes, 1 <= n <=
// MaxRecoveryCodes, each of the form "rc-XXXX-XXXX-XXXX".
//
// Each X is a symbol of Crockford's base32 alphabet without I, L, O and U
// ("0123456789ABCDEFGHJKMNPQRSTVWXYZ"), so that no two symbols look alike.
// The 12 symbols of a code are the 60 low bits of 8 bytes read from
// crypto/rand, 5 bits each: since the alphabet has exactly 32 symbols, the
// mapping has no bias and every code carries 60 bits of entropy.
func GenerateRecoveryCodes(n int) ([]string, error) {
	if n < 1 || n > MaxRecoveryCodes {
		return nil, ErrRecoveryCodeCount
	}
	codes := make([]string, n)
	var buf [8]byte
	defer clear(buf[:])
	for i := range codes {
		if err := randomBytes(buf[:]); err != nil {
			return nil, err
		}
		v := binary.BigEndian.Uint64(buf[:])
		var body [recoverySymbols]byte
		for j := range body {
			body[j] = recoveryAlphabet[v&0x1f]
			v >>= 5
		}
		codes[i] = formatRecoveryCode(body[:])
	}
	return codes, nil
}

// formatRecoveryCode returns "rc-" followed by body in dash-separated groups.
func formatRecoveryCode(body []byte) string {
	var b strings.Builder
	b.Grow(len(RecoveryCodePrefix) + recoverySymbols + recoveryGroups - 1)
	b.WriteString(RecoveryCodePrefix)
	for g := range recoveryGroups {
		if g > 0 {
			b.WriteByte('-')
		}
		b.Write(body[g*recoveryGroupLen : (g+1)*recoveryGroupLen])
	}
	return b.String()
}

// NormalizeRecoveryCode returns the canonical form "rc-XXXX-XXXX-XXXX" of a
// recovery code typed by a user, and whether s is one. Letters are matched
// case-insensitively, dashes and spaces may be missing, misplaced or
// repeated, and the "rc" prefix is optional. Anything else (another
// character, a symbol outside the alphabet, such as I, L, O or U, or a wrong
// number of symbols) is refused, as is an input longer than 64 bytes.
func NormalizeRecoveryCode(s string) (string, bool) {
	if len(s) > maxRecoveryInput {
		return "", false
	}
	body := make([]byte, 0, len(s))
	for i := range len(s) {
		c := s[i]
		switch {
		case c == '-' || c == ' ':
			continue
		case c >= 'a' && c <= 'z':
			c -= 'a' - 'A'
		}
		body = append(body, c)
	}
	if len(body) == recoverySymbols+2 && body[0] == 'R' && body[1] == 'C' {
		body = body[2:]
	}
	if len(body) != recoverySymbols {
		return "", false
	}
	for _, c := range body {
		if strings.IndexByte(recoveryAlphabet, c) < 0 {
			return "", false
		}
	}
	return formatRecoveryCode(body), true
}

// RecoveryCodeMACPurpose is the purpose of the recovery code MACs (see
// [RecoveryCodeMAC]). It is not a [MACPurpose] of the master key: its key is
// derived from the TOTP secret of the administrator.
const RecoveryCodeMACPurpose = "admin-recovery"

// ErrRecoveryKey is returned by RecoveryCodeMAC for a TOTP secret shorter
// than 16 bytes, too short to key a MAC.
var ErrRecoveryKey = errors.New("crypto: the recovery code key must be at least 16 bytes")

// minRecoveryKey is the shortest secret accepted by RecoveryCodeMAC.
const minRecoveryKey = 16

// RecoveryCodeMAC returns the MAC of a normalized recovery code (see
// NormalizeRecoveryCode), the only form stored in the database. It is
//
//	HMAC-SHA256(K, lp("transteira/v1/mac") | lp("admin-recovery") | lp(code))
//	K = HKDF-SHA256(totpSecret, salt = none, info = "transteira/v1/mac/admin-recovery")
//
// with the message layout of MasterKey.MAC, keyed by the TOTP secret in use
// of the administrator (TOTPSecretSize random bytes) that the codes belong to.
//
// The key is secret: a stolen database alone does not allow to test
// guesses offline, since the TOTP secret is stored wrapped by the master
// key (PurposeAdminTOTP). Deriving it from the TOTP secret rather than from
// the master key directly keeps the codes valid across a master key
// rotation: the rotation rewraps the TOTP secret, so the key does not
// change, while a MAC key derived from the master key would be lost with
// the retired key. The codes are bound to one TOTP enrollment anyway: they
// are replaced at each confirmation and erased with the enrollment.
//
// A fast MAC is enough, unlike for passwords: a code carries 60 bits of
// uniform entropy, is single use, and online guessing is bounded by the
// rate limiting of the login. It fails with ErrRecoveryKey for a secret
// shorter than 16 bytes.
func RecoveryCodeMAC(totpSecret []byte, normalized string) ([]byte, error) {
	if len(totpSecret) < minRecoveryKey {
		return nil, ErrRecoveryKey
	}
	// hkdf.Key cannot fail here: the requested length (32 bytes) is far
	// below the HKDF-SHA256 limit and the secret is at least 128 bits long.
	key, _ := hkdf.Key(sha256.New, totpSecret, nil, macInfoPrefix+RecoveryCodeMACPurpose, MasterKeySize)
	defer clear(key)
	h := hmac.New(sha256.New, key)
	writeLP(h, []byte(macLabel))
	writeLP(h, []byte(RecoveryCodeMACPurpose))
	writeLP(h, []byte(normalized))
	return h.Sum(nil), nil
}
