package id

import (
	"fmt"
	"io"
	"math/big"
	"strings"
)

// MinTokenBytes is the minimum entropy of a public token: 16 bytes (128 bits).
const MinTokenBytes = 16

// MaxTokenBytes bounds the entropy of a public token to keep outputs short.
const MaxTokenBytes = 64

// Public token prefixes of the deposit flow and their entropy, shared by the
// store (which validates the shape of the identifiers it keeps) and the
// deposit service (which generates them). Every one of them matches the
// OpenAPI pattern "^<prefix>_[A-Za-z0-9]{22,43}$".
//
// The session ("ds") and invitation ("inv") prefixes are also entity
// identifier prefixes ([DepositSession], [Invitation]): a record ID
// ("ds_" + 26-character ULID) and a bearer token ("ds_" + 43 base62
// characters) can look alike. They are never confused because a token is
// only ever looked up by its SHA-256 hash, and a record by its ID.
const (
	// ChallengeTokenPrefix starts a verification challenge ID, which
	// appears in the confirmation URL.
	ChallengeTokenPrefix = "vch"
	// SessionTokenPrefix starts a deposit session token (cookie value).
	SessionTokenPrefix = "ds"
	// InvitationTokenPrefix starts an invitation link token.
	InvitationTokenPrefix = "inv"
	// ChallengeTokenBytes is the entropy of a challenge ID: 128 bits, as it
	// lives 15 minutes and allows 2 attempts.
	ChallengeTokenBytes = MinTokenBytes
	// SessionTokenBytes is the entropy of a session token (256 bits).
	SessionTokenBytes = 32
	// InvitationTokenBytes is the entropy of an invitation token (256
	// bits, long-lived).
	InvitationTokenBytes = 32
	// MinTokenBodyLen and MaxTokenBodyLen bound the base62 part of a
	// deposit token: TokenLen(MinTokenBytes) and TokenLen(32).
	MinTokenBodyLen = 22
	MaxTokenBodyLen = 43
)

// base62 is the alphabet produced by big.Int.Text(62).
const base62 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

// NewToken returns an unguessable public token "<p>_<base62>" carrying
// entropyBytes bytes read from crypto/rand. p must be 1 to 16 lowercase ASCII
// letters and entropyBytes must be between MinTokenBytes and MaxTokenBytes.
//
// The whole random byte string is interpreted as one big-endian integer and
// converted to base62, then left-padded with '0' to the length of the largest
// possible value (see TokenLen). This mapping is injective, so each token is
// exactly as likely as the byte string it came from: there is no modulo bias,
// unlike reducing each random byte modulo 62. The output length is fixed for a
// given entropyBytes: 22 characters for 16 bytes, 43 characters for 32 bytes.
func NewToken(p string, entropyBytes int) (string, error) {
	return newToken(cryptoReader, p, entropyBytes)
}

// newToken is NewToken with an injectable random source.
func newToken(r io.Reader, p string, entropyBytes int) (string, error) {
	if !validPrefix(p) {
		return "", ErrPrefix
	}
	if entropyBytes < MinTokenBytes || entropyBytes > MaxTokenBytes {
		return "", ErrEntropy
	}
	buf := make([]byte, entropyBytes)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", fmt.Errorf("id: read random: %w", err)
	}
	digits := new(big.Int).SetBytes(buf).Text(62)
	pad := strings.Repeat("0", TokenLen(entropyBytes)-len(digits))
	return p + "_" + pad + digits, nil
}

// TokenLen returns the length of the base62 part of a token generated with
// entropyBytes bytes of entropy: the number of base62 digits of 256^n - 1.
// It returns 0 when entropyBytes is not positive.
func TokenLen(entropyBytes int) int {
	if entropyBytes <= 0 {
		return 0
	}
	maxVal := new(big.Int).Lsh(big.NewInt(1), uint(8*entropyBytes))
	maxVal.Sub(maxVal, big.NewInt(1))
	return len(maxVal.Text(62))
}

// TokenValid reports whether s is "<p>_" followed by between minLen and
// maxLen (inclusive) characters of [A-Za-z0-9].
func TokenValid(p, s string, minLen, maxLen int) bool {
	if !validPrefix(p) || !strings.HasPrefix(s, p+"_") {
		return false
	}
	body := s[len(p)+1:]
	if len(body) < minLen || len(body) > maxLen {
		return false
	}
	for i := range len(body) {
		if strings.IndexByte(base62, body[i]) < 0 {
			return false
		}
	}
	return true
}
