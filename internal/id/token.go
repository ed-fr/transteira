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
	// UploadTokenPrefix starts a tus upload identifier, which appears in
	// the upload URL of a file and is looked up by value.
	UploadTokenPrefix = "upl"
	// DownloadTokenPrefix starts a download link token, which appears in
	// the download URL of a transfer and is looked up by its SHA-256 hash.
	DownloadTokenPrefix = "dl"
	// ChallengeTokenBytes is the entropy of a challenge ID: 128 bits, as it
	// lives 15 minutes and allows 2 attempts.
	ChallengeTokenBytes = MinTokenBytes
	// SessionTokenBytes is the entropy of a session token (256 bits).
	SessionTokenBytes = 32
	// InvitationTokenBytes is the entropy of an invitation token (256
	// bits, long-lived).
	InvitationTokenBytes = 32
	// UploadTokenBytes is the entropy of an upload identifier (256 bits):
	// it is looked up by value and lives as long as the upload.
	UploadTokenBytes = 32
	// DownloadTokenBytes is the entropy of a download token (256 bits): it
	// lives as long as the transfer, up to 30 days.
	DownloadTokenBytes = 32
	// MinTokenBodyLen and MaxTokenBodyLen bound the base62 part of a
	// deposit token: TokenLen(MinTokenBytes) and TokenLen(32).
	MinTokenBodyLen = 22
	MaxTokenBodyLen = 43
)

// NewUploadToken returns a new tus upload identifier: UploadTokenPrefix
// followed by UploadTokenBytes of crypto/rand entropy in base62 (matching the
// OpenAPI pattern "^upl_[A-Za-z0-9]{22,43}$").
func NewUploadToken() (string, error) {
	return NewToken(UploadTokenPrefix, UploadTokenBytes)
}

// UploadTokenValid reports whether s has the shape of an upload identifier
// ("upl_" + 22 to 43 base62 characters).
func UploadTokenValid(s string) bool {
	return TokenValid(UploadTokenPrefix, s, MinTokenBodyLen, MaxTokenBodyLen)
}

// NewDownloadToken returns a new download link token: DownloadTokenPrefix
// followed by DownloadTokenBytes of crypto/rand entropy in base62 (matching
// the OpenAPI LinkToken pattern "^dl_[A-Za-z0-9]{22,43}$").
func NewDownloadToken() (string, error) {
	return NewToken(DownloadTokenPrefix, DownloadTokenBytes)
}

// DownloadTokenValid reports whether s has the shape of a download token
// ("dl_" + 22 to 43 base62 characters).
func DownloadTokenValid(s string) bool {
	return TokenValid(DownloadTokenPrefix, s, MinTokenBodyLen, MaxTokenBodyLen)
}

// DownloadPath is the path of the web download page, followed by the
// download token: the link mailed to the recipients is
// "https://" + FQDN + DownloadPath + token (see DownloadURL).
const DownloadPath = "/d/"

// DownloadURL returns the download link of token for the tenant served on
// fqdn: "https://" + fqdn + DownloadPath + token. fqdn must be the host name
// stored for the tenant, never one taken from a request (threat T-03); it
// and token are used as they are, without validation.
func DownloadURL(fqdn, token string) string {
	return "https://" + fqdn + DownloadPath + token
}

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
