package apitoken

import (
	"crypto/sha256"
	"strings"

	"github.com/ed-fr/transteira/internal/id"
)

// Format of a token secret: "tt_" followed by SecretLen - 3 base62
// characters carrying secretEntropyBytes bytes from crypto/rand.
const (
	// secretPrefix is the prefix of a secret, before the underscore. It is
	// also matched by the secret scanning rule of the repository.
	secretPrefix = "tt"
	// secretEntropyBytes is the entropy of a secret: 32 bytes (256 bits).
	secretEntropyBytes = 32
	// secretBodyLen is the number of base62 characters after "tt_".
	secretBodyLen = 43
	// SecretLen is the length of a secret.
	SecretLen = len(secretPrefix) + 1 + secretBodyLen
	// PrefixLen is the length of the visible prefix kept to recognize a
	// token: "tt_" and 4 characters, far too few to help guess the secret.
	PrefixLen = 7
)

// bearerScheme is the authentication scheme of the Authorization header
// (RFC 6750), compared case-insensitively.
const bearerScheme = "Bearer"

// Generated is a new token secret with what the store keeps of it.
type Generated struct {
	// Secret is the token, shown once to the admin and never stored.
	Secret string
	// Prefix is its first PrefixLen characters.
	Prefix string
	// Hash is its SHA-256.
	Hash []byte
}

// newSecret draws a secret; tests replace it to reach the failure path.
var newSecret = func() (string, error) { return id.NewToken(secretPrefix, secretEntropyBytes) }

// Generate returns a new token secret, its prefix and its hash. It fails
// only when the random source fails.
func Generate() (Generated, error) {
	secret, err := newSecret()
	if err != nil {
		return Generated{}, err
	}
	return Generated{Secret: secret, Prefix: secret[:PrefixLen], Hash: hashOf(secret)}, nil
}

// ValidSecret reports whether s has the shape of a token secret: "tt_"
// followed by exactly 43 base62 characters.
func ValidSecret(s string) bool {
	return id.TokenValid(secretPrefix, s, secretBodyLen, secretBodyLen)
}

// hashOf returns the SHA-256 of a secret.
func hashOf(secret string) []byte {
	h := sha256.Sum256([]byte(secret))
	return h[:]
}

// ParseAuthorization extracts the bearer token of an Authorization header
// value. It returns ErrMissing when the header is empty or uses another
// scheme than Bearer, and ErrInvalid when the Bearer value is not exactly
// "Bearer <secret>" (scheme compared case-insensitively, one space, no
// other character) with a secret of the right shape ([ValidSecret]). The
// errors never quote the header.
func ParseAuthorization(header string) (string, error) {
	scheme, rest, found := strings.Cut(header, " ")
	if !strings.EqualFold(scheme, bearerScheme) {
		return "", ErrMissing
	}
	if !found || !ValidSecret(rest) {
		return "", ErrInvalid
	}
	return rest, nil
}
