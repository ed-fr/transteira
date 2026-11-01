package provisioning

import (
	"context"
	"crypto/sha256"

	"github.com/ed-fr/transteira/internal/id"
)

// Format of a provisioning token secret: "ttp_" followed by secretBodyLen
// base62 characters carrying secretEntropyBytes bytes from crypto/rand. The
// prefix differs from the tenant API tokens ("tt_"), so that neither parser
// accepts the other kind (T-269).
const (
	// secretPrefix is the prefix of a secret, before the underscore. It is
	// also matched by the secret scanning rule of the repository.
	secretPrefix = "ttp"
	// secretEntropyBytes is the entropy of a secret: 32 bytes (256 bits).
	secretEntropyBytes = 32
	// secretBodyLen is the number of base62 characters after "ttp_".
	secretBodyLen = 43
	// SecretLen is the length of a secret.
	SecretLen = len(secretPrefix) + 1 + secretBodyLen
	// PrefixLen is the length of the visible prefix kept to recognize a
	// token: "ttp_" and 4 characters, far too few to help guess the secret.
	PrefixLen = len(secretPrefix) + 1 + 4
)

// Generated is a new token secret with what the store keeps of it.
type Generated struct {
	// Secret is the token, shown once to the super admin and never stored.
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

// ValidSecret reports whether s has the shape of a provisioning token
// secret: "ttp_" followed by exactly 43 base62 characters. A tenant API
// token ("tt_...") never has it.
func ValidSecret(s string) bool {
	return id.TokenValid(secretPrefix, s, secretBodyLen, secretBodyLen)
}

// hashOf returns the SHA-256 of a secret.
func hashOf(secret string) []byte {
	h := sha256.Sum256([]byte(secret))
	return h[:]
}

// contextKey is the key of the Principal in a context.
type contextKey struct{}

// NewContext returns ctx carrying the provisioning principal p, as the HTTP
// middleware stores it once the token is authenticated.
func NewContext(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, contextKey{}, p)
}

// FromContext returns the provisioning principal of ctx, and whether there
// is one.
func FromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(contextKey{}).(Principal)
	return p, ok && p.TokenID != ""
}
