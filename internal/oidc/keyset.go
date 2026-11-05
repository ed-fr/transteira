package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// Key set rules (T-290).
const (
	// keyReloadInterval is the shortest interval between two loads of the
	// key set of an issuer: an unknown key ID never causes more.
	keyReloadInterval = time.Minute
	// maxKeys bounds the keys kept from one key set.
	maxKeys = 32
	// minRSABits is the smallest RSA key accepted.
	minRSABits = 2048
)

// allowedAlgs are the only signature algorithms of an ID token: never
// none, never HMAC (T-290).
var allowedAlgs = []jose.SignatureAlgorithm{jose.RS256, jose.PS256, jose.ES256}

// allowedAlgNames are allowedAlgs as strings, for go-oidc.
var allowedAlgNames = []string{string(jose.RS256), string(jose.PS256), string(jose.ES256)}

// keySet holds the signing keys of an issuer, loaded from its jwks_uri at
// most once per keyReloadInterval. It implements the KeySet of go-oidc.
type keySet struct {
	client *Client
	url    string

	// load serializes the loads.
	load sync.Mutex

	mu       sync.Mutex
	keys     []jose.JSONWebKey
	loadedAt time.Time
	loaded   bool
}

// newKeySet returns the key set of jwksURL, loaded on first use.
func newKeySet(c *Client, jwksURL string) *keySet {
	return &keySet{client: c, url: jwksURL}
}

// fetchFailure is put in the context of a verification to receive the
// failure to load the keys: go-oidc drops the error chain of a key set.
type fetchFailure struct{ err *Error }

// fetchFailureKey is the context key of a *fetchFailure.
type fetchFailureKey struct{}

// VerifySignature verifies the signature of the compact JWS jwt against
// the keys of the issuer and returns its payload. An algorithm other than
// RS256, PS256 or ES256, or more than one signature, is refused. When no
// key verifies it, the keys are reloaded if the last load is older than a
// minute; a failed load is recorded in the *fetchFailure of ctx.
func (s *keySet) VerifySignature(ctx context.Context, jwt string) ([]byte, error) {
	jws, err := jose.ParseSignedCompact(jwt, allowedAlgs)
	if err != nil || len(jws.Signatures) != 1 {
		return nil, failure(ReasonTokenInvalid)
	}
	kid := jws.Signatures[0].Header.KeyID
	if payload, ok := verifyWith(jws, kid, s.cached()); ok {
		return payload, nil
	}
	keys, ferr := s.reload(ctx)
	if ferr != nil {
		if f, ok := ctx.Value(fetchFailureKey{}).(*fetchFailure); ok {
			f.err = ferr
		}
		return nil, ferr
	}
	if payload, ok := verifyWith(jws, kid, keys); ok {
		return payload, nil
	}
	return nil, failure(ReasonTokenInvalid)
}

// verifyWith verifies jws with the keys of ID kid (all of them when kid is
// empty) whose algorithm, when set, is the one of the signature.
func verifyWith(jws *jose.JSONWebSignature, kid string, keys []jose.JSONWebKey) ([]byte, bool) {
	alg := jws.Signatures[0].Header.Algorithm
	for i := range keys {
		k := &keys[i]
		if (kid != "" && k.KeyID != kid) || (k.Algorithm != "" && k.Algorithm != alg) {
			continue
		}
		if payload, err := jws.Verify(k); err == nil {
			return payload, true
		}
	}
	return nil, false
}

// cached returns the keys loaded last.
func (s *keySet) cached() []jose.JSONWebKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.keys
}

// reload loads the keys unless they were loaded less than a minute ago,
// in which case it returns the cached keys.
func (s *keySet) reload(ctx context.Context) ([]jose.JSONWebKey, *Error) {
	s.load.Lock()
	defer s.load.Unlock()
	now := s.client.now()
	s.mu.Lock()
	recent := s.loaded && now.Sub(s.loadedAt) < keyReloadInterval && !now.Before(s.loadedAt)
	keys := s.keys
	s.mu.Unlock()
	if recent {
		return keys, nil
	}
	body, ferr := s.client.get(ctx, s.url)
	s.mu.Lock()
	// A failed load counts too: a failing provider is not hammered.
	s.loaded, s.loadedAt = true, now
	s.mu.Unlock()
	if ferr != nil {
		return nil, ferr
	}
	keys, ok := ParseKeySet(body)
	if !ok {
		return nil, &Error{Reason: ReasonIssuerError, Stage: StageDiscovery, Category: CategoryInvalidDocument}
	}
	s.mu.Lock()
	s.keys = keys
	s.mu.Unlock()
	return keys, nil
}

// ParseKeySet parses a JSON Web Key Set and keeps its usable signing keys:
// public RSA keys of 2048 bits or more and public ECDSA P-256 keys, whose
// use, when set, is "sig" and whose algorithm, when set, is RS256, PS256
// or ES256; at most 32 of them. Keys of another type (symmetric keys
// included) or that do not parse are skipped. It reports false when the
// body is not a JSON object with a "keys" array.
func ParseKeySet(body []byte) ([]jose.JSONWebKey, bool) {
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(body, &set); err != nil || set.Keys == nil {
		return nil, false
	}
	keys := []jose.JSONWebKey{}
	for _, raw := range set.Keys {
		var k jose.JSONWebKey
		if len(keys) == maxKeys || k.UnmarshalJSON(raw) != nil || !usable(&k) {
			continue
		}
		keys = append(keys, k)
	}
	return keys, true
}

// usable reports whether k is an acceptable public signing key.
func usable(k *jose.JSONWebKey) bool {
	if k.Use != "" && k.Use != "sig" {
		return false
	}
	switch pub := k.Key.(type) {
	case *rsa.PublicKey:
		if pub.N.BitLen() < minRSABits {
			return false
		}
		return k.Algorithm == "" || k.Algorithm == string(jose.RS256) || k.Algorithm == string(jose.PS256)
	case *ecdsa.PublicKey:
		return pub.Curve == elliptic.P256() && (k.Algorithm == "" || k.Algorithm == string(jose.ES256))
	default:
		return false
	}
}
