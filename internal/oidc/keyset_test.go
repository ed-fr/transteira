package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
)

// jwkJSON returns the JSON of a public key.
func jwkJSON(t *testing.T, k jose.JSONWebKey) string {
	t.Helper()
	b, err := json.Marshal(k)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestParseKeySet(t *testing.T) {
	t.Parallel()
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	good := []string{
		jwkJSON(t, jose.JSONWebKey{Key: &rsaKey.PublicKey, KeyID: "r"}),
		jwkJSON(t, jose.JSONWebKey{Key: &rsaKey.PublicKey, KeyID: "rp", Algorithm: "PS256", Use: "sig"}),
		jwkJSON(t, jose.JSONWebKey{Key: &p256.PublicKey, KeyID: "e", Algorithm: "ES256"}),
	}
	bad := []string{
		jwkJSON(t, jose.JSONWebKey{Key: &rsaKey.PublicKey, KeyID: "enc", Use: "enc"}),
		jwkJSON(t, jose.JSONWebKey{Key: &small.PublicKey, KeyID: "small"}),
		jwkJSON(t, jose.JSONWebKey{Key: &rsaKey.PublicKey, KeyID: "ralg", Algorithm: "ES256"}),
		jwkJSON(t, jose.JSONWebKey{Key: &p384.PublicKey, KeyID: "p384"}),
		jwkJSON(t, jose.JSONWebKey{Key: &p256.PublicKey, KeyID: "ealg", Algorithm: "RS256"}),
		jwkJSON(t, jose.JSONWebKey{Key: []byte("0123456789abcdef0123456789abcdef"), KeyID: "oct"}),
		jwkJSON(t, jose.JSONWebKey{Key: rsaKey, KeyID: "private"}),
		`{"kty":"unknown"}`,
		`42`,
	}
	keys, ok := ParseKeySet([]byte(`{"keys":[` + strings.Join(append(bad, good...), ",") + `]}`))
	if !ok || len(keys) != 3 {
		t.Fatalf("ParseKeySet kept %d keys, %v", len(keys), ok)
	}
	for _, k := range keys {
		if !k.IsPublic() {
			t.Error("private key kept")
		}
	}
	for _, body := range []string{`[]`, `{}`, `{"keys":{}}`, `not json`} {
		if _, ok := ParseKeySet([]byte(body)); ok {
			t.Errorf("ParseKeySet(%s) accepted", body)
		}
	}
	if keys, ok := ParseKeySet([]byte(`{"keys":[]}`)); !ok || len(keys) != 0 {
		t.Error("empty key set refused")
	}
	many := strings.Repeat(good[0]+",", maxKeys+5) + good[0]
	if keys, ok := ParseKeySet([]byte(`{"keys":[` + many + `]}`)); !ok || len(keys) != maxKeys {
		t.Errorf("ParseKeySet kept %d keys of %d", len(keys), maxKeys+6)
	}
}

// signedBy returns a compact JWS of payload signed by key with alg and
// kid.
func signedBy(t *testing.T, alg jose.SignatureAlgorithm, key any, kid string, payload string) string {
	t.Helper()
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: jose.JSONWebKey{Key: key, KeyID: kid}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	jws, err := s.Sign([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	out, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestKeySetVerifySignature(t *testing.T) {
	t.Parallel()
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	c := NewClient(Options{Guard: loopbackGuard(), Now: newClock().Now})
	// A key set loaded just now: no reload is attempted.
	s := newKeySet(c, "https://127.0.0.1:1/jwks")
	s.keys = []jose.JSONWebKey{
		{Key: &other.PublicKey, KeyID: "k1", Algorithm: "RS256"},
		{Key: &rsaKey.PublicKey, KeyID: "k1", Algorithm: "PS256"},
		{Key: &rsaKey.PublicKey, KeyID: "k1"},
	}
	s.loaded, s.loadedAt = true, c.now()
	ctx := context.Background()
	if p, err := s.VerifySignature(ctx, signedBy(t, jose.RS256, rsaKey, "k1", "hello")); err != nil || string(p) != "hello" {
		t.Fatalf("VerifySignature = %q, %v", p, err)
	}
	// No key ID: every key is tried.
	if _, err := s.VerifySignature(ctx, signedBy(t, jose.RS256, rsaKey, "", "x")); err != nil {
		t.Fatalf("without kid: %v", err)
	}
	if _, err := s.VerifySignature(ctx, signedBy(t, jose.RS256, rsaKey, "k2", "x")); ReasonOf(err) != ReasonTokenInvalid {
		t.Errorf("unknown kid = %v", err)
	}
	if _, err := s.VerifySignature(ctx, signedBy(t, jose.HS256, []byte("0123456789abcdef0123456789abcdef"), "k1", "x")); ReasonOf(err) != ReasonTokenInvalid {
		t.Errorf("HS256 = %v", err)
	}
	if _, err := s.VerifySignature(ctx, "garbage"); ReasonOf(err) != ReasonTokenInvalid {
		t.Errorf("garbage = %v", err)
	}
	// Several signatures (JSON serialization): only the compact form is read.
	ms, err := jose.NewMultiSigner([]jose.SigningKey{{Algorithm: jose.RS256, Key: rsaKey}, {Algorithm: jose.RS256, Key: other}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	jws, _ := ms.Sign([]byte("x"))
	if _, err := s.VerifySignature(ctx, jws.FullSerialize()); ReasonOf(err) != ReasonTokenInvalid {
		t.Errorf("multi-signature = %v", err)
	}
	// A failed load without a fetchFailure in the context.
	s.loadedAt = s.loadedAt.Add(-keyReloadInterval)
	if _, err := s.VerifySignature(ctx, signedBy(t, jose.RS256, rsaKey, "k3", "x")); ReasonOf(err) != ReasonIssuerError {
		t.Errorf("failed load = %v", err)
	}
}
