// Package oidctest is a fake OpenID Connect provider for the tests of the
// single sign-on: discovery, key set (RSA and ECDSA keys, rotation),
// authorization (code bound to the nonce and the PKCE challenge) and token
// endpoints, on an httptest TLS server, with configurable claims and
// misbehaviors (alg none, HS256, unknown key ID, wrong issuer, redirects,
// oversized or slow answers, any change of the discovery document).
//
// The server listens on 127.0.0.1: the client under test needs a dial
// guard allowing loopback and the root pool of [Provider.CertPool].
package oidctest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// Paths of the endpoints, below the issuer path IssuerPath.
const (
	IssuerPath    = "/idp"
	AuthorizePath = IssuerPath + "/authorize"
	TokenPath     = IssuerPath + "/token"
	JWKSPath      = IssuerPath + "/jwks"
	DiscoveryPath = IssuerPath + "/.well-known/openid-configuration"
	// ClientID is the client ID registered at the provider.
	ClientID = "tt-client"
	// OversizeBytes is the size of an oversized answer (beyond 64 KiB).
	OversizeBytes = 80 << 10
)

// Algorithms of the ID token signature ([Behavior.Alg]).
const (
	AlgRS256 = "RS256"
	AlgPS256 = "PS256"
	AlgES256 = "ES256"
	// AlgNone: an unsigned token ("alg": "none").
	AlgNone = "none"
	// AlgHS256: a token signed with HMAC-SHA256 keyed by the client
	// secret (RS256/HS256 confusion).
	AlgHS256 = "HS256"
)

// Claims are the claims of the next ID tokens. The zero value of a field
// uses the default given.
type Claims struct {
	// Subject is sub ("subject-1").
	Subject string
	// Email is email (empty: no claim).
	Email string
	// EmailVerified is email_verified (nil: no claim).
	EmailVerified *bool
	// PreferredUsername is preferred_username (empty: no claim).
	PreferredUsername string
	// AMR is amr (nil: no claim).
	AMR []string
	// Audience is aud ([ClientID]); one entry is sent as a string.
	Audience []string
	// AZP is azp (empty: no claim).
	AZP string
	// Issuer is iss (the issuer of the provider).
	Issuer string
	// IssuedAt, Expiry and NotBefore are iat (now), exp (now + 5 minutes)
	// and nbf (no claim).
	IssuedAt, Expiry, NotBefore time.Time
	// Nonce replaces the nonce of the authorization request when not nil.
	Nonce *string
	// Extra adds or replaces claims; a nil value removes the claim.
	Extra map[string]any
}

// Behavior are the misbehaviors of the provider. The zero value behaves.
type Behavior struct {
	// Alg is the signature algorithm of the ID token (AlgRS256).
	Alg string
	// KID replaces the key ID of the token header (for example an unknown
	// one).
	KID string
	// Discovery edits the discovery document before it is sent (change
	// the issuer, an endpoint, remove a member...).
	Discovery func(doc map[string]any)
	// DiscoveryBody, when set, replaces the discovery document.
	DiscoveryBody []byte
	// JWKSBody, when set, replaces the key set.
	JWKSBody []byte
	// Status replaces the status of the discovery, key set or token answer
	// when not zero (keyed by DiscoveryPath, JWKSPath or TokenPath).
	Status map[string]int
	// Redirect makes these paths answer 302 to the issuer.
	Redirect map[string]bool
	// Oversize makes these paths answer more than 64 KiB.
	Oversize map[string]bool
	// Delay is waited before every answer (or until the client leaves).
	Delay time.Duration
	// NoIDToken leaves the id_token out of the token answer.
	NoIDToken bool
	// IDToken, when set, is sent as the id_token as is.
	IDToken string
	// AuthorizeError makes the authorization endpoint redirect back with
	// this error parameter.
	AuthorizeError string
	// NoIss leaves the iss parameter out of the authorization response;
	// WrongIss puts another issuer in it.
	NoIss, WrongIss bool
	// ClientSecretPost announces client_secret_post only.
	ClientSecretPost bool
}

// signingKey is a key of the provider.
type signingKey struct {
	kid string
	rsa *rsa.PrivateKey
	ec  *ecdsa.PrivateKey
}

// grant is an issued authorization code.
type grant struct {
	nonce, challenge, redirectURI string
}

// Provider is a fake OpenID Connect provider. Its methods are safe for
// concurrent use.
type Provider struct {
	// Server is the TLS server.
	Server *httptest.Server

	secret string

	mu        sync.Mutex
	rsaKey    signingKey
	ecKey     signingKey
	retired   []signingKey
	claims    Claims
	behavior  Behavior
	codes     map[string]grant
	now       func() time.Time
	counts    map[string]int
	lastToken url.Values
}

// New starts a provider and stops it at the end of the test.
func New(tb testing.TB) *Provider {
	tb.Helper()
	p := &Provider{secret: randomText(), codes: map[string]grant{}, now: time.Now, counts: map[string]int{}}
	p.rsaKey, p.ecKey = newRSAKey(tb), newECKey(tb)
	p.Server = httptest.NewUnstartedServer(http.HandlerFunc(p.serve))
	// Handshakes refused by a client under test are expected: no noise.
	p.Server.Config.ErrorLog = log.New(io.Discard, "", 0)
	p.Server.StartTLS()
	tb.Cleanup(p.Server.Close)
	return p
}

// newRSAKey generates an RSA key with a fresh key ID.
func newRSAKey(tb testing.TB) signingKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		tb.Fatal(err)
	}
	return signingKey{kid: "rsa-" + randomText()[:8], rsa: k}
}

// newECKey generates an ECDSA P-256 key with a fresh key ID.
func newECKey(tb testing.TB) signingKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	return signingKey{kid: "ec-" + randomText()[:8], ec: k}
}

// randomText returns 256 random bits, base64url.
func randomText() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// Issuer returns the issuer URL (the server URL followed by IssuerPath).
func (p *Provider) Issuer() string { return p.Server.URL + IssuerPath }

// ClientSecret returns the client secret registered for [ClientID].
func (p *Provider) ClientSecret() string { return p.secret }

// CertPool returns a pool holding the certificate of the server, for the
// RootCAs of the client under test.
func (p *Provider) CertPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(p.Server.Certificate())
	return pool
}

// SetClaims sets the claims of the next ID tokens.
func (p *Provider) SetClaims(c Claims) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.claims = c
}

// SetBehavior sets the misbehaviors.
func (p *Provider) SetBehavior(b Behavior) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.behavior = b
}

// SetNow sets the clock of the provider (time.Now by default), used for
// the default iat and exp.
func (p *Provider) SetNow(now func() time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.now = now
}

// RotateKeys replaces the signing keys with new ones of new key IDs. With
// keepOld, the previous keys stay published (but are no longer used).
func (p *Provider) RotateKeys(tb testing.TB, keepOld bool) {
	tb.Helper()
	r, e := newRSAKey(tb), newECKey(tb)
	p.mu.Lock()
	defer p.mu.Unlock()
	if keepOld {
		p.retired = append(p.retired, p.rsaKey, p.ecKey)
	} else {
		p.retired = nil
	}
	p.rsaKey, p.ecKey = r, e
}

// Requests returns how many requests path received.
func (p *Provider) Requests(path string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.counts[path]
}

// LastTokenRequest returns the form of the last token request, with the
// client_secret of a Basic authorization added.
func (p *Provider) LastTokenRequest() url.Values {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastToken
}

// Client returns an HTTP client trusting the server and following no
// redirect, to play the browser.
func (p *Provider) Client() *http.Client {
	c := p.Server.Client()
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return c
}

// Authorize plays the browser at the authorization URL authURL (as
// returned by the relying party): the provider signs the user in and
// redirects back. It returns the callback URL, carrying code, state and
// iss, or error and state.
func (p *Provider) Authorize(authURL string) (*url.URL, error) {
	resp, err := p.Client().Get(authURL)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound {
		return nil, fmt.Errorf("oidctest: authorize answered %d", resp.StatusCode)
	}
	return url.Parse(resp.Header.Get("Location"))
}

// Code issues a code for the nonce, PKCE verifier and redirect URI given,
// without going through the authorization endpoint.
func (p *Provider) Code(nonce, verifier, redirectURI string) string {
	sum := sha256.Sum256([]byte(verifier))
	code := randomText()
	p.mu.Lock()
	defer p.mu.Unlock()
	p.codes[code] = grant{nonce: nonce, challenge: base64.RawURLEncoding.EncodeToString(sum[:]), redirectURI: redirectURI}
	return code
}

// serve dispatches the requests.
func (p *Provider) serve(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	p.counts[r.URL.Path]++
	b := p.behavior
	p.mu.Unlock()
	if b.Delay > 0 {
		select {
		case <-time.After(b.Delay):
		case <-r.Context().Done():
			return
		}
	}
	if b.Redirect[r.URL.Path] {
		http.Redirect(w, r, p.Issuer(), http.StatusFound)
		return
	}
	if b.Oversize[r.URL.Path] {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"pad":"` + strings.Repeat("a", OversizeBytes) + `"}`))
		return
	}
	if s := b.Status[r.URL.Path]; s != 0 {
		http.Error(w, "status", s)
		return
	}
	switch r.URL.Path {
	case DiscoveryPath:
		p.discovery(w, b)
	case JWKSPath:
		if b.JWKSBody != nil {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(b.JWKSBody)
			return
		}
		p.jwks(w)
	case AuthorizePath:
		p.authorize(w, r, b)
	case TokenPath:
		p.token(w, r, b)
	default:
		http.NotFound(w, r)
	}
}

// writeJSON writes v as JSON.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// Document returns the discovery document as served without
// misbehavior.
func (p *Provider) Document() map[string]any {
	methods := []string{"client_secret_basic", "client_secret_post"}
	p.mu.Lock()
	if p.behavior.ClientSecretPost {
		methods = []string{"client_secret_post"}
	}
	p.mu.Unlock()
	return map[string]any{
		"issuer":                                         p.Issuer(),
		"authorization_endpoint":                         p.Server.URL + AuthorizePath,
		"token_endpoint":                                 p.Server.URL + TokenPath,
		"jwks_uri":                                       p.Server.URL + JWKSPath,
		"response_types_supported":                       []string{"code"},
		"subject_types_supported":                        []string{"pairwise"},
		"id_token_signing_alg_values_supported":          []string{AlgRS256, AlgPS256, AlgES256},
		"token_endpoint_auth_methods_supported":          methods,
		"code_challenge_methods_supported":               []string{"S256"},
		"authorization_response_iss_parameter_supported": true,
	}
}

// discovery serves the discovery document.
func (p *Provider) discovery(w http.ResponseWriter, b Behavior) {
	if b.DiscoveryBody != nil {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(b.DiscoveryBody)
		return
	}
	doc := p.Document()
	if b.Discovery != nil {
		b.Discovery(doc)
	}
	writeJSON(w, http.StatusOK, doc)
}

// JWKS returns the published key set.
func (p *Provider) JWKS() jose.JSONWebKeySet {
	p.mu.Lock()
	defer p.mu.Unlock()
	var set jose.JSONWebKeySet
	for _, k := range append([]signingKey{p.rsaKey, p.ecKey}, p.retired...) {
		if k.rsa != nil {
			set.Keys = append(set.Keys, jose.JSONWebKey{Key: &k.rsa.PublicKey, KeyID: k.kid, Use: "sig"})
		} else {
			set.Keys = append(set.Keys, jose.JSONWebKey{Key: &k.ec.PublicKey, KeyID: k.kid, Algorithm: AlgES256, Use: "sig"})
		}
	}
	return set
}

// jwks serves the key set.
func (p *Provider) jwks(w http.ResponseWriter) { writeJSON(w, http.StatusOK, p.JWKS()) }

// authorize checks an authorization request and redirects back with a
// code bound to its nonce and PKCE challenge.
func (p *Provider) authorize(w http.ResponseWriter, r *http.Request, b Behavior) {
	q := r.URL.Query()
	redirect, err := url.Parse(q.Get("redirect_uri"))
	scopes := strings.Fields(q.Get("scope"))
	if err != nil || redirect.Scheme == "" || q.Get("client_id") != ClientID || q.Get("response_type") != "code" ||
		!slices.Contains(scopes, "openid") || q.Get("code_challenge_method") != "S256" ||
		q.Get("code_challenge") == "" || q.Get("state") == "" || q.Get("nonce") == "" {
		http.Error(w, "invalid_request", http.StatusBadRequest)
		return
	}
	back := url.Values{"state": {q.Get("state")}}
	switch {
	case b.WrongIss:
		back.Set("iss", p.Server.URL+"/other")
	case !b.NoIss:
		back.Set("iss", p.Issuer())
	}
	if b.AuthorizeError != "" {
		back.Set("error", b.AuthorizeError)
	} else {
		code := randomText()
		p.mu.Lock()
		p.codes[code] = grant{nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), redirectURI: q.Get("redirect_uri")}
		p.mu.Unlock()
		back.Set("code", code)
	}
	redirect.RawQuery = back.Encode()
	http.Redirect(w, r, redirect.String(), http.StatusFound) //nolint:gosec // G710: a test fake redirecting to the redirect_uri of the relying party under test, as a provider does
}

// tokenError answers an OAuth 2.0 error.
func tokenError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}

// token redeems a code: client authentication, single use, redirect URI
// and PKCE verifier.
func (p *Provider) token(w http.ResponseWriter, r *http.Request, b Behavior) {
	if r.Method != http.MethodPost || r.ParseForm() != nil {
		tokenError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	form := maps.Clone(r.PostForm)
	if id, secret, ok := r.BasicAuth(); ok {
		id, _ = url.QueryUnescape(id)
		secret, _ = url.QueryUnescape(secret)
		form.Set("client_id", id)
		form.Set("client_secret", secret)
	}
	code := form.Get("code")
	p.mu.Lock()
	p.lastToken = form
	g, ok := p.codes[code]
	delete(p.codes, code)
	p.mu.Unlock()
	if form.Get("client_id") != ClientID || subtle.ConstantTimeCompare([]byte(form.Get("client_secret")), []byte(p.secret)) != 1 {
		tokenError(w, http.StatusUnauthorized, "invalid_client")
		return
	}
	sum := sha256.Sum256([]byte(form.Get("code_verifier")))
	if !ok || form.Get("grant_type") != "authorization_code" || form.Get("redirect_uri") != g.redirectURI ||
		base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge {
		tokenError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	answer := map[string]any{"access_token": randomText(), "token_type": "Bearer", "expires_in": 300}
	switch {
	case b.IDToken != "":
		answer["id_token"] = b.IDToken
	case !b.NoIDToken:
		tok, err := p.IDToken(g.nonce)
		if err != nil {
			tokenError(w, http.StatusInternalServerError, "server_error")
			return
		}
		answer["id_token"] = tok
	}
	writeJSON(w, http.StatusOK, answer)
}

// ClaimsMap returns the claims of an ID token for nonce, from the current
// Claims.
func (p *Provider) ClaimsMap(nonce string) map[string]any {
	p.mu.Lock()
	defer p.mu.Unlock()
	c, now := p.claims, p.now()
	m := map[string]any{
		"iss": p.Issuer(), "sub": "subject-1", "aud": ClientID, "nonce": nonce,
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
	}
	if c.Subject != "" {
		m["sub"] = c.Subject
	}
	if c.Issuer != "" {
		m["iss"] = c.Issuer
	}
	switch len(c.Audience) {
	case 0:
	case 1:
		m["aud"] = c.Audience[0]
	default:
		m["aud"] = c.Audience
	}
	if c.Nonce != nil {
		m["nonce"] = *c.Nonce
	}
	if !c.IssuedAt.IsZero() {
		m["iat"] = c.IssuedAt.Unix()
	}
	if !c.Expiry.IsZero() {
		m["exp"] = c.Expiry.Unix()
	}
	if !c.NotBefore.IsZero() {
		m["nbf"] = c.NotBefore.Unix()
	}
	if c.Email != "" {
		m["email"] = c.Email
	}
	if c.EmailVerified != nil {
		m["email_verified"] = *c.EmailVerified
	}
	if c.PreferredUsername != "" {
		m["preferred_username"] = c.PreferredUsername
	}
	if c.AMR != nil {
		m["amr"] = c.AMR
	}
	if c.AZP != "" {
		m["azp"] = c.AZP
	}
	for k, v := range c.Extra {
		if v == nil {
			delete(m, k)
		} else {
			m[k] = v
		}
	}
	return m
}

// IDToken returns an ID token for nonce, from the current Claims, signed
// as the current Behavior says.
func (p *Provider) IDToken(nonce string) (string, error) {
	payload, err := json.Marshal(p.ClaimsMap(nonce))
	if err != nil {
		return "", err
	}
	p.mu.Lock()
	b, rsaKey, ecKey := p.behavior, p.rsaKey, p.ecKey
	p.mu.Unlock()
	alg := b.Alg
	if alg == "" {
		alg = AlgRS256
	}
	var key jose.SigningKey
	switch alg {
	case AlgNone:
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
		return header + "." + base64.RawURLEncoding.EncodeToString(payload) + ".", nil
	case AlgHS256:
		key = jose.SigningKey{Algorithm: jose.HS256, Key: jose.JSONWebKey{Key: []byte(p.secret), KeyID: rsaKey.kid}}
	case AlgES256:
		key = jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: ecKey.ec, KeyID: ecKey.kid}}
	case AlgRS256, AlgPS256:
		key = jose.SigningKey{Algorithm: jose.SignatureAlgorithm(alg), Key: jose.JSONWebKey{Key: rsaKey.rsa, KeyID: rsaKey.kid}}
	default:
		return "", errors.New("oidctest: unknown algorithm")
	}
	if b.KID != "" {
		jwk := key.Key.(jose.JSONWebKey)
		jwk.KeyID = b.KID
		key.Key = jwk
	}
	signer, err := jose.NewSigner(key, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return "", err
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return jws.CompactSerialize()
}
