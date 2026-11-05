package oidc

import (
	"container/list"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"

	"github.com/ed-fr/transteira/internal/crypto"
)

// Flow rules (T-289).
const (
	// FlowCookieName is the name of the flow cookie (SetOidcFlowCookie).
	FlowCookieName = "__Host-tt_oidc"
	// FlowTTL is the life of a pending flow and of its cookie.
	FlowTTL = 10 * time.Minute
	// MaxFlows bounds the pending flows; beyond it the oldest is dropped.
	MaxFlows = 10000
	// flowIDPrefix starts every flow ID.
	flowIDPrefix = "of_"
	// maxCookieLength bounds the flow cookie value accepted.
	maxCookieLength = 256
	// maxStateLength bounds the state parameter accepted.
	maxStateLength = 256
	// randomBytes is the size of the flow ID, state, nonce and PKCE
	// verifier (256 bits each).
	randomBytes = 32
)

// Scopes are the scopes requested.
var Scopes = []string{"openid", "email", "profile"}

// Keys computes and verifies the MACs of the flow cookie
// (crypto.MACPurposeOIDCFlow). *crypto.MasterKey implements it, as does
// the Keys of internal/adminauth.
type Keys interface {
	MAC(p crypto.MACPurpose, parts ...[]byte) ([]byte, error)
	VerifyMAC(p crypto.MACPurpose, mac []byte, parts ...[]byte) (bool, error)
}

// Config is the single sign-on configuration of a tenant, as stored, with
// the client secret opened.
type Config struct {
	// TenantID is the tenant whose configuration is used.
	TenantID string
	// Issuer is the issuer URL ([CheckIssuer]).
	Issuer string
	// ClientID and ClientSecret identify the application at the provider.
	ClientID, ClientSecret string
	// RedirectURL is the fixed callback of the admin host,
	// https://<admin host>/api/v1/admin/auth/oidc/callback.
	RedirectURL string
}

// validate checks the fields of c.
func (c Config) validate() error {
	if err := CheckIssuer(c.Issuer); err != nil {
		return err
	}
	if c.TenantID == "" || c.ClientID == "" || len(c.ClientID) > 255 || c.ClientSecret == "" || len(c.ClientSecret) > 1024 {
		return ErrConfigInvalid
	}
	u, err := url.Parse(c.RedirectURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return ErrConfigInvalid
	}
	return nil
}

// Pending is a flow taken back by [Flows.Consume], to redeem with
// [Flows.Redeem]. Its secret parts (PKCE verifier, nonce) are not
// exported: only Consume makes a usable Pending.
type Pending struct {
	// TenantID is the tenant whose configuration started the flow: the
	// caller uses this configuration only (T-288).
	TenantID string
	// Issuer and ClientID are those of the configuration at the start.
	Issuer, ClientID string

	redirectURL string
	verifier    string
	nonce       string
	// issRequired is true when the discovery document announced the iss
	// parameter (RFC 9207).
	issRequired bool
}

// flow is a pending flow.
type flow struct {
	id      string
	state   string
	pending Pending
	expires time.Time
	elem    *list.Element
}

// Flows holds the pending authorization code flows in memory (decision
// A4: a single instance; a restart loses the flows in progress). A flow is
// used once, lives FlowTTL, and at most MaxFlows are kept, the oldest
// being dropped beyond. It is safe for concurrent use.
type Flows struct {
	client *Client
	keys   Keys
	max    int

	mu    sync.Mutex
	byID  map[string]*flow
	order *list.List // of *flow, oldest first
}

// NewFlows returns an empty set of flows using c for the provider and keys
// for the cookie MAC.
func NewFlows(c *Client, keys Keys) *Flows {
	return &Flows{client: c, keys: keys, max: MaxFlows, byID: map[string]*flow{}, order: list.New()}
}

// random returns 256 random bits, base64url without padding.
func random() string {
	b := make([]byte, randomBytes)
	_, _ = rand.Read(b) // never fails (crypto/rand)
	return base64.RawURLEncoding.EncodeToString(b)
}

// Begin starts a flow for cfg: it validates cfg (ErrIssuerInvalid,
// ErrIssuerNotAllowed or ErrConfigInvalid), loads the discovery document
// of the issuer (an *Error of ReasonIssuerError when it fails), draws the
// flow ID, the state, the nonce and the PKCE verifier (256 bits each),
// keeps the flow, and returns the URL to send the browser to (built from
// the validated authorization_endpoint only: response_type code, the
// client ID, the redirect URL, the scopes openid email profile, state,
// nonce, S256 challenge) and the value of the flow cookie ([FlowCookie]).
func (f *Flows) Begin(ctx context.Context, cfg Config) (redirectURL, cookie string, err error) {
	if err := cfg.validate(); err != nil {
		return "", "", err
	}
	p, ferr := f.client.provider(ctx, cfg.Issuer)
	if ferr != nil {
		return "", "", ferr
	}
	fl := &flow{
		id:    flowIDPrefix + random(),
		state: random(),
		pending: Pending{
			TenantID: cfg.TenantID, Issuer: cfg.Issuer, ClientID: cfg.ClientID,
			redirectURL: cfg.RedirectURL, verifier: oauth2.GenerateVerifier(), nonce: random(),
			issRequired: p.doc.IssParameter,
		},
	}
	mac, err := f.keys.MAC(crypto.MACPurposeOIDCFlow, []byte(fl.id), []byte(fl.state))
	if err != nil {
		return "", "", err
	}
	oc := oauth2Config(p.doc, cfg, fl.pending.redirectURL)
	redirectURL = oc.AuthCodeURL(fl.state, oauth2.S256ChallengeOption(fl.pending.verifier),
		oauth2.SetAuthURLParam("nonce", fl.pending.nonce))
	f.add(fl)
	return redirectURL, fl.id + "." + base64.RawURLEncoding.EncodeToString(mac), nil
}

// oauth2Config returns the OAuth 2.0 configuration of cfg at the
// endpoints of doc.
func oauth2Config(doc *Document, cfg Config, redirectURL string) *oauth2.Config {
	style := oauth2.AuthStyleInHeader
	if doc.clientSecretPost() {
		style = oauth2.AuthStyleInParams
	}
	return &oauth2.Config{
		ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret, RedirectURL: redirectURL, Scopes: Scopes,
		Endpoint: oauth2.Endpoint{AuthURL: doc.AuthorizationEndpoint, TokenURL: doc.TokenEndpoint, AuthStyle: style},
	}
}

// add keeps fl, after dropping the expired flows and, at the bound, the
// oldest one.
func (f *Flows) add(fl *flow) {
	now := f.client.now()
	fl.expires = now.Add(FlowTTL)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.purgeLocked(now)
	for f.order.Len() >= f.max {
		f.removeLocked(f.order.Front().Value.(*flow))
	}
	fl.elem = f.order.PushBack(fl)
	f.byID[fl.id] = fl
}

// purgeLocked drops the expired flows (the oldest come first).
func (f *Flows) purgeLocked(now time.Time) {
	for e := f.order.Front(); e != nil; e = f.order.Front() {
		fl := e.Value.(*flow)
		if now.Before(fl.expires) {
			return
		}
		f.removeLocked(fl)
	}
}

// removeLocked drops fl.
func (f *Flows) removeLocked(fl *flow) {
	f.order.Remove(fl.elem)
	delete(f.byID, fl.id)
}

// Purge drops the expired flows. Begin also does it; the caller may run
// it periodically.
func (f *Flows) Purge() {
	now := f.client.now()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.purgeLocked(now)
}

// Len returns the number of flows kept.
func (f *Flows) Len() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.order.Len()
}

// ParseCookie splits a flow cookie value into the flow ID and the MAC. It
// reports false for a malformed value.
func ParseCookie(value string) (id string, mac []byte, ok bool) {
	if len(value) > maxCookieLength {
		return "", nil, false
	}
	id, macText, found := strings.Cut(value, ".")
	if !found || !strings.HasPrefix(id, flowIDPrefix) || len(id) == len(flowIDPrefix) {
		return "", nil, false
	}
	if _, err := base64.RawURLEncoding.DecodeString(id[len(flowIDPrefix):]); err != nil {
		return "", nil, false
	}
	mac, err := base64.RawURLEncoding.DecodeString(macText)
	if err != nil || len(mac) != crypto.MACSize {
		return "", nil, false
	}
	return id, mac, true
}

// bind returns the flow ID of the cookie value when the cookie is well
// formed and its MAC binds that flow ID to state.
func (f *Flows) bind(cookie, state string) (string, bool) {
	id, mac, ok := ParseCookie(cookie)
	if !ok || state == "" || len(state) > maxStateLength {
		return "", false
	}
	valid, err := f.keys.VerifyMAC(crypto.MACPurposeOIDCFlow, mac, []byte(id), []byte(state))
	return id, err == nil && valid
}

// Bound reports whether the cookie value is a well-formed flow cookie
// whose MAC binds its flow ID to state, without consuming anything nor
// looking the flow up. A callback that fails it carries no flow of this
// browser: a missing cookie (a cross-site request does not send a
// SameSite=Lax cookie on a subresource) or a forged one. The caller may
// then refuse it without counting it against the client, since a third
// party can produce it at will, whereas it cannot plant a __Host- cookie
// bound to a state it never saw.
func (f *Flows) Bound(cookie, state string) bool {
	_, ok := f.bind(cookie, state)
	return ok
}

// Consume takes back the flow of the cookie value and of the state and iss
// parameters of the authorization response. Once the cookie MAC binds the
// flow ID to state, the flow is removed whatever the outcome (single use);
// a cookie whose MAC does not verify removes nothing, since its flow ID is
// not trusted. It fails with an *Error of ReasonStateInvalid
// for a malformed cookie, a MAC that does not bind the cookie to state, an
// unknown, used or expired flow; and of ReasonIssuerError when iss
// (RFC 9207) is present and is not exactly the issuer of the flow, or is
// absent while the provider announces it. It never contacts the provider:
// it runs before the code is redeemed.
func (f *Flows) Consume(cookie, state, iss string) (Pending, error) {
	id, ok := f.bind(cookie, state)
	if !ok {
		return Pending{}, failure(ReasonStateInvalid)
	}
	now := f.client.now()
	f.mu.Lock()
	fl := f.byID[id]
	if fl != nil {
		f.removeLocked(fl)
	}
	f.mu.Unlock()
	if fl == nil || !now.Before(fl.expires) || subtle.ConstantTimeCompare([]byte(fl.state), []byte(state)) != 1 {
		return Pending{}, failure(ReasonStateInvalid)
	}
	p := fl.pending
	if iss != "" && iss != p.Issuer {
		return Pending{}, failure(ReasonIssuerError)
	}
	if iss == "" && p.issRequired {
		return Pending{}, failure(ReasonIssuerError)
	}
	return p, nil
}

// FlowCookie returns the flow cookie holding value: __Host-tt_oidc, Path=/,
// Max-Age 600, HttpOnly, Secure, SameSite=Lax (the provider redirects the
// browser back, a Strict cookie would not be sent; decision A4).
func FlowCookie(value string) *http.Cookie {
	return &http.Cookie{
		Name: FlowCookieName, Value: value, Path: "/", MaxAge: int(FlowTTL / time.Second),
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	}
}

// ClearFlowCookie returns the cookie expiring the flow cookie, set by the
// callback whatever its outcome.
func ClearFlowCookie() *http.Cookie {
	return &http.Cookie{
		Name: FlowCookieName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	}
}
