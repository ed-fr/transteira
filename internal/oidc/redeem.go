package oidc

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Token rules (T-290).
const (
	// Leeway is the clock skew tolerated on exp, iat and nbf (H8).
	Leeway = 2 * time.Minute
	// maxCodeLength bounds the authorization code (completeAdminOidcLogin).
	maxCodeLength = 2048
	// maxSubjectLength and maxEmailLength bound the claims kept (database
	// limits).
	maxSubjectLength = 255
	maxEmailLength   = 254
)

// Identity is the identity proven by a valid ID token.
type Identity struct {
	// Issuer and ClientID are those of the flow.
	Issuer, ClientID string
	// Subject is the sub claim, 1 to 255 characters. It is the subject
	// pinned with the issuer and the client ID (admin_identities). For
	// Microsoft Entra ID, sub is pairwise per application, which the
	// client ID in the key accounts for; the Entra-specific oid claim is
	// deliberately not used, so that every provider is keyed the same way.
	Subject string
	// Email is the verified address, lower case: the email claim when
	// email_verified is true; for a tenant-specific Entra ID issuer
	// ([IsEntraTenantIssuer]) and no email_verified claim at all,
	// preferred_username (decision A6), unless the idp claim names another
	// directory (a guest account). Empty when
	// none is acceptable: the caller then fails with account_unknown.
	Email string
	// MFA is true when the amr claim contains "mfa".
	MFA bool
}

// claims are the claims read from the ID token beside those of go-oidc.
type claims struct {
	Subject           string          `json:"sub"`
	Nonce             string          `json:"nonce"`
	AZP               string          `json:"azp"`
	Email             string          `json:"email"`
	EmailVerified     json.RawMessage `json:"email_verified"`
	PreferredUsername string          `json:"preferred_username"`
	AMR               []string        `json:"amr"`
	TID               string          `json:"tid"`
	IDP               string          `json:"idp"`
	NotBefore         *float64        `json:"nbf"`
}

// Redeem exchanges code for an ID token and validates it. cfg is the
// configuration of p.TenantID as read again by the caller: a configuration
// changed since the start (another tenant, issuer or client ID) fails
// with ReasonIssuerError, and so does a provider that cannot be reached
// or answers a server error. The code is sent to the token endpoint of the
// validated discovery document with the client secret and the PKCE
// verifier, to the redirect URL of the start. A code refused by the
// provider (4xx), a missing or invalid ID token fail with
// ReasonTokenInvalid. The ID token must be signed with RS256, PS256 or
// ES256 by a key of the issuer's jwks_uri, carry iss equal to the issuer,
// aud containing the client ID, azp equal to the client ID when present
// (required with several audiences), exp and iat (and nbf when present)
// valid within Leeway, the nonce of the flow and a sub of 1 to 255
// characters. For a Microsoft Entra ID issuer of one tenant, the tid
// claim must also be the tenant ID of the issuer.
func (f *Flows) Redeem(ctx context.Context, p Pending, cfg Config, code string) (Identity, error) {
	if p.verifier == "" || p.nonce == "" {
		return Identity{}, failure(ReasonStateInvalid)
	}
	if cfg.TenantID != p.TenantID || cfg.Issuer != p.Issuer || cfg.ClientID != p.ClientID {
		return Identity{}, failure(ReasonIssuerError)
	}
	if code == "" || len(code) > maxCodeLength {
		return Identity{}, failure(ReasonTokenInvalid)
	}
	c := f.client
	prov, ferr := c.provider(ctx, p.Issuer)
	if ferr != nil {
		return Identity{}, ferr
	}
	rawIDToken, err := c.exchange(ctx, prov.doc, cfg, p, code)
	if err != nil {
		return Identity{}, err
	}
	return c.verify(ctx, prov, p, rawIDToken)
}

// exchange redeems code at the token endpoint and returns the raw ID
// token.
func (c *Client) exchange(ctx context.Context, doc *Document, cfg Config, p Pending, code string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	ctx = context.WithValue(ctx, oauth2.HTTPClient, c.http)
	tok, err := oauth2Config(doc, cfg, p.redirectURL).Exchange(ctx, code, oauth2.VerifierOption(p.verifier))
	if err != nil {
		if re, ok := errors.AsType[*oauth2.RetrieveError](err); ok && re.Response != nil &&
			re.Response.StatusCode >= http.StatusBadRequest && re.Response.StatusCode < http.StatusInternalServerError {
			return "", failure(ReasonTokenInvalid)
		}
		return "", failure(ReasonIssuerError)
	}
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" {
		return "", failure(ReasonTokenInvalid)
	}
	return raw, nil
}

// verify validates the ID token raw for the flow p.
func (c *Client) verify(ctx context.Context, prov *provider, p Pending, raw string) (Identity, error) {
	var ff fetchFailure
	vctx := context.WithValue(ctx, fetchFailureKey{}, &ff)
	verifier := gooidc.NewVerifier(p.Issuer, prov.keys, &gooidc.Config{
		ClientID:             p.ClientID,
		SupportedSigningAlgs: allowedAlgNames,
		// Times are checked below, with the leeway of the specification.
		SkipExpiryCheck: true,
	})
	tok, err := verifier.Verify(vctx, raw)
	if err != nil {
		if ff.err != nil {
			return Identity{}, ff.err
		}
		return Identity{}, failure(ReasonTokenInvalid)
	}
	var cl claims
	if err := tok.Claims(&cl); err != nil {
		return Identity{}, failure(ReasonTokenInvalid)
	}
	if !c.validClaims(tok, &cl, p) {
		return Identity{}, failure(ReasonTokenInvalid)
	}
	id := Identity{Issuer: p.Issuer, ClientID: p.ClientID, Subject: cl.Subject, MFA: slices.Contains(cl.AMR, "mfa")}
	id.Email = email(p.Issuer, &cl)
	return id, nil
}

// validClaims checks what go-oidc leaves out: exact issuer (go-oidc
// tolerates a Google variant), the tid claim of a Microsoft Entra ID
// tenant issuer, authorized party, times with Leeway, nonce and subject.
func (c *Client) validClaims(tok *gooidc.IDToken, cl *claims, p Pending) bool {
	now := c.now()
	if tok.Issuer != p.Issuer {
		return false
	}
	if tid, ok := entraTenantID(p.Issuer); ok && !strings.EqualFold(cl.TID, tid) {
		return false
	}
	if (cl.AZP != "" && cl.AZP != p.ClientID) || (len(tok.Audience) > 1 && cl.AZP == "") {
		return false
	}
	if tok.Expiry.IsZero() || !now.Before(tok.Expiry.Add(Leeway)) {
		return false
	}
	if tok.IssuedAt.IsZero() || now.Add(Leeway).Before(tok.IssuedAt) {
		return false
	}
	if cl.NotBefore != nil && *cl.NotBefore > float64(now.Add(Leeway).Unix()) {
		return false
	}
	if subtle.ConstantTimeCompare([]byte(cl.Nonce), []byte(p.nonce)) != 1 {
		return false
	}
	return cl.Subject != "" && len(cl.Subject) <= maxSubjectLength
}

// email returns the verified address of the claims, lower case, or "".
func email(issuer string, cl *claims) string {
	verified, present := emailVerified(cl.EmailVerified)
	var addr string
	switch {
	case verified:
		addr = cl.Email
	case !present && IsEntraTenantIssuer(issuer) && homeAccount(issuer, cl.IDP):
		// Entra never sends email_verified, and its email claim may be
		// set by the user: only preferred_username, set by the tenant's
		// administrators, is taken (T-286). A guest (B2B) account, whose
		// idp claim names its home identity provider, is refused: its
		// preferred_username is set by another directory.
		addr = cl.PreferredUsername
	}
	addr = strings.ToLower(strings.TrimSpace(addr))
	if len(addr) > maxEmailLength || strings.Count(addr, "@") != 1 || strings.HasPrefix(addr, "@") || strings.HasSuffix(addr, "@") {
		return ""
	}
	return addr
}

// homeAccount reports whether the idp claim of an ID token of the Entra
// ID tenant issuer says the account belongs to that tenant: no idp claim,
// the issuer itself, or an issuer of the same Entra ID tenant (such as the
// v1 https://sts.windows.net/<tenant id>/).
func homeAccount(issuer, idp string) bool {
	if idp == "" || idp == issuer {
		return true
	}
	tid, _ := entraTenantID(issuer)
	other, ok := entraTenantID(idp)
	return ok && other == tid
}

// emailVerified reads the email_verified claim: true or "true" is
// verified; present reports whether the claim is there at all (null
// counts as absent).
func emailVerified(raw json.RawMessage) (verified, present bool) {
	if len(raw) == 0 || string(raw) == "null" {
		return false, false
	}
	var b bool
	if json.Unmarshal(raw, &b) == nil {
		return b, true
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s == "true", true
	}
	return false, true
}
