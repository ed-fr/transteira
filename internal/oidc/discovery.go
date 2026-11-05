package oidc

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"strings"
	"time"
)

// DiscoveryPath is appended to the issuer to fetch its discovery document.
const DiscoveryPath = "/.well-known/openid-configuration"

// Document is the part of a discovery document this package uses, after
// validation ([ParseDocument]).
type Document struct {
	// Issuer equals the configured issuer exactly.
	Issuer string `json:"issuer"`
	// AuthorizationEndpoint, TokenEndpoint and JWKSURI are https URLs
	// without credentials or fragment.
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	// TokenAuthMethods lists the client authentication methods of the
	// token endpoint (client_secret_basic when empty).
	TokenAuthMethods []string `json:"token_endpoint_auth_methods_supported"`
	// IssParameter is true when the provider adds the iss parameter to its
	// authorization responses (RFC 9207): the parameter is then required.
	IssParameter bool `json:"authorization_response_iss_parameter_supported"`
}

// ParseDocument parses and validates the discovery document body of
// issuer: a JSON object (CategoryInvalidDocument otherwise) whose issuer
// equals issuer exactly (CategoryIssuerMismatch, T-288) and whose
// authorization, token and key set endpoints are https URLs without
// credentials (CategoryMissingEndpoint, T-295). Failures have the reason
// ReasonIssuerError.
func ParseDocument(issuer string, body []byte) (*Document, *Error) {
	var d Document
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(&d); err != nil || dec.More() {
		return nil, &Error{Reason: ReasonIssuerError, Stage: StageDiscovery, Category: CategoryInvalidDocument}
	}
	if d.Issuer == "" {
		return nil, &Error{Reason: ReasonIssuerError, Stage: StageDiscovery, Category: CategoryInvalidDocument}
	}
	if d.Issuer != issuer {
		return nil, &Error{Reason: ReasonIssuerError, Stage: StageIssuer, Category: CategoryIssuerMismatch}
	}
	for _, e := range []string{d.AuthorizationEndpoint, d.TokenEndpoint, d.JWKSURI} {
		if !checkEndpoint(e) {
			return nil, &Error{Reason: ReasonIssuerError, Stage: StageEndpoints, Category: CategoryMissingEndpoint}
		}
	}
	return &d, nil
}

// clientSecretPost reports whether the token endpoint takes the client
// secret in the form (client_secret_post) rather than in the
// Authorization header (client_secret_basic, the default).
func (d *Document) clientSecretPost() bool {
	return !slices.Contains(d.TokenAuthMethods, "client_secret_basic") && slices.Contains(d.TokenAuthMethods, "client_secret_post")
}

// provider is a cached validated discovery document with the key set of
// its jwks_uri.
type provider struct {
	doc       *Document
	keys      *keySet
	fetchedAt time.Time
}

// discover fetches and validates the discovery document of issuer.
func (c *Client) discover(ctx context.Context, issuer string) (*Document, *Error) {
	if err := CheckIssuer(issuer); err != nil {
		return nil, &Error{Reason: ReasonIssuerError, Stage: StageSettings, Category: CategoryInternal}
	}
	body, ferr := c.get(ctx, strings.TrimSuffix(issuer, "/")+DiscoveryPath)
	if ferr != nil {
		return nil, ferr
	}
	return ParseDocument(issuer, body)
}

// provider returns the provider of issuer, from the cache when fetched
// less than an hour ago. A refreshed document keeps the key set (and its
// reload rate) while jwks_uri is unchanged. Beyond MaxProviders entries,
// the oldest is evicted.
func (c *Client) provider(ctx context.Context, issuer string) (*provider, *Error) {
	now := c.now()
	c.mu.Lock()
	old := c.providers[issuer]
	c.mu.Unlock()
	if old != nil && now.Sub(old.fetchedAt) < providerTTL && !now.Before(old.fetchedAt) {
		return old, nil
	}
	doc, err := c.discover(ctx, issuer)
	if err != nil {
		return nil, err
	}
	p := &provider{doc: doc, fetchedAt: now}
	if old != nil && old.doc.JWKSURI == doc.JWKSURI {
		p.keys = old.keys
	} else {
		p.keys = newKeySet(c, doc.JWKSURI)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.providers[issuer]; !ok && len(c.providers) >= c.maxProviders {
		var oldest string
		var at time.Time
		for k, v := range c.providers {
			if oldest == "" || v.fetchedAt.Before(at) {
				oldest, at = k, v.fetchedAt
			}
		}
		delete(c.providers, oldest)
	}
	c.providers[issuer] = p
	return p, nil
}

// TestResult is the result of [Client.Test], the SsoTestResult of the API.
// Stage and Error only ever hold the closed values of the Stage* and
// Category* constants.
type TestResult struct {
	// Success is true when the discovery document is valid.
	Success bool
	// Duration is the time the test took.
	Duration time.Duration
	// Stage is StageDone on success, else the stage that failed.
	Stage string
	// Error is the category of the failure, empty on success.
	Error string
}

// Test fetches and validates the discovery document of issuer, without
// the cache and without signing anyone in or sending any secret (the
// testTenantSso operation). A failure is a result, never an error.
func (c *Client) Test(ctx context.Context, issuer string) TestResult {
	start := c.now()
	_, err := c.discover(ctx, issuer)
	r := TestResult{Success: err == nil, Stage: StageDone}
	if err != nil {
		r.Stage, r.Error = err.Stage, err.Category
	}
	r.Duration = max(c.now().Sub(start), 0)
	return r
}
