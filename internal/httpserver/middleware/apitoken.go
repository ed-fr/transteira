package middleware

import "context"

// TokenPrincipal is the API token that authenticated a request (OpenAPI
// security scheme apiToken). The httpserver package stores it in the
// request context of the deposit routes accepting a token; the handlers
// read it with [APITokenFrom] to take the token path (no deposit session,
// no cookie).
type TokenPrincipal struct {
	// TokenID is the token identifier ("tok_" + ULID).
	TokenID string
	// Name is the label of the token.
	Name string
}

// apiTokenKey is the context key of the API token principal.
type apiTokenKey struct{}

// WithAPIToken returns a copy of ctx carrying the API token principal p.
func WithAPIToken(ctx context.Context, p TokenPrincipal) context.Context {
	return context.WithValue(ctx, apiTokenKey{}, p)
}

// APITokenFrom returns the API token principal stored in ctx by
// [WithAPIToken]; ok is false when the request was not authenticated by an
// API token.
func APITokenFrom(ctx context.Context) (TokenPrincipal, bool) {
	p, ok := ctx.Value(apiTokenKey{}).(TokenPrincipal)
	return p, ok
}
