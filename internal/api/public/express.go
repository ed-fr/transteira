package public

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/httpserver/middleware"
	"github.com/ed-fr/transteira/internal/secret"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/tte2"
)

// ExpressRoute is the route pattern of createExpressSecret (since 2.3), as
// set in Request.Pattern by the API router: the only route whose raw body
// CaptureRawBody keeps.
const ExpressRoute = http.MethodPost + " /api/v1/express-secrets"

// MaxExtraMembers bounds the members outside the schema of an express
// secret creation reported in the answer (field code not-allowed): a body
// with more is refused all the same, with the first MaxExtraMembers named.
const MaxExtraMembers = 16

// expressMembers are the members of the OpenAPI ExpressSecretCreate.
const (
	memberEncryptedText = "encryptedText"
	memberVerifier      = "verifier"
	memberKeyVerifier   = "keyVerifier"
	memberExpiresIn     = "expiresIn"
)

// WithExpressKillSwitch reports the instance kill switch of the express
// secrets (TT_EXPRESS_SECRETS_DISABLED, since 2.3) in the public
// configuration of every tenant (features.expressSecrets.enabled false).
// The secret service enforces it on its side.
func WithExpressKillSwitch(disabled bool) Option {
	return func(s *Server) { s.expressDisabled = disabled }
}

// rawBodyKey is the context key of the raw body kept by CaptureRawBody.
type rawBodyKey struct{}

// errNoExpressBody reports a server whose router does not run
// CaptureRawBody before createExpressSecret: a wiring error, answered 500
// rather than accepting a body whose extra members would go unseen.
var errNoExpressBody = errors.New("public: raw body of the express secret missing (CaptureRawBody not installed)")

// CaptureRawBody is a middleware of the API router keeping the raw body of
// createExpressSecret (ExpressRoute) in the request context, and of that
// operation only: the handler parses it itself, so that the switches of
// the express service are checked before the body (a malformed body of a
// closed service is refused as closed) and the members outside the schema
// (passphrase, file, delivery...) are refused rather than dropped by the
// generated decoder (threat model T-398). The generated decoder then reads
// an empty object, which always decodes. The body is read after the body
// limit and the JSON media type checks, so it is bounded; a read failure
// (an oversized body) is handed to the generated decoder, which answers it
// (413).
func CaptureRawBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Pattern != ExpressRoute {
			next.ServeHTTP(w, r)
			return
		}
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			r.Body = io.NopCloser(failingReader{err: err})
			next.ServeHTTP(w, r)
			return
		}
		r.Body = io.NopCloser(strings.NewReader("{}"))
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), rawBodyKey{}, raw)))
	})
}

// failingReader returns err on every read.
type failingReader struct{ err error }

// Read implements io.Reader.
func (f failingReader) Read([]byte) (int, error) { return 0, f.err }

// CreateExpressSecret creates an express secret (since 2.3): anonymous, or
// attributed to the API token that authenticated the request (the token
// middleware has already refused an invalid token, 401, and a client
// outside its allowed ranges, 403 ip-not-allowed). The body is the raw
// body kept by CaptureRawBody, parsed here: a body that is not a JSON
// object with string members is refused 400 validation-failed only once
// the service has checked its switches. A token revoked or expired since
// the middleware authenticated it is answered 401 invalid-credentials
// (the WWW-Authenticate challenge is set by the error handler of the
// server). The answer, 201 with the token shown once, is never cached.
func (s *Server) CreateExpressSecret(ctx context.Context, _ gen.CreateExpressSecretRequestObject) (gen.CreateExpressSecretResponseObject, error) {
	t, err := s.secretTenant(ctx)
	if err != nil {
		return nil, err
	}
	raw, ok := ctx.Value(rawBodyKey{}).([]byte)
	if !ok {
		return nil, errNoExpressBody
	}
	creator := secret.ExpressCreator{ClientIP: middleware.ClientIP(ctx)}
	if p, ok := middleware.APITokenFrom(ctx); ok {
		creator.APITokenID, creator.ExpressAllowed = p.TokenID, p.ExpressAllowed
	}
	body, wellFormed := parseExpressBody(raw)
	c, err := s.secrets.CreateExpress(ctx, t, creator, body)
	var invalid *secret.ValidationError
	switch {
	case err != nil && !wellFormed && errors.As(err, &invalid):
		// The empty request stood for a body that is not a JSON object of
		// strings: as for any undecodable body, no field is named.
		return nil, problem.New(problem.CodeValidationFailed)
	case err != nil:
		return nil, secretError(err)
	}
	cc := noStore
	resp := gen.CreateExpressSecret201JSONResponse{
		Body:    gen.SecretCreated{Id: c.ID, Token: c.Token, State: gen.SecretCreatedState(c.State)},
		Headers: gen.CreateExpressSecret201ResponseHeaders{CacheControl: &cc},
	}
	resp.Body.ExpiresAt = optionalTime(c.ExpiresAt)
	return resp, nil
}

// parseExpressBody reads raw as the OpenAPI ExpressSecretCreate: the four
// string members, and the JSON pointers of the other members in the order
// of the body (at most MaxExtraMembers). wellFormed is false, with an
// empty request, when raw is not a JSON object or a member of the schema
// is not a string (null reads as absent, as the generated decoders do);
// data after the object is ignored, as the generated decoders do.
func parseExpressBody(raw []byte) (req secret.ExpressCreateRequest, wellFormed bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return secret.ExpressCreateRequest{}, false
	}
	extra := 0
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return secret.ExpressCreateRequest{}, false
		}
		name, _ := tok.(string) // an object key is always a string
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return secret.ExpressCreateRequest{}, false
		}
		var dst *string
		switch name {
		case memberEncryptedText:
			dst = &req.EncryptedText
		case memberVerifier:
			dst = &req.Verifier
		case memberKeyVerifier:
			dst = &req.KeyVerifier
		case memberExpiresIn:
			dst = &req.ExpiresIn
		default:
			if extra++; extra <= MaxExtraMembers {
				req.Extra = append(req.Extra, jsonPointer(name))
			}
			continue
		}
		if err := json.Unmarshal(value, dst); err != nil {
			return secret.ExpressCreateRequest{}, false
		}
	}
	if _, err := dec.Token(); err != nil { // the closing brace
		return secret.ExpressCreateRequest{}, false
	}
	return req, true
}

// jsonPointer returns the JSON pointer (RFC 6901) of the top-level member
// name.
func jsonPointer(name string) string {
	return "/" + strings.NewReplacer("~", "~0", "/", "~1").Replace(name)
}

// ReportSecretAbuse records an abuse report on an express secret (since
// 2.3), named by the token of its link: 202, the administrators of the
// tenant being alerted. It is open while the express service is closed.
func (s *Server) ReportSecretAbuse(ctx context.Context, req gen.ReportSecretAbuseRequestObject) (gen.ReportSecretAbuseResponseObject, error) {
	t, err := s.secretTenant(ctx)
	if err != nil {
		return nil, err
	}
	var body secret.AbuseReportRequest
	if b := req.Body; b != nil {
		body = secret.AbuseReportRequest{Category: string(b.Category), Message: deref(b.Message)}
	}
	if err := s.secrets.ReportAbuse(ctx, t, middleware.ClientIP(ctx), req.SecretToken, body); err != nil {
		return nil, secretError(err)
	}
	return gen.ReportSecretAbuse202Response{}, nil
}

// expressFeatures renders the express secrets of t for the creation page
// (OpenAPI ExpressSecretFeatures, since 2.3): offered when the anonymous
// mode of t is on and the instance kill switch is off; the durations and
// the text limit are fixed. No limit of the tenant is disclosed.
func (s *Server) expressFeatures(t *tenant.Tenant) *gen.ExpressSecretFeatures {
	durations := tenant.ExpressDurations()
	out := &gen.ExpressSecretFeatures{
		Enabled: t.Express.Enabled && !s.expressDisabled, Durations: make([]gen.ExpressSecretDuration, len(durations)),
		MaxChars: gen.ExpressSecretFeaturesMaxChars(tte2.MaxSecretRunes),
	}
	for i, d := range durations {
		out.Durations[i] = gen.ExpressSecretDuration(d)
	}
	return out
}
