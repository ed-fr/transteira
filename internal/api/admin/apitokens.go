package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strings"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/apitoken"
	"github.com/ed-fr/transteira/internal/httpserver/middleware"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// APITokenService manages the API tokens of the tenants
// (*apitoken.Service). Every method checks the principal itself: a tenant
// the administrator is not attached to, and a token of another tenant,
// answer apitoken.ErrNotFound, like an unknown one.
type APITokenService interface {
	List(ctx context.Context, p adminauth.Principal, tid tenant.ID) ([]store.APIToken, error)
	Create(ctx context.Context, p adminauth.Principal, tid tenant.ID, in apitoken.CreateInput, ip netip.Addr) (apitoken.Created, error)
	Update(ctx context.Context, p adminauth.Principal, tid tenant.ID, tokID string, in apitoken.UpdateInput, ip netip.Addr) (store.APIToken, error)
	Revoke(ctx context.Context, p adminauth.Principal, tid tenant.ID, tokID string, ip netip.Addr) error
}

// Compile-time check that the token service fits.
var _ APITokenService = (*apitoken.Service)(nil)

// WithAPITokenService serves the API token operations with svc. Without it
// they answer 500.
func WithAPITokenService(svc APITokenService) Option {
	return func(s *Server) { s.tokenSvc = svc }
}

// errNoAPITokenService reports a server built without WithAPITokenService:
// a wiring error, answered 500.
var errNoAPITokenService = errors.New("admin: no api token service configured")

// tokenError maps an error of the token service to the error the strict
// handler renders. Server errors keep their cause, which is logged (the
// service never puts a secret or a hash in it).
func tokenError(err error) error {
	var invalid *apitoken.InvalidError
	switch {
	case errors.As(err, &invalid):
		return validationFailed(invalid.Field, fieldInvalidFormat)
	case errors.Is(err, apitoken.ErrInvalidInput):
		return problem.New(problem.CodeValidationFailed)
	case errors.Is(err, apitoken.ErrStateConflict):
		return problem.New(problem.CodeStateConflict)
	case errors.Is(err, apitoken.ErrUnauthenticated):
		return problem.New(problem.CodeUnauthenticated)
	case errors.Is(err, apitoken.ErrForbidden):
		return problem.New(problem.CodeForbidden)
	case errors.Is(err, apitoken.ErrNotFound):
		return problem.New(problem.CodeNotFound)
	default:
		return err
	}
}

// tokenSession returns the token service and the session of the request,
// or the error to answer.
func (s *Server) tokenSession(ctx context.Context) (APITokenService, adminauth.Principal, error) {
	if s.tokenSvc == nil {
		return nil, adminauth.Principal{}, errNoAPITokenService
	}
	p, err := principal(ctx)
	if err != nil {
		return nil, adminauth.Principal{}, err
	}
	return s.tokenSvc, p, nil
}

// ListApiTokens lists the API tokens of a tenant, revoked ones included,
// never their secrets.
func (s *Server) ListApiTokens(ctx context.Context, req gen.ListApiTokensRequestObject) (gen.ListApiTokensResponseObject, error) { //nolint:revive // method name set by the generated gen.StrictServerInterface
	svc, p, err := s.tokenSession(ctx)
	if err != nil {
		return nil, err
	}
	list, err := svc.List(ctx, p, tenant.ID(req.TenantId))
	if err != nil {
		return nil, tokenError(err)
	}
	resp := make(gen.ListApiTokens200JSONResponse, len(list))
	for i, t := range list {
		resp[i] = apiTokenBody(t)
	}
	return resp, nil
}

// CreateApiToken creates an API token (201). The secret is in this answer
// only; the admin router already marks every answer Cache-Control:
// no-store.
func (s *Server) CreateApiToken(ctx context.Context, req gen.CreateApiTokenRequestObject) (gen.CreateApiTokenResponseObject, error) { //nolint:revive // method name set by the generated gen.StrictServerInterface
	svc, p, err := s.tokenSession(ctx)
	if err != nil {
		return nil, err
	}
	// A missing body is checked by the service after the access, so that a
	// tenant the administrator may not change answers 404 whatever the body.
	var in apitoken.CreateInput
	if req.Body != nil {
		in = apitoken.CreateInput{
			Name: req.Body.Name, AllowedCIDRs: req.Body.AllowedCidrs, ExpiresAt: deref(req.Body.ExpiresAt),
		}
		if req.Body.AllowedSenders != nil {
			in.AllowedSenders = *req.Body.AllowedSenders
		}
	}
	c, err := svc.Create(ctx, p, tenant.ID(req.TenantId), in, middleware.ClientIP(ctx))
	if err != nil {
		return nil, tokenError(err)
	}
	t := apiTokenBody(c.Token)
	return gen.CreateApiToken201JSONResponse{
		Id: t.Id, Name: t.Name, Prefix: t.Prefix, AllowedCidrs: t.AllowedCidrs, AllowedSenders: t.AllowedSenders,
		CreatedBy: t.CreatedBy, CreatedAt: t.CreatedAt, LastUsedAt: t.LastUsedAt, ExpiresAt: t.ExpiresAt,
		RevokedAt: t.RevokedAt, Token: c.Secret,
	}, nil
}

// UpdateApiToken applies a JSON merge patch to an API token: absent fields
// are left unchanged, a list given replaces the current one (an empty
// allowedSenders lifts the sender restriction), and null on a field (none
// can be removed) or an unknown member is refused with 400
// validation-failed naming it. A revoked token answers 409.
func (s *Server) UpdateApiToken(ctx context.Context, req gen.UpdateApiTokenRequestObject) (gen.UpdateApiTokenResponseObject, error) { //nolint:revive // method name set by the generated gen.StrictServerInterface
	svc, p, err := s.tokenSession(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, validationFailed("", fieldRequired)
	}
	in, err := decodeAPITokenUpdate(*req.Body)
	if err != nil {
		return nil, err
	}
	t, err := svc.Update(ctx, p, tenant.ID(req.TenantId), req.TokenId, in, middleware.ClientIP(ctx))
	if err != nil {
		return nil, tokenError(err)
	}
	return gen.UpdateApiToken200JSONResponse(apiTokenBody(t)), nil
}

// RevokeApiToken revokes an API token (204, also when it was already
// revoked).
func (s *Server) RevokeApiToken(ctx context.Context, req gen.RevokeApiTokenRequestObject) (gen.RevokeApiTokenResponseObject, error) { //nolint:revive // method name set by the generated gen.StrictServerInterface
	svc, p, err := s.tokenSession(ctx)
	if err != nil {
		return nil, err
	}
	if err := svc.Revoke(ctx, p, tenant.ID(req.TenantId), req.TokenId, middleware.ClientIP(ctx)); err != nil {
		return nil, tokenError(err)
	}
	return gen.RevokeApiToken204Response{}, nil
}

// apiTokenPatch is the OpenAPI ApiTokenUpdate, decoded by the handler
// itself (the generated type is raw JSON) so that a null field can be told
// from an absent one.
type apiTokenPatch struct {
	Name           *string  `json:"name"`
	AllowedCIDRs   []string `json:"allowedCidrs"`
	AllowedSenders []string `json:"allowedSenders"`
}

// apiTokenPatchFields lists the members of a token merge patch, in the
// order their errors are reported.
var apiTokenPatchFields = []string{"name", "allowedCidrs", "allowedSenders"}

// decodeAPITokenUpdate decodes a token merge patch: a JSON object whose
// members are absent (unchanged) or set, never null. A body that is not an
// object answers validation-failed on the whole body (""). Unlike
// decodeTenantUpdate, an unknown member answers invalid-format on its
// pointer (the first one in sorted order; OpenAPI ApiTokenUpdate has
// additionalProperties false); a name longer than maxEchoedMemberLen bytes
// is not echoed, and the error names the whole body. Then null members
// answer one not-nullable entry each, and a member (or a list item) of the
// wrong type invalid-format on its pointer. An empty allowedCidrs or
// allowedSenders list decodes non-nil, so that the service refuses the
// first and clears the second rather than keeping them.
func decodeAPITokenUpdate(raw []byte) (apitoken.UpdateInput, error) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil || members == nil {
		return apitoken.UpdateInput{}, validationFailed("", fieldInvalidFormat)
	}
	if err := rejectUnknownMembers(members, apiTokenPatchFields); err != nil {
		return apitoken.UpdateInput{}, err
	}
	var nulls []problem.FieldError
	for _, name := range apiTokenPatchFields {
		if v, ok := members[name]; ok && bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			nulls = append(nulls, problem.FieldError{Field: "/" + name, Code: fieldNotNullable})
		}
	}
	if len(nulls) > 0 {
		return apitoken.UpdateInput{}, problem.New(problem.CodeValidationFailed, problem.WithFieldErrors(nulls...))
	}
	var b apiTokenPatch
	if err := json.Unmarshal(raw, &b); err != nil {
		field := ""
		var typeErr *json.UnmarshalTypeError
		if errors.As(err, &typeErr) {
			field = "/" + strings.ReplaceAll(typeErr.Field, ".", "/") // "allowedSenders.0": an item
		}
		return apitoken.UpdateInput{}, validationFailed(field, fieldInvalidFormat)
	}
	return apitoken.UpdateInput{Name: b.Name, AllowedCIDRs: b.AllowedCIDRs, AllowedSenders: b.AllowedSenders}, nil
}

// rejectUnknownMembers returns a 400 validation-failed Problem when
// members holds a member not in fields: invalid-format on the pointer of
// the first unknown member in sorted order, or on the whole body ("") when
// that name is longer than maxEchoedMemberLen bytes. It returns nil when
// every member is known.
func rejectUnknownMembers(members map[string]json.RawMessage, fields []string) error {
	var unknown []string
	for name := range members {
		if !slices.Contains(fields, name) {
			unknown = append(unknown, name)
		}
	}
	if len(unknown) == 0 {
		return nil
	}
	field := ""
	if name := slices.Min(unknown); len(name) <= maxEchoedMemberLen {
		field = "/" + pointerEscape(name)
	}
	return validationFailed(field, fieldInvalidFormat)
}

// maxEchoedMemberLen bounds the unknown member name echoed in a
// validation error, in bytes.
const maxEchoedMemberLen = 64

// pointerEscape escapes a member name as a JSON pointer token (RFC 6901).
func pointerEscape(name string) string {
	return strings.NewReplacer("~", "~0", "/", "~1").Replace(name)
}

// apiTokenBody renders t as the OpenAPI ApiToken: the allowed ranges in
// CIDR notation, and the dates never set absent.
func apiTokenBody(t store.APIToken) gen.ApiToken {
	cidrs := make([]string, len(t.AllowedCIDRs))
	for i, c := range t.AllowedCIDRs {
		cidrs[i] = c.String()
	}
	senders := t.AllowedSenders
	if senders == nil {
		senders = []string{}
	}
	return gen.ApiToken{
		Id: t.ID, Name: t.Name, Prefix: t.Prefix, AllowedCidrs: cidrs, AllowedSenders: senders,
		CreatedBy: t.CreatedBy, CreatedAt: t.CreatedAt,
		LastUsedAt: optionalTime(t.LastUsedAt), ExpiresAt: optionalTime(t.ExpiresAt), RevokedAt: optionalTime(t.RevokedAt),
	}
}
