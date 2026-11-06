package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/droplink"
	"github.com/ed-fr/transteira/internal/httpserver/middleware"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// DropLinkService manages the permanent drop links of the tenants
// (*droplink.Service). Every method checks the principal itself: a tenant
// the administrator is not attached to, and a link of another tenant,
// answer droplink.ErrNotFound, like an unknown one.
type DropLinkService interface {
	List(ctx context.Context, p adminauth.Principal, tid tenant.ID) ([]store.DropLink, error)
	Get(ctx context.Context, p adminauth.Principal, tid tenant.ID, linkID string) (store.DropLink, error)
	Create(ctx context.Context, p adminauth.Principal, tid tenant.ID, in droplink.CreateInput, ip netip.Addr) (droplink.Created, error)
	Update(ctx context.Context, p adminauth.Principal, tid tenant.ID, linkID string, in droplink.UpdateInput, ip netip.Addr) (store.DropLink, error)
	Rotate(ctx context.Context, p adminauth.Principal, tid tenant.ID, linkID string, ip netip.Addr) (droplink.Created, error)
	Revoke(ctx context.Context, p adminauth.Principal, tid tenant.ID, linkID string, ip netip.Addr) error
}

// Compile-time check that the drop link service fits.
var _ DropLinkService = (*droplink.Service)(nil)

// WithDropLinkService serves the drop link operations with svc. Without it
// they answer 500.
func WithDropLinkService(svc DropLinkService) Option {
	return func(s *Server) { s.dropLinkSvc = svc }
}

// errNoDropLinkService reports a server built without WithDropLinkService:
// a wiring error, answered 500.
var errNoDropLinkService = errors.New("admin: no drop link service configured")

// dropLinkError maps an error of the drop link service to the error the
// strict handler renders. Server errors keep their cause, which is logged
// (the service never puts a token in it).
func dropLinkError(err error) error {
	var invalid *droplink.InvalidError
	switch {
	case errors.As(err, &invalid):
		return validationFailed(invalid.Field, fieldInvalidFormat)
	case errors.Is(err, droplink.ErrInvalidInput):
		return problem.New(problem.CodeValidationFailed)
	case errors.Is(err, droplink.ErrStateConflict):
		return problem.New(problem.CodeStateConflict)
	case errors.Is(err, droplink.ErrLimitReached):
		return problem.New(problem.CodeDropLinkLimitReached)
	case errors.Is(err, droplink.ErrUnauthenticated):
		return problem.New(problem.CodeUnauthenticated)
	case errors.Is(err, adminauth.ErrReadOnlyRole):
		return problem.New(problem.CodeReadOnlyRole)
	case errors.Is(err, droplink.ErrForbidden):
		return problem.New(problem.CodeForbidden)
	case errors.Is(err, droplink.ErrNotFound):
		return problem.New(problem.CodeNotFound)
	default:
		return err
	}
}

// dropLinkSession returns the drop link service and the session of the
// request, or the error to answer.
func (s *Server) dropLinkSession(ctx context.Context) (DropLinkService, adminauth.Principal, error) {
	if s.dropLinkSvc == nil {
		return nil, adminauth.Principal{}, errNoDropLinkService
	}
	p, err := principal(ctx)
	if err != nil {
		return nil, adminauth.Principal{}, err
	}
	return s.dropLinkSvc, p, nil
}

// ListDropLinks lists the permanent drop links of a tenant, revoked ones
// included, never their tokens. An auditor may read.
func (s *Server) ListDropLinks(ctx context.Context, req gen.ListDropLinksRequestObject) (gen.ListDropLinksResponseObject, error) {
	svc, p, err := s.dropLinkSession(ctx)
	if err != nil {
		return nil, err
	}
	list, err := svc.List(ctx, p, tenant.ID(req.TenantId))
	if err != nil {
		return nil, dropLinkError(err)
	}
	items := make([]gen.DropLink, len(list))
	now := s.now()
	for i, l := range list {
		items[i] = dropLinkBody(l, now)
	}
	return gen.ListDropLinks200JSONResponse{Items: items}, nil
}

// CreateDropLink creates a permanent drop link (201). The token and the URL
// are in this answer only; the admin router already marks every answer
// Cache-Control: no-store.
func (s *Server) CreateDropLink(ctx context.Context, req gen.CreateDropLinkRequestObject) (gen.CreateDropLinkResponseObject, error) {
	svc, p, err := s.dropLinkSession(ctx)
	if err != nil {
		return nil, err
	}
	// A missing body is checked by the service after the access, so that a
	// tenant the administrator may not change answers 404 whatever the body.
	var in droplink.CreateInput
	if req.Body != nil {
		in = droplink.CreateInput{
			Label: req.Body.Label, Recipients: req.Body.Recipients, ValidityDays: int(req.Body.ValidityDays),
			ConfidentialityLevel: deref(req.Body.ConfidentialityLevel), Enabled: req.Body.Enabled,
			ExpiresAt: req.Body.ExpiresAt, MaxDepositsPerHour: req.Body.MaxDepositsPerHour,
		}
	}
	c, err := svc.Create(ctx, p, tenant.ID(req.TenantId), in, middleware.ClientIP(ctx))
	if err != nil {
		return nil, dropLinkError(err)
	}
	return gen.CreateDropLink201JSONResponse(dropLinkCreatedBody(c, s.now())), nil
}

// GetDropLink returns one permanent drop link, without its token. An
// auditor may read.
func (s *Server) GetDropLink(ctx context.Context, req gen.GetDropLinkRequestObject) (gen.GetDropLinkResponseObject, error) {
	svc, p, err := s.dropLinkSession(ctx)
	if err != nil {
		return nil, err
	}
	l, err := svc.Get(ctx, p, tenant.ID(req.TenantId), req.DropLinkId)
	if err != nil {
		return nil, dropLinkError(err)
	}
	return gen.GetDropLink200JSONResponse(dropLinkBody(l, s.now())), nil
}

// UpdateDropLink applies a JSON merge patch to a drop link: absent members
// are left unchanged, a list given replaces the current one, null on
// confidentialityLevel selects the tenant default level, null on expiresAt
// removes the expiry, and null on any other member or an unknown member is
// refused with 400 validation-failed naming it. A revoked link answers 409.
func (s *Server) UpdateDropLink(ctx context.Context, req gen.UpdateDropLinkRequestObject) (gen.UpdateDropLinkResponseObject, error) {
	svc, p, err := s.dropLinkSession(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, validationFailed("", fieldRequired)
	}
	in, err := decodeDropLinkUpdate(*req.Body)
	if err != nil {
		return nil, err
	}
	l, err := svc.Update(ctx, p, tenant.ID(req.TenantId), req.DropLinkId, in, middleware.ClientIP(ctx))
	if err != nil {
		return nil, dropLinkError(err)
	}
	return gen.UpdateDropLink200JSONResponse(dropLinkBody(l, s.now())), nil
}

// DeleteDropLink revokes a drop link (204, also when it was already
// revoked).
func (s *Server) DeleteDropLink(ctx context.Context, req gen.DeleteDropLinkRequestObject) (gen.DeleteDropLinkResponseObject, error) {
	svc, p, err := s.dropLinkSession(ctx)
	if err != nil {
		return nil, err
	}
	if err := svc.Revoke(ctx, p, tenant.ID(req.TenantId), req.DropLinkId, middleware.ClientIP(ctx)); err != nil {
		return nil, dropLinkError(err)
	}
	return gen.DeleteDropLink204Response{}, nil
}

// RotateDropLink replaces the token of a drop link (200) and returns the
// new token and URL, once. A revoked link answers 409.
func (s *Server) RotateDropLink(ctx context.Context, req gen.RotateDropLinkRequestObject) (gen.RotateDropLinkResponseObject, error) {
	svc, p, err := s.dropLinkSession(ctx)
	if err != nil {
		return nil, err
	}
	c, err := svc.Rotate(ctx, p, tenant.ID(req.TenantId), req.DropLinkId, middleware.ClientIP(ctx))
	if err != nil {
		return nil, dropLinkError(err)
	}
	return gen.RotateDropLink200JSONResponse(dropLinkCreatedBody(c, s.now())), nil
}

// dropLinkPatch is the OpenAPI DropLinkUpdate, decoded by the handler
// itself (the generated type is raw JSON) so that a null member can be told
// from an absent one. confidentialityLevel and expiresAt are read apart.
type dropLinkPatch struct {
	Label              *string  `json:"label"`
	Recipients         []string `json:"recipients"`
	ValidityDays       *int     `json:"validityDays"`
	Enabled            *bool    `json:"enabled"`
	MaxDepositsPerHour *int     `json:"maxDepositsPerHour"`
}

// dropLinkPatchFields lists the members of a drop link merge patch, in the
// order their errors are reported.
var dropLinkPatchFields = []string{
	"label", "recipients", "validityDays", "confidentialityLevel", "enabled", "expiresAt", "maxDepositsPerHour",
}

// dropLinkNullable lists the members of a drop link merge patch that accept
// null.
var dropLinkNullable = map[string]bool{"confidentialityLevel": true, "expiresAt": true}

// decodeDropLinkUpdate decodes a drop link merge patch, like
// decodeAPITokenUpdate: a body that is not an object answers
// validation-failed on the whole body; an unknown member answers
// invalid-format on its pointer; null members other than
// confidentialityLevel and expiresAt answer one not-nullable entry each; a
// member (or a list item) of the wrong type answers invalid-format on its
// pointer. A null or empty confidentialityLevel is the default level; a
// null expiresAt removes the expiry, which otherwise must be an RFC 3339
// time. An empty recipients list decodes non-nil, so that the service
// refuses it.
func decodeDropLinkUpdate(raw []byte) (droplink.UpdateInput, error) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil || members == nil {
		return droplink.UpdateInput{}, validationFailed("", fieldInvalidFormat)
	}
	if err := rejectUnknownMembers(members, dropLinkPatchFields); err != nil {
		return droplink.UpdateInput{}, err
	}
	var nulls []problem.FieldError
	for _, name := range dropLinkPatchFields {
		if v, ok := members[name]; ok && !dropLinkNullable[name] && bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			nulls = append(nulls, problem.FieldError{Field: "/" + name, Code: fieldNotNullable})
		}
	}
	if len(nulls) > 0 {
		return droplink.UpdateInput{}, problem.New(problem.CodeValidationFailed, problem.WithFieldErrors(nulls...))
	}
	var b dropLinkPatch
	if err := json.Unmarshal(raw, &b); err != nil {
		field := ""
		var typeErr *json.UnmarshalTypeError
		if errors.As(err, &typeErr) {
			field = "/" + strings.ReplaceAll(typeErr.Field, ".", "/") // "recipients.0": an item
		}
		return droplink.UpdateInput{}, validationFailed(field, fieldInvalidFormat)
	}
	in := droplink.UpdateInput{
		Label: b.Label, Recipients: b.Recipients, ValidityDays: b.ValidityDays, Enabled: b.Enabled,
		MaxDepositsPerHour: b.MaxDepositsPerHour,
	}
	if v, ok := members["expiresAt"]; ok {
		var at *time.Time
		// A non-null zero time would read as "no end": refused rather
		// than silently clearing the expiry.
		if err := json.Unmarshal(v, &at); err != nil || (at != nil && at.IsZero()) {
			return droplink.UpdateInput{}, validationFailed("/expiresAt", fieldInvalidFormat)
		}
		in.ExpiresSet = true
		if at != nil {
			in.ExpiresAt = *at
		}
	}
	if v, ok := members["confidentialityLevel"]; ok {
		var level *string
		if err := json.Unmarshal(v, &level); err != nil {
			return droplink.UpdateInput{}, validationFailed("/confidentialityLevel", fieldInvalidFormat)
		}
		in.LevelSet = true
		in.ConfidentialityLevel = deref(level)
	}
	return in, nil
}

// dropLinkBody renders l as the OpenAPI DropLink at now: the level and the
// dates never set absent, unused computed by [droplink.Unused].
func dropLinkBody(l store.DropLink, now time.Time) gen.DropLink {
	unused := droplink.Unused(l, now)
	return gen.DropLink{
		Id: l.ID, Label: l.Label, Recipients: nonNil(l.Recipients), ValidityDays: gen.ExpiryDays(l.ValidityDays),
		ConfidentialityLevel: optional(l.ConfidentialityLevel), Enabled: l.Enabled, CreatedBy: l.CreatedBy,
		CreatedAt: l.CreatedAt, UpdatedAt: l.UpdatedAt,
		LastUsedAt: optionalTime(l.LastUsedAt), RevokedAt: optionalTime(l.RevokedAt),
		ExpiresAt: optionalTime(l.ExpiresAt), MaxDepositsPerHour: l.MaxDepositsPerHour, Unused: &unused,
	}
}

// dropLinkCreatedBody renders c as the OpenAPI DropLinkCreated at now: the
// link with its token and URL.
func dropLinkCreatedBody(c droplink.Created, now time.Time) gen.DropLinkCreated {
	b := dropLinkBody(c.Link, now)
	return gen.DropLinkCreated{
		Id: b.Id, Label: b.Label, Recipients: b.Recipients, ValidityDays: b.ValidityDays,
		ConfidentialityLevel: b.ConfidentialityLevel, Enabled: b.Enabled, CreatedBy: b.CreatedBy,
		CreatedAt: b.CreatedAt, UpdatedAt: b.UpdatedAt, LastUsedAt: b.LastUsedAt, RevokedAt: b.RevokedAt,
		ExpiresAt: b.ExpiresAt, MaxDepositsPerHour: b.MaxDepositsPerHour, Unused: b.Unused,
		Token: c.Token, Url: c.URL,
	}
}

// nonNil returns s, or an empty list for nil: the JSON members are arrays,
// never null.
func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
