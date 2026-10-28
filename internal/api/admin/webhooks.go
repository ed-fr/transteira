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
	"github.com/ed-fr/transteira/internal/events"
	"github.com/ed-fr/transteira/internal/httpserver/middleware"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/webhook"
	"github.com/ed-fr/transteira/internal/webhookadmin"
)

// WebhookService manages the webhooks of the tenants and of the instance
// (*webhookadmin.Service). Every method checks the principal itself, before
// validating the input (a creation body that is not valid JSON is still
// refused with 400 by the generated layer first; an update patch is decoded
// only after the check): a tenant the administrator is not attached to, a webhook of
// another tenant and an instance-wide webhook under a tenant (and the
// reverse) answer webhookadmin.ErrNotFound; an instance-wide operation by
// a delegated admin answers webhookadmin.ErrForbidden.
type WebhookService interface {
	ListTenant(ctx context.Context, p adminauth.Principal, tid tenant.ID) ([]store.Webhook, error)
	GetTenant(ctx context.Context, p adminauth.Principal, tid tenant.ID, whkID string) (store.Webhook, error)
	CreateTenant(ctx context.Context, p adminauth.Principal, tid tenant.ID, in webhookadmin.CreateInput, ip netip.Addr) (webhookadmin.Result, error)
	UpdateTenant(ctx context.Context, p adminauth.Principal, tid tenant.ID, whkID string, in webhookadmin.UpdateInput, ip netip.Addr) (webhookadmin.Result, error)
	DeleteTenant(ctx context.Context, p adminauth.Principal, tid tenant.ID, whkID string, ip netip.Addr) error
	TestTenant(ctx context.Context, p adminauth.Principal, tid tenant.ID, whkID string, ip netip.Addr) (webhook.Result, error)
	ListSystem(ctx context.Context, p adminauth.Principal) ([]store.Webhook, error)
	GetSystem(ctx context.Context, p adminauth.Principal, whkID string) (store.Webhook, error)
	CreateSystem(ctx context.Context, p adminauth.Principal, in webhookadmin.CreateInput, ip netip.Addr) (webhookadmin.Result, error)
	UpdateSystem(ctx context.Context, p adminauth.Principal, whkID string, in webhookadmin.UpdateInput, ip netip.Addr) (webhookadmin.Result, error)
	DeleteSystem(ctx context.Context, p adminauth.Principal, whkID string, ip netip.Addr) error
	TestSystem(ctx context.Context, p adminauth.Principal, whkID string, ip netip.Addr) (webhook.Result, error)
}

// Compile-time check that the webhook service fits.
var _ WebhookService = (*webhookadmin.Service)(nil)

// WithWebhookService serves the webhook operations with svc. Without it
// they answer 500.
func WithWebhookService(svc WebhookService) Option {
	return func(s *Server) { s.webhookSvc = svc }
}

// errNoWebhookService reports a server built without WithWebhookService:
// a wiring error, answered 500.
var errNoWebhookService = errors.New("admin: no webhook service configured")

// webhookError maps an error of the webhook service to the error the
// strict handler renders. Server errors keep their cause, which is logged
// (the service never puts a URL or a secret in it).
func webhookError(err error) error {
	var (
		invalid *webhookadmin.InvalidError
		limited *webhookadmin.RateLimitError
	)
	switch {
	case errors.As(err, &invalid):
		return validationFailed(invalid.Field, invalid.Code)
	case errors.As(err, &limited):
		return problem.New(problem.CodeRateLimited, problem.WithRetryAfter(limited.RetryAfter))
	case errors.Is(err, webhookadmin.ErrLimitReached), errors.Is(err, webhookadmin.ErrConflict):
		return problem.New(problem.CodeStateConflict)
	case errors.Is(err, webhookadmin.ErrUnauthenticated):
		return problem.New(problem.CodeUnauthenticated)
	case errors.Is(err, webhookadmin.ErrForbidden):
		return problem.New(problem.CodeForbidden)
	case errors.Is(err, webhookadmin.ErrNotFound):
		return problem.New(problem.CodeNotFound)
	default:
		return err
	}
}

// webhookSession returns the webhook service and the session of the
// request, or the error to answer.
func (s *Server) webhookSession(ctx context.Context) (WebhookService, adminauth.Principal, error) {
	if s.webhookSvc == nil {
		return nil, adminauth.Principal{}, errNoWebhookService
	}
	p, err := principal(ctx)
	if err != nil {
		return nil, adminauth.Principal{}, err
	}
	return s.webhookSvc, p, nil
}

// ListTenantWebhooks lists the webhooks of a tenant, never their URLs in
// full nor their secrets.
func (s *Server) ListTenantWebhooks(ctx context.Context, req gen.ListTenantWebhooksRequestObject) (gen.ListTenantWebhooksResponseObject, error) {
	svc, p, err := s.webhookSession(ctx)
	if err != nil {
		return nil, err
	}
	list, err := svc.ListTenant(ctx, p, tenant.ID(req.TenantId))
	if err != nil {
		return nil, webhookError(err)
	}
	return gen.ListTenantWebhooks200JSONResponse(s.webhookList(list)), nil
}

// CreateTenantWebhook creates a webhook of a tenant (201); the secret of a
// generic webhook is in this answer only (the admin router marks every
// answer Cache-Control: no-store).
func (s *Server) CreateTenantWebhook(ctx context.Context, req gen.CreateTenantWebhookRequestObject) (gen.CreateTenantWebhookResponseObject, error) {
	svc, p, err := s.webhookSession(ctx)
	if err != nil {
		return nil, err
	}
	res, err := svc.CreateTenant(ctx, p, tenant.ID(req.TenantId), webhookCreateInput(req.Body), middleware.ClientIP(ctx))
	if err != nil {
		return nil, webhookError(err)
	}
	return gen.CreateTenantWebhook201JSONResponse(s.webhookWithSecret(res)), nil
}

// GetTenantWebhook returns one webhook of a tenant.
func (s *Server) GetTenantWebhook(ctx context.Context, req gen.GetTenantWebhookRequestObject) (gen.GetTenantWebhookResponseObject, error) {
	svc, p, err := s.webhookSession(ctx)
	if err != nil {
		return nil, err
	}
	w, err := svc.GetTenant(ctx, p, tenant.ID(req.TenantId), req.WebhookId)
	if err != nil {
		return nil, webhookError(err)
	}
	return gen.GetTenantWebhook200JSONResponse(s.webhookBody(w)), nil
}

// UpdateTenantWebhook applies a JSON merge patch to a webhook of a tenant:
// absent members are left unchanged, null and unknown members are refused
// with 400 validation-failed naming them, once the access to the tenant
// is checked. The answer carries the new secret after a rotation only.
func (s *Server) UpdateTenantWebhook(ctx context.Context, req gen.UpdateTenantWebhookRequestObject) (gen.UpdateTenantWebhookResponseObject, error) {
	svc, p, err := s.webhookSession(ctx)
	if err != nil {
		return nil, err
	}
	if err := webhookPrecheck(p, tenant.ID(req.TenantId)); err != nil {
		return nil, err
	}
	in, err := decodeWebhookPatch(req.Body)
	if err != nil {
		return nil, err
	}
	res, err := svc.UpdateTenant(ctx, p, tenant.ID(req.TenantId), req.WebhookId, in, middleware.ClientIP(ctx))
	if err != nil {
		return nil, webhookError(err)
	}
	return gen.UpdateTenantWebhook200JSONResponse(s.webhookWithSecret(res)), nil
}

// DeleteTenantWebhook deletes a webhook of a tenant (204), destroying its
// sealed URL and secret.
func (s *Server) DeleteTenantWebhook(ctx context.Context, req gen.DeleteTenantWebhookRequestObject) (gen.DeleteTenantWebhookResponseObject, error) {
	svc, p, err := s.webhookSession(ctx)
	if err != nil {
		return nil, err
	}
	if err := svc.DeleteTenant(ctx, p, tenant.ID(req.TenantId), req.WebhookId, middleware.ClientIP(ctx)); err != nil {
		return nil, webhookError(err)
	}
	return gen.DeleteTenantWebhook204Response{}, nil
}

// TestTenantWebhook sends a test event to a webhook of a tenant and
// returns the outcome, with a coarse error category only.
func (s *Server) TestTenantWebhook(ctx context.Context, req gen.TestTenantWebhookRequestObject) (gen.TestTenantWebhookResponseObject, error) {
	svc, p, err := s.webhookSession(ctx)
	if err != nil {
		return nil, err
	}
	res, err := svc.TestTenant(ctx, p, tenant.ID(req.TenantId), req.WebhookId, middleware.ClientIP(ctx))
	if err != nil {
		return nil, webhookError(err)
	}
	return gen.TestTenantWebhook200JSONResponse(webhookTestBody(res)), nil
}

// ListSystemWebhooks lists the instance-wide webhooks (super admin).
func (s *Server) ListSystemWebhooks(ctx context.Context, _ gen.ListSystemWebhooksRequestObject) (gen.ListSystemWebhooksResponseObject, error) {
	svc, p, err := s.webhookSession(ctx)
	if err != nil {
		return nil, err
	}
	list, err := svc.ListSystem(ctx, p)
	if err != nil {
		return nil, webhookError(err)
	}
	return gen.ListSystemWebhooks200JSONResponse(s.webhookList(list)), nil
}

// CreateSystemWebhook creates an instance-wide webhook (super admin, 201).
func (s *Server) CreateSystemWebhook(ctx context.Context, req gen.CreateSystemWebhookRequestObject) (gen.CreateSystemWebhookResponseObject, error) {
	svc, p, err := s.webhookSession(ctx)
	if err != nil {
		return nil, err
	}
	res, err := svc.CreateSystem(ctx, p, webhookCreateInput(req.Body), middleware.ClientIP(ctx))
	if err != nil {
		return nil, webhookError(err)
	}
	return gen.CreateSystemWebhook201JSONResponse(s.webhookWithSecret(res)), nil
}

// GetSystemWebhook returns one instance-wide webhook (super admin).
func (s *Server) GetSystemWebhook(ctx context.Context, req gen.GetSystemWebhookRequestObject) (gen.GetSystemWebhookResponseObject, error) {
	svc, p, err := s.webhookSession(ctx)
	if err != nil {
		return nil, err
	}
	w, err := svc.GetSystem(ctx, p, req.WebhookId)
	if err != nil {
		return nil, webhookError(err)
	}
	return gen.GetSystemWebhook200JSONResponse(s.webhookBody(w)), nil
}

// UpdateSystemWebhook applies a JSON merge patch to an instance-wide
// webhook (super admin), like UpdateTenantWebhook. The role is checked
// before the patch is decoded.
func (s *Server) UpdateSystemWebhook(ctx context.Context, req gen.UpdateSystemWebhookRequestObject) (gen.UpdateSystemWebhookResponseObject, error) {
	svc, p, err := s.webhookSession(ctx)
	if err != nil {
		return nil, err
	}
	if err := webhookPrecheck(p, ""); err != nil {
		return nil, err
	}
	in, err := decodeWebhookPatch(req.Body)
	if err != nil {
		return nil, err
	}
	res, err := svc.UpdateSystem(ctx, p, req.WebhookId, in, middleware.ClientIP(ctx))
	if err != nil {
		return nil, webhookError(err)
	}
	return gen.UpdateSystemWebhook200JSONResponse(s.webhookWithSecret(res)), nil
}

// DeleteSystemWebhook deletes an instance-wide webhook (super admin, 204).
func (s *Server) DeleteSystemWebhook(ctx context.Context, req gen.DeleteSystemWebhookRequestObject) (gen.DeleteSystemWebhookResponseObject, error) {
	svc, p, err := s.webhookSession(ctx)
	if err != nil {
		return nil, err
	}
	if err := svc.DeleteSystem(ctx, p, req.WebhookId, middleware.ClientIP(ctx)); err != nil {
		return nil, webhookError(err)
	}
	return gen.DeleteSystemWebhook204Response{}, nil
}

// TestSystemWebhook sends a test event to an instance-wide webhook (super
// admin).
func (s *Server) TestSystemWebhook(ctx context.Context, req gen.TestSystemWebhookRequestObject) (gen.TestSystemWebhookResponseObject, error) {
	svc, p, err := s.webhookSession(ctx)
	if err != nil {
		return nil, err
	}
	res, err := svc.TestSystem(ctx, p, req.WebhookId, middleware.ClientIP(ctx))
	if err != nil {
		return nil, webhookError(err)
	}
	return gen.TestSystemWebhook200JSONResponse(webhookTestBody(res)), nil
}

// webhookPrecheck checks, before a merge patch is decoded, that p may
// change the webhooks of tenant tid ("" for the instance-wide webhooks),
// so that a malformed patch never tells a reachable tenant from another
// one; the service checks again, with the state of the tenant.
func webhookPrecheck(p adminauth.Principal, tid tenant.ID) error {
	err := adminauth.RequireAuthenticated(p)
	switch {
	case err != nil:
	case tid == "":
		err = adminauth.RequireSuperAdmin(p.Admin)
	default:
		err = adminauth.RequireTenantWrite(p.Admin, tid)
	}
	return webhookError(err)
}

// webhookCreateInput converts a creation body; a missing body gives an
// empty input, refused by the service after the access check.
func webhookCreateInput(b *gen.WebhookCreate) webhookadmin.CreateInput {
	if b == nil {
		return webhookadmin.CreateInput{}
	}
	evs := make([]events.Type, len(b.Events))
	for i, e := range b.Events {
		evs[i] = events.Type(e)
	}
	return webhookadmin.CreateInput{
		Name: b.Name, Kind: store.WebhookKind(b.Kind), URL: b.Url, Events: evs, Enabled: b.Enabled,
	}
}

// webhookPatch is the OpenAPI WebhookUpdate, decoded by the handler itself
// (the generated type is raw JSON) so that a null member can be told from
// an absent one.
type webhookPatch struct {
	Name         *string  `json:"name"`
	URL          *string  `json:"url"`
	Events       []string `json:"events"`
	Enabled      *bool    `json:"enabled"`
	RotateSecret *bool    `json:"rotateSecret"`
}

// webhookPatchFields lists the members of a webhook merge patch, in the
// order their errors are reported.
var webhookPatchFields = []string{"name", "url", "events", "enabled", "rotateSecret"}

// decodeWebhookPatch decodes a webhook merge patch like
// decodeAPITokenUpdate: a missing body answers required on the whole body,
// a body that is not an object invalid-format on it, an unknown member
// invalid-format on its pointer, null members one not-nullable entry each
// and a member (or an event) of the wrong type invalid-format on its
// pointer. An empty events list decodes non-nil, so that the service
// refuses it rather than keeping the events.
func decodeWebhookPatch(body *gen.WebhookUpdate) (webhookadmin.UpdateInput, error) {
	if body == nil {
		return webhookadmin.UpdateInput{}, validationFailed("", fieldRequired)
	}
	raw := []byte(*body)
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil || members == nil {
		return webhookadmin.UpdateInput{}, validationFailed("", fieldInvalidFormat)
	}
	if err := rejectUnknownMembers(members, webhookPatchFields); err != nil {
		return webhookadmin.UpdateInput{}, err
	}
	var nulls []problem.FieldError
	for _, name := range webhookPatchFields {
		if v, ok := members[name]; ok && bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			nulls = append(nulls, problem.FieldError{Field: "/" + name, Code: fieldNotNullable})
		}
	}
	if len(nulls) > 0 {
		return webhookadmin.UpdateInput{}, problem.New(problem.CodeValidationFailed, problem.WithFieldErrors(nulls...))
	}
	var b webhookPatch
	if err := json.Unmarshal(raw, &b); err != nil {
		field := ""
		var typeErr *json.UnmarshalTypeError
		if errors.As(err, &typeErr) {
			field = "/" + strings.ReplaceAll(typeErr.Field, ".", "/") // "events.0": an item
		}
		return webhookadmin.UpdateInput{}, validationFailed(field, fieldInvalidFormat)
	}
	in := webhookadmin.UpdateInput{Name: b.Name, URL: b.URL, Enabled: b.Enabled, RotateSecret: deref(b.RotateSecret)}
	if b.Events != nil {
		in.Events = make([]events.Type, len(b.Events))
		for i, e := range b.Events {
			in.Events[i] = events.Type(e)
		}
	}
	return in, nil
}

// webhookList renders a list of webhooks, never null.
func (s *Server) webhookList(list []store.Webhook) []gen.Webhook {
	out := make([]gen.Webhook, len(list))
	for i, w := range list {
		out[i] = s.webhookBody(w)
	}
	return out
}

// webhookBody renders w as the OpenAPI Webhook: the URL hint only, the last
// delivery or null, and the end of the circuit breaker suspension or null
// once it has passed.
func (s *Server) webhookBody(w store.Webhook) gen.Webhook {
	evs := make([]gen.WebhookEventType, len(w.Events))
	for i, e := range w.Events {
		evs[i] = gen.WebhookEventType(e)
	}
	out := gen.Webhook{
		Id: w.ID, Name: w.Name, Kind: gen.WebhookKind(w.Kind), UrlHint: w.URLHint, Events: evs, Enabled: w.Enabled,
		HasSecret: w.HasSecret(), CreatedBy: w.CreatedBy, CreatedAt: w.CreatedAt, UpdatedAt: w.UpdatedAt,
	}
	if d := w.LastDelivery; !d.At.IsZero() {
		out.LastDelivery = &gen.WebhookDelivery{
			At: d.At, Success: d.Success, DurationMs: int(d.Duration / time.Millisecond),
			HttpStatus: optionalStatus(d.HTTPStatus), ErrorCategory: optionalCategory(d.ErrorCategory),
		}
	}
	if w.CircuitOpenUntil.After(s.now()) {
		out.CircuitOpenUntil = optionalTime(w.CircuitOpenUntil)
	}
	return out
}

// webhookWithSecret renders the result of a creation or an update as the
// OpenAPI WebhookWithSecret, with the secret when one was generated.
func (s *Server) webhookWithSecret(res webhookadmin.Result) gen.WebhookWithSecret {
	w := s.webhookBody(res.Webhook)
	return gen.WebhookWithSecret{
		Id: w.Id, Name: w.Name, Kind: w.Kind, UrlHint: w.UrlHint, Events: w.Events, Enabled: w.Enabled,
		HasSecret: w.HasSecret, CreatedBy: w.CreatedBy, CreatedAt: w.CreatedAt, UpdatedAt: w.UpdatedAt,
		LastDelivery: w.LastDelivery, CircuitOpenUntil: w.CircuitOpenUntil, Secret: optional(res.Secret),
	}
}

// webhookTestBody renders the outcome of a test as the OpenAPI
// WebhookTestResult.
func webhookTestBody(r webhook.Result) gen.WebhookTestResult {
	return gen.WebhookTestResult{
		Success: r.Success, DurationMs: int(r.Duration / time.Millisecond),
		HttpStatus: optionalStatus(r.HTTPStatus), ErrorCategory: optionalCategory(string(r.Category)),
	}
}

// optionalStatus returns a pointer to an HTTP status, nil for none.
func optionalStatus(status int) *int {
	if status == 0 {
		return nil
	}
	return &status
}

// optionalCategory returns a pointer to an error category, nil for none.
func optionalCategory(c string) *gen.WebhookErrorCategory {
	if c == "" {
		return nil
	}
	v := gen.WebhookErrorCategory(c)
	return &v
}
