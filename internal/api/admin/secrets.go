package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/httpserver/middleware"
	"github.com/ed-fr/transteira/internal/secret"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/tenantadmin"
	"github.com/ed-fr/transteira/internal/tenantops"
)

// ListTenantSecrets lists the one-time secrets of a tenant (since 2.1),
// most recent first, metadata only. An auditor may list, without the
// creator filter.
func (s *Server) ListTenantSecrets(ctx context.Context, req gen.ListTenantSecretsRequestObject) (gen.ListTenantSecretsResponseObject, error) {
	svc, p, err := s.opsSession(ctx)
	if err != nil {
		return nil, err
	}
	f := tenantops.SecretFilter{
		State: string(deref(req.Params.State)), Sender: string(deref(req.Params.Sender)),
		Cursor: deref(req.Params.Cursor), Limit: deref(req.Params.Limit),
	}
	page, err := svc.ListSecrets(ctx, p, tenant.ID(req.TenantId), f)
	if err != nil {
		return nil, operationError(err)
	}
	resp := gen.ListTenantSecrets200JSONResponse{Items: make([]gen.AdminSecret, len(page.Items)), NextCursor: nextCursor(page.NextCursor)}
	for i, sec := range page.Items {
		resp.Items[i] = adminSecretBody(sec)
	}
	return resp, nil
}

// DeleteTenantSecret deletes a pending or active secret (204, also when it
// had already ended).
func (s *Server) DeleteTenantSecret(ctx context.Context, req gen.DeleteTenantSecretRequestObject) (gen.DeleteTenantSecretResponseObject, error) {
	svc, p, err := s.opsSession(ctx)
	if err != nil {
		return nil, err
	}
	if err := svc.DeleteSecret(ctx, p, tenant.ID(req.TenantId), req.SecretId, middleware.ClientIP(ctx)); err != nil {
		return nil, operationError(err)
	}
	return gen.DeleteTenantSecret204Response{}, nil
}

// adminSecretBody renders sec as the OpenAPI AdminSecret: metadata only.
// Both deletion reasons are the API reason "deleted" (the audit entry tells
// the actor).
// Since 2.3 it says whether the secret is an express secret, which has no
// creator address (senderEmail absent, creatorKind anonymous or
// api_token).
func adminSecretBody(sec store.Secret) gen.AdminSecret {
	out := gen.AdminSecret{
		Id: sec.ID, State: gen.SecretState(sec.State), CreatorKind: gen.AdminSecretCreatorKind(sec.CreatorKind),
		SenderEmail: optional(sec.SenderEmail), Delivery: gen.AdminSecretDelivery(sec.Delivery), ReadReceipt: sec.ReadReceipt,
		HasFile: sec.FileSize > 0, CreatedAt: sec.CreatedAt.UTC(), Express: new(sec.Express),
		ExpiresAt: optionalTime(sec.ExpiresAt.UTC()), ReadAt: optionalTime(sec.ReadAt.UTC()), EndedAt: optionalTime(sec.EndedAt.UTC()),
	}
	if sec.RecipientEmail != "" {
		out.Recipient = &sec.RecipientEmail
	}
	if sec.FileSize > 0 {
		out.FileSize = &sec.FileSize
	}
	if sec.EndReason != "" {
		out.EndReason = new(gen.AdminSecretEndReason(secret.APIReason(sec.EndReason)))
	}
	return out
}

// GetSecretSettings returns the one-time secrets settings of a tenant
// (since 2.1): configuration, closed to the auditor.
func (s *Server) GetSecretSettings(ctx context.Context, req gen.GetSecretSettingsRequestObject) (gen.GetSecretSettingsResponseObject, error) {
	svc, p, err := s.tenantSession(ctx)
	if err != nil {
		return nil, err
	}
	in, err := svc.GetSecretSettings(ctx, p, tenant.ID(req.TenantId))
	if err != nil {
		return nil, tenantError(err)
	}
	return gen.GetSecretSettings200JSONResponse(secretSettingsBody(in)), nil
}

// secretSettingsMembers lists the members the SecretSettings schema
// requires, none of which may be null.
var secretSettingsMembers = []bodyMember{
	{"enabled", false}, {"durations", false}, {"fileAllowed", false}, {"fileMaxBytes", false}, {"emailAllowed", false},
}

// expressSettingsMembers lists the members of the express secrets in the
// SecretSettings schema (since 2.3): optional in a replacement (absent
// keeps the stored value), never null.
var expressSettingsMembers = []string{"expressEnabled", "expressPerHourPerIp", "expressPerHourPerToken", "expressMaxPending"}

// checkSecretSettingsBody checks the raw body of a secret settings
// replacement: every required member present and not null
// (secretSettingsMembers), and no express member null
// (expressSettingsMembers), each one named.
func checkSecretSettingsBody(raw []byte) error {
	if err := checkMembers(raw, secretSettingsMembers); err != nil {
		return err
	}
	var members map[string]json.RawMessage
	_ = json.Unmarshal(raw, &members) // a JSON object: checkMembers decoded it
	var errs []problem.FieldError
	for _, name := range expressSettingsMembers {
		if v, ok := members[name]; ok && bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			errs = append(errs, problem.FieldError{Field: "/" + name, Code: fieldNotNullable})
		}
	}
	if len(errs) > 0 {
		return problem.New(problem.CodeValidationFailed, problem.WithFieldErrors(errs...))
	}
	return nil
}

// errNoSecretSettingsBody reports a server built without CaptureRawBody:
// a wiring error, answered 500.
var errNoSecretSettingsBody = errors.New("admin: raw body of the secret settings missing (CaptureRawBody not installed)")

// UpdateSecretSettings replaces the one-time secrets settings of a tenant
// (since 2.1) and returns them. Every required member must be present (a
// missing boolean would silently become false), and the members of the
// express secrets (since 2.3), optional, must not be null: the raw body
// kept by CaptureRawBody is checked, after the access to the tenant is
// probed. An absent express member keeps its stored value.
func (s *Server) UpdateSecretSettings(ctx context.Context, req gen.UpdateSecretSettingsRequestObject) (gen.UpdateSecretSettingsResponseObject, error) {
	svc, p, err := s.tenantSession(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, validationFailed(tenantadmin.FieldDurations, fieldRequired)
	}
	raw, ok := ctx.Value(rawBodyKey{}).([]byte)
	if !ok {
		return nil, errNoSecretSettingsBody
	}
	if err := checkSecretSettingsBody(raw); err != nil {
		// A tenant the administrator cannot reach answers 404 whatever the
		// body.
		if _, perr := svc.GetSecretSettings(ctx, p, tenant.ID(req.TenantId)); perr != nil {
			return nil, tenantError(perr)
		}
		return nil, err
	}
	b := req.Body
	in := tenantadmin.SecretSettingsInput{
		Enabled: b.Enabled, Durations: make([]string, len(b.Durations)), DefaultDuration: string(deref(b.DefaultDuration)),
		FileAllowed: b.FileAllowed, FileMaxBytes: b.FileMaxBytes, EmailAllowed: b.EmailAllowed,
		EmailRequiresPassphrase: deref(b.EmailRequiresPassphrase),
		ExpressEnabled:          b.ExpressEnabled, ExpressPerHourPerIP: b.ExpressPerHourPerIp,
		ExpressPerHourPerToken: b.ExpressPerHourPerToken, ExpressMaxPending: b.ExpressMaxPending,
	}
	for i, d := range b.Durations {
		in.Durations[i] = string(d)
	}
	out, err := svc.UpdateSecretSettings(ctx, p, tenant.ID(req.TenantId), in, middleware.ClientIP(ctx))
	if err != nil {
		return nil, tenantError(err)
	}
	return gen.UpdateSecretSettings200JSONResponse(secretSettingsBody(out)), nil
}

// secretSettingsBody renders in as the OpenAPI SecretSettings, the
// express members as the service set them (always, since 2.3).
func secretSettingsBody(in tenantadmin.SecretSettingsInput) gen.SecretSettings {
	out := gen.SecretSettings{
		Enabled: in.Enabled, Durations: make([]gen.SecretDuration, len(in.Durations)), FileAllowed: in.FileAllowed,
		FileMaxBytes: in.FileMaxBytes, EmailAllowed: in.EmailAllowed, EmailRequiresPassphrase: new(in.EmailRequiresPassphrase),
		ExpressEnabled: in.ExpressEnabled, ExpressPerHourPerIp: in.ExpressPerHourPerIP,
		ExpressPerHourPerToken: in.ExpressPerHourPerToken, ExpressMaxPending: in.ExpressMaxPending,
	}
	for i, d := range in.Durations {
		out.Durations[i] = gen.SecretDuration(d)
	}
	if in.DefaultDuration != "" {
		out.DefaultDuration = new(gen.SecretDuration(in.DefaultDuration))
	}
	return out
}
