package admin

import (
	"context"

	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/httpserver/middleware"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/tenantadmin"
)

// --- Confidentiality levels --------------------------------------------------

// GetConfidentialityLevels returns the confidentiality levels of a tenant.
func (s *Server) GetConfidentialityLevels(ctx context.Context, req gen.GetConfidentialityLevelsRequestObject) (gen.GetConfidentialityLevelsResponseObject, error) {
	svc, p, err := s.tenantSession(ctx)
	if err != nil {
		return nil, err
	}
	levels, err := svc.GetConfidentialityLevels(ctx, p, tenant.ID(req.TenantId))
	if err != nil {
		return nil, tenantError(err)
	}
	return gen.GetConfidentialityLevels200JSONResponse(levelListBody(levels)), nil
}

// UpdateConfidentialityLevels replaces the confidentiality levels of a
// tenant and returns them.
func (s *Server) UpdateConfidentialityLevels(ctx context.Context, req gen.UpdateConfidentialityLevelsRequestObject) (gen.UpdateConfidentialityLevelsResponseObject, error) {
	svc, p, err := s.tenantSession(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, validationFailed(tenantadmin.FieldLevels, fieldRequired)
	}
	in := make([]tenantadmin.ConfidentialityLevel, len(req.Body.Items))
	for i, l := range req.Body.Items {
		in[i] = tenantadmin.ConfidentialityLevel{
			Key: l.Key, Labels: l.Labels, Descriptions: deref(l.Descriptions), IsDefault: l.IsDefault,
			Rules: tenantadmin.ConfidentialityRules{
				AllowedExpiryDays: expiryDaysInts(l.Rules.AllowedExpiryDays), MaxDownloads: l.Rules.MaxDownloads,
				RequirePassword:               l.Rules.RequirePassword,
				RequireRecipientVerification:  l.Rules.RequireRecipientVerification,
				InternalRecipientsOnly:        l.Rules.InternalRecipientsOnly,
				ForceDeleteAfterFirstDownload: l.Rules.ForceDeleteAfterFirstDownload,
			},
		}
	}
	out, err := svc.UpdateConfidentialityLevels(ctx, p, tenant.ID(req.TenantId), in, middleware.ClientIP(ctx))
	if err != nil {
		return nil, tenantError(err)
	}
	return gen.UpdateConfidentialityLevels200JSONResponse(levelListBody(out)), nil
}

// expiryDaysInts converts the validities of the API to day counts.
func expiryDaysInts(days []gen.ExpiryDays) []int {
	out := make([]int, len(days))
	for i, d := range days {
		out[i] = int(d)
	}
	return out
}

// levelListBody renders levels as the OpenAPI ConfidentialityLevelList.
func levelListBody(levels []tenantadmin.ConfidentialityLevel) gen.ConfidentialityLevelList {
	items := make([]gen.ConfidentialityLevel, len(levels))
	for i, l := range levels {
		days := make([]gen.ExpiryDays, len(l.Rules.AllowedExpiryDays))
		for j, d := range l.Rules.AllowedExpiryDays {
			days[j] = gen.ExpiryDays(d)
		}
		descriptions := l.Descriptions
		if descriptions == nil {
			descriptions = map[string]string{}
		}
		items[i] = gen.ConfidentialityLevel{
			Key: l.Key, Labels: l.Labels, Descriptions: &descriptions, IsDefault: l.IsDefault,
			Rules: gen.ConfidentialityRules{
				AllowedExpiryDays: days, MaxDownloads: l.Rules.MaxDownloads,
				RequirePassword:               l.Rules.RequirePassword,
				RequireRecipientVerification:  l.Rules.RequireRecipientVerification,
				InternalRecipientsOnly:        l.Rules.InternalRecipientsOnly,
				ForceDeleteAfterFirstDownload: l.Rules.ForceDeleteAfterFirstDownload,
			},
		}
	}
	return gen.ConfidentialityLevelList{Items: items}
}

// --- Recipient rules ---------------------------------------------------------

// GetRecipientRules returns the recipient domain rules of a tenant.
func (s *Server) GetRecipientRules(ctx context.Context, req gen.GetRecipientRulesRequestObject) (gen.GetRecipientRulesResponseObject, error) {
	svc, p, err := s.tenantSession(ctx)
	if err != nil {
		return nil, err
	}
	r, err := svc.GetRecipientRules(ctx, p, tenant.ID(req.TenantId))
	if err != nil {
		return nil, tenantError(err)
	}
	return gen.GetRecipientRules200JSONResponse(recipientBody(r)), nil
}

// UpdateRecipientRules replaces the recipient domain rules of a tenant and
// returns them normalized.
func (s *Server) UpdateRecipientRules(ctx context.Context, req gen.UpdateRecipientRulesRequestObject) (gen.UpdateRecipientRulesResponseObject, error) {
	svc, p, err := s.tenantSession(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, validationFailed(tenantadmin.FieldAllowedDomains, fieldRequired)
	}
	r, err := svc.UpdateRecipientRules(ctx, p, tenant.ID(req.TenantId), req.Body.AllowedDomains, req.Body.DeniedDomains,
		middleware.ClientIP(ctx))
	if err != nil {
		return nil, tenantError(err)
	}
	return gen.UpdateRecipientRules200JSONResponse(recipientBody(r)), nil
}

// recipientBody renders r as the OpenAPI RecipientRules, with empty lists
// rather than null.
func recipientBody(r tenantadmin.RecipientRules) gen.RecipientRules {
	return gen.RecipientRules{
		AllowedDomains: append([]string{}, r.Allowed...), DeniedDomains: append([]string{}, r.Denied...),
	}
}
