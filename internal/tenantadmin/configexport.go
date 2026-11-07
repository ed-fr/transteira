package tenantadmin

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/branding"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/version"
)

// ConfigSchemaVersion is the only schemaVersion of a configuration export
// this version writes and reads (OpenAPI TenantConfigExport).
const ConfigSchemaVersion = 1

// ConfigExport is the exported configuration of a tenant (OpenAPI
// TenantConfigExport), member by member. It is a whitelist: every member
// is copied explicitly from the stored configuration, never through an
// internal type, so that no secret (SMTP user name or password, webhook URL
// or secret, API token, single sign-on configuration) can slip in (T-304).
// A nil pointer or slice is an absent member; on import, an absent section
// keeps the defaults of a new tenant. The JSON tags give the OpenAPI
// member names.
type ConfigExport struct {
	// SchemaVersion is [ConfigSchemaVersion].
	SchemaVersion int `json:"schemaVersion"`
	// ExportedAt is the time of the export (UTC).
	ExportedAt time.Time `json:"exportedAt"`
	// SourceVersion is the version of the instance that exported.
	SourceVersion string `json:"sourceVersion"`

	Settings              *ExportedSettings        `json:"settings,omitempty"`
	Branding              *ExportedBranding        `json:"branding,omitempty"`
	Network               *ExportedNetwork         `json:"network,omitempty"`
	SMTP                  *ExportedSMTP            `json:"smtp,omitempty"`
	RecipientRules        *ExportedRecipientRules  `json:"recipientRules,omitempty"`
	ConfidentialityLevels *ExportedLevelList       `json:"confidentialityLevels,omitempty"`
	AbuseThresholds       *ExportedAbuseThresholds `json:"abuseThresholds,omitempty"`
	// EmailTemplates are the customized templates only.
	EmailTemplates []ExportedTemplate      `json:"emailTemplates,omitempty"`
	LegalDocuments []ExportedLegalDocument `json:"legalDocuments,omitempty"`
	// Webhooks are informative: never imported.
	Webhooks  []ExportedWebhook        `json:"webhooks,omitempty"`
	Blocklist []ExportedBlocklistEntry `json:"blocklist,omitempty"`
}

// ExportedSettings are the general settings of a tenant, without its
// storage quota (OpenAPI TenantConfigExport.settings).
type ExportedSettings struct {
	DefaultLanguage            *string `json:"defaultLanguage,omitempty"`
	MaxTransferBytes           *int64  `json:"maxTransferBytes,omitempty"`
	MaxTransferCeiling         *int64  `json:"maxTransferCeiling,omitempty"`
	AllowRemoteInternalDeposit *bool   `json:"allowRemoteInternalDeposit,omitempty"`
	AllowTransferReply         *bool   `json:"allowTransferReply,omitempty"`
	WebhookIncludeAddresses    *bool   `json:"webhookIncludeAddresses,omitempty"`
	// LinkOnlyAllowed is the link-only switch of the tenant (since 2.0,
	// super admin only: the import is a super admin operation).
	LinkOnlyAllowed *bool `json:"linkOnlyAllowed,omitempty"`
	// E2EPolicy is the end-to-end encryption policy of the tenant (since
	// 2.0, super admin only like the import); always exported, absent on
	// import means "forbidden".
	E2EPolicy *string `json:"e2ePolicy,omitempty"`
}

// ExportedBranding is the branding of a tenant (OpenAPI
// TenantConfigExport.branding); the images only when asked for.
type ExportedBranding struct {
	PrimaryColor     *string        `json:"primaryColor,omitempty"`
	AccentColor      *string        `json:"accentColor,omitempty"`
	BackgroundPreset *string        `json:"backgroundPreset,omitempty"`
	Logo             *ExportedAsset `json:"logo,omitempty"`
	Background       *ExportedAsset `json:"background,omitempty"`
}

// ExportedAsset is a branding image of an export (OpenAPI ExportedAsset).
type ExportedAsset struct {
	MediaType string `json:"mediaType"`
	// DataBase64 is the image, base64 with the standard alphabet.
	DataBase64 string `json:"dataBase64"`
}

// ExportedNetwork are the internal ranges and domains (OpenAPI
// NetworkRules).
type ExportedNetwork struct {
	InternalCIDRs   []string `json:"internalCidrs"`
	InternalDomains []string `json:"internalDomains"`
}

// ExportedSMTP is the SMTP server and sender of a tenant, never its user
// name nor its password (OpenAPI TenantConfigExport.smtp).
type ExportedSMTP struct {
	Host        string  `json:"host"`
	Port        int     `json:"port"`
	Security    string  `json:"security"`
	FromAddress string  `json:"fromAddress"`
	FromName    *string `json:"fromName,omitempty"`
}

// ExportedRecipientRules are the recipient domain rules (OpenAPI
// RecipientRules).
type ExportedRecipientRules struct {
	AllowedDomains []string `json:"allowedDomains"`
	DeniedDomains  []string `json:"deniedDomains"`
}

// ExportedLevelList is the list of confidentiality levels (OpenAPI
// ConfidentialityLevelList).
type ExportedLevelList struct {
	Items []ExportedLevel `json:"items"`
}

// ExportedLevel is a confidentiality level (OpenAPI ConfidentialityLevel).
type ExportedLevel struct {
	Key          string             `json:"key"`
	Labels       map[string]string  `json:"labels"`
	Descriptions map[string]string  `json:"descriptions,omitempty"`
	IsDefault    bool               `json:"isDefault"`
	Rules        ExportedLevelRules `json:"rules"`
}

// ExportedLevelRules are the rules of a level (OpenAPI
// ConfidentialityRules).
type ExportedLevelRules struct {
	AllowedExpiryDays             []int `json:"allowedExpiryDays"`
	MaxDownloads                  *int  `json:"maxDownloads"`
	RequirePassword               bool  `json:"requirePassword"`
	RequireRecipientVerification  bool  `json:"requireRecipientVerification"`
	InternalRecipientsOnly        bool  `json:"internalRecipientsOnly"`
	ForceDeleteAfterFirstDownload bool  `json:"forceDeleteAfterFirstDownload"`
	// E2EPolicy is the end-to-end encryption policy of the level (since
	// 2.0), exported only when the level has its own; absent means the
	// tenant's.
	E2EPolicy *string `json:"e2ePolicy,omitempty"`
	// LinkOnlyAllowed is the link-only switch of the level (since 2.0),
	// always exported; absent on import means true.
	LinkOnlyAllowed *bool `json:"linkOnlyAllowed,omitempty"`
}

// ExportedAbuseThresholds are the abuse detection settings in the form of
// the API (OpenAPI AbuseThresholds): a factor rather than a percentage,
// office hours as clock times and ISO 8601 weekdays.
type ExportedAbuseThresholds struct {
	MaxDailyBytesPerSender     *int64               `json:"maxDailyBytesPerSender"`
	MaxDailyTransfersPerSender *int                 `json:"maxDailyTransfersPerSender"`
	MaxRecipientsPerTransfer   *int                 `json:"maxRecipientsPerTransfer"`
	BlockOnExceed              bool                 `json:"blockOnExceed"`
	UnusualVolumeFactor        *float64             `json:"unusualVolumeFactor"`
	UnusualMinHistoryDays      int                  `json:"unusualMinHistoryDays"`
	LargeExternalTransferBytes *int64               `json:"largeExternalTransferBytes"`
	TimeZone                   string               `json:"timeZone"`
	OfficeHours                *ExportedOfficeHours `json:"officeHours"`
	MaxInvitationsPerInviter   int                  `json:"maxInvitationsPerInviter"`
	ExternalMaxDailyBytes      *int64               `json:"externalMaxDailyBytes"`
	ExternalMaxDailyDeposits   *int                 `json:"externalMaxDailyDeposits"`
}

// ExportedOfficeHours are office hours (OpenAPI OfficeHours): "HH:MM"
// times ("24:00" for the end of the day) and weekdays 1 (Monday) to 7.
type ExportedOfficeHours struct {
	Start    string `json:"start"`
	End      string `json:"end"`
	Weekdays []int  `json:"weekdays"`
}

// ExportedTemplate is a customized mail template.
type ExportedTemplate struct {
	Key      string `json:"key"`
	Language string `json:"language"`
	Subject  string `json:"subject"`
	BodyHTML string `json:"bodyHtml"`
	BodyText string `json:"bodyText"`
}

// ExportedLegalDocument is a written legal document.
type ExportedLegalDocument struct {
	Document string `json:"document"`
	Language string `json:"language"`
	Markdown string `json:"markdown"`
}

// ExportedWebhook describes a webhook for information: never its URL nor
// its secret, always disabled, never recreated by an import (A2, P62).
type ExportedWebhook struct {
	Name   string   `json:"name"`
	Kind   string   `json:"kind"`
	Events []string `json:"events"`
	// Enabled is always false.
	Enabled bool `json:"enabled"`
}

// ExportedBlocklistEntry is a blocklist entry.
type ExportedBlocklistEntry struct {
	Kind    string `json:"kind"`
	Value   string `json:"value"`
	Comment string `json:"comment,omitempty"`
}

// ExportConfig returns the configuration of tenant tid as a
// [ConfigExport] (schemaVersion [ConfigSchemaVersion]), to create another
// tenant from it with [Service.ImportTenant]. It requires the right to
// change the tenant: the super admin or a delegated admin of the tenant
// (an auditor gets adminauth.ErrReadOnlyRole, a tenant out of reach
// ErrNotFound). The logo and background images are included only with
// includeBranding. Never exported: the storage quota, the SMTP user name
// and password, the webhook URLs and secrets, the API tokens, the admins,
// the single sign-on configuration and every piece of transfer data.
// Audited as tenant.exported with includeBranding.
func (s *Service) ExportConfig(ctx context.Context, p adminauth.Principal, tid tenant.ID, includeBranding bool, ip netip.Addr) (ConfigExport, error) {
	t, err := s.writable(ctx, p, tid)
	if err != nil {
		return ConfigExport{}, err
	}
	out := ConfigExport{
		SchemaVersion: ConfigSchemaVersion,
		ExportedAt:    s.now().UTC().Truncate(time.Second),
		SourceVersion: version.Get().Version,
		Settings: &ExportedSettings{
			DefaultLanguage: ptrTo(t.DefaultLanguage), MaxTransferBytes: ptrTo(t.MaxTransferBytes),
			MaxTransferCeiling:         ptrTo(t.MaxTransferCeiling),
			AllowRemoteInternalDeposit: ptrTo(t.AllowRemoteInternalDeposit),
			AllowTransferReply:         ptrTo(t.AllowTransferReply),
			WebhookIncludeAddresses:    ptrTo(t.WebhookIncludeAddresses),
			LinkOnlyAllowed:            ptrTo(t.LinkOnlyAllowed),
			E2EPolicy:                  ptrTo(string(t.E2EPolicy)),
		},
	}
	if out.Branding, err = s.exportBranding(t, includeBranding); err != nil {
		return ConfigExport{}, err
	}
	for _, step := range []func(context.Context, tenant.ID, *ConfigExport) error{
		s.exportRules, s.exportSMTP, s.exportTemplates, s.exportLegal, s.exportWebhooks, s.exportBlocklist,
	} {
		if err := step(ctx, tid, &out); err != nil {
			return ConfigExport{}, err
		}
	}
	s.record(ctx, p, ip, tid, audit.ActionTenantExported, map[string]any{"includeBranding": includeBranding})
	return out, nil
}

// ptrTo returns a pointer to a copy of v.
func ptrTo[T any](v T) *T { return &v }

// exportBranding returns the branding of t, with its images when
// includeBranding.
func (s *Service) exportBranding(t *tenant.Tenant, includeBranding bool) (*ExportedBranding, error) {
	b := brandingOf(t)
	out := &ExportedBranding{
		PrimaryColor: ptrTo(b.PrimaryColor), AccentColor: ptrTo(b.AccentColor), BackgroundPreset: ptrTo(b.BackgroundPreset),
	}
	if !includeBranding {
		return out, nil
	}
	for _, a := range []struct {
		kind branding.Kind
		dst  **ExportedAsset
	}{{branding.KindLogo, &out.Logo}, {branding.KindBackground, &out.Background}} {
		img, ok, err := s.storedAsset(t, a.kind)
		if err != nil {
			return nil, err
		}
		if ok {
			*a.dst = &ExportedAsset{MediaType: img.ContentType, DataBase64: base64.StdEncoding.EncodeToString(img.Data)}
		}
	}
	return out, nil
}

// exportRules adds the network rules, the recipient rules, the
// confidentiality levels and the abuse thresholds of tid to out.
func (s *Service) exportRules(ctx context.Context, tid tenant.ID, out *ConfigExport) error {
	nr, err := s.repo.networkRules(ctx, tid)
	if err != nil {
		return fmt.Errorf("tenantadmin: export network rules: %w", err)
	}
	n := rulesOf(nr)
	out.Network = &ExportedNetwork{InternalCIDRs: n.CIDRs, InternalDomains: n.Domains}
	rr, err := s.repo.recipientRules(ctx, tid)
	if err != nil {
		return fmt.Errorf("tenantadmin: export recipient rules: %w", err)
	}
	r := recipientRulesOf(rr)
	out.RecipientRules = &ExportedRecipientRules{AllowedDomains: r.Allowed, DeniedDomains: r.Denied}
	levels, err := s.repo.confidentialityLevels(ctx, tid)
	if err != nil {
		return fmt.Errorf("tenantadmin: export confidentiality levels: %w", err)
	}
	out.ConfidentialityLevels = &ExportedLevelList{Items: make([]ExportedLevel, len(levels))}
	for i, l := range levels {
		out.ConfidentialityLevels.Items[i] = levelToExport(levelOf(l))
	}
	abuse, err := s.repo.abuseSettings(ctx, tid)
	if err != nil {
		return fmt.Errorf("tenantadmin: export abuse settings: %w", err)
	}
	out.AbuseThresholds = AbuseToAPI(abuse)
	return nil
}

// levelToExport converts a confidentiality level.
func levelToExport(l ConfidentialityLevel) ExportedLevel {
	out := ExportedLevel{
		Key: l.Key, Labels: l.Labels, IsDefault: l.IsDefault,
		Rules: ExportedLevelRules{
			AllowedExpiryDays: l.Rules.AllowedExpiryDays, MaxDownloads: l.Rules.MaxDownloads,
			RequirePassword: l.Rules.RequirePassword, RequireRecipientVerification: l.Rules.RequireRecipientVerification,
			InternalRecipientsOnly:        l.Rules.InternalRecipientsOnly,
			ForceDeleteAfterFirstDownload: l.Rules.ForceDeleteAfterFirstDownload,
			LinkOnlyAllowed:               ptrTo(!l.Rules.LinkOnlyForbidden),
		},
	}
	if l.Rules.E2EPolicy != nil {
		out.Rules.E2EPolicy = ptrTo(string(*l.Rules.E2EPolicy))
	}
	if len(l.Descriptions) > 0 {
		out.Descriptions = l.Descriptions
	}
	return out
}

// AbuseToAPI converts the abuse settings of the store to the form of the
// API (OpenAPI AbuseThresholds), the inverse of [AbuseFromAPI]: the
// percentage becomes a factor, the office hours clock times and ISO 8601
// weekdays (absent when the settings have none).
func AbuseToAPI(a store.AbuseSettings) *ExportedAbuseThresholds {
	out := &ExportedAbuseThresholds{
		MaxDailyBytesPerSender: a.MaxDailyBytesPerSender, MaxDailyTransfersPerSender: a.MaxDailyTransfersPerSender,
		MaxRecipientsPerTransfer: a.MaxRecipientsPerTransfer, BlockOnExceed: a.BlockOnExceed,
		UnusualMinHistoryDays: a.UnusualMinHistoryDays, LargeExternalTransferBytes: a.LargeExternalTransferBytes,
		TimeZone: a.TimeZone, MaxInvitationsPerInviter: a.MaxInvitationsPerInviter,
		ExternalMaxDailyBytes: a.ExternalMaxDailyBytes, ExternalMaxDailyDeposits: a.ExternalMaxDailyDeposits,
	}
	if a.UnusualVolumePct != nil {
		out.UnusualVolumeFactor = ptrTo(float64(*a.UnusualVolumePct) / percent)
	}
	if a.OfficeStartMinute != nil && a.OfficeEndMinute != nil {
		days := []int{}
		for d := 1; d <= daysPerWeek; d++ {
			if a.OfficeWeekdays&(1<<(d-1)) != 0 {
				days = append(days, d)
			}
		}
		out.OfficeHours = &ExportedOfficeHours{
			Start: FormatClock(*a.OfficeStartMinute), End: FormatClock(*a.OfficeEndMinute), Weekdays: days,
		}
	}
	return out
}

// exportSMTP adds the SMTP server and sender of tid to out, when it has
// SMTP settings: never the user name nor the password.
func (s *Service) exportSMTP(ctx context.Context, tid tenant.ID, out *ConfigExport) error {
	c, err := s.repo.smtp(ctx, tid)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil
	case err != nil:
		return fmt.Errorf("tenantadmin: export smtp settings: %w", err)
	}
	out.SMTP = &ExportedSMTP{Host: c.Host, Port: c.Port, Security: string(c.Security), FromAddress: c.FromAddress}
	if c.FromName != "" {
		out.SMTP.FromName = ptrTo(c.FromName)
	}
	return nil
}

// exportTemplates adds the customized mail templates of tid to out.
func (s *Service) exportTemplates(ctx context.Context, tid tenant.ID, out *ConfigExport) error {
	custom, err := s.repo.listTemplates(ctx, tid)
	if err != nil {
		return fmt.Errorf("tenantadmin: export templates: %w", err)
	}
	// Only keys with a built-in template can be customized (UpdateTemplate),
	// so every exported template passes the checks of the import.
	for _, c := range custom {
		t, err := s.repo.template(ctx, tid, c.Key, c.Language)
		switch {
		case errors.Is(err, store.ErrNotFound):
			continue // reset meanwhile
		case err != nil:
			return fmt.Errorf("tenantadmin: export template: %w", err)
		}
		out.EmailTemplates = append(out.EmailTemplates, ExportedTemplate{
			Key: t.Key, Language: t.Language, Subject: t.Subject, BodyHTML: t.BodyHTML, BodyText: t.BodyText,
		})
	}
	return nil
}

// exportLegal adds the written legal documents of tid to out.
func (s *Service) exportLegal(ctx context.Context, tid tenant.ID, out *ConfigExport) error {
	keys, err := s.repo.listLegal(ctx, tid)
	if err != nil {
		return fmt.Errorf("tenantadmin: export legal documents: %w", err)
	}
	for _, k := range keys {
		d, err := s.repo.legal(ctx, tid, k.Document, k.Language)
		switch {
		case errors.Is(err, store.ErrNotFound):
			continue // removed meanwhile
		case err != nil:
			return fmt.Errorf("tenantadmin: export legal document: %w", err)
		}
		out.LegalDocuments = append(out.LegalDocuments, ExportedLegalDocument{
			Document: k.Document, Language: k.Language, Markdown: d.Content,
		})
	}
	return nil
}

// exportWebhooks adds the webhooks of tid to out: name, kind and events
// only, disabled; never the URL (that of a Teams or Slack webhook is a
// secret itself) nor the signing secret (T-304).
func (s *Service) exportWebhooks(ctx context.Context, tid tenant.ID, out *ConfigExport) error {
	hooks, err := s.repo.listWebhooks(ctx, tid)
	if err != nil {
		return fmt.Errorf("tenantadmin: export webhooks: %w", err)
	}
	for _, w := range hooks {
		evs := make([]string, len(w.Events))
		for i, e := range w.Events {
			evs[i] = string(e)
		}
		out.Webhooks = append(out.Webhooks, ExportedWebhook{Name: w.Name, Kind: string(w.Kind), Events: evs, Enabled: false})
	}
	return nil
}

// exportBlocklist adds every blocklist entry of tid to out, page by page.
func (s *Service) exportBlocklist(ctx context.Context, tid tenant.ID, out *ConfigExport) error {
	cursor := ""
	for {
		page, err := s.repo.listBlocklist(ctx, tid, cursor)
		if err != nil {
			return fmt.Errorf("tenantadmin: export blocklist: %w", err)
		}
		for _, e := range page.Items {
			out.Blocklist = append(out.Blocklist, ExportedBlocklistEntry{Kind: string(e.Kind), Value: e.Value, Comment: e.Comment})
		}
		if page.NextCursor == "" {
			return nil
		}
		cursor = page.NextCursor
	}
}
