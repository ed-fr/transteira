package tenantadmin

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/branding"
	"github.com/ed-fr/transteira/internal/events"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/strictjson"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/tenantops"
)

// Errors of [Service.ImportTenant].
var (
	// ErrImportInvalid reports a configuration document that cannot be
	// imported (422 import-invalid). The error is an *[ImportError]
	// carrying the JSON pointer of the first problem.
	ErrImportInvalid = errors.New("tenantadmin: invalid configuration import")
	// ErrImportSchemaUnsupported reports a schemaVersion other than
	// [ConfigSchemaVersion] (422 import-schema-unsupported).
	ErrImportSchemaUnsupported = errors.New("tenantadmin: unsupported configuration schema version")
)

// ImportError reports the first problem of an import. It matches
// [ErrImportInvalid].
type ImportError struct {
	// Pointer is the RFC 6901 JSON pointer of the value in the import body
	// (OpenAPI TenantImport): "/name", "/config/network/internalCidrs/3"...
	Pointer string
	// Reason explains the problem in English; it never quotes the value.
	Reason string
	// Code is the stable code of the problem when the API must tell it
	// apart from a malformed value ([CodeAdminHost]); "" otherwise.
	Code string
}

// Error implements error.
func (e *ImportError) Error() string {
	return "tenantadmin: invalid import " + e.Pointer + ": " + e.Reason
}

// Is makes errors.Is(err, ErrImportInvalid) true.
func (e *ImportError) Is(target error) bool { return target == ErrImportInvalid }

// importErr returns an *ImportError at pointer.
func importErr(pointer, format string, args ...any) error {
	return &ImportError{Pointer: pointer, Reason: fmt.Sprintf(format, args...)}
}

// atPointer turns the *InvalidError of a validator shared with the manual
// entry, whose field is relative to the section at prefix, into an
// *ImportError; any other error is returned unchanged.
func atPointer(prefix string, err error) error {
	var ie *InvalidError
	if errors.As(err, &ie) {
		return &ImportError{Pointer: prefix + ie.Field, Reason: ie.Reason, Code: ie.Code}
	}
	return err
}

// ImportInput is the input of [Service.ImportTenant] (OpenAPI
// TenantImport).
type ImportInput struct {
	Name              string
	FQDN              string
	StorageQuotaBytes int64
	// Config is the exported configuration.
	Config ConfigExport
	// DelegatedAdmin, when not nil, creates the first delegated admin of
	// the tenant in the same transaction, as [TenantCreate.DelegatedAdmin].
	DelegatedAdmin *adminauth.DelegatedAdmin
}

// Bounds of the members of an import that no manual entry checks.
const (
	// MaxImportBlocklistEntries bounds the blocklist entries of an import
	// (OpenAPI TenantConfigExport.blocklist maxItems): the manual entry
	// adds them one by one, an import must stay bounded (T-306).
	MaxImportBlocklistEntries = 10000
	// maxSourceVersionLen bounds sourceVersion, recorded in the audit.
	maxSourceVersionLen = 64
	// maxMediaTypeLen bounds the media type of an exported image.
	maxMediaTypeLen = 255
)

// Pointers of the sections of an import body.
var (
	ptrSettings       = strictjson.Pointer("config", "settings")
	ptrBranding       = strictjson.Pointer("config", "branding")
	ptrNetwork        = strictjson.Pointer("config", "network")
	ptrSMTP           = strictjson.Pointer("config", "smtp")
	ptrRecipientRules = strictjson.Pointer("config", "recipientRules")
	ptrLevels         = strictjson.Pointer("config", "confidentialityLevels")
	ptrAbuse          = strictjson.Pointer("config", "abuseThresholds")
)

// importPlan is a validated import: everything the transaction writes.
type importPlan struct {
	tenant    *tenant.Tenant
	cidrs     []netip.Prefix
	domains   []string
	hasNet    bool
	recipient *store.RecipientRuleSet
	levels    []store.ConfidentialityLevel
	abuse     *store.AbuseSettings
	smtp      *store.SMTPConfig
	templates []store.EmailTemplate
	legal     []store.LegalDocument
	blocklist []store.BlocklistEntry
	files     []assetFile
	// webhooks is the number of webhooks described, never recreated.
	webhooks int
}

// ImportTenant creates a tenant from an exported configuration (super
// admin only), in the setup state, with in.Name, in.FQDN and
// in.StorageQuotaBytes. Config.SchemaVersion must be [ConfigSchemaVersion],
// else ErrImportSchemaUnsupported. Everything is validated first, with the
// validators of the manual entry, and the first problem is an
// *[ImportError] with its JSON pointer; ErrAlreadyExists reports an FQDN
// (or the username of the delegated admin) already used. Then the tenant,
// its optional first delegated admin (as [Service.CreateTenant]) and its
// configuration are written in one transaction, the branding images (re-
// encoded by [branding.Process], favicons regenerated) being written
// inside it and removed again when it does not commit: all or nothing.
//
// The SMTP settings are stored without credentials and untested, so that
// the setup checklist still asks for them; the webhooks are never
// recreated (their URLs are not exported). Audited as tenant.imported with
// the sourceVersion and exportedAt of the document and the count of each
// section.
func (s *Service) ImportTenant(ctx context.Context, p adminauth.Principal, in ImportInput, ip netip.Addr) (TenantCreated, error) {
	if err := superAdmin(p); err != nil {
		return TenantCreated{}, err
	}
	if in.Config.SchemaVersion != ConfigSchemaVersion {
		return TenantCreated{}, ErrImportSchemaUnsupported
	}
	if in.DelegatedAdmin != nil && s.admins == nil {
		return TenantCreated{}, errNoAdminCreator
	}
	plan, err := s.planImport(ctx, p, in)
	if err != nil {
		return TenantCreated{}, err
	}
	var (
		invited *InvitedAdmin
		restore func()
	)
	t, err := s.repo.createTenant(ctx, plan.tenant, func(tx *store.SystemTx, t *tenant.Tenant) error {
		if in.DelegatedAdmin != nil {
			a, link, err := s.admins.CreateDelegatedAdminTx(ctx, tx, p, t, *in.DelegatedAdmin, ip)
			if err != nil {
				return err
			}
			invited = &InvitedAdmin{Account: a, Activation: link}
		}
		if err := tx.WithTenant(ctx, t.ID, func(st *store.ScopedTx) error {
			return s.writeImport(ctx, st, p, plan)
		}); err != nil {
			return err
		}
		if len(plan.files) == 0 {
			return nil
		}
		// Last, so that only a failed commit can follow: the files of a
		// tenant that is not created are then removed below. The tenant
		// is not visible before the commit, so no other request touches
		// its folder meanwhile.
		restore, err = s.putAssets(t.ID, plan.files)
		return err
	})
	if err != nil {
		if restore != nil {
			restore()
		}
		return TenantCreated{}, createError("import tenant", err)
	}
	s.invalidate(t.ID, t.FQDN)
	s.record(ctx, p, ip, t.ID, audit.ActionTenantImported, importDetails(in.Config, plan))
	v, err := s.view(ctx, t)
	if err != nil {
		return TenantCreated{}, err
	}
	return TenantCreated{TenantView: v, DelegatedAdmin: invited}, nil
}

// importDetails returns the details of the tenant.imported event: the
// origin of the document and the size of each section, never a value.
func importDetails(c ConfigExport, plan *importPlan) map[string]any {
	return map[string]any{
		"name": audit.RedactAddresses(plan.tenant.Name), "fqdn": plan.tenant.FQDN,
		"setupState":    string(plan.tenant.SetupState),
		"sourceVersion": c.SourceVersion, "exportedAt": c.ExportedAt.UTC().Format(time.RFC3339),
		"counts": map[string]any{
			"internalCidrs": len(plan.cidrs), "internalDomains": len(plan.domains),
			"recipientRules":        recipientCount(plan.recipient),
			"confidentialityLevels": len(plan.levels), "abuseThresholds": plan.abuse != nil,
			"smtp": plan.smtp != nil, "emailTemplates": len(plan.templates),
			"legalDocuments": len(plan.legal), "blocklist": len(plan.blocklist),
			"logo": plan.tenant.HasLogo, "background": plan.tenant.HasBackground,
			"webhooksSkipped": plan.webhooks,
		},
	}
}

// recipientCount returns the number of recipient rules of set.
func recipientCount(set *store.RecipientRuleSet) int {
	if set == nil {
		return 0
	}
	return len(set.Allowed) + len(set.Denied)
}

// writeImport writes the configuration of plan for the new tenant tx is
// bound to. It only writes: plan is validated already.
func (s *Service) writeImport(ctx context.Context, tx *store.ScopedTx, p adminauth.Principal, plan *importPlan) error {
	now := s.now()
	if plan.hasNet {
		if err := s.repo.replaceNetworkRulesTx(ctx, tx, plan.cidrs, plan.domains); err != nil {
			return err
		}
	}
	if plan.recipient != nil {
		if err := s.repo.replaceRecipientRulesTx(ctx, tx, *plan.recipient, now); err != nil {
			return err
		}
	}
	if plan.levels != nil {
		if err := s.repo.replaceConfidentialityLevelsTx(ctx, tx, plan.levels, p.Admin.ID, now); err != nil {
			return err
		}
	}
	if plan.abuse != nil {
		a := *plan.abuse
		a.UpdatedAt, a.UpdatedBy = now, p.Admin.ID
		if err := s.repo.putAbuseSettingsTx(ctx, tx, a); err != nil {
			return err
		}
	}
	if plan.smtp != nil {
		if err := s.repo.putSMTPConfigTx(ctx, tx, *plan.smtp); err != nil {
			return err
		}
	}
	for _, t := range plan.templates {
		if err := s.repo.putTemplateTx(ctx, tx, t); err != nil {
			return err
		}
	}
	for _, d := range plan.legal {
		if err := s.repo.putLegalTx(ctx, tx, d); err != nil {
			return err
		}
	}
	for _, e := range plan.blocklist {
		if err := s.repo.createBlocklistEntryTx(ctx, tx, e); err != nil {
			return err
		}
	}
	return nil
}

// planImport validates in completely and returns what to write. Each part
// goes through the validator of its manual entry; the errors are mapped to
// pointers of the import body.
func (s *Service) planImport(ctx context.Context, p adminauth.Principal, in ImportInput) (*importPlan, error) {
	c := in.Config
	if err := checkOrigin(c); err != nil {
		return nil, err
	}
	nt, err := s.importTenantRow(in)
	if err != nil {
		return nil, err
	}
	plan := &importPlan{tenant: nt, webhooks: len(c.Webhooks)}
	if err := s.planBranding(ctx, c.Branding, plan); err != nil {
		return nil, err
	}
	if n := c.Network; n != nil {
		if plan.cidrs, plan.domains, err = networkToStore(n.InternalCIDRs, n.InternalDomains); err != nil {
			return nil, atPointer(ptrNetwork, err)
		}
		plan.hasNet = true
	}
	if c.SMTP != nil {
		if plan.smtp, err = s.planSMTP(*c.SMTP); err != nil {
			return nil, err
		}
	}
	if r := c.RecipientRules; r != nil {
		set, err := recipientRulesToStore(r.AllowedDomains, r.DeniedDomains)
		if err != nil {
			return nil, atPointer(ptrRecipientRules, err)
		}
		plan.recipient = &set
	}
	if c.ConfidentialityLevels != nil {
		if plan.levels, err = planLevels(c.ConfidentialityLevels.Items); err != nil {
			return nil, err
		}
	}
	if c.AbuseThresholds != nil {
		a, err := AbuseFromAPI(*c.AbuseThresholds)
		if err == nil {
			err = validateAbuse(a)
		}
		if err != nil {
			return nil, atPointer(ptrAbuse, err)
		}
		plan.abuse = &a
	}
	if plan.templates, err = planTemplates(c.EmailTemplates, p.Admin.ID); err != nil {
		return nil, err
	}
	if plan.legal, err = planLegal(c.LegalDocuments, p.Admin.ID); err != nil {
		return nil, err
	}
	if err := checkWebhooks(c.Webhooks); err != nil {
		return nil, err
	}
	if plan.blocklist, err = planBlocklist(c.Blocklist, p.Admin.Username); err != nil {
		return nil, err
	}
	return plan, nil
}

// checkOrigin validates the members telling where the document comes from,
// recorded in the audit.
func checkOrigin(c ConfigExport) error {
	if c.ExportedAt.IsZero() {
		return importErr(strictjson.Pointer("config", "exportedAt"), "required")
	}
	if v := c.SourceVersion; v == "" || len(v) > maxSourceVersionLen || !safeLine(v) {
		return importErr(strictjson.Pointer("config", "sourceVersion"), "must be 1 to %d bytes on one line", maxSourceVersionLen)
	}
	return nil
}

// importTenantRow validates the tenant row of an import exactly as
// [Service.CreateTenant] does, in the setup state, with the general
// settings and colors of the document.
func (s *Service) importTenantRow(in ImportInput) (*tenant.Tenant, error) {
	st := in.Config.Settings
	if st == nil {
		st = &ExportedSettings{}
	}
	e2e := tenant.E2EForbidden
	if st.E2EPolicy != nil {
		if e2e = tenant.E2EPolicy(*st.E2EPolicy); !e2e.Valid() {
			return nil, importErr(ptrSettings+"/e2ePolicy", "must be forbidden, allowed or required")
		}
	}
	create := TenantCreate{
		Name: in.Name, FQDN: in.FQDN, DefaultLanguage: tenant.Languages()[0], StorageQuotaBytes: in.StorageQuotaBytes,
		MaxTransferCeiling: st.MaxTransferCeiling, SetupState: tenant.SetupStateSetup,
	}
	if st.DefaultLanguage != nil {
		create.DefaultLanguage = *st.DefaultLanguage
	}
	if st.MaxTransferBytes != nil {
		if err := checkTransferBytes(FieldMaxTransferBytes, *st.MaxTransferBytes); err != nil {
			return nil, atPointer(ptrSettings, err)
		}
		create.MaxTransferBytes = *st.MaxTransferBytes
	}
	if b := in.Config.Branding; b != nil {
		create.BackgroundPreset = b.BackgroundPreset
	}
	t, err := s.newTenant(create)
	var ie *InvalidError
	switch {
	case errors.Is(err, ErrUnknownBackgroundPreset):
		return nil, importErr(ptrBranding+"/backgroundPreset", "unknown background preset")
	case errors.As(err, &ie) && (ie.Field == FieldName || ie.Field == FieldFQDN || ie.Field == FieldStorageQuotaBytes):
		return nil, atPointer("", err)
	case err != nil:
		return nil, atPointer(ptrSettings, err)
	}
	t.AllowRemoteInternalDeposit = deref(st.AllowRemoteInternalDeposit)
	t.AllowTransferReply = deref(st.AllowTransferReply)
	t.WebhookIncludeAddresses = deref(st.WebhookIncludeAddresses)
	t.LinkOnlyAllowed = deref(st.LinkOnlyAllowed)
	t.E2EPolicy = e2e
	return t, nil
}

// deref returns *p, or the zero value for nil.
func deref[T any](p *T) T {
	if p == nil {
		var zero T
		return zero
	}
	return *p
}

// planBranding validates the colors and images of b and sets them on the
// tenant of plan, with the files to write.
func (s *Service) planBranding(ctx context.Context, b *ExportedBranding, plan *importPlan) error {
	if b == nil {
		return nil
	}
	t := plan.tenant
	if b.PrimaryColor != nil || b.AccentColor != nil {
		primary, accent, err := checkColors(derefOr(b.PrimaryColor, tenant.DefaultPrimaryColor),
			derefOr(b.AccentColor, tenant.DefaultAccentColor))
		if err != nil {
			return atPointer(ptrBranding, err)
		}
		t.PrimaryColor, t.AccentColor = primary, accent
	}
	for _, a := range []struct {
		kind  branding.Kind
		asset *ExportedAsset
		name  string
	}{{branding.KindLogo, b.Logo, "logo"}, {branding.KindBackground, b.Background, "background"}} {
		if a.asset == nil {
			continue
		}
		files, err := s.planAsset(ctx, a.kind, *a.asset, ptrBranding+"/"+a.name)
		if err != nil {
			return err
		}
		plan.files = append(plan.files, files...)
		setAssetFlag(t, a.kind, true)
	}
	return nil
}

// derefOr returns *p, or def for nil.
func derefOr[T any](p *T, def T) T {
	if p == nil {
		return def
	}
	return *p
}

// importMediaTypes are the media types of an exported image: those of the
// formats [branding.Process] reads (the content itself is sniffed).
var importMediaTypes = map[string]bool{"image/png": true, "image/jpeg": true, "image/webp": true}

// planAsset decodes the exported image at pointer at and re-encodes it as
// an upload is ([Service.processAsset]); its base64 length is checked
// against the size limit of kind before decoding (T-307).
func (s *Service) planAsset(ctx context.Context, kind branding.Kind, a ExportedAsset, at string) ([]assetFile, error) {
	if len(a.MediaType) > maxMediaTypeLen || !importMediaTypes[a.MediaType] {
		return nil, importErr(at+"/mediaType", "must be image/png, image/jpeg or image/webp")
	}
	data := at + "/dataBase64"
	if int64(len(a.DataBase64)) > int64(base64.StdEncoding.EncodedLen(int(kind.MaxBytes()))) {
		return nil, importErr(data, "image larger than %d bytes", kind.MaxBytes())
	}
	raw, err := base64.StdEncoding.DecodeString(a.DataBase64)
	if err != nil {
		return nil, importErr(data, "must be standard base64")
	}
	files, _, err := s.processAsset(ctx, kind, bytes.NewReader(raw))
	switch {
	case errors.Is(err, ErrUnsupportedMediaType):
		return nil, importErr(data, "must be a PNG, JPEG or WebP image")
	case errors.Is(err, ErrPayloadTooLarge):
		return nil, importErr(data, "image above the size or dimension limits")
	case errors.Is(err, ErrInvalid):
		return nil, importErr(data, "corrupt or unreadable image")
	case err != nil:
		return nil, err
	}
	return files, nil
}

// planSMTP validates the SMTP server and sender of an import: stored
// without user name nor password.
func (s *Service) planSMTP(in ExportedSMTP) (*store.SMTPConfig, error) {
	c, err := s.checkSMTP(SMTPUpdate{
		Host: in.Host, Port: in.Port, Security: store.SMTPSecurity(in.Security),
		FromAddress: in.FromAddress, FromName: deref(in.FromName),
	})
	if err != nil {
		return nil, atPointer(ptrSMTP, err)
	}
	return &c, nil
}

// planLevels validates the confidentiality levels of an import.
func planLevels(items []ExportedLevel) ([]store.ConfidentialityLevel, error) {
	levels := make([]ConfidentialityLevel, len(items))
	for i, l := range items {
		rules := ptrLevels + strictjson.Pointer("items", i, "rules")
		var e2e *tenant.E2EPolicy
		if l.Rules.E2EPolicy != nil {
			pol := tenant.E2EPolicy(*l.Rules.E2EPolicy)
			if !pol.Valid() {
				return nil, importErr(rules+"/e2ePolicy", "must be forbidden, allowed or required")
			}
			e2e = &pol
		}
		levels[i] = ConfidentialityLevel{
			Key: l.Key, Labels: l.Labels, Descriptions: l.Descriptions, IsDefault: l.IsDefault,
			Rules: ConfidentialityRules{
				AllowedExpiryDays: l.Rules.AllowedExpiryDays, MaxDownloads: l.Rules.MaxDownloads,
				RequirePassword: l.Rules.RequirePassword, RequireRecipientVerification: l.Rules.RequireRecipientVerification,
				InternalRecipientsOnly:        l.Rules.InternalRecipientsOnly,
				ForceDeleteAfterFirstDownload: l.Rules.ForceDeleteAfterFirstDownload,
				// Absent means allowed.
				LinkOnlyForbidden: l.Rules.LinkOnlyAllowed != nil && !*l.Rules.LinkOnlyAllowed,
				E2EPolicy:         e2e,
			},
		}
	}
	out, err := levelsToStore(levels)
	if err != nil {
		return nil, atPointer(ptrLevels, err)
	}
	return out, nil
}

// planTemplates validates the mail templates of an import as
// [Service.UpdateTemplate] does, saved by the administrator ID by. A key
// and language may appear once.
func planTemplates(items []ExportedTemplate, by string) ([]store.EmailTemplate, error) {
	out := make([]store.EmailTemplate, 0, len(items))
	seen := map[[2]string]bool{}
	for i, t := range items {
		at := strictjson.Pointer("config", "emailTemplates", i)
		if _, err := checkTemplate(t.Key, "en"); err != nil {
			return nil, importErr(at+"/key", "unknown mail template")
		}
		if !tenant.IsLanguage(t.Language) {
			return nil, importErr(at+"/language", "unsupported language")
		}
		if seen[[2]string{t.Key, t.Language}] {
			return nil, importErr(at, "duplicate template and language")
		}
		seen[[2]string{t.Key, t.Language}] = true
		st, err := templateToStore(t.Key, t.Language, TemplateInput{Subject: t.Subject, HTML: t.BodyHTML, Text: t.BodyText}, by)
		if err != nil {
			return nil, templateImportError(at, err)
		}
		out = append(out, st)
	}
	return out, nil
}

// templatePartMembers maps the parts of a template issue to the members
// of an exported template.
var templatePartMembers = map[string]string{
	mail.PartSubject: "/subject", mail.PartHTML: "/bodyHtml", mail.PartText: "/bodyText",
}

// templateImportError maps the error of the template at pointer at,
// pointing at the part of its first issue.
func templateImportError(at string, err error) error {
	var ie *InvalidError
	if !errors.As(err, &ie) {
		return err
	}
	reason := ie.Reason
	if len(ie.Issues) > 0 {
		first := ie.Issues[0]
		at += templatePartMembers[first.Part]
		if first.Line > 0 {
			reason += ", line " + strconv.Itoa(first.Line) + ", column " + strconv.Itoa(first.Column)
		}
	}
	return &ImportError{Pointer: at, Reason: reason}
}

// planLegal validates the legal documents of an import as
// [Service.UpdateLegal] does, saved by the administrator ID by; a blank
// document is not written (it would be removed). A document and language
// may appear once.
func planLegal(items []ExportedLegalDocument, by string) ([]store.LegalDocument, error) {
	out := make([]store.LegalDocument, 0, len(items))
	seen := map[[2]string]bool{}
	for i, d := range items {
		at := strictjson.Pointer("config", "legalDocuments", i)
		if checkLegal(d.Document, "en") != nil {
			return nil, importErr(at+"/document", "must be legal-notice or privacy-policy")
		}
		if !tenant.IsLanguage(d.Language) {
			return nil, importErr(at+"/language", "unsupported language")
		}
		if seen[[2]string{d.Document, d.Language}] {
			return nil, importErr(at, "duplicate document and language")
		}
		seen[[2]string{d.Document, d.Language}] = true
		if err := checkLegalMarkdown(d.Markdown); err != nil {
			return nil, atPointer(at, err)
		}
		if strings.TrimSpace(d.Markdown) == "" {
			continue
		}
		out = append(out, store.LegalDocument{Document: d.Document, Language: d.Language, Content: d.Markdown, UpdatedBy: by})
	}
	return out, nil
}

// checkWebhooks validates the shape of the described webhooks, which are
// never recreated: their URLs and secrets are not exported (A2, P62).
func checkWebhooks(items []ExportedWebhook) error {
	if len(items) > store.MaxWebhooks {
		return importErr(strictjson.Pointer("config", "webhooks"), "at most %d webhooks", store.MaxWebhooks)
	}
	for i, w := range items {
		at := strictjson.Pointer("config", "webhooks", i)
		if n := utf8.RuneCountInString(strings.TrimSpace(w.Name)); n == 0 || n > store.MaxWebhookNameLen || !safeLine(w.Name) {
			return importErr(at+"/name", "must be 1 to %d characters on one line", store.MaxWebhookNameLen)
		}
		switch store.WebhookKind(w.Kind) {
		case store.WebhookTeams, store.WebhookSlack, store.WebhookGeneric:
		default:
			return importErr(at+"/kind", "must be teams, slack or generic")
		}
		if len(w.Events) == 0 {
			return importErr(at+"/events", "at least one event")
		}
		seen := map[string]bool{}
		for j, e := range w.Events {
			if !events.IsTenant(events.Type(e)) || seen[e] {
				return importErr(at+"/events/"+strconv.Itoa(j), "must be a distinct tenant event")
			}
			seen[e] = true
		}
		if w.Enabled {
			return importErr(at+"/enabled", "must be false")
		}
	}
	return nil
}

// planBlocklist validates the blocklist entries of an import as
// [tenantops.Service.CreateBlocklistEntry] does, created by the
// administrator username by, at most [MaxImportBlocklistEntries]. Two
// entries of the same kind whose values are equal once normalized are
// refused: on PostgreSQL the duplicate would abort the transaction.
func planBlocklist(items []ExportedBlocklistEntry, by string) ([]store.BlocklistEntry, error) {
	if len(items) > MaxImportBlocklistEntries {
		return nil, importErr(strictjson.Pointer("config", "blocklist"), "at most %d entries", MaxImportBlocklistEntries)
	}
	out := make([]store.BlocklistEntry, 0, len(items))
	seen := map[[2]string]bool{}
	for i, e := range items {
		at := strictjson.Pointer("config", "blocklist", i)
		kind := store.BlocklistKind(e.Kind)
		switch kind {
		case store.BlockEmail, store.BlockDomain, store.BlockSHA256:
		default:
			return nil, importErr(at+"/kind", "must be email, domain or sha256")
		}
		value := strings.ToLower(strings.TrimSpace(e.Value))
		if value == "" || utf8.RuneCountInString(value) > tenantops.MaxBlocklistValueLen {
			return nil, importErr(at+"/value", "must be 1 to %d characters", tenantops.MaxBlocklistValueLen)
		}
		norm, err := kind.Normalize(value)
		if err != nil {
			return nil, importErr(at+"/value", "malformed %s", kind)
		}
		if !utf8.ValidString(e.Comment) || utf8.RuneCountInString(e.Comment) > tenantops.MaxBlocklistCommentLen {
			return nil, importErr(at+"/comment", "must be text of at most %d characters", tenantops.MaxBlocklistCommentLen)
		}
		key := [2]string{e.Kind, norm}
		if seen[key] {
			return nil, importErr(at+"/value", "duplicate entry")
		}
		seen[key] = true
		out = append(out, store.BlocklistEntry{Kind: kind, Value: norm, Comment: e.Comment, CreatedBy: by})
	}
	return out, nil
}

// Conversions of the abuse thresholds between the form of the API and the
// form of the store.
const (
	percent        = 100
	daysPerWeek    = 7
	minutesPerHour = 60
	minutesPerDay  = 24 * minutesPerHour
	officeEndOfDay = "24:00"
)

// AbuseFromAPI converts thresholds in the form of the API (OpenAPI
// AbuseThresholds) to the settings of the store, for an import and for the
// manual entry alike: the factor becomes a percentage (rounded, saturated
// at math.MaxInt32), the office hours minutes of the day and a weekday
// mask. A value that cannot be converted is an *InvalidError naming its
// field (relative to the thresholds); the bounds are checked by the
// service when the settings are written.
func AbuseFromAPI(b ExportedAbuseThresholds) (store.AbuseSettings, error) {
	out := store.AbuseSettings{
		MaxDailyBytesPerSender: b.MaxDailyBytesPerSender, MaxDailyTransfersPerSender: b.MaxDailyTransfersPerSender,
		MaxRecipientsPerTransfer: b.MaxRecipientsPerTransfer, BlockOnExceed: b.BlockOnExceed,
		UnusualMinHistoryDays: b.UnusualMinHistoryDays, LargeExternalTransferBytes: b.LargeExternalTransferBytes,
		TimeZone: b.TimeZone, MaxInvitationsPerInviter: b.MaxInvitationsPerInviter,
		ExternalMaxDailyBytes: b.ExternalMaxDailyBytes, ExternalMaxDailyDeposits: b.ExternalMaxDailyDeposits,
	}
	if f := b.UnusualVolumeFactor; f != nil {
		pct := math.MaxInt32
		if v := math.Round(*f * percent); v < math.MaxInt32 && v > math.MinInt32 {
			pct = int(v)
		}
		out.UnusualVolumePct = &pct
	}
	if oh := b.OfficeHours; oh != nil {
		start, ok := ParseClock(oh.Start, false)
		if !ok {
			return store.AbuseSettings{}, invalid(FieldOfficeHours+"/start", "must be HH:MM")
		}
		end, ok := ParseClock(oh.End, true)
		if !ok {
			return store.AbuseSettings{}, invalid(FieldOfficeHours+"/end", "must be HH:MM or 24:00")
		}
		mask, ok := WeekdayMask(oh.Weekdays)
		if !ok {
			return store.AbuseSettings{}, invalid(FieldOfficeHoursWeekdays, "must be distinct days from 1 to 7")
		}
		out.OfficeStartMinute, out.OfficeEndMinute, out.OfficeWeekdays = &start, &end, mask
	}
	return out, nil
}

// WeekdayMask converts ISO 8601 weekdays (1 = Monday ... 7 = Sunday) to
// the mask of the store (bit 0 = Monday); false for an empty list, a day
// out of range or a duplicate day.
func WeekdayMask(days []int) (int, bool) {
	mask := 0
	for _, d := range days {
		if d < 1 || d > daysPerWeek || mask&(1<<(d-1)) != 0 {
			return 0, false
		}
		mask |= 1 << (d - 1)
	}
	return mask, mask != 0
}

// ParseClock parses "HH:MM" (00:00 to 23:59), and "24:00" when allowEnd,
// to minutes of the day.
func ParseClock(s string, allowEnd bool) (int, bool) {
	if allowEnd && s == officeEndOfDay {
		return minutesPerDay, true
	}
	h, m, ok := strings.Cut(s, ":")
	if !ok || len(h) != 2 || len(m) != 2 {
		return 0, false
	}
	hh, err1 := strconv.Atoi(h)
	mm, err2 := strconv.Atoi(m)
	if err1 != nil || err2 != nil || hh < 0 || hh > 23 || mm < 0 || mm > 59 {
		return 0, false
	}
	return hh*minutesPerHour + mm, true
}

// FormatClock renders minutes of the day as HH:MM ("24:00" for the end).
func FormatClock(minutes int) string {
	return fmt.Sprintf("%02d:%02d", minutes/minutesPerHour, minutes%minutesPerHour)
}
