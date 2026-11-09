package tenantadmin

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/branding"
	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/events"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/version"
)

// --- Fault injection of the export and import repo methods ------------------

func (f *faultRepo) listWebhooks(ctx context.Context, tid tenant.ID) ([]store.Webhook, error) {
	if err := f.fail("listWebhooks"); err != nil {
		return nil, err
	}
	return f.repo.listWebhooks(ctx, tid)
}

func (f *faultRepo) listBlocklist(ctx context.Context, tid tenant.ID, cursor string) (store.Page[store.BlocklistEntry], error) {
	if err := f.fail("listBlocklist"); err != nil {
		return store.Page[store.BlocklistEntry]{}, err
	}
	return f.repo.listBlocklist(ctx, tid, cursor)
}

func (f *faultRepo) replaceNetworkRulesTx(ctx context.Context, tx *store.ScopedTx, c []netip.Prefix, d []string) error {
	if err := f.fail("replaceNetworkRulesTx"); err != nil {
		return err
	}
	return f.repo.replaceNetworkRulesTx(ctx, tx, c, d)
}

func (f *faultRepo) replaceRecipientRulesTx(ctx context.Context, tx *store.ScopedTx, set store.RecipientRuleSet, now time.Time) error {
	if err := f.fail("replaceRecipientRulesTx"); err != nil {
		return err
	}
	return f.repo.replaceRecipientRulesTx(ctx, tx, set, now)
}

func (f *faultRepo) replaceConfidentialityLevelsTx(ctx context.Context, tx *store.ScopedTx, l []store.ConfidentialityLevel, by string, now time.Time) error {
	if err := f.fail("replaceConfidentialityLevelsTx"); err != nil {
		return err
	}
	return f.repo.replaceConfidentialityLevelsTx(ctx, tx, l, by, now)
}

func (f *faultRepo) putAbuseSettingsTx(ctx context.Context, tx *store.ScopedTx, s store.AbuseSettings) error {
	if err := f.fail("putAbuseSettingsTx"); err != nil {
		return err
	}
	return f.repo.putAbuseSettingsTx(ctx, tx, s)
}

func (f *faultRepo) putSMTPConfigTx(ctx context.Context, tx *store.ScopedTx, c store.SMTPConfig) error {
	if err := f.fail("putSMTPConfigTx"); err != nil {
		return err
	}
	return f.repo.putSMTPConfigTx(ctx, tx, c)
}

func (f *faultRepo) putTemplateTx(ctx context.Context, tx *store.ScopedTx, t store.EmailTemplate) error {
	if err := f.fail("putTemplateTx"); err != nil {
		return err
	}
	return f.repo.putTemplateTx(ctx, tx, t)
}

func (f *faultRepo) putLegalTx(ctx context.Context, tx *store.ScopedTx, d store.LegalDocument) error {
	if err := f.fail("putLegalTx"); err != nil {
		return err
	}
	return f.repo.putLegalTx(ctx, tx, d)
}

func (f *faultRepo) createBlocklistEntryTx(ctx context.Context, tx *store.ScopedTx, e store.BlocklistEntry) error {
	if err := f.fail("createBlocklistEntryTx"); err != nil {
		return err
	}
	return f.repo.createBlocklistEntryTx(ctx, tx, e)
}

// lateFailRepo makes the creation of a tenant fail after its then hook
// succeeded, as a failed commit would.
type lateFailRepo struct{ repo }

func (r lateFailRepo) createTenant(ctx context.Context, t *tenant.Tenant, then func(tx *store.SystemTx, t *tenant.Tenant) error) (*tenant.Tenant, error) {
	return r.repo.createTenant(ctx, t, func(tx *store.SystemTx, t *tenant.Tenant) error {
		if err := then(tx, t); err != nil {
			return err
		}
		return errBoom
	})
}

// --- Fixtures ----------------------------------------------------------------

// Secrets and values that must never appear in an export (T-304).
const (
	secretSMTPUser     = "smtp-user-7c1e"
	secretSMTPPassword = "smtp-pass-9f2a"
	secretWebhookURL   = "https://hooks.example.net/services/T000/B000/xoxb-secret-path-4d8e"
	secretWebhookKey   = "whsec-signing-secret-3b6f" // gitleaks:allow (fake test secret)
	secretSSO          = "sso-client-secret-5a0c"
	tokenName          = "ci-token-name-2e9d"
	tokenPrefix        = "tt_live_8b1"
)

// configure sets every exportable part of the configuration of tenant A,
// plus the secrets an export must never carry: SMTP credentials, a webhook
// with its URL and secret, single sign-on and an API token. nBlocks
// blocklist entries are added on top of three fixed ones.
func (ev *env) configure(t *testing.T, nBlocks int) {
	t.Helper()
	ctx := context.Background()
	tid := ev.a.ID
	_, err := ev.svc.UpdateTenant(ctx, ev.super, tid, TenantUpdate{
		DefaultLanguage: ptr("fr"), MaxTransferCeiling: ptr(int64(15 << 30)), MaxTransferBytes: ptr(int64(12 << 30)),
		AllowTransferReply: ptr(true), WebhookIncludeAddresses: ptr(true), AllowRemoteInternalDeposit: ptr(true),
	}, clientIP)
	mustNoErr(t, "settings", err)
	_, err = ev.svc.UpdateBranding(ctx, ev.adminA, tid, "#1f4e79", "#c55a11", clientIP)
	mustNoErr(t, "colors", err)
	_, err = ev.svc.SetBackgroundPreset(ctx, ev.adminA, tid, ptr(branding.Presets()[1].ID), clientIP)
	mustNoErr(t, "preset", err)
	mustNoErr(t, "logo", ev.svc.UploadAsset(ctx, ev.adminA, tid, "logo", bytes.NewReader(pngImage(t, 64, 32)), clientIP))
	mustNoErr(t, "background", ev.svc.UploadAsset(ctx, ev.adminA, tid, "background", bytes.NewReader(pngImage(t, 80, 60)), clientIP))
	_, err = ev.svc.PutSSO(ctx, ev.super, tid, ssoIn(secretSSO), clientIP)
	mustNoErr(t, "sso", err)
	_, err = ev.svc.UpdateNetworkRules(ctx, ev.adminA, tid, []string{"10.10.0.0/16", "2001:db8::/32"},
		[]string{domainA, domainA2, sharedDom}, clientIP)
	mustNoErr(t, "network", err)
	_, err = ev.svc.UpdateRecipientRules(ctx, ev.adminA, tid, []string{"partner.example.org"}, []string{"mail.example.net"}, clientIP)
	mustNoErr(t, "recipient rules", err)
	secret := goodLevel("secret", false)
	secret.Descriptions = map[string]string{"en": "Restricted", "fr": "Restreint"}
	secret.Rules = ConfidentialityRules{
		AllowedExpiryDays: []int{1, 7}, MaxDownloads: ptr(3), RequirePassword: true, RequireRecipientVerification: true,
		InternalRecipientsOnly: true, ForceDeleteAfterFirstDownload: true,
	}
	_, err = ev.svc.UpdateConfidentialityLevels(ctx, ev.adminA, tid, []ConfidentialityLevel{goodLevel("public", true), secret}, clientIP)
	mustNoErr(t, "levels", err)
	abuse := store.DefaultAbuseSettings()
	abuse.MaxDailyBytesPerSender, abuse.MaxRecipientsPerTransfer = ptr(int64(50<<30)), ptr(20)
	abuse.UnusualVolumePct, abuse.BlockOnExceed, abuse.TimeZone = ptr(250), true, "Europe/Paris"
	abuse.OfficeStartMinute, abuse.OfficeEndMinute, abuse.OfficeWeekdays = ptr(8*60), ptr(24*60), 0b0011111
	abuse.ExternalMaxDailyDeposits = ptr(4)
	_, err = ev.svc.UpdateAbuseThresholds(ctx, ev.adminA, tid, abuse, clientIP)
	mustNoErr(t, "abuse", err)
	_, err = ev.svc.UpdateSecretSettings(ctx, ev.adminA, tid, SecretSettingsInput{
		Enabled: true, Durations: []string{"1h", "3d"}, DefaultDuration: "3d", FileAllowed: false,
		FileMaxBytes: 2 << 20, EmailAllowed: true, EmailRequiresPassphrase: true,
	}, clientIP)
	mustNoErr(t, "secret settings", err)
	_, err = ev.svc.UpdateSMTP(ctx, ev.adminA, tid, SMTPUpdate{
		Host: "smtp.example.com", Port: 587, Security: store.SMTPSecuritySTARTTLS, Username: secretSMTPUser,
		Password: ptr(secretSMTPPassword), FromAddress: "transfer@entity-a.example.com", FromName: "Entity A",
	}, clientIP)
	mustNoErr(t, "smtp", err)
	_, err = ev.svc.UpdateTemplate(ctx, ev.adminA, tid, keyCode, "en", goodTemplate(), clientIP)
	mustNoErr(t, "template", err)
	_, err = ev.svc.UpdateLegal(ctx, ev.adminA, tid, store.LegalNotice, "fr", "# Mentions\n\nEntity A.", clientIP)
	mustNoErr(t, "legal", err)
	_, err = ev.svc.UpdateLegal(ctx, ev.adminA, tid, store.PrivacyPolicy, "en", "# Privacy", clientIP)
	mustNoErr(t, "privacy", err)
	ev.addWebhook(t, tid)
	_, err = ev.db.APITokens().Create(ctx, tid, store.APIToken{
		ID: id.New(id.APIToken), Name: tokenName, Prefix: tokenPrefix, TokenHash: bytes.Repeat([]byte{7}, store.TokenHashSize),
		AllowedCIDRs: mustPrefixes("10.10.0.0/16"), CreatedBy: "alice",
	})
	mustNoErr(t, "api token", err)
	blocks := ev.db.Blocklist()
	for _, e := range []store.BlocklistEntry{
		{Kind: store.BlockEmail, Value: "spam@example.org", Comment: "spammer"},
		{Kind: store.BlockDomain, Value: "bad.example.net"},
		{Kind: store.BlockSHA256, Value: strings.Repeat("ab", 32)},
	} {
		e.CreatedBy = "alice"
		_, err := blocks.Create(ctx, tid, e)
		mustNoErr(t, "blocklist", err)
	}
	for i := range nBlocks {
		_, err := blocks.Create(ctx, tid, store.BlocklistEntry{
			Kind: store.BlockDomain, Value: "d" + strconv.Itoa(i) + ".example.com",
			CreatedBy: "alice",
		})
		mustNoErr(t, "blocklist bulk", err)
	}
}

// addWebhook stores a generic webhook of tid with a sealed URL and secret.
func (ev *env) addWebhook(t *testing.T, tid tenant.ID) {
	t.Helper()
	ctx := context.Background()
	sc, err := ev.db.Scoped(tid)
	mustNoErr(t, "scoped", err)
	mustNoErr(t, "webhook", sc.Tx(ctx, func(tx *store.ScopedTx) error {
		urlID, err := ev.vault.SealTx(ctx, tx, crypto.PurposeSecret, []byte(secretWebhookURL))
		if err != nil {
			return err
		}
		keyID, err := ev.vault.SealTx(ctx, tx, crypto.PurposeSecret, []byte(secretWebhookKey))
		if err != nil {
			return err
		}
		_, err = ev.db.Webhooks().CreateTx(ctx, tx, store.Webhook{
			ID: id.New(id.Webhook), Name: "SOC alerts", Kind: store.WebhookGeneric, URLKeyID: urlID,
			URLHint: "https://hooks.example.net", SecretKeyID: keyID,
			Events: []events.Type{events.VirusDetected, events.QuotaReached}, Enabled: true, CreatedBy: "alice",
		})
		return err
	}))
}

// minimalImport is a valid import of a new tenant with fqdn and an almost
// empty document.
func minimalImport(fqdn string) ImportInput {
	return ImportInput{
		Name: "Entity C", FQDN: fqdn, StorageQuotaBytes: 1 << 40,
		Config: ConfigExport{SchemaVersion: ConfigSchemaVersion, ExportedAt: testStart, SourceVersion: "2.0.0"},
	}
}

// importErrorAt fails unless err is an *ImportError at pointer.
func importErrorAt(t *testing.T, what string, err error, pointer string) *ImportError {
	t.Helper()
	var ie *ImportError
	if !errors.As(err, &ie) || !errors.Is(err, ErrImportInvalid) || ie.Pointer != pointer || ie.Error() == "" {
		t.Fatalf("%s: got %v, want an import error at %q", what, err, pointer)
	}
	return ie
}

// tenantFiles returns the number of branding files of every tenant other
// than A and B.
func (ev *env) strayFiles() int {
	ev.assets.mu.Lock()
	defer ev.assets.mu.Unlock()
	n := 0
	for k := range ev.assets.data {
		if !strings.HasPrefix(k, string(ev.a.ID)+"/") && !strings.HasPrefix(k, string(ev.b.ID)+"/") {
			n++
		}
	}
	return n
}

// importedEvents returns the tenant.imported events of every tenant.
func (ev *env) importedEvents(ctx context.Context, t *testing.T) int {
	t.Helper()
	page, err := ev.db.AuditEvents().List(ctx, store.AuditFilter{Action: string(audit.ActionTenantImported)})
	mustNoErr(t, "audit", err)
	return len(page.Items)
}

// sortedBlocklist returns the blocklist of c sorted, the order of entries
// created in the same millisecond being random.
func sortedBlocklist(c ConfigExport) []ExportedBlocklistEntry {
	out := slices.Clone(c.Blocklist)
	slices.SortFunc(out, func(a, b ExportedBlocklistEntry) int { return strings.Compare(a.Kind+a.Value, b.Kind+b.Value) })
	return out
}

// --- Export ------------------------------------------------------------------

func TestExportConfig(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev, _ := ssoEnv(t, e)
		ev.configure(t, store.MaxPageSize) // more than one page of blocklist

		out, err := ev.svc.ExportConfig(ctx, ev.adminA, ev.a.ID, true, clientIP)
		mustNoErr(t, "export", err)
		if out.SchemaVersion != 1 || !out.ExportedAt.Equal(testStart) || out.ExportedAt.Location() != time.UTC ||
			out.SourceVersion != version.Get().Version {
			t.Errorf("header = %d %v %q", out.SchemaVersion, out.ExportedAt, out.SourceVersion)
		}
		st := out.Settings
		if *st.DefaultLanguage != "fr" || *st.MaxTransferBytes != 12<<30 || *st.MaxTransferCeiling != 15<<30 ||
			!*st.AllowRemoteInternalDeposit || !*st.AllowTransferReply || !*st.WebhookIncludeAddresses ||
			st.LinkOnlyAllowed == nil || *st.LinkOnlyAllowed || st.E2EPolicy == nil || *st.E2EPolicy != "forbidden" {
			t.Errorf("settings = %+v", st)
		}
		b := out.Branding
		if *b.PrimaryColor != "#1F4E79" || *b.AccentColor != "#C55A11" || *b.BackgroundPreset != branding.Presets()[1].ID ||
			b.Logo == nil || b.Logo.MediaType != branding.KindLogo.ContentType() ||
			b.Background == nil || b.Background.MediaType != branding.KindBackground.ContentType() {
			t.Fatalf("branding = %+v", b)
		}
		if logo, _ := base64.StdEncoding.DecodeString(b.Logo.DataBase64); !bytes.Equal(logo, ev.assets.get(ev.a.ID, branding.KindLogo)) {
			t.Error("logo is not the stored one")
		}
		if !slices.Equal(out.Network.InternalCIDRs, []string{"10.10.0.0/16", "2001:db8::/32"}) || len(out.Network.InternalDomains) != 3 {
			t.Errorf("network = %+v", out.Network)
		}
		if !slices.Equal(out.RecipientRules.AllowedDomains, []string{"partner.example.org"}) ||
			!slices.Equal(out.RecipientRules.DeniedDomains, []string{"mail.example.net"}) {
			t.Errorf("recipient rules = %+v", out.RecipientRules)
		}
		lv := out.ConfidentialityLevels.Items
		if len(lv) != 2 || lv[1].Key != "secret" || *lv[1].Rules.MaxDownloads != 3 || !slices.Equal(lv[1].Rules.AllowedExpiryDays, []int{1, 7}) ||
			lv[1].Descriptions["fr"] != "Restreint" || lv[0].Descriptions != nil || lv[1].Rules.E2EPolicy != nil ||
			lv[1].Rules.LinkOnlyAllowed == nil || !*lv[1].Rules.LinkOnlyAllowed {
			t.Errorf("levels = %+v", lv)
		}
		ab := out.AbuseThresholds
		if *ab.UnusualVolumeFactor != 2.5 || ab.TimeZone != "Europe/Paris" || ab.OfficeHours == nil ||
			ab.OfficeHours.Start != "08:00" || ab.OfficeHours.End != "24:00" || !slices.Equal(ab.OfficeHours.Weekdays, []int{1, 2, 3, 4, 5}) {
			t.Errorf("abuse = %+v", ab)
		}
		if ss := out.SecretSettings; ss == nil || !ss.Enabled || !slices.Equal(ss.Durations, []string{"1h", "3d"}) ||
			ss.DefaultDuration == nil || *ss.DefaultDuration != "3d" || ss.FileAllowed || ss.FileMaxBytes != 2<<20 ||
			!ss.EmailAllowed || !ss.EmailRequiresPassphrase {
			t.Errorf("secret settings = %+v", ss)
		}
		if s := out.SMTP; s == nil || s.Host != "smtp.example.com" || s.Port != 587 || s.Security != "starttls" ||
			s.FromAddress != "transfer@entity-a.example.com" || *s.FromName != "Entity A" {
			t.Errorf("smtp = %+v", out.SMTP)
		}
		if len(out.EmailTemplates) != 1 || out.EmailTemplates[0].Key != keyCode || out.EmailTemplates[0].Language != "en" ||
			strings.Contains(out.EmailTemplates[0].BodyHTML, "<script") {
			t.Errorf("templates = %+v", out.EmailTemplates)
		}
		if len(out.LegalDocuments) != 2 {
			t.Errorf("legal = %+v", out.LegalDocuments)
		}
		if len(out.Webhooks) != 1 || out.Webhooks[0].Enabled || out.Webhooks[0].Kind != "generic" ||
			!slices.Equal(out.Webhooks[0].Events, []string{"virus.detected", "quota.reached"}) {
			t.Errorf("webhooks = %+v", out.Webhooks)
		}
		if len(out.Blocklist) != 3+store.MaxPageSize {
			t.Errorf("blocklist entries = %d", len(out.Blocklist))
		}

		// No secret, no hash, no internal identifier (T-304).
		doc, err := json.Marshal(out)
		mustNoErr(t, "marshal", err)
		for _, s := range []string{
			secretSMTPUser, secretSMTPPassword, secretWebhookURL, "hooks.example.net", secretWebhookKey, secretSSO,
			ssoIssuerA, ssoAppA, tokenName, tokenPrefix, "wk_", "whk_", "blk_", "tok_", string(ev.a.ID), "storageQuota",
			"username", "password", "\"url", "createdBy", "alice",
		} {
			if bytes.Contains(doc, []byte(s)) {
				t.Errorf("the export holds %q", s)
			}
		}
		evs := ev.auditEvents(t, ev.a.ID, audit.ActionTenantExported)
		if len(evs) != 1 || detailsOf(t, evs[0])["includeBranding"] != true || evs[0].Actor != "alice" {
			t.Errorf("tenant.exported = %+v", evs)
		}

		// Without the images; the super admin may export too.
		out, err = ev.svc.ExportConfig(ctx, ev.super, ev.a.ID, false, clientIP)
		mustNoErr(t, "export without branding", err)
		if out.Branding.Logo != nil || out.Branding.Background != nil || out.Branding.PrimaryColor == nil {
			t.Errorf("branding without images = %+v", out.Branding)
		}
		evs = ev.auditEvents(t, ev.a.ID, audit.ActionTenantExported)
		if len(evs) != 2 || detailsOf(t, evs[0])["includeBranding"] != false {
			t.Errorf("tenant.exported = %+v", evs)
		}

		// A new tenant: defaults, no SMTP, no optional section.
		out, err = ev.svc.ExportConfig(ctx, ev.adminB, ev.b.ID, true, clientIP)
		mustNoErr(t, "export B", err)
		if ss := out.SecretSettings; ss == nil || ss.DefaultDuration != nil || !ss.Enabled || ss.EmailRequiresPassphrase ||
			!slices.Equal(ss.Durations, []string{"1h", "1d", "7d"}) {
			t.Errorf("default secret settings = %+v", ss)
		}
		if out.SMTP != nil || out.EmailTemplates != nil || out.LegalDocuments != nil || out.Webhooks != nil ||
			out.Blocklist != nil || out.Branding.Logo != nil || *out.Branding.BackgroundPreset != branding.DefaultPresetID ||
			out.AbuseThresholds.OfficeHours != nil || out.AbuseThresholds.UnusualVolumeFactor != nil ||
			len(out.ConfidentialityLevels.Items) == 0 {
			t.Errorf("export of a new tenant = %+v", out)
		}
	})
}

func TestExportConfigFaults(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev, _ := ssoEnv(t, e)
		ev.configure(t, 0)
		for _, m := range []string{
			"networkRules", "recipientRules", "confidentialityLevels", "abuseSettings", "smtp", "listTemplates",
			"template", "listLegal", "legal", "listWebhooks", "listBlocklist",
		} {
			ev.faults(m)
			_, err := ev.svc.ExportConfig(ctx, ev.adminA, ev.a.ID, false, clientIP)
			wantErr(t, m, err, errBoom)
		}
		ev.faults()
		ev.assets.getErrAt = map[branding.Kind]error{branding.KindBackground: errBoom}
		_, err := ev.svc.ExportConfig(ctx, ev.adminA, ev.a.ID, true, clientIP)
		wantErr(t, "asset", err, errBoom)
		ev.assets.getErrAt = nil
		if n := len(ev.auditEvents(t, ev.a.ID, audit.ActionTenantExported)); n != 0 {
			t.Errorf("tenant.exported recorded after a failure: %d", n)
		}

		// A template or legal document removed between the listing and its
		// read is skipped.
		f := ev.faults()
		f.errs["template"], f.errs["legal"] = store.ErrNotFound, store.ErrNotFound
		out, err := ev.svc.ExportConfig(ctx, ev.adminA, ev.a.ID, false, clientIP)
		mustNoErr(t, "removed meanwhile", err)
		if out.EmailTemplates != nil || out.LegalDocuments != nil {
			t.Errorf("removed documents exported: %+v %+v", out.EmailTemplates, out.LegalDocuments)
		}
	})
}

// --- Import ------------------------------------------------------------------

func TestImportRoundTrip(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev, _ := ssoEnv(t, e)
		ev.configure(t, 5)
		ev.withAdmins(t, false)
		src, err := ev.svc.ExportConfig(ctx, ev.adminA, ev.a.ID, true, clientIP)
		mustNoErr(t, "export", err)
		// Through JSON, as the API receives it.
		doc, err := json.Marshal(src)
		mustNoErr(t, "marshal", err)
		var cfg ConfigExport
		mustNoErr(t, "unmarshal", json.Unmarshal(doc, &cfg))

		ev.clock.Advance(time.Hour)
		in := ImportInput{
			Name: "Entity C", FQDN: "Transfer.Entity-C.example.com", StorageQuotaBytes: 1 << 40, Config: cfg,
			DelegatedAdmin: &adminauth.DelegatedAdmin{Username: "carol", Email: "carol@entity-c.example.com", Language: "fr"},
		}
		got, err := ev.svc.ImportTenant(ctx, ev.super, in, clientIP)
		mustNoErr(t, "import", err)
		cid := got.ID
		if got.Name != "Entity C" || got.FQDN != "transfer.entity-c.example.com" || got.StorageQuotaBytes != 1<<40 ||
			got.SetupState != tenant.SetupStateSetup || got.DefaultLanguage != "fr" || got.MaxTransferBytes != 12<<30 ||
			got.MaxTransferCeiling != 15<<30 || !got.AllowTransferReply || !got.WebhookIncludeAddresses ||
			!got.AllowRemoteInternalDeposit || !got.AntivirusEnabled {
			t.Errorf("tenant = %+v", got.TenantView)
		}
		if got.DelegatedAdmin == nil || got.DelegatedAdmin.Account.Username != "carol" ||
			!slices.Equal(got.DelegatedAdmin.Account.TenantIDs, []tenant.ID{cid}) {
			t.Errorf("delegated admin = %+v", got.DelegatedAdmin)
		}
		if !ev.cache.sawHost("transfer.entity-c.example.com") {
			t.Error("resolver cache not invalidated")
		}

		// The same configuration, but the parts never imported.
		back, err := ev.svc.ExportConfig(ctx, ev.super, cid, false, clientIP)
		mustNoErr(t, "export C", err)
		want := src
		want.ExportedAt, want.Webhooks = back.ExportedAt, nil
		want.Blocklist, back.Blocklist = sortedBlocklist(want), sortedBlocklist(back)
		wb := *want.Branding
		wb.Logo, wb.Background = nil, nil
		want.Branding = &wb
		if !reflect.DeepEqual(want, back) {
			wj, _ := json.Marshal(want)
			bj, _ := json.Marshal(back)
			t.Errorf("round trip differs:\nwant %s\ngot  %s", wj, bj)
		}

		// Images re-encoded, favicons regenerated.
		br, err := ev.svc.GetBranding(ctx, ev.super, cid)
		mustNoErr(t, "branding", err)
		if !br.HasLogo || !br.HasBackground {
			t.Errorf("branding flags = %+v", br)
		}
		for _, k := range append([]branding.Kind{branding.KindLogo, branding.KindBackground}, branding.FaviconKinds()...) {
			if !ev.assets.has(cid, k) {
				t.Errorf("missing %s", k)
			}
		}
		icons, err := branding.GenerateFavicons(ctx, ev.assets.get(cid, branding.KindLogo))
		mustNoErr(t, "favicons", err)
		for _, k := range branding.FaviconKinds() {
			icon, _ := icons.Get(k)
			if !bytes.Equal(icon.Data, ev.assets.get(cid, k)) {
				t.Errorf("%s not generated from the imported logo", k)
			}
		}

		// SMTP without credentials and untested; no webhook, no SSO.
		smtp, err := ev.svc.GetSMTP(ctx, ev.super, cid)
		mustNoErr(t, "smtp", err)
		if smtp.Username != "" || smtp.PasswordSet || smtp.Host != "smtp.example.com" {
			t.Errorf("smtp = %+v", smtp)
		}
		// The SMTP item is to do again, and the imported network rules
		// must be confirmed (T-307).
		setup, err := ev.svc.GetSetup(ctx, ev.super, cid)
		mustNoErr(t, "setup", err)
		if d := done(setup); d[SetupSMTP] || d[SetupInternalNetworks] || d[SetupInternalDomains] {
			t.Errorf("items done after an import: %v", d)
		}
		if setup.State != tenant.SetupStateSetup || setup.CanComplete || !setup.NetworkReviewedAt.IsZero() {
			t.Errorf("setup = %+v", setup)
		}
		if stored, err := ev.db.Tenants().Get(ctx, cid); err != nil || !stored.NetworkReviewedAt.IsZero() {
			t.Errorf("stored review = %+v, %v", stored, err)
		}
		// Saving the imported rules unchanged confirms them.
		_, err = ev.svc.UpdateNetworkRules(ctx, ev.super, cid, back.Network.InternalCIDRs, back.Network.InternalDomains, clientIP)
		mustNoErr(t, "confirm network", err)
		setup, err = ev.svc.GetSetup(ctx, ev.super, cid)
		mustNoErr(t, "setup", err)
		if d := done(setup); !d[SetupInternalNetworks] || !d[SetupInternalDomains] ||
			!setup.NetworkReviewedAt.Equal(testStart.Add(time.Hour)) {
			t.Errorf("after the confirmation: %v, %v", d, setup.NetworkReviewedAt)
		}
		if again, err := ev.svc.ExportConfig(ctx, ev.super, cid, false, clientIP); err != nil ||
			!reflect.DeepEqual(again.Network, back.Network) {
			t.Errorf("rules changed by the confirmation: %+v, %v", again.Network, err)
		}
		if hooks, err := ev.db.Webhooks().List(ctx, cid); err != nil || len(hooks) != 0 {
			t.Errorf("webhooks = %v, %v", hooks, err)
		}
		if sso, err := ev.svc.GetSSO(ctx, ev.super, cid); err == nil && sso.Enabled {
			t.Errorf("sso imported: %+v", sso)
		}

		// Audit: origin and counts, never a value.
		evs := ev.auditEvents(t, cid, audit.ActionTenantImported)
		if len(evs) != 1 {
			t.Fatalf("tenant.imported = %d", len(evs))
		}
		d := detailsOf(t, evs[0])
		counts, _ := d["counts"].(map[string]any)
		if d["sourceVersion"] != src.SourceVersion || d["exportedAt"] != testStart.Format(time.RFC3339) ||
			counts["blocklist"] != float64(8) || counts["webhooksSkipped"] != float64(1) || counts["logo"] != true ||
			counts["internalCidrs"] != float64(2) || counts["recipientRules"] != float64(2) || counts["smtp"] != true {
			t.Errorf("details = %+v", d)
		}
		raw, _ := json.Marshal(d)
		if bytes.Contains(raw, []byte("10.10.0.0")) || bytes.Contains(raw, []byte("spam@")) {
			t.Errorf("details hold values: %s", raw)
		}

		// The same FQDN again is a conflict, and leaves no file.
		before := ev.strayFiles()
		in.DelegatedAdmin = nil
		in.FQDN = "transfer.entity-c.example.com"
		_, err = ev.svc.ImportTenant(ctx, ev.super, in, clientIP)
		wantErr(t, "fqdn conflict", err, ErrAlreadyExists)
		if ev.strayFiles() != before {
			t.Error("files left by a conflicting import")
		}
	})
}

func TestImportMinimal(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		in := minimalImport("c1.example.com")
		// The link-only switches are stored (since step 6 of V2); the
		// end-to-end policies are stored too (see TestImportExportE2E).
		in.Config.Settings = &ExportedSettings{LinkOnlyAllowed: ptr(true), E2EPolicy: ptr("forbidden")}
		in.Config.Branding = &ExportedBranding{AccentColor: ptr("#00aa00")}
		lvl := levelToExport(goodLevel("public", true))
		closed := levelToExport(goodLevel("closed", false))
		closed.Rules.LinkOnlyAllowed = ptr(false)
		in.Config.ConfidentialityLevels = &ExportedLevelList{Items: []ExportedLevel{lvl, closed}}
		in.Config.LegalDocuments = []ExportedLegalDocument{{Document: store.LegalNotice, Language: "en", Markdown: "  \n"}}
		got, err := ev.svc.ImportTenant(ctx, ev.super, in, clientIP)
		mustNoErr(t, "import", err)
		if got.DefaultLanguage != "en" || got.MaxTransferBytes != tenant.MaxTransferLimit || got.SetupState != tenant.SetupStateSetup ||
			got.DelegatedAdmin != nil {
			t.Errorf("tenant = %+v", got)
		}
		br, err := ev.svc.GetBranding(ctx, ev.super, got.ID)
		mustNoErr(t, "branding", err)
		if br.PrimaryColor != tenant.DefaultPrimaryColor || br.AccentColor != "#00AA00" || br.HasLogo ||
			br.BackgroundPreset != branding.DefaultPresetID {
			t.Errorf("branding = %+v", br)
		}
		if v, err := ev.svc.GetTenant(ctx, ev.super, got.ID); err != nil || !v.LinkOnlyAllowed {
			t.Errorf("tenant link-only = %+v, %v", v, err)
		}
		if lv, err := ev.svc.GetConfidentialityLevels(ctx, ev.super, got.ID); err != nil || len(lv) != 2 ||
			lv[0].Rules.LinkOnlyForbidden || !lv[1].Rules.LinkOnlyForbidden {
			t.Errorf("levels = %+v, %v", lv, err)
		}
		if _, err := ev.svc.GetSMTP(ctx, ev.super, got.ID); !errors.Is(err, ErrNotFound) {
			t.Errorf("smtp of a minimal import: %v", err)
		}
		if docs, err := ev.svc.LegalDocuments(ctx, &tenant.Tenant{ID: got.ID}); err != nil || len(docs) != 0 {
			t.Errorf("blank legal document stored: %v %v", docs, err)
		}
		if ev.strayFiles() != 0 {
			t.Error("files without images")
		}
	})
}

func TestImportAccess(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		in := minimalImport("c2.example.com")
		unauth := ev.super
		unauth.State = store.SessionTOTPRequired
		auditor := principal(store.RoleAuditor, "audrey", ev.a.ID)
		for name, tc := range map[string]struct {
			p    adminauth.Principal
			want error
		}{
			"delegated admin": {ev.adminA, ErrForbidden},
			"auditor":         {auditor, ErrForbidden},
			"unauthenticated": {unauth, ErrUnauthenticated},
		} {
			_, err := ev.svc.ImportTenant(ctx, tc.p, in, clientIP)
			wantErr(t, name, err, tc.want)
		}
		// The schema version is checked before any other member.
		bad := minimalImport("c2.example.com")
		bad.Name, bad.Config.SchemaVersion = "", 2
		_, err := ev.svc.ImportTenant(ctx, ev.super, bad, clientIP)
		wantErr(t, "schema 2", err, ErrImportSchemaUnsupported)
		bad.Config.SchemaVersion = 0
		_, err = ev.svc.ImportTenant(ctx, ev.super, bad, clientIP)
		wantErr(t, "schema 0", err, ErrImportSchemaUnsupported)
		// A delegated admin without an admin creator.
		withAdmin := minimalImport("c2.example.com")
		withAdmin.DelegatedAdmin = &adminauth.DelegatedAdmin{Username: "x.admin", Email: "x@entity-c.example.com", Language: "en"}
		_, err = ev.svc.ImportTenant(ctx, ev.super, withAdmin, clientIP)
		wantErr(t, "no admin creator", err, errNoAdminCreator)
		// The errors of the account creation, as for CreateTenant.
		ev.svc.admins = fakeAdminCreator{err: adminauth.ErrAlreadyExists}
		_, err = ev.svc.ImportTenant(ctx, ev.super, withAdmin, clientIP)
		wantErr(t, "username taken", err, ErrAlreadyExists)
		ev.tenantGone(t, "c2.example.com")
		if ev.importedEvents(ctx, t) != 0 {
			t.Error("tenant.imported recorded")
		}
	})
}

// validLogo returns an exported logo.
func validLogo(t *testing.T) *ExportedAsset {
	return &ExportedAsset{MediaType: "image/png", DataBase64: base64.StdEncoding.EncodeToString(pngImage(t, 16, 16))}
}

func TestImportValidation(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		const fqdn = "c3.example.com"
		long := strings.Repeat("x", 400)
		corrupt := slices.Concat(pngImage(t, 4, 4)[:40], bytes.Repeat([]byte{0xff}, 64))
		level := func(mod func(*ExportedLevel)) func(*ImportInput) {
			return func(in *ImportInput) {
				l := levelToExport(goodLevel("public", true))
				mod(&l)
				in.Config.ConfidentialityLevels = &ExportedLevelList{Items: []ExportedLevel{l}}
			}
		}
		abuse := func(mod func(*ExportedAbuseThresholds)) func(*ImportInput) {
			return func(in *ImportInput) {
				a := AbuseToAPI(store.DefaultAbuseSettings())
				mod(a)
				in.Config.AbuseThresholds = a
			}
		}
		secrets := func(mod func(*ExportedSecretSettings)) func(*ImportInput) {
			return func(in *ImportInput) {
				x := &ExportedSecretSettings{
					Enabled: true, Durations: []string{"1h"}, FileAllowed: true, FileMaxBytes: tenant.MinSecretFileBytes, EmailAllowed: true,
				}
				mod(x)
				in.Config.SecretSettings = x
			}
		}
		tpl := func(items ...ExportedTemplate) func(*ImportInput) {
			return func(in *ImportInput) { in.Config.EmailTemplates = items }
		}
		good := goodTemplate()
		goodTpl := ExportedTemplate{Key: keyCode, Language: "en", Subject: good.Subject, BodyHTML: good.HTML, BodyText: good.Text}
		legal := func(items ...ExportedLegalDocument) func(*ImportInput) {
			return func(in *ImportInput) { in.Config.LegalDocuments = items }
		}
		hook := func(mod func(*ExportedWebhook)) func(*ImportInput) {
			return func(in *ImportInput) {
				w := ExportedWebhook{Name: "Ops", Kind: "teams", Events: []string{"virus.detected"}}
				mod(&w)
				in.Config.Webhooks = []ExportedWebhook{w}
			}
		}
		block := func(items ...ExportedBlocklistEntry) func(*ImportInput) {
			return func(in *ImportInput) { in.Config.Blocklist = items }
		}
		settings := func(mod func(*ExportedSettings)) func(*ImportInput) {
			return func(in *ImportInput) {
				s := &ExportedSettings{}
				mod(s)
				in.Config.Settings = s
			}
		}
		smtp := func(mod func(*ExportedSMTP)) func(*ImportInput) {
			return func(in *ImportInput) {
				s := &ExportedSMTP{Host: "smtp.example.com", Port: 25, Security: "none", FromAddress: "a@example.com"}
				mod(s)
				in.Config.SMTP = s
			}
		}
		asset := func(logo, background *ExportedAsset) func(*ImportInput) {
			return func(in *ImportInput) { in.Config.Branding = &ExportedBranding{Logo: logo, Background: background} }
		}
		tooWide := &ExportedAsset{MediaType: "image/png", DataBase64: base64.StdEncoding.EncodeToString(pngImage(t, branding.MaxBackgroundSide+1, 1))}
		for _, tc := range []struct {
			name, pointer string
			mod           func(*ImportInput)
		}{
			{"name", "/name", func(in *ImportInput) { in.Name = " " }},
			{"fqdn", "/fqdn", func(in *ImportInput) { in.FQDN = "bad host" }},
			{"admin host", "/fqdn", func(in *ImportInput) { in.FQDN = adminHost }},
			{"quota", "/storageQuotaBytes", func(in *ImportInput) { in.StorageQuotaBytes = 0 }},
			{"exportedAt", "/config/exportedAt", func(in *ImportInput) { in.Config.ExportedAt = time.Time{} }},
			{"sourceVersion empty", "/config/sourceVersion", func(in *ImportInput) { in.Config.SourceVersion = "" }},
			{"sourceVersion long", "/config/sourceVersion", func(in *ImportInput) { in.Config.SourceVersion = long }},
			{"sourceVersion control", "/config/sourceVersion", func(in *ImportInput) { in.Config.SourceVersion = "2.0\n" }},
			{"language", "/config/settings/defaultLanguage", settings(func(s *ExportedSettings) { s.DefaultLanguage = ptr("de") })},
			{"limit 0", "/config/settings/maxTransferBytes", settings(func(s *ExportedSettings) { s.MaxTransferBytes = ptr(int64(0)) })},
			{"limit too high", "/config/settings/maxTransferBytes", settings(func(s *ExportedSettings) { s.MaxTransferBytes = ptr(tenant.MaxTransferLimit + 1) })},
			{"ceiling 0", "/config/settings/maxTransferCeiling", settings(func(s *ExportedSettings) { s.MaxTransferCeiling = ptr(int64(0)) })},
			{"limit above ceiling", "/config/settings/maxTransferBytes", settings(func(s *ExportedSettings) {
				s.MaxTransferBytes, s.MaxTransferCeiling = ptr(int64(10)), ptr(int64(5))
			})},
			{"e2e", "/config/settings/e2ePolicy", settings(func(s *ExportedSettings) { s.E2EPolicy = ptr("sometimes") })},
			{"preset", "/config/branding/backgroundPreset", func(in *ImportInput) {
				in.Config.Branding = &ExportedBranding{BackgroundPreset: ptr("../../etc/passwd")}
			}},
			{"primary", "/config/branding/primaryColor", func(in *ImportInput) { in.Config.Branding = &ExportedBranding{PrimaryColor: ptr("red")} }},
			{"accent", "/config/branding/accentColor", func(in *ImportInput) { in.Config.Branding = &ExportedBranding{AccentColor: ptr("#12345")} }},
			{"media type", "/config/branding/logo/mediaType", asset(&ExportedAsset{MediaType: "image/svg+xml", DataBase64: validLogo(t).DataBase64}, nil)},
			{"base64 too long", "/config/branding/logo/dataBase64", asset(&ExportedAsset{
				MediaType: "image/png", DataBase64: strings.Repeat("A", int(base64.StdEncoding.EncodedLen(int(branding.MaxLogoBytes)))+4),
			}, nil)},
			{"not base64", "/config/branding/background/dataBase64", asset(nil, &ExportedAsset{MediaType: "image/jpeg", DataBase64: "!!!!"})},
			{"not an image", "/config/branding/logo/dataBase64", asset(&ExportedAsset{
				MediaType: "image/png", DataBase64: base64.StdEncoding.EncodeToString([]byte("<svg onload=alert(1)></svg>")),
			}, nil)},
			{"corrupt image", "/config/branding/logo/dataBase64", asset(&ExportedAsset{
				MediaType: "image/png", DataBase64: base64.StdEncoding.EncodeToString(corrupt),
			}, nil)},
			{"image too wide", "/config/branding/background/dataBase64", asset(validLogo(t), tooWide)},
			{"cidr", "/config/network/internalCidrs/2", func(in *ImportInput) {
				in.Config.Network = &ExportedNetwork{InternalCIDRs: []string{"10.0.0.0/8", "::1", "not-a-cidr-0x51"}}
			}},
			{"internal domain", "/config/network/internalDomains/0", func(in *ImportInput) {
				in.Config.Network = &ExportedNetwork{InternalDomains: []string{"a@b"}}
			}},
			{"smtp host", "/config/smtp/host", smtp(func(s *ExportedSMTP) { s.Host = "bad host" })},
			{"smtp port", "/config/smtp/port", smtp(func(s *ExportedSMTP) { s.Port = 0 })},
			{"smtp security", "/config/smtp/security", smtp(func(s *ExportedSMTP) { s.Security = "ssl" })},
			{"smtp from", "/config/smtp/fromAddress", smtp(func(s *ExportedSMTP) { s.FromAddress = "nobody" })},
			{"smtp from name", "/config/smtp/fromName", smtp(func(s *ExportedSMTP) { s.FromName = ptr("a\nb") })},
			{"recipient duplicate", "/config/recipientRules/deniedDomains/1", func(in *ImportInput) {
				in.Config.RecipientRules = &ExportedRecipientRules{DeniedDomains: []string{"example.net", "EXAMPLE.net."}}
			}},
			{"recipient allowed", "/config/recipientRules/allowedDomains/0", func(in *ImportInput) {
				in.Config.RecipientRules = &ExportedRecipientRules{AllowedDomains: []string{"not a domain"}}
			}},
			{"no level", "/config/confidentialityLevels/items", func(in *ImportInput) {
				in.Config.ConfidentialityLevels = &ExportedLevelList{}
			}},
			{"level key", "/config/confidentialityLevels/items/0/key", level(func(l *ExportedLevel) { l.Key = "Bad Key" })},
			{"level label", "/config/confidentialityLevels/items/0/labels/fr", level(func(l *ExportedLevel) { delete(l.Labels, "fr") })},
			{"level expiry", "/config/confidentialityLevels/items/0/rules/allowedExpiryDays", level(func(l *ExportedLevel) {
				l.Rules.AllowedExpiryDays = []int{2}
			})},
			{"level e2e", "/config/confidentialityLevels/items/0/rules/e2ePolicy", level(func(l *ExportedLevel) { l.Rules.E2EPolicy = ptr("sometimes") })},
			{"secret durations", "/config/secretSettings/durations", secrets(func(x *ExportedSecretSettings) { x.Durations = nil })},
			{"secret duration", "/config/secretSettings/durations/1", secrets(func(x *ExportedSecretSettings) { x.Durations = []string{"1h", "2d"} })},
			{"secret default", "/config/secretSettings/defaultDuration", secrets(func(x *ExportedSecretSettings) { x.DefaultDuration = ptr("7d") })},
			{"secret file", "/config/secretSettings/fileMaxBytes", secrets(func(x *ExportedSecretSettings) { x.FileMaxBytes = 5 })},
			{"office start", "/config/abuseThresholds/officeHours/start", abuse(func(a *ExportedAbuseThresholds) {
				a.OfficeHours = &ExportedOfficeHours{Start: "25:00", End: "18:00", Weekdays: []int{1}}
			})},
			{"office end", "/config/abuseThresholds/officeHours/end", abuse(func(a *ExportedAbuseThresholds) {
				a.OfficeHours = &ExportedOfficeHours{Start: "08:00", End: "8h", Weekdays: []int{1}}
			})},
			{"office weekdays", "/config/abuseThresholds/officeHours/weekdays", abuse(func(a *ExportedAbuseThresholds) {
				a.OfficeHours = &ExportedOfficeHours{Start: "08:00", End: "18:00", Weekdays: []int{1, 1}}
			})},
			{"office order", "/config/abuseThresholds/officeHours", abuse(func(a *ExportedAbuseThresholds) {
				a.OfficeHours = &ExportedOfficeHours{Start: "18:00", End: "08:00", Weekdays: []int{8 - 1}}
			})},
			{"time zone", "/config/abuseThresholds/timeZone", abuse(func(a *ExportedAbuseThresholds) { a.TimeZone = "Local" })},
			{"factor", "/config/abuseThresholds/unusualVolumeFactor", abuse(func(a *ExportedAbuseThresholds) { a.UnusualVolumeFactor = ptr(1.0) })},
			{"factor huge", "/config/abuseThresholds/unusualVolumeFactor", abuse(func(a *ExportedAbuseThresholds) { a.UnusualVolumeFactor = ptr(1e300) })},
			{"invitations", "/config/abuseThresholds/maxInvitationsPerInviter", abuse(func(a *ExportedAbuseThresholds) { a.MaxInvitationsPerInviter = 0 })},
			{"template key", "/config/emailTemplates/0/key", tpl(ExportedTemplate{Key: diskAlertKey, Language: "en"})},
			{"template language", "/config/emailTemplates/0/language", tpl(ExportedTemplate{Key: keyCode, Language: "de"})},
			{"template duplicate", "/config/emailTemplates/1", tpl(goodTpl, goodTpl)},
			{"template subject", "/config/emailTemplates/0/subject", tpl(ExportedTemplate{
				Key: keyCode, Language: "fr", Subject: "{{", BodyHTML: good.HTML, BodyText: good.Text,
			})},
			{"template text", "/config/emailTemplates/0/bodyText", tpl(ExportedTemplate{
				Key: keyCode, Language: "fr", Subject: good.Subject, BodyHTML: good.HTML, BodyText: "no code",
			})},
			{"template subject bounds", "/config/emailTemplates/0/subject", tpl(ExportedTemplate{
				Key: keyCode, Language: "fr", Subject: strings.Repeat("s", store.MaxEmailSubjectLen+1) + " {{tenant_name}}",
				BodyHTML: good.HTML, BodyText: good.Text,
			})},
			{"template body bounds", "/config/emailTemplates/0", tpl(ExportedTemplate{
				// The sanitizer escapes "&": the stored HTML outgrows the bound.
				Key: keyCode, Language: "fr", Subject: good.Subject, BodyHTML: good.HTML + strings.Repeat("&", store.MaxEmailBodyLen/2),
				BodyText: good.Text,
			})},
			{"legal document", "/config/legalDocuments/0/document", legal(ExportedLegalDocument{Document: "terms", Language: "en", Markdown: "x"})},
			{"legal language", "/config/legalDocuments/0/language", legal(ExportedLegalDocument{Document: store.LegalNotice, Language: "de", Markdown: "x"})},
			{"legal duplicate", "/config/legalDocuments/1", legal(
				ExportedLegalDocument{Document: store.LegalNotice, Language: "en", Markdown: "x"},
				ExportedLegalDocument{Document: store.LegalNotice, Language: "en", Markdown: "y"},
			)},
			{"legal markdown", "/config/legalDocuments/0/markdown", legal(ExportedLegalDocument{Document: store.PrivacyPolicy, Language: "en", Markdown: "a\x00b"})},
			{"webhooks", "/config/webhooks", func(in *ImportInput) {
				in.Config.Webhooks = make([]ExportedWebhook, store.MaxWebhooks+1)
			}},
			{"webhook name", "/config/webhooks/0/name", hook(func(w *ExportedWebhook) { w.Name = " " })},
			{"webhook kind", "/config/webhooks/0/kind", hook(func(w *ExportedWebhook) { w.Kind = "email" })},
			{"webhook no event", "/config/webhooks/0/events", hook(func(w *ExportedWebhook) { w.Events = nil })},
			{"webhook system event", "/config/webhooks/0/events/0", hook(func(w *ExportedWebhook) { w.Events = []string{"disk.alert_raised"} })},
			{"webhook duplicate event", "/config/webhooks/0/events/1", hook(func(w *ExportedWebhook) {
				w.Events = []string{"quota.reached", "quota.reached"}
			})},
			{"webhook enabled", "/config/webhooks/0/enabled", hook(func(w *ExportedWebhook) { w.Enabled = true })},
			{"block kind", "/config/blocklist/0/kind", block(ExportedBlocklistEntry{Kind: "ip", Value: "10.0.0.1"})},
			{"block empty", "/config/blocklist/0/value", block(ExportedBlocklistEntry{Kind: "domain", Value: "  "})},
			{"block long", "/config/blocklist/0/value", block(ExportedBlocklistEntry{Kind: "domain", Value: long})},
			{"block malformed", "/config/blocklist/0/value", block(ExportedBlocklistEntry{Kind: "email", Value: "nobody"})},
			{"block comment", "/config/blocklist/0/comment", block(ExportedBlocklistEntry{Kind: "domain", Value: "a.example", Comment: long + long})},
			{"block too many", "/config/blocklist", block(make([]ExportedBlocklistEntry, MaxImportBlocklistEntries+1)...)},
			{"block duplicate", "/config/blocklist/2/value", block(
				ExportedBlocklistEntry{Kind: "email", Value: "Bad@Example.COM"},
				ExportedBlocklistEntry{Kind: "domain", Value: "example.com"},
				ExportedBlocklistEntry{Kind: "email", Value: " bad@example.com "},
			)},
		} {
			in := minimalImport(fqdn)
			tc.mod(&in)
			_, err := ev.svc.ImportTenant(ctx, ev.super, in, clientIP)
			ie := importErrorAt(t, tc.name, err, tc.pointer)
			if strings.Contains(ie.Reason, "not-a-cidr-0x51") || strings.Contains(ie.Reason, "Bad@") {
				t.Errorf("%s: the reason quotes the value: %s", tc.name, ie.Reason)
			}
			if tc.name == "admin host" && ie.Code != CodeAdminHost {
				t.Errorf("admin host code = %q", ie.Code)
			}
			ev.tenantGone(t, fqdn)
		}
		if ev.strayFiles() != 0 || ev.importedEvents(ctx, t) != 0 {
			t.Error("a refused import left files or events")
		}
	})
}

// TestImportRollback makes each write of the import fail: nothing is
// created, no file is left, nothing is audited, no mail is queued.
func TestImportRollback(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev, _ := ssoEnv(t, e)
		ev.configure(t, 0)
		mailer := ev.withAdmins(t, true)
		cfg, err := ev.svc.ExportConfig(ctx, ev.adminA, ev.a.ID, true, clientIP)
		mustNoErr(t, "export", err)
		const fqdn = "c4.example.com"
		in := ImportInput{
			Name: "Entity C", FQDN: fqdn, StorageQuotaBytes: 1 << 40, Config: cfg,
			DelegatedAdmin: &adminauth.DelegatedAdmin{Username: "carl", Email: "carl@entity-c.example.com", Language: "en", Delivery: store.DeliveryCopy},
		}
		check := func(what string, err error, want error) {
			t.Helper()
			wantErr(t, what, err, want)
			if _, err := ev.db.Tenants().TenantByFQDN(ctx, fqdn); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("%s: the tenant exists: %v", what, err)
			}
			if n := ev.strayFiles(); n != 0 {
				t.Errorf("%s: %d files left", what, n)
			}
			if _, err := ev.db.Admins().GetByUsername(ctx, "carl"); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("%s: the delegated admin exists: %v", what, err)
			}
			if ev.importedEvents(ctx, t) != 0 || len(mailer.mails) != 0 {
				t.Errorf("%s: audited or mailed", what)
			}
		}
		for _, m := range []string{
			"replaceNetworkRulesTx", "replaceRecipientRulesTx", "replaceConfidentialityLevelsTx", "putAbuseSettingsTx",
			"putSMTPConfigTx", "putTemplateTx", "putLegalTx", "createBlocklistEntryTx",
		} {
			ev.faults(m)
			_, err := ev.svc.ImportTenant(ctx, ev.super, in, clientIP)
			check(m, err, errBoom)
		}
		// A failing file write restores the files already written.
		ev.faults()
		ev.assets.putErrAt = map[branding.Kind]error{branding.FaviconKinds()[1]: errBoom}
		_, err = ev.svc.ImportTenant(ctx, ev.super, in, clientIP)
		check("asset write", err, errBoom)
		ev.assets.putErrAt = nil
		// A failure once the files are written (a failed commit) removes
		// them.
		inner := ev.svc.repo
		ev.svc.repo = lateFailRepo{inner}
		_, err = ev.svc.ImportTenant(ctx, ev.super, in, clientIP)
		check("commit", err, errBoom)
		ev.svc.repo = inner
		// A failing favicon generation refuses the import before writing.
		ev.svc.favicons = func(context.Context, []byte) (branding.Favicons, error) { return branding.Favicons{}, errBoom }
		_, err = ev.svc.ImportTenant(ctx, ev.super, in, clientIP)
		check("favicons", err, errBoom)
		ev.svc.favicons = branding.GenerateFavicons

		// The view after the creation: the tenant stays created.
		ev.faults("usedBytes")
		_, err = ev.svc.ImportTenant(ctx, ev.super, in, clientIP)
		wantErr(t, "view", err, errBoom)
	})
}

// TestImportTemplateInternalError checks that an unexpected failure of the
// template validation is an internal error, not an import error.
func TestImportTemplateInternalError(t *testing.T) {
	prev := normalizeTemplate
	t.Cleanup(func() { normalizeTemplate = prev })
	normalizeTemplate = func(string, mail.TemplateSource) (mail.TemplateSource, error) {
		return mail.TemplateSource{}, errBoom
	}
	_, err := planTemplates([]ExportedTemplate{{Key: keyCode, Language: "en"}}, "")
	if !errors.Is(err, errBoom) || errors.Is(err, ErrImportInvalid) {
		t.Errorf("err = %v", err)
	}
	if err := atPointer("/x", errBoom); !errors.Is(err, errBoom) || errors.Is(err, ErrImportInvalid) {
		t.Errorf("atPointer passed %v", err)
	}
}

func TestAbuseConversions(t *testing.T) {
	a := store.DefaultAbuseSettings()
	a.UnusualVolumePct = ptr(150)
	a.OfficeStartMinute, a.OfficeEndMinute, a.OfficeWeekdays = ptr(0), ptr(23*60+59), 0b1000001
	back, err := AbuseFromAPI(*AbuseToAPI(a))
	mustNoErr(t, "convert", err)
	if !reflect.DeepEqual(a, back) {
		t.Errorf("round trip: %+v != %+v", back, a)
	}
	if _, ok := ParseClock("1:00", false); ok {
		t.Error("1:00 accepted")
	}
	if _, ok := ParseClock("24:00", false); ok {
		t.Error("24:00 accepted as a start")
	}
	if _, ok := WeekdayMask(nil); ok {
		t.Error("no weekday accepted")
	}
	f := AbuseToAPI(store.DefaultAbuseSettings())
	f.UnusualVolumeFactor = ptr(-1e300)
	got, err := AbuseFromAPI(*f)
	mustNoErr(t, "negative", err)
	if *got.UnusualVolumePct != 1<<31-1 {
		t.Errorf("huge negative factor = %d", *got.UnusualVolumePct)
	}
}
