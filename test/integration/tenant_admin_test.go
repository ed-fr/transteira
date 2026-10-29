package integration_test

import (
	"bytes"
	"encoding/json"
	"image/jpeg"
	"image/png"
	"net/http"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// End-to-end tests of the tenant configuration through the real HTTP
// server, on SQLite and PostgreSQL: creation by the super admin, branding,
// network rules, SMTP (test to Mailpit, SSRF guard), mail templates and
// legal texts by a delegated admin, the deposit mail of the configured
// tenant, the rights of each role, malicious inputs and the deletion of a
// tenant with its resumption (CLAUDE.md sections 5, 6.5, 12, 13, 16.1, 20
// and 21; docs/operations/tenants.md; threat model T-63, T-64, T-92,
// T-110, P21).

// customSubject, customHTML and customText are the customized
// transfer-notification template of tenant C. The HTML carries a script,
// an event handler and a remote image that the sanitizer must remove.
const (
	customSubject = "Custom notice from {{sender_email}} via {{tenant_name}}"
	customHTML    = `<p onclick="steal()">Custom body for C</p><script>alert(1)</script>` +
		`<img src="https://evil.example.com/pixel.png" alt="x">` +
		`<p><a href="{{download_link}}">Get the files</a></p>{{password_notice}}{{files}}`
	customText = "Custom text body for C\n{{download_link}}\n\n{{password_notice}}\n\n{{files}}\n"
	// legalC is the legal notice of tenant C, with raw HTML that must be
	// escaped on output.
	legalC = "# Legal notice of C\n\nPublisher: **Entity C**.\n\n<script>alert(1)</script>\n"
)

// expectSanitized asserts that html holds none of the dangerous parts of
// customHTML.
func expectSanitized(t *testing.T, what, html string) {
	t.Helper()
	for _, bad := range []string{"<script", "alert(1)", "onclick", "steal()", "evil.example.com"} {
		if strings.Contains(html, bad) {
			t.Errorf("%s contains %q:\n%s", what, bad, html)
		}
	}
}

// TestTenantAdminLifecycle: the super admin creates tenant C, whose host
// then resolves with the default branding; a delegated admin of C,
// activated through the link of the API response, configures colors,
// images, network rules, SMTP (tested against Mailpit), the DNS check, a
// mail template and the legal notice. A deposit on C then sends the
// customized, sanitized mail, and the public pages of C reflect the
// configuration. Every change is audited without secrets.
func TestTenantAdminLifecycle(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		o, _ := withScanner(t, serverOptions{})
		a := startAdmin(t, e, o, true)
		sa := a.bootstrap(t, adminIP(1))

		// 1. Before its creation, C's host is unknown.
		expectProblem(t, a.get(t, hostC, pathPublicTenant), http.StatusMisdirectedRequest, "unknown-tenant")
		c := sa.createTenantC(t)
		pub := a.publicTenant(t, hostC)
		if pub.Name != nameC || pub.Branding.PrimaryColor != defaultPrimary || pub.Branding.AccentColor != defaultAccent ||
			pub.Branding.HasLogo || pub.Branding.HasBackground || pub.Branding.LogoURL != nil ||
			pub.Branding.BackgroundURL != pathPublicBg || pub.Limits.MaxTransferBytes != ceilingC/2 || len(pub.LegalDocuments) != 0 {
			t.Errorf("public tenant C after creation = %+v", pub)
		}
		expectProblem(t, a.get(t, hostC, pathPublicLogo), http.StatusNotFound, "not-found")
		if resp := a.get(t, hostC, pathPublicBg); resp.status != http.StatusOK || resp.header.Get("Content-Type") != "image/jpeg" {
			t.Errorf("default background of C: %d %q", resp.status, resp.header.Get("Content-Type"))
		}
		dc := sa.createDelegatedOf(t, "delegate-c", c.ID, domainC, adminIP(2))
		if me := dc.me(t); len(me.Tenants) != 1 || me.Tenants[0].ID != c.ID || me.Tenants[0].FQDN != hostC {
			t.Errorf("delegated admin of C sees tenants %+v", me.Tenants)
		}

		// 2. Colors: a failing pair is accepted and reported.
		resp := mustStatus(t, "updateBranding", dc.call(t, http.MethodPut, tenantPath(c.ID, "/branding"),
			map[string]string{"primaryColor": "#0b5fff", "accentColor": "#ffff00"}), http.StatusOK)
		var br brandingJSON
		mustJSON(t, resp.body, &br)
		if br.PrimaryColor != "#0B5FFF" || br.AccentColor != "#FFFF00" || len(br.Contrast) == 0 {
			t.Errorf("branding = %+v, want the colors in upper case with contrast results", br)
		}
		failing := false
		for _, cr := range br.Contrast {
			if cr.Pair == "accent-on-light" && cr.Level == "fail" && cr.Ratio < 4.5 {
				failing = true
			}
		}
		if !failing {
			t.Errorf("contrast = %+v, want accent-on-light at level fail", br.Contrast)
		}

		// Images: re-encoded, metadata stripped, ETag and 304, nosniff.
		logo := pngWithText(t, 64, 32, "logo-metadata-marker")
		mustStatus(t, "upload logo", dc.putBytes(t, tenantPath(c.ID, "/branding/logo"), "image/png", logo), http.StatusNoContent)
		bg := jpegWithExif(t, 320, 200, "exif-gps-marker")
		mustStatus(t, "upload background", dc.putBytes(t, tenantPath(c.ID, "/branding/background"), "image/jpeg", bg), http.StatusNoContent)
		servedLogo := expectServedAsset(t, a.server, pathPublicLogo, "image/png", logo, "logo-metadata-marker")
		if _, err := png.Decode(bytes.NewReader(servedLogo)); err != nil {
			t.Errorf("served logo is not a PNG: %v", err)
		}
		servedBg := expectServedAsset(t, a.server, pathPublicBg, "image/jpeg", bg, "exif-gps-marker")
		if bytes.Contains(servedBg, []byte("Exif")) {
			t.Error("served background still carries an Exif segment")
		}
		if _, err := jpeg.Decode(bytes.NewReader(servedBg)); err != nil {
			t.Errorf("served background is not a JPEG: %v", err)
		}

		// Network rules.
		resp = mustStatus(t, "updateNetworkRules", dc.call(t, http.MethodPut, tenantPath(c.ID, "/network"),
			map[string][]string{"internalCidrs": {internalNetC}, "internalDomains": {domainC}}), http.StatusOK)
		var rules struct {
			CIDRs   []string `json:"internalCidrs"`
			Domains []string `json:"internalDomains"`
		}
		mustJSON(t, resp.body, &rules)
		if !slices.Equal(rules.CIDRs, []string{internalNetC}) || !slices.Equal(rules.Domains, []string{domainC}) {
			t.Errorf("network rules = %+v", rules)
		}

		// Confidentiality levels and recipient rules.
		resp = mustStatus(t, "updateConfidentialityLevels", dc.call(t, http.MethodPut, tenantPath(c.ID, "/confidentiality-levels"),
			map[string]any{"items": []map[string]any{{
				"key": "open", "labels": map[string]string{"en": "Open", "fr": "Ouvert"}, "isDefault": true,
				"rules": map[string]any{
					"requireRecipientVerification": false, "requirePassword": false, "allowedExpiryDays": []int{7},
					"internalRecipientsOnly": false, "forceDeleteAfterFirstDownload": false, "maxDownloads": 3,
				},
			}}}), http.StatusOK)
		var levels struct {
			Items []struct {
				Key   string `json:"key"`
				Rules struct {
					RequirePassword   bool  `json:"requirePassword"`
					AllowedExpiryDays []int `json:"allowedExpiryDays"`
					MaxDownloads      *int  `json:"maxDownloads"`
				} `json:"rules"`
			} `json:"items"`
		}
		mustJSON(t, resp.body, &levels)
		if len(levels.Items) != 1 || levels.Items[0].Key != "open" || levels.Items[0].Rules.RequirePassword ||
			!slices.Equal(levels.Items[0].Rules.AllowedExpiryDays, []int{7}) || *levels.Items[0].Rules.MaxDownloads != 3 {
			t.Errorf("confidentiality levels = %s", resp.body)
		}
		expectProblem(t, dc.call(t, http.MethodPut, tenantPath(c.ID, "/confidentiality-levels"),
			map[string]any{"items": []map[string]any{{
				"key": "Bad Key", "labels": map[string]string{"en": "Open", "fr": "Ouvert"}, "isDefault": true,
				"rules": map[string]any{
					"requireRecipientVerification": false, "requirePassword": false, "allowedExpiryDays": []int{7},
					"internalRecipientsOnly": false, "forceDeleteAfterFirstDownload": false, "maxDownloads": nil,
				},
			}}}), http.StatusBadRequest, "validation-failed")
		resp = mustStatus(t, "updateRecipientRules", dc.call(t, http.MethodPut, tenantPath(c.ID, "/recipient-rules"),
			// A deny rule, so that the later deposit on C to example.net still passes.
			map[string][]string{"allowedDomains": {}, "deniedDomains": {"Webmail.Example.org."}}), http.StatusOK)
		var recipients struct {
			Allowed []string `json:"allowedDomains"`
			Denied  []string `json:"deniedDomains"`
		}
		mustJSON(t, resp.body, &recipients)
		if !slices.Equal(recipients.Denied, []string{"webmail.example.org"}) || recipients.Allowed == nil || len(recipients.Allowed) != 0 {
			t.Errorf("recipient rules = %s", resp.body)
		}
		expectProblem(t, dc.call(t, http.MethodPut, tenantPath(c.ID, "/recipient-rules"),
			map[string][]string{"allowedDomains": {"a@b.example"}, "deniedDomains": {}}), http.StatusBadRequest, "validation-failed")

		// The abuse thresholds (since 1.1): the defaults, a full replacement,
		// then the refusal of a body that forgets a member (which would
		// silently disable its rule) and of a bad time zone.
		resp = mustStatus(t, "getAbuseThresholds", dc.call(t, http.MethodGet, tenantPath(c.ID, "/abuse-thresholds"), nil), http.StatusOK)
		var thresholds map[string]any
		mustJSON(t, resp.body, &thresholds)
		thresholds["maxDailyTransfersPerSender"] = 40
		thresholds["blockOnExceed"] = true
		thresholds["unusualVolumeFactor"] = 4.5
		thresholds["officeHours"] = map[string]any{"start": "08:30", "end": "24:00", "weekdays": []int{1, 2, 3, 4, 5}}
		resp = mustStatus(t, "updateAbuseThresholds", dc.call(t, http.MethodPut, tenantPath(c.ID, "/abuse-thresholds"), thresholds), http.StatusOK)
		var stored struct {
			MaxTransfers *int     `json:"maxDailyTransfersPerSender"`
			Block        bool     `json:"blockOnExceed"`
			Factor       *float64 `json:"unusualVolumeFactor"`
			Office       *struct {
				Start, End string
				Weekdays   []int
			} `json:"officeHours"`
		}
		mustJSON(t, resp.body, &stored)
		if stored.MaxTransfers == nil || *stored.MaxTransfers != 40 || !stored.Block || stored.Factor == nil || *stored.Factor != 4.5 ||
			stored.Office == nil || stored.Office.Start != "08:30" || stored.Office.End != "24:00" ||
			!slices.Equal(stored.Office.Weekdays, []int{1, 2, 3, 4, 5}) {
			t.Errorf("abuse thresholds = %s", resp.body)
		}
		delete(thresholds, "externalMaxDailyBytes")
		expectProblem(t, dc.call(t, http.MethodPut, tenantPath(c.ID, "/abuse-thresholds"), thresholds), http.StatusBadRequest, "validation-failed")
		thresholds["externalMaxDailyBytes"] = nil
		thresholds["timeZone"] = "Mars/Olympus"
		expectProblem(t, dc.call(t, http.MethodPut, tenantPath(c.ID, "/abuse-thresholds"), thresholds), http.StatusBadRequest, "validation-failed")

		// SMTP to Mailpit, then the test mail.
		resp = mustStatus(t, "updateSmtpSettings", dc.call(t, http.MethodPut, tenantPath(c.ID, "/smtp"), map[string]any{
			"host": a.mp.host, "port": a.mp.port, "security": "none", "fromAddress": "noreply@" + domainC, "fromName": nameC,
		}), http.StatusOK)
		var smtp smtpJSON
		mustJSON(t, resp.body, &smtp)
		if smtp.Host != a.mp.host || smtp.Port != a.mp.port || smtp.PasswordSet || smtp.FromAddress != "noreply@"+domainC {
			t.Errorf("smtp settings = %+v", smtp)
		}
		testTo := uniqueEmail(t, "smtp-test", "example.net")
		resp = mustStatus(t, "testSmtp", dc.call(t, http.MethodPost, tenantPath(c.ID, "/smtp/test"), map[string]string{"to": testTo}), http.StatusOK)
		var res smtpTestJSON
		mustJSON(t, resp.body, &res)
		if !res.Success || res.Stage != "done" || res.Error != nil {
			t.Errorf("testSmtp = %s, want success at stage done", resp.body)
		}
		msg := a.mp.waitSubject(t, testTo, "TransTeira SMTP test - "+nameC)
		if msg.From.Address != "noreply@"+domainC {
			t.Errorf("test mail From = %q", msg.From.Address)
		}

		// DNS check: only the shape (the *.localhost domain has no record,
		// and the lookups may fail offline).
		resp = mustStatus(t, "checkMailDns", dc.call(t, http.MethodGet, tenantPath(c.ID, "/smtp/dns-check?dkimSelector=selector1"), nil), http.StatusOK)
		expectDNSShape(t, resp.body)

		// Template and legal notice.
		resp = mustStatus(t, "updateEmailTemplate", dc.call(t, http.MethodPut, tenantPath(c.ID, "/email-templates/transfer-notification/en"),
			map[string]string{"subject": customSubject, "bodyHtml": customHTML, "bodyText": customText}), http.StatusOK)
		var tpl templateJSON
		mustJSON(t, resp.body, &tpl)
		if !tpl.Customized || tpl.Subject != customSubject || !strings.Contains(tpl.BodyHTML, "Custom body for C") ||
			!strings.Contains(tpl.BodyHTML, "{{download_link}}") || tpl.BodyText != customText {
			t.Errorf("saved template = %+v", tpl)
		}
		expectSanitized(t, "saved template", tpl.BodyHTML)
		resp = mustStatus(t, "getEmailTemplate", dc.call(t, http.MethodGet, tenantPath(c.ID, "/email-templates/transfer-notification/en"), nil), http.StatusOK)
		var got templateJSON
		mustJSON(t, resp.body, &got)
		if got.BodyHTML != tpl.BodyHTML || !got.Customized {
			t.Errorf("stored template = %+v, want the saved one", got)
		}
		mustStatus(t, "updateLegalDocument", dc.call(t, http.MethodPut, tenantPath(c.ID, "/legal/legal-notice/en"),
			map[string]string{"markdown": legalC}), http.StatusOK)

		// The delegated admin raises the limit up to the ceiling.
		resp = mustStatus(t, "raise the limit to the ceiling", dc.mergePatch(t, tenantPath(c.ID, ""),
			`{"maxTransferBytes":`+strconv.FormatInt(ceilingC, 10)+`}`), http.StatusOK)
		var upd tenantJSON
		mustJSON(t, resp.body, &upd)
		if upd.MaxTransferBytes != ceilingC || upd.MaxTransferCeiling != ceilingC {
			t.Errorf("tenant after the raise = %+v", upd)
		}

		// The public configuration of C reflects it all.
		pub = a.publicTenant(t, hostC)
		if pub.Branding.PrimaryColor != "#0B5FFF" || pub.Branding.AccentColor != "#FFFF00" || !pub.Branding.HasLogo ||
			!pub.Branding.HasBackground || pub.Branding.LogoURL == nil || *pub.Branding.LogoURL != pathPublicLogo ||
			pub.Limits.MaxTransferBytes != ceilingC || !slices.Equal(pub.LegalDocuments, []string{"legal-notice"}) {
			t.Errorf("public tenant C after configuration = %+v", pub)
		}
		resp = mustStatus(t, "public legal notice", a.get(t, hostC, pathPublicLegal+"legal-notice"), http.StatusOK)
		var legal legalJSON
		mustJSON(t, resp.body, &legal)
		if legal.HTML == nil || !strings.Contains(*legal.HTML, "Legal notice of C") ||
			!strings.Contains(*legal.HTML, "<strong>Entity C</strong>") || strings.Contains(*legal.HTML, "<script") ||
			legal.Markdown != legalC || legal.Language != "en" {
			t.Errorf("public legal notice = %s", resp.body)
		}
		// Tenant A is untouched.
		if pa := a.publicTenant(t, hostA); pa.Name != nameA || pa.Branding.HasLogo || len(pa.LegalDocuments) != 0 {
			t.Errorf("public tenant A changed: %+v", pa)
		}

		// A deposit on C by an internal user of C sends the customized,
		// sanitized notification.
		dep := &depositor{d: a.depositEnv, host: hostC, ip: insideC}
		sender := uniqueEmail(t, "alice", domainC)
		if s := dep.openSession(t, sender, ""); s.Kind != "internal" {
			t.Errorf("session kind on C = %q, want internal", s.Kind)
		}
		rcpt := uniqueEmail(t, "rcpt-c", "example.net")
		tr, _ := dep.availableTransfer(t, transferCreate{Recipients: []string{rcpt}},
			uploadedFile{name: "report.txt", content: []byte("quarterly figures of C")})
		note := a.mp.waitSubject(t, rcpt, "Custom notice from "+sender+" via "+nameC)
		if !strings.Contains(note.HTML, "Custom body for C") || !strings.Contains(note.HTML, tr.DownloadURL) ||
			!strings.Contains(note.text(), "Custom text body for C") || !strings.Contains(note.text(), tr.DownloadURL) {
			t.Errorf("notification of C does not use the customized template:\nHTML %s\nText %s", note.HTML, note.Text)
		}
		expectSanitized(t, "notification mail", note.HTML)
		if !strings.HasPrefix(tr.DownloadURL, "https://"+hostC+"/") {
			t.Errorf("download URL %q, want one of %s", tr.DownloadURL, hostC)
		}

		// 7. Audit of every change, without secret.
		rows := a.expectTenantAudit(t, c.ID, "tenant.created", "tenant.updated", "tenant.branding_updated",
			"tenant.asset_uploaded", "tenant.network_updated", "tenant.confidentiality_updated", "tenant.recipient_rules_updated",
			"tenant.smtp_updated", "tenant.smtp_tested",
			"tenant.template_updated", "tenant.legal_updated")
		a.expectNoSecrets(t, rows)
	})
}

// expectServedAsset fetches the public asset path of tenant C and checks
// it: 200 with the exact type, nosniff, a strong ETag and a cache policy;
// bytes re-encoded (different from the input, without marker); then 304
// on If-None-Match. It returns the served bytes.
func expectServedAsset(t *testing.T, s *server, path, contentType string, input []byte, marker string) []byte {
	t.Helper()
	resp := mustStatus(t, "GET "+path, s.get(t, hostC, path), http.StatusOK)
	etag := resp.header.Get("ETag")
	if resp.header.Get("Content-Type") != contentType || resp.header.Get("X-Content-Type-Options") != "nosniff" ||
		!strings.HasPrefix(etag, `"`) || resp.header.Get("Cache-Control") == "" {
		t.Errorf("%s headers = %v", path, resp.header)
	}
	if bytes.Equal(resp.body, input) {
		t.Errorf("%s served the uploaded bytes as is", path)
	}
	if bytes.Contains(resp.body, []byte(marker)) {
		t.Errorf("%s still carries the metadata %q", path, marker)
	}
	nm := s.do(t, request{host: hostC, path: path, headers: http.Header{"If-None-Match": {etag}}})
	if nm.status != http.StatusNotModified || len(nm.body) != 0 || nm.header.Get("ETag") != etag {
		t.Errorf("%s with If-None-Match: %d (%d bytes), want 304 without body", path, nm.status, len(nm.body))
	}
	return resp.body
}

// expectDNSShape checks the structure of a MailDnsCheck answer.
func expectDNSShape(t *testing.T, body []byte) {
	t.Helper()
	var chk struct {
		Domain string `json:"domain"`
		SPF    struct {
			Status string `json:"status"`
		} `json:"spf"`
		DKIM struct {
			Status    string `json:"status"`
			Selectors []struct {
				Selector string `json:"selector"`
				Found    bool   `json:"found"`
			} `json:"selectors"`
		} `json:"dkim"`
		DMARC struct {
			Status string `json:"status"`
		} `json:"dmarc"`
	}
	mustJSON(t, body, &chk)
	statuses := []string{"ok", "warning", "missing", "error"}
	if chk.Domain != domainC || !slices.Contains(statuses, chk.SPF.Status) || !slices.Contains(statuses, chk.DKIM.Status) ||
		!slices.Contains(statuses, chk.DMARC.Status) || len(chk.DKIM.Selectors) != 1 || chk.DKIM.Selectors[0].Selector != "selector1" {
		t.Errorf("checkMailDns = %s", body)
	}
}

// configureC gives tenant C, as admin c, the branding, SMTP settings,
// template and legal notice the rights tests check afterwards.
func configureC(t *testing.T, c *adminClient, tid string) {
	t.Helper()
	mustStatus(t, "updateBranding", c.call(t, http.MethodPut, tenantPath(tid, "/branding"),
		map[string]string{"primaryColor": "#123456", "accentColor": "#654321"}), http.StatusOK)
	mustStatus(t, "upload logo", c.putBytes(t, tenantPath(tid, "/branding/logo"), "image/png", pngWithText(t, 16, 16, "x")), http.StatusNoContent)
	mustStatus(t, "updateSmtpSettings", c.call(t, http.MethodPut, tenantPath(tid, "/smtp"), map[string]any{
		"host": "smtp-relay.example.org", "port": 25, "security": "none", "fromAddress": "noreply@" + domainC,
	}), http.StatusOK)
	mustStatus(t, "updateEmailTemplate", c.call(t, http.MethodPut, tenantPath(tid, "/email-templates/transfer-notification/en"),
		map[string]string{"subject": customSubject, "bodyHtml": customHTML, "bodyText": customText}), http.StatusOK)
	mustStatus(t, "updateLegalDocument", c.call(t, http.MethodPut, tenantPath(tid, "/legal/legal-notice/en"),
		map[string]string{"markdown": legalC}), http.StatusOK)
}

// tenantOp is one admin operation on a tenant ID.
type tenantOp struct {
	name   string
	method string
	sub    string // path after the tenant ID
	body   string
	ctype  string
}

// tenantOps lists the 24 operations of api/openapi.yaml taking a tenant
// ID, with valid inputs (so that only the tenant decides the answer).
func tenantOps(t *testing.T) []tenantOp {
	t.Helper()
	tplBody, err := json.Marshal(map[string]string{"subject": customSubject, "bodyHtml": customHTML, "bodyText": customText})
	if err != nil {
		t.Fatal(err)
	}
	return []tenantOp{
		{"getTenant", http.MethodGet, "", "", ""},
		{"updateTenant", http.MethodPatch, "", `{"defaultLanguage":"fr"}`, mergePatch},
		{"deleteTenant", http.MethodDelete, confirmQuery(nameC), "", ""},
		{"getBranding", http.MethodGet, "/branding", "", ""},
		{"updateBranding", http.MethodPut, "/branding", `{"primaryColor":"#000000","accentColor":"#FFFFFF"}`, contentJSON},
		{"uploadBrandingAsset", http.MethodPut, "/branding/logo", string(pngWithText(t, 8, 8, "y")), "image/png"},
		{"deleteBrandingAsset", http.MethodDelete, "/branding/logo", "", ""},
		{"getNetworkRules", http.MethodGet, "/network", "", ""},
		{"updateNetworkRules", http.MethodPut, "/network", `{"internalCidrs":["10.0.0.0/8"],"internalDomains":["example.org"]}`, contentJSON},
		{"getConfidentialityLevels", http.MethodGet, "/confidentiality-levels", "", ""},
		{"updateConfidentialityLevels", http.MethodPut, "/confidentiality-levels", `{"items":[{"key":"open","labels":{"en":"Open","fr":"Ouvert"},"isDefault":true,"rules":{"requireRecipientVerification":false,"requirePassword":false,"allowedExpiryDays":[1,7,30],"internalRecipientsOnly":false,"forceDeleteAfterFirstDownload":false,"maxDownloads":null}}]}`, contentJSON},
		{"getRecipientRules", http.MethodGet, "/recipient-rules", "", ""},
		{"updateRecipientRules", http.MethodPut, "/recipient-rules", `{"allowedDomains":["example.org"],"deniedDomains":[]}`, contentJSON},
		{"getSmtpSettings", http.MethodGet, "/smtp", "", ""},
		{"updateSmtpSettings", http.MethodPut, "/smtp", `{"host":"mail.example.org","port":25,"security":"none","fromAddress":"x@example.org"}`, contentJSON},
		{"testSmtp", http.MethodPost, "/smtp/test", `{"to":"probe@example.org"}`, contentJSON},
		{"checkMailDns", http.MethodGet, "/smtp/dns-check", "", ""},
		{"listEmailTemplates", http.MethodGet, "/email-templates", "", ""},
		{"getEmailTemplate", http.MethodGet, "/email-templates/transfer-notification/en", "", ""},
		{"updateEmailTemplate", http.MethodPut, "/email-templates/transfer-notification/en", string(tplBody), contentJSON},
		{"resetEmailTemplate", http.MethodDelete, "/email-templates/transfer-notification/en", "", ""},
		{"previewEmailTemplate", http.MethodPost, "/email-templates/transfer-notification/en/preview", "", ""},
		{"getLegalDocumentAdmin", http.MethodGet, "/legal/legal-notice/en", "", ""},
		{"updateLegalDocument", http.MethodPut, "/legal/legal-notice/en", `{"markdown":"overwritten by A"}`, contentJSON},
	}
}

// run sends op as client c on the tenant tid.
func (op tenantOp) run(t *testing.T, c *adminClient, tid string) response {
	t.Helper()
	var extra http.Header
	if op.method != http.MethodGet {
		extra = http.Header{hdrCSRF: {c.csrf}}
		if op.ctype != "" {
			extra.Set("Content-Type", op.ctype)
		}
	}
	var body any
	if op.body != "" {
		body = op.body
	}
	return c.send(t, op.method, tenantPath(tid, op.sub), body, extra)
}

// unknownTenantID returns a well-formed tenant ID differing from tid.
func unknownTenantID(tid string) string {
	last := tid[len(tid)-1]
	repl := byte('0')
	if last == '0' {
		repl = '1'
	}
	return tid[:len(tid)-1] + string(repl)
}

// TestTenantAdminRights: a delegated admin of C may lower or raise the
// limit up to the ceiling only and change no reserved setting; a delegated
// admin of A gets, for each of the 24 operations on C's ID, exactly the
// answer of an unknown ID and changes nothing of C; the FQDN can be
// neither an admin host nor one already used.
func TestTenantAdminRights(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		a := startAdmin(t, e, serverOptions{}, false)
		sa := a.bootstrap(t, adminIP(1))
		c := sa.createTenantC(t)
		dc := sa.createDelegatedOf(t, "delegate-c", c.ID, domainC, adminIP(2))
		da := sa.createDelegatedOf(t, "delegate-a", string(a.tenantA.ID), domainA, adminIP(3))
		configureC(t, dc, c.ID)

		// Delegated admin of C: the reserved settings are refused.
		path := tenantPath(c.ID, "")
		for _, patch := range []string{
			`{"maxTransferBytes":` + strconv.FormatInt(ceilingC+1, 10) + `}`,
			`{"storageQuotaBytes":` + strconv.FormatInt(quotaC*2, 10) + `}`,
			`{"maxTransferCeiling":` + strconv.FormatInt(ceilingC*2, 10) + `}`,
			`{"fqdn":"transfer.other.localhost"}`,
			`{"name":"Renamed by the delegate"}`,
			`{"defaultLanguage":"fr","storageQuotaBytes":1}`,
		} {
			expectProblem(t, dc.mergePatch(t, path, patch), http.StatusForbidden, "forbidden")
		}
		expectProblem(t, dc.call(t, http.MethodDelete, path+confirmQuery(nameC), nil), http.StatusForbidden, "forbidden")
		expectProblem(t, dc.call(t, http.MethodPost, pathTenants, map[string]any{
			"name": "Entity D", "fqdn": "transfer.entity-d.localhost", "defaultLanguage": "en", "storageQuotaBytes": 1 << 30,
		}), http.StatusForbidden, "forbidden")
		resp := mustStatus(t, "lower the limit", dc.mergePatch(t, path, `{"maxTransferBytes":1048576,"defaultLanguage":"fr"}`), http.StatusOK)
		var cur tenantJSON
		mustJSON(t, resp.body, &cur)
		if cur.Name != nameC || cur.FQDN != hostC || cur.StorageQuotaBytes != quotaC || cur.MaxTransferCeiling != ceilingC ||
			cur.MaxTransferBytes != 1048576 || cur.DefaultLanguage != "fr" {
			t.Errorf("tenant C after the delegate's changes = %+v", cur)
		}
		if m := sysQuery(t, e, `SELECT name, fqdn, storage_quota_bytes FROM tenants WHERE id = '`+c.ID+`'`); len(m) != 1 ||
			m[0][0] != nameC || m[0][1] != hostC || m[0][2] != strconv.FormatInt(quotaC, 10) {
			t.Errorf("tenant row of C = %v", m)
		}

		// Delegated admin of A on C's ID: the answer of an unknown ID.
		unknown := unknownTenantID(c.ID)
		for _, op := range tenantOps(t) {
			onC, onUnknown := op.run(t, da, c.ID), op.run(t, da, unknown)
			want, code := http.StatusNotFound, "not-found"
			if op.name == "deleteTenant" {
				// Reserved to the super admin whatever the tenant.
				want, code = http.StatusForbidden, "forbidden"
			}
			expectProblem(t, onC, want, code)
			expectProblem(t, onUnknown, want, code)
			if problemWithoutInstance(t, onC.body) != problemWithoutInstance(t, onUnknown.body) {
				t.Errorf("%s: C's ID answers %s, an unknown ID %s", op.name, onC.body, onUnknown.body)
			}
			for _, leak := range []string{nameC, hostC, "smtp-relay", "Legal notice of C", "#123456"} {
				if strings.Contains(string(onC.body), leak) {
					t.Errorf("%s on C's ID leaks %q: %s", op.name, leak, onC.body)
				}
			}
		}
		// listTenants shows A only.
		resp = mustStatus(t, "listTenants by A's delegate", da.call(t, http.MethodGet, pathTenants, nil), http.StatusOK)
		var list struct {
			Items []tenantJSON `json:"items"`
		}
		mustJSON(t, resp.body, &list)
		if len(list.Items) != 1 || list.Items[0].ID != string(a.tenantA.ID) {
			t.Errorf("listTenants of A's delegate = %s", resp.body)
		}
		// Nothing of C changed.
		resp = mustStatus(t, "getBranding of C", dc.call(t, http.MethodGet, tenantPath(c.ID, "/branding"), nil), http.StatusOK)
		var br brandingJSON
		mustJSON(t, resp.body, &br)
		if br.PrimaryColor != "#123456" || br.AccentColor != "#654321" || !br.HasLogo {
			t.Errorf("branding of C = %+v", br)
		}
		resp = mustStatus(t, "getSmtpSettings of C", dc.call(t, http.MethodGet, tenantPath(c.ID, "/smtp"), nil), http.StatusOK)
		var smtp smtpJSON
		mustJSON(t, resp.body, &smtp)
		if smtp.Host != "smtp-relay.example.org" {
			t.Errorf("smtp of C = %+v", smtp)
		}
		resp = mustStatus(t, "getEmailTemplate of C", dc.call(t, http.MethodGet, tenantPath(c.ID, "/email-templates/transfer-notification/en"), nil), http.StatusOK)
		var tpl templateJSON
		mustJSON(t, resp.body, &tpl)
		if !tpl.Customized || tpl.Subject != customSubject {
			t.Errorf("template of C = %+v", tpl)
		}
		resp = mustStatus(t, "getLegalDocumentAdmin of C", dc.call(t, http.MethodGet, tenantPath(c.ID, "/legal/legal-notice/en"), nil), http.StatusOK)
		var legal legalJSON
		mustJSON(t, resp.body, &legal)
		if legal.Markdown != legalC {
			t.Errorf("legal notice of C = %+v", legal)
		}
		if n := countSystem(t, e, `SELECT COUNT(*) FROM tenants WHERE id = '`+c.ID+`' AND status = 'active'`); n != 1 {
			t.Errorf("tenant C is no longer active (%d rows)", n)
		}
		if got := a.publicTenant(t, hostC); got.Branding.PrimaryColor != "#123456" {
			t.Errorf("public branding of C = %+v", got.Branding)
		}

		// FQDN rules: never an admin host (400), never a used one (409).
		for _, body := range []map[string]any{
			{"name": "Entity Admin", "fqdn": adminHost, "defaultLanguage": "en", "storageQuotaBytes": 1 << 30},
			{"name": "Entity Admin", "fqdn": strings.ToUpper(adminHost), "defaultLanguage": "en", "storageQuotaBytes": 1 << 30},
		} {
			expectFieldError(t, sa.call(t, http.MethodPost, pathTenants, body), "/fqdn")
		}
		expectFieldError(t, sa.mergePatch(t, path, `{"fqdn":"`+adminHost+`"}`), "/fqdn")
		expectProblem(t, sa.call(t, http.MethodPost, pathTenants, map[string]any{
			"name": "Entity A bis", "fqdn": hostA, "defaultLanguage": "en", "storageQuotaBytes": 1 << 30,
		}), http.StatusConflict, "already-exists")
		expectProblem(t, sa.mergePatch(t, path, `{"fqdn":"`+hostA+`"}`), http.StatusConflict, "already-exists")
		if got := a.publicTenant(t, hostA); got.Name != nameA {
			t.Errorf("host A now serves %q", got.Name)
		}
	})
}

// expectFieldError asserts a 400 validation-failed naming field.
func expectFieldError(t *testing.T, resp response, field string) fieldProblem {
	t.Helper()
	expectProblem(t, resp, http.StatusBadRequest, "validation-failed")
	var p fieldProblem
	mustJSON(t, resp.body, &p)
	if !slices.ContainsFunc(p.Errors, func(e fieldErr) bool { return e.Field == field }) {
		t.Errorf("errors = %s, want one on %s", resp.body, field)
	}
	return p
}

// TestTenantAdminMaliciousInputs: trapped images (SVG, polyglot with an
// HTML trailer, decompression bomb, non-image type) and malicious
// templates (Go template syntax, missing required variable, script, event
// handler, remote image) are refused or sanitized.
func TestTenantAdminMaliciousInputs(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		a := startAdmin(t, e, serverOptions{}, false)
		sa := a.bootstrap(t, adminIP(1))
		c := sa.createTenantC(t)
		dc := sa.createDelegatedOf(t, "delegate-c", c.ID, domainC, adminIP(2))
		logoPath := tenantPath(c.ID, "/branding/logo")

		// SVG, even declared as an image: 415.
		svg := []byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`)
		expectProblem(t, dc.putBytes(t, logoPath, "image/svg+xml", svg), http.StatusUnsupportedMediaType, "unsupported-media-type")
		// A real PNG declared with a non-image type: 415.
		plain := pngWithText(t, 16, 16, "z")
		for _, ct := range []string{"text/html", "application/octet-stream"} {
			expectProblem(t, dc.putBytes(t, logoPath, ct, plain), http.StatusUnsupportedMediaType, "unsupported-media-type")
		}
		// Decompression bomb: refused before decoding.
		bomb := dc.putBytes(t, logoPath, "image/png", pngBomb(t, 60000))
		if bomb.status != http.StatusRequestEntityTooLarge && bomb.status != http.StatusBadRequest {
			t.Errorf("decompression bomb: %d %s, want 413 or 400", bomb.status, bomb.body)
		}
		bgBomb := dc.putBytes(t, tenantPath(c.ID, "/branding/background"), "image/png", pngBomb(t, 1<<20))
		if bgBomb.status != http.StatusRequestEntityTooLarge && bgBomb.status != http.StatusBadRequest {
			t.Errorf("background decompression bomb: %d %s, want 413 or 400", bgBomb.status, bgBomb.body)
		}
		if p := a.publicTenant(t, hostC); p.Branding.HasLogo || p.Branding.HasBackground {
			t.Errorf("a refused image was stored: %+v", p.Branding)
		}
		// Polyglot: a PNG followed by an HTML document, accepted and served
		// without the trailer.
		trailer := "<html><body><script>alert(document.cookie)</script></body></html>"
		poly := append(pngWithText(t, 24, 24, "poly"), trailer...)
		mustStatus(t, "polyglot logo", dc.putBytes(t, logoPath, "image/png", poly), http.StatusNoContent)
		served := mustStatus(t, "served polyglot", a.get(t, hostC, pathPublicLogo), http.StatusOK)
		if bytes.Contains(served.body, []byte("<script")) || bytes.Contains(served.body, []byte("<html")) ||
			served.header.Get("Content-Type") != "image/png" || served.header.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("served polyglot keeps its trailer or lacks its type: %v", served.header)
		}
		if _, err := png.Decode(bytes.NewReader(served.body)); err != nil {
			t.Errorf("served polyglot is not a PNG: %v", err)
		}

		// Templates: template syntax is refused with line and column.
		tplPath := tenantPath(c.ID, "/email-templates/transfer-notification/en")
		resp := dc.call(t, http.MethodPut, tplPath, map[string]string{
			"subject": "Files from {{.SenderEmail}}", "bodyHtml": customHTML, "bodyText": customText,
		})
		expectTemplateIssue(t, resp, "/subject", 1)
		resp = dc.call(t, http.MethodPut, tplPath, map[string]string{
			"subject": customSubject, "bodyHtml": "<p>Hello</p>\n{{ if .Password }}secret{{ end }}" + customHTML, "bodyText": customText,
		})
		expectTemplateIssue(t, resp, "/bodyHtml", 2)
		resp = dc.call(t, http.MethodPut, tplPath, map[string]string{
			"subject": customSubject, "bodyHtml": customHTML, "bodyText": "{{ printf \"%s\" .Link }}\n" + customText,
		})
		expectTemplateIssue(t, resp, "/bodyText", 1)
		// A missing required variable is refused.
		resp = dc.call(t, http.MethodPut, tplPath, map[string]string{
			"subject": customSubject, "bodyHtml": customHTML, "bodyText": "No link here\n{{password_notice}}\n{{files}}",
		})
		expectFieldError(t, resp, "/bodyText")
		resp = dc.call(t, http.MethodPut, tplPath, map[string]string{
			"subject": customSubject, "bodyHtml": "<p>{{download_link}}</p>{{files}}", "bodyText": customText,
		})
		expectFieldError(t, resp, "/bodyHtml")
		// An unknown variable is refused too.
		resp = dc.call(t, http.MethodPut, tplPath, map[string]string{
			"subject": "{{admin_password}}", "bodyHtml": customHTML, "bodyText": customText,
		})
		expectFieldError(t, resp, "/subject")
		if got := mustStatus(t, "getEmailTemplate", dc.call(t, http.MethodGet, tplPath, nil), http.StatusOK); strings.Contains(string(got.body), customizedTrue) {
			t.Errorf("a refused template was stored: %s", got.body)
		}
		// Script, event handler and remote image are removed from the
		// stored template, in both languages.
		for _, lang := range []string{"en", "fr"} {
			p := tenantPath(c.ID, "/email-templates/transfer-notification/"+lang)
			mustStatus(t, "updateEmailTemplate "+lang, dc.call(t, http.MethodPut, p,
				map[string]string{"subject": customSubject, "bodyHtml": customHTML, "bodyText": customText}), http.StatusOK)
			got := mustStatus(t, "getEmailTemplate "+lang, dc.call(t, http.MethodGet, p, nil), http.StatusOK)
			var tpl templateJSON
			mustJSON(t, got.body, &tpl)
			if !tpl.Customized || !strings.Contains(tpl.BodyHTML, "Custom body for C") || !strings.Contains(tpl.BodyHTML, `href="{{download_link}}"`) {
				t.Errorf("stored template %s = %+v", lang, tpl)
			}
			expectSanitized(t, "stored template "+lang, tpl.BodyHTML)
		}
		// The preview renders the sanitized template.
		prev := mustStatus(t, "previewEmailTemplate", dc.call(t, http.MethodPost, tplPath+"/preview", nil), http.StatusOK)
		expectSanitized(t, "preview", string(prev.body))
		if !strings.Contains(string(prev.body), "Custom body for C") {
			t.Errorf("preview does not render the customized template: %s", prev.body)
		}
	})
}

// expectTemplateIssue asserts a 400 validation-failed with an
// invalid-template error on field at line, with a column.
func expectTemplateIssue(t *testing.T, resp response, field string, line int) {
	t.Helper()
	p := expectFieldError(t, resp, field)
	for _, fe := range p.Errors {
		if fe.Field == field {
			if fe.Code != "invalid-template" || fe.Line != line || fe.Column < 1 || fe.Message == "" {
				t.Errorf("error on %s = %+v, want invalid-template at line %d with a column and a message", field, fe, line)
			}
			return
		}
	}
}

// TestTenantAdminSMTPDeniedLiteral covers the SMTP SSRF guard (P21): an
// SMTP host given as an IP literal in a denied network is refused at save.
func TestTenantAdminSMTPDeniedLiteral(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		a := startAdmin(t, e, serverOptions{}, false)
		sa := a.bootstrap(t, adminIP(1))
		path := tenantPath(string(a.tenantA.ID), "/smtp")
		for _, host := range []string{"169.254.169.254", "::ffff:169.254.169.254", "fe80::1"} {
			resp := sa.call(t, http.MethodPut, path, map[string]any{
				"host": host, "port": 25, "security": "none", "fromAddress": "noreply@" + domainA,
			})
			expectFieldError(t, resp, "/host")
		}
		expectProblem(t, sa.call(t, http.MethodGet, path, nil), http.StatusNotFound, "not-found")

		// A stored password never follows a change of host or port: it
		// must be given again (or removed), else the change is refused.
		pw := "relay-password-literal-test"
		a.secret(pw)
		mustStatus(t, "save with a password", sa.call(t, http.MethodPut, path, map[string]any{
			"host": "smtp.example.org", "port": 587, "security": "starttls", "username": "relay", "password": pw,
			"fromAddress": "noreply@" + domainA,
		}), http.StatusOK)
		for _, moved := range []map[string]any{
			{"host": "collector.example.net", "port": 587},
			{"host": "smtp.example.org", "port": 2525},
		} {
			moved["security"], moved["username"], moved["fromAddress"] = "starttls", "relay", "noreply@"+domainA
			expectFieldError(t, sa.call(t, http.MethodPut, path, moved), "/password")
		}
		resp := mustStatus(t, "getSmtpSettings", sa.call(t, http.MethodGet, path, nil), http.StatusOK)
		var smtp smtpJSON
		mustJSON(t, resp.body, &smtp)
		if smtp.Host != "smtp.example.org" || smtp.Port != 587 || !smtp.PasswordSet || strings.Contains(string(resp.body), pw) {
			t.Errorf("smtp settings after the refused moves = %s", resp.body)
		}
		a.expectNoSecrets(t, a.expectTenantAudit(t, string(a.tenantA.ID), "tenant.smtp_updated"))
	})
}

// TestTenantAdminSMTPDeniedResolved: with the default deny list, a host
// name resolving to the loopback is saved but never contacted, neither by
// the test send nor by a regular tenant mail.
func TestTenantAdminSMTPDeniedResolved(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		a := startAdmin(t, e, serverOptions{env: map[string]string{config.EnvSMTPDenyNetworks: config.DefaultSMTPDenyNetworks}}, false)
		sa := a.bootstrap(t, adminIP(1))
		relay := newCountingListener(t)
		path := tenantPath(string(a.tenantA.ID), "/smtp")
		resp := sa.call(t, http.MethodPut, path, map[string]any{
			"host": "127.0.0.1", "port": relay.port(), "security": "none", "fromAddress": "noreply@" + domainA,
		})
		expectFieldError(t, resp, "/host")
		// A name is saved: it is checked when resolved, at connection.
		mustStatus(t, "save localhost", sa.call(t, http.MethodPut, path, map[string]any{
			"host": "localhost", "port": relay.port(), "security": "none", "fromAddress": "noreply@" + domainA,
		}), http.StatusOK)
		resp = mustStatus(t, "testSmtp", sa.call(t, http.MethodPost, path+"/test", map[string]string{"to": "probe@example.net"}), http.StatusOK)
		var res smtpTestJSON
		mustJSON(t, resp.body, &res)
		if res.Success || res.Stage != "connect" || res.Error == nil || !strings.Contains(*res.Error, "denied network") {
			t.Errorf("testSmtp to localhost = %s, want a refusal at connect (denied network)", resp.body)
		}
		// A regular tenant mail (verification code) is not delivered.
		email := uniqueEmail(t, "alice", domainA)
		expectChallenge(t, a.newDepositor().start(t, email, ""), email)
		line := waitLog(t, a.server, `"msg":"mail delivery failed"`, `"recipients":["`+mail.AddressHash(email)+`"]`)
		if !strings.Contains(line, "denied network") {
			t.Errorf("mail delivery failure is not the deny list: %s", line)
		}
		if a.mailSentLines(t, email) != 0 {
			t.Error("the verification code was reported sent")
		}
		if n := relay.accepted.Load(); n != 0 {
			t.Errorf("the loopback relay received %d connections, want none", n)
		}
		if strings.Contains(a.appLog.String(), email) {
			t.Error("the application log contains the address in clear")
		}
	})
}

// cBundle is tenant C populated for a deletion test: a transfer available
// and one uploading, an SMTP password, both images, a template and a
// legal notice.
type cBundle struct {
	c       tenantJSON
	smtpPw  string
	files   []string
	keyRows int
}

// populateC creates tenant C as the super admin sa and fills it.
func populateC(t *testing.T, a *adminEnv, sa *adminClient) cBundle {
	t.Helper()
	c := sa.createTenantC(t)
	mustStatus(t, "raise C's limit", sa.mergePatch(t, tenantPath(c.ID, ""), `{"maxTransferBytes":`+strconv.FormatInt(ceilingC, 10)+`}`), http.StatusOK)
	mustStatus(t, "network of C", sa.call(t, http.MethodPut, tenantPath(c.ID, "/network"),
		map[string][]string{"internalCidrs": {internalNetC}, "internalDomains": {domainC}}), http.StatusOK)
	mustStatus(t, "smtp of C", sa.call(t, http.MethodPut, tenantPath(c.ID, "/smtp"), map[string]any{
		"host": a.mp.host, "port": a.mp.port, "security": "none", "fromAddress": "noreply@" + domainC,
	}), http.StatusOK)
	dep := &depositor{d: a.depositEnv, host: hostC, ip: insideC}
	dep.openSession(t, uniqueEmail(t, "alice", domainC), "")
	rcpt := uniqueEmail(t, "rcpt-c", "example.net")
	dep.availableTransfer(t, transferCreate{Recipients: []string{rcpt}}, uploadedFile{name: "done.txt", content: []byte("available content of C")})
	// The notification is delivered before the SMTP settings change.
	a.waitMailSent(t, rcpt)
	partial := seededBytes(t, 7, 4096)
	up := dep.mustCreate(t, transferCreate{Recipients: []string{rcpt}, ExpiryDays: 7, Files: []fileDecl{{Name: "partial.bin", Size: 8192}}})
	dep.mustPatch(t, up.Files[0].UploadURL, 0, partial)
	pw := "smtp-password-of-tenant-c-7f3a9e"
	a.secret(pw)
	resp := mustStatus(t, "smtp password of C", sa.call(t, http.MethodPut, tenantPath(c.ID, "/smtp"), map[string]any{
		"host": a.mp.host, "port": a.mp.port, "security": "starttls", "username": "relay-user", "password": pw,
		"fromAddress": "noreply@" + domainC,
	}), http.StatusOK)
	if strings.Contains(string(resp.body), pw) || !strings.Contains(string(resp.body), `"passwordSet":true`) {
		t.Errorf("smtp settings answer = %s", resp.body)
	}
	mustStatus(t, "logo of C", sa.putBytes(t, tenantPath(c.ID, "/branding/logo"), "image/png", pngWithText(t, 32, 32, "l")), http.StatusNoContent)
	mustStatus(t, "background of C", sa.putBytes(t, tenantPath(c.ID, "/branding/background"), "image/jpeg", jpegWithExif(t, 64, 48, "b")), http.StatusNoContent)
	mustStatus(t, "template of C", sa.call(t, http.MethodPut, tenantPath(c.ID, "/email-templates/transfer-notification/en"),
		map[string]string{"subject": customSubject, "bodyHtml": customHTML, "bodyText": customText}), http.StatusOK)
	mustStatus(t, "legal notice of C", sa.call(t, http.MethodPut, tenantPath(c.ID, "/legal/legal-notice/en"),
		map[string]string{"markdown": legalC}), http.StatusOK)

	b := cBundle{c: c, smtpPw: pw, files: filesUnder(t, a.tenantDirOf(c.ID))}
	b.keyRows = countSystem(t, a.e, `SELECT COUNT(*) FROM wrapped_keys WHERE tenant_id = '`+c.ID+`'`)
	// At least the file key and the download token of the available
	// transfer, the file key of the uploading one and the SMTP password.
	if b.keyRows < 4 {
		t.Errorf("tenant C has %d wrapped keys, want at least 4", b.keyRows)
	}
	// The two images, the encrypted files and the checkpoint.
	if len(b.files) < 4 {
		t.Errorf("tenant C has %d files on disk, want at least 4: %v", len(b.files), b.files)
	}
	statuses := sysQuery(t, a.e, `SELECT status FROM transfers WHERE tenant_id = '`+c.ID+`' ORDER BY status`)
	if len(statuses) != 2 || statuses[0][0] != "available" || statuses[1][0] != "uploading" {
		t.Errorf("transfers of C = %v, want available and uploading", statuses)
	}
	return b
}

// expectErased asserts that tenant C is entirely gone: host 421, no row,
// no key, no directory; its audit events are kept, without its SMTP
// password; tenants A and B are untouched.
func expectErased(t *testing.T, a *adminEnv, s *server, b cBundle) {
	t.Helper()
	expectProblem(t, s.get(t, hostC, pathPublicTenant), http.StatusMisdirectedRequest, "unknown-tenant")
	for table, n := range tenantRows(t, a.e, b.c.ID) {
		if n != 0 {
			t.Errorf("%s still holds %d rows of the deleted tenant", table, n)
		}
	}
	if _, err := os.Stat(s.tenantDirOf(b.c.ID)); !os.IsNotExist(err) {
		t.Errorf("tenant directory of C: %v, want it removed (files left: %v)", err, filesUnder(t, s.tenantDirOf(b.c.ID)))
	}
	for _, f := range b.files {
		if _, err := os.Stat(f); !os.IsNotExist(err) {
			t.Errorf("file %s of C: %v, want it removed", f, err)
		}
	}
	rows := a.expectTenantAudit(t, b.c.ID, "tenant.created", "tenant.smtp_updated", "tenant.asset_uploaded",
		"tenant.template_updated", "tenant.legal_updated")
	for _, r := range rows {
		if strings.Contains(r.details, b.smtpPw) {
			t.Errorf("audit event %s contains the SMTP password", r.action)
		}
	}
	for _, other := range []string{string(a.tenantA.ID), string(a.tenantB.ID)} {
		if n := countSystem(t, a.e, `SELECT COUNT(*) FROM tenants WHERE id = '`+other+`'`); n != 1 {
			t.Errorf("tenant %s was deleted too", other)
		}
	}
	if p := s.publicTenant(t, hostA); p.Name != nameA {
		t.Errorf("host A serves %q", p.Name)
	}
}

// TestTenantAdminDeletion: deleting tenant C with a wrong confirmation is
// refused; an interrupted deletion leaves C deleting (host 421, change
// refused) and a new call resumes it; afterwards nothing of C remains but
// its audit events, and its FQDN serves a new tenant.
func TestTenantAdminDeletion(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		o, _ := withScanner(t, serverOptions{})
		a := startAdmin(t, e, o, true)
		sa := a.bootstrap(t, adminIP(1))
		b := populateC(t, a, sa)
		dc := sa.createDelegatedOf(t, "delegate-c", b.c.ID, domainC, adminIP(2))
		path := tenantPath(b.c.ID, "")

		for _, wrong := range []string{"", "entity c integration", nameC + " ", "Entity A Integration"} {
			resp := sa.call(t, http.MethodDelete, path+confirmQuery(wrong), nil)
			if wrong == "" {
				// The confirm parameter is required by the contract.
				expectProblem(t, resp, http.StatusBadRequest, "validation-failed")
				continue
			}
			expectFieldError(t, resp, "confirm")
		}
		if p := a.publicTenant(t, hostC); p.Name != nameC {
			t.Fatalf("C after refused deletions = %+v", p)
		}

		// Interrupted deletion: the tenant directory cannot be removed.
		release := blockTenantDir(t, a.tenantDirOf(b.c.ID))
		if release != nil {
			resp := sa.call(t, http.MethodDelete, path+confirmQuery(nameC), nil)
			expectProblem(t, resp, http.StatusInternalServerError, "internal-error")
			resp = mustStatus(t, "getTenant while deleting", sa.call(t, http.MethodGet, path, nil), http.StatusOK)
			var tn tenantJSON
			mustJSON(t, resp.body, &tn)
			if tn.Status != "deleting" {
				t.Errorf("tenant C after the interrupted deletion = %+v, want status deleting", tn)
			}
			expectProblem(t, a.get(t, hostC, pathPublicTenant), http.StatusMisdirectedRequest, "unknown-tenant")
			expectProblem(t, sa.call(t, http.MethodPut, tenantPath(b.c.ID, "/branding"),
				map[string]string{"primaryColor": "#000000", "accentColor": "#FFFFFF"}), http.StatusNotFound, "not-found")
			expectProblem(t, dc.call(t, http.MethodGet, path, nil), http.StatusNotFound, "not-found")
			if n := countSystem(t, e, `SELECT COUNT(*) FROM wrapped_keys WHERE tenant_id = '`+b.c.ID+`' AND id IN (
				SELECT dek_key_id FROM transfer_files WHERE tenant_id = '`+b.c.ID+`')`); n != 0 {
				t.Errorf("%d file keys of C survived the interrupted deletion, want them destroyed first", n)
			}
			release()
		} else {
			t.Log("the tenant directory cannot be locked on this platform: the interrupted deletion is covered by TestTenantAdminDeletionResumedAtStartup only")
		}

		mustStatus(t, "deleteTenant", sa.call(t, http.MethodDelete, path+confirmQuery(nameC), nil), http.StatusNoContent)
		expectErased(t, a, a.server, b)
		expectProblem(t, sa.call(t, http.MethodGet, path, nil), http.StatusNotFound, "not-found")
		expectProblem(t, sa.call(t, http.MethodDelete, path+confirmQuery(nameC), nil), http.StatusNotFound, "not-found")
		if me := dc.me(t); len(me.Tenants) != 0 {
			t.Errorf("the delegate of the deleted tenant still sees %+v", me.Tenants)
		}
		// Started by the super admin (once per call), erased and recorded
		// once, the interrupted call included.
		a.expectDeletionAudit(t, b.c.ID, nameC, hostC, adminIP(1))

		// The FQDN is free again.
		resp := mustStatus(t, "create a tenant on the freed FQDN", sa.call(t, http.MethodPost, pathTenants, map[string]any{
			"name": "Entity C Reborn", "fqdn": hostC, "defaultLanguage": "fr", "storageQuotaBytes": 1 << 30,
		}), http.StatusCreated)
		var reborn tenantJSON
		mustJSON(t, resp.body, &reborn)
		if reborn.ID == b.c.ID {
			t.Errorf("the new tenant reuses the deleted ID %s", b.c.ID)
		}
		p := a.publicTenant(t, hostC)
		if p.Name != "Entity C Reborn" || p.Branding.HasLogo || p.Branding.HasBackground || len(p.LegalDocuments) != 0 {
			t.Errorf("new tenant on %s inherits data of the deleted one: %+v", hostC, p)
		}
		expectProblem(t, a.get(t, hostC, pathPublicLogo), http.StatusNotFound, "not-found")
		resp = mustStatus(t, "template of the new tenant", sa.call(t, http.MethodGet,
			tenantPath(reborn.ID, "/email-templates/transfer-notification/en"), nil), http.StatusOK)
		if strings.Contains(string(resp.body), customizedTrue) {
			t.Errorf("the new tenant inherits the template: %s", resp.body)
		}
		expectProblem(t, sa.call(t, http.MethodGet, tenantPath(reborn.ID, "/smtp"), nil), http.StatusNotFound, "not-found")
	})
}

// blockTenantDir makes the removal of dir fail and returns the function
// that lifts the block, or nil when the platform offers no way to do so
// (or the test runs as root).
func blockTenantDir(t *testing.T, dir string) func() {
	t.Helper()
	files := filesUnder(t, dir)
	if len(files) == 0 {
		t.Fatalf("no file in %s to block its removal", dir)
	}
	if runtime.GOOS == "windows" {
		// An open file cannot be deleted on Windows (no FILE_SHARE_DELETE).
		f, err := os.Open(files[0])
		if err != nil {
			t.Fatal(err)
		}
		var once bool
		release := func() {
			if !once {
				once = true
				_ = f.Close()
			}
		}
		t.Cleanup(release)
		return release
	}
	if os.Geteuid() == 0 {
		return nil
	}
	// The entries of a read-only directory cannot be removed.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	var once bool
	release := func() {
		if !once {
			once = true
			_ = os.Chmod(dir, 0o700)
		}
	}
	t.Cleanup(release)
	return release
}

// TestTenantAdminDeletionResumedAtStartup: a tenant left deleting (a
// deletion interrupted by a failure, or a crash right after the status
// change) is erased by the tenant-deletions task when the server starts
// again, which records tenant.deleted once.
func TestTenantAdminDeletionResumedAtStartup(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		o, _ := withScanner(t, serverOptions{})
		a := startAdmin(t, e, o, true)
		sa := a.bootstrap(t, adminIP(1))
		b := populateC(t, a, sa)
		startedFrom := ""
		if release := blockTenantDir(t, a.tenantDirOf(b.c.ID)); release != nil {
			// The deletion started by the super admin fails half-way.
			resp := sa.call(t, http.MethodDelete, tenantPath(b.c.ID, "")+confirmQuery(nameC), nil)
			expectProblem(t, resp, http.StatusInternalServerError, "internal-error")
			release()
			startedFrom = adminIP(1)
		}
		if err := a.stop(); err != nil {
			t.Fatalf("stop: %v\napp log:\n%s", err, a.appLog)
		}
		if startedFrom == "" {
			// The crash happened right after the status change.
			execSystem(t, e, `UPDATE tenants SET status = 'deleting' WHERE id = '`+b.c.ID+`'`)
		}
		s2 := a.restart(t)
		waitLog(t, s2, `"msg":"lifecycle: tenant erased"`, `"tenant":"`+b.c.ID+`"`)
		expectErased(t, a, s2, b)
		a.expectDeletionAudit(t, b.c.ID, nameC, hostC, startedFrom)
		if strings.Contains(s2.appLog.String(), b.smtpPw) || strings.Contains(a.appLog.String(), b.smtpPw) {
			t.Error("the application log contains the SMTP password")
		}
	})
}
