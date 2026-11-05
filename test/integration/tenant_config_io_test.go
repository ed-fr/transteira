package integration_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// Integration tests of the export and the import of a tenant configuration
// (V2 step 5; api/openapi.yaml exportTenantConfig and importTenant; threat
// model T-300 to T-306): a real round trip through HTTP, on both engines.

const (
	// Secrets configured on the source tenant: none may appear in the export.
	ioSMTPUser     = "smtp-user-io-4c1"
	ioSMTPPassword = "io-smtp-password-7f3a"
	// ioHostD and ioNameD name the imported tenant.
	ioHostD = "transfer.entity-d.localhost"
	ioNameD = "Entity D Imported"
	// importQuota is the storage quota of the imported tenant.
	importQuota = int64(1 << 39)
	// ioBlockedDomain is the blocklist entry of the source tenant.
	ioBlockedDomain = "spam-io.example.net"
	// customizedMember is the member of an EmailTemplate (spec spelling).
	customizedMember = "customised" //nolint:misspell // member name of the OpenAPI schema
	pathImport       = "/api/v1/admin/tenants/import"
	// importLimit is the body limit of importTenant (32 MiB).
	importLimit = 32 << 20
)

// createAuditorOf creates, as the super admin c, an auditor of tenant tid
// and returns it signed in.
func (c *adminClient) createAuditorOf(t *testing.T, username, tid, ip string) *adminClient {
	t.Helper()
	acct := &adminAccount{username: username, email: uniqueEmail(t, username, domainA), password: "auditor password " + username}
	resp := mustStatus(t, "createAdmin "+username, c.call(t, http.MethodPost, pathAdmins, map[string]any{
		"username": username, "email": acct.email, "role": "auditor", "tenantIds": []string{tid},
	}), http.StatusCreated)
	_, token := c.a.activationOf(t, resp)
	c.a.secret(acct.password)
	d := c.a.client(acct, ip)
	if resp := d.activate(t, token); resp.status != http.StatusOK {
		t.Fatalf("activate %s: %d %s", username, resp.status, resp.body)
	}
	if d.state == stateEnrollRequired {
		d.enroll(t)
	}
	return d
}

// tenantCount returns the number of tenants the super admin lists.
func tenantCount(t *testing.T, sa *adminClient) int {
	t.Helper()
	resp := mustStatus(t, "listTenants", sa.call(t, http.MethodGet, pathTenants+"?limit=200", nil), http.StatusOK)
	var list struct {
		Items []json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(resp.body, &list); err != nil {
		var plain []json.RawMessage
		mustJSON(t, resp.body, &plain)
		return len(plain)
	}
	return len(list.Items)
}

// importBody returns the body of importTenant around the document cfg.
func importBody(name, fqdn, cfg string) string {
	return `{"name":` + quoteJSON(name) + `,"fqdn":` + quoteJSON(fqdn) + `,"storageQuotaBytes":` + "549755813888" + `,"config":` + cfg + `}`
}

func quoteJSON(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// getJSON GETs path as c and decodes the 200 answer to a generic value.
func getJSON(t *testing.T, c *adminClient, path string) any {
	t.Helper()
	resp := mustStatus(t, "GET "+path, c.call(t, http.MethodGet, path, nil), http.StatusOK)
	var v any
	mustJSON(t, resp.body, &v)
	return v
}

// TestTenantConfigRoundTrip configures tenant A completely, exports it,
// checks that the file holds no secret, imports it as a new tenant and
// compares the configuration of both through the API.
func TestTenantConfigRoundTrip(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		s := startSSO(t, e, serverOptions{env: map[string]string{
			config.EnvWebhookAllowNetworks:     "127.0.0.0/8",
			config.EnvWebhookAllowHTTPNetworks: "127.0.0.0/8",
		}})
		a, sa := s.adminEnv, s.sa
		a.secret(webhookURLToken, ioSMTPPassword)
		tidA := string(a.tenantA.ID)
		rcv := newWebhookReceiver(t)
		deleg := sa.createDelegatedOf(t, "delegate-io", tidA, domainA, adminIP(40))
		auditor := sa.createAuditorOf(t, "auditor-io", tidA, adminIP(41))

		// --- Configure tenant A completely, as the API clients would.
		mustStatus(t, "branding", sa.call(t, http.MethodPut, tenantPath(tidA, "/branding"),
			map[string]string{"primaryColor": "#0B5FFF", "accentColor": "#7A2E00"}), http.StatusOK)
		mustStatus(t, "logo", sa.putBytes(t, tenantPath(tidA, "/branding/logo"), "image/png", pngWithText(t, 32, 16, "io-logo")), http.StatusNoContent)
		mustStatus(t, "network", sa.call(t, http.MethodPut, tenantPath(tidA, "/network"),
			map[string][]string{"internalCidrs": {"100.64.20.0/24", "100.64.21.0/24"}, "internalDomains": {domainA, "partner.example.org"}}), http.StatusOK)
		mustStatus(t, "recipient rules", sa.call(t, http.MethodPut, tenantPath(tidA, "/recipient-rules"),
			map[string][]string{"allowedDomains": {}, "deniedDomains": {"webmail.example.org"}}), http.StatusOK)
		mustStatus(t, "levels", sa.call(t, http.MethodPut, tenantPath(tidA, "/confidentiality-levels"),
			map[string]any{"items": []map[string]any{{
				"key": "open", "labels": map[string]string{"en": "Open", "fr": "Ouvert"}, "isDefault": true,
				"rules": map[string]any{
					"requireRecipientVerification": false, "requirePassword": false, "allowedExpiryDays": []int{7},
					"internalRecipientsOnly": false, "forceDeleteAfterFirstDownload": false, "maxDownloads": 3,
				},
			}}}), http.StatusOK)
		var thresholds map[string]any
		mustJSON(t, mustStatus(t, "get abuse", sa.call(t, http.MethodGet, tenantPath(tidA, "/abuse-thresholds"), nil), http.StatusOK).body, &thresholds)
		thresholds["maxDailyTransfersPerSender"] = 40
		thresholds["blockOnExceed"] = true
		thresholds["unusualVolumeFactor"] = 4.5
		thresholds["officeHours"] = map[string]any{"start": "08:30", "end": "24:00", "weekdays": []int{1, 2, 3, 4, 5}}
		mustStatus(t, "abuse", sa.call(t, http.MethodPut, tenantPath(tidA, "/abuse-thresholds"), thresholds), http.StatusOK)
		mustStatus(t, "smtp", sa.call(t, http.MethodPut, tenantPath(tidA, "/smtp"), map[string]any{
			"host": "mail.example.org", "port": 587, "security": "starttls", "username": ioSMTPUser, "password": ioSMTPPassword,
			"fromAddress": "noreply@" + domainA, "fromName": nameA,
		}), http.StatusOK)
		mustStatus(t, "template", sa.call(t, http.MethodPut, tenantPath(tidA, "/email-templates/transfer-notification/en"),
			map[string]string{"subject": customSubject, "bodyHtml": customHTML, "bodyText": customText}), http.StatusOK)
		mustStatus(t, "legal", sa.call(t, http.MethodPut, tenantPath(tidA, "/legal/legal-notice/en"),
			map[string]string{"markdown": legalC}), http.StatusOK)
		mustStatus(t, "blocklist", sa.call(t, http.MethodPost, tenantPath(tidA, "/blocklist"),
			map[string]string{"kind": "domain", "value": ioBlockedDomain, "comment": "spam"}), http.StatusCreated)
		wh := sa.mustCreateWebhook(t, tidA, map[string]any{
			"name": "Round trip hook", "kind": "generic", "url": rcv.url(), "events": []string{"virus.detected"},
		})
		mustStatus(t, "sso", s.putSSO(t, tidA, s.ssoBody([]string{domainA}, nil)), http.StatusOK)

		// --- Export.
		exportPath := tenantPath(tidA, "/export?includeBranding=true")
		exp := mustStatus(t, "exportTenantConfig", sa.call(t, http.MethodGet, exportPath, nil), http.StatusOK)
		expectContract(t, "exportTenantConfig", http.MethodGet, exportPath, exp)
		if got, want := exp.header.Get("Content-Disposition"), `attachment; filename="tenant-`+hostA+`-config.json"`; got != want {
			t.Errorf("Content-Disposition = %q, want %q", got, want)
		}
		if cc := exp.header.Get("Cache-Control"); cc != "no-store" {
			t.Errorf("Cache-Control = %q, want no-store", cc)
		}
		if ct := exp.header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
			t.Errorf("Content-Type = %q", ct)
		}
		raw := string(exp.body)
		for _, secret := range []string{
			ioSMTPUser, ioSMTPPassword, webhookURLToken, rcv.srv.URL, wh.Secret, s.idp.Issuer(), s.idp.ClientSecret(), "clientId", "clientSecret",
			`"issuer"`, `"password"`, `"username"`, `"sso"`, `"apiToken"`,
		} {
			if secret != "" && strings.Contains(raw, secret) {
				t.Errorf("the export holds %q: %s", secret, raw)
			}
		}
		var doc map[string]any
		mustJSON(t, exp.body, &doc)
		hooks, _ := doc["webhooks"].([]any)
		if len(hooks) != 1 {
			t.Fatalf("export webhooks = %v, want the one of A", doc["webhooks"])
		}
		if h := hooks[0].(map[string]any); h["enabled"] != false || h["name"] != "Round trip hook" || h["url"] != nil {
			t.Errorf("exported webhook = %v, want name and enabled:false, no url", h)
		}
		if _, ok := doc["branding"].(map[string]any)["logo"]; !ok {
			t.Errorf("includeBranding=true: no logo in %v", doc["branding"])
		}
		// Without branding images by default.
		plain := mustStatus(t, "export without images", sa.call(t, http.MethodGet, tenantPath(tidA, "/export"), nil), http.StatusOK)
		expectContract(t, "exportTenantConfig", http.MethodGet, tenantPath(tidA, "/export"), plain)
		if strings.Contains(string(plain.body), `"logo"`) {
			t.Errorf("an export without includeBranding holds the logo")
		}
		a.expectTenantAudit(t, tidA, "tenant.exported")

		// Delegated admin of A: allowed on A; auditor: 403; another tenant, unknown tenant: 404.
		own := mustStatus(t, "delegated export", deleg.call(t, http.MethodGet, tenantPath(tidA, "/export"), nil), http.StatusOK)
		expectContract(t, "exportTenantConfig", http.MethodGet, tenantPath(tidA, "/export"), own)
		aud := auditor.call(t, http.MethodGet, tenantPath(tidA, "/export"), nil)
		expectProblem(t, aud, http.StatusForbidden, "read-only-role")
		expectContract(t, "exportTenantConfig", http.MethodGet, tenantPath(tidA, "/export"), aud)
		other := deleg.call(t, http.MethodGet, tenantPath(string(a.tenantB.ID), "/export"), nil)
		expectProblem(t, other, http.StatusNotFound, "not-found")
		expectContract(t, "exportTenantConfig", http.MethodGet, tenantPath(string(a.tenantB.ID), "/export"), other)
		for _, r := range a.tenantAudit(t, string(a.tenantB.ID)) {
			if r.action == "tenant.exported" {
				t.Errorf("tenant B has a tenant.exported event after a refused export")
			}
		}

		// --- Import as a new tenant.
		before := tenantCount(t, sa)
		okBody := importBody(ioNameD, ioHostD, string(exp.body))
		created := sa.call(t, http.MethodPost, pathImport, okBody)
		mustStatus(t, "importTenant", created, http.StatusCreated)
		expectContract(t, "importTenant", http.MethodPost, pathImport, created)
		var tn struct {
			ID         string `json:"id"`
			Name       string `json:"name"`
			FQDN       string `json:"fqdn"`
			SetupState string `json:"setupState"`
			Quota      int64  `json:"storageQuotaBytes"`
		}
		mustJSON(t, created.body, &tn)
		if tn.SetupState != "setup" || tn.Name != ioNameD || tn.FQDN != ioHostD || tn.Quota != importQuota || tn.ID == tidA {
			t.Errorf("imported tenant = %+v", tn)
		}
		if got := tenantCount(t, sa); got != before+1 {
			t.Errorf("%d tenants after the import, want %d", got, before+1)
		}
		rows := a.expectTenantAudit(t, tn.ID, "tenant.imported")
		for _, r := range rows {
			if r.action == "tenant.imported" {
				for _, want := range []string{"sourceVersion", "exportedAt"} {
					if !strings.Contains(r.details, want) {
						t.Errorf("tenant.imported details %s lack %s", r.details, want)
					}
				}
			}
		}
		a.expectNoSecrets(t, rows)

		// --- The new tenant holds the exported configuration.
		for _, sub := range []string{
			"/network", "/recipient-rules", "/confidentiality-levels", "/abuse-thresholds",
			"/email-templates/transfer-notification/en", "/legal/legal-notice/en",
		} {
			want, got := getJSON(t, sa, tenantPath(tidA, sub)), getJSON(t, sa, tenantPath(tn.ID, sub))
			if sub == "/email-templates/transfer-notification/en" || sub == "/legal/legal-notice/en" {
				// Timestamps, if any, differ: compare the content members only.
				for _, k := range []string{customizedMember, "subject", "bodyHtml", "bodyText", "markdown"} {
					if want.(map[string]any)[k] != got.(map[string]any)[k] {
						t.Errorf("%s member %s: A %v, imported %v", sub, k, want.(map[string]any)[k], got.(map[string]any)[k])
					}
				}
				continue
			}
			if !equalJSON(want, got) {
				t.Errorf("%s differs: A %v, imported %v", sub, want, got)
			}
		}
		if got := getJSON(t, sa, tenantPath(tn.ID, "/email-templates/transfer-notification/en")).(map[string]any); got[customizedMember] != true {
			t.Errorf("imported template customized = %v", got[customizedMember])
		}
		brA := getJSON(t, sa, tenantPath(tidA, "/branding")).(map[string]any)
		brD := getJSON(t, sa, tenantPath(tn.ID, "/branding")).(map[string]any)
		for _, k := range []string{"primaryColor", "accentColor", "hasLogo"} {
			if brA[k] != brD[k] {
				t.Errorf("branding %s: A %v, imported %v", k, brA[k], brD[k])
			}
		}
		if brD["hasLogo"] != true {
			t.Errorf("imported tenant has no logo: %v", brD)
		}
		blk := getJSON(t, sa, tenantPath(tn.ID, "/blocklist")).(map[string]any)
		if !strings.Contains(mustMarshal(blk), ioBlockedDomain) {
			t.Errorf("imported blocklist = %v, want %s", blk, ioBlockedDomain)
		}
		var smtp smtpJSON
		mustJSON(t, mustStatus(t, "imported smtp", sa.call(t, http.MethodGet, tenantPath(tn.ID, "/smtp"), nil), http.StatusOK).body, &smtp)
		if smtp.Host != "mail.example.org" || smtp.PasswordSet || (smtp.Username != nil && *smtp.Username != "") {
			t.Errorf("imported smtp = %+v, want the server without user nor password", smtp)
		}
		type setupJSON struct {
			SetupState        string  `json:"setupState"`
			NetworkReviewedAt *string `json:"networkReviewedAt"`
			Items             []struct {
				Key  string `json:"key"`
				Done bool   `json:"done"`
			} `json:"items"`
		}
		readSetup := func() setupJSON {
			t.Helper()
			res := mustStatus(t, "setup", sa.call(t, http.MethodGet, tenantPath(tn.ID, "/setup"), nil), http.StatusOK)
			expectContract(t, "getTenantSetup", http.MethodGet, tenantPath(tn.ID, "/setup"), res)
			var out setupJSON
			mustJSON(t, res.body, &out)
			return out
		}
		itemDone := func(st setupJSON) map[string]bool {
			out := map[string]bool{}
			for _, it := range st.Items {
				out[it.Key] = it.Done
			}
			return out
		}
		setup := readSetup()
		if setup.SetupState != "setup" {
			t.Errorf("setupState = %q", setup.SetupState)
		}
		// The SMTP item is to do again, and the imported network rules must
		// be confirmed (T-307).
		if d := itemDone(setup); d["smtp"] || d["internal_networks"] || d["internal_domains"] || setup.NetworkReviewedAt != nil {
			t.Errorf("imported tenant setup = %+v, want smtp and network items to do, no review", setup)
		}
		// The completion is refused for the network items too.
		incomplete := sa.call(t, http.MethodPost, tenantPath(tn.ID, "/setup/complete"), map[string]any{})
		expectProblem(t, incomplete, http.StatusConflict, "setup-incomplete")
		for _, key := range []string{"internal_networks", "internal_domains"} {
			if !strings.Contains(string(incomplete.body), `"`+key+`"`) {
				t.Errorf("setup-incomplete does not list %s: %s", key, incomplete.body)
			}
		}
		// Saving the imported rules unchanged confirms them.
		rulesD := getJSON(t, sa, tenantPath(tn.ID, "/network"))
		mustStatus(t, "confirm network", sa.call(t, http.MethodPut, tenantPath(tn.ID, "/network"), rulesD), http.StatusOK)
		setup = readSetup()
		if d := itemDone(setup); !d["internal_networks"] || !d["internal_domains"] || setup.NetworkReviewedAt == nil {
			t.Errorf("after the confirmation, setup = %+v", setup)
		}
		if got := getJSON(t, sa, tenantPath(tn.ID, "/network")); !equalJSON(rulesD, got) {
			t.Errorf("the confirmation changed the rules: %v, want %v", got, rulesD)
		}
		if hooksD := sa.listWebhooks(t, tn.ID); len(hooksD) != 0 {
			t.Errorf("imported tenant has webhooks %+v", hooksD)
		}
		ssoD := sa.call(t, http.MethodGet, tenantPath(tn.ID, "/sso"), nil)
		if ssoD.status == http.StatusOK && strings.Contains(string(ssoD.body), `"enabled":true`) {
			t.Errorf("imported tenant has SSO: %s", ssoD.body)
		}
		if strings.Contains(string(ssoD.body), s.idp.Issuer()) {
			t.Errorf("imported tenant sso leaks the issuer: %s", ssoD.body)
		}

		// --- Refusals of the same body.
		dup := sa.call(t, http.MethodPost, pathImport, okBody)
		expectProblem(t, dup, http.StatusConflict, "already-exists")
		expectContract(t, "importTenant", http.MethodPost, pathImport, dup)
		reserved := sa.call(t, http.MethodPost, pathImport, importBody(ioNameD, adminHost, string(exp.body)))
		expectProblem(t, reserved, http.StatusBadRequest, "validation-failed")
		expectContract(t, "importTenant", http.MethodPost, pathImport, reserved)
		var rp fieldProblem
		mustJSON(t, reserved.body, &rp)
		if len(rp.Errors) == 0 || rp.Errors[0].Field != "/fqdn" || rp.Errors[0].Code != "reserved-host" {
			t.Errorf("reserved host errors = %+v, want /fqdn reserved-host", rp.Errors)
		}
		forbidden := deleg.call(t, http.MethodPost, pathImport, importBody("Entity E", "transfer.entity-e.localhost", string(exp.body)))
		expectProblem(t, forbidden, http.StatusForbidden, "forbidden")
		expectContract(t, "importTenant", http.MethodPost, pathImport, forbidden)
		audImport := auditor.call(t, http.MethodPost, pathImport, importBody("Entity E", "transfer.entity-e.localhost", string(exp.body)))
		expectProblem(t, audImport, http.StatusForbidden, "read-only-role")
		expectContract(t, "importTenant", http.MethodPost, pathImport, audImport)
		if got := tenantCount(t, sa); got != before+1 {
			t.Errorf("%d tenants after the refusals, want %d", got, before+1)
		}

		// --- Hostile documents: each refused, none creates a tenant.
		const fqdnE = "transfer.entity-e.localhost"
		hostile := []struct {
			name   string
			body   string
			status int
			code   string
			field  string
			reason string
		}{
			{
				"duplicate key", importBody("Entity E", fqdnE, strings.Replace(raw, `"schemaVersion":1`, `"schemaVersion":1,"schemaVersion":1`, 1)),
				http.StatusUnprocessableEntity, "import-invalid", "/config/schemaVersion", "duplicate",
			},
			{
				"unknown member", importBody("Entity E", fqdnE, strings.Replace(raw, `{"schemaVersion":1`, `{"bogus":true,"schemaVersion":1`, 1)),
				http.StatusUnprocessableEntity, "import-invalid", "/config/bogus", "unknown-member",
			},
			{
				"schema version 2", importBody("Entity E", fqdnE, strings.Replace(raw, `"schemaVersion":1`, `"schemaVersion":2`, 1)),
				http.StatusUnprocessableEntity, "import-schema-unsupported", "", "",
			},
			{
				"bad CIDR", importBody("Entity E", fqdnE, withCIDRs(t, doc, "100.64.20.0/24", "not-a-cidr")),
				http.StatusUnprocessableEntity, "import-invalid", "/config/network/internalCidrs/1", "invalid-value",
			},
		}
		for _, tc := range hostile {
			resp := sa.call(t, http.MethodPost, pathImport, tc.body)
			expectProblem(t, resp, tc.status, tc.code)
			expectContract(t, "importTenant", http.MethodPost, pathImport, resp)
			if tc.field != "" {
				var fp fieldProblem
				mustJSON(t, resp.body, &fp)
				if len(fp.Errors) == 0 || fp.Errors[0].Field != tc.field || fp.Errors[0].Code != tc.reason {
					t.Errorf("%s: errors = %+v, want %s %s", tc.name, fp.Errors, tc.field, tc.reason)
				}
			}
			if got := tenantCount(t, sa); got != before+1 {
				t.Errorf("%s: %d tenants, want %d", tc.name, got, before+1)
			}
		}
		// Missing CSRF token.
		noCSRF := sa.send(t, http.MethodPost, pathImport, importBody("Entity E", fqdnE, string(exp.body)), nil)
		if noCSRF.status != http.StatusForbidden {
			t.Errorf("import without CSRF token: %d %s, want 403", noCSRF.status, noCSRF.body)
		}
		expectContract(t, "importTenant", http.MethodPost, pathImport, noCSRF)
		// 32 MiB + 1: refused upfront on Content-Length, and when a chunked
		// body crosses the limit.
		common := "POST " + pathImport + " HTTP/1.1\r\nHost: " + adminHost + "\r\nContent-Type: application/json\r\n" +
			hdrXFF + ": " + sa.ip + "\r\nCookie: " + adminCookieName + "=" + sa.cookie + "\r\n" + hdrCSRF + ": " + sa.csrf + "\r\n"
		big := a.raw(t, common+"Content-Length: "+strconv.Itoa(importLimit+1)+"\r\n", nil)
		expectProblem(t, big, http.StatusRequestEntityTooLarge, "payload-too-large")
		expectContract(t, "importTenant", http.MethodPost, pathImport, big)
		chunked := a.raw(t, common+"Transfer-Encoding: chunked\r\n", func(w io.Writer) {
			writeChunk(w, []byte(`{"name":"`))
			for range importLimit / oneMiB {
				if !writeChunk(w, bytes.Repeat([]byte("a"), oneMiB)) {
					return
				}
			}
			writeChunk(w, []byte(`a"}`))
			_, _ = io.WriteString(w, "0\r\n\r\n")
		})
		expectProblem(t, chunked, http.StatusRequestEntityTooLarge, "payload-too-large")
		if got := tenantCount(t, sa); got != before+1 {
			t.Errorf("%d tenants after the hostile documents, want %d", got, before+1)
		}
		if a.countTenantsByFQDN(t, fqdnE) != 0 {
			t.Errorf("a tenant %s exists after refused imports", fqdnE)
		}
	})
}

// countTenantsByFQDN counts the tenants of the database with fqdn.
func (a *adminEnv) countTenantsByFQDN(t *testing.T, fqdn string) int {
	t.Helper()
	return countSystem(t, a.e, `SELECT COUNT(*) FROM tenants WHERE fqdn = '`+fqdn+`'`)
}

// withCIDRs returns the exported document doc with its internal ranges
// replaced by cidrs.
func withCIDRs(t *testing.T, doc map[string]any, cidrs ...string) string {
	t.Helper()
	var clone map[string]any
	b, _ := json.Marshal(doc)
	mustJSON(t, b, &clone)
	clone["network"].(map[string]any)["internalCidrs"] = cidrs
	out, err := json.Marshal(clone)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func mustMarshal(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// equalJSON compares two decoded JSON values.
func equalJSON(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}
