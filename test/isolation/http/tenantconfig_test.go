package httpisolation_test

import (
	"bytes"
	"context"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/storage"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Markers of the legal documents seeded for each tenant: each appears in
// the documents of its tenant only.
const (
	legalMarkerA = "Legal notice of Entity A Isolation, marker LGA-7c41"
	legalMarkerB = "Privacy policy of Entity B Isolation, marker LGB-93d2"
	// colorB is the primary color of tenant B (A keeps the default one).
	colorB = "#5A189A"
)

// configFixtures is the tenant configuration seeded for the tenant cases.
type configFixtures struct {
	// logoB is the logo stored for tenant B (tenant A has none).
	logoB []byte
}

// seedTenantConfig gives the two tenants a different configuration, as an
// administrator would through the API: tenant A has a legal notice;
// tenant B has a privacy policy, a logo stored in dataDir and its own
// primary color.
func seedTenantConfig(t *testing.T, db *store.DB, h *harness, dataDir string) configFixtures {
	t.Helper()
	ctx := context.Background()
	put := func(tid tenant.ID, doc, content string) {
		if _, err := db.TenantLegalDocuments().Put(ctx, tid, store.LegalDocument{
			Document: doc, Language: "fr", Content: "# " + content + "\n\n" + content,
		}); err != nil {
			t.Fatalf("seed legal document: %v", err)
		}
	}
	put(h.tenantA.ID, store.LegalNotice, legalMarkerA)
	put(h.tenantB.ID, store.PrivacyPolicy, legalMarkerB)

	img := image.NewNRGBA(image.Rect(0, 0, 2, 2))
	img.Set(0, 0, color.NRGBA{R: 0x5A, G: 0x18, B: 0x9A, A: 0xFF})
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	files, err := storage.New(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = files.Close() }()
	if err := files.WriteAsset(h.tenantB.ID, storage.AssetLogo, buf.Bytes()); err != nil {
		t.Fatalf("seed logo: %v", err)
	}
	b := h.tenantB.Clone()
	b.HasLogo, b.PrimaryColor = true, colorB
	updated, err := db.Tenants().Update(ctx, b)
	if err != nil {
		t.Fatalf("seed branding: %v", err)
	}
	h.tenantB = updated
	return configFixtures{logoB: buf.Bytes()}
}

// session returns the session of the delegated admin of tenant A, opened
// on first use and shared by the tenant configuration cases.
func (h *harness) session(t *testing.T) adminSession {
	t.Helper()
	h.sessMu.Lock()
	defer h.sessMu.Unlock()
	if h.sess == nil {
		s := h.adminLogin(t)
		h.sess = &s
	}
	return *h.sess
}

// adminTenantOp is the isolation case of a tenant configuration
// operation: served on the admin host only (adminHostOnly), and a
// delegated admin of tenant A never reaches tenant B (tenantScoped).
func adminTenantOp(t *testing.T, h *harness, op operation) {
	t.Helper()
	adminHostOnly(t, h, op)
	tenantScoped(t, h, op)
}

// superAdminOnly lists the tenant operations reserved to the super admin
// whatever the tenant: a delegated admin gets 403 forbidden there, for
// tenant B exactly as for an unknown tenant.
var superAdminOnly = map[string]bool{"deleteTenant": true}

// tenantScoped asserts that the delegated admin of tenant A, sending op
// for tenant B's ID, gets exactly the answer of an unknown tenant ID (404
// not-found, or 403 forbidden for a super admin operation), never data of
// B. The operations without tenant ID show only A (listTenants) or are
// refused (createTenant).
func tenantScoped(t *testing.T, h *harness, op operation) {
	t.Helper()
	sess := h.session(t)
	switch op.id {
	case "listTenants":
		resp := h.sendAs(t, sess, op, "")
		if resp.status != http.StatusOK || !strings.Contains(string(resp.body), string(h.tenantA.ID)) {
			t.Fatalf("%s: %d %s, want tenant A listed", op, resp.status, resp.body)
		}
		h.noTenantB(t, op, resp)
		return
	case "createTenant":
		resp := h.sendAs(t, sess, op, "")
		if resp.status != http.StatusForbidden || problemCode(resp) != "forbidden" {
			t.Fatalf("%s: %d %s, want 403 forbidden", op, resp.status, resp.body)
		}
		return
	}
	unknown := id.New(id.Tenant) // well-formed, never created
	foreign := h.sendAs(t, sess, op, string(h.tenantB.ID))
	missing := h.sendAs(t, sess, op, unknown)
	wantStatus, wantCode := http.StatusNotFound, "not-found"
	if superAdminOnly[op.id] {
		wantStatus, wantCode = http.StatusForbidden, "forbidden"
	}
	if foreign.status != wantStatus || problemCode(foreign) != wantCode {
		t.Fatalf("%s for tenant B: %d %s, want %d %s", op, foreign.status, foreign.body, wantStatus, wantCode)
	}
	if missing.status != foreign.status || !bytes.Equal(withoutInstance(t, missing), withoutInstance(t, foreign)) {
		t.Errorf("%s: tenant B answers %d %s, an unknown tenant %d %s: they must be identical",
			op, foreign.status, foreign.body, missing.status, missing.body)
	}
	h.noTenantB(t, op, foreign)
	if op.id == "getTenant" {
		// Control: the same session reaches its own tenant.
		if own := h.sendAs(t, sess, op, string(h.tenantA.ID)); own.status != http.StatusOK ||
			!strings.Contains(string(own.body), nameA) {
			t.Errorf("%s for tenant A: %d %s, want 200", op, own.status, own.body)
		}
	}
}

// validBodies are request bodies that pass the input validation, which
// some operations run before the authorization (an invalid body is
// refused the same way whatever the tenant): with them, the request
// reaches the tenant check. The other operations accept the sample body.
var validBodies = map[string]string{
	"updateBranding":      `{"primaryColor":"#112233","accentColor":"#445566"}`,
	"updateSmtpSettings":  `{"host":"smtp-relay","port":25,"security":"none","fromAddress":"no-reply@entity-b.example.com"}`,
	"testSmtp":            `{"to":"admin@entity-b.example.com"}`,
	"updateLegalDocument": `{"markdown":"# Notice"}`,
	"updateNetworkRules":  `{"internalCidrs":["10.0.0.0/8"],"internalDomains":["entity-b.example.com"]}`,
	// The tenant operations check the rights first; with valid bodies, a
	// broken check would show (409 for B's existing entry, B's sender
	// counted or erased).
	"createBlocklistEntry": `{"kind":"domain","value":"` + blockedB + `"}`,
	"deleteTenantTransfer": `{"reason":"isolation check"}`,
	"searchDataSubject":    `{"email":"` + insiderB + `"}`,
	"eraseDataSubject":     `{"email":"` + insiderB + `"}`,
}

// sendAs performs op on the admin host with the session sess, tenantID in
// the {tenantId} path parameter, and sample values for the others.
func (h *harness) sendAs(t *testing.T, sess adminSession, op operation, tenantID string) response {
	t.Helper()
	path := op.template
	query := url.Values{}
	for _, p := range op.params {
		v := p.sample()
		if p.Name == "tenantId" {
			v = tenantID
		}
		switch p.In {
		case "path":
			path = strings.ReplaceAll(path, "{"+p.Name+"}", v)
		case "query":
			if p.Required {
				query.Set(p.Name, v)
			}
		}
	}
	header := sess.header(false)
	var body io.Reader
	if op.body != nil {
		ct, payload := sampleBody(op.body)
		if v, ok := validBodies[op.id]; ok {
			payload = []byte(v)
		}
		header.Set("Content-Type", ct)
		body = bytes.NewReader(payload)
	}
	target := "http://" + h.addr + op.base + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	return h.do(t, op.verb, target, hostAdmin, body, header)
}

// withoutInstance returns the Problem body of resp without its instance
// (the request identifier, different for each request).
func withoutInstance(t *testing.T, resp response) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(resp.body, &m); err != nil {
		t.Fatalf("not a JSON body: %s", resp.body)
	}
	delete(m, "instance")
	out, _ := json.Marshal(m)
	return out
}

// noTenantB asserts that resp holds no data of tenant B.
func (h *harness) noTenantB(t *testing.T, op operation, resp response) {
	t.Helper()
	for _, s := range []string{nameB, hostB, string(h.tenantB.ID), legalMarkerB, colorB} {
		if strings.Contains(string(resp.body), s) {
			t.Errorf("%s leaks %q of tenant B: %s", op, s, resp.body)
		}
	}
}

// publicTenantConfig is the isolation case of getPublicTenant: under each
// tenant host, the configuration of that tenant only.
func publicTenantConfig(t *testing.T, h *harness, op operation) {
	t.Helper()
	type config struct {
		Name     string `json:"name"`
		Branding struct {
			PrimaryColor string `json:"primaryColor"`
			HasLogo      bool   `json:"hasLogo"`
		} `json:"branding"`
		LegalDocuments []string `json:"legalDocuments"`
	}
	for _, c := range []struct {
		host, name, other, otherHost string
		other2                       []string
		hasLogo                      bool
		legal                        string
	}{
		{hostA, nameA, nameB, hostB, []string{string(h.tenantB.ID), colorB}, false, "legal-notice"},
		{hostB, nameB, nameA, hostA, []string{string(h.tenantA.ID)}, true, "privacy-policy"},
	} {
		resp := h.send(t, op, c.host)
		var got config
		if resp.status != http.StatusOK || json.Unmarshal(resp.body, &got) != nil {
			t.Fatalf("%s under %s: %d %s", op, c.host, resp.status, resp.body)
		}
		if got.Name != c.name || got.Branding.HasLogo != c.hasLogo || !slices.Equal(got.LegalDocuments, []string{c.legal}) {
			t.Errorf("%s under %s: %+v", op, c.host, got)
		}
		for _, leak := range append([]string{c.other, c.otherHost}, c.other2...) {
			if strings.Contains(string(resp.body), leak) {
				t.Errorf("%s under %s leaks %q", op, c.host, leak)
			}
		}
	}
}

// tenantAssets is the isolation case of getTenantAsset: tenant B's logo is
// served under B's host only; tenant A, without logo, answers 404 rather
// than B's; the default background is the same under both.
func tenantAssets(t *testing.T, h *harness, op operation) {
	t.Helper()
	get := func(host, asset string) response {
		return h.do(t, http.MethodGet, "http://"+h.addr+"/api/v1/tenant/assets/"+asset, host, nil, http.Header{})
	}
	b := get(hostB, "logo")
	if b.status != http.StatusOK || !bytes.Equal(b.body, h.config.logoB) || b.header.Get("Content-Type") != "image/png" ||
		b.header.Get("X-Content-Type-Options") != "nosniff" || b.header.Get("ETag") == "" {
		t.Fatalf("%s: logo under %s: %d %v", op, hostB, b.status, b.header)
	}
	a := get(hostA, "logo")
	if a.status != http.StatusNotFound || problemCode(a) != "not-found" || bytes.Contains(a.body, h.config.logoB) {
		t.Errorf("%s: logo under %s: %d %s, want 404", op, hostA, a.status, a.body)
	}
	// A's host with B's entity tag gets no 304 for B's logo.
	hdr := http.Header{"If-None-Match": {b.header.Get("ETag")}}
	if r := h.do(t, http.MethodGet, "http://"+h.addr+"/api/v1/tenant/assets/logo", hostA, nil, hdr); r.status != http.StatusNotFound {
		t.Errorf("%s: logo under %s with B's ETag: %d", op, hostA, r.status)
	}
	bgA, bgB := get(hostA, "background"), get(hostB, "background")
	if bgA.status != http.StatusOK || bgB.status != http.StatusOK || !bytes.Equal(bgA.body, bgB.body) {
		t.Errorf("%s: default background %d/%d, want the same image under both", op, bgA.status, bgB.status)
	}
	noLeak(t, h, op, hostA, a)
	noLeak(t, h, op, hostA, bgA)
}

// tenantLegal is the isolation case of getTenantLegalDocument: each tenant
// serves its own documents only, and 404 for a document only the other
// tenant has written.
func tenantLegal(t *testing.T, h *harness, op operation) {
	t.Helper()
	get := func(host, doc string) response {
		return h.do(t, http.MethodGet, "http://"+h.addr+"/api/v1/tenant/legal/"+doc, host, nil, http.Header{})
	}
	for _, c := range []struct {
		host, doc, marker, foreign string
	}{
		{hostA, "legal-notice", legalMarkerA, legalMarkerB},
		{hostB, "privacy-policy", legalMarkerB, legalMarkerA},
	} {
		resp := get(c.host, c.doc)
		if resp.status != http.StatusOK || !strings.Contains(string(resp.body), c.marker) || strings.Contains(string(resp.body), c.foreign) {
			t.Errorf("%s: %s under %s: %d %s", op, c.doc, c.host, resp.status, resp.body)
		}
	}
	for _, c := range []struct{ host, doc string }{{hostA, "privacy-policy"}, {hostB, "legal-notice"}} {
		resp := get(c.host, c.doc)
		if resp.status != http.StatusNotFound || problemCode(resp) != "not-found" {
			t.Errorf("%s: %s under %s: %d %s, want 404", op, c.doc, c.host, resp.status, resp.body)
		}
		noLeak(t, h, op, c.host, resp)
	}
}

// adminBrandingAsset is the isolation case of getBrandingAsset: served on
// the admin host only, and on tenant B's ID with the operation's sample
// asset the delegated admin of tenant A gets the answer of an unknown
// tenant (adminTenantOp). With the logo, which only tenant B has, A's
// admin still gets exactly that answer and never B's image, while the
// super admin is served B's logo (no-store, nosniff).
func adminBrandingAsset(t *testing.T, h *harness, op operation) {
	t.Helper()
	adminTenantOp(t, h, op)
	sess := h.session(t)
	logo := func(s adminSession, tid string) response {
		return h.adminCall(t, s, http.MethodGet, "/admin/tenants/"+tid+"/branding/logo", "")
	}
	foreign, missing := logo(sess, string(h.tenantB.ID)), logo(sess, id.New(id.Tenant))
	if foreign.status != http.StatusNotFound || problemCode(foreign) != "not-found" || bytes.Contains(foreign.body, h.config.logoB) {
		t.Fatalf("%s: B's logo for A's admin: %d %s, want 404 not-found", op, foreign.status, foreign.body)
	}
	if missing.status != foreign.status || !bytes.Equal(withoutInstance(t, missing), withoutInstance(t, foreign)) {
		t.Errorf("%s: B's logo answers %d %s, an unknown tenant %d %s: they must be identical",
			op, foreign.status, foreign.body, missing.status, missing.body)
	}
	h.noTenantB(t, op, foreign)
	// Tenant A has no logo: 404, never B's.
	if own := logo(sess, string(h.tenantA.ID)); own.status != http.StatusNotFound || bytes.Contains(own.body, h.config.logoB) {
		t.Errorf("%s: A's logo for A's admin: %d %s, want 404", op, own.status, own.body)
	}
	// Control: the super admin reaches B's logo.
	b := logo(h.superSession(t), string(h.tenantB.ID))
	if b.status != http.StatusOK || !bytes.Equal(b.body, h.config.logoB) || b.header.Get("Content-Type") != "image/png" ||
		b.header.Get("Cache-Control") != "no-store" || b.header.Get("X-Content-Type-Options") != "nosniff" || b.header.Get("ETag") == "" {
		t.Errorf("%s: B's logo for the super admin: %d %v", op, b.status, b.header)
	}
}
