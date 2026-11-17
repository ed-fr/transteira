package httpisolation_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// The express secrets (since 2.3, threat model T-390): an API token of A
// never creates under B (nor the reverse), an express secret of A is
// unknown under B (status, report), the anonymous mode and the limits of a
// tenant never apply to another, a lookup under A's path never finds B's
// secret, and a purge of A never touches B's.

// opCreateExpress and opSecretLink are the creation and the status of an
// express secret.
var (
	opCreateExpress = operation{id: "createExpressSecret", verb: http.MethodPost, template: "/express-secrets", base: "/api/v1"}
	opSecretLink    = operation{id: "getSecretLink", verb: http.MethodGet, template: "/secret-links/{secretToken}", base: "/api/v1"}
)

// expressBody is the creation body of an express secret of s.
func (s sealedSecret) expressBody() string {
	return `{"encryptedText":"` + s.text + `","verifier":"` + s.verifier + `","keyVerifier":"` + s.keyVerifier + `","expiresIn":"1h"}`
}

// setExpress turns the anonymous express mode of tenant tid on or off, as
// the super admin, keeping the other settings.
func (h *harness) setExpress(t *testing.T, tid tenant.ID, enabled bool) {
	t.Helper()
	settings := h.secretSettingsOf(t, operation{id: "setExpress"}, h.superSession(t), tid)
	settings["expressEnabled"] = enabled
	body, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	if resp := h.adminCall(t, h.superSession(t), http.MethodPut, tenantPath(tid, "/secret-settings"), string(body)); resp.status != http.StatusOK {
		t.Fatalf("express mode of %s: %d %s", tid, resp.status, resp.body)
	}
}

// expressTokenOf creates, as the super admin, an API token of tenant tid
// allowed for the express secrets, from any address, and returns its
// secret.
func (h *harness) expressTokenOf(t *testing.T, tid tenant.ID) string {
	t.Helper()
	resp := h.adminCall(t, h.superSession(t), http.MethodPost, tenantPath(tid, "/api-tokens"),
		`{"name":"Express token","allowedCidrs":["0.0.0.0/0","::/0"],"expressAllowed":true}`)
	var tok apiTokenView
	if resp.status != http.StatusCreated || json.Unmarshal(resp.body, &tok) != nil || tok.Token == "" {
		t.Fatalf("create an express API token of %s: %d %s", tid, resp.status, resp.body)
	}
	return tok.Token
}

// createExpress creates an express secret under host, anonymous when
// bearer is "" (the anonymous mode of the tenant must be on), and returns
// it.
func (h *harness) createExpress(t *testing.T, host, bearer string) createdSecretA {
	t.Helper()
	s := createdSecretA{sealedSecret: sealSecret(t, "isolation express secret under "+host)}
	var hdr []string
	if bearer != "" {
		hdr = []string{"Authorization", "Bearer " + bearer}
	}
	resp := h.call(t, opCreateExpress, host, nil, s.expressBody(), hdr...)
	if resp.status != http.StatusCreated || json.Unmarshal(resp.body, &s) != nil || s.ID == "" || s.Token == "" {
		t.Fatalf("create express secret under %s: %d %s", host, resp.status, resp.body)
	}
	return s
}

// expressStatus returns the status code of the link of s under host.
func (h *harness) expressStatus(t *testing.T, host string, s createdSecretA) response {
	t.Helper()
	return h.call(t, opSecretLink, host, map[string]string{"secretToken": s.Token}, "")
}

// createForeignExpress: each tenant's API token creates under its own
// host only; an anonymous secret of A is unknown under B; the anonymous
// mode of A does not open nor close B's.
func createForeignExpress(t *testing.T, h *harness, op operation) {
	t.Helper()
	h.setExpress(t, h.tenantA.ID, true)
	h.setExpress(t, h.tenantB.ID, true)
	defer func() {
		h.setExpress(t, h.tenantA.ID, false)
		h.setExpress(t, h.tenantB.ID, false)
	}()
	a := h.createExpress(t, hostA, "")
	if resp := h.expressStatus(t, hostA, a); resp.status != http.StatusOK || !strings.Contains(string(resp.body), `"anonymous":true`) {
		t.Fatalf("%s: status of A's express secret under %s: %d %s", op, hostA, resp.status, resp.body)
	}
	resp := h.expressStatus(t, hostB, a)
	wantCode(t, op, hostB, resp, http.StatusNotFound, "not-found")
	noSealed(t, h, op, hostB, resp, a)

	tokA, tokB := h.expressTokenOf(t, h.tenantA.ID), h.expressTokenOf(t, h.tenantB.ID)
	body := sealSecret(t, "express by token").expressBody()
	for _, c := range []struct {
		host, token string
		ok          bool
	}{
		{hostA, tokA, true}, {hostB, tokB, true}, {hostB, tokA, false}, {hostA, tokB, false},
	} {
		resp := h.call(t, op, c.host, nil, body, "Authorization", "Bearer "+c.token)
		if c.ok {
			if resp.status != http.StatusCreated {
				t.Errorf("%s under %s with its own token: %d %s, want 201", op, c.host, resp.status, resp.body)
			}
			continue
		}
		wantCode(t, op, c.host, resp, http.StatusUnauthorized, "invalid-credentials")
		noLeak(t, h, op, c.host, resp)
	}

	// Closing A's anonymous mode leaves B's open, and closes the reading
	// of A's anonymous secret only.
	h.setExpress(t, h.tenantA.ID, false)
	wantCode(t, op, hostA, h.call(t, op, hostA, nil, body), http.StatusForbidden, "express-secrets-disabled")
	wantCode(t, op, hostA, h.expressStatus(t, hostA, a), http.StatusForbidden, "express-secrets-disabled")
	b := h.createExpress(t, hostB, "")
	if resp := h.expressStatus(t, hostB, b); resp.status != http.StatusOK {
		t.Errorf("%s: B's anonymous secret while A is closed: %d %s", op, resp.status, resp.body)
	}
	// A closed tenant's anonymous secret stays unknown under B, never
	// "closed" there (no oracle).
	wantCode(t, op, hostB, h.expressStatus(t, hostB, a), http.StatusNotFound, "not-found")
}

// reportForeignSecretAbuse: A's express secret is unknown under B (404,
// nothing recorded); a report under A is accepted and kept for A only.
func reportForeignSecretAbuse(t *testing.T, h *harness, op operation) {
	t.Helper()
	tokA := h.expressTokenOf(t, h.tenantA.ID)
	a := h.createExpress(t, hostA, tokA)
	params := map[string]string{"secretToken": a.Token}
	body := `{"category":"phishing","message":"isolation check"}`
	for range 4 {
		refusedUnderB(t, h, op, h.call(t, op, hostB, params, body), http.StatusNotFound, "not-found")
	}
	if resp := h.call(t, op, hostA, params, body); resp.status != http.StatusAccepted || len(resp.body) != 0 {
		t.Fatalf("%s under %s: %d %s, want 202", op, hostA, resp.status, resp.body)
	}
	ctx := context.Background()
	db, err := store.Open(ctx, h.engine.Config())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	for tid, want := range map[tenant.ID]bool{h.tenantA.ID: true, h.tenantB.ID: false} {
		page, err := db.AbuseReports().List(ctx, tid, "", 200, "")
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, r := range page.Items {
			found = found || r.SecretID == a.ID
		}
		if found != want {
			t.Errorf("%s: report of %s listed for tenant %s: %v, want %v", op, a.ID, tid, found, want)
		}
	}
}

// lookupBody is the body of a lookup of the link of token, pasted with a
// host and a key.
func lookupBody(host, token string) string {
	return `{"link":"https://` + host + `/s/` + token + `#k=ew7WSQ3aQqhKCGs_K2QR3lal5iX7Jr66egxAI_Wmhuk"}`
}

// checkLookupForeignSecret: under A's path, B's secret answers like an
// unknown token, whatever the host of the link; A's is found, without
// its token.
func checkLookupForeignSecret(t *testing.T, h *harness, op operation, sess adminSession) {
	t.Helper()
	b := h.createSecretOfB(t)
	path := tenantPath(h.tenantA.ID, "/secrets/lookup")
	unknown := "tts_" + strings.Repeat("Z", 43)
	for _, host := range []string{hostA, hostB} {
		foreign := h.adminCall(t, sess, http.MethodPost, path, lookupBody(host, b.Token))
		missing := h.adminCall(t, sess, http.MethodPost, path, lookupBody(host, unknown))
		h.sameAsMissing(t, op, foreign, missing, b.ID, b.Token)
	}
	a := h.createSecretA(t)
	own := h.adminCall(t, sess, http.MethodPost, path, lookupBody(hostA, a.Token))
	if body := wantOK(t, op, "the lookup of A's secret", own); !strings.Contains(string(body), a.ID) ||
		strings.Contains(string(body), a.Token) || strings.Contains(string(body), a.verifier) {
		t.Errorf("%s: A's secret: %s", op, body)
	}
	// B's secret is found under B's path, by the super admin.
	other := h.adminCall(t, h.superSession(t), http.MethodPost, tenantPath(h.tenantB.ID, "/secrets/lookup"), lookupBody(hostB, b.Token))
	if body := wantOK(t, op, "the lookup of B's secret", other); !strings.Contains(string(body), b.ID) {
		t.Errorf("%s: B's secret: %s", op, body)
	}
}

// checkPurgeForeignExpress: A's purge ends A's live anonymous express
// secrets and none of B's.
func checkPurgeForeignExpress(t *testing.T, h *harness, op operation, sess adminSession) {
	t.Helper()
	h.setExpress(t, h.tenantA.ID, true)
	h.setExpress(t, h.tenantB.ID, true)
	defer func() {
		h.setExpress(t, h.tenantA.ID, false)
		h.setExpress(t, h.tenantB.ID, false)
	}()
	a, b := h.createExpress(t, hostA, ""), h.createExpress(t, hostB, "")
	resp := h.adminCall(t, sess, http.MethodPost, tenantPath(h.tenantA.ID, "/express-secrets/purge"), "")
	var out struct {
		Deleted int `json:"deleted"`
	}
	if json.Unmarshal(wantOK(t, op, "A's purge", resp), &out) != nil || out.Deleted < 1 {
		t.Fatalf("%s: A's purge: %s", op, resp.body)
	}
	h.noDataOfB(t, op, "A's purge", resp, b.ID, b.Token)
	wantCode(t, opSecretLink, hostA, h.expressStatus(t, hostA, a), http.StatusGone, "secret-gone")
	if resp := h.expressStatus(t, hostB, b); resp.status != http.StatusOK {
		t.Errorf("%s: B's anonymous secret after A's purge: %d %s, want active", op, resp.status, resp.body)
	}
	// The purge of an unknown tenant is the 404 of B's (adminTenantOp).
	missing := h.adminCall(t, sess, http.MethodPost, tenantPath(tenant.ID(id.New(id.Tenant)), "/express-secrets/purge"), "")
	foreign := h.adminCall(t, sess, http.MethodPost, tenantPath(h.tenantB.ID, "/express-secrets/purge"), "")
	h.sameAsMissing(t, op, foreign, missing, b.ID)
	if resp := h.expressStatus(t, hostB, b); resp.status != http.StatusOK {
		t.Errorf("%s: B's anonymous secret after the attempt on B: %d %s, want active", op, resp.status, resp.body)
	}
}
