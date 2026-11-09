package httpisolation_test

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/tenant"
)

// The administration of the one-time secrets (since 2.1): the listing, the
// deletion and the settings of a tenant. Served on the admin host only; the
// delegated admin of tenant A gets for tenant B exactly the answer of an
// unknown tenant, and under its own path, for a secret of B, exactly the
// answer of an unknown secret. B's secret is never listed, deleted nor
// changed, and a change of A's settings never reaches B.

// createSecretOfB creates, through the API under B's host, a secret of the
// other tenant's depositor and returns it.
func (h *harness) createSecretOfB(t *testing.T) createdSecretA {
	t.Helper()
	s := createdSecretA{sealedSecret: sealSecret(t, "isolation secret of tenant B")}
	resp := h.call(t, opCreateSecret, hostB, nil, s.createBody(), h.other(t).headers()...)
	if resp.status != http.StatusCreated || json.Unmarshal(resp.body, &s) != nil || s.ID == "" || s.Token == "" {
		t.Fatalf("create secret under %s: %d %s", hostB, resp.status, resp.body)
	}
	return s
}

// adminSecret is the isolation case of an administration operation of the
// secrets: admin host only, tenant B's ID answered like an unknown tenant
// (adminTenantOp), then the checks of the operation (adminSecretChecks).
func adminSecret(t *testing.T, h *harness, op operation) {
	t.Helper()
	adminTenantOp(t, h, op)
	check, ok := adminSecretChecks[op.id]
	if !ok {
		t.Fatalf("%s has no entry in adminSecretChecks", op)
	}
	check(t, h, op, h.session(t))
}

// adminSecretChecks are the per-operation checks of adminSecret, run with
// the session of tenant A's delegated admin.
var adminSecretChecks = map[string]func(t *testing.T, h *harness, op operation, sess adminSession){
	"listTenantSecrets":    checkListSecrets,
	"deleteTenantSecret":   checkDeleteForeignSecret,
	"getSecretSettings":    checkGetSecretSettings,
	"updateSecretSettings": checkUpdateSecretSettings,
}

// secretListOf lists the secrets of tenant tid with sess and returns the
// raw answer and the identifiers.
func (h *harness) secretListOf(t *testing.T, op operation, sess adminSession, tid tenant.ID) (response, []string) {
	t.Helper()
	resp := h.adminCall(t, sess, http.MethodGet, tenantPath(tid, "/secrets"), "")
	var list struct {
		Items []struct {
			ID    string `json:"id"`
			State string `json:"state"`
		} `json:"items"`
	}
	if json.Unmarshal(wantOK(t, op, "the secret list of "+string(tid), resp), &list) != nil {
		t.Fatalf("%s: secret list of %s: %s", op, tid, resp.body)
	}
	ids := make([]string, len(list.Items))
	for i, it := range list.Items {
		ids[i] = it.ID
	}
	return resp, ids
}

// checkListSecrets: A's list holds A's secret, never B's, and B's list (by
// the super admin) holds B's.
func checkListSecrets(t *testing.T, h *harness, op operation, sess adminSession) {
	t.Helper()
	a, b := h.createSecretA(t), h.createSecretOfB(t)
	resp, ids := h.secretListOf(t, op, sess, h.tenantA.ID)
	if !slices.Contains(ids, a.ID) || slices.Contains(ids, b.ID) {
		t.Errorf("%s: A's list = %v, want %s and not %s", op, ids, a.ID, b.ID)
	}
	h.noDataOfB(t, op, "the list of A", resp, b.ID, b.Token, b.text, b.verifier)
	for _, v := range []string{a.text, a.Token, a.verifier, a.keyVerifier} {
		if strings.Contains(string(resp.body), v) {
			t.Errorf("%s: the list exposes a value of a secret: %s", op, resp.body)
		}
	}
	if _, ids := h.secretListOf(t, op, h.superSession(t), h.tenantB.ID); !slices.Contains(ids, b.ID) || slices.Contains(ids, a.ID) {
		t.Errorf("%s: B's list = %v, want %s and not %s", op, ids, b.ID, a.ID)
	}
}

// checkDeleteForeignSecret: A's admin deleting B's secret under A's path
// gets the answer of an unknown secret, and B's secret stays active and
// readable under B.
func checkDeleteForeignSecret(t *testing.T, h *harness, op operation, sess adminSession) {
	t.Helper()
	b := h.createSecretOfB(t)
	foreign := h.adminCall(t, sess, http.MethodDelete, tenantPath(h.tenantA.ID, "/secrets/"+b.ID), "")
	missing := h.adminCall(t, sess, http.MethodDelete, tenantPath(h.tenantA.ID, "/secrets/"+id.New(id.Secret)), "")
	h.sameAsMissing(t, op, foreign, missing, b.ID, b.Token)
	foreignTenant := h.adminCall(t, sess, http.MethodDelete, tenantPath(h.tenantB.ID, "/secrets/"+b.ID), "")
	missingTenant := h.adminCall(t, sess, http.MethodDelete, tenantPath(tenant.ID(id.New(id.Tenant)), "/secrets/"+b.ID), "")
	h.sameAsMissing(t, op, foreignTenant, missingTenant, b.ID, b.Token)
	link := operation{id: "getSecretLink", verb: http.MethodGet, template: "/secret-links/{secretToken}", base: "/api/v1"}
	if resp := h.call(t, link, hostB, map[string]string{"secretToken": b.Token}, ""); resp.status != http.StatusOK ||
		!strings.Contains(string(resp.body), `"state":"active"`) {
		t.Errorf("%s: B's secret after the attempts: %d %s, want active", op, resp.status, resp.body)
	}
	// A's admin does delete A's own secret (idempotent).
	a := h.createSecretA(t)
	for range 2 {
		if resp := h.adminCall(t, sess, http.MethodDelete, tenantPath(h.tenantA.ID, "/secrets/"+a.ID), ""); resp.status != http.StatusNoContent {
			t.Errorf("%s: A's admin deleting A's secret: %d %s, want 204", op, resp.status, resp.body)
		}
	}
	wantCode(t, link, hostA, h.call(t, link, hostA, map[string]string{"secretToken": a.Token}, ""), http.StatusGone, "secret-gone")
}

// secretSettingsOf reads the settings of tenant tid with sess.
func (h *harness) secretSettingsOf(t *testing.T, op operation, sess adminSession, tid tenant.ID) map[string]any {
	t.Helper()
	resp := h.adminCall(t, sess, http.MethodGet, tenantPath(tid, "/secret-settings"), "")
	var out map[string]any
	if json.Unmarshal(wantOK(t, op, "the secret settings of "+string(tid), resp), &out) != nil {
		t.Fatalf("%s: secret settings of %s: %s", op, tid, resp.body)
	}
	return out
}

// checkGetSecretSettings: A's admin reads A's settings, which are not B's
// object (B's are read by the super admin).
func checkGetSecretSettings(t *testing.T, h *harness, op operation, sess adminSession) {
	t.Helper()
	got := h.secretSettingsOf(t, op, sess, h.tenantA.ID)
	if got["enabled"] != true || got["durations"] == nil {
		t.Errorf("%s: A's settings = %v", op, got)
	}
}

// checkUpdateSecretSettings: A's admin changes A's settings, B's stay as
// they were, and A's are restored afterwards.
func checkUpdateSecretSettings(t *testing.T, h *harness, op operation, sess adminSession) {
	t.Helper()
	const body = `{"enabled":true,"durations":["1h","1d"],"defaultDuration":"1d","fileAllowed":true,"fileMaxBytes":2097152,` +
		`"emailAllowed":true,"emailRequiresPassphrase":false}`
	const restore = `{"enabled":true,"durations":["1h","1d","7d"],"fileAllowed":true,"fileMaxBytes":10485760,"emailAllowed":true}`
	beforeB := h.secretSettingsOf(t, op, h.superSession(t), h.tenantB.ID)
	if resp := h.adminCall(t, sess, http.MethodPut, tenantPath(h.tenantA.ID, "/secret-settings"), body); resp.status != http.StatusOK {
		t.Fatalf("%s: A's admin updating A: %d %s", op, resp.status, resp.body)
	}
	defer func() {
		if resp := h.adminCall(t, sess, http.MethodPut, tenantPath(h.tenantA.ID, "/secret-settings"), restore); resp.status != http.StatusOK {
			t.Errorf("%s: restoring A's settings: %d %s", op, resp.status, resp.body)
		}
	}()
	if got := h.secretSettingsOf(t, op, sess, h.tenantA.ID); got["fileMaxBytes"] != float64(2097152) {
		t.Errorf("%s: A's settings after the update = %v", op, got)
	}
	afterB := h.secretSettingsOf(t, op, h.superSession(t), h.tenantB.ID)
	if mustJSON(t, afterB) != mustJSON(t, beforeB) {
		t.Errorf("%s: B's settings changed: %v, was %v", op, afterB, beforeB)
	}
	// With an invalid body for B, A's admin still gets the answer of an
	// unknown tenant.
	h.invalidInputOfB(t, op, sess, http.MethodPut, "/secret-settings", `{"durations":[]}`)
}

// mustJSON returns v as JSON.
func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
