package httpisolation_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// listTenantIDs returns the IDs of the tenants the super admin sees.
func (h *harness) listTenantIDs(t *testing.T) []string {
	t.Helper()
	resp := h.adminCall(t, h.superSession(t), http.MethodGet, "/admin/tenants?limit=200", "")
	var list struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	if resp.status != http.StatusOK || json.Unmarshal(resp.body, &list) != nil {
		t.Fatalf("list tenants: %d %s", resp.status, resp.body)
	}
	ids := make([]string, 0, len(list.Items))
	for _, it := range list.Items {
		ids = append(ids, it.ID)
	}
	return ids
}

// exportTenantConfigCase is the isolation case of exportTenantConfig:
// served on the admin host only; the delegated admin of A exports A, and
// for tenant B gets exactly the 404 of an unknown tenant, with nothing
// exported (no audit event in B); an auditor of A gets 403 read-only-role.
func exportTenantConfigCase(t *testing.T, h *harness, op operation) {
	t.Helper()
	adminHostOnly(t, h, op)
	tenantScoped(t, h, op)
	deleg := h.session(t)

	own := h.adminCall(t, deleg, http.MethodGet, tenantPath(h.tenantA.ID, "/export"), "")
	if own.status != http.StatusOK || !strings.Contains(string(own.body), `"schemaVersion"`) {
		t.Fatalf("%s for tenant A by its delegated admin: %d %s", op, own.status, own.body)
	}
	h.noTenantB(t, op, own)

	foreign := h.adminCall(t, deleg, http.MethodGet, tenantPath(h.tenantB.ID, "/export?includeBranding=true"), "")
	wantCode(t, op, hostAdmin, foreign, http.StatusNotFound, "not-found")
	h.noTenantB(t, op, foreign)

	// Nothing was exported for B: its audit log holds no export event.
	audit := h.adminCall(t, h.superSession(t), http.MethodGet, tenantPath(h.tenantB.ID, "/audit-events?limit=200"), "")
	wantOK(t, op, "tenant B's audit log", audit)
	if strings.Contains(string(audit.body), "tenant.exported") {
		t.Errorf("%s: tenant B's audit log holds an export event after a refused export: %s", op, audit.body)
	}

	aud := h.auditorSession(t)
	for _, tid := range []string{string(h.tenantA.ID), string(h.tenantB.ID)} {
		resp := h.adminCall(t, aud, http.MethodGet, "/admin/tenants/"+tid+"/export", "")
		// A read of B is the 404 of a missing tenant, a read of A is
		// refused: a configuration export is not an audit read.
		if tid == string(h.tenantA.ID) {
			wantCode(t, op, hostAdmin, resp, http.StatusForbidden, "read-only-role")
		} else if resp.status != http.StatusNotFound && resp.status != http.StatusForbidden {
			t.Errorf("%s by an auditor for tenant B: %d %s", op, resp.status, resp.body)
		}
		h.noTenantB(t, op, resp)
	}
}

// importTenantCase is the isolation case of importTenant: served on the
// admin host only and reserved to the super admin: a delegated admin gets
// 403 forbidden whatever the body, and no tenant is created; an auditor
// gets 403 read-only-role.
func importTenantCase(t *testing.T, h *harness, op operation) {
	t.Helper()
	adminHostOnly(t, h, op)
	before := h.listTenantIDs(t)
	body := `{"name":"Imported Entity","fqdn":"imported.entity-a.example.com","storageQuotaBytes":1073741824,` +
		`"config":{"schemaVersion":1}}`
	resp := h.adminCall(t, h.session(t), http.MethodPost, "/admin/tenants/import", body)
	wantCode(t, op, hostAdmin, resp, http.StatusForbidden, "forbidden")
	h.noTenantB(t, op, resp)
	resp = h.adminCall(t, h.auditorSession(t), http.MethodPost, "/admin/tenants/import", body)
	wantCode(t, op, hostAdmin, resp, http.StatusForbidden, "read-only-role")
	if after := h.listTenantIDs(t); len(after) != len(before) {
		t.Errorf("%s: tenants %v before, %v after the refused imports", op, before, after)
	}
}

// auditorSession returns the session of the auditor of tenant A, created on
// first use (the account can be created once).
func (h *harness) auditorSession(t *testing.T) adminSession {
	t.Helper()
	h.sessMu.Lock()
	have := h.auditor
	h.sessMu.Unlock()
	if have != nil {
		return *have
	}
	s := h.newAuditor(t)
	h.sessMu.Lock()
	h.auditor = &s
	h.sessMu.Unlock()
	return s
}
