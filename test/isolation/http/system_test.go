package httpisolation_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// unknownRotation is a well-formed master key rotation identifier that
// the harness never creates.
const unknownRotation = "rot_01JABCM8Q9R0S1T2V3V4W5X6Y7"

// systemBodies are the valid request bodies of the system operations, so
// that a refusal of the delegated admin is the role check and nothing else.
var systemBodies = map[string]string{
	"setMaintenance":         `{"enabled":false}`,
	"updateSystemSettings":   `{"diskAlertThreshold":0.85}`,
	"startMasterKeyRotation": `{"code":"123456"}`,
}

// systemPath returns the path of the system operation op under /api/v1.
func systemPath(op operation) string {
	return strings.ReplaceAll(op.template, "{rotationId}", unknownRotation)
}

// systemOperation is the isolation case of an instance-wide system
// operation reserved to the super admin (maintenance mode change, system
// settings, master key): served on the admin host only, 403 forbidden for
// tenant A's delegated admin even with a valid body (and CSRF token),
// without data of any tenant; then served to the super admin, whose answer
// holds no tenant data either.
func systemOperation(t *testing.T, h *harness, op operation) {
	t.Helper()
	adminHostOnly(t, h, op)
	deleg := h.adminCall(t, h.session(t), op.verb, systemPath(op), systemBodies[op.id])
	wantCode(t, op, hostAdmin, deleg, http.StatusForbidden, "forbidden")
	h.noDataOfB(t, op, "the answer to a delegated admin", deleg)
	noLeak(t, h, op, hostAdmin, deleg)

	super := h.superSession(t)
	var resp response
	switch op.id {
	case "setMaintenance":
		// Enable with a message, then restore: the harness keeps serving
		// deposits to the other cases.
		resp = h.adminCall(t, super, op.verb, systemPath(op), `{"enabled":true,"message":{"en":"Upgrade in progress"}}`)
		restored := h.adminCall(t, super, op.verb, systemPath(op), `{"enabled":false}`)
		wantOK(t, op, "super admin enable", resp)
		var st struct {
			Enabled bool              `json:"enabled"`
			Source  string            `json:"source"`
			Message map[string]string `json:"message"`
		}
		if json.Unmarshal(resp.body, &st) != nil || !st.Enabled || st.Source != "admin" || st.Message["en"] != "Upgrade in progress" {
			t.Errorf("%s: enabled state %s", op, resp.body)
		}
		wantOK(t, op, "super admin restore", restored)
		if json.Unmarshal(restored.body, &st) != nil || st.Enabled || st.Source != "none" {
			t.Errorf("%s: restored state %s", op, restored.body)
		}
		noLeak(t, h, op, hostAdmin, restored)
	case "startMasterKeyRotation":
		// The harness configures no new master key: refused before the
		// TOTP code is checked.
		resp = h.adminCall(t, super, op.verb, systemPath(op), systemBodies[op.id])
		wantCode(t, op, hostAdmin, resp, http.StatusConflict, "new-master-key-missing")
	case "getMasterKeyRotation":
		resp = h.adminCall(t, super, op.verb, systemPath(op), "")
		wantCode(t, op, hostAdmin, resp, http.StatusNotFound, "not-found")
	default: // getSystemSettings, updateSystemSettings, getMasterKeyStatus
		resp = h.adminCall(t, super, op.verb, systemPath(op), systemBodies[op.id])
		wantOK(t, op, "super admin", resp)
		if op.id == "getMasterKeyStatus" && !strings.Contains(string(resp.body), `"activeKeyId":"`) {
			t.Errorf("%s: no active key in %s", op, resp.body)
		}
	}
	h.noDataOfB(t, op, "the answer to the super admin", resp)
	noLeak(t, h, op, hostAdmin, resp)
}

// readMaintenance is the isolation case of getMaintenance: served on the
// admin host only, readable by every administrator, the delegated admin of
// tenant A included, with the same answer as the super admin's and no
// data of any tenant.
func readMaintenance(t *testing.T, h *harness, op operation) {
	t.Helper()
	adminHostOnly(t, h, op)
	deleg := h.adminCall(t, h.session(t), op.verb, systemPath(op), "")
	wantOK(t, op, "delegated admin", deleg)
	super := h.adminCall(t, h.superSession(t), op.verb, systemPath(op), "")
	wantOK(t, op, "super admin", super)
	if string(deleg.body) != string(super.body) {
		t.Errorf("%s: delegated admin %s, super admin %s: want the same state", op, deleg.body, super.body)
	}
	for _, s := range []string{nameA, hostA, string(h.tenantA.ID)} {
		if strings.Contains(string(deleg.body), s) {
			t.Errorf("%s holds tenant data %q: %s", op, s, deleg.body)
		}
	}
	h.noDataOfB(t, op, "the answer to a delegated admin", deleg)
	noLeak(t, h, op, hostAdmin, deleg)
}
