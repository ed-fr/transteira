package httpisolation_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// auditorClass is what an auditor session attached to tenant A gets from
// an administration operation (T-281, P55).
type auditorClass int

const (
	// refused: 403 read-only-role, answered by the HTTP guard before the
	// handler, for every operation outside adminauth.AuditorOperations:
	// tenant writes, configuration reads, and also the account and system
	// operations (a delegated admin gets 403 forbidden there; the auditor
	// gets the more precise read-only-role, which tells no more: the
	// answer never depends on the object). A read (GET) of tenant B is 404
	// not-found instead, like a missing tenant; a write on B stays 403
	// read-only-role, the same answer as on A.
	refused auditorClass = iota
	// tenantRead: an audit read of a tenant, 2xx on A and 404 not-found on
	// B (both 404 while the operation is a stub).
	tenantRead
	// ownAccount: an operation on the auditor's own account or the tenant
	// list, which reaches its handler (status in ownAccountStatus).
	ownAccount
	// loginFlow: an operation served without a session (or before the
	// session is authenticated): the auditor cookie plays no part, the
	// guard never answers it.
	loginFlow
)

// auditorExpect classifies every administration operation of the
// specification (paths under /admin). The test fails when an operation is
// missing, so that a new operation is denied or opened deliberately.
var auditorExpect = map[string]auditorClass{
	// Login flow: open routes, and the second factor of a pending
	// session.
	"activateAdmin":          loginFlow,
	"adminLogin":             loginFlow,
	"completeAdminOidcLogin": loginFlow,
	"createSuperAdmin":       loginFlow,
	"getAdminAuthMethods":    loginFlow,
	"getSetupStatus":         loginFlow,
	"startAdminOidcLogin":    loginFlow,
	// The second factor is a step of a pending session, which the guard
	// leaves to the service; an authenticated auditor session has nothing
	// to verify and is refused.
	"adminVerifyTotp": refused,

	// Own account and tenant list.
	"adminLogout":           ownAccount,
	"changeAdminPassword":   ownAccount,
	"confirmTotpEnrollment": ownAccount,
	"disableTotp":           ownAccount,
	"getAdminMe":            ownAccount,
	"listTenants":           ownAccount,
	"startTotpEnrollment":   ownAccount,

	// Audit reads of an attached tenant.
	"getTenant":                tenantRead,
	"getTenantStats":           tenantRead,
	"getTenantSso":             tenantRead,
	"getTenantTransfer":        tenantRead,
	"getTenantTransferProof":   tenantRead,
	"listTenantAuditEvents":    tenantRead,
	"listTenantSecurityEvents": tenantRead,
	"listTenantTransfers":      tenantRead,

	// Accounts (super admin only).
	"createAdmin":           refused,
	"deleteAdmin":           refused,
	"deleteAdminIdentity":   refused,
	"getAdmin":              refused,
	"inviteAdmin":           refused,
	"listAdmins":            refused,
	"resetAdminCredentials": refused,
	"updateAdmin":           refused,

	// System (super admin only).
	"checkSystemVersion":       refused,
	"createProvisioningToken":  refused,
	"createSystemWebhook":      refused,
	"createTenant":             refused,
	"deleteSystemWebhook":      refused,
	"deleteTenant":             refused,
	"getGlobalStats":           refused,
	"getMaintenance":           refused,
	"getMasterKeyRotation":     refused,
	"getMasterKeyStatus":       refused,
	"getSystemSettings":        refused,
	"getSystemVersion":         refused,
	"getSystemWebhook":         refused,
	"importTenant":             refused,
	"listGlobalAuditEvents":    refused,
	"listGlobalSecurityEvents": refused,
	"listProvisioningTokens":   refused,
	"listSystemWebhooks":       refused,
	"revokeProvisioningToken":  refused,
	"setMaintenance":           refused,
	"startMasterKeyRotation":   refused,
	"testAntivirus":            refused,
	"testSystemWebhook":        refused,
	"updateSystemSettings":     refused,
	"updateSystemWebhook":      refused,

	// Background presets (configuration screens).
	"getBackgroundPreset":   refused,
	"listBackgroundPresets": refused,

	// Tenant configuration, reads and writes.
	"checkMailDns":                refused,
	"completeTenantSetup":         refused,
	"deleteBrandingAsset":         refused,
	"deleteTenantSso":             refused,
	"exportTenantConfig":          refused,
	"getAbuseThresholds":          refused,
	"getBranding":                 refused,
	"getBrandingAsset":            refused,
	"getConfidentialityLevels":    refused,
	"getEmailTemplate":            refused,
	"getLegalDocumentAdmin":       refused,
	"getNetworkRules":             refused,
	"getRecipientRules":           refused,
	"getSmtpSettings":             refused,
	"getTenantSetup":              refused,
	"getTextProposal":             refused,
	"listEmailTemplates":          refused,
	"previewEmailTemplate":        refused,
	"putTenantSso":                refused,
	"resetEmailTemplate":          refused,
	"setBackgroundPreset":         refused,
	"testSmtp":                    refused,
	"testTenantSso":               refused,
	"updateAbuseThresholds":       refused,
	"updateBranding":              refused,
	"updateConfidentialityLevels": refused,
	"updateEmailTemplate":         refused,
	"updateLegalDocument":         refused,
	"updateNetworkRules":          refused,
	"updateRecipientRules":        refused,
	"updateSmtpSettings":          refused,
	"updateTenant":                refused,
	"uploadBrandingAsset":         refused,

	// Tenant operations other than the audit reads.
	"createApiToken":             refused,
	"createBlocklistEntry":       refused,
	"createDropLink":             refused,
	"createTenantWebhook":        refused,
	"deleteBlocklistEntry":       refused,
	"deleteDropLink":             refused,
	"deleteTenantTransfer":       refused,
	"deleteTenantWebhook":        refused,
	"eraseDataSubject":           refused,
	"getAbuseReport":             refused,
	"getDropLink":                refused,
	"getTenantWebhook":           refused,
	"listAbuseReports":           refused,
	"listApiTokens":              refused,
	"listBlocklist":              refused,
	"listDropLinks":              refused,
	"listTenantInvitations":      refused,
	"listTenantWebhooks":         refused,
	"resendTransferNotification": refused,
	"revokeApiToken":             refused,
	"revokeInvitation":           refused,
	"rotateDropLink":             refused,
	"searchDataSubject":          refused,
	"testTenantWebhook":          refused,
	"updateAbuseReport":          refused,
	"updateApiToken":             refused,
	"updateDropLink":             refused,
	"updateTenantWebhook":        refused,
}

// ownAccountStatus is the answer of each ownAccount operation to the
// auditor session with the sample body ({}): the handler is reached, and
// refuses the empty body or answers normally. adminLogout runs last.
var ownAccountStatus = map[string]int{
	"getAdminMe":            http.StatusOK,
	"listTenants":           http.StatusOK,
	"changeAdminPassword":   http.StatusBadRequest,
	"startTotpEnrollment":   http.StatusBadRequest,
	"confirmTotpEnrollment": http.StatusBadRequest,
	"disableTotp":           http.StatusUnauthorized, // wrong (empty) password
	"adminLogout":           http.StatusNoContent,
}

// auditorUser and auditorPassword identify the auditor of tenant A.
const (
	auditorUser     = "audit.entity-a"
	auditorPassword = "a-long-passphrase-for-the-auditor"
)

// newAuditor creates, through the super admin API, an auditor of tenant A
// without TOTP requirement, activates it with its copied link and returns
// its authenticated session.
func (h *harness) newAuditor(t *testing.T) adminSession {
	t.Helper()
	super := h.superSession(t)
	body := `{"username":"` + auditorUser + `","email":"audit@entity-a.example.com","role":"auditor","tenantIds":["` +
		string(h.tenantA.ID) + `"],"requireTotp":false}`
	resp := h.adminCall(t, super, http.MethodPost, "/admin/admins", body)
	var created struct {
		Role          string   `json:"role"`
		TenantIDs     []string `json:"tenantIds"`
		ActivationURL string   `json:"activationUrl"`
	}
	if resp.status != http.StatusCreated || json.Unmarshal(resp.body, &created) != nil || created.Role != "auditor" ||
		!slices.Equal(created.TenantIDs, []string{string(h.tenantA.ID)}) {
		t.Fatalf("create auditor: %d %s", resp.status, resp.body)
	}
	_, token, ok := strings.Cut(created.ActivationURL, "#")
	if !ok || token == "" {
		t.Fatalf("activation link %q", created.ActivationURL)
	}
	act, _ := json.Marshal(map[string]string{"activationToken": token, "password": auditorPassword})
	hdr := http.Header{
		"Content-Type": {"application/json"}, "Origin": {"https://" + hostAdmin}, "Sec-Fetch-Site": {"same-origin"},
	}
	resp = h.do(t, http.MethodPost, "http://"+h.addr+"/api/v1/admin/activation", hostAdmin, bytes.NewReader(act), hdr)
	var state struct {
		Status    string `json:"status"`
		CsrfToken string `json:"csrfToken"`
	}
	if resp.status != http.StatusOK || json.Unmarshal(resp.body, &state) != nil || state.Status != "authenticated" || state.CsrfToken == "" {
		t.Fatalf("activate auditor: %d %s", resp.status, resp.body)
	}
	for _, c := range (&http.Response{Header: resp.header}).Cookies() {
		if c.Name == adminCookie && c.Value != "" {
			return adminSession{cookie: c.Value, csrf: state.CsrfToken}
		}
	}
	t.Fatalf("activation set no admin cookie: %v", resp.header)
	return adminSession{}
}

// sendRole performs op on the admin host with the session sess, tenantID
// in {tenantId}, the given path parameters, and sample values (or the
// validBodies body) for the rest.
func (h *harness) sendRole(t *testing.T, sess adminSession, op operation, tenantID string, params map[string]string) response {
	t.Helper()
	path := op.template
	query := url.Values{}
	for _, p := range op.params {
		v, ok := params[p.Name]
		if !ok {
			v = p.sample()
		}
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

// TestAuditorRoleEveryOperation walks every administration operation of
// the specification as an auditor of tenant A (T-281): the operations
// outside adminauth.AuditorOperations are refused with 403 read-only-role
// whatever the tenant, the audit reads answer on A and 404 on B, the own
// account operations reach their handler. A delegated admin of A still
// writes on A.
func TestAuditorRoleEveryOperation(t *testing.T) {
	ops := loadOperations(t)
	var adminOps []operation
	for _, op := range ops {
		if strings.HasPrefix(op.template, "/admin/") || op.template == "/admin" {
			adminOps = append(adminOps, op)
		}
	}

	t.Run("table covers the specification", func(t *testing.T) {
		known := map[string]bool{}
		for _, op := range adminOps {
			known[op.id] = true
			if _, ok := auditorExpect[op.id]; !ok {
				t.Errorf("administration operation %s is not classified in auditorExpect: deny or open it deliberately", op.id)
			}
		}
		for id, class := range auditorExpect {
			if !known[id] {
				t.Errorf("auditorExpect has a stale entry %q", id)
			}
			open := class == tenantRead || class == ownAccount
			if open != adminauth.AuditorOperations[id] {
				t.Errorf("%s: class %d, but adminauth.AuditorOperations[%s] = %v", id, class, id, adminauth.AuditorOperations[id])
			}
			if class == ownAccount {
				if _, ok := ownAccountStatus[id]; !ok {
					t.Errorf("%s has no ownAccountStatus", id)
				}
			}
		}
		for id := range adminauth.AuditorOperations {
			if !known[id] {
				t.Errorf("adminauth.AuditorOperations has %q, not in the specification", id)
			}
		}
	})

	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		h := startHarness(t, e)
		auditor := h.newAuditor(t)
		trA := h.newTransfer(t, h.colleague(t), "ivan@customer.example.net")
		params := map[string]string{"transferId": trA.ID}
		a, b := string(h.tenantA.ID), string(h.tenantB.ID)
		var logout *operation
		sort.Slice(adminOps, func(i, j int) bool { return adminOps[i].id < adminOps[j].id })
		for _, op := range adminOps {
			t.Run(op.id, func(t *testing.T) {
				switch auditorExpect[op.id] {
				case refused:
					resp := h.sendRole(t, auditor, op, a, params)
					if resp.status != http.StatusForbidden || problemCode(resp) != "read-only-role" {
						t.Errorf("%s by the auditor of A on A: %d %s, want 403 read-only-role", op, resp.status, resp.body)
					}
					resp = h.sendRole(t, auditor, op, b, params)
					if op.verb == http.MethodGet && strings.Contains(op.template, "{tenantId}") {
						wantCode(t, op, hostAdmin, resp, http.StatusNotFound, "not-found")
					} else if resp.status != http.StatusForbidden || problemCode(resp) != "read-only-role" {
						t.Errorf("%s by the auditor of A on B: %d %s, want 403 read-only-role", op, resp.status, resp.body)
					}
					h.noDataOfB(t, op, "auditor of A on B", resp)
				case tenantRead:
					own := h.sendRole(t, auditor, op, a, params)
					foreign := h.sendRole(t, auditor, op, b, params)
					if isStub(t, op) {
						wantCode(t, op, hostAdmin, own, http.StatusNotFound, "not-found")
					} else if own.status < 200 || own.status > 299 {
						t.Errorf("%s by the auditor of A on A: %d %s, want 2xx", op, own.status, own.body)
					}
					wantCode(t, op, hostAdmin, foreign, http.StatusNotFound, "not-found")
					h.noDataOfB(t, op, "auditor of A", own)
					h.noDataOfB(t, op, "auditor of A on B", foreign)
					if op.id == "getTenantTransfer" && !strings.Contains(string(own.body), trA.ID) {
						t.Errorf("%s: %s", op, own.body)
					}
				case ownAccount:
					if op.id == "adminLogout" {
						logout = &op
						return
					}
					resp := h.sendRole(t, auditor, op, a, params)
					if want := ownAccountStatus[op.id]; resp.status != want {
						t.Errorf("%s by the auditor: %d %s, want %d", op, resp.status, resp.body, want)
					}
					h.noDataOfB(t, op, "auditor of A", resp)
					if op.id == "getAdminMe" && !strings.Contains(string(resp.body), `"role":"auditor"`) {
						t.Errorf("%s: %s", op, resp.body)
					}
				case loginFlow:
					resp := h.sendRole(t, auditor, op, a, params)
					if problemCode(resp) == "read-only-role" || resp.status >= 500 {
						t.Errorf("%s with the auditor cookie: %d %s", op, resp.status, resp.body)
					}
				}
			})
		}

		t.Run("no search by address", func(t *testing.T) {
			// T-282: an auditor may not look a person up by address.
			for _, path := range []string{
				tenantPath(h.tenantA.ID, "/transfers?email=ivan%40customer.example.net"),
				tenantPath(h.tenantA.ID, "/audit-events?actor=ivan%40customer.example.net"),
			} {
				resp := h.adminCall(t, auditor, http.MethodGet, path, "")
				if resp.status != http.StatusForbidden || problemCode(resp) != "read-only-role" {
					t.Errorf("GET %s by the auditor: %d %s, want 403 read-only-role", path, resp.status, resp.body)
				}
				resp = h.adminCall(t, h.session(t), http.MethodGet, path, "")
				if resp.status != http.StatusOK {
					t.Errorf("GET %s by the delegated admin: %d %s, want 200", path, resp.status, resp.body)
				}
			}
		})

		t.Run("delegated admin still writes", func(t *testing.T) {
			deleg := h.session(t)
			resp := h.adminCall(t, deleg, http.MethodPost, tenantPath(h.tenantA.ID, "/blocklist"), `{"kind":"domain","value":"roles.example.net"}`)
			if resp.status != http.StatusCreated {
				t.Errorf("delegated admin blocklist write on A: %d %s", resp.status, resp.body)
			}
			resp = h.adminCall(t, deleg, http.MethodGet, tenantPath(h.tenantA.ID, "/smtp"), "")
			if resp.status != http.StatusOK && resp.status != http.StatusNotFound {
				t.Errorf("delegated admin smtp read on A: %d %s", resp.status, resp.body)
			}
			resp = h.adminCall(t, deleg, http.MethodGet, "/admin/admins", "")
			if resp.status != http.StatusForbidden || problemCode(resp) != "forbidden" {
				t.Errorf("delegated admin account list: %d %s, want 403 forbidden", resp.status, resp.body)
			}
		})

		t.Run("adminLogout", func(t *testing.T) {
			if logout == nil {
				t.Fatal("adminLogout is not in the specification")
			}
			resp := h.sendRole(t, auditor, *logout, a, params)
			if resp.status != ownAccountStatus["adminLogout"] {
				t.Errorf("logout of the auditor: %d %s", resp.status, resp.body)
			}
			resp = h.adminCall(t, auditor, http.MethodGet, "/admin/me", "")
			if resp.status != http.StatusUnauthorized {
				t.Errorf("auditor session after logout: %d %s", resp.status, resp.body)
			}
		})
	})
}
