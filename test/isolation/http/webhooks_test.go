package httpisolation_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/id"
)

// Values of the webhook cases.
const (
	// webhookNameB is the name of the webhooks created for tenant B.
	webhookNameB = "Tenant B alert webhook"
	// webhookURL is a receiver URL on a public documentation address
	// (RFC 5737): the network guard accepts it without resolving any name,
	// and no case ever delivers to it.
	webhookURL = "https://203.0.113.10/hooks/EXAMPLE"
)

// webhookView is the part of the OpenAPI WebhookWithSecret the webhook
// cases read.
type webhookView struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	Secret  string `json:"secret"`
}

// adminWebhook is the isolation case of a tenant webhook operation:
// served on the admin host only, tenant B's ID answered like an unknown
// tenant (adminTenantOp), then the checks of the operation on a webhook of
// B created by the super admin (webhookChecks).
func adminWebhook(t *testing.T, h *harness, op operation) {
	t.Helper()
	adminTenantOp(t, h, op)
	check, ok := webhookChecks[op.id]
	if !ok {
		t.Fatalf("%s has no entry in webhookChecks", op)
	}
	check(t, h, op, h.session(t), h.webhookOfB(t, op))
}

// webhookChecks are the per-operation checks of adminWebhook, run with the
// session of tenant A's delegated admin and a fresh webhook of tenant B.
var webhookChecks = map[string]func(t *testing.T, h *harness, op operation, sess adminSession, whkB webhookView){
	"listTenantWebhooks":  checkListWebhooks,
	"createTenantWebhook": checkCreateWebhook,
	"getTenantWebhook":    checkForeignWebhook(http.MethodGet, "", ""),
	"updateTenantWebhook": checkForeignWebhook(http.MethodPatch, "", `{"name":"Renamed by A","enabled":false,"rotateSecret":true}`),
	"deleteTenantWebhook": checkForeignWebhook(http.MethodDelete, "", ""),
	"testTenantWebhook":   checkForeignWebhook(http.MethodPost, "/test", ""),
}

// webhookOfB creates, as the super admin, a generic webhook of tenant B and
// returns it with its secret.
func (h *harness) webhookOfB(t *testing.T, op operation) webhookView {
	t.Helper()
	resp := h.adminCall(t, h.superSession(t), http.MethodPost, tenantPath(h.tenantB.ID, "/webhooks"),
		`{"name":"`+webhookNameB+`","kind":"generic","url":"`+webhookURL+`","events":["virus.detected"]}`)
	var w webhookView
	if resp.status != http.StatusCreated || json.Unmarshal(resp.body, &w) != nil || w.ID == "" || w.Secret == "" {
		t.Fatalf("%s: create a webhook of tenant B (super admin): %d %s", op, resp.status, resp.body)
	}
	return w
}

// webhooksOf lists the webhooks of tenant tid with the session sess.
func (h *harness) webhooksOf(t *testing.T, op operation, sess adminSession, tid string) []webhookView {
	t.Helper()
	resp := h.adminCall(t, sess, http.MethodGet, "/admin/tenants/"+tid+"/webhooks", "")
	var list []webhookView
	if json.Unmarshal(wantOK(t, op, "the webhook list of "+tid, resp), &list) != nil {
		t.Fatalf("%s: webhook list of %s: %s", op, tid, resp.body)
	}
	return list
}

// webhookOfBIntact asserts that tenant B's webhook whkB is still listed
// for B unchanged: same name, enabled.
func (h *harness) webhookOfBIntact(t *testing.T, op operation, whkB webhookView) {
	t.Helper()
	for _, w := range h.webhooksOf(t, op, h.superSession(t), string(h.tenantB.ID)) {
		if w.ID != whkB.ID {
			continue
		}
		if w.Name != webhookNameB || !w.Enabled || w.Secret != "" {
			t.Errorf("%s: tenant B's webhook was changed (or its secret listed): %+v", op, w)
		}
		return
	}
	t.Errorf("%s: tenant B's webhook %s is gone", op, whkB.ID)
}

// noWebhookOfB asserts that resp holds nothing of tenant B's webhook whkB.
func (h *harness) noWebhookOfB(t *testing.T, op operation, what string, resp response, whkB webhookView) {
	t.Helper()
	h.noDataOfB(t, op, what, resp, whkB.ID, whkB.Secret, webhookNameB)
}

// checkListWebhooks: A's list never holds B's webhook.
func checkListWebhooks(t *testing.T, h *harness, op operation, sess adminSession, whkB webhookView) {
	resp := h.adminCall(t, sess, http.MethodGet, tenantPath(h.tenantA.ID, "/webhooks"), "")
	wantOK(t, op, "tenant A's list", resp)
	h.noWebhookOfB(t, op, "tenant A's list", resp, whkB)
}

// checkCreateWebhook: an invalid body for B (a denied URL included)
// answers like an unknown tenant (the access is checked first); A's
// webhook, created under A's path, is listed for A only, never for B.
func checkCreateWebhook(t *testing.T, h *harness, op operation, sess adminSession, whkB webhookView) {
	for _, bad := range []string{
		`{}`, `null`, `{"name":"x","kind":"teams","url":"https://10.0.0.1/x","events":["virus.detected"]}`,
		`{"name":"x","kind":"teams","url":"` + webhookURL + `","events":["disk.alert_raised"]}`,
	} {
		h.invalidInputOfB(t, op, sess, http.MethodPost, "/webhooks", bad)
	}
	resp := h.adminCall(t, sess, http.MethodPost, tenantPath(h.tenantA.ID, "/webhooks"),
		`{"name":"Tenant A webhook","kind":"teams","url":"`+webhookURL+`","events":["abuse.reported"]}`)
	var whkA webhookView
	if resp.status != http.StatusCreated || json.Unmarshal(resp.body, &whkA) != nil || whkA.ID == "" {
		t.Fatalf("%s: tenant A's own webhook: %d %s, want 201", op, resp.status, resp.body)
	}
	h.noWebhookOfB(t, op, "tenant A's new webhook", resp, whkB)
	for _, w := range h.webhooksOf(t, op, h.superSession(t), string(h.tenantB.ID)) {
		if w.ID == whkA.ID {
			t.Errorf("%s: tenant A's webhook %s is listed for tenant B", op, whkA.ID)
		}
	}
	h.webhookOfBIntact(t, op, whkB)
}

// checkForeignWebhook returns the check of an operation on one webhook
// (method, path suffix, body): B's webhook under A's path answers exactly
// like a missing webhook and stays unchanged; nothing is delivered.
func checkForeignWebhook(method, suffix, body string) func(t *testing.T, h *harness, op operation, sess adminSession, whkB webhookView) {
	return func(t *testing.T, h *harness, op operation, sess adminSession, whkB webhookView) {
		foreign := h.adminCall(t, sess, method, tenantPath(h.tenantA.ID, "/webhooks/"+whkB.ID+suffix), body)
		missing := h.adminCall(t, sess, method, tenantPath(h.tenantA.ID, "/webhooks/"+id.New(id.Webhook)+suffix), body)
		h.sameAsMissing(t, op, foreign, missing, whkB.ID, whkB.Secret, webhookNameB)
		h.webhookOfBIntact(t, op, whkB)
	}
}

// systemWebhookBodies are the valid request bodies of the instance-wide
// webhook operations, so that a refusal of the delegated admin is the role
// check and nothing else.
var systemWebhookBodies = map[string]string{
	"createSystemWebhook": `{"name":"Operations","kind":"slack","url":"` + webhookURL + `","events":["disk.alert_raised"]}`,
	"updateSystemWebhook": `{"enabled":false}`,
}

// systemWebhook is the isolation case of an instance-wide webhook
// operation: served on the admin host only; 403 forbidden for tenant A's
// delegated admin, even with a valid body, without data of any tenant;
// for the super admin, a tenant webhook (of B) under the system path
// answers 404 like a missing webhook and stays unchanged, and the
// instance-wide list never holds a tenant webhook.
func systemWebhook(t *testing.T, h *harness, op operation) {
	t.Helper()
	adminHostOnly(t, h, op)
	whkB := h.webhookOfB(t, op)
	path := func(whkID string) string { return strings.ReplaceAll(op.template, "{webhookId}", whkID) }
	body := systemWebhookBodies[op.id]
	deleg := h.adminCall(t, h.session(t), op.verb, path(whkB.ID), body)
	wantCode(t, op, hostAdmin, deleg, http.StatusForbidden, "forbidden")
	h.noWebhookOfB(t, op, "the answer to a delegated admin", deleg, whkB)
	noLeak(t, h, op, hostAdmin, deleg)

	super := h.superSession(t)
	switch op.id {
	case "listSystemWebhooks":
		resp := h.adminCall(t, super, op.verb, path(""), "")
		wantOK(t, op, "super admin", resp)
		h.noWebhookOfB(t, op, "the instance-wide list", resp, whkB)
		noLeak(t, h, op, hostAdmin, resp)
	case "createSystemWebhook":
		resp := h.adminCall(t, super, op.verb, path(""), body)
		if resp.status != http.StatusCreated {
			t.Fatalf("%s: super admin: %d %s, want 201", op, resp.status, resp.body)
		}
		h.noWebhookOfB(t, op, "the new instance-wide webhook", resp, whkB)
		noLeak(t, h, op, hostAdmin, resp)
	default: // get, update, delete, test
		foreign := h.adminCall(t, super, op.verb, path(whkB.ID), body)
		missing := h.adminCall(t, super, op.verb, path(id.New(id.Webhook)), body)
		h.sameAsMissing(t, op, foreign, missing, whkB.ID, whkB.Secret, webhookNameB)
	}
	h.webhookOfBIntact(t, op, whkB)
}
