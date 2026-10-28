package integration_test

import (
	"encoding/json"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// End-to-end tests of the webhook administration (CLAUDE.md section 12.4;
// api/openapi.yaml webhook operations; threat model T-181 to T-186): a real
// server and a local receiver opened by TT_WEBHOOK_ALLOW_NETWORKS, on
// SQLite and PostgreSQL.

// TestWebhookLifecycle: a delegated admin creates a generic webhook (the
// secret, 64 hexadecimal characters, is shown once and never listed; the
// URL is never returned, only its scheme and host), lists, reads, renames
// and disables it, rotates its secret, tests it (the receiver gets a
// webhook.test event signed with the new secret) and deletes it. The audit
// log of the tenant records each step without the URL nor the secret.
func TestWebhookLifecycle(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		a, _, da := startWebhookAdmin(t, e)
		rcv := newWebhookReceiver(t)
		tid := string(a.tenantA.ID)

		w := da.mustCreateWebhook(t, tid, map[string]any{
			"name": "SIEM collector", "kind": "generic", "url": rcv.url(), "events": []string{"virus.detected", "quota.reached"},
		})
		if !webhookSecretRE.MatchString(w.Secret) || w.Kind != "generic" || !w.HasSecret || !w.Enabled ||
			w.URLHint != rcv.hint() || w.CreatedBy != "delegate-webhooks" || w.LastDelivery != nil || w.CircuitOpenUntil != nil ||
			!slices.Equal(w.Events, []string{"virus.detected", "quota.reached"}) {
			t.Errorf("created = %+v", w)
		}
		teams := da.mustCreateWebhook(t, tid, map[string]any{
			"name": "Security channel", "kind": "teams", "url": rcv.url(), "events": []string{"abuse.reported"}, "enabled": false,
		})
		if teams.Secret != "" || teams.HasSecret || teams.Enabled {
			t.Errorf("created teams = %+v", teams)
		}
		list := da.listWebhooks(t, tid)
		if len(list) != 2 || list[0].ID != w.ID || list[1].ID != teams.ID || list[0].Secret != "" {
			t.Errorf("list = %+v", list)
		}
		resp := mustStatus(t, "getTenantWebhook", da.call(t, http.MethodGet, webhooksPath(tid)+"/"+w.ID, nil), http.StatusOK)
		checkWebhookMembers(t, "Webhook", resp.body, false)

		// Rename and disable, then rotate the secret.
		resp = mustStatus(t, "updateTenantWebhook", da.mergePatch(t, webhooksPath(tid)+"/"+w.ID, `{"name":"Renamed","enabled":false}`), http.StatusOK)
		checkWebhookMembers(t, "WebhookWithSecret", resp.body, true)
		var upd webhookJSON
		mustJSON(t, resp.body, &upd)
		if upd.Name != "Renamed" || upd.Enabled || upd.Secret != "" {
			t.Errorf("updated = %+v", upd)
		}
		resp = mustStatus(t, "rotate", da.mergePatch(t, webhooksPath(tid)+"/"+w.ID, `{"rotateSecret":true,"enabled":true}`), http.StatusOK)
		var rot webhookJSON
		mustJSON(t, resp.body, &rot)
		if !webhookSecretRE.MatchString(rot.Secret) || rot.Secret == w.Secret || !rot.Enabled {
			t.Fatalf("rotated = %+v", rot)
		}
		da.a.secret(rot.Secret)
		// A teams webhook has no secret to rotate; null and unknown members
		// are refused.
		for body, field := range map[string]string{
			`{"rotateSecret":true}`: "/rotateSecret", `{"name":null}`: "/name", `{"kind":"slack"}`: "/kind",
		} {
			resp := da.mergePatch(t, webhooksPath(tid)+"/"+teams.ID, body)
			expectProblem(t, resp, http.StatusBadRequest, "validation-failed")
			var p fieldProblem
			mustJSON(t, resp.body, &p)
			if len(p.Errors) != 1 || p.Errors[0].Field != field {
				t.Errorf("%s: errors %+v, want %s", body, p.Errors, field)
			}
		}

		// Test: one signed webhook.test delivery with the rotated secret.
		resp = mustStatus(t, "testTenantWebhook", da.call(t, http.MethodPost, webhooksPath(tid)+"/"+w.ID+"/test", nil), http.StatusOK)
		var tr webhookTestJSON
		mustJSON(t, resp.body, &tr)
		if !tr.Success || tr.HTTPStatus != http.StatusOK || tr.ErrorCategory != "" {
			t.Errorf("test = %+v (%s)", tr, resp.body)
		}
		got := rcv.last(t)
		if got.header.Get("X-TransTeira-Event") != "webhook.test" {
			t.Errorf("test event headers %v", got.header)
		}
		verifySignature(t, got, rot.Secret)
		var ev struct {
			Type   string `json:"type"`
			Tenant struct {
				ID string `json:"id"`
			} `json:"tenant"`
		}
		mustJSON(t, got.body, &ev)
		if ev.Type != "webhook.test" || ev.Tenant.ID != tid {
			t.Errorf("test event %s", got.body)
		}

		// Delete.
		mustStatus(t, "deleteTenantWebhook", da.call(t, http.MethodDelete, webhooksPath(tid)+"/"+w.ID, nil), http.StatusNoContent)
		expectProblem(t, da.call(t, http.MethodGet, webhooksPath(tid)+"/"+w.ID, nil), http.StatusNotFound, "not-found")
		if list := da.listWebhooks(t, tid); len(list) != 1 || list[0].ID != teams.ID {
			t.Errorf("list after delete = %+v", list)
		}
		rows := a.expectTenantAudit(t, tid, actWebhookCreated, actWebhookUpdated, actWebhookTested, actWebhookDeleted)
		for _, r := range rows {
			if strings.HasPrefix(r.action, "webhook.") && (r.objectID == "" || strings.Contains(r.details, "hooks/transteira")) {
				t.Errorf("audit %s = %+v", r.action, r)
			}
		}
		a.expectNoSecrets(t, rows)
	})
}

// TestWebhookValidation: a URL resolving to a denied network answers
// url-not-allowed on /url, a system event on a tenant webhook (and a tenant
// event on an instance-wide one) invalid-format on /events/<index>; the
// 21st webhook of a tenant answers 409 state-conflict; the 11th test of an
// hour answers 429 with Retry-After.
func TestWebhookValidation(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		a, sa, da := startWebhookAdmin(t, e)
		rcv := newWebhookReceiver(t)
		tid := string(a.tenantA.ID)
		for _, c := range []struct {
			tid   string
			body  map[string]any
			field string
			code  string
		}{
			{tid, map[string]any{"name": "x", "kind": "teams", "url": "https://10.20.30.40/hook", "events": []string{"virus.detected"}}, "/url", "url-not-allowed"},
			{tid, map[string]any{"name": "x", "kind": "teams", "url": "ftp://hooks.example.com/x", "events": []string{"virus.detected"}}, "/url", "invalid-format"},
			{tid, map[string]any{"name": "x", "kind": "teams", "url": rcv.url(), "events": []string{"virus.detected", "disk.alert_raised"}}, "/events/1", "invalid-format"},
			{tid, map[string]any{"name": "x", "kind": "teams", "url": rcv.url(), "events": []string{"webhook.test"}}, "/events/0", "invalid-format"},
			{"", map[string]any{"name": "x", "kind": "teams", "url": rcv.url(), "events": []string{"quota.reached"}}, "/events/0", "invalid-format"},
		} {
			cl := da
			if c.tid == "" {
				cl = sa
			}
			resp := cl.createWebhook(t, c.tid, c.body)
			expectProblem(t, resp, http.StatusBadRequest, "validation-failed")
			var p fieldProblem
			mustJSON(t, resp.body, &p)
			if len(p.Errors) != 1 || p.Errors[0].Field != c.field || p.Errors[0].Code != c.code {
				t.Errorf("%v: errors %+v, want %s %s", c.body, p.Errors, c.field, c.code)
			}
		}

		// At most 20 webhooks per tenant.
		var first webhookJSON
		for i := range maxWebhooks {
			w := da.mustCreateWebhook(t, tid, map[string]any{
				"name": "Hook " + strconv.Itoa(i), "kind": "slack", "url": rcv.url(), "events": []string{"quota.warning"},
			})
			if i == 0 {
				first = w
			}
		}
		expectProblem(t, da.createWebhook(t, tid, map[string]any{
			"name": "One too many", "kind": "slack", "url": rcv.url(), "events": []string{"quota.warning"},
		}), http.StatusConflict, "state-conflict")

		// At most 10 tests per hour per administrator and tenant.
		testPath := webhooksPath(tid) + "/" + first.ID + "/test"
		for i := range webhookTestLimit {
			mustStatus(t, "test "+strconv.Itoa(i), da.call(t, http.MethodPost, testPath, nil), http.StatusOK)
		}
		resp := da.call(t, http.MethodPost, testPath, nil)
		expectProblem(t, resp, http.StatusTooManyRequests, "rate-limited")
		if ra, err := strconv.Atoi(resp.header.Get(hdrRetryAfter)); err != nil || ra < 1 || ra > 3600 {
			t.Errorf("Retry-After = %q", resp.header.Get(hdrRetryAfter))
		}
		// The super admin has a budget of its own.
		mustStatus(t, "test by the super admin", sa.call(t, http.MethodPost, testPath, nil), http.StatusOK)
	})
}

// TestSystemWebhooks: the instance-wide webhooks are reserved to the super
// admin (403 for a delegated admin, before the body is read); a tenant
// webhook is unknown under the system path and an instance-wide webhook
// under a tenant path; their audit events have no tenant.
func TestSystemWebhooks(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		a, sa, da := startWebhookAdmin(t, e)
		rcv := newWebhookReceiver(t)
		tid := string(a.tenantA.ID)
		sys := sa.mustCreateWebhook(t, "", map[string]any{
			"name": "Ops", "kind": "generic", "url": rcv.url(), "events": []string{"disk.alert_raised", "maintenance.enabled"},
		})
		if !webhookSecretRE.MatchString(sys.Secret) || !sys.HasSecret {
			t.Errorf("system webhook = %+v", sys)
		}
		if list := sa.listWebhooks(t, ""); len(list) != 1 || list[0].ID != sys.ID {
			t.Errorf("system list = %+v", list)
		}
		tw := da.mustCreateWebhook(t, tid, map[string]any{
			"name": "A", "kind": "teams", "url": rcv.url(), "events": []string{"virus.detected"},
		})

		// A delegated admin: 403 on every system operation, even with an
		// invalid body.
		item := pathSystemWebhooks + "/" + sys.ID
		for _, r := range []struct {
			method, path string
			body         any
		}{
			{http.MethodGet, pathSystemWebhooks, nil},
			{http.MethodPost, pathSystemWebhooks, map[string]any{}},
			{http.MethodGet, item, nil},
			{http.MethodDelete, item, nil},
			{http.MethodPost, item + "/test", nil},
		} {
			expectProblem(t, da.call(t, r.method, r.path, r.body), http.StatusForbidden, "forbidden")
		}
		expectProblem(t, da.mergePatch(t, item, `{"kind":"slack"}`), http.StatusForbidden, "forbidden")

		// Cross paths: 404 like an unknown webhook.
		expectProblem(t, sa.call(t, http.MethodGet, pathSystemWebhooks+"/"+tw.ID, nil), http.StatusNotFound, "not-found")
		expectProblem(t, sa.call(t, http.MethodDelete, pathSystemWebhooks+"/"+tw.ID, nil), http.StatusNotFound, "not-found")
		expectProblem(t, sa.call(t, http.MethodGet, webhooksPath(tid)+"/"+sys.ID, nil), http.StatusNotFound, "not-found")
		expectProblem(t, da.call(t, http.MethodGet, webhooksPath(string(a.tenantB.ID)), nil), http.StatusNotFound, "not-found")
		expectProblem(t, sa.call(t, http.MethodGet, pathSystemWebhooks+"/"+id.New(id.Webhook), nil), http.StatusNotFound, "not-found")

		// Rotation, test and deletion by the super admin.
		resp := mustStatus(t, "rotate system", sa.mergePatch(t, item, `{"rotateSecret":true}`), http.StatusOK)
		var rot webhookJSON
		mustJSON(t, resp.body, &rot)
		sa.a.secret(rot.Secret)
		resp = mustStatus(t, "test system", sa.call(t, http.MethodPost, item+"/test", nil), http.StatusOK)
		var tr webhookTestJSON
		mustJSON(t, resp.body, &tr)
		if !tr.Success {
			t.Errorf("system test = %s", resp.body)
		}
		got := rcv.last(t)
		verifySignature(t, got, rot.Secret)
		var ev map[string]json.RawMessage
		mustJSON(t, got.body, &ev)
		if _, ok := ev["tenant"]; ok {
			t.Errorf("the system test event names a tenant: %s", got.body)
		}
		mustStatus(t, "delete system", sa.call(t, http.MethodDelete, item, nil), http.StatusNoContent)
		rows := a.expectAudit(t, actWebhookCreated, actWebhookUpdated, actWebhookTested, actWebhookDeleted)
		for _, r := range rows {
			if r.objectID == tw.ID {
				t.Errorf("a tenant webhook event is global: %+v", r)
			}
		}
	})
}
