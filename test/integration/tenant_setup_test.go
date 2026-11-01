package integration_test

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/store/storetest"
)

// setupHost is the FQDN of the tenant created in the setup state.
const setupHost = "transfer.entity-setup.localhost"

// requiredSetupItems are the required items of the setup checklist a bare
// tenant has not done.
var requiredSetupItems = []string{"smtp", "internal_networks", "internal_domains", "legal_notice", "privacy_policy"}

// TestTenantSetupState covers the public behavior of a tenant in the setup
// state (V1.2, threat model T-260 and T-264): only its public information,
// assets and legal texts are served; deposit, invitation, upload and
// download operations answer 503 tenant-in-setup; the completion refuses an
// unfinished checklist, and once forced by the super admin the tenant is
// active and its operations are served again.
func TestTenantSetupState(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		a := startAdmin(t, e, serverOptions{}, false)
		sa := a.bootstrap(t, adminIP(50))
		resp := mustStatus(t, "createTenant in setup", sa.call(t, http.MethodPost, pathTenants, map[string]any{
			"name": "Entity Setup", "fqdn": setupHost, "defaultLanguage": "en", "storageQuotaBytes": 1 << 30,
			"setupState": "setup",
		}), http.StatusCreated)
		var tn tenantJSON
		mustJSON(t, resp.body, &tn)

		publicState := func() string {
			t.Helper()
			resp := mustStatus(t, "GET /tenant", a.get(t, setupHost, pathPublicTenant), http.StatusOK)
			var p struct {
				SetupState string `json:"setupState"`
			}
			mustJSON(t, resp.body, &p)
			return p.SetupState
		}
		if got := publicState(); got != "setup" {
			t.Fatalf("public setupState = %q, want setup", got)
		}

		// Served while in setup: the tenant information, its assets and its
		// legal texts (absent ones answer 404, never 503), and the version.
		for _, tc := range []struct {
			name, path string
			want       []int
		}{
			{"tenant", pathPublicTenant, []int{http.StatusOK}},
			{"background", pathPublicBg, []int{http.StatusOK, http.StatusNotFound}},
			{"logo", pathPublicLogo, []int{http.StatusNotFound}},
			{"legal notice", pathPublicLegal + "legal-notice", []int{http.StatusOK, http.StatusNotFound}},
			{"privacy policy", pathPublicLegal + "privacy-policy", []int{http.StatusOK, http.StatusNotFound}},
			{"version", "/api/v1/version", []int{http.StatusOK}},
		} {
			if got := a.get(t, setupHost, tc.path); !slices.Contains(tc.want, got.status) {
				t.Errorf("%s while in setup: %d %s, want one of %v", tc.name, got.status, got.body, tc.want)
			}
		}

		// Refused while in setup, before any credential is looked at.
		refused := []struct {
			name string
			req  request
		}{
			{"verification code request", request{method: http.MethodPost, path: pathSessions, body: []byte(`{"email":"alice@` + domainA + `"}`)}},
			{"invitation", request{method: http.MethodPost, path: pathInvitations, body: []byte(`{"email":"bob@example.org"}`)}},
			{"invitation lookup", request{path: pathInvitations + "/inv_" + strings.Repeat("a", 32)}},
			{"transfer creation with an API token", request{
				method: http.MethodPost, path: pathTransfers, body: []byte(`{}`),
				headers: http.Header{"Authorization": {"Bearer tt_" + strings.Repeat("A", 43)}},
			}},
			{"download page", request{path: pathDownloads + "dl_" + strings.Repeat("a", 32)}},
			{"download archive", request{path: pathDownloads + "dl_" + strings.Repeat("a", 32) + "/archive"}},
		}
		for _, tc := range refused {
			tc.req.host = setupHost
			tc.req.headers = withHeader(tc.req.headers, hdrXFF, insideA)
			p := expectProblem(t, a.do(t, tc.req), http.StatusServiceUnavailable, "tenant-in-setup")
			if p.RetryAfterSeconds != nil {
				t.Errorf("%s: retryAfterSeconds = %d, want none", tc.name, *p.RetryAfterSeconds)
			}
		}
		// The tus operations get a bodyless 503.
		for _, method := range []string{http.MethodOptions, http.MethodHead, http.MethodPatch, http.MethodDelete} {
			path := pathUploads
			if method != http.MethodOptions {
				path += "/" + exampleUploadID
			}
			// Well-formed requests: the tus parameters are validated before the
			// tenant state is looked at.
			h := http.Header{hdrXFF: {insideA}, "Tus-Resumable": {"1.0.0"}}
			r := request{method: method, path: path, host: setupHost, headers: h}
			if method == http.MethodPatch {
				h.Set("Upload-Offset", "0")
				h.Set("Content-Type", "application/offset+octet-stream")
				r.body = []byte("x")
			}
			got := a.do(t, r)
			if got.status != http.StatusServiceUnavailable || len(got.body) != 0 || got.header.Get("Retry-After") != "" {
				t.Errorf("tus %s while in setup: %d %q Retry-After %q, want a bodyless 503", method, got.status, got.body, got.header.Get("Retry-After"))
			}
		}
		// Another tenant of the instance is not affected.
		if got := a.get(t, hostA, pathPublicTenant); got.status != http.StatusOK || strings.Contains(string(got.body), `"setup"`) {
			t.Errorf("tenant A while C is in setup: %d %s", got.status, got.body)
		}

		// The checklist is not done: the completion lists the missing items.
		completePath := tenantPath(tn.ID, "/setup/complete")
		p := sa.call(t, http.MethodPost, completePath, map[string]any{})
		expectProblem(t, p, http.StatusConflict, "setup-incomplete")
		var fp fieldProblem
		mustJSON(t, p.body, &fp)
		var missing []string
		for _, fe := range fp.Errors {
			if fe.Code != "not-done" {
				t.Errorf("field error %+v, want code not-done", fe)
			}
			missing = append(missing, fe.Field)
		}
		if !slices.Equal(missing, requiredSetupItems) {
			t.Errorf("missing items = %v, want %v", missing, requiredSetupItems)
		}
		if got := publicState(); got != "setup" {
			t.Errorf("public setupState after the refused completion = %q, want setup", got)
		}

		// Forced by the super admin: active at once, and the code request is
		// no longer stopped by the setup (the internal rules refuse it here).
		mustStatus(t, "forced completion", sa.call(t, http.MethodPost, completePath, map[string]any{"force": true}), http.StatusOK)
		if got := publicState(); got != "active" {
			t.Errorf("public setupState after completion = %q, want active", got)
		}
		after := a.do(t, request{
			method: http.MethodPost, path: pathSessions, host: setupHost, body: []byte(`{"email":"alice@` + domainA + `"}`),
			headers: http.Header{hdrXFF: {insideA}},
		})
		if after.status == http.StatusServiceUnavailable && strings.Contains(string(after.body), "tenant-in-setup") {
			t.Errorf("code request after completion still answers tenant-in-setup: %s", after.body)
		}
		if after.status == http.StatusAccepted || after.status == http.StatusCreated {
			t.Errorf("code request on a tenant without internal rules: %d %s, want a refusal", after.status, after.body)
		}
		// No way back: a second completion is refused.
		expectProblem(t, sa.call(t, http.MethodPost, completePath, map[string]any{"force": true}),
			http.StatusConflict, "setup-already-complete")
		a.expectLogsClean(t, nil)
	})
}

// withHeader returns h (copied) with key set to value.
func withHeader(h http.Header, key, value string) http.Header {
	out := h.Clone()
	if out == nil {
		out = http.Header{}
	}
	out.Set(key, value)
	return out
}
