package integration_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// pathSystemStatus is getSystemStatus (since 2.3).
const pathSystemStatus = "/api/v1/admin/system/status"

// TestSystemStatus (T-415, T-416): the super admin reads the component
// states, validated against the contract, in agreement with /healthz and
// without any error message; the maintenance forced by the environment is
// reported, and the express kill switch off (TestExpressKillSwitch covers
// it on); a delegated admin gets 403 and a visitor 401, both within the
// contract.
func TestSystemStatus(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		a := startAdmin(t, e, serverOptions{env: map[string]string{config.EnvMaintenance: "true"}}, false)
		sa := a.bootstrapUnique(t, adminIP(30))

		resp := mustStatus(t, "getSystemStatus", sa.call(t, http.MethodGet, pathSystemStatus, nil), http.StatusOK)
		expectContract(t, "getSystemStatus", http.MethodGet, pathSystemStatus, resp)
		var got struct {
			Status   string `json:"status"`
			Database struct {
				Engine string `json:"engine"`
				Status string `json:"status"`
			} `json:"database"`
			Antivirus struct{ Status string } `json:"antivirus"`
			Storage   struct{ Status string } `json:"storage"`
			Maint     struct {
				Enabled bool   `json:"enabled"`
				Source  string `json:"source"`
			} `json:"maintenance"`
			Express *struct {
				InstanceDisabled *bool `json:"instanceDisabled"`
			} `json:"expressSecrets"`
			Version struct {
				UpdateCheckEnabled bool    `json:"updateCheckEnabled"`
				LatestVersion      *string `json:"latestVersion"`
			} `json:"version"`
		}
		mustJSON(t, resp.body, &got)
		if got.Status != "ok" || got.Database.Engine != e.Name || got.Database.Status != "ok" ||
			got.Storage.Status != "ok" || !got.Maint.Enabled || got.Maint.Source != "environment" ||
			got.Version.UpdateCheckEnabled || got.Version.LatestVersion != nil ||
			got.Express == nil || got.Express.InstanceDisabled == nil || *got.Express.InstanceDisabled {
			t.Errorf("getSystemStatus = %s", resp.body)
		}
		var raw map[string]json.RawMessage
		mustJSON(t, resp.body, &raw)
		if len(raw) != 8 {
			t.Errorf("getSystemStatus has %d members, want 8: %s", len(raw), resp.body)
		}
		if h := healthOf(t, a.server); h.Status != got.Status {
			t.Errorf("/healthz = %+v, status = %s", h, got.Status)
		}

		da := sa.createDelegatedOf(t, "delegate", string(a.tenantA.ID), domainA, adminIP(31))
		forbidden := da.call(t, http.MethodGet, pathSystemStatus, nil)
		expectProblem(t, forbidden, http.StatusForbidden, "forbidden")
		expectContract(t, "getSystemStatus", http.MethodGet, pathSystemStatus, forbidden)

		anonymous := a.client(&adminAccount{}, adminIP(32)).call(t, http.MethodGet, pathSystemStatus, nil)
		expectProblem(t, anonymous, http.StatusUnauthorized, "unauthenticated")
		expectContract(t, "getSystemStatus", http.MethodGet, pathSystemStatus, anonymous)
	})
}

// TestSystemStatusDegradedHasNoErrorText (T-415): with the antivirus
// unreachable the status is degraded and answers 200 with statuses only: the
// address of the engine and the connection error never appear, and the
// report agrees with /healthz.
func TestSystemStatusDegradedHasNoErrorText(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		dead := deadPort(t)
		a := startAdmin(t, e, serverOptions{clamd: dead}, false)
		sa := a.bootstrapUnique(t, adminIP(33))

		resp := mustStatus(t, "getSystemStatus", sa.call(t, http.MethodGet, pathSystemStatus, nil), http.StatusOK)
		expectContract(t, "getSystemStatus", http.MethodGet, pathSystemStatus, resp)
		var got struct {
			Status    string `json:"status"`
			Antivirus struct {
				Status string `json:"status"`
			} `json:"antivirus"`
		}
		mustJSON(t, resp.body, &got)
		if got.Status != "degraded" || got.Antivirus.Status != "unavailable" {
			t.Errorf("getSystemStatus = %s", resp.body)
		}
		body := strings.ToLower(string(resp.body))
		for _, leak := range []string{dead, "refused", "dial", "error", "connect"} {
			if strings.Contains(body, strings.ToLower(leak)) {
				t.Errorf("getSystemStatus leaks %q: %s", leak, resp.body)
			}
		}
		hz := mustStatus(t, "/healthz", a.get(t, "", "/healthz"), http.StatusServiceUnavailable)
		var h healthBody
		mustJSON(t, hz.body, &h)
		if h.Status != got.Status || h.Checks["antivirus"] != "unavailable" {
			t.Errorf("/healthz = %+v, status = %s", h, got.Status)
		}
	})
}
