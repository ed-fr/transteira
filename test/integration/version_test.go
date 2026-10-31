package integration_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// System version API paths (since 1.2).
const (
	pathSystemVersion = "/api/v1/admin/system/version"
	pathVersionCheck  = "/api/v1/admin/system/version/check"
)

// updateCheckJSON is the OpenAPI UpdateCheck, every member raw so that
// null is told from absent.
type updateCheckJSON map[string]json.RawMessage

// systemVersion returns the update check of getSystemVersion.
func (c *adminClient) systemVersion(t *testing.T) updateCheckJSON {
	t.Helper()
	resp := mustStatus(t, "getSystemVersion", c.call(t, http.MethodGet, pathSystemVersion, nil), http.StatusOK)
	var body struct {
		Version     string          `json:"version"`
		UpdateCheck updateCheckJSON `json:"updateCheck"`
	}
	mustJSON(t, resp.body, &body)
	if body.Version == "" || len(body.UpdateCheck) != 6 {
		t.Fatalf("getSystemVersion = %s", resp.body)
	}
	return body.UpdateCheck
}

// TestSystemVersionDisabled (T-244 to T-248; no test reaches GitHub):
// with TT_UPDATE_CHECK=false, the version is shown without any check and
// a manual check answers 409 update-check-disabled.
func TestSystemVersionDisabled(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		a := startAdmin(t, e, serverOptions{}, false)
		sa := a.bootstrapUnique(t, adminIP(10))
		got := sa.systemVersion(t)
		for member, want := range map[string]string{
			"enabled": "false", "latestVersion": "null", "releaseUrl": "null", "updateAvailable": "false",
			"checkedAt": "null", "lastError": `"none"`,
		} {
			if string(got[member]) != want {
				t.Errorf("disabled: %s = %s, want %s", member, got[member], want)
			}
		}
		expectProblem(t, sa.call(t, http.MethodPost, pathVersionCheck, nil), http.StatusConflict, "update-check-disabled")
	})
}

// TestSystemVersionNoCheckAtStart: enabled, the start-up and /healthz
// make no check (T-247): the outcome stays "never checked". No manual
// check is asked, which would reach GitHub.
func TestSystemVersionNoCheckAtStart(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		b := startAdmin(t, e, serverOptions{env: map[string]string{config.EnvUpdateCheck: "true"}}, false)
		if h := healthOf(t, b.server); h.Status != "ok" {
			t.Errorf("/healthz with the update check enabled = %+v", h)
		}
		sb := b.bootstrapUnique(t, adminIP(11))
		got := sb.systemVersion(t)
		if string(got["enabled"]) != "true" || string(got["latestVersion"]) != "null" || string(got["checkedAt"]) != "null" ||
			string(got["lastError"]) != `"none"` {
			t.Errorf("enabled, right after the start: %v", got)
		}
	})
}
