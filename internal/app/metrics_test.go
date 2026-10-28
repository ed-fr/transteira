package app

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// testMetricsToken is a made-up monitoring token of the tests.
const testMetricsToken = "metrics-token-of-the-tests-0123456789"

// getWithToken sends GET path with the monitoring token, "" for none.
func (s *started) getWithToken(t *testing.T, path, token string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://memory"+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = tenantHost
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := s.ln.client().Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// TestRunSupervision checks the wiring of /metrics and /status on a running
// server: absent without a token, protected by it, and fed by the collector
// and the HTTP counters.
func TestRunSupervision(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		cfg := testConfig(t, e)
		prepare(t, cfg)
		if e.Driver == config.DriverPostgres {
			cfg.DBMigrateDSN = config.Secret{}
		}
		cfg.ClamAV.Address = fakeClamd(t)
		cfg.MetricsToken = config.NewSecret(testMetricsToken)
		s := start(t, cfg)

		if code, _ := s.getWithToken(t, "/metrics", ""); code != http.StatusUnauthorized {
			t.Fatalf("metrics without token = %d", code)
		}
		if code, _ := s.getWithToken(t, "/metrics", testMetricsToken+"x"); code != http.StatusUnauthorized {
			t.Fatalf("metrics with a wrong token = %d", code)
		}
		code, body := s.getWithToken(t, "/metrics", testMetricsToken)
		if code != http.StatusOK {
			t.Fatalf("metrics = %d %s", code, body)
		}
		for _, want := range []string{
			"transteira_build_info{", `transteira_storage_quota_bytes{tenant="ten_`,
			`transteira_http_requests_total{class="4xx"}`, "transteira_antivirus_up 1",
			`transteira_events_dropped_total{subscriber="webhook"} 0`,
		} {
			if !strings.Contains(body, want) {
				t.Errorf("metrics lack %q:\n%s", want, body)
			}
		}

		code, body = s.getWithToken(t, "/status", testMetricsToken)
		if code != http.StatusOK {
			t.Fatalf("status = %d %s", code, body)
		}
		var st struct {
			Status  string `json:"status"`
			Tenants []struct {
				Name              string `json:"name"`
				StorageQuotaBytes int64  `json:"storageQuotaBytes"`
			} `json:"tenants"`
		}
		if err := json.Unmarshal([]byte(body), &st); err != nil {
			t.Fatal(err)
		}
		if st.Status != "ok" || len(st.Tenants) != 1 || st.Tenants[0].Name != "Entity A" || st.Tenants[0].StorageQuotaBytes != 10<<30 {
			t.Errorf("status = %s", body)
		}
		if err := s.stop(t); err != nil {
			t.Fatalf("Run = %v", err)
		}
		if strings.Contains(s.logs.String(), testMetricsToken) {
			t.Error("the logs reveal the monitoring token")
		}
	})
}
