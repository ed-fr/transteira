package integration_test

import (
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/ed-fr/transteira/internal/store/storetest"
)

// healthBody is the Health schema.
type healthBody struct {
	Status      string            `json:"status"`
	Version     string            `json:"version"`
	Maintenance bool              `json:"maintenance"`
	Checks      map[string]string `json:"checks"`
}

// depositRequests are the operations that start or feed a deposit, which
// maintenance mode must refuse (CLAUDE.md section 4).
func depositRequests() map[string]request {
	tus := http.Header{
		"Content-Type":  {"application/offset+octet-stream"},
		"Tus-Resumable": {"1.0.0"},
		"Upload-Offset": {"0"},
	}
	return map[string]request{
		"startDepositSession": {method: http.MethodPost, path: "/api/v1/deposit-sessions", body: []byte(`{}`)},
		"createTransfer":      {method: http.MethodPost, path: "/api/v1/transfers", body: []byte(`{}`)},
		"finalizeTransfer":    {method: http.MethodPost, path: "/api/v1/transfers/" + exampleTransferID + "/finalize", body: []byte(`{}`)},
		"appendUploadChunk":   {method: http.MethodPatch, path: "/api/v1/uploads/" + exampleUploadID, body: []byte("x"), headers: tus},
		"createInvitation":    {method: http.MethodPost, path: "/api/v1/invitations", body: []byte(`{}`)},
	}
}

// TestMaintenanceMode checks maintenance started from TT_MAINTENANCE, then
// toggled at run time through the shared flag: deposits get 503 maintenance
// with Retry-After, while the health check, getVersion and other operations
// stay available and /healthz reports the flag.
func TestMaintenanceMode(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		flag := new(atomic.Bool)
		s := startServer(t, e, serverOptions{maintenance: true, flag: flag})
		if !flag.Load() {
			t.Fatal("TT_MAINTENANCE=true did not set the maintenance flag")
		}

		for _, host := range []string{hostA, hostB} {
			for name, req := range depositRequests() {
				t.Run(host+"/"+name, func(t *testing.T) {
					req.host = host
					resp := s.do(t, req)
					expectSecurityHeaders(t, "503", resp.header)
					if resp.header.Get(hdrRetryAfter) != "300" {
						t.Errorf("Retry-After = %q, want 300", resp.header.Get(hdrRetryAfter))
					}
					if name == "appendUploadChunk" {
						// tus answers carry no body (api/openapi.yaml), only
						// the status and the tus headers.
						if resp.status != http.StatusServiceUnavailable || len(resp.body) != 0 {
							t.Errorf("tus PATCH: status %d, body %q; want a bodyless 503", resp.status, resp.body)
						}
						if got := resp.header.Get("Tus-Resumable"); got != "1.0.0" {
							t.Errorf("Tus-Resumable = %q, want 1.0.0", got)
						}
						return
					}
					p := expectProblem(t, resp, http.StatusServiceUnavailable, "maintenance")
					if p.RetryAfterSeconds == nil || *p.RetryAfterSeconds != 300 {
						t.Errorf("retryAfterSeconds = %v, want 300", p.RetryAfterSeconds)
					}
				})
			}
			if resp := s.get(t, host, "/api/v1/version"); resp.status != http.StatusOK {
				t.Errorf("getVersion in maintenance: %d, want 200", resp.status)
			}
			// Downloads and other reads are not refused (still stubs here).
			expectProblem(t, s.get(t, host, exampleDownload), http.StatusNotFound, "not-found")
		}

		var h healthBody
		resp := s.get(t, "", "/healthz")
		if resp.status != http.StatusOK {
			t.Fatalf("/healthz in maintenance: %d, want 200; body %s", resp.status, resp.body)
		}
		mustJSON(t, resp.body, &h)
		if !h.Maintenance {
			t.Errorf("/healthz maintenance = false while active: %s", resp.body)
		}

		// Leaving maintenance at run time.
		flag.Store(false)
		for name, req := range depositRequests() {
			req.host = hostA
			// The operation is reached again: a stub answers 404, an
			// implemented operation refuses the empty request (400, 401).
			if resp := s.do(t, req); resp.status == http.StatusServiceUnavailable {
				t.Errorf("%s after maintenance: %d, want the operation to be reached; body %s", name, resp.status, resp.body)
			}
		}
		mustJSON(t, s.get(t, "", "/healthz").body, &h)
		if h.Maintenance {
			t.Error("/healthz still reports maintenance after it ended")
		}

		// Entering maintenance at run time.
		flag.Store(true)
		req := depositRequests()["createTransfer"]
		req.host = hostB
		expectProblem(t, s.do(t, req), http.StatusServiceUnavailable, "maintenance")

		// An unknown host is still rejected as such, not with 503.
		req.host = "unknown.example.net"
		expectProblem(t, s.do(t, req), http.StatusMisdirectedRequest, "unknown-tenant")
	})
}
