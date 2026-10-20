package integration_test

import (
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/store/storetest"
)

// TestHealthz checks /healthz (CLAUDE.md section 19): 200 ok with every
// component available, 503 degraded when ClamAV is unreachable, HEAD
// support, 405 with Allow on other methods, never cached, security headers,
// no secret in the body.
func TestHealthz(t *testing.T) {
	t.Parallel()
	t.Run("healthy", func(t *testing.T) {
		forEngine(t, func(t *testing.T, e storetest.Engine) {
			s := startServer(t, e, serverOptions{})
			resp := s.get(t, hostA, "/healthz")
			if resp.status != http.StatusOK {
				t.Fatalf("status = %d, want 200; body %s", resp.status, resp.body)
			}
			var h healthBody
			mustJSON(t, resp.body, &h)
			want := map[string]string{"database": "ok", "antivirus": "ok", "storage": "ok"}
			if h.Status != "ok" || h.Maintenance || !equalMaps(h.Checks, want) {
				t.Errorf("health = %+v", h)
			}
			if resp.header.Get("Cache-Control") != "no-store" {
				t.Errorf("Cache-Control = %q, want no-store", resp.header.Get("Cache-Control"))
			}
			expectSecurityHeaders(t, "healthz", resp.header)

			head := s.do(t, request{method: http.MethodHead, path: "/healthz"})
			if head.status != http.StatusOK || len(head.body) != 0 {
				t.Errorf("HEAD: status %d with %d body bytes, want 200 and none", head.status, len(head.body))
			}
			for _, m := range []string{http.MethodPost, http.MethodDelete, http.MethodPatch, http.MethodOptions} {
				r := s.do(t, request{method: m, path: "/healthz"})
				expectProblem(t, r, http.StatusMethodNotAllowed, "method-not-allowed")
				if r.header.Get("Allow") != "GET, HEAD" {
					t.Errorf("%s: Allow = %q, want \"GET, HEAD\"", m, r.header.Get("Allow"))
				}
				expectSecurityHeaders(t, m+" healthz", r.header)
			}
		})
	})

	t.Run("ClamAV unreachable", func(t *testing.T) {
		forEngine(t, func(t *testing.T, e storetest.Engine) {
			addr := closedPort(t)
			s := startServer(t, e, serverOptions{clamd: addr})
			resp := s.get(t, "", "/healthz")
			if resp.status != http.StatusServiceUnavailable {
				t.Fatalf("status = %d, want 503; body %s", resp.status, resp.body)
			}
			var h healthBody
			mustJSON(t, resp.body, &h)
			want := map[string]string{"database": "ok", "antivirus": "unavailable", "storage": "ok"}
			if h.Status != "degraded" || !equalMaps(h.Checks, want) {
				t.Errorf("health = %+v, want degraded with antivirus unavailable", h)
			}
			if strings.Contains(string(resp.body), addr) || strings.Contains(string(resp.body), "refused") {
				t.Errorf("health body leaks error details: %s", resp.body)
			}
			expectSecurityHeaders(t, "healthz 503", resp.header)
			head := s.do(t, request{method: http.MethodHead, path: "/healthz"})
			if head.status != http.StatusServiceUnavailable || len(head.body) != 0 {
				t.Errorf("HEAD: status %d with %d body bytes, want 503 and none", head.status, len(head.body))
			}
		})
	})
}

func equalMaps(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// buildBinary builds cmd/transteira into dir. The healthcheck command lives
// in package main and cannot be called directly; the build cache makes this
// cheap after the first time.
func buildBinary(t *testing.T, dir string) string {
	t.Helper()
	name := "transteira"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	bin := filepath.Join(dir, name)
	cmd := exec.CommandContext(t.Context(), "go", "build", "-o", bin, "github.com/ed-fr/transteira/cmd/transteira")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build ./cmd/transteira: %v\n%s", err, out)
	}
	return bin
}

// TestHealthcheckCommand runs "transteira healthcheck" against the running
// server: exit 0 when healthy, 1 when degraded or unreachable, 2 on a bad
// URL; it also derives the URL from TT_LISTEN_ADDR.
func TestHealthcheckCommand(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the transteira binary")
	}
	t.Parallel()
	bin := buildBinary(t, t.TempDir())

	run := func(t *testing.T, env []string, args ...string) (int, string) {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), bin, append([]string{"healthcheck"}, args...)...)
		cmd.Env = append(os.Environ(), env...)
		out, err := cmd.CombinedOutput()
		var exitErr *exec.ExitError
		switch {
		case err == nil:
			return 0, string(out)
		case errors.As(err, &exitErr):
			return exitErr.ExitCode(), string(out)
		default:
			t.Fatalf("run healthcheck: %v", err)
			return -1, ""
		}
	}

	e := storetest.SQLite(t)
	healthy := startServer(t, e, serverOptions{})
	if code, out := run(t, nil, "-url", healthy.url("/healthz")); code != 0 {
		t.Errorf("healthy server: exit %d, want 0; output %s", code, out)
	}
	if code, out := run(t, []string{"TT_LISTEN_ADDR=" + healthy.addr}); code != 0 {
		t.Errorf("URL from TT_LISTEN_ADDR: exit %d, want 0; output %s", code, out)
	}

	degraded := startServer(t, storetest.SQLite(t), serverOptions{clamd: closedPort(t)})
	if code, out := run(t, nil, "-url", degraded.url("/healthz")); code != 1 {
		t.Errorf("degraded server: exit %d, want 1; output %s", code, out)
	}
	if code, _ := run(t, nil, "-url", "http://"+closedPort(t)+"/healthz"); code != 1 {
		t.Errorf("no server: exit %d, want 1", code)
	}
	if code, _ := run(t, nil, "-url", "ftp://127.0.0.1/healthz"); code != 2 {
		t.Errorf("invalid URL: exit %d, want 2", code)
	}
}
