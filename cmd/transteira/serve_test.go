package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/app"
	"github.com/ed-fr/transteira/internal/config"
)

// stubRunApp replaces runApp for the duration of the test.
func stubRunApp(t *testing.T, fn func(ctx context.Context, cfg *config.Config, opts ...app.Option) error) {
	t.Helper()
	orig := runApp
	runApp = fn
	t.Cleanup(func() { runApp = orig })
}

func TestServeCommand(t *testing.T) {
	setMigrateEnv(t)
	var got *config.Config
	stubRunApp(t, func(ctx context.Context, cfg *config.Config, _ ...app.Option) error {
		if ctx.Err() != nil {
			t.Error("context already canceled")
		}
		got = cfg
		return nil
	})
	if code, _, errOut := runCmd("serve"); code != exitOK {
		t.Fatalf("serve = %d, %q", code, errOut)
	}
	if got == nil || got.DBDriver != config.DriverSQLite {
		t.Errorf("runApp received %+v", got)
	}

	stubRunApp(t, func(context.Context, *config.Config, ...app.Option) error { return errors.New("port in use") })
	if code, _, errOut := runCmd("serve"); code != exitError || !strings.Contains(errOut, "serve: port in use") {
		t.Errorf("serve (failing) = %d, %q", code, errOut)
	}
}

func TestServeCommandUsageAndConfig(t *testing.T) {
	setMigrateEnv(t)
	stubRunApp(t, func(context.Context, *config.Config, ...app.Option) error {
		t.Error("runApp must not be called")
		return nil
	})
	if code, out, _ := runCmd("serve", "-h"); code != exitOK || out != "" {
		t.Errorf("serve -h = %d", code)
	}
	if code, _, _ := runCmd("serve", "extra"); code != exitUsage {
		t.Errorf("serve extra = %d", code)
	}
	t.Setenv("TT_DB_DRIVER", "oracle")
	if code, _, errOut := runCmd("serve"); code != exitError || !strings.Contains(errOut, "TT_DB_DRIVER") {
		t.Errorf("serve (bad config) = %d, %q", code, errOut)
	}
}

func TestHealthcheckCommand(t *testing.T) {
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(status)
	}))
	defer srv.Close()
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))

	if code, _, errOut := runCmd("healthcheck", "--url", srv.URL+"/healthz"); code != exitOK {
		t.Errorf("healthy = %d, %q", code, errOut)
	}
	t.Setenv(config.EnvListenAddr, ":"+port)
	if code, _, errOut := runCmd("healthcheck"); code != exitOK {
		t.Errorf("healthy via TT_LISTEN_ADDR = %d, %q", code, errOut)
	}
	status = http.StatusServiceUnavailable
	if code, _, errOut := runCmd("healthcheck"); code != exitError || !strings.Contains(errOut, "503") {
		t.Errorf("unhealthy = %d, %q", code, errOut)
	}

	tests := []struct {
		name string
		args []string
		env  string
		want int
	}{
		{"bad listen addr", nil, "no-port", exitUsage},
		{"bad url scheme", []string{"--url", "ftp://127.0.0.1/healthz"}, "", exitUsage},
		{"url without host", []string{"--url", "http:///healthz"}, "", exitUsage},
		{"unparsable url", []string{"--url", "http://[::1"}, "", exitUsage},
		{"unreachable", []string{"--url", "http://127.0.0.1:1/healthz"}, "", exitError},
		{"extra arg", []string{"extra"}, "", exitUsage},
		{"help", []string{"-h"}, "", exitOK},
	}
	for _, tt := range tests {
		t.Setenv(config.EnvListenAddr, tt.env)
		if code, _, errOut := runCmd(append([]string{"healthcheck"}, tt.args...)...); code != tt.want {
			t.Errorf("%s: code %d, want %d (%q)", tt.name, code, tt.want, errOut)
		}
	}
}

func TestDefaultHealthURL(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in, want string
		ok       bool
	}{
		{"", "http://127.0.0.1:8080/healthz", true},
		{"  :9000 ", "http://127.0.0.1:9000/healthz", true},
		{"0.0.0.0:8081", "http://127.0.0.1:8081/healthz", true},
		{"[::]:8082", "http://127.0.0.1:8082/healthz", true},
		{"[::1]:8083", "http://[::1]:8083/healthz", true},
		{"10.0.0.5:8084", "http://10.0.0.5:8084/healthz", true},
		{"8080", "", false},
		{"host:", "", false},
	}
	for _, tt := range tests {
		got, err := defaultHealthURL(tt.in)
		if (err == nil) != tt.ok || got != tt.want {
			t.Errorf("defaultHealthURL(%q) = %q, %v", tt.in, got, err)
		}
	}
}
