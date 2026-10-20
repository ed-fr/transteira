package health

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/httpserver/middleware"
)

func TestHandlerGolden(t *testing.T) {
	orig := versionString
	t.Cleanup(func() { versionString = orig })
	versionString = func() string { return "1.0.0" }

	tests := []struct {
		name        string
		svc         *Service
		maintenance func() bool
		wantCode    int
		wantBody    string
	}{
		{
			name:     "healthy",
			svc:      &Service{Database: Check{Checker: ok}, Antivirus: Check{Checker: ok}, Storage: Check{Checker: ok}},
			wantCode: http.StatusOK,
			wantBody: `{"status":"ok","version":"1.0.0","maintenance":false,"checks":{"database":"ok","antivirus":"ok","storage":"ok"}}`,
		},
		{
			name:        "degraded in maintenance",
			svc:         &Service{Database: Check{Checker: ok}, Antivirus: Check{Checker: bad}, Storage: Check{Checker: ok}},
			maintenance: func() bool { return true },
			wantCode:    http.StatusServiceUnavailable,
			wantBody:    `{"status":"degraded","version":"1.0.0","maintenance":true,"checks":{"database":"ok","antivirus":"unavailable","storage":"ok"}}`,
		},
		{
			name:        "maintenance off",
			svc:         &Service{Database: Check{Checker: bad}, Antivirus: Check{Checker: ok}, Storage: Check{Checker: bad}},
			maintenance: func() bool { return false },
			wantCode:    http.StatusServiceUnavailable,
			wantBody:    `{"status":"degraded","version":"1.0.0","maintenance":false,"checks":{"database":"unavailable","antivirus":"ok","storage":"unavailable"}}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logs bytes.Buffer
			tt.svc.Logger = slog.New(slog.NewTextHandler(&logs, nil))
			rec := httptest.NewRecorder()
			Handler(tt.svc, tt.maintenance).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

			if rec.Code != tt.wantCode {
				t.Errorf("code = %d, want %d", rec.Code, tt.wantCode)
			}
			if got := rec.Body.String(); got != tt.wantBody {
				t.Errorf("body =\n%s\nwant\n%s", got, tt.wantBody)
			}
			if strings.Contains(rec.Body.String(), "secret") {
				t.Error("error detail leaked into the response")
			}
			h := rec.Header()
			if h.Get("Content-Type") != "application/json" || h.Get("Cache-Control") != "no-store" ||
				h.Get("Content-Length") != strconv.Itoa(len(tt.wantBody)) {
				t.Errorf("headers = %v", h)
			}
		})
	}
}

func TestHandlerHead(t *testing.T) {
	svc := &Service{Database: Check{Checker: ok}, Antivirus: Check{Checker: ok}, Storage: Check{Checker: ok}}
	rec := httptest.NewRecorder()
	Handler(svc, nil).ServeHTTP(rec, httptest.NewRequest(http.MethodHead, "/healthz", nil))
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Fatalf("HEAD = %d, body %q", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Content-Type") != "application/json" || rec.Header().Get("Content-Length") == "" {
		t.Fatalf("headers = %v", rec.Header())
	}
}

func TestHandlerMethodNotAllowed(t *testing.T) {
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodOptions} {
		for _, id := range []string{"", "req-123"} {
			t.Run(m+"/"+id, func(t *testing.T) {
				rec := httptest.NewRecorder()
				if id != "" {
					rec.Header().Set(middleware.HeaderRequestID, id)
				}
				Handler(&Service{}, nil).ServeHTTP(rec, httptest.NewRequest(m, "/healthz", nil))
				if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "GET, HEAD" ||
					rec.Header().Get("Content-Type") != problem.ContentType ||
					rec.Header().Get("Cache-Control") != "no-store" {
					t.Fatalf("%s = %d %v", m, rec.Code, rec.Header())
				}
				var p problem.Problem
				if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
					t.Fatal(err)
				}
				if p.Status != http.StatusMethodNotAllowed || p.Type != problem.CodeMethodNotAllowed.TypeURI() || p.Instance != id {
					t.Fatalf("problem = %+v", p)
				}
			})
		}
	}
}

// TestHandlerOverHTTP exercises the handler through a real server, with the
// default version resolver.
func TestHandlerOverHTTP(t *testing.T) {
	srv := httptest.NewServer(Handler(&Service{Storage: Check{Checker: StorageCheck(t.TempDir())}}, nil))
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusServiceUnavailable ||
		!strings.Contains(string(body), `"storage":"ok"`) || !strings.Contains(string(body), `"version":"`) {
		t.Fatalf("GET = %d %s", resp.StatusCode, body)
	}
}
