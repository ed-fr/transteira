package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/api/problem"
)

func TestRequireJSON(t *testing.T) {
	isTus := func(r *http.Request) bool { return strings.HasPrefix(r.URL.Path, "/tus/") }
	const ok, bad = http.StatusNoContent, http.StatusUnsupportedMediaType
	tests := []struct {
		name   string
		method string
		path   string
		ct     string // "-" means no header
		length int64  // -1 means unknown (chunked)
		want   int
	}{
		{"json", http.MethodPost, "/api", "application/json", 2, ok},
		{"json charset", http.MethodPost, "/api", "application/json; charset=utf-8", 2, ok},
		{"upper case", http.MethodPut, "/api", "APPLICATION/JSON", 2, ok},
		{"merge patch", http.MethodPatch, "/api", "application/merge-patch+json", 2, ok},
		{"mixed case merge patch", http.MethodPatch, "/api", "Application/Merge-Patch+JSON;charset=UTF-8", 2, ok},
		{"chunked json", http.MethodPost, "/api", "application/json", -1, ok},
		{"trailing semicolon", http.MethodPost, "/api", "application/json;", 2, ok},
		{"jsonx", http.MethodPost, "/api", "application/jsonx", 2, bad},
		{"text plain", http.MethodPost, "/api", "text/plain", 2, bad},
		{"form", http.MethodPost, "/api", "application/x-www-form-urlencoded", 2, bad},
		{"multipart", http.MethodPost, "/api", "multipart/form-data; boundary=x", 2, bad},
		{"missing", http.MethodPost, "/api", "-", 2, bad},
		{"empty", http.MethodPost, "/api", "", 2, bad},
		{"garbage", http.MethodPost, "/api", "application/json; =", 2, bad},
		{"json in param", http.MethodPost, "/api", "text/plain; x=application/json", 2, bad},
		{"chunked missing", http.MethodPatch, "/api", "-", -1, bad},
		{"no body", http.MethodPost, "/api", "-", 0, ok},
		{"get with body", http.MethodGet, "/api", "text/plain", 2, ok},
		{"delete with body", http.MethodDelete, "/api", "text/plain", 2, ok},
		{"exempt", http.MethodPatch, "/tus/x", "application/offset+octet-stream", 2, ok},
		{"exempt func not matching", http.MethodPatch, "/api", "application/offset+octet-stream", 2, bad},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := withRID(httptest.NewRequest(tc.method, tc.path, strings.NewReader("{}")), "req_j")
			req.ContentLength = tc.length
			if tc.ct != "-" {
				req.Header.Set("Content-Type", tc.ct)
			}
			rec := httptest.NewRecorder()
			RequireJSON(isTus)(okHandler).ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d", rec.Code, tc.want)
			}
			if rec.Code == bad {
				if p := decodeProblem(t, rec); p.Code != problem.CodeUnsupportedMediaType || p.Instance != "req_j" {
					t.Fatalf("problem = %+v", p)
				}
			}
		})
	}
}

func TestRequireJSONNilExempt(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("x"))
	req.Header.Set("Content-Type", "text/plain")
	rec := httptest.NewRecorder()
	RequireJSON(nil)(okHandler).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d", rec.Code)
	}
}
