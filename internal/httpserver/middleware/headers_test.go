package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSecurityHeaders(t *testing.T) {
	common := map[string]string{
		"X-Content-Type-Options":       "nosniff",
		"Referrer-Policy":              "no-referrer",
		"X-Frame-Options":              "DENY",
		"Permissions-Policy":           DefaultPermissionsPolicy,
		"Cross-Origin-Opener-Policy":   "same-origin",
		"Cross-Origin-Resource-Policy": "same-origin",
	}
	tests := []struct {
		name        string
		opts        []SecurityOption
		path        string
		wantCSP     string
		wantNoStore bool
	}{
		{"api path", nil, "/api/v1/transfers", DefaultCSP, true},
		{"api root", nil, "/api", DefaultCSP, true},
		{"not api", nil, "/healthz", DefaultCSP, false},
		{"api lookalike", nil, "/apix", DefaultCSP, false},
		{"custom csp", []SecurityOption{WithCSP("default-src 'self'")}, "/", "default-src 'self'", false},
		{"empty csp ignored", []SecurityOption{WithCSP("")}, "/", DefaultCSP, false},
		{"custom prefix with slash", []SecurityOption{WithNoStorePrefix("/admin/")}, "/admin/x", DefaultCSP, true},
		{"custom prefix replaces api", []SecurityOption{WithNoStorePrefix("/admin")}, "/api/v1", DefaultCSP, false},
		{"no-store disabled", []SecurityOption{WithNoStorePrefix("")}, "/api/v1", DefaultCSP, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			SecurityHeaders(tc.opts...)(okHandler).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.path, nil))
			h := rec.Header()
			if got := h.Get("Content-Security-Policy"); got != tc.wantCSP {
				t.Errorf("CSP = %q, want %q", got, tc.wantCSP)
			}
			for k, v := range common {
				if got := h.Get(k); got != v {
					t.Errorf("%s = %q, want %q", k, got, v)
				}
			}
			if got := h.Get("Cache-Control") == "no-store"; got != tc.wantNoStore {
				t.Errorf("no-store = %v, want %v", got, tc.wantNoStore)
			}
		})
	}
}

func TestSecurityHeadersOnError(t *testing.T) {
	rec := httptest.NewRecorder()
	h := Chain(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusTeapot)
	}), SecurityHeaders())
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec.Header().Get("Content-Security-Policy") != DefaultCSP || rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatalf("security headers missing on error response: %v", rec.Header())
	}
}
