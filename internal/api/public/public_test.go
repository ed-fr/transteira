package public

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/version"
)

func tenantCtx() context.Context {
	return tenant.WithTenant(context.Background(), &tenant.Tenant{ID: "ten_x", FQDN: "transfer.entity-a.example.com"})
}

func TestGetVersion(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		info       version.Info
		wantCommit string
	}{
		{"with commit", version.Info{Version: "1.2.3", Commit: "3f9c2ab"}, "3f9c2ab"},
		{"unknown commit", version.Info{Version: "1.2.3", Commit: "unknown"}, ""},
		{"empty commit", version.Info{Version: "1.2.3"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := NewServer()
			s.version = func() version.Info { return tt.info }
			resp, err := s.GetVersion(tenantCtx(), gen.GetVersionRequestObject{})
			if err != nil {
				t.Fatal(err)
			}
			got, ok := resp.(gen.GetVersion200JSONResponse)
			if !ok {
				t.Fatalf("response type %T", resp)
			}
			if got.Version != "1.2.3" || got.ApiVersion != gen.V1 {
				t.Errorf("got %+v", got)
			}
			switch {
			case tt.wantCommit == "" && got.Commit != nil:
				t.Errorf("commit = %q, want none", *got.Commit)
			case tt.wantCommit != "" && (got.Commit == nil || *got.Commit != tt.wantCommit):
				t.Errorf("commit = %v, want %q", got.Commit, tt.wantCommit)
			}
		})
	}
}

func TestGetVersionDefaultsToBuildInfo(t *testing.T) {
	t.Parallel()
	resp, err := NewServer().GetVersion(tenantCtx(), gen.GetVersionRequestObject{})
	if err != nil {
		t.Fatal(err)
	}
	if got := resp.(gen.GetVersion200JSONResponse).Version; got != version.Get().Version {
		t.Errorf("version %q, want %q", got, version.Get().Version)
	}
}

func TestGetVersionWithoutTenant(t *testing.T) {
	t.Parallel()
	_, err := NewServer().GetVersion(context.Background(), gen.GetVersionRequestObject{})
	var p *problem.Problem
	if !errors.As(err, &p) || p.Code != problem.CodeUnknownTenant {
		t.Fatalf("err = %v, want unknown-tenant", err)
	}
}

func TestSpecHandler(t *testing.T) {
	t.Parallel()
	spec := []byte("openapi: 3.1.0\n")
	h := SpecHandler(spec)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/openapi.yaml", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != string(spec) {
		t.Fatalf("GET = %d %q", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != SpecContentType {
		t.Errorf("Content-Type %q", ct)
	}
	etag := rec.Header().Get("ETag")
	if len(etag) != 34 || etag[0] != '"' {
		t.Errorf("ETag %q", etag)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-cache" {
		t.Errorf("Cache-Control %q", cc)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/openapi.yaml", nil)
	req.Header.Set("If-None-Match", etag)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotModified || rec.Body.Len() != 0 {
		t.Errorf("conditional GET = %d, body %d bytes", rec.Code, rec.Body.Len())
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodHead, "/api/openapi.yaml", nil))
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Errorf("HEAD = %d, body %d bytes", rec.Code, rec.Body.Len())
	}

	other := SpecHandler([]byte("openapi: 3.1.1\n"))
	rec2 := httptest.NewRecorder()
	other.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/api/openapi.yaml", nil))
	if rec2.Header().Get("ETag") == etag {
		t.Error("different documents share an ETag")
	}
}
