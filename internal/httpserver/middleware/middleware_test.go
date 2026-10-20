package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/tenant"
)

func TestChainOrder(t *testing.T) {
	var order []string
	mw := func(name string) func(http.Handler) http.Handler {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				order = append(order, name+">")
				next.ServeHTTP(w, r)
				order = append(order, "<"+name)
			})
		}
	}
	h := Chain(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		order = append(order, "handler")
	}), mw("a"), mw("b"))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	if got, want := strings.Join(order, " "), "a> b> handler <b <a"; got != want {
		t.Fatalf("order = %q, want %q", got, want)
	}
	// No middleware: the handler itself.
	rec := httptest.NewRecorder()
	Chain(okHandler).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestAssignRequestID(t *testing.T) {
	var seen string
	h := AssignRequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = RequestID(r.Context())
		w.WriteHeader(http.StatusNoContent)
	}))
	ids := map[string]bool{}
	for range 3 {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set(HeaderRequestID, "req_attacker\r\nX-Evil: 1")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		got := rec.Header().Get(HeaderRequestID)
		if !id.Valid(id.Request, got) {
			t.Fatalf("invalid request id %q", got)
		}
		if seen != got {
			t.Fatalf("context id %q != header id %q", seen, got)
		}
		ids[got] = true
	}
	if len(ids) != 3 {
		t.Fatalf("request ids are not unique: %v", ids)
	}
	if RequestID(context.Background()) != "" {
		t.Fatal("RequestID of empty context should be empty")
	}
}

func TestRequestIDOf(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	if got := requestIDOf(rec, r); got != "" {
		t.Fatalf("got %q, want empty", got)
	}
	rec.Header().Set(HeaderRequestID, "req_header")
	if got := requestIDOf(rec, r); got != "req_header" {
		t.Fatalf("got %q, want header value", got)
	}
	if got := requestIDOf(rec, withRID(r, "req_ctx")); got != "req_ctx" {
		t.Fatalf("got %q, want context value", got)
	}
}

func TestTenantFQDN(t *testing.T) {
	if got := tenantFQDN(context.Background()); got != "" {
		t.Fatalf("got %q", got)
	}
	ctx := tenant.WithTenant(context.Background(), &tenant.Tenant{FQDN: "transfer.example.com"})
	if got := tenantFQDN(ctx); got != "transfer.example.com" {
		t.Fatalf("got %q", got)
	}
}
