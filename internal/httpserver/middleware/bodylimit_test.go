package middleware

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/api/problem"
)

// readingHandler reads the whole body and answers 413 on a body limit
// error, as real handlers must.
var readingHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	if _, err := io.ReadAll(r.Body); err != nil {
		if IsBodyTooLarge(err) {
			problem.Write(w, problem.New(problem.CodePayloadTooLarge))
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
})

func TestBodyLimit(t *testing.T) {
	isPatch := func(r *http.Request) bool { return r.Method == http.MethodPatch }
	tests := []struct {
		name       string
		exempt     func(*http.Request) bool
		method     string
		body       string
		unknownLen bool
		wantStatus int
	}{
		{"under limit", nil, http.MethodPost, "12345", false, http.StatusNoContent},
		{"at limit", nil, http.MethodPost, "1234567890", false, http.StatusNoContent},
		{"content-length over limit", nil, http.MethodPost, "12345678901", false, http.StatusRequestEntityTooLarge},
		{"streamed over limit", nil, http.MethodPost, "12345678901", true, http.StatusRequestEntityTooLarge},
		{"exempt over limit", isPatch, http.MethodPatch, strings.Repeat("x", 100), false, http.StatusNoContent},
		{"not exempt", isPatch, http.MethodPost, strings.Repeat("x", 100), false, http.StatusRequestEntityTooLarge},
		{"empty body", nil, http.MethodGet, "", false, http.StatusNoContent},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/api/v1/x", strings.NewReader(tc.body))
			req = withRID(req, "req_b")
			if tc.unknownLen {
				req.ContentLength = -1
			}
			orig := req.Body
			rec := httptest.NewRecorder()
			BodyLimit(10, tc.exempt)(readingHandler).ServeHTTP(rec, req)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			if req.Body != orig {
				t.Fatal("caller's request was mutated")
			}
			if rec.Code == http.StatusRequestEntityTooLarge {
				if p := decodeProblem(t, rec); p.Code != problem.CodePayloadTooLarge {
					t.Fatalf("problem = %+v", p)
				}
			}
		})
	}
}

func TestBodyLimitUpfrontInstance(t *testing.T) {
	req := withRID(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("too long")), "req_up")
	rec := httptest.NewRecorder()
	called := false
	BodyLimit(1, nil)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })).ServeHTTP(rec, req)
	if called {
		t.Fatal("handler called despite oversized Content-Length")
	}
	if p := decodeProblem(t, rec); p.Instance != "req_up" {
		t.Fatalf("problem = %+v", p)
	}
}

func TestBodyLimitNegativePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected a panic")
		}
	}()
	BodyLimit(-1, nil)
}

func TestIsBodyTooLarge(t *testing.T) {
	mbe := &http.MaxBytesError{Limit: 1}
	tests := []struct {
		err  error
		want bool
	}{
		{nil, false},
		{errors.New("other"), false},
		{mbe, true},
		{fmt.Errorf("decode: %w", mbe), true},
	}
	for _, tc := range tests {
		if got := IsBodyTooLarge(tc.err); got != tc.want {
			t.Errorf("IsBodyTooLarge(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}

func TestBodyLimitFunc(t *testing.T) {
	limit := func(r *http.Request) int64 {
		switch r.URL.Path {
		case "/tus":
			return NoBodyLimit
		case "/image":
			return 20
		default:
			return 5
		}
	}
	tests := []struct {
		path       string
		size       int
		unknownLen bool
		wantStatus int
	}{
		{"/json", 5, false, http.StatusNoContent},
		{"/json", 6, false, http.StatusRequestEntityTooLarge},
		{"/image", 20, false, http.StatusNoContent},
		{"/image", 21, false, http.StatusRequestEntityTooLarge},
		{"/image", 21, true, http.StatusRequestEntityTooLarge},
		{"/tus", 1000, true, http.StatusNoContent},
	}
	h := BodyLimitFunc(limit)(readingHandler)
	for _, tc := range tests {
		req := httptest.NewRequest(http.MethodPut, tc.path, strings.NewReader(strings.Repeat("x", tc.size)))
		if tc.unknownLen {
			req.ContentLength = -1
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != tc.wantStatus {
			t.Errorf("%s (%d bytes, unknown length %v): status = %d, want %d", tc.path, tc.size, tc.unknownLen, rec.Code, tc.wantStatus)
		}
	}
	if ImageBodyLimit != 10<<20 || NoBodyLimit >= 0 {
		t.Fatalf("ImageBodyLimit = %d, NoBodyLimit = %d", ImageBodyLimit, NoBodyLimit)
	}
}

func TestBodyLimitFuncNilPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected a panic")
		}
	}()
	BodyLimitFunc(nil)
}
