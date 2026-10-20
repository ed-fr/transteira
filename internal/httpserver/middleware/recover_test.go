package middleware

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/api/problem"
)

// recoverChain wraps h like production: Recover, request ID, headers.
func recoverChain(logger *slog.Logger, h http.Handler) http.Handler {
	return Chain(h, Recover(logger), AssignRequestID, SecurityHeaders())
}

func TestRecoverNoPanic(t *testing.T) {
	rec := httptest.NewRecorder()
	recoverChain(nil, okHandler).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestRecoverPanicBeforeWrite(t *testing.T) {
	tests := []struct {
		name  string
		value any
		pre   func(w http.ResponseWriter)
	}{
		{"string", "boom", nil},
		{"error", errors.New("boom"), nil},
		{"nil", nil, nil},
		{"after early hints", "boom", func(w http.ResponseWriter) { w.WriteHeader(http.StatusEarlyHints) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logs, nil))
			h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Disposition", "attachment; filename=x")
				w.Header().Set("ETag", `"x"`)
				if tc.pre != nil {
					tc.pre(w)
				}
				panic(tc.value)
			})
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/api/v1/downloads/secret-token?q=1", nil)
			// Like net/http, send 1xx statuses without freezing the final one.
			recoverChain(logger, h).ServeHTTP(informationalWriter{rec}, req)
			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d", rec.Code)
			}
			p := decodeProblem(t, rec)
			rid := rec.Header().Get(HeaderRequestID)
			if p.Code != problem.CodeInternalError || p.Instance != rid || rid == "" {
				t.Fatalf("problem = %+v, request id %q", p, rid)
			}
			for _, k := range []string{"Content-Disposition", "ETag"} {
				if rec.Header().Get(k) != "" {
					t.Errorf("header %s kept on panic response", k)
				}
			}
			for _, k := range preservedOnPanic {
				if rec.Header().Get(k) == "" {
					t.Errorf("header %s missing on panic response", k)
				}
			}
			out := logs.String()
			if !strings.Contains(out, rid) || !strings.Contains(out, "panic serving request") {
				t.Fatalf("log misses request id or message: %s", out)
			}
			if strings.Contains(out, "secret-token") {
				t.Fatalf("log leaks the path: %s", out)
			}
		})
	}
}

// servePanics serves h and returns the value it panics with, if any.
func servePanics(h http.Handler, w http.ResponseWriter) (v any) {
	defer func() { v = recover() }()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	return nil
}

func TestRecoverPanicAfterWrite(t *testing.T) {
	tests := []struct {
		name  string
		start func(w http.ResponseWriter)
	}{
		{"write", func(w http.ResponseWriter) { _, _ = w.Write([]byte("partial")) }},
		{"write header", func(w http.ResponseWriter) { w.WriteHeader(http.StatusOK) }},
		{"switching protocols", func(w http.ResponseWriter) { w.WriteHeader(http.StatusSwitchingProtocols) }},
		{"flush", func(w http.ResponseWriter) { w.(http.Flusher).Flush() }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := recoverChain(nil, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				tc.start(w)
				panic("late")
			}))
			v := servePanics(h, httptest.NewRecorder())
			if v != http.ErrAbortHandler { //nolint:errorlint // the exact sentinel is expected
				t.Fatalf("panic value = %v, want http.ErrAbortHandler", v)
			}
		})
	}
}

func TestRecoverAbortHandlerPropagated(t *testing.T) {
	wrapped := fmt.Errorf("wrapped: %w", http.ErrAbortHandler)
	for _, v := range []any{http.ErrAbortHandler, wrapped} {
		var logs bytes.Buffer
		h := recoverChain(slog.New(slog.NewTextHandler(&logs, nil)), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			panic(v)
		}))
		rec := httptest.NewRecorder()
		if got := servePanics(h, rec); got != v {
			t.Fatalf("panic value = %v, want %v", got, v)
		}
		if logs.Len() != 0 {
			t.Fatalf("abort panic was logged: %s", logs.String())
		}
	}
}

// informationalWriter drops 1xx statuses, which httptest.ResponseRecorder
// would otherwise record as the final status.
type informationalWriter struct{ *httptest.ResponseRecorder }

func (w informationalWriter) WriteHeader(code int) {
	if code >= http.StatusOK {
		w.ResponseRecorder.WriteHeader(code)
	}
}

// plainWriter is a ResponseWriter without Flush.
type plainWriter struct{ http.ResponseWriter }

func TestTrackingWriter(t *testing.T) {
	rec := httptest.NewRecorder()
	tw := &trackingWriter{ResponseWriter: plainWriter{rec}}
	if tw.Unwrap() != (plainWriter{rec}) {
		t.Fatal("Unwrap did not return the underlying writer")
	}
	tw.Flush() // not supported underneath: no panic
	if !tw.started {
		t.Fatal("Flush should mark the response as started")
	}
	tw2 := &trackingWriter{ResponseWriter: rec}
	tw2.WriteHeader(http.StatusContinue)
	if tw2.started {
		t.Fatal("1xx should not start the response")
	}
	if err := http.NewResponseController(tw2).Flush(); err != nil {
		t.Fatalf("Flush through ResponseController: %v", err)
	}
	if !rec.Flushed {
		t.Fatal("underlying writer not flushed")
	}
}

// unwrapWriter is a third-party style wrapper exposing Unwrap.
type unwrapWriter struct{ http.ResponseWriter }

func (w unwrapWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func TestResponseStarted(t *testing.T) {
	if ResponseStarted(nil) {
		t.Fatal("nil writer reported as started")
	}
	rec := httptest.NewRecorder()
	rec.WriteHeader(http.StatusOK)
	if ResponseStarted(rec) {
		t.Fatal("writer without a tracking writer reported as started")
	}
	if ResponseStarted(unwrapWriter{nil}) {
		t.Fatal("wrapper unwrapping to nil reported as started")
	}

	tw := &trackingWriter{ResponseWriter: informationalWriter{httptest.NewRecorder()}}
	wrapped := unwrapWriter{unwrapWriter{tw}}
	if ResponseStarted(wrapped) {
		t.Fatal("fresh response reported as started")
	}
	tw.WriteHeader(http.StatusContinue)
	if ResponseStarted(wrapped) {
		t.Fatal("1xx reported as started")
	}
	if _, err := wrapped.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if !ResponseStarted(wrapped) || !ResponseStarted(tw) {
		t.Fatal("written response not reported as started")
	}
}

func TestResponseStartedUnderRecover(t *testing.T) {
	var before, after bool
	h := Chain(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		before = ResponseStarted(w)
		w.WriteHeader(http.StatusAccepted)
		after = ResponseStarted(w)
	}), Recover(nil), AssignRequestID, SecurityHeaders())
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	if before || !after {
		t.Fatalf("before = %v, after = %v; want false, true", before, after)
	}
}
