package httpserver

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/ed-fr/transteira/internal/api/public"
	"github.com/ed-fr/transteira/internal/download"
)

// fakeCounter implements RequestCounter and StreamCounter.
type fakeCounter struct {
	mu      sync.Mutex
	status  []int
	opened  int
	closed  int
	inFlite int
}

func (c *fakeCounter) HTTPRequest(status int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.status = append(c.status, status)
}

func (c *fakeCounter) StreamOpened() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.opened++
	c.inFlite++
}

func (c *fakeCounter) StreamClosed() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed++
	c.inFlite--
}

func (c *fakeCounter) statuses() []int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]int(nil), c.status...)
}

// TestRequestsCountedThroughTheChain: every response is counted by status,
// the refusals of the inner layers (404, 421) included.
func TestRequestsCountedThroughTheChain(t *testing.T) {
	t.Parallel()
	c := &fakeCounter{}
	e := newEnv(t, envConfig{requests: c})
	e.do(t, http.MethodGet, "/healthz", hostA, nil)
	e.do(t, http.MethodGet, "/api/v1/nope", hostA, nil)
	e.do(t, http.MethodGet, "/api/v1/nope", "unknown.example.net", nil)
	got := c.statuses()
	want := []int{http.StatusOK, http.StatusNotFound, http.StatusMisdirectedRequest}
	if len(got) != len(want) {
		t.Fatalf("counted %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("counted %v, want %v", got, want)
		}
	}
}

func TestRequestCountMiddleware(t *testing.T) {
	t.Parallel()
	run := func(h http.HandlerFunc) (c *fakeCounter, panicked any) {
		c = &fakeCounter{}
		func() {
			defer func() { panicked = recover() }()
			requestCountMiddleware(c)(h).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
		}()
		return c, panicked
	}
	cases := map[string]struct {
		h    http.HandlerFunc
		want int
	}{
		"explicit":   {func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) }, http.StatusTeapot},
		"implicit":   {func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("x")) }, http.StatusOK},
		"silent":     {func(http.ResponseWriter, *http.Request) {}, http.StatusOK},
		"flush only": {func(w http.ResponseWriter, _ *http.Request) { _ = http.NewResponseController(w).Flush() }, http.StatusOK},
		"1xx first": {func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusEarlyHints)
			w.WriteHeader(http.StatusNoContent)
			w.WriteHeader(http.StatusTeapot)
		}, http.StatusNoContent},
		"flusher": {func(w http.ResponseWriter, _ *http.Request) { w.(http.Flusher).Flush() }, http.StatusOK},
	}
	for name, tc := range cases {
		c, p := run(tc.h)
		if got := c.statuses(); p != nil || len(got) != 1 || got[0] != tc.want {
			t.Errorf("%s: counted %v (panic %v), want [%d]", name, got, p, tc.want)
		}
	}
	c, p := run(func(http.ResponseWriter, *http.Request) { panic(http.ErrAbortHandler) })
	if got := c.statuses(); p == nil || len(got) != 1 || got[0] != http.StatusInternalServerError {
		t.Errorf("panic: counted %v (panic %v)", got, p)
	}
	// A nil counter is a pass-through.
	h := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	if requestCountMiddleware(nil)(h) == nil {
		t.Error("nil counter returned no handler")
	}
}

func TestStatusWriterUnwrap(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	if (&statusWriter{ResponseWriter: rec}).Unwrap() != rec {
		t.Error("Unwrap did not return the wrapped writer")
	}
}

// TestDownloadStreamGauge: a served download opens and closes a stream; a
// refused one (locked grant) and a HEAD do not.
func TestDownloadStreamGauge(t *testing.T) {
	t.Parallel()
	c := &fakeCounter{}
	e := newEnv(t, envConfig{api: public.NewServer(public.WithDownloads(fakeDownloads{})), streams: c})
	const file = "/api/v1/downloads/dl_Xk4Lm9Qp2Zr7Vb1Nt6Yc3Hd8Jf/files/fil_01JABCD9F1A2B3C4D5E6F7G8H9"
	if rec := e.do(t, http.MethodGet, file, hostA, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("locked: %d", rec.Code)
	}
	if c.opened != 0 {
		t.Fatalf("a refused download opened a stream")
	}
	e.do(t, http.MethodGet, file, hostA, nil, "Cookie", download.GrantCookieName+"=dg_ok", "Range", "bytes=2-4")
	e.do(t, http.MethodHead, file, hostA, nil, "Cookie", download.GrantCookieName+"=dg_ok")
	e.do(t, http.MethodGet, "/healthz", hostA, nil)
	if c.opened != 1 || c.closed != 1 || c.inFlite != 0 {
		t.Errorf("opened %d closed %d in flight %d, want 1 1 0", c.opened, c.closed, c.inFlite)
	}
}

// TestStreamGaugeClosedOnPanic: the stream is closed even when the handler
// aborts.
func TestStreamGaugeClosedOnPanic(t *testing.T) {
	t.Parallel()
	c := &fakeCounter{}
	h := streamGaugeMiddleware(c)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		panic(http.ErrAbortHandler)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Pattern = http.MethodGet + " " + APIBaseURL + "/downloads/{linkToken}/archive"
	func() {
		defer func() { _ = recover() }()
		h.ServeHTTP(httptest.NewRecorder(), req)
	}()
	if c.opened != 1 || c.closed != 1 {
		t.Errorf("opened %d closed %d", c.opened, c.closed)
	}
	if streamGaugeMiddleware(nil)(h) == nil {
		t.Error("nil counter returned no handler")
	}
}
