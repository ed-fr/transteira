package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRetryAfterHonored(t *testing.T) {
	now := time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC)
	var n atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		switch n.Add(1) {
		case 1:
			w.Header().Set("Retry-After", "7")
			w.WriteHeader(http.StatusServiceUnavailable)
		case 2:
			w.Header().Set("Retry-After", now.Add(90*time.Second).Format(http.TimeFormat))
			w.WriteHeader(http.StatusTooManyRequests)
		case 3:
			w.Header().Set("Retry-After", "3600")
			w.WriteHeader(http.StatusServiceUnavailable)
		case 4:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()
	var retries []string
	c, rec := newTestClient(t, srv, "", WithClock(func() time.Time { return now }))
	_, err := get(t, c, "/x", Policy{MaxRetryAfter: 2 * time.Minute, OnRetry: func(a int, _ error, d time.Duration) {
		retries = append(retries, fmt.Sprint(a, d))
	}})
	if err != nil {
		t.Fatal(err)
	}
	want := []time.Duration{7 * time.Second, 90 * time.Second, 2 * time.Minute, 8 * time.Second}
	if got := rec.all(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("sleeps %v, want %v", got, want)
	}
	if strings.Join(retries, ",") != "1 7s,2 1m30s,3 2m0s,4 8s" {
		t.Fatalf("OnRetry %v", retries)
	}
}

func TestStopOnPermanentStatus(t *testing.T) {
	for _, status := range []int{401, 403, 404, 409, 410, 413, 501, 507} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			var n atomic.Int32
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				n.Add(1)
				w.Header().Set("Content-Type", "application/problem+json")
				w.Header().Set("X-Request-Id", "req-42")
				w.Header().Set("WWW-Authenticate", "Bearer")
				w.WriteHeader(status)
				_, _ = io.WriteString(w, `{"type":"about:blank","title":"Nope","status":`+fmt.Sprint(status)+`,"code":"invalid-credentials"}`)
			}))
			defer srv.Close()
			c, rec := newTestClient(t, srv, testToken('x'))
			_, err := get(t, c, "/api/v1/transfers", Policy{})
			var p *Problem
			if !errors.As(err, &p) || p.Status != status || p.Code != "invalid-credentials" || p.RequestID != "req-42" {
				t.Fatalf("got %v", err)
			}
			if n.Load() != 1 || len(rec.all()) != 0 || IsRetryable(err) {
				t.Fatalf("%d attempts for %d", n.Load(), status)
			}
			if p.Method != http.MethodGet || p.Path != "/api/v1/transfers" {
				t.Fatalf("request %s %s", p.Method, p.Path)
			}
		})
	}
}

func TestRetryExhaustedAndConnectionErrors(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()
	c, rec := newTestClient(t, srv, "")
	_, err := get(t, c, "/x", Policy{})
	var p *Problem
	if !errors.As(err, &p) || p.Status != http.StatusBadGateway || n.Load() != DefaultMaxAttempts {
		t.Fatalf("got %v after %d", err, n.Load())
	}
	sleeps := rec.all()
	if len(sleeps) != DefaultMaxAttempts-1 || sleeps[0] != time.Second || sleeps[len(sleeps)-1] != DefaultMaxDelay {
		t.Fatalf("sleeps %v", sleeps)
	}

	// Connection refused: a temporary RequestError, retried MaxAttempts times.
	url := srv.URL
	srv.Close()
	var logBuf bytes.Buffer
	c, err = New(Config{URL: url}, WithRootCAs(x509.NewCertPool()), WithSleep(rec.sleep), WithLogger(&logBuf))
	if err != nil {
		t.Fatal(err)
	}
	rec.sleeps = nil
	_, err = get(t, c, "/api/v1/downloads/dl_Xk4Lm9Qp2Zr7Vb1Nt6Yc3Hd8Jf?code=123", Policy{MaxAttempts: 3})
	var re *RequestError
	if !errors.As(err, &re) || !re.Temporary || !IsRetryable(err) || len(rec.all()) != 2 || re.Unwrap() == nil {
		t.Fatalf("got %v, %d sleeps", err, len(rec.all()))
	}
	for _, s := range []string{err.Error(), logBuf.String()} {
		if strings.Contains(s, "Xk4Lm9Qp2Zr7") || strings.Contains(s, "code=") {
			t.Fatalf("not redacted: %s", s)
		}
	}
	if !strings.Contains(logBuf.String(), "attempt 3: error after") {
		t.Fatalf("log %s", logBuf.String())
	}
}

func TestContextEnds(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	c, _ := newTestClient(t, srv, "", WithSleep(func(context.Context, time.Duration) error {
		cancel()
		return errors.New("sleep interrupted")
	}))
	req, _ := c.NewRequest(ctx, http.MethodGet, "/x", nil)
	if err := doClose(c, req, Policy{}); err == nil || err.Error() != "sleep interrupted" {
		t.Fatalf("sleep error: %v", err)
	}
	// Context already over: ctx.Err().
	if err := doClose(c, req, Policy{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled: %v", err)
	}
}

func TestDelay(t *testing.T) {
	var p Policy
	want := []time.Duration{1, 2, 4, 8, 16, 32, 60, 60}
	for i, w := range want {
		if d := p.Delay(i+1, errors.New("x")); d != w*time.Second {
			t.Errorf("attempt %d: %v", i+1, d)
		}
	}
	p = Policy{BaseDelay: 100 * time.Millisecond, MaxDelay: 300 * time.Millisecond}
	if d := p.Delay(10, nil); d != 300*time.Millisecond {
		t.Errorf("cap: %v", d)
	}
	p.Jitter = true
	for range 50 {
		if d := p.Delay(1, nil); d < 50*time.Millisecond || d > 100*time.Millisecond {
			t.Fatalf("jitter out of range: %v", d)
		}
	}
	// Retry-After capped by the default.
	if d := (Policy{}).Delay(1, &Problem{Status: 503, RetryAfter: time.Hour}); d != DefaultMaxRetryAfter {
		t.Errorf("retry-after cap: %v", d)
	}
	if (Policy{MaxAttempts: 3}).attempts() != 3 || (Policy{}).attempts() != DefaultMaxAttempts {
		t.Error("attempts")
	}
}

func TestTemporary(t *testing.T) {
	permanent := []error{
		context.Canceled, context.DeadlineExceeded,
		x509.UnknownAuthorityError{},
		x509.HostnameError{},
		x509.CertificateInvalidError{},
		&tls.CertificateVerificationError{Err: errors.New("x")}, tls.AlertError(70),
		tls.RecordHeaderError{},
		fmt.Errorf("wrapped: %w", x509.UnknownAuthorityError{}),
	}
	for _, err := range permanent {
		if temporary(err) {
			t.Errorf("%T temporary", err)
		}
	}
	if temporary(&net.OpError{Op: "remote error", Err: errors.New("tls: protocol version not supported")}) ||
		temporary(errors.New("tls: handshake failure")) {
		t.Error("TLS alert temporary")
	}
	if !temporary(io.ErrUnexpectedEOF) || !temporary(&net.OpError{Op: "dial", Err: errors.New("refused")}) {
		t.Error("EOF permanent")
	}
	if IsRetryable(errors.New("plain")) || IsRetryable(nil) {
		t.Error("plain error retryable")
	}
	if !IsRetryable(fmt.Errorf("w: %w", &Problem{Status: 429})) {
		t.Error("wrapped 429 not retryable")
	}
	if !errors.Is(cause(io.EOF), io.EOF) {
		t.Error("cause")
	}
}

func TestVerboseLogRedaction(t *testing.T) {
	tok := testToken('q')
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Request-Id", "req-7\u202e")
		http.SetCookie(w, &http.Cookie{Name: "__Host-dl", Value: "cookievalue", Path: "/", Secure: true})
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	var logBuf bytes.Buffer
	c, _ := newTestClient(t, srv, tok, WithLogger(&logBuf))
	for range 2 {
		if _, err := get(t, c, "/api/v1/downloads/dl_Xk4Lm9Qp2Zr7Vb1Nt6Yc3Hd8Jf/files/fil_01JABCD9F1A2B3C4D5E6F7G8H9?code=654321", Policy{}); err != nil {
			t.Fatal(err)
		}
	}
	out := logBuf.String()
	for _, secret := range []string{tok, tok[3:12], "cookievalue", "654321", "Xk4Lm9Qp2Z", "key", "Bearer", "\u202e"} {
		if strings.Contains(out, secret) {
			t.Fatalf("log contains %q: %s", secret, out)
		}
	}
	if !strings.Contains(out, "GET /api/v1/downloads/dl_Xk4L…/files/fil_01JA… attempt 1: 200 request-id=req-7") {
		t.Fatalf("log line: %s", out)
	}
}

func TestJSON(t *testing.T) {
	type msg struct {
		A string `json:"a"`
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/echo":
			if r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Idempotency-Key") != "k1" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusCreated)
			_, _ = io.Copy(w, r.Body)
		case "/empty":
			w.WriteHeader(http.StatusNoContent)
		case "/text":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, "{}")
		case "/big":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"a":"`+strings.Repeat("x", 100)+`"}`)
		case "/broken":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"a":`)
		case "/short":
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Length", "100")
			_, _ = io.WriteString(w, `{"a":"b"`)
		case "/fail":
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	c, _ := newTestClient(t, srv, "")
	ctx := context.Background()
	var out msg
	resp, err := c.JSON(ctx, http.MethodPost, "/echo", msg{A: "hello"}, &out, http.Header{"Idempotency-Key": {"k1"}}, Policy{})
	if err != nil || resp.StatusCode != http.StatusCreated || out.A != "hello" {
		t.Fatalf("echo: %v %v %+v", resp, err, out)
	}
	if resp, err := c.JSON(ctx, http.MethodDelete, "/empty", nil, &out, nil, Policy{}); err != nil || resp.StatusCode != http.StatusNoContent {
		t.Fatalf("empty: %v", err)
	}
	if _, err := c.JSON(ctx, http.MethodGet, "/text", nil, nil, nil, Policy{}); err != nil {
		t.Fatalf("no out: %v", err)
	}
	errorCases := map[string]string{
		"/text":    "not JSON",
		"/big":     "larger than 50 bytes",
		"/broken":  "decoding the answer",
		"/short":   "unexpected EOF",
		"/fail":    "HTTP 404",
		"//evil/x": "outside",
	}
	for path, want := range errorCases {
		_, err := c.JSON(ctx, http.MethodGet, path, nil, &out, nil, Policy{MaxResponseBytes: 50, MaxAttempts: 1})
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want %q", path, err, want)
		}
	}
	if _, err := c.JSON(ctx, http.MethodPost, "/echo", make(chan int), nil, nil, Policy{}); err == nil || !strings.Contains(err.Error(), "encoding") {
		t.Fatalf("encode: %v", err)
	}
	// Default response limit.
	if _, err := c.JSON(ctx, http.MethodGet, "/big", nil, &out, nil, Policy{}); err != nil {
		t.Fatalf("default limit: %v", err)
	}
}

func TestRequestErrorMessage(t *testing.T) {
	e := &RequestError{Method: "PATCH", Path: "/api/v1/uploads/upl_7Hq2…", Err: errors.New("dial tcp: refused")}
	if e.Error() != "PATCH /api/v1/uploads/upl_7Hq2…: dial tcp: refused" || !errors.Is(e, e.Err) {
		t.Fatalf("got %q", e.Error())
	}
}
