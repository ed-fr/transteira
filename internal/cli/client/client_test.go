package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// recorder keeps the sleeps asked by the client.
type recorder struct {
	mu     sync.Mutex
	sleeps []time.Duration
}

func (r *recorder) sleep(ctx context.Context, d time.Duration) error {
	r.mu.Lock()
	r.sleeps = append(r.sleeps, d)
	r.mu.Unlock()
	return ctx.Err()
}

func (r *recorder) all() []time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]time.Duration(nil), r.sleeps...)
}

// poolOf returns a pool trusting the certificate of srv.
func poolOf(srv *httptest.Server) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return pool
}

// quiet silences the TLS handshake errors logged by a test server.
func quiet(srv *httptest.Server) *httptest.Server {
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	return srv
}

// newTestClient returns a client for srv with a fake sleep.
func newTestClient(t *testing.T, srv *httptest.Server, token string, opts ...Option) (*Client, *recorder) {
	t.Helper()
	rec := &recorder{}
	opts = append([]Option{WithRootCAs(poolOf(srv)), WithSleep(rec.sleep)}, opts...)
	c, err := New(Config{URL: srv.URL, Token: token}, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return c, rec
}

// doClose sends req and closes the body of a 2xx answer.
func doClose(c *Client, req *http.Request, p Policy) error {
	resp, err := c.Do(req.Context(), req, p)
	if err == nil {
		_ = resp.Body.Close()
	}
	return err
}

// get sends a GET to ref and returns the status of a 2xx answer.
func get(t *testing.T, c *Client, ref string, p Policy) (int, error) {
	t.Helper()
	req, err := c.NewRequest(context.Background(), http.MethodGet, ref, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(context.Background(), req, p)
	if err != nil {
		return 0, err
	}
	_ = resp.Body.Close()
	return resp.StatusCode, nil
}

func TestTLSVersionRefused(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11}
	quiet(srv).StartTLS()
	defer srv.Close()
	c, rec := newTestClient(t, srv, "")
	_, err := get(t, c, "/x", Policy{})
	var re *RequestError
	if !errors.As(err, &re) || re.Temporary || IsRetryable(err) {
		t.Fatalf("got %v", err)
	}
	if len(rec.all()) != 0 {
		t.Fatal("a TLS failure was retried")
	}
}

func TestUnknownAuthorityNotRetried(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	quiet(srv).StartTLS()
	defer srv.Close()
	rec := &recorder{}
	c, err := New(Config{URL: srv.URL}, WithRootCAs(x509.NewCertPool()), WithSleep(rec.sleep))
	if err != nil {
		t.Fatal(err)
	}
	_, err = get(t, c, "/x", Policy{})
	if err == nil || IsRetryable(err) || len(rec.all()) != 0 {
		t.Fatalf("got %v, %d retries", err, len(rec.all()))
	}
}

func writeCAFile(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ca.pem")
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCAFile(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer srv.Close()
	ca := writeCAFile(t, srv)
	// System pool plus the CA file.
	c, err := New(Config{URL: srv.URL, CAFile: ca})
	if err != nil {
		t.Fatal(err)
	}
	if status, err := get(t, c, "/x", Policy{}); err != nil || status != http.StatusNoContent {
		t.Fatalf("got %v %v", status, err)
	}
	// Given pool plus the CA file: the given pool is not modified.
	base := x509.NewCertPool()
	if _, err := New(Config{URL: srv.URL, CAFile: ca}, WithRootCAs(base)); err != nil {
		t.Fatal(err)
	}
	if !base.Equal(x509.NewCertPool()) {
		t.Fatal("WithRootCAs pool modified")
	}
	// System pool unavailable: an empty pool plus the CA file.
	old := systemCertPool
	systemCertPool = func() (*x509.CertPool, error) { return nil, errors.New("no system roots") }
	c, err = New(Config{URL: srv.URL, CAFile: ca})
	systemCertPool = old
	if err != nil {
		t.Fatal(err)
	}
	if _, err := get(t, c, "/x", Policy{}); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.pem")
	big := filepath.Join(dir, "big.pem")
	_ = os.WriteFile(empty, []byte("not a certificate"), 0o600)
	_ = os.WriteFile(big, bytes.Repeat([]byte("x"), MaxCAFileBytes+1), 0o600)
	for file, want := range map[string]string{
		empty:                         "no PEM certificate",
		big:                           "larger than",
		filepath.Join(dir, "missing"): "CA file",
	} {
		if _, err := New(Config{URL: srv.URL, CAFile: file}); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want %q", file, err, want)
		}
	}
	setOpen(t, fakeFile{readErr: errors.New("read failed")})
	if _, err := New(Config{URL: srv.URL, CAFile: "x"}); err == nil || !strings.Contains(err.Error(), "read failed") {
		t.Errorf("read error: %v", err)
	}
}

func TestNewInvalidURL(t *testing.T) {
	if _, err := New(Config{URL: "http://a.example.com"}); err == nil {
		t.Fatal("http accepted")
	}
}

func TestRedirectNotFollowed(t *testing.T) {
	var hits atomic.Int32
	var gotAuth atomic.Value
	target := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		gotAuth.Store(r.Header.Get("Authorization"))
	}))
	defer target.Close()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/same" {
			http.Redirect(w, r, "/other", http.StatusFound)
			return
		}
		if r.URL.Path == "/other" {
			hits.Add(100)
		}
		http.Redirect(w, r, target.URL+"/steal", http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	pool := poolOf(srv)
	pool.AddCert(target.Certificate())
	c, rec := newTestClient(t, srv, testToken('r'), WithRootCAs(pool))
	for _, ref := range []string{"/away", "/same"} {
		_, err := get(t, c, ref, Policy{})
		var p *Problem
		if !errors.As(err, &p) || p.Status/100 != 3 || IsRetryable(err) {
			t.Fatalf("%s: got %v", ref, err)
		}
	}
	if hits.Load() != 0 || gotAuth.Load() != nil || len(rec.all()) != 0 {
		t.Fatalf("redirect followed: hits %d auth %v", hits.Load(), gotAuth.Load())
	}
}

func TestAuthorizationAndOrigin(t *testing.T) {
	tok := testToken('a')
	var gotAuth, gotUA atomic.Value
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth.Store(r.Header.Get("Authorization"))
		gotUA.Store(r.Header.Get("User-Agent"))
		if r.URL.RawQuery != "a=1" {
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()
	c, _ := newTestClient(t, srv, tok)
	req, err := c.NewRequest(context.Background(), http.MethodGet, srv.URL+"/api/v1/x?a=1", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer forged")
	resp, err := c.Do(context.Background(), req, Policy{})
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if gotAuth.Load() != "Bearer "+tok || !strings.HasPrefix(gotUA.Load().(string), "transteira-cli/") {
		t.Fatalf("auth %v ua %v", gotAuth.Load(), gotUA.Load())
	}
	// Anonymous: no Authorization, even a caller-set one.
	req, _ = c.NewRequest(context.Background(), http.MethodGet, "/api/v1/x?a=1", nil)
	req.Header.Set("Authorization", "Bearer forged")
	if err := doClose(c, req, Policy{Anonymous: true}); err != nil {
		t.Fatal(err)
	}
	if gotAuth.Load() != "" {
		t.Fatalf("anonymous sent %v", gotAuth.Load())
	}
	// No token configured, custom User-Agent, empty User-Agent.
	c2, _ := newTestClient(t, srv, "", WithUserAgent("ua-test"))
	if _, err := get(t, c2, "/x?a=1", Policy{}); err != nil || gotAuth.Load() != "" || gotUA.Load() != "ua-test" {
		t.Fatalf("no token: %v %v %v", err, gotAuth.Load(), gotUA.Load())
	}
	c3, _ := newTestClient(t, srv, "", WithUserAgent(""))
	if _, err := get(t, c3, "/x?a=1", Policy{}); err != nil || gotUA.Load() == "ua-test" {
		t.Fatalf("empty UA: %v %v", err, gotUA.Load())
	}

	// A request to another origin is refused before any connection.
	other, _ := http.NewRequest(http.MethodGet, "https://evil.example.com/x", nil)
	if err := doClose(c, other, Policy{}); !errors.Is(err, ErrForeignOrigin) {
		t.Fatalf("foreign: %v", err)
	}
	if err := doClose(c, &http.Request{Method: http.MethodGet}, Policy{}); !errors.Is(err, ErrForeignOrigin) {
		t.Fatalf("nil URL: %v", err)
	}
}

func TestResolve(t *testing.T) {
	c, err := New(Config{URL: "https://transfer.entity-a.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if c.BaseURL() != "https://transfer.entity-a.example.com" || c.Config().URL != c.BaseURL() || c.HTTPClient() == nil {
		t.Fatal("accessors")
	}
	good := map[string]string{
		"/api/v1/uploads/upl_x": "https://transfer.entity-a.example.com/api/v1/uploads/upl_x",
		"/api/v1/x?y=1":         "https://transfer.entity-a.example.com/api/v1/x?y=1",
		"https://transfer.entity-a.example.com/api/v1/downloads/dl_x": "https://transfer.entity-a.example.com/api/v1/downloads/dl_x",
		"HTTPS://Transfer.Entity-A.example.com:443/a%2Fb":             "https://transfer.entity-a.example.com/a%2Fb",
	}
	for ref, want := range good {
		u, err := c.Resolve(ref)
		if err != nil || u.String() != want {
			t.Errorf("%s: got %v %v, want %s", ref, u, err, want)
		}
	}
	bad := map[string]string{
		"https://evil.example.com/x":                   "outside",
		"https://transfer.entity-a.example.com:8443/x": "outside",
		"http://transfer.entity-a.example.com/x":       "outside",
		"//evil.example.com/x":                         "outside",
		"https://u:p@transfer.entity-a.example.com/x":  "outside",
		"https:opaque":                                 "outside",
		"api/v1/x":                                     "not an absolute path",
		"/x#k=secret":                                  "fragment",
		"/x#":                                          "fragment",
		"/%zz":                                         "invalid reference",
	}
	for ref, want := range bad {
		_, err := c.Resolve(ref)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want %q", ref, err, want)
		}
		if strings.Contains(err.Error(), "secret") {
			t.Errorf("%s: error quotes the fragment", ref)
		}
	}
	// A base URL with a port.
	c2, _ := New(Config{URL: "https://transfer.entity-a.example.com:8443"})
	if _, err := c2.Resolve("https://transfer.entity-a.example.com/x"); !errors.Is(err, ErrForeignOrigin) {
		t.Fatalf("port: %v", err)
	}
	if _, err := c2.Resolve("https://transfer.entity-a.example.com:8443/x"); err != nil {
		t.Fatal(err)
	}
	// NewRequest errors.
	if _, err := c.NewRequest(context.Background(), http.MethodGet, "https://evil.example.com/", nil); !errors.Is(err, ErrForeignOrigin) {
		t.Fatalf("NewRequest foreign: %v", err)
	}
	if _, err := c.NewRequest(context.Background(), "BAD METHOD", "/x", nil); err == nil {
		t.Fatal("bad method accepted")
	}
}

func TestDialContextAndDefaultPort(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "example.com" {
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()
	var dialed atomic.Bool
	dial := func(ctx context.Context, network, _ string) (net.Conn, error) {
		dialed.Store(true)
		var d net.Dialer
		return d.DialContext(ctx, network, srv.Listener.Addr().String())
	}
	c, err := New(Config{URL: "https://example.com"}, WithRootCAs(poolOf(srv)), WithDialContext(dial))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := get(t, c, "https://example.com:443/x", Policy{}); err != nil || !dialed.Load() {
		t.Fatalf("got %v, dialed %v", err, dialed.Load())
	}
}

func TestCookieJar(t *testing.T) {
	var second atomic.Value
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/unlock" {
			http.SetCookie(w, &http.Cookie{Name: "__Host-dlgrant", Value: "g1", Path: "/", Secure: true, HttpOnly: true})
			return
		}
		second.Store(r.Header.Get("Cookie"))
	}))
	defer srv.Close()
	c, _ := newTestClient(t, srv, "")
	if _, err := get(t, c, "/unlock", Policy{}); err != nil {
		t.Fatal(err)
	}
	if _, err := get(t, c, "/file", Policy{}); err != nil {
		t.Fatal(err)
	}
	if second.Load() != "__Host-dlgrant=g1" {
		t.Fatalf("cookie %v", second.Load())
	}
}

func TestSleepContext(t *testing.T) {
	if err := sleepContext(context.Background(), time.Millisecond); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := sleepContext(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

// errBody is a request body that is not replayable.
type errBody struct{ io.Reader }

func (errBody) Close() error { return nil }

func TestBodyReplay(t *testing.T) {
	var bodies []string
	var mu sync.Mutex
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		n := len(bodies)
		mu.Unlock()
		if n < 3 {
			w.WriteHeader(http.StatusBadGateway)
		}
	}))
	defer srv.Close()
	c, rec := newTestClient(t, srv, "")
	req, _ := c.NewRequest(context.Background(), http.MethodPost, "/x", strings.NewReader("payload"))
	resp, err := c.Do(context.Background(), req, Policy{})
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if strings.Join(bodies, ",") != "payload,payload,payload" {
		t.Fatalf("bodies %q", bodies)
	}
	if got := rec.all(); len(got) != 2 || got[0] != time.Second || got[1] != 2*time.Second {
		t.Fatalf("sleeps %v", got)
	}

	// No GetBody.
	req, _ = c.NewRequest(context.Background(), http.MethodPost, "/x", errBody{strings.NewReader("x")})
	if err := doClose(c, req, Policy{}); !errors.Is(err, ErrBodyNotReplayable) {
		t.Fatalf("no GetBody: %v", err)
	}
	// GetBody failing on the second attempt.
	bodies = nil
	req, _ = c.NewRequest(context.Background(), http.MethodPost, "/x", strings.NewReader("x"))
	req.GetBody = func() (io.ReadCloser, error) { return nil, errors.New("reopen failed") }
	err = doClose(c, req, Policy{})
	var re *RequestError
	if !errors.As(err, &re) || re.Temporary || !strings.Contains(err.Error(), "reopen failed") {
		t.Fatalf("GetBody error: %v", err)
	}
}
