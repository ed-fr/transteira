package antivirus

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"

	"github.com/ed-fr/transteira/internal/antivirus/antivirustest"
)

// Rules of the clamav-rest example (github.com/ajilach/clamav-rest, /scan
// endpoint): 200 {"Status":"OK","Description":""} when clean, 406
// {"Status":"FOUND","Description":"<signature>"} when infected. The exact
// response shape comes from memory of that project and may differ between
// its versions (the /v2/scan endpoint answers a JSON array).
const (
	restCleanRule    = `status=200 && json:/Status="OK"`
	restInfectedRule = `status=406 && json:/Status="FOUND"`
	restSigPointer   = "/Description"
	secretValue      = "s3cr3t-T0ken-value"
	secretAuthHeader = "Authorization: Bearer " + secretValue
)

func mustURL(t testing.TB, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// received is what the fake engine got in one request.
type received struct {
	method        string
	path          string
	contentType   string
	contentLength int64
	auth          string
	content       []byte // the file content (multipart part or raw body)
	field         string
	filename      string
	partType      string
	complete      bool // the body (and multipart framing) was read entirely
}

// fakeEngine is a clamav-rest-like HTTP engine: it detects the EICAR
// string in the content it receives and records every request.
type fakeEngine struct {
	srv  *httptest.Server
	mu   sync.Mutex
	reqs []received
	// respond, when set, replaces the clamav-rest answer.
	respond func(w http.ResponseWriter, r *http.Request, got received)
}

func newFakeEngine(t *testing.T, tlsCert *tls.Certificate) *fakeEngine {
	t.Helper()
	e := &fakeEngine{}
	e.srv = httptest.NewUnstartedServer(http.HandlerFunc(e.handle))
	e.srv.Config.ErrorLog = log.New(io.Discard, "", 0) // expected TLS handshake failures
	if tlsCert != nil {
		e.srv.TLS = &tls.Config{Certificates: []tls.Certificate{*tlsCert}, MinVersion: tls.VersionTLS12}
		e.srv.StartTLS()
	} else {
		e.srv.Start()
	}
	t.Cleanup(e.srv.Close)
	return e
}

func (e *fakeEngine) handle(w http.ResponseWriter, r *http.Request) {
	got := received{
		method: r.Method, path: r.URL.Path, contentType: r.Header.Get("Content-Type"),
		contentLength: r.ContentLength, auth: r.Header.Get("Authorization"),
	}
	if strings.HasPrefix(got.contentType, "multipart/form-data") {
		readMultipart(r, &got)
	} else {
		body, err := io.ReadAll(r.Body)
		got.content, got.complete = body, err == nil
	}
	e.mu.Lock()
	e.reqs = append(e.reqs, got)
	respond := e.respond
	e.mu.Unlock()
	if respond != nil {
		respond(w, r, got)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if bytes.Contains(got.content, antivirustest.EICAR()) {
		w.WriteHeader(http.StatusNotAcceptable)
		_, _ = io.WriteString(w, `{"Status":"FOUND","Description":"`+antivirustest.EicarSignature+`"}`)
		return
	}
	_, _ = io.WriteString(w, `{"Status":"OK","Description":""}`)
}

func readMultipart(r *http.Request, got *received) {
	mr, err := r.MultipartReader()
	if err != nil {
		return
	}
	part, err := mr.NextPart()
	if err != nil {
		return
	}
	got.field, got.filename, got.partType = part.FormName(), part.FileName(), part.Header.Get("Content-Type")
	content, err := io.ReadAll(part)
	got.content = content
	if err != nil {
		return
	}
	if _, err := mr.NextPart(); errors.Is(err, io.EOF) {
		got.complete = true
	}
}

func (e *fakeEngine) setRespond(f func(w http.ResponseWriter, r *http.Request, got received)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.respond = f
}

func (e *fakeEngine) requests() []received {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]received(nil), e.reqs...)
}

// engineReply returns a responder answering status and body.
func engineReply(status int, body string) func(http.ResponseWriter, *http.Request, received) {
	return func(w http.ResponseWriter, _ *http.Request, _ received) {
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}
}

func restConfig(t testing.TB, rawURL string) HTTPConfig {
	t.Helper()
	return HTTPConfig{
		URL:              rawURL,
		CleanRule:        mustRule(t, restCleanRule),
		InfectedRule:     mustRule(t, restInfectedRule),
		SignaturePointer: restSigPointer,
		AuthHeader:       secretAuthHeader,
	}
}

func newHTTP(t testing.TB, cfg HTTPConfig) *HTTPClient {
	t.Helper()
	c, err := NewHTTPClient(cfg)
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}
	return c
}

func httpScan(t *testing.T, c *HTTPClient, data []byte) (Result, error) {
	t.Helper()
	res, err := c.Scan(context.Background(), bytes.NewReader(data), int64(len(data)))
	checkNoSecret(t, err)
	return res, err
}

// checkNoSecret fails when an error leaks the auth header or a URL secret.
func checkNoSecret(t testing.TB, err error) {
	t.Helper()
	if err != nil && (strings.Contains(err.Error(), secretValue) || strings.Contains(err.Error(), "querysecret")) {
		t.Fatalf("error leaks a secret: %v", err)
	}
}

// newTestCA returns a runtime CA (PEM) and a server certificate it signed
// for 127.0.0.1 and localhost.
func newTestCA(t testing.TB) ([]byte, tls.Certificate) {
	t.Helper()
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "TransTeira test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "engine"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, DNSNames: []string{"localhost"},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}
}

// closedAddr returns a local address nothing listens on.
func closedAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func TestNewHTTPClientDefaults(t *testing.T) {
	c := newHTTP(t, restConfig(t, "http://engine.example.com:8080/scan?key=querysecret#frag"))
	if c.method != http.MethodPost || c.body != BodyMultipart || c.field != DefaultMultipartField ||
		c.maxScanBytes != DefaultMaxScanBytes || c.timeout != DefaultScanTimeout || c.pingTimeout != DefaultTimeout {
		t.Fatalf("defaults = %+v", c)
	}
	if c.authName != "Authorization" || c.authValue != "Bearer "+secretValue || !c.needJSON {
		t.Fatalf("auth or rules not applied: %q %t", c.authName, c.needJSON)
	}
	if c.url.Fragment != "" {
		t.Error("fragment kept")
	}
	if got := c.String(); got != "http engine http://engine.example.com:8080" {
		t.Errorf("String = %q", got)
	}
	cfg := restConfig(t, "https://engine.example.com/scan")
	cfg.Method, cfg.Body, cfg.MultipartField = "put", BodyRaw, "data.file_1"
	cfg.MaxScanBytes, cfg.Timeout, cfg.PingTimeout = 10, time.Second, time.Millisecond
	cfg.AuthHeader = "X-Api-Key:\t" + secretValue + " \r\n"
	c = newHTTP(t, cfg)
	if c.method != http.MethodPut || c.body != BodyRaw || c.field != "data.file_1" || c.maxScanBytes != 10 ||
		c.timeout != time.Second || c.pingTimeout != time.Millisecond || c.authName != "X-Api-Key" || c.authValue != secretValue {
		t.Fatalf("options not applied: %+v", c)
	}
	cfg = restConfig(t, "http://engine.example.com/scan")
	cfg.CleanRule, cfg.InfectedRule = mustRule(t, "status=200"), mustRule(t, "status=406")
	if newHTTP(t, cfg).needJSON {
		t.Error("needJSON with status rules")
	}
}

func TestNewHTTPClientInvalid(t *testing.T) {
	caPEM, _ := newTestCA(t)
	base := func() HTTPConfig { return restConfig(t, "https://engine.example.com/scan?key=querysecret") }
	cases := map[string]func(*HTTPConfig){
		"bad url":             func(c *HTTPConfig) { c.URL = "http://user:" + secretValue + "@[::1" },
		"scheme":              func(c *HTTPConfig) { c.URL = "ftp://engine.example.com/" },
		"no scheme":           func(c *HTTPConfig) { c.URL = "engine.example.com/scan" },
		"userinfo":            func(c *HTTPConfig) { c.URL = "https://user:" + secretValue + "@engine.example.com/" },
		"no host":             func(c *HTTPConfig) { c.URL = "https:///scan" },
		"port only":           func(c *HTTPConfig) { c.URL = "https://:8080/scan" },
		"opaque":              func(c *HTTPConfig) { c.URL = "https:engine.example.com" },
		"health userinfo":     func(c *HTTPConfig) { c.HealthURL = "http://u:" + secretValue + "@engine.example.com/health" },
		"method":              func(c *HTTPConfig) { c.Method = "GET" },
		"body":                func(c *HTTPConfig) { c.Body = "form" },
		"field":               func(c *HTTPConfig) { c.MultipartField = `fi"le` },
		"field length":        func(c *HTTPConfig) { c.MultipartField = strings.Repeat("f", 65) },
		"auth no colon":       func(c *HTTPConfig) { c.AuthHeader = "Bearer " + secretValue },
		"auth empty name":     func(c *HTTPConfig) { c.AuthHeader = ": " + secretValue },
		"auth bad name":       func(c *HTTPConfig) { c.AuthHeader = "Auth orization: " + secretValue },
		"auth host":           func(c *HTTPConfig) { c.AuthHeader = "host: " + secretValue },
		"auth content-length": func(c *HTTPConfig) { c.AuthHeader = "Content-Length: 1" + secretValue },
		"auth empty value":    func(c *HTTPConfig) { c.AuthHeader = "Authorization:  " },
		"auth CRLF":           func(c *HTTPConfig) { c.AuthHeader = "Authorization: a\r\nX-Injected: " + secretValue },
		"auth LF":             func(c *HTTPConfig) { c.AuthHeader = "Authorization: " + secretValue + "\nb" },
		"auth NUL":            func(c *HTTPConfig) { c.AuthHeader = "Authorization: " + secretValue + "\x00" },
		"auth DEL":            func(c *HTTPConfig) { c.AuthHeader = "Authorization: " + secretValue + "\x7f" },
		"no clean rule":       func(c *HTTPConfig) { c.CleanRule = Rule{} },
		"no infected rule":    func(c *HTTPConfig) { c.InfectedRule = Rule{} },
		"signature pointer":   func(c *HTTPConfig) { c.SignaturePointer = "Description" },
		"CA with http":        func(c *HTTPConfig) { c.URL, c.CAPEM = "http://engine.example.com/", caPEM },
		"CA not PEM":          func(c *HTTPConfig) { c.CAPEM = []byte("not a certificate") },
	}
	for name, mutate := range cases {
		cfg := base()
		mutate(&cfg)
		c, err := NewHTTPClient(cfg)
		if err == nil {
			t.Errorf("%s: accepted (%v)", name, c)
			continue
		}
		checkNoSecret(t, err)
	}
	cfg := base()
	cfg.CAPEM = caPEM
	if _, err := NewHTTPClient(cfg); err != nil {
		t.Errorf("valid CA refused: %v", err)
	}
}

func TestHTTPScanClamavRest(t *testing.T) {
	e := newFakeEngine(t, nil)
	c := newHTTP(t, restConfig(t, e.srv.URL+"/scan?key=querysecret"))
	clean := []byte("hello, this is a clean file\x00\xff")
	if res, err := httpScan(t, c, clean); err != nil || res != (Result{Verdict: Clean}) {
		t.Fatalf("clean scan = %+v, %v", res, err)
	}
	infected := append([]byte("prefix "), antivirustest.EICAR()...)
	res, err := httpScan(t, c, infected)
	if err != nil || res != (Result{Verdict: Infected, Signature: antivirustest.EicarSignature}) {
		t.Fatalf("infected scan = %+v, %v", res, err)
	}
	reqs := e.requests()
	if len(reqs) != 2 {
		t.Fatalf("%d requests", len(reqs))
	}
	for i, want := range [][]byte{clean, infected} {
		got := reqs[i]
		if got.method != http.MethodPost || got.path != "/scan" || got.field != "file" || got.filename != "file" ||
			got.partType != "application/octet-stream" || !got.complete || !bytes.Equal(got.content, want) ||
			got.auth != "Bearer "+secretValue {
			t.Errorf("request %d = %+v", i, got)
		}
	}
	// The multipart boundary changes with every request.
	if reqs[0].contentType == reqs[1].contentType {
		t.Error("multipart boundary reused")
	}
}

func TestHTTPScanBodies(t *testing.T) {
	e := newFakeEngine(t, nil)
	data := make([]byte, 300<<10+17)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []BodyMode{BodyRaw, BodyMultipart} {
		for _, method := range []string{http.MethodPost, http.MethodPut} {
			for _, content := range [][]byte{data, {}} {
				name := fmt.Sprintf("%s %s %d", mode, method, len(content))
				before := len(e.requests())
				cfg := restConfig(t, e.srv.URL+"/scan")
				cfg.Body, cfg.Method, cfg.MultipartField, cfg.AuthHeader = mode, method, "upload", ""
				res, err := httpScan(t, newHTTP(t, cfg), content)
				if err != nil || res.Verdict != Clean {
					t.Errorf("%s: %+v, %v", name, res, err)
					continue
				}
				reqs := e.requests()
				got := reqs[before]
				if got.method != method || !got.complete || !bytes.Equal(got.content, content) || got.auth != "" {
					t.Errorf("%s: received %d bytes, complete %t, method %s, auth %q", name, len(got.content), got.complete, got.method, got.auth)
				}
				switch mode {
				case BodyRaw:
					if got.contentType != "application/octet-stream" || got.contentLength != int64(len(content)) {
						t.Errorf("%s: content type %q, length %d", name, got.contentType, got.contentLength)
					}
				default:
					if got.field != "upload" || got.filename != "file" || got.contentLength <= int64(len(content)) {
						t.Errorf("%s: field %q, filename %q, length %d", name, got.field, got.filename, got.contentLength)
					}
				}
			}
		}
	}
}

func TestHTTPScanVerdicts(t *testing.T) {
	e := newFakeEngine(t, nil)
	cfg := restConfig(t, e.srv.URL+"/scan?key=querysecret")
	c := newHTTP(t, cfg)
	long := strings.Repeat("x", MaxHTTPResponseBytes)
	cases := []struct {
		name    string
		status  int
		body    string
		want    Result
		wantErr error
	}{
		{"clean", 200, `{"Status":"OK","Description":""}`, Result{Verdict: Clean}, nil},
		{"clean with spaces", 200, " {\"Description\":null, \"Status\" : \"OK\"}\n", Result{Verdict: Clean}, nil},
		{"infected", 406, `{"Status":"FOUND","Description":"Win.Test.EICAR_HDB-1"}`, Result{Verdict: Infected, Signature: "Win.Test.EICAR_HDB-1"}, nil},
		{"infected empty signature", 406, `{"Status":"FOUND","Description":""}`, Result{Verdict: Infected, Signature: "unknown"}, nil},
		{"infected no signature", 406, `{"Status":"FOUND"}`, Result{Verdict: Infected, Signature: "unknown"}, nil},
		{"infected null signature", 406, `{"Status":"FOUND","Description":null}`, Result{Verdict: Infected, Signature: "unknown"}, nil},
		{"infected number signature", 406, `{"Status":"FOUND","Description":42}`, Result{Verdict: Infected, Signature: "42"}, nil},
		{"infected array signature", 406, `{"Status":"FOUND","Description":[1,"Sig.A","Sig.B"]}`, Result{Verdict: Infected, Signature: "Sig.A"}, nil},
		{"infected array without string", 406, `{"Status":"FOUND","Description":[1]}`, Result{Verdict: Infected, Signature: "unknown"}, nil},
		{"infected object signature", 406, `{"Status":"FOUND","Description":{"a":1}}`, Result{Verdict: Infected, Signature: `{"a":1}`}, nil},
		{"infected hostile signature", 406, `{"Status":"FOUND","Description":"Sig\r\nX-Evil: <b>` + "\u202e" + strings.Repeat("A", 300) + `"}`, Result{}, nil},
		{"neither", 200, `{"Status":"FOUND"}`, Result{}, ErrProtocol},
		{"missing pointer", 200, `{"status":"OK"}`, Result{}, ErrProtocol},
		{"invalid JSON", 200, `{"Status":"OK"`, Result{}, ErrProtocol},
		{"empty body", 200, ``, Result{}, ErrProtocol},
		{"trailing data", 200, `{"Status":"OK"} {}`, Result{}, ErrProtocol},
		{"html", 200, `<html>OK</html>`, Result{}, ErrProtocol},
		{"oversized body", 200, `{"Status":"OK","Pad":"` + long + `"}`, Result{}, ErrProtocol},
		{"500", 500, `{"Status":"ERROR"}`, Result{}, ErrProtocol},
		{"400", 400, `{"Status":"OK"}`, Result{}, ErrProtocol},
		{"502", 502, `bad gateway`, Result{}, ErrUnavailable},
		{"503", 503, `{"Status":"OK"}`, Result{}, ErrUnavailable},
		{"504", 504, ``, Result{}, ErrUnavailable},
	}
	for _, tc := range cases {
		e.setRespond(engineReply(tc.status, tc.body))
		res, err := httpScan(t, c, []byte("content"))
		switch {
		case tc.wantErr != nil:
			if !errors.Is(err, tc.wantErr) || res != (Result{}) {
				t.Errorf("%s: %+v, %v, want %v", tc.name, res, err, tc.wantErr)
			}
			if errors.Is(err, ErrUnavailable) && errors.Is(err, ErrConnectionLost) {
				t.Errorf("%s: status counted as a lost connection", tc.name)
			}
		case tc.name == "infected hostile signature":
			if err != nil || res.Verdict != Infected || res.Signature != sanitizeSignature(res.Signature) ||
				strings.ContainsAny(res.Signature, "\r\n\u202e") || len(res.Signature) > MaxSignatureLen {
				t.Errorf("%s: %+v, %v", tc.name, res, err)
			}
		default:
			if err != nil || res != tc.want {
				t.Errorf("%s: %+v, %v, want %+v", tc.name, res, err, tc.want)
			}
		}
	}

	// Both rules true is ambiguous.
	cfg.InfectedRule = mustRule(t, "status=200")
	e.setRespond(engineReply(200, `{"Status":"OK"}`))
	if _, err := httpScan(t, newHTTP(t, cfg), []byte("x")); !errors.Is(err, ErrProtocol) || !strings.Contains(err.Error(), "ambiguous") {
		t.Errorf("both rules true: %v", err)
	}
}

func TestHTTPScanStatusRules(t *testing.T) {
	e := newFakeEngine(t, nil)
	cfg := restConfig(t, e.srv.URL+"/scan")
	cfg.CleanRule, cfg.InfectedRule = mustRule(t, "status=204"), mustRule(t, "status=200")
	cfg.SignaturePointer = "/viruses"
	c := newHTTP(t, cfg)
	// The body is not decoded for a clean verdict.
	e.setRespond(engineReply(204, ""))
	if res, err := httpScan(t, c, []byte("x")); err != nil || res.Verdict != Clean {
		t.Errorf("204: %+v, %v", res, err)
	}
	e.setRespond(engineReply(200, `{"viruses":["Eicar-Signature"]}`))
	if res, err := httpScan(t, c, []byte("x")); err != nil || res.Signature != "Eicar-Signature" {
		t.Errorf("200 JSON: %+v, %v", res, err)
	}
	// An infected verdict stands without a readable signature.
	e.setRespond(engineReply(200, `infected!`))
	if res, err := httpScan(t, c, []byte("x")); err != nil || res != (Result{Verdict: Infected, Signature: "unknown"}) {
		t.Errorf("200 text: %+v, %v", res, err)
	}
	cfg.SignaturePointer = ""
	e.setRespond(engineReply(200, `{"viruses":["Eicar-Signature"]}`))
	if res, err := httpScan(t, newHTTP(t, cfg), []byte("x")); err != nil || res.Signature != "unknown" {
		t.Errorf("no pointer: %+v, %v", res, err)
	}
}

func TestHTTPScanNoRedirect(t *testing.T) {
	e := newFakeEngine(t, nil)
	var followed atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		followed.Add(1)
		_, _ = io.WriteString(w, `{"Status":"OK"}`)
	}))
	defer target.Close()
	c := newHTTP(t, restConfig(t, e.srv.URL+"/scan"))
	for _, status := range []int{301, 302, 303, 307, 308} {
		e.setRespond(func(w http.ResponseWriter, r *http.Request, _ received) {
			http.Redirect(w, r, target.URL+"/scan", status)
		})
		if _, err := httpScan(t, c, []byte("x")); !errors.Is(err, ErrProtocol) {
			t.Errorf("redirect %d: %v", status, err)
		}
	}
	if followed.Load() != 0 {
		t.Error("redirect followed")
	}
}

func TestHTTPScanEnvironmentProxyIgnored(t *testing.T) {
	var proxied atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxied.Add(1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer proxy.Close()
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("http_proxy", proxy.URL)
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
	e := newFakeEngine(t, nil)
	// A non-loopback-looking host name would be needed for the standard
	// proxy function to apply; dial it to the engine instead.
	addr := e.srv.Listener.Addr().String()
	cfg := restConfig(t, "http://engine.example.com/scan")
	cfg.dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	if res, err := httpScan(t, newHTTP(t, cfg), []byte("x")); err != nil || res.Verdict != Clean {
		t.Fatalf("scan = %+v, %v", res, err)
	}
	if proxied.Load() != 0 {
		t.Error("environment proxy used")
	}
}

func TestHTTPScanSizes(t *testing.T) {
	e := newFakeEngine(t, nil)
	cfg := restConfig(t, e.srv.URL+"/scan")
	cfg.MaxScanBytes = 10
	c := newHTTP(t, cfg)
	if res, err := httpScan(t, c, make([]byte, 11)); err != nil || res != (Result{Verdict: TooLarge, Detail: DetailClientLimit}) {
		t.Errorf("too large = %+v, %v", res, err)
	}
	if res, err := httpScan(t, c, make([]byte, 10)); err != nil || res.Verdict != Clean {
		t.Errorf("at the limit = %+v, %v", res, err)
	}
	if _, err := c.Scan(context.Background(), bytes.NewReader(nil), -1); !errors.Is(err, ErrSource) {
		t.Errorf("negative size: %v", err)
	}
	if n := len(e.requests()); n != 1 {
		t.Errorf("%d requests, want 1", n)
	}
}

func TestHTTPScanSourceMismatch(t *testing.T) {
	data := make([]byte, 512<<10)
	for _, mode := range []BodyMode{BodyRaw, BodyMultipart} {
		cases := map[string]struct {
			r    io.Reader
			size int64
		}{
			"short":      {bytes.NewReader(data[:len(data)/2]), int64(len(data))},
			"long":       {bytes.NewReader(data), int64(len(data) - 1)},
			"long small": {bytes.NewReader([]byte("abc")), 2},
			"long empty": {bytes.NewReader([]byte("a")), 0},
			"read error": {io.MultiReader(bytes.NewReader(data[:1000]), iotest.ErrReader(errors.New("disk"))), int64(len(data))},
			"late error": {io.MultiReader(bytes.NewReader(data), iotest.ErrReader(errors.New("disk"))), int64(len(data))},
		}
		for name, tc := range cases {
			e := newFakeEngine(t, nil)
			cfg := restConfig(t, e.srv.URL+"/scan")
			cfg.Body = mode
			res, err := newHTTP(t, cfg).Scan(context.Background(), tc.r, tc.size)
			checkNoSecret(t, err)
			if !errors.Is(err, ErrSource) || res != (Result{}) {
				t.Errorf("%s %s: %+v, %v", mode, name, res, err)
			}
			e.srv.Close() // waits for the handler
			for _, got := range e.requests() {
				if name == "short" || name == "read error" || mode == BodyMultipart {
					if got.complete && int64(len(got.content)) == tc.size {
						t.Errorf("%s %s: engine received a complete content", mode, name)
					}
				}
			}
		}
	}
}

func TestHTTPScanAnsweredEarly(t *testing.T) {
	c := newHTTP(t, restConfig(t, "http://engine.example.com/scan"))
	big := make([]byte, 8<<20)
	for status, want := range map[int]error{200: ErrProtocol, 503: ErrUnavailable} {
		// Answer before reading the body, then keep reading it (full
		// duplex), so that the client gets the answer while still sending.
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = http.NewResponseController(w).EnableFullDuplex()
			const answer = `{"Status":"OK","Description":""}`
			w.Header().Set("Content-Length", strconv.Itoa(len(answer)))
			w.WriteHeader(status)
			_, _ = io.WriteString(w, answer)
			_ = http.NewResponseController(w).Flush()
			_, _ = io.Copy(io.Discard, r.Body)
		}))
		c.url = mustURL(t, srv.URL+"/scan")
		_, err := c.Scan(context.Background(), bytes.NewReader(big), int64(len(big)))
		checkNoSecret(t, err)
		if !errors.Is(err, want) {
			t.Errorf("early %d: %v, want %v", status, err, want)
		}
		srv.Close()
	}
}

func TestHTTPScanTLS(t *testing.T) {
	caPEM, cert := newTestCA(t)
	e := newFakeEngine(t, &cert)
	cfg := restConfig(t, e.srv.URL+"/scan")
	cfg.CAPEM = caPEM
	if res, err := httpScan(t, newHTTP(t, cfg), []byte("x")); err != nil || res.Verdict != Clean {
		t.Fatalf("scan with CA = %+v, %v", res, err)
	}
	// Without the CA, the system pool does not trust the engine.
	cfg.CAPEM = nil
	_, err := httpScan(t, newHTTP(t, cfg), []byte("x"))
	if !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrConnectionLost) {
		t.Errorf("untrusted certificate: %v", err)
	}
	// Another CA is not trusted either: the CA file replaces the pool.
	otherCA, _ := newTestCA(t)
	cfg.CAPEM = otherCA
	if _, err := httpScan(t, newHTTP(t, cfg), []byte("x")); !errors.Is(err, ErrUnavailable) {
		t.Errorf("certificate of another CA: %v", err)
	}
	if n := len(e.requests()); n != 1 {
		t.Errorf("%d requests reached the engine, want 1", n)
	}
}

func TestHTTPScanTransportErrors(t *testing.T) {
	// Connection refused.
	c := newHTTP(t, restConfig(t, "http://"+closedAddr(t)+"/scan?key=querysecret"))
	_, err := httpScan(t, c, []byte("x"))
	if !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrConnectionLost) || errors.Is(err, ErrTimeout) {
		t.Errorf("refused: %v", err)
	}
	if strings.Contains(err.Error(), "/scan") {
		t.Errorf("error quotes the URL path: %v", err)
	}
	// Dial failure (DNS) through the dialer hook.
	cfg := restConfig(t, "http://engine.invalid/scan")
	cfg.dial = func(context.Context, string, string) (net.Conn, error) {
		return nil, &net.DNSError{Err: "no such host", Name: "engine.invalid", IsNotFound: true}
	}
	if _, err := httpScan(t, newHTTP(t, cfg), []byte("x")); !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrConnectionLost) {
		t.Errorf("DNS: %v", err)
	}

	// Connection dropped in the middle of the body.
	drop := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.CopyN(io.Discard, r.Body, 1000)
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			_ = conn.Close()
		}
	}))
	defer drop.Close()
	big := make([]byte, 4<<20)
	c = newHTTP(t, restConfig(t, drop.URL+"/scan"))
	_, err = c.Scan(context.Background(), bytes.NewReader(big), int64(len(big)))
	checkNoSecret(t, err)
	if !errors.Is(err, ErrUnavailable) || !errors.Is(err, ErrConnectionLost) {
		t.Errorf("dropped mid-body: %v", err)
	}
	// Connection dropped in the middle of the response body.
	cut := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(200)
		_, _ = io.WriteString(w, `{"Status":`)
		w.(http.Flusher).Flush()
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			_ = conn.Close()
		}
	}))
	defer cut.Close()
	if _, err := httpScan(t, newHTTP(t, restConfig(t, cut.URL+"/scan")), []byte("x")); !errors.Is(err, ErrUnavailable) || !errors.Is(err, ErrConnectionLost) {
		t.Errorf("dropped mid-response: %v", err)
	}
}

func TestHTTPScanTimeouts(t *testing.T) {
	release := make(chan struct{})
	hang := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer hang.Close()
	defer close(release)

	cfg := restConfig(t, hang.URL+"/scan")
	cfg.Timeout = 200 * time.Millisecond
	c := newHTTP(t, cfg)
	_, err := httpScan(t, c, []byte("x"))
	if !errors.Is(err, ErrTimeout) {
		t.Errorf("scan timeout: %v", err)
	}

	cfg.Timeout = time.Minute
	c = newHTTP(t, cfg)
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	_, err = c.Scan(ctx, bytes.NewReader([]byte("x")), 1)
	if !errors.Is(err, ErrUnavailable) || !errors.Is(err, context.Canceled) {
		t.Errorf("caller canceled: %v", err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err = c.Scan(ctx, bytes.NewReader([]byte("x")), 1)
	if !errors.Is(err, ErrUnavailable) || !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrTimeout) {
		t.Errorf("caller deadline: %v", err)
	}
}

func TestHTTPExchangeErrorTimeout(t *testing.T) {
	c := newHTTP(t, restConfig(t, "http://engine.example.com/scan"))
	ctx := context.Background()
	timeoutErr := &net.OpError{Op: "read", Net: "tcp", Err: timeoutError{}}
	if err := c.exchangeError(ctx, ctx, true, "read", timeoutErr); !errors.Is(err, ErrTimeout) {
		t.Errorf("net timeout: %v", err)
	}
}

// timeoutError is a net.Error that timed out.
type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func TestHTTPPing(t *testing.T) {
	var healthAuth atomic.Value
	healthStatus := atomic.Int32{}
	healthStatus.Store(200)
	health := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		healthAuth.Store(r.Header.Get("Authorization"))
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path == "/slow" {
			<-r.Context().Done()
			return
		}
		w.WriteHeader(int(healthStatus.Load()))
		_, _ = io.WriteString(w, strings.Repeat("ok", 10<<10))
	}))
	defer health.Close()
	other := newFakeEngine(t, nil)

	// Same host: the auth header is sent.
	cfg := restConfig(t, health.URL+"/scan")
	cfg.HealthURL = health.URL + "/health?key=querysecret"
	c := newHTTP(t, cfg)
	if err := c.Ping(context.Background()); err != nil {
		t.Errorf("health 200: %v", err)
	}
	if got := healthAuth.Load(); got != "Bearer "+secretValue {
		t.Errorf("health auth = %v", got)
	}
	healthStatus.Store(500)
	err := c.Ping(context.Background())
	checkNoSecret(t, err)
	if !errors.Is(err, ErrUnexpectedReply) {
		t.Errorf("health 500: %v", err)
	}
	healthStatus.Store(200)

	// Another host: the auth header is not sent.
	cfg = restConfig(t, other.srv.URL+"/scan")
	cfg.HealthURL = health.URL + "/health"
	if err := newHTTP(t, cfg).Ping(context.Background()); err != nil {
		t.Errorf("health on another host: %v", err)
	}
	if got := healthAuth.Load(); got != "" {
		t.Errorf("auth header sent to another host: %v", got)
	}

	// Timeout and unreachable health URL.
	cfg.HealthURL, cfg.PingTimeout = health.URL+"/slow", 100*time.Millisecond
	if err := newHTTP(t, cfg).Ping(context.Background()); err == nil {
		t.Error("slow health accepted")
	}
	cfg.HealthURL = "http://" + closedAddr(t) + "/health?key=querysecret"
	err = newHTTP(t, cfg).Ping(context.Background())
	checkNoSecret(t, err)
	if err == nil {
		t.Error("unreachable health accepted")
	}
}

func TestHTTPPingDial(t *testing.T) {
	e := newFakeEngine(t, nil)
	if err := newHTTP(t, restConfig(t, e.srv.URL+"/scan")).Ping(context.Background()); err != nil {
		t.Errorf("dial ping: %v", err)
	}
	if err := newHTTP(t, restConfig(t, "http://"+closedAddr(t)+"/scan")).Ping(context.Background()); err == nil {
		t.Error("dial ping to a closed port succeeded")
	}
	caPEM, cert := newTestCA(t)
	tlsEngine := newFakeEngine(t, &cert)
	cfg := restConfig(t, tlsEngine.srv.URL+"/scan")
	cfg.CAPEM = caPEM
	if err := newHTTP(t, cfg).Ping(context.Background()); err != nil {
		t.Errorf("TLS dial ping: %v", err)
	}
	cfg.CAPEM = nil
	if err := newHTTP(t, cfg).Ping(context.Background()); err == nil {
		t.Error("TLS dial ping with an untrusted certificate succeeded")
	}
	if n := len(e.requests()) + len(tlsEngine.requests()); n != 0 {
		t.Errorf("dial ping sent %d requests", n)
	}
	// Default ports.
	var dialed []string
	for _, raw := range []string{"http://engine.example.com/scan", "https://engine.example.com/scan", "http://[::1]:81/"} {
		cfg := restConfig(t, raw)
		cfg.dial = func(_ context.Context, _, addr string) (net.Conn, error) {
			dialed = append(dialed, addr)
			return nil, errors.New("no network in tests")
		}
		if err := newHTTP(t, cfg).Ping(context.Background()); err == nil {
			t.Errorf("%s: ping succeeded", raw)
		}
	}
	if want := "engine.example.com:80 engine.example.com:443 [::1]:81"; strings.Join(dialed, " ") != want {
		t.Errorf("dialed %v, want %s", dialed, want)
	}
}

func TestHTTPFraming(t *testing.T) {
	c := newHTTP(t, restConfig(t, "http://engine.example.com/scan"))
	head, tail, ct := c.framing()
	_, boundary, _ := strings.Cut(ct, "boundary=")
	if !strings.HasPrefix(ct, "multipart/form-data; boundary=") || !bytes.HasPrefix(head, []byte("--"+boundary+"\r\n")) ||
		string(tail) != "\r\n--"+boundary+"--\r\n" || len(boundary) > 70 {
		t.Errorf("framing = %q %q %q", head, tail, ct)
	}
}

// roundTripFunc is an http.RoundTripper that does not touch the network.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestHTTPScanInternalFailures(t *testing.T) {
	t.Run("invalid method", func(t *testing.T) {
		c := newHTTP(t, restConfig(t, "http://engine.example.com/scan"))
		c.method = "bad method"
		_, err := httpScan(t, c, []byte("abc"))
		assertProtocol(t, err)
	})
	t.Run("source fails after the engine answered", func(t *testing.T) {
		// The transport answers after the body read failed on the source
		// error: that error still wins over the answer.
		cfg := restConfig(t, "http://engine.example.com/scan")
		c := newHTTP(t, cfg)
		c.http = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			_, _ = io.Copy(io.Discard, r.Body)
			return &http.Response{
				StatusCode: http.StatusOK, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
				Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"Status":"OK"}`)), Request: r,
			}, nil
		})}
		res, err := c.Scan(context.Background(), iotest.ErrReader(errors.New("disk")), 10)
		if !errors.Is(err, ErrSource) || res != (Result{}) {
			t.Fatalf("Scan = %+v, %v", res, err)
		}
	})
	t.Run("invalid health URL", func(t *testing.T) {
		c := newHTTP(t, restConfig(t, "http://engine.example.com/scan"))
		c.healthURL = &url.URL{Scheme: "http", Host: "bad host"}
		if err := c.pingHealth(context.Background()); err == nil || strings.Contains(err.Error(), secretValue) {
			t.Fatalf("pingHealth = %v", err)
		}
	})
}
