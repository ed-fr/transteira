package antivirus

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"

	"github.com/ed-fr/transteira/internal/antivirus/antivirustest"
)

const icapService = "/avscan"

func newICAP(t *testing.T, srv *antivirustest.ICAPServer, opts ...ICAPOption) *ICAPClient {
	t.Helper()
	c, err := NewICAPClient(srv.URL(icapService), opts...)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func icapScan(t *testing.T, c *ICAPClient, data []byte) (Result, error) {
	t.Helper()
	return c.Scan(context.Background(), bytes.NewReader(data), int64(len(data)))
}

func assertProtocol(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrProtocol) || errors.Is(err, ErrUnavailable) || errors.Is(err, ErrSource) || errors.Is(err, ErrTimeout) {
		t.Fatalf("Scan = %v, want only ErrProtocol", err)
	}
}

// icapClosedAddr returns a local address nobody listens on.
func icapClosedAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func TestNewICAPClientDefaultsAndOptions(t *testing.T) {
	c, err := NewICAPClient("icap://av.example.com/avscan")
	if err != nil {
		t.Fatal(err)
	}
	if c.address != "av.example.com:1344" || c.uri != "icap://av.example.com/avscan" || c.host != "av.example.com" ||
		c.Host() != "av.example.com" || c.tlsConfig != nil {
		t.Fatalf("client = %+v", c)
	}
	if c.maxScanBytes != DefaultMaxScanBytes || c.scanTimeout != DefaultScanTimeout || c.pingTimeout != DefaultTimeout ||
		c.idleTimeout != DefaultIdleTimeout {
		t.Fatalf("defaults = %+v", c)
	}
	if strings.Join(c.headers, ",") != "X-Infection-Found,X-Virus-Id,X-Violations-Found" {
		t.Fatalf("headers = %v", c.headers)
	}

	c, err = NewICAPClient("icaps://av.example.com:9999/av/scan", WithICAPMaxScanBytes(0), WithICAPScanTimeout(-1),
		WithICAPPingTimeout(0), WithICAPIdleTimeout(0), WithICAPRootCAs(nil), WithICAPInfectionHeaders(), WithICAPDialer(nil))
	if err != nil {
		t.Fatal(err)
	}
	if c.address != "av.example.com:9999" || c.uri != "icaps://av.example.com:9999/av/scan" || c.maxScanBytes != DefaultMaxScanBytes ||
		c.scanTimeout != DefaultScanTimeout || c.pingTimeout != DefaultTimeout || c.idleTimeout != DefaultIdleTimeout || c.dial == nil {
		t.Fatalf("ignored options changed client: %+v", c)
	}
	if c.tlsConfig == nil || c.tlsConfig.ServerName != "av.example.com" || c.tlsConfig.RootCAs != nil ||
		c.tlsConfig.InsecureSkipVerify || c.tlsConfig.MinVersion < 0x0303 {
		t.Fatalf("tls = %+v", c.tlsConfig)
	}

	c, err = NewICAPClient("ICAPS://[::1]/avscan", WithICAPMaxScanBytes(5), WithICAPScanTimeout(time.Second),
		WithICAPPingTimeout(time.Millisecond), WithICAPIdleTimeout(2*time.Second), WithICAPInfectionHeaders("x-found"))
	if err != nil {
		t.Fatal(err)
	}
	if c.address != "[::1]:11344" || c.maxScanBytes != 5 || c.scanTimeout != time.Second || c.pingTimeout != time.Millisecond ||
		c.idleTimeout != 2*time.Second || len(c.headers) != 1 || c.headers[0] != "X-Found" {
		t.Fatalf("options = %+v", c)
	}
}

func TestNewICAPClientInvalid(t *testing.T) {
	_, caPEM := antivirustest.TLSConfig(t)
	tests := []struct {
		name, url string
		opts      []ICAPOption
	}{
		{"unparsable", "icap://%zz/x", nil},
		{"http scheme", "http://av.example.com/avscan", nil},
		{"no scheme", "av.example.com/avscan", nil},
		{"credentials", "icap://user:secret@av.example.com/avscan", nil},
		{"no host", "icap:///avscan", nil},
		{"opaque", "icap:avscan", nil},
		{"query", "icap://av.example.com/avscan?x=1", nil},
		{"empty query", "icap://av.example.com/avscan?", nil},
		{"fragment", "icap://av.example.com/avscan#x", nil},
		{"no service", "icap://av.example.com", nil},
		{"root service", "icap://av.example.com/", nil},
		{"port zero", "icap://av.example.com:0/avscan", nil},
		{"port too large", "icap://av.example.com:70000/avscan", nil},
		{"CA with cleartext", "icap://av.example.com/avscan", []ICAPOption{WithICAPRootCAs(caPEM)}},
		{"CA not PEM", "icaps://av.example.com/avscan", []ICAPOption{WithICAPRootCAs([]byte("not a certificate"))}},
		{"bad header name", "icap://av.example.com/avscan", []ICAPOption{WithICAPInfectionHeaders("X Found")}},
		{"empty header name", "icap://av.example.com/avscan", []ICAPOption{WithICAPInfectionHeaders("")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewICAPClient(tt.url, tt.opts...)
			if err == nil {
				t.Fatalf("NewICAPClient(%q) = %+v, want an error", tt.url, c)
			}
			if strings.Contains(err.Error(), "secret") {
				t.Fatalf("error leaks the credentials: %v", err)
			}
		})
	}
}

func TestICAPScanVerdicts(t *testing.T) {
	srv := antivirustest.NewICAP(t)
	c := newICAP(t, srv)

	// Clean (204), several chunks with a short last one.
	data := randomBytes(t, 3*chunkSize+1234)
	res, err := icapScan(t, c, data)
	if err != nil || res != (Result{Verdict: Clean}) {
		t.Fatalf("clean: %+v, %v", res, err)
	}
	reqs := srv.Requests()
	if len(reqs) != 2 || reqs[0].Method != "OPTIONS" || reqs[1].Method != "RESPMOD" {
		t.Fatalf("requests = %+v", reqs)
	}
	r := reqs[1]
	want := fmt.Sprintf(icapReqHeader+icapResHeader, len(data))
	if !r.Complete || !bytes.Equal(r.Body, data) || r.Preview || r.URI != srv.URL(icapService) {
		t.Fatalf("RESPMOD complete %v, equal %v, preview %v, uri %q", r.Complete, bytes.Equal(r.Body, data), r.Preview, r.URI)
	}
	if r.Header.Get("Allow") != "204" || r.Header.Get("Host") != srv.Addr() || r.Header.Get("Encapsulated") != fmt.Sprintf("req-hdr=0, res-hdr=%d, res-body=%d", len(icapReqHeader), len(want)) {
		t.Fatalf("headers = %v", r.Header)
	}
	if string(r.Encapsulated) != want {
		t.Fatalf("encapsulated = %q, want %q", r.Encapsulated, want)
	}

	// Infected: the EICAR string straddles two chunks; the ICAP header
	// gives the signature.
	infected := append(randomBytes(t, chunkSize-10), EICAR()...)
	res, err = icapScan(t, c, infected)
	if err != nil || res != (Result{Verdict: Infected, Signature: antivirustest.EicarSignature}) {
		t.Fatalf("infected: %+v, %v", res, err)
	}

	// Empty content.
	res, err = icapScan(t, c, nil)
	if err != nil || res.Verdict != Clean {
		t.Fatalf("empty: %+v, %v", res, err)
	}

	srv.SetMode(antivirustest.ICAPModeNoContent)
	if res, err = icapScan(t, c, data); err != nil || res.Verdict != Clean {
		t.Fatalf("204: %+v, %v", res, err)
	}
	srv.SetMode(antivirustest.ICAPModeEcho)
	for _, d := range [][]byte{data, nil} {
		if res, err = icapScan(t, c, d); err != nil || res.Verdict != Clean {
			t.Fatalf("echo of %d bytes: %+v, %v", len(d), res, err)
		}
	}
	srv.SetMode(antivirustest.ICAPModeModified)
	for _, d := range [][]byte{data, nil} {
		_, err = icapScan(t, c, d)
		assertProtocol(t, err)
	}
	srv.SetMode(antivirustest.ICAPMode500)
	_, err = icapScan(t, c, data)
	assertProtocol(t, err)
	srv.SetMode(antivirustest.ICAPMode503)
	_, err = icapScan(t, c, data)
	assertNotLost(t, err)
	srv.SetMode(antivirustest.ICAPModeClose)
	_, err = icapScan(t, c, data)
	assertLost(t, err)
	srv.SetMode(antivirustest.ICAPModeRaw)
	srv.SetRaw([]byte("this is not ICAP\r\n\r\n"))
	_, err = icapScan(t, c, data)
	assertProtocol(t, err)

	if n := srv.Count("OPTIONS"); n != 1 {
		t.Fatalf("OPTIONS sent %d times, want 1 (cached)", n)
	}
}

func TestICAPScanPreview(t *testing.T) {
	srv := antivirustest.NewICAP(t)
	srv.SetPreview(1024)
	c := newICAP(t, srv)

	last := func() antivirustest.ICAPRequest {
		reqs := srv.Requests()
		return reqs[len(reqs)-1]
	}

	// Fits in the preview: "0; ieof", no 100 Continue.
	small := randomBytes(t, 1000)
	if res, err := icapScan(t, c, small); err != nil || res.Verdict != Clean {
		t.Fatalf("small: %+v, %v", res, err)
	}
	if r := last(); !r.Preview || !r.IEOF || r.Continued || !bytes.Equal(r.Body, small) || r.Header.Get("Preview") != "1000" {
		t.Fatalf("small request = %+v", r)
	}

	// Larger than the preview: 100 Continue then the rest.
	big := randomBytes(t, 2*chunkSize+7)
	if res, err := icapScan(t, c, big); err != nil || res.Verdict != Clean {
		t.Fatalf("big: %+v, %v", res, err)
	}
	if r := last(); !r.Preview || r.IEOF || !r.Continued || !bytes.Equal(r.Body, big) || r.Header.Get("Preview") != "1024" {
		t.Fatalf("big request: preview %v ieof %v continued %v equal %v", r.Preview, r.IEOF, r.Continued, bytes.Equal(r.Body, big))
	}
	infected := append(randomBytes(t, 3000), EICAR()...)
	if res, err := icapScan(t, c, infected); err != nil || res.Verdict != Infected {
		t.Fatalf("infected after preview: %+v, %v", res, err)
	}
	srv.SetMode(antivirustest.ICAPModeEcho)
	if res, err := icapScan(t, c, big); err != nil || res.Verdict != Clean {
		t.Fatalf("echo after preview: %+v, %v", res, err)
	}

	// Final reply to the preview alone.
	srv.SetMode(antivirustest.ICAPModeScan)
	srv.SetEarlyVerdict(true)
	if res, err := icapScan(t, c, big); err != nil || res.Verdict != Clean {
		t.Fatalf("early 204: %+v, %v", res, err)
	}
	if r := last(); r.Continued || len(r.Body) != 1024 {
		t.Fatalf("early request: continued %v, %d bytes", r.Continued, len(r.Body))
	}
	early := append(EICAR(), randomBytes(t, 5000)...)
	if res, err := icapScan(t, c, early); err != nil || res.Verdict != Infected {
		t.Fatalf("early infected: %+v, %v", res, err)
	}

	// Preview: 0 sends no byte before 100 Continue.
	srv.SetEarlyVerdict(false)
	srv.SetPreview(0)
	c = newICAP(t, srv)
	if res, err := icapScan(t, c, small); err != nil || res.Verdict != Clean {
		t.Fatalf("preview 0: %+v, %v", res, err)
	}
	if r := last(); !r.Continued || r.Header.Get("Preview") != "0" || !bytes.Equal(r.Body, small) {
		t.Fatalf("preview 0 request = %+v", r)
	}
	if res, err := icapScan(t, c, nil); err != nil || res.Verdict != Clean {
		t.Fatalf("preview 0, empty: %+v, %v", res, err)
	}
	if r := last(); !r.IEOF || r.Continued {
		t.Fatalf("preview 0, empty request = %+v", r)
	}
}

func TestICAPPing(t *testing.T) {
	srv := antivirustest.NewICAP(t)
	srv.SetPreview(1 << 20)
	srv.SetOptionsTTL(60)
	c := newICAP(t, srv)
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	c.now = func() time.Time { return now }

	if err := c.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c.options.preview != maxICAPPreview || !c.options.expires.Equal(now.Add(time.Minute)) {
		t.Fatalf("options = %+v", c.options)
	}
	r := srv.Requests()[0]
	if r.Method != "OPTIONS" || r.URI != srv.URL(icapService) || r.Header.Get("Host") != srv.Addr() {
		t.Fatalf("request = %+v", r)
	}

	// Scans use the cached reply until it expires.
	data := randomBytes(t, 10)
	for range 2 {
		if _, err := icapScan(t, c, data); err != nil {
			t.Fatal(err)
		}
	}
	if n := srv.Count("OPTIONS"); n != 1 {
		t.Fatalf("OPTIONS sent %d times, want 1", n)
	}
	now = now.Add(time.Minute)
	if _, err := icapScan(t, c, data); err != nil {
		t.Fatal(err)
	}
	if n := srv.Count("OPTIONS"); n != 2 {
		t.Fatalf("OPTIONS sent %d times after expiry, want 2", n)
	}

	srv.SetOptions(200, "REQMOD, RESPMOD")
	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("methods list: %v", err)
	}
	srv.SetOptions(200, "REQMOD")
	if err := c.Ping(context.Background()); !errors.Is(err, ErrProtocol) {
		t.Fatalf("no RESPMOD: %v", err)
	}
	srv.SetOptions(500, "RESPMOD")
	if err := c.Ping(context.Background()); !errors.Is(err, ErrProtocol) || errors.Is(err, ErrUnavailable) {
		t.Fatalf("500: %v", err)
	}
	srv.SetOptions(503, "RESPMOD")
	if err := c.Ping(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("503: %v", err)
	}

	// A broken OPTIONS reply makes Scan report the engine unavailable,
	// never a protocol error counted against the file.
	srv.SetOptions(500, "RESPMOD")
	now = now.Add(time.Hour)
	_, err := icapScan(t, c, data)
	assertNotLost(t, err)

	srv.Stop()
	if err := c.Ping(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("stopped: %v", err)
	}
}

func TestParseOptions(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	head := func(lines ...string) icapHead {
		h := textproto.MIMEHeader{"Methods": {"RESPMOD"}}
		for _, l := range lines {
			k, v, _ := strings.Cut(l, ": ")
			h.Add(k, v)
		}
		return icapHead{status: 200, header: h}
	}
	o, err := parseOptions(head(), now, "h")
	if err != nil || o.preview != -1 || !o.expires.Equal(now.Add(DefaultOptionsTTL)) {
		t.Fatalf("defaults = %+v, %v", o, err)
	}
	o, err = parseOptions(head("Preview: 4096", "Options-TTL: 999999999"), now, "h")
	if err != nil || o.preview != 4096 || !o.expires.Equal(now.Add(maxOptionsTTL)) {
		t.Fatalf("capped = %+v, %v", o, err)
	}
	for _, bad := range [][]string{
		{"Preview: -1"},
		{"Preview: x"},
		{"Preview: 1", "Preview: 2"},
		{"Preview: 9999999999"},
		{"Options-TTL: 1h"},
		{"Options-TTL: 1", "Options-TTL: 2"},
	} {
		if _, err := parseOptions(head(bad...), now, "h"); !errors.Is(err, ErrProtocol) {
			t.Errorf("%v: %v", bad, err)
		}
	}
}

// icapRaw returns a client of a fake server answering every RESPMOD with
// reply (no preview).
func icapRaw(t *testing.T, reply string) *ICAPClient {
	t.Helper()
	srv := antivirustest.NewICAP(t)
	srv.SetMode(antivirustest.ICAPModeRaw)
	srv.SetRaw([]byte(reply))
	return newICAP(t, srv)
}

// echoReply builds an ICAP 200 reply carrying res and body (chunked as
// given).
func echoReply(icapHeaders, res string, chunks ...string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "ICAP/1.0 200 OK\r\n%sEncapsulated: res-hdr=0, res-body=%d\r\n\r\n%s", icapHeaders, len(res), res)
	for _, c := range chunks {
		fmt.Fprintf(&b, "%x\r\n%s\r\n", len(c), c)
	}
	b.WriteString("0\r\n\r\n")
	return b.String()
}

func TestICAPReplies(t *testing.T) {
	const content = "hello world"
	okRes := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", len(content))
	reqHdr := "GET / HTTP/1.1\r\n\r\n"
	withReq := fmt.Sprintf("ICAP/1.0 200 OK\r\nEncapsulated: req-hdr=0, res-hdr=%d, res-body=%d\r\n\r\n%s%s5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
		len(reqHdr), len(reqHdr)+len("HTTP/1.0 200 OK\r\n\r\n"), reqHdr, "HTTP/1.0 200 OK\r\n\r\n")
	folded := "ICAP/1.0 200 OK\r\nX-Violations-Found: 1\r\n\teicar.com\r\n\tEICAR-Test-File\r\n\t0\r\n\t0\r\nEncapsulated: null-body=0\r\n\r\n"
	resInfected := "HTTP/1.1 403 Forbidden\r\nX-Virus-ID: Win.Trojan.Agent\r\n\r\n"
	manyHeaders := "ICAP/1.0 204 No Content\r\n" + strings.Repeat("X-Pad: "+strings.Repeat("a", 1000)+"\r\n", 17) + "\r\n"

	clean := Result{Verdict: Clean}
	tests := []struct {
		name, reply string
		want        Result // zero: ErrProtocol expected
	}{
		{"204 bare", "ICAP/1.0 204 No Content\r\n\r\n", clean},
		{"204 null-body", "ICAP/1.0 204\r\nEncapsulated: null-body=0\r\n\r\n", clean},
		{"echo", echoReply("", okRes, "hello", " world"), clean},
		{"echo without Content-Length", echoReply("", "HTTP/1.1 206 Partial\r\n\r\n", content), clean},
		{"echo with req-hdr", withReq, clean},
		{
			"infected, threat field", "ICAP/1.0 200 OK\r\nX-Infection-Found: Type=0; Resolution=2; Threat=Bad.Sig;\r\nEncapsulated: null-body=0\r\n\r\n",
			Result{Verdict: Infected, Signature: "Bad.Sig"},
		},
		{"infected on 204", "ICAP/1.0 204 No Content\r\nx-virus-id: Some Virus\r\n\r\n", Result{Verdict: Infected, Signature: "Some Virus"}},
		{"infected on 500", "ICAP/1.0 500 Error\r\nX-Virus-ID: V\r\n\r\n", Result{Verdict: Infected, Signature: "V"}},
		{"infected, empty value", "ICAP/1.0 200 OK\r\nX-Infection-Found:\r\nEncapsulated: null-body=0\r\n\r\n", Result{Verdict: Infected, Signature: "unknown"}},
		{"infected, hostile value", "ICAP/1.0 200 OK\r\nX-Virus-ID: \xe2\x80\x8b\r\n\r\n", Result{Verdict: Infected, Signature: "unknown"}},
		{"infected, folded violations", folded, Result{Verdict: Infected, Signature: "EICAR-Test-File"}},
		{
			"infected in HTTP headers", fmt.Sprintf("ICAP/1.0 200 OK\r\nEncapsulated: res-hdr=0, res-body=%d\r\n\r\n%s4\r\nnope\r\n0\r\n\r\n", len(resInfected), resInfected),
			Result{Verdict: Infected, Signature: "Win.Trojan.Agent"},
		},
		{
			"infected in 204 HTTP headers", fmt.Sprintf("ICAP/1.0 204 No Content\r\nEncapsulated: res-hdr=0, null-body=%d\r\n\r\n%s", len(resInfected), resInfected),
			Result{Verdict: Infected, Signature: "Win.Trojan.Agent"},
		},
		{"204 with a body", "ICAP/1.0 204 No Content\r\nEncapsulated: res-body=0\r\n\r\n0\r\n\r\n", Result{}},
		{"200 null-body", "ICAP/1.0 200 OK\r\nEncapsulated: null-body=0\r\n\r\n", Result{}},
		{"200 without Encapsulated", "ICAP/1.0 200 OK\r\n\r\n", Result{}},
		{"200 body without res-hdr", "ICAP/1.0 200 OK\r\nEncapsulated: res-body=0\r\n\r\nb\r\nhello world\r\n0\r\n\r\n", Result{}},
		{"200 with HTTP 403", echoReply("", "HTTP/1.1 403 Forbidden\r\n\r\n", content), Result{}},
		{"200 with HTTP 199", echoReply("", "HTTP/1.1 199 Odd\r\n\r\n", content), Result{}},
		{"modified body", echoReply("", okRes, "hello", " worle"), Result{}},
		{"longer body", echoReply("", "HTTP/1.1 200 OK\r\n\r\n", content, "!"), Result{}},
		{"shorter body", echoReply("", "HTTP/1.1 200 OK\r\n\r\n", "hello"), Result{}},
		{"wrong Content-Length", echoReply("", "HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n", content), Result{}},
		{"transfer encoding", echoReply("", "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n", content), Result{}},
		{"ICAP Content-Length", "ICAP/1.0 204 No Content\r\nContent-Length: 0\r\n\r\n", Result{}},
		{"two Encapsulated", "ICAP/1.0 204\r\nEncapsulated: null-body=0\r\nEncapsulated: null-body=0\r\n\r\n", Result{}},
		{"Encapsulated offset too large", "ICAP/1.0 200 OK\r\nEncapsulated: res-hdr=0, res-body=99\r\n\r\nHTTP/1.1 200 OK\r\n\r\n0\r\n\r\n", Result{}},
		{"Encapsulated offset too small", "ICAP/1.0 200 OK\r\nEncapsulated: res-hdr=0, res-body=5\r\n\r\nHTTP/1.1 200 OK\r\n\r\n0\r\n\r\n", Result{}},
		{"Encapsulated req-body", "ICAP/1.0 200 OK\r\nEncapsulated: req-body=0\r\n\r\n0\r\n\r\n", Result{}},
		{"encapsulated head too long", "ICAP/1.0 200 OK\r\nEncapsulated: res-hdr=0, res-body=20000\r\n\r\n", Result{}},
		{"bad HTTP status line", echoReply("", "HTTP/2 200 OK\r\n\r\n", content), Result{}},
		{"bad request line", "ICAP/1.0 200 OK\r\nEncapsulated: req-hdr=0, null-body=2\r\n\r\n\r\n", Result{}},
		{"bad chunk size", "ICAP/1.0 200 OK\r\nEncapsulated: res-hdr=0, res-body=19\r\n\r\nHTTP/1.1 200 OK\r\n\r\nzz\r\n", Result{}},
		{"chunk without CRLF", "ICAP/1.0 200 OK\r\nEncapsulated: res-hdr=0, res-body=19\r\n\r\nHTTP/1.1 200 OK\r\n\r\n2\r\nhexx", Result{}},
		{"trailer", "ICAP/1.0 200 OK\r\nEncapsulated: res-hdr=0, res-body=19\r\n\r\nHTTP/1.1 200 OK\r\n\r\nb\r\nhello world\r\n0\r\nX: y\r\n\r\n", Result{}},
		{"line too long", "ICAP/1.0 204 No Content\r\nX-Pad: " + strings.Repeat("a", maxICAPLineLen) + "\r\n\r\n", Result{}},
		{"head too long", manyHeaders, Result{}},
		{"garbage status", "HTTP/1.1 200 OK\r\n\r\n", Result{}},
		{"status without code", "ICAP/1.0 2x4\r\n\r\n", Result{}},
		{"status code glued", "ICAP/1.0 2040\r\n\r\n", Result{}},
		{"LF only", "ICAP/1.0 204 No Content\n\n", Result{}},
		{"folded first header", "ICAP/1.0 204 No Content\r\n x: y\r\n\r\n", Result{}},
		{"bad header name", "ICAP/1.0 204 No Content\r\nBad Name: y\r\n\r\n", Result{}},
		{"control in header", "ICAP/1.0 204 No Content\r\nX: a\x00b\r\n\r\n", Result{}},
		{"unexpected 100", "ICAP/1.0 100 Continue\r\n\r\n", Result{}},
		{"unexpected 404", "ICAP/1.0 404 Not Found\r\n\r\n", Result{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := icapScan(t, icapRaw(t, tt.reply), []byte(content))
			if tt.want == (Result{}) {
				assertProtocol(t, err)
				return
			}
			if err != nil || res != tt.want {
				t.Fatalf("Scan = %+v, %v, want %+v", res, err, tt.want)
			}
		})
	}

	// A reply cut in the middle is a lost connection.
	for _, cut := range []string{"ICAP/1.0 204", "ICAP/1.0 204 No Content\r\nX: y", echoReply("", okRes, "hello")[:60]} {
		_, err := icapScan(t, icapRaw(t, cut), []byte(content))
		assertLost(t, err)
	}
}

func TestICAPScanSize(t *testing.T) {
	srv := antivirustest.NewICAP(t)
	c := newICAP(t, srv, WithICAPMaxScanBytes(100))
	res, err := c.Scan(context.Background(), iotest.ErrReader(errors.New("must not be read")), 101)
	if err != nil || res != (Result{Verdict: TooLarge, Detail: DetailClientLimit}) {
		t.Fatalf("over limit: %+v, %v", res, err)
	}
	if n := len(srv.Requests()); n != 0 {
		t.Fatalf("server contacted %d times", n)
	}
	if res, err := icapScan(t, c, randomBytes(t, 100)); err != nil || res.Verdict != Clean {
		t.Fatalf("at limit: %+v, %v", res, err)
	}
	if _, err := c.Scan(context.Background(), bytes.NewReader(nil), -1); !errors.Is(err, ErrSource) {
		t.Fatalf("negative size = %v", err)
	}
}

func TestICAPScanSourceErrors(t *testing.T) {
	errRead := errors.New("decrypt failed")
	data := randomBytes(t, chunkSize+10)
	for _, preview := range []int{-1, 100, 2 * chunkSize} {
		srv := antivirustest.NewICAP(t)
		srv.SetPreview(preview)
		c := newICAP(t, srv)
		tests := []struct {
			name string
			r    io.Reader
			size int64
			want error
		}{
			{"shorter", bytes.NewReader(data), int64(len(data)) + 1, nil},
			{"longer", bytes.NewReader(data), int64(len(data)) - 1, nil},
			{"read error", io.MultiReader(bytes.NewReader(data[:100]), iotest.ErrReader(errRead)), int64(len(data)), errRead},
			{"error after the content", &probeErrReader{data: data, err: errRead}, int64(len(data)), errRead},
		}
		for _, tt := range tests {
			t.Run(fmt.Sprintf("preview %d/%s", preview, tt.name), func(t *testing.T) {
				_, err := c.Scan(context.Background(), tt.r, tt.size)
				if !errors.Is(err, ErrSource) || errors.Is(err, ErrUnavailable) || errors.Is(err, ErrProtocol) {
					t.Fatalf("Scan = %v, want only ErrSource", err)
				}
				if tt.want != nil && !errors.Is(err, tt.want) {
					t.Fatalf("Scan = %v, want %v", err, tt.want)
				}
			})
		}
	}
}

func TestICAPScanTimeouts(t *testing.T) {
	t.Run("hang", func(t *testing.T) {
		srv := antivirustest.NewICAP(t)
		srv.SetMode(antivirustest.ICAPModeHang)
		c := newICAP(t, srv, WithICAPScanTimeout(200*time.Millisecond))
		_, err := icapScan(t, c, randomBytes(t, 1000))
		assertTimeout(t, err)
	})
	t.Run("idle", func(t *testing.T) {
		// The server reads the request head and stops reading.
		c := pipeICAPClient(t, func(net.Conn, *bufio.Reader) { <-t.Context().Done() }, WithICAPIdleTimeout(100*time.Millisecond))
		start := time.Now()
		_, err := icapScan(t, c, randomBytes(t, 4*chunkSize))
		assertTimeout(t, err)
		if d := time.Since(start); d > 5*time.Second {
			t.Fatalf("Scan took %v", d)
		}
	})
	t.Run("canceled", func(t *testing.T) {
		srv := antivirustest.NewICAP(t)
		srv.SetMode(antivirustest.ICAPModeHang)
		c := newICAP(t, srv)
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(100*time.Millisecond, cancel)
		_, err := c.Scan(ctx, bytes.NewReader(make([]byte, 10)), 10)
		assertUnavailable(t, err)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Scan = %v, want context.Canceled", err)
		}
	})
	t.Run("canceled before dial", func(t *testing.T) {
		srv := antivirustest.NewICAP(t)
		c := newICAP(t, srv)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := c.Scan(ctx, bytes.NewReader(nil), 0)
		assertNotLost(t, err)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Scan = %v, want context.Canceled", err)
		}
	})
	t.Run("ping timeout", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				t.Cleanup(func() { _ = conn.Close() })
			}
		}()
		c, err := NewICAPClient("icap://"+ln.Addr().String()+icapService, WithICAPPingTimeout(100*time.Millisecond))
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Ping(context.Background()); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("Ping = %v", err)
		}
	})
}

func TestICAPScanDialError(t *testing.T) {
	c, err := NewICAPClient("icap://" + icapClosedAddr(t) + icapService)
	if err != nil {
		t.Fatal(err)
	}
	_, err = icapScan(t, c, []byte("x"))
	assertNotLost(t, err)
	if err := c.Ping(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Ping = %v", err)
	}

	// The OPTIONS reply is cached: the RESPMOD dial fails on its own.
	srv := antivirustest.NewICAP(t)
	c = newICAP(t, srv)
	if err := c.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
	srv.Stop()
	_, err = icapScan(t, c, []byte("x"))
	assertNotLost(t, err)
}

// pipeICAPClient returns a client whose connections are in-memory pipes:
// OPTIONS is answered (no preview), RESPMOD is handed to handle after its
// ICAP head.
func pipeICAPClient(t *testing.T, handle func(net.Conn, *bufio.Reader), opts ...ICAPOption) *ICAPClient {
	t.Helper()
	return scriptedICAPClient(t, optionsOK, nil, handle, opts...)
}

// scriptedICAPClient is pipeICAPClient with the OPTIONS reply given and,
// when wrap is not nil, each client connection passed through wrap (n is the
// 1-based number of the dial).
func scriptedICAPClient(t *testing.T, optionsReply string, wrap func(n int, c net.Conn) net.Conn,
	handle func(net.Conn, *bufio.Reader), opts ...ICAPOption,
) *ICAPClient {
	t.Helper()
	var dials atomic.Int32
	dial := func(context.Context, string, string) (net.Conn, error) {
		n := int(dials.Add(1))
		client, server := net.Pipe()
		t.Cleanup(func() { _ = server.Close() })
		go func() {
			br := bufio.NewReader(server)
			tp := textproto.NewReader(br)
			line, err := tp.ReadLine()
			if err != nil {
				return
			}
			if _, err := tp.ReadMIMEHeader(); err != nil {
				return
			}
			if strings.HasPrefix(line, "OPTIONS ") {
				_, _ = io.WriteString(server, optionsReply)
				return
			}
			handle(server, br)
		}()
		if wrap != nil {
			return wrap(n, client), nil
		}
		return client, nil
	}
	c, err := NewICAPClient("icap://pipe"+icapService, append([]ICAPOption{WithICAPDialer(dial)}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// failConn is a connection whose deadline setters or Write fail.
type failConn struct {
	net.Conn
	setDeadline, setReadDeadline, setWriteDeadline, write bool
}

var errInjected = errors.New("injected failure")

func (f failConn) SetDeadline(t time.Time) error {
	if f.setDeadline {
		return errInjected
	}
	return f.Conn.SetDeadline(t)
}

func (f failConn) SetReadDeadline(t time.Time) error {
	if f.setReadDeadline {
		return errInjected
	}
	return f.Conn.SetReadDeadline(t)
}

func (f failConn) SetWriteDeadline(t time.Time) error {
	if f.setWriteDeadline {
		return errInjected
	}
	return f.Conn.SetWriteDeadline(t)
}

func (f failConn) Write(p []byte) (int, error) {
	if f.write {
		return 0, errInjected
	}
	return f.Conn.Write(p)
}

const optionsOK = "ICAP/1.0 200 OK\r\nMethods: RESPMOD\r\n\r\n"

func hold(t *testing.T) func(net.Conn, *bufio.Reader) {
	return func(net.Conn, *bufio.Reader) { <-t.Context().Done() }
}

func TestICAPOptionsFailures(t *testing.T) {
	cases := map[string]struct {
		reply    string
		conn     failConn
		protocol bool
	}{
		"set deadline": {reply: optionsOK, conn: failConn{setDeadline: true}},
		"write":        {reply: optionsOK, conn: failConn{write: true}},
		"garbage":      {reply: "garbage\r\n\r\n", protocol: true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			wrap := func(_ int, c net.Conn) net.Conn {
				tc.conn.Conn = c
				return tc.conn
			}
			c := scriptedICAPClient(t, tc.reply, wrap, hold(t))
			err := c.Ping(context.Background())
			if tc.protocol {
				assertProtocolWrapped(t, err)
				return
			}
			assertNotLost(t, err)
		})
	}
}

func assertProtocolWrapped(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrProtocol) {
		t.Fatalf("error = %v, want ErrProtocol", err)
	}
}

func TestICAPScanExchangeFailures(t *testing.T) {
	data := []byte("12345678")
	preview := "ICAP/1.0 200 OK\r\nMethods: RESPMOD\r\nPreview: 4\r\n\r\n"
	headLen := len(icapReqHeader) + len(fmt.Sprintf(icapResHeader, len(data)))
	okRes := "HTTP/1.1 200 OK\r\n\r\n"

	t.Run("read deadline cannot be set", func(t *testing.T) {
		wrap := func(n int, c net.Conn) net.Conn {
			if n == 2 {
				return failConn{Conn: c, setReadDeadline: true}
			}
			return c
		}
		c := scriptedICAPClient(t, optionsOK, wrap, hold(t))
		_, err := icapScan(t, c, data)
		assertUnavailable(t, err)
	})
	t.Run("head cannot be written", func(t *testing.T) {
		c := pipeICAPClient(t, func(conn net.Conn, _ *bufio.Reader) { _ = conn.Close() })
		_, err := icapScan(t, c, data)
		assertUnavailable(t, err)
	})
	t.Run("head write fails while the server stays silent", func(t *testing.T) {
		// The reply wait ends only after the sender failed: its error path
		// always runs before Scan returns.
		wrap := func(n int, c net.Conn) net.Conn {
			if n == 2 {
				return failConn{Conn: c, write: true}
			}
			return c
		}
		c := scriptedICAPClient(t, optionsOK, wrap, hold(t))
		_, err := icapScan(t, c, data)
		assertUnavailable(t, err)
	})
	t.Run("write deadline cannot be set", func(t *testing.T) {
		wrap := func(n int, c net.Conn) net.Conn {
			if n == 2 {
				return failConn{Conn: c, setWriteDeadline: true}
			}
			return c
		}
		c := scriptedICAPClient(t, optionsOK, wrap, hold(t))
		_, err := icapScan(t, c, data)
		assertUnavailable(t, err)
	})
	t.Run("preview terminator cannot be written", func(t *testing.T) {
		c := scriptedICAPClient(t, preview, nil, func(conn net.Conn, br *bufio.Reader) {
			_, _ = io.ReadFull(br, make([]byte, headLen+len("4\r\n")+4+2))
			_ = conn.Close()
		})
		_, err := icapScan(t, c, data)
		assertUnavailable(t, err)
	})
	t.Run("200 to a preview", func(t *testing.T) {
		c := scriptedICAPClient(t, preview, nil, func(conn net.Conn, _ *bufio.Reader) {
			_, _ = io.WriteString(conn, echoReply("", okRes, "1234"))
			<-t.Context().Done()
		})
		_, err := icapScan(t, c, data)
		assertProtocol(t, err)
	})
	t.Run("echo then the sender fails", func(t *testing.T) {
		c := pipeICAPClient(t, func(conn net.Conn, _ *bufio.Reader) {
			_, _ = io.WriteString(conn, echoReply("", okRes, string(data)))
			_ = conn.Close()
		})
		_, err := icapScan(t, c, data)
		assertUnavailable(t, err)
	})
	t.Run("204 then the source fails", func(t *testing.T) {
		// The source fails only once the client has read the 204, so that
		// the verdict, not the expired connection, meets the source error.
		got := make(chan struct{})
		wrap := func(n int, c net.Conn) net.Conn {
			if n == 2 {
				return &signalConn{Conn: c, got: got}
			}
			return c
		}
		c := scriptedICAPClient(t, optionsOK, wrap, func(conn net.Conn, br *bufio.Reader) {
			_, _ = io.WriteString(conn, "ICAP/1.0 204 No Content\r\n\r\n")
			_, _ = io.Copy(io.Discard, br)
		})
		src := readerFunc(func([]byte) (int, error) {
			<-got
			return 0, errors.New("disk")
		})
		_, err := c.Scan(context.Background(), src, int64(len(data)))
		if !errors.Is(err, ErrSource) {
			t.Fatalf("Scan = %v, want ErrSource", err)
		}
	})
}

// signalConn closes got after its first successful read.
type signalConn struct {
	net.Conn
	got  chan struct{}
	once sync.Once
}

func (s *signalConn) Read(p []byte) (int, error) {
	n, err := s.Conn.Read(p)
	if n > 0 {
		s.once.Do(func() { close(s.got) })
	}
	return n, err
}

// readerFunc adapts a function to io.Reader.
type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) { return f(p) }

func TestICAPExchangeTryWaitFinished(t *testing.T) {
	x := &icapExchange{finished: true, werr: errInjected}
	if ok, err := x.tryWait(); !ok || !errors.Is(err, errInjected) {
		t.Fatalf("tryWait = %t, %v", ok, err)
	}
}

func TestICAPParserBounds(t *testing.T) {
	br := func(s string) *bufio.Reader { return bufio.NewReader(strings.NewReader(s)) }

	head := icapHead{status: 200, header: textproto.MIMEHeader{"Encapsulated": {"bogus=0"}}}
	if _, err := readRESPMODReply(br(""), head); !errors.Is(err, ErrProtocol) {
		t.Errorf("readRESPMODReply with a bad Encapsulated = %v", err)
	}
	line := "HTTP/1.1 200 OK\r\nno colon here\r\n\r\n"
	if _, _, err := readEncapsulatedHead(br(line), len(line), true); !errors.Is(err, ErrProtocol) {
		t.Errorf("readEncapsulatedHead with a bad header = %v", err)
	}
	if _, _, err := readHeaderBlock(br("\r\n"), 1); !errors.Is(err, ErrProtocol) {
		t.Errorf("readHeaderBlock with no budget = %v", err)
	}
	if err := readChunkedEnd(br("")); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("readChunkedEnd at EOF = %v", err)
	}
	if err := readChunkedEnd(bufio.NewReader(iotest.ErrReader(errInjected))); !errors.Is(err, errInjected) {
		t.Errorf("readChunkedEnd with a read error = %v", err)
	}
	if err := readChunkedEnd(br("trailer\r\n")); !errors.Is(err, ErrProtocol) {
		t.Errorf("readChunkedEnd with a trailer = %v", err)
	}
}

func TestICAPScanEarlyReplies(t *testing.T) {
	data := randomBytes(t, 8*chunkSize)
	t.Run("204 then reads everything", func(t *testing.T) {
		c := pipeICAPClient(t, func(conn net.Conn, br *bufio.Reader) {
			_, _ = io.WriteString(conn, "ICAP/1.0 204 No Content\r\n\r\n")
			_, _ = io.Copy(io.Discard, br)
		})
		if res, err := icapScan(t, c, data); err != nil || res.Verdict != Clean {
			t.Fatalf("Scan = %+v, %v", res, err)
		}
	})
	t.Run("204 then closes", func(t *testing.T) {
		c := pipeICAPClient(t, func(conn net.Conn, _ *bufio.Reader) {
			_, _ = io.WriteString(conn, "ICAP/1.0 204 No Content\r\n\r\n")
			_ = conn.Close()
		})
		_, err := icapScan(t, c, data)
		assertProtocol(t, err)
	})
	t.Run("infected then closes", func(t *testing.T) {
		c := pipeICAPClient(t, func(conn net.Conn, _ *bufio.Reader) {
			_, _ = io.WriteString(conn, "ICAP/1.0 403 Forbidden\r\nX-Infection-Found: Type=0; Threat=Early;\r\n\r\n")
			_ = conn.Close()
		})
		if res, err := icapScan(t, c, data); err != nil || res != (Result{Verdict: Infected, Signature: "Early"}) {
			t.Fatalf("Scan = %+v, %v", res, err)
		}
	})
	t.Run("503 then stops reading", func(t *testing.T) {
		c := pipeICAPClient(t, func(conn net.Conn, _ *bufio.Reader) {
			_, _ = io.WriteString(conn, "ICAP/1.0 503 Busy\r\n\r\n")
			<-t.Context().Done()
		})
		_, err := icapScan(t, c, data)
		assertNotLost(t, err)
	})
	t.Run("closes while reading", func(t *testing.T) {
		c := pipeICAPClient(t, func(conn net.Conn, br *bufio.Reader) {
			_, _ = br.Discard(1000)
			_ = conn.Close()
		})
		_, err := icapScan(t, c, data)
		assertLost(t, err)
	})
	t.Run("echo streamed while reading", func(t *testing.T) {
		// The server copies the chunked body back as it arrives, so that
		// neither side could finish if writing and reading were sequential.
		c := pipeICAPClient(t, func(conn net.Conn, br *bufio.Reader) {
			enc := make([]byte, len(icapReqHeader)+len(fmt.Sprintf(icapResHeader, len(data))))
			if _, err := io.ReadFull(br, enc); err != nil {
				return
			}
			res := enc[len(icapReqHeader):]
			_, _ = fmt.Fprintf(conn, "ICAP/1.0 200 OK\r\nEncapsulated: res-hdr=0, res-body=%d\r\n\r\n%s", len(res), res)
			_, _ = io.Copy(conn, br)
		})
		if res, err := icapScan(t, c, data); err != nil || res.Verdict != Clean {
			t.Fatalf("Scan = %+v, %v", res, err)
		}
	})
}

func TestICAPTLS(t *testing.T) {
	cfg, caPEM := antivirustest.TLSConfig(t)
	_, otherCA := antivirustest.TLSConfig(t)
	srv := antivirustest.NewICAPTLS(t, cfg)

	c := newICAP(t, srv, WithICAPRootCAs(caPEM))
	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("Ping with the CA: %v", err)
	}
	if res, err := icapScan(t, c, append([]byte("x"), EICAR()...)); err != nil || res.Verdict != Infected {
		t.Fatalf("Scan with the CA: %+v, %v", res, err)
	}

	for name, opts := range map[string][]ICAPOption{
		"system pool": nil,
		"wrong CA":    {WithICAPRootCAs(otherCA)},
	} {
		t.Run(name, func(t *testing.T) {
			c := newICAP(t, srv, opts...)
			if err := c.Ping(context.Background()); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("Ping = %v, want ErrUnavailable", err)
			}
			c.store(icapOptions{preview: -1, expires: time.Now().Add(time.Hour)})
			_, err := icapScan(t, c, []byte("x"))
			assertNotLost(t, err)
		})
	}

	// A cleartext client against the TLS server gets no valid reply.
	c, err := NewICAPClient("icap://"+srv.Addr()+icapService, WithICAPPingTimeout(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Ping(context.Background()); err == nil {
		t.Fatal("cleartext Ping to a TLS server succeeded")
	}
}

func TestInfectionSignature(t *testing.T) {
	long := strings.Repeat("é", MaxSignatureLen)
	tests := []struct{ in, want string }{
		{"Type=0; Resolution=2; Threat=Eicar-Test-Signature;", "Eicar-Test-Signature"},
		{"threat = Win.Test ; Type=0", "Win.Test"},
		{"Type=0; Threat=;", "Type=0; Threat=;"},
		{"Win.Trojan.Agent-1", "Win.Trojan.Agent-1"},
		{"1\nfile.exe\nW32/Bad\n0\n0", "W32/Bad"},
		{"x\ny", "x y"},
		{"Bad\x1b[31m\u202eSig", "Bad[31mSig"},
		{"Threat=" + long, long[:MaxSignatureLen]},
		{"", ""},
	}
	for _, tt := range tests {
		if got := infectionSignature(tt.in); got != tt.want {
			t.Errorf("infectionSignature(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestParseEncapsulated(t *testing.T) {
	valid := map[string]string{
		"null-body=0":                           "null-body@0",
		"res-hdr=0, res-body=10":                "res-hdr@0 res-body@10",
		"REQ-HDR=0,RES-HDR=5,RES-BODY=9":        "req-hdr@0 res-hdr@5 res-body@9",
		"req-hdr=0, res-hdr=37, null-body=128 ": "req-hdr@0 res-hdr@37 null-body@128",
		"opt-body=0":                            "opt-body@0",
	}
	for in, want := range valid {
		parts, err := parseEncapsulated(in)
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		var got []string
		for _, p := range parts {
			got = append(got, fmt.Sprintf("%s@%d", p.name, p.offset))
		}
		if strings.Join(got, " ") != want {
			t.Errorf("%q = %v, want %s", in, got, want)
		}
	}
	for _, in := range []string{
		"", "res-hdr=0", "res-body=0, res-hdr=5", "res-hdr=1, res-body=5", "res-hdr=0, res-body=0",
		"res-hdr=0, res-hdr=5, res-body=9", "res-hdr=0, req-hdr=5, res-body=9", "foo=0", "res-body=-1",
		"res-body", "res-body=x", "res-hdr=0, res-body=99999", "req-hdr=0, res-hdr=1, res-body=2, null-body=3",
		"res-hdr=0, res-body=10, null-body=20",
	} {
		if _, err := parseEncapsulated(in); !errors.Is(err, ErrProtocol) {
			t.Errorf("%q: %v, want ErrProtocol", in, err)
		}
	}
}

func TestChunkedReader(t *testing.T) {
	read := func(in string) (string, error) {
		b, err := io.ReadAll(&chunkedReader{br: bufio.NewReader(strings.NewReader(in))})
		return string(b), err
	}
	for in, want := range map[string]string{
		"0\r\n\r\n":               "",
		"5\r\nhello\r\n0\r\n\r\n": "hello",
		"5;ext=1\r\nhello\r\nA\r\n0123456789\r\n0; ieof\r\n\r\n": "hello0123456789",
		"0000000000000003 \r\nabc\r\n0\r\n\r\n":                  "abc",
	} {
		if got, err := read(in); err != nil || got != want {
			t.Errorf("%q = %q, %v, want %q", in, got, err, want)
		}
	}
	for _, in := range []string{
		"", "5\r\nhel", "5\r\nhello", "5\r\nhello\r\n",
	} {
		if _, err := read(in); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Errorf("%q: %v, want an unexpected EOF", in, err)
		}
	}
	for _, in := range []string{
		"\r\n", "-1\r\n", "+1\r\nx\r\n", "x\r\n", "10000000000000000\r\n", "8000000000000000\r\n",
		"5\r\nhelloXX0\r\n\r\n", "0\r\nTrailer: x\r\n\r\n", "1;\x01\r\nx\r\n", "5\nhello\r\n",
		strings.Repeat("0", 70) + "\r\n",
	} {
		if _, err := read(in); !errors.Is(err, ErrProtocol) {
			t.Errorf("%q: %v, want ErrProtocol", in, err)
		}
	}
	// Errors are sticky and empty reads do nothing.
	cr := &chunkedReader{br: bufio.NewReader(strings.NewReader("x\r\n"))}
	if n, err := cr.Read(nil); n != 0 || err != nil {
		t.Fatalf("empty read = %d, %v", n, err)
	}
	_, err1 := cr.Read(make([]byte, 4))
	_, err2 := cr.Read(make([]byte, 4))
	if err1 == nil || !errors.Is(err2, err1) {
		t.Fatalf("errors = %v, %v", err1, err2)
	}
}

func TestReadCRLFLineLongFragments(t *testing.T) {
	// A line longer than the bufio buffer but within the limit is read in
	// fragments.
	line := strings.Repeat("a", 6000)
	br := bufio.NewReaderSize(strings.NewReader(line+"\r\n"), 16)
	got, err := readCRLFLine(br, maxICAPLineLen)
	if err != nil || string(got) != line {
		t.Fatalf("readCRLFLine = %d bytes, %v", len(got), err)
	}
}

// FuzzICAPResponse feeds arbitrary bytes to the RESPMOD reply parser: the
// ICAP head, the encapsulated heads and the chunked body. It must never
// panic, and never read beyond its bounds.
func FuzzICAPResponse(f *testing.F) {
	f.Add([]byte("ICAP/1.0 204 No Content\r\n\r\n"))
	f.Add([]byte(echoReply("", "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n", "hello")))
	f.Add([]byte("ICAP/1.0 200 OK\r\nX-Violations-Found: 1\r\n\tf\r\n\tT\r\n\t0\r\nEncapsulated: null-body=0\r\n\r\n"))
	f.Add([]byte("ICAP/1.0 200 OK\r\nEncapsulated: req-hdr=0, res-hdr=18, res-body=37\r\n\r\nGET / HTTP/1.1\r\n\r\nHTTP/1.0 200 OK\r\n\r\n0; ieof\r\n\r\n"))
	f.Add([]byte("ICAP/1.0 200 OK\r\nPreview: 1024\r\nMethods: RESPMOD\r\nOptions-TTL: 60\r\n\r\n"))
	c, err := NewICAPClient("icap://fuzz/avscan")
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		br := bufio.NewReaderSize(bytes.NewReader(data), 32<<10)
		head, err := readICAPHead(br)
		if err != nil {
			return
		}
		_, _ = parseOptions(head, time.Now(), "fuzz")
		if sig, ok := c.infection(head.header); ok && (sig == "" || len(sig) > MaxSignatureLen) {
			t.Fatalf("signature %q", sig)
		}
		reply, err := readRESPMODReply(br, head)
		if err != nil {
			return
		}
		if sig, ok := c.infection(reply.httpHeader); ok && (sig == "" || len(sig) > MaxSignatureLen) {
			t.Fatalf("signature %q", sig)
		}
		if reply.body == encResBody {
			_, _ = io.Copy(io.Discard, io.LimitReader(&chunkedReader{br: br}, 1<<20))
		}
	})
}

// FuzzICAPChunked feeds arbitrary bytes to the chunked reader, and checks
// that any content encoded in chunks decodes to itself.
func FuzzICAPChunked(f *testing.F) {
	f.Add([]byte("5\r\nhello\r\n0\r\n\r\n"), []byte("hello"))
	f.Add([]byte("1;ieof\r\nx\r\n0; ieof\r\n\r\n"), []byte{})
	f.Add([]byte("ffffffffffffffff\r\n"), []byte("\r\n0\r\n"))
	f.Fuzz(func(t *testing.T, raw, content []byte) {
		_, _ = io.Copy(io.Discard, io.LimitReader(&chunkedReader{br: bufio.NewReader(bytes.NewReader(raw))}, 1<<20))

		var enc bytes.Buffer
		for rest := content; len(rest) > 0; {
			n := min(len(rest), 7)
			fmt.Fprintf(&enc, "%x\r\n%s\r\n", n, rest[:n])
			rest = rest[n:]
		}
		enc.WriteString("0\r\n\r\n")
		got, err := io.ReadAll(&chunkedReader{br: bufio.NewReader(&enc)})
		if err != nil || !bytes.Equal(got, content) {
			t.Fatalf("round trip of %q = %q, %v", content, got, err)
		}
	})
}
