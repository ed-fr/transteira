//go:build bigfile

package bigfile

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/test/internal/seeded"
)

// HTTPS client of the large-file test: every request goes through Caddy,
// as a browser or an integration script would, with the real host names
// for the TLS server name and the Host header (dialed through Dialer).
// HTTP/1.1 only, without compression, with large buffers; request bodies
// are streamed from test/internal/seeded and response bodies are hashed on
// the fly, never stored.

const (
	// tusVersion is the tus protocol version of TransTeira.
	tusVersion = "1.0.0"
	// adminCookie is the name of the admin session cookie.
	adminCookie = "__Host-tt_admin"
	// ioBuffer is the size of the copy buffers.
	ioBuffer = 1 << 20
	// pollInterval is the period of the state polls (lock release,
	// checkpoint, scan); not a synchronization sleep.
	pollInterval = 250 * time.Millisecond
	// unlockTimeout bounds the wait for the server to notice a cut and
	// checkpoint (TT_UPLOAD_IDLE_TIMEOUT is 60 s by default).
	unlockTimeout = 5 * time.Minute
)

// run carries the test and its report: fatalf records the first failure in
// the report before failing the test.
type run struct {
	t   *testing.T
	rep *Report
}

// fatalf records the failure in the report and stops the test.
func (r *run) fatalf(format string, args ...any) {
	r.t.Helper()
	msg := fmt.Sprintf(format, args...)
	if r.rep.Error == "" {
		r.rep.Error = msg
	}
	r.t.Fatal(msg)
}

// logf logs a line of the human-readable report.
func (r *run) logf(format string, args ...any) {
	r.t.Helper()
	r.t.Logf(format, args...)
}

// phase records a phase and logs it.
func (r *run) phase(name string, start time.Time, bytes int64) {
	r.t.Helper()
	r.logf("%s", r.rep.AddPhase(name, start, time.Now(), bytes))
}

// client talks to the stack.
type client struct {
	cfg    Config
	dialer *Dialer
	tls    *tls.Config
	http   *http.Client
	// Admin session (cookie and CSRF token), as the admin web interface.
	cookie, csrf string
	// token is the API token of the test tenant.
	token string
}

// newClient builds the client of cfg.
func newClient(r *run, cfg Config) *client {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			r.fatalf("%s: %v", EnvCAFile, err)
		}
		pool = x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			r.fatalf("%s: no PEM certificate in %s", EnvCAFile, cfg.CAFile)
		}
	}
	tlsConf := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	d := &Dialer{Resolve: cfg.Resolve, Base: net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}}
	tr := &http.Transport{
		DialContext:     d.DialContext,
		TLSClientConfig: tlsConf.Clone(),
		// An empty map disables HTTP/2: one TCP connection per stream, the
		// simplest path through the proxy for multi-GiB bodies.
		TLSNextProto:          map[string]func(string, *tls.Conn) http.RoundTripper{},
		DisableCompression:    true,
		WriteBufferSize:       256 << 10,
		ReadBufferSize:        256 << 10,
		TLSHandshakeTimeout:   30 * time.Second,
		ResponseHeaderTimeout: 10 * time.Minute,
		MaxIdleConnsPerHost:   4,
	}
	r.t.Cleanup(tr.CloseIdleConnections)
	return &client{cfg: cfg, dialer: d, tls: tlsConf, http: &http.Client{Transport: tr}}
}

// request builds a request of method on ref (a path, or an absolute URL of
// the stack whose origin is replaced by origin: the URLs built by the
// server may omit the published port) with the Host header of origin
// without its port, as the deployment smoke test does.
func (c *client) request(ctx context.Context, origin *url.URL, method, ref string, body io.Reader, length int64) (*http.Request, error) {
	u, err := origin.Parse(ref)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", method, ref, err)
	}
	u.Scheme, u.Host = origin.Scheme, origin.Host
	if body == nil || length == 0 {
		body = http.NoBody
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", method, ref, err)
	}
	if body != http.NoBody {
		req.ContentLength = length
	}
	req.Host = origin.Hostname()
	return req, nil
}

// response is a small response read entirely.
type response struct {
	status int
	header http.Header
	body   []byte
}

// do sends req and reads at most 1 MiB of the response.
func (c *client) do(req *http.Request) (response, error) {
	resp, err := c.http.Do(req)
	if err != nil {
		return response{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return response{}, fmt.Errorf("%s %s: read response: %w", req.Method, req.URL.Path, err)
	}
	return response{status: resp.StatusCode, header: resp.Header, body: b}, nil
}

// expect fails unless res has one of the statuses want.
func expect(r *run, what string, res response, want ...int) {
	r.t.Helper()
	for _, w := range want {
		if res.status == w {
			return
		}
	}
	r.fatalf("%s: HTTP %d, want %v: %s", what, res.status, want, BodyForLog(what, res.body))
}

// decode unmarshals the JSON body of res into out.
func decode(r *run, what string, res response, out any) {
	r.t.Helper()
	if err := json.Unmarshal(res.body, out); err != nil {
		r.fatalf("%s: invalid JSON (%v): %s", what, err, BodyForLog(what, res.body))
	}
}

// jsonBody encodes in, or returns no body for nil.
func jsonBody(r *run, in any) (io.Reader, int64) {
	r.t.Helper()
	if in == nil {
		return nil, 0
	}
	b, err := json.Marshal(in)
	if err != nil {
		r.fatalf("encode request: %v", err)
	}
	return bytes.NewReader(b), int64(len(b))
}

// admin sends an admin API call (cookie, CSRF token and same-origin
// headers) and decodes the answer into out when not nil.
func (c *client) admin(r *run, method, path string, in, out any, want ...int) {
	r.t.Helper()
	body, n := jsonBody(r, in)
	req, err := c.request(r.t.Context(), c.cfg.AdminURL, method, "/api/v1"+path, body, n)
	if err != nil {
		r.fatalf("%v", err)
	}
	req.Header.Set("Origin", "https://"+c.cfg.AdminHost())
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.cookie != "" {
		req.AddCookie(&http.Cookie{Name: adminCookie, Value: c.cookie})
	}
	if c.csrf != "" {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	res, err := c.do(req)
	if err != nil {
		r.fatalf("%s %s: %v", method, path, err)
	}
	for _, ck := range (&http.Response{Header: res.header}).Cookies() {
		if ck.Name == adminCookie {
			c.cookie = ck.Value
		}
	}
	var csrf struct {
		CSRFToken string `json:"csrfToken"`
	}
	if json.Unmarshal(res.body, &csrf) == nil && csrf.CSRFToken != "" {
		c.csrf = csrf.CSRFToken
	}
	expect(r, method+" "+path, res, want...)
	if out != nil {
		decode(r, method+" "+path, res, out)
	}
}

// tokenRequest builds a request on the tenant origin authenticated with the
// API token.
func (c *client) tokenRequest(ctx context.Context, method, ref string, body io.Reader, length int64) (*http.Request, error) {
	req, err := c.request(ctx, c.cfg.BaseURL, method, ref, body, length)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	return req, nil
}

// api sends a JSON call with the API token and decodes the answer into out
// when not nil.
func (c *client) api(r *run, method, path string, in, out any, header http.Header, want ...int) response {
	r.t.Helper()
	body, n := jsonBody(r, in)
	req, err := c.tokenRequest(r.t.Context(), method, path, body, n)
	if err != nil {
		r.fatalf("%v", err)
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, vs := range header {
		req.Header[k] = vs
	}
	res, err := c.do(req)
	if err != nil {
		r.fatalf("%s %s: %v", method, path, err)
	}
	expect(r, method+" "+path, res, want...)
	if out != nil {
		decode(r, method+" "+path, res, out)
	}
	return res
}

// tusRequest builds a tus request with the API token.
func (c *client) tusRequest(ctx context.Context, method, uploadURL string, body io.Reader, length int64) (*http.Request, error) {
	req, err := c.tokenRequest(ctx, method, uploadURL, body, length)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Tus-Resumable", tusVersion)
	return req, nil
}

// head returns the offset and the length of an upload (tus HEAD).
func (c *client) head(ctx context.Context, uploadURL string) (offset, length int64, err error) {
	req, err := c.tusRequest(ctx, http.MethodHead, uploadURL, nil, 0)
	if err != nil {
		return 0, 0, err
	}
	res, err := c.do(req)
	if err != nil {
		return 0, 0, fmt.Errorf("HEAD: %w", err)
	}
	if res.status != http.StatusOK {
		return 0, 0, fmt.Errorf("HEAD: HTTP %d", res.status)
	}
	offset, err1 := strconv.ParseInt(res.header.Get("Upload-Offset"), 10, 64)
	length, err2 := strconv.ParseInt(res.header.Get("Upload-Length"), 10, 64)
	if err := errors.Join(err1, err2); err != nil {
		return 0, 0, fmt.Errorf("HEAD: Upload-Offset %q, Upload-Length %q: %w",
			res.header.Get("Upload-Offset"), res.header.Get("Upload-Length"), err)
	}
	return offset, length, nil
}

// patch uploads the bytes [from, to) of the content with one PATCH whose
// body is generated while it is sent.
func (c *client) patch(ctx context.Context, uploadURL string, from, to int64) error {
	req, err := c.tusRequest(ctx, http.MethodPatch, uploadURL, seeded.Range(c.cfg.Seed, from, to-from), to-from)
	if err != nil {
		return err
	}
	req.Header.Set("Upload-Offset", strconv.FormatInt(from, 10))
	req.Header.Set("Content-Type", "application/offset+octet-stream")
	res, err := c.do(req)
	if err != nil {
		return fmt.Errorf("PATCH [%d, %d): %w", from, to, err)
	}
	if res.status != http.StatusNoContent || res.header.Get("Upload-Offset") != strconv.FormatInt(to, 10) {
		return fmt.Errorf("PATCH [%d, %d): HTTP %d, Upload-Offset %q; want 204 and %d",
			from, to, res.status, res.header.Get("Upload-Offset"), to)
	}
	return nil
}

// poll evaluates cond every pollInterval until it returns true, failing
// after timeout; cond may fail the test itself.
func poll(r *run, what string, timeout time.Duration, cond func() bool) {
	r.t.Helper()
	deadline := time.Now().Add(timeout)
	tick := time.NewTicker(pollInterval)
	defer tick.Stop()
	for !cond() {
		if time.Now().After(deadline) {
			r.fatalf("%s: not reached within %s", what, timeout)
		}
		select {
		case <-tick.C:
		case <-r.t.Context().Done():
			r.fatalf("%s: %v", what, r.t.Context().Err())
		}
	}
}

// problem is the part of an RFC 9457 problem the test reads.
type problem struct {
	Code string `json:"code"`
}

// waitUnlocked waits until the server released the upload lock of the
// transfer trfID after a cut: finalize answers state-conflict while an
// upload is in progress and upload-incomplete once it is released.
func (c *client) waitUnlocked(r *run, trfID string) {
	r.t.Helper()
	poll(r, "upload lock released after the cut", unlockTimeout, func() bool {
		res := c.api(r, http.MethodPost, "/api/v1/transfers/"+trfID+"/finalize", nil, nil, nil, http.StatusConflict)
		var p problem
		decode(r, "finalize while waiting for the lock", res, &p)
		switch p.Code {
		case "state-conflict":
			return false
		case "upload-incomplete":
			return true
		}
		r.fatalf("finalize while waiting for the lock: HTTP %d %s", res.status, res.body)
		return false
	})
}

// cutPatch sends the interrupted PATCH of plan on a raw TLS connection: the
// head declares every remaining byte of the file, the bytes
// [plan.Start, plan.At) are written, then, once HEAD shows that the server
// checkpointed inside the request (when the plan expects it), the TCP
// connection is reset (linger 0: no TLS close_notify, no FIN, no more
// bytes). It returns the offset HEAD showed before the cut (0 without
// checkpoint).
func (c *client) cutPatch(r *run, uploadURL string, plan CutPlan) int64 {
	r.t.Helper()
	ctx := r.t.Context()
	u, err := c.cfg.BaseURL.Parse(uploadURL)
	if err != nil {
		r.fatalf("upload URL %q: %v", uploadURL, err)
	}
	port := c.cfg.BaseURL.Port()
	if port == "" {
		port = "443"
	}
	host := c.cfg.TenantHost()
	raw, err := c.dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		r.fatalf("dial for the interrupted PATCH: %v", err)
	}
	tcp, ok := raw.(*net.TCPConn)
	if !ok {
		_ = raw.Close()
		r.fatalf("dial for the interrupted PATCH: %T is not a TCP connection", raw)
	}
	defer func() { _ = tcp.Close() }()
	conf := c.tls.Clone()
	conf.ServerName = host
	conf.NextProtos = []string{"http/1.1"}
	conn := tls.Client(tcp, conf)
	if err := conn.HandshakeContext(ctx); err != nil {
		r.fatalf("TLS handshake for the interrupted PATCH: %v", err)
	}
	_ = conn.SetWriteDeadline(time.Now().Add(30 * time.Minute))
	declared := c.cfg.Bytes - plan.Start
	head := fmt.Sprintf("PATCH %s HTTP/1.1\r\nHost: %s\r\nAuthorization: Bearer %s\r\nTus-Resumable: %s\r\n"+
		"Upload-Offset: %d\r\nContent-Type: application/offset+octet-stream\r\nContent-Length: %d\r\n\r\n",
		u.RequestURI(), host, c.token, tusVersion, plan.Start, declared)
	if _, err := io.WriteString(conn, head); err != nil {
		r.fatalf("write the head of the interrupted PATCH: %v", err)
	}
	if _, err := io.CopyBuffer(conn, seeded.Range(c.cfg.Seed, plan.Start, plan.At-plan.Start), make([]byte, ioBuffer)); err != nil {
		r.fatalf("write the body of the interrupted PATCH before the cut (offset %d to %d): %v%s",
			plan.Start, plan.At, err, earlyAnswer(conn))
	}
	var seen int64
	if plan.Checkpoint {
		poll(r, fmt.Sprintf("server checkpoint past offset %d during the interrupted PATCH", plan.Start), unlockTimeout, func() bool {
			off, _, err := c.head(ctx, uploadURL)
			if err != nil {
				r.fatalf("HEAD during the interrupted PATCH: %v", err)
			}
			seen = off
			return off > plan.Start
		})
	}
	// The cut: an abrupt reset, as a lost network would leave it (linger 0,
	// then the deferred Close sends the RST).
	_ = tcp.SetLinger(0)
	return seen
}

// earlyAnswer returns the response the server may have sent before the
// body was complete (an error), to explain a failed write.
func earlyAnswer(conn net.Conn) string {
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	b := make([]byte, 2048)
	n, _ := conn.Read(b)
	if n == 0 {
		return ""
	}
	return "; the server answered: " + strings.TrimSpace(string(b[:n]))
}

// download sends a GET of a file with the given extra headers and returns
// the response with its body open; the caller closes it.
func (c *client) download(ctx context.Context, path string, header http.Header) (*http.Response, error) {
	req, err := c.request(ctx, c.cfg.BaseURL, http.MethodGet, path, nil, 0)
	if err != nil {
		return nil, err
	}
	// Offer compression explicitly, as a browser does: the transport does
	// not decompress what it did not ask for itself (DisableCompression),
	// so a proxy compressing the file would show up as a Content-Encoding
	// header, which checkDownloadHeaders rejects (CLAUDE.md section 18.2).
	req.Header.Set("Accept-Encoding", "zstd, gzip")
	for k, vs := range header {
		req.Header[k] = vs
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", path, err)
	}
	return resp, nil
}

// randomString returns n random bytes in hexadecimal (crypto/rand).
func randomString(r *run, n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		r.fatalf("random: %v", err)
	}
	return hex.EncodeToString(b)
}
