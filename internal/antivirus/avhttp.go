package antivirus

import (
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
	"net/http/httptrace"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

// BodyMode selects how the HTTP engine client sends the content.
type BodyMode string

// Body modes.
const (
	// BodyMultipart sends a multipart/form-data body with a single part
	// (the default).
	BodyMultipart BodyMode = "multipart"
	// BodyRaw sends the content as is, as application/octet-stream.
	BodyRaw BodyMode = "raw"
)

// HTTP engine defaults and bounds.
const (
	// DefaultMultipartField is the name of the multipart part holding the
	// content.
	DefaultMultipartField = "file"
	// MaxHTTPResponseBytes bounds the response body of a scan request; a
	// larger body is a protocol error.
	MaxHTTPResponseBytes = 64 << 10
	// maxHTTPHeaderBytes bounds the response headers.
	maxHTTPHeaderBytes = 64 << 10
	// maxHealthBodyBytes bounds what Ping drains from the health URL.
	maxHealthBodyBytes = 4 << 10
	// maxMultipartFieldLen bounds the length of the multipart field name.
	maxMultipartFieldLen = 64
	// httpDialTimeout bounds the TCP connection and the TLS handshake.
	httpDialTimeout = 30 * time.Second
	// multipartFilename is the file name announced in the multipart part:
	// the real name is never sent.
	multipartFilename = "file"
	// unknownSignature is reported when an infected verdict gives no
	// signature.
	unknownSignature = "unknown"
	// octetStream is the content type of the content.
	octetStream = "application/octet-stream"
	// httpUserAgent is sent with every request.
	httpUserAgent = "TransTeira-antivirus"
)

// errAnsweredEarly closes the request body when the engine answered before
// reading the whole content.
var errAnsweredEarly = errors.New("antivirus: engine answered before reading the whole content")

// forbiddenAuthHeaders are header names AuthHeader may not set, because
// the client or the transport owns them.
var forbiddenAuthHeaders = map[string]bool{
	"Host": true, "Content-Length": true, "Content-Type": true, "Transfer-Encoding": true,
	"Connection": true, "Te": true, "Trailer": true, "Upgrade": true, "Expect": true,
}

// HTTPConfig configures an HTTPClient. URL, CleanRule and InfectedRule are
// required; the other fields have defaults.
type HTTPConfig struct {
	// URL receives the content to analyze. Scheme http or https, no
	// userinfo.
	URL string
	// Method is POST (default) or PUT.
	Method string
	// Body is BodyMultipart (default) or BodyRaw.
	Body BodyMode
	// MultipartField names the part holding the content in BodyMultipart
	// mode (default DefaultMultipartField). Letters, digits, ".", "_" and
	// "-" only.
	MultipartField string
	// AuthHeader is an optional "Name: value" header line sent with every
	// request, read by the caller from a secret file (decision P46). It is
	// never included in an error or in String.
	AuthHeader string
	// CAPEM, when set, holds the only root certificates trusted for the
	// engine (PEM). It requires an https URL. The system pool is used
	// otherwise; certificate verification cannot be disabled (P45).
	CAPEM []byte
	// CleanRule and InfectedRule decide the verdict (decision P44).
	CleanRule    Rule
	InfectedRule Rule
	// SignaturePointer is an optional RFC 6901 pointer to the signature
	// name in the JSON body of an infected verdict.
	SignaturePointer string
	// HealthURL is an optional URL Ping checks with a GET (same rules as
	// URL). Without it, Ping only opens a connection to the URL host.
	HealthURL string
	// MaxScanBytes is the largest size sent to the engine (default
	// DefaultMaxScanBytes).
	MaxScanBytes int64
	// Timeout bounds a whole scan request (default DefaultScanTimeout).
	Timeout time.Duration
	// PingTimeout bounds Ping (default DefaultTimeout).
	PingTimeout time.Duration

	// dial replaces the dialer, for tests.
	dial DialFunc
}

// HTTPClient is a client for a generic HTTP antivirus engine: the content
// is sent in a POST or PUT request and the verdict is read from the status
// code and the JSON response body with two explicit rules. It is safe for
// concurrent use.
type HTTPClient struct {
	url          *url.URL
	healthURL    *url.URL
	method       string
	body         BodyMode
	field        string
	authName     string
	authValue    string
	clean        Rule
	infected     Rule
	needJSON     bool
	sigPointer   string
	maxScanBytes int64
	timeout      time.Duration
	pingTimeout  time.Duration
	tlsConfig    *tls.Config
	dial         DialFunc
	http         *http.Client
}

// NewHTTPClient validates cfg and returns a client. No connection is opened.
// Errors never contain the auth header nor the full URL.
func NewHTTPClient(cfg HTTPConfig) (*HTTPClient, error) {
	u, err := parseEngineURL(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("antivirus: http engine URL: %w", err)
	}
	c := &HTTPClient{
		url:          u,
		method:       http.MethodPost,
		body:         BodyMultipart,
		field:        DefaultMultipartField,
		clean:        cfg.CleanRule,
		infected:     cfg.InfectedRule,
		sigPointer:   cfg.SignaturePointer,
		maxScanBytes: DefaultMaxScanBytes,
		timeout:      DefaultScanTimeout,
		pingTimeout:  DefaultTimeout,
		dial:         cfg.dial,
	}
	if cfg.HealthURL != "" {
		if c.healthURL, err = parseEngineURL(cfg.HealthURL); err != nil {
			return nil, fmt.Errorf("antivirus: http engine health URL: %w", err)
		}
	}
	if err := c.applyOptions(cfg); err != nil {
		return nil, err
	}
	if c.tlsConfig, err = engineTLSConfig(cfg.CAPEM, u); err != nil {
		return nil, err
	}
	if c.dial == nil {
		c.dial = (&net.Dialer{Timeout: httpDialTimeout}).DialContext
	}
	c.http = &http.Client{
		Transport: &http.Transport{
			Proxy:                  nil, // never the environment proxy
			DialContext:            c.dial,
			TLSClientConfig:        c.tlsConfig,
			TLSHandshakeTimeout:    httpDialTimeout,
			ResponseHeaderTimeout:  c.timeout,
			MaxResponseHeaderBytes: maxHTTPHeaderBytes,
			DisableKeepAlives:      true,
			DisableCompression:     true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return c, nil
}

// applyOptions validates and applies the optional fields of cfg.
func (c *HTTPClient) applyOptions(cfg HTTPConfig) error {
	switch strings.ToUpper(cfg.Method) {
	case "", http.MethodPost:
	case http.MethodPut:
		c.method = http.MethodPut
	default:
		return errors.New("antivirus: http engine method must be POST or PUT")
	}
	switch cfg.Body {
	case "", BodyMultipart:
	case BodyRaw:
		c.body = BodyRaw
	default:
		return errors.New(`antivirus: http engine body must be "multipart" or "raw"`)
	}
	if cfg.MultipartField != "" {
		if !validFieldName(cfg.MultipartField) {
			return errors.New("antivirus: invalid http engine multipart field name")
		}
		c.field = cfg.MultipartField
	}
	if cfg.AuthHeader != "" {
		name, value, err := parseAuthHeader(cfg.AuthHeader)
		if err != nil {
			return err
		}
		c.authName, c.authValue = name, value
	}
	if c.clean.IsZero() || c.infected.IsZero() {
		return errors.New("antivirus: http engine clean and infected rules are required")
	}
	c.needJSON = c.clean.NeedsJSON() || c.infected.NeedsJSON()
	if cfg.SignaturePointer != "" {
		if err := checkPointer(cfg.SignaturePointer); err != nil {
			return fmt.Errorf("antivirus: http engine signature pointer: %w", err)
		}
	}
	if cfg.MaxScanBytes > 0 {
		c.maxScanBytes = cfg.MaxScanBytes
	}
	if cfg.Timeout > 0 {
		c.timeout = cfg.Timeout
	}
	if cfg.PingTimeout > 0 {
		c.pingTimeout = cfg.PingTimeout
	}
	return nil
}

// parseEngineURL parses an http or https URL without userinfo. The error
// never quotes the URL, which may carry secrets.
func parseEngineURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	switch {
	case err != nil:
		return nil, errors.New("invalid URL")
	case u.Scheme != "http" && u.Scheme != "https":
		return nil, errors.New("scheme must be http or https")
	case u.User != nil:
		return nil, errors.New("credentials in the URL are refused, use the auth header file")
	case u.Host == "" || u.Hostname() == "":
		return nil, errors.New("missing host")
	}
	u.Fragment, u.RawFragment = "", ""
	return u, nil
}

// engineTLSConfig returns the TLS configuration: TLS 1.2 or later, verified
// against the system pool or, when caPEM is set, against its certificates
// only.
func engineTLSConfig(caPEM []byte, u *url.URL) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if len(caPEM) == 0 {
		return cfg, nil
	}
	if u.Scheme != "https" {
		return nil, errors.New("antivirus: http engine CA file requires an https URL")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("antivirus: http engine CA file holds no PEM certificate")
	}
	cfg.RootCAs = pool
	return cfg, nil
}

// validFieldName reports whether s is a safe multipart field name.
func validFieldName(s string) bool {
	if len(s) > maxMultipartFieldLen {
		return false
	}
	for i := range len(s) {
		b := s[i]
		if !isAlnum(b) && b != '.' && b != '_' && b != '-' {
			return false
		}
	}
	return true
}

// isAlnum reports whether b is an ASCII letter or digit.
func isAlnum(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// parseAuthHeader validates a "Name: value" header line: the name is an
// HTTP token not owned by the client, the value is non-empty without CR,
// LF, NUL or other control character (tab allowed). The errors never quote
// the line.
func parseAuthHeader(line string) (name, value string, err error) {
	name, value, ok := strings.Cut(strings.TrimRight(line, "\r\n"), ":")
	if !ok {
		return "", "", errors.New(`antivirus: http engine auth header must be "Name: value"`)
	}
	if name == "" || !isToken(name) {
		return "", "", errors.New("antivirus: invalid http engine auth header name")
	}
	if forbiddenAuthHeaders[http.CanonicalHeaderKey(name)] {
		return "", "", errors.New("antivirus: http engine auth header name not allowed")
	}
	value = strings.Trim(value, " \t")
	if value == "" {
		return "", "", errors.New("antivirus: empty http engine auth header value")
	}
	for i := range len(value) {
		if b := value[i]; (b < 0x20 && b != '\t') || b == 0x7f {
			return "", "", errors.New("antivirus: invalid character in http engine auth header value")
		}
	}
	return name, value, nil
}

// isToken reports whether s is an HTTP token (RFC 9110).
func isToken(s string) bool {
	for i := range len(s) {
		if b := s[i]; !isAlnum(b) && !strings.ContainsRune("!#$%&'*+-.^_`|~", rune(b)) {
			return false
		}
	}
	return true
}

// String describes the engine for logs: the scheme and host only.
func (c *HTTPClient) String() string {
	return "http engine " + c.url.Scheme + "://" + c.url.Host
}

// Scan analyzes the size bytes read from r by sending them to the engine.
//
// A content larger than MaxScanBytes is reported TooLarge without
// contacting the engine. Otherwise r is streamed through a pipe, never
// buffered, with an exact Content-Length; r must yield exactly size bytes,
// or the request is aborted and ErrSource is returned (threat T-44). The
// response body is read up to MaxHTTPResponseBytes.
//
// The verdict is fail-closed (decision P44): 502, 503 and 504 are
// ErrUnavailable; otherwise the content is Clean only when the clean rule
// holds and the infected rule does not, Infected only in the reverse case,
// and anything else (both, neither, missing JSON field, invalid JSON) is
// ErrProtocol. An engine that answers before reading the whole content
// gives ErrProtocol too.
//
// A non-nil error wraps ErrUnavailable, ErrTimeout, ErrProtocol or
// ErrSource, and names the host only.
func (c *HTTPClient) Scan(ctx context.Context, r io.Reader, size int64) (Result, error) {
	if size < 0 {
		return Result{}, fmt.Errorf("%w: negative size %d", ErrSource, size)
	}
	if size > c.maxScanBytes {
		return Result{Verdict: TooLarge, Detail: DetailClientLimit}, nil
	}
	parent := ctx
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	var connected atomic.Bool
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn: func(httptrace.GotConnInfo) { connected.Store(true) },
	})
	head, tail, contentType := c.framing()
	length := int64(len(head)) + size + int64(len(tail))
	var body io.Reader = http.NoBody
	var pr *io.PipeReader
	var pw *io.PipeWriter
	if length == 0 {
		// The transport takes a zero length with a body for an unknown
		// length: check that the content is empty and send no body.
		if err := writeBody(io.Discard, r, 0, nil, nil); err != nil {
			return Result{}, err
		}
	} else {
		pr, pw = io.Pipe()
		body = pr
	}
	req, err := http.NewRequestWithContext(ctx, c.method, c.url.String(), body)
	if err != nil {
		return Result{}, fmt.Errorf("%w: build request to %s", ErrProtocol, c.url.Host)
	}
	req.ContentLength = length
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", httpUserAgent)
	if c.authName != "" {
		req.Header.Set(c.authName, c.authValue)
	}

	// finish stops the writer and returns its result; a source error wins
	// over any response.
	finish := func() error { return nil }
	if pr != nil {
		written := make(chan error, 1)
		go func() {
			err := writeBody(pw, r, size, head, tail)
			_ = pw.CloseWithError(err)
			written <- err
		}()
		finish = func() error {
			_ = pr.CloseWithError(errAnsweredEarly)
			return <-written
		}
	}

	resp, err := c.http.Do(req)
	if err != nil {
		if werr := finish(); errors.Is(werr, ErrSource) {
			return Result{}, werr
		}
		return Result{}, c.exchangeError(parent, ctx, connected.Load(), "send", err)
	}
	respBody, rerr := io.ReadAll(io.LimitReader(resp.Body, MaxHTTPResponseBytes+1))
	_ = resp.Body.Close()
	werr := finish()
	switch {
	case errors.Is(werr, ErrSource):
		return Result{}, werr
	case rerr != nil:
		return Result{}, c.exchangeError(parent, ctx, true, "read", rerr)
	case isUnavailableStatus(resp.StatusCode):
		return Result{}, fmt.Errorf("%w: %s answered status %d", ErrUnavailable, c.url.Host, resp.StatusCode)
	case werr != nil:
		return Result{}, fmt.Errorf("%w: %s answered status %d before reading the whole content", ErrProtocol, c.url.Host, resp.StatusCode)
	case len(respBody) > MaxHTTPResponseBytes:
		return Result{}, fmt.Errorf("%w: %s response body larger than %d bytes", ErrProtocol, c.url.Host, MaxHTTPResponseBytes)
	}
	return c.verdict(resp.StatusCode, respBody)
}

// framing returns the bytes sent before and after the content and the
// request content type. Each multipart request gets a random boundary, so
// that a content cannot forge it.
func (c *HTTPClient) framing() (head, tail []byte, contentType string) {
	if c.body == BodyRaw {
		return nil, nil, octetStream
	}
	var rnd [24]byte
	// Since Go 1.24 rand.Read never returns an error: it aborts the program
	// when the system source fails, so a predictable boundary is impossible.
	_, _ = rand.Read(rnd[:])
	boundary := "TransTeira-" + hex.EncodeToString(rnd[:])
	head = []byte("--" + boundary + "\r\n" +
		`Content-Disposition: form-data; name="` + c.field + `"; filename="` + multipartFilename + "\"\r\n" +
		"Content-Type: " + octetStream + "\r\n\r\n")
	tail = []byte("\r\n--" + boundary + "--\r\n")
	return head, tail, "multipart/form-data; boundary=" + boundary
}

// writeBody writes head, exactly size bytes of r and tail to w. A content
// shorter or longer than size gives ErrSource.
func writeBody(w io.Writer, r io.Reader, size int64, head, tail []byte) error {
	if _, err := w.Write(head); err != nil {
		return err
	}
	src := &sourceReader{r: r}
	if n, err := io.CopyN(w, src, size); n < size {
		switch {
		case src.err == nil:
			return err // write error: the request was aborted
		case errors.Is(src.err, io.EOF):
			return fmt.Errorf("%w: content shorter than its declared size %d", ErrSource, size)
		default:
			return fmt.Errorf("%w: %w", ErrSource, src.err)
		}
	}
	var extra [1]byte
	switch _, err := io.ReadFull(r, extra[:]); {
	case err == nil:
		return fmt.Errorf("%w: content longer than its declared size %d", ErrSource, size)
	case !errors.Is(err, io.EOF):
		return fmt.Errorf("%w: %w", ErrSource, err)
	}
	_, err := w.Write(tail)
	return err
}

// sourceReader records the read error of the content, so that writeBody
// tells it apart from a write error.
type sourceReader struct {
	r   io.Reader
	err error
}

// Read reads from the content and records its error.
func (s *sourceReader) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	if err != nil {
		s.err = err
	}
	return n, err
}

// isUnavailableStatus reports whether status means the engine (or a proxy
// in front of it) is unavailable rather than answering about the content.
func isUnavailableStatus(status int) bool {
	return status == http.StatusBadGateway || status == http.StatusServiceUnavailable ||
		status == http.StatusGatewayTimeout
}

// verdict applies the rules to a complete response.
func (c *HTTPClient) verdict(status int, body []byte) (Result, error) {
	var doc any
	if c.needJSON {
		var err error
		if doc, err = decodeJSON(body); err != nil {
			return Result{}, fmt.Errorf("%w: %s answered status %d with an invalid JSON body", ErrProtocol, c.url.Host, status)
		}
	}
	clean, cerr := c.clean.Eval(status, doc)
	infected, ierr := c.infected.Eval(status, doc)
	switch {
	case cerr != nil || ierr != nil:
		return Result{}, fmt.Errorf("%w: %s answered status %d: %w", ErrProtocol, c.url.Host, status, errors.Join(cerr, ierr))
	case clean && !infected:
		return Result{Verdict: Clean}, nil
	case infected && !clean:
		return Result{Verdict: Infected, Signature: c.signature(doc, body)}, nil
	default:
		return Result{}, fmt.Errorf("%w: %s answered status %d, ambiguous verdict (clean rule %t, infected rule %t)",
			ErrProtocol, c.url.Host, status, clean, infected)
	}
}

// signature extracts the signature of an infected verdict with the
// signature pointer: a string as is, the first string of an array, the JSON
// text of any other value. It is sanitized, and unknownSignature when
// absent or empty. A body that is not JSON gives unknownSignature too: the
// infected verdict stands.
func (c *HTTPClient) signature(doc any, body []byte) string {
	if c.sigPointer == "" {
		return unknownSignature
	}
	if !c.needJSON {
		var err error
		if doc, err = decodeJSON(body); err != nil {
			return unknownSignature
		}
	}
	v, found, _ := lookupPointer(doc, c.sigPointer)
	if !found {
		return unknownSignature
	}
	var sig string
	switch x := v.(type) {
	case nil:
	case string:
		sig = x
	case []any:
		for _, e := range x {
			if s, ok := e.(string); ok {
				sig = s
				break
			}
		}
	default:
		if b, err := json.Marshal(x); err == nil {
			sig = string(b)
		}
	}
	if sig = sanitizeSignature(sig); sig == "" {
		return unknownSignature
	}
	return sig
}

// exchangeError classifies a transport failure, like the clamd client: the
// caller's context done is ErrUnavailable with its error; a timeout while
// it is live is ErrTimeout; a failure before a connection was established
// is ErrUnavailable; after, ErrUnavailable with ErrConnectionLost. The
// *url.Error wrapper, which quotes the full URL, is removed.
func (c *HTTPClient) exchangeError(parent, ctx context.Context, connected bool, op string, err error) error {
	var uerr *url.Error
	if errors.As(err, &uerr) {
		err = uerr.Err
	}
	op = op + " " + c.url.Host
	if parent.Err() != nil || parentExpired(parent) {
		return unavailable(parent, op, err)
	}
	var nerr net.Error
	if ctx.Err() != nil || errors.Is(err, os.ErrDeadlineExceeded) || (errors.As(err, &nerr) && nerr.Timeout()) {
		return fmt.Errorf("%w: %s: %w", ErrTimeout, op, err)
	}
	if !connected {
		return fmt.Errorf("%w: %s: %w", ErrUnavailable, op, err)
	}
	return fmt.Errorf("%w: %w: %s: %w", ErrUnavailable, ErrConnectionLost, op, err)
}

// Ping checks that the engine is reachable. With a health URL, it sends a
// GET and expects a 2xx status (the auth header is sent only when the
// health URL has the scheme and host of the scan URL); otherwise it opens a
// TCP connection to the scan URL host, with a TLS handshake for https. It
// is bounded by the ping timeout and by ctx. Errors name the host only.
func (c *HTTPClient) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, c.pingTimeout)
	defer cancel()
	if c.healthURL != nil {
		return c.pingHealth(ctx)
	}
	return c.pingDial(ctx)
}

// pingHealth checks the health URL.
func (c *HTTPClient) pingHealth(ctx context.Context) error {
	host := c.healthURL.Host
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.healthURL.String(), nil)
	if err != nil {
		return fmt.Errorf("antivirus: ping %s: build request", host)
	}
	req.Header.Set("User-Agent", httpUserAgent)
	if c.authName != "" && c.healthURL.Scheme == c.url.Scheme && c.healthURL.Host == c.url.Host {
		req.Header.Set(c.authName, c.authValue)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = uerr.Err
		}
		return fmt.Errorf("antivirus: ping %s: %w", host, err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxHealthBodyBytes))
	_ = resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("%w: ping %s: status %d", ErrUnexpectedReply, host, resp.StatusCode)
	}
	return nil
}

// pingDial opens a connection to the scan URL host.
func (c *HTTPClient) pingDial(ctx context.Context) (err error) {
	addr := hostPort(c.url)
	conn, err := c.dial(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("antivirus: ping %s: dial: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()
	if c.url.Scheme != "https" {
		return nil
	}
	cfg := c.tlsConfig.Clone()
	cfg.ServerName = c.url.Hostname()
	if err := tls.Client(conn, cfg).HandshakeContext(ctx); err != nil {
		return fmt.Errorf("antivirus: ping %s: tls: %w", addr, err)
	}
	return nil
}

// hostPort returns the host:port of u, with the default port of its scheme.
func hostPort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return net.JoinHostPort(u.Hostname(), port)
	}
	if u.Scheme == "https" {
		return net.JoinHostPort(u.Hostname(), "443")
	}
	return net.JoinHostPort(u.Hostname(), "80")
}
