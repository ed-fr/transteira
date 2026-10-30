package antivirus

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ICAP defaults, used when the matching option is not given.
const (
	// DefaultICAPPort is the port of an icap:// URL without one.
	DefaultICAPPort = "1344"
	// DefaultICAPSPort is the port of an icaps:// URL without one.
	DefaultICAPSPort = "11344"
	// DefaultOptionsTTL is how long the OPTIONS reply of an ICAP server is
	// kept when it carries no Options-TTL header.
	DefaultOptionsTTL = time.Hour
)

// DefaultInfectionHeaders are the ICAP and HTTP header names whose presence
// in a RESPMOD reply means the content is infected.
var DefaultInfectionHeaders = []string{"X-Infection-Found", "X-Virus-ID", "X-Violations-Found"}

// ICAP protocol bounds: every read of a server reply is bounded, so that a
// hostile or broken server cannot make the client buffer an unbounded amount
// of data (threat T-242).
const (
	// maxICAPLineLen bounds a status or header line, CRLF included.
	maxICAPLineLen = 8 << 10
	// maxICAPHeadLen bounds a header block (ICAP or encapsulated HTTP),
	// status line and final empty line included.
	maxICAPHeadLen = 16 << 10
	// maxChunkLineLen bounds a chunk-size line, CRLF included.
	maxChunkLineLen = 64
	// maxICAPPreview caps the Preview size advertised by the server.
	maxICAPPreview = 64 << 10
	// maxOptionsTTL caps the Options-TTL advertised by the server.
	maxOptionsTTL = 24 * time.Hour
	// icapUserAgent is sent with every request.
	icapUserAgent = "TransTeira"
)

// Synthetic encapsulated HTTP messages of a RESPMOD request. They never
// carry the file name or any other metadata of the deposit.
const (
	icapReqHeader = "GET / HTTP/1.1\r\nHost: transteira\r\n\r\n"
	icapResHeader = "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\n\r\n"
)

// Encapsulated section names (RFC 3507, section 4.4.1).
const (
	encReqHdr   = "req-hdr"
	encResHdr   = "res-hdr"
	encReqBody  = "req-body"
	encResBody  = "res-body"
	encNullBody = "null-body"
	encOptBody  = "opt-body"
)

// errPreviewStopped is returned by the RESPMOD sender when the server gave a
// final reply to the preview, so that the rest of the content is not sent.
var errPreviewStopped = errors.New("antivirus: icap: final reply to the preview")

// ICAPClient is an ICAP (RFC 3507) antivirus client. It is safe for
// concurrent use: every request opens its own connection; only the OPTIONS
// reply of the server (Preview size, Options-TTL) is shared, behind a mutex.
type ICAPClient struct {
	address    string // host:port to dial
	host       string // host as given in the URL, for the Host header and errors
	uri        string // request URI: scheme, host and service path
	tlsConfig  *tls.Config
	caPEM      []byte
	headers    []string
	rawHeaders []string

	maxScanBytes int64
	scanTimeout  time.Duration
	pingTimeout  time.Duration
	idleTimeout  time.Duration
	dial         DialFunc
	now          func() time.Time

	mu      sync.Mutex
	options icapOptions
	cached  bool
}

// icapOptions is what Scan uses from the OPTIONS reply of the server.
type icapOptions struct {
	// preview is the Preview size, -1 when the server does not support
	// previews.
	preview int64
	// expires is when the reply must be fetched again.
	expires time.Time
}

// ICAPOption customizes an ICAPClient.
type ICAPOption func(*ICAPClient)

// WithICAPMaxScanBytes sets the largest size Scan sends to the server;
// larger contents are reported TooLarge without contacting it. It should be
// below the limit of the server: a server answering 204 to what it did not
// analyze would be fail-open. Non-positive values are ignored.
func WithICAPMaxScanBytes(n int64) ICAPOption {
	return func(c *ICAPClient) {
		if n > 0 {
			c.maxScanBytes = n
		}
	}
}

// WithICAPScanTimeout sets the maximum duration of a whole RESPMOD exchange,
// from the dial to the end of the reply. Non-positive values are ignored.
func WithICAPScanTimeout(d time.Duration) ICAPOption {
	return func(c *ICAPClient) {
		if d > 0 {
			c.scanTimeout = d
		}
	}
}

// WithICAPPingTimeout sets the maximum duration of an OPTIONS exchange.
// Non-positive values are ignored.
func WithICAPPingTimeout(d time.Duration) ICAPOption {
	return func(c *ICAPClient) {
		if d > 0 {
			c.pingTimeout = d
		}
	}
}

// WithICAPIdleTimeout sets the maximum duration of each write to the server
// during a scan, so that a stalled stream is cut long before the scan
// timeout. Non-positive values are ignored.
func WithICAPIdleTimeout(d time.Duration) ICAPOption {
	return func(c *ICAPClient) {
		if d > 0 {
			c.idleTimeout = d
		}
	}
}

// WithICAPRootCAs makes the PEM certificates the only trusted roots of an
// icaps:// server, instead of the system pool. It is refused with icap://.
// A nil or empty value is ignored.
func WithICAPRootCAs(pem []byte) ICAPOption {
	return func(c *ICAPClient) {
		if len(pem) > 0 {
			c.caPEM = bytes.Clone(pem)
		}
	}
}

// WithICAPInfectionHeaders replaces the header names whose presence in a
// reply means the content is infected (default DefaultInfectionHeaders).
// Names are case-insensitive; an empty list is ignored.
func WithICAPInfectionHeaders(names ...string) ICAPOption {
	return func(c *ICAPClient) {
		if len(names) > 0 {
			c.rawHeaders = append([]string(nil), names...)
		}
	}
}

// WithICAPDialer replaces the function used to open the TCP connection to
// the server (TLS, for icaps://, is added on top). A nil dialer is ignored.
func WithICAPDialer(dial DialFunc) ICAPOption {
	return func(c *ICAPClient) {
		if dial != nil {
			c.dial = dial
		}
	}
}

// NewICAPClient returns a client for the ICAP service at rawURL:
// icap://host[:port]/service (cleartext, port 1344 by default) or
// icaps://host[:port]/service (TLS 1.2 or later, port 11344 by default,
// certificate always verified against the host name). The URL must name a
// service and must not carry credentials, a query or a fragment. No
// connection is opened until a request is sent.
func NewICAPClient(rawURL string, opts ...ICAPOption) (*ICAPClient, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, errors.New("antivirus: icap: invalid URL")
	}
	c := &ICAPClient{
		maxScanBytes: DefaultMaxScanBytes,
		scanTimeout:  DefaultScanTimeout,
		pingTimeout:  DefaultTimeout,
		idleTimeout:  DefaultIdleTimeout,
		rawHeaders:   DefaultInfectionHeaders,
		dial:         (&net.Dialer{}).DialContext,
		now:          time.Now,
	}
	for _, opt := range opts {
		opt(c)
	}
	if err := c.setURL(u); err != nil {
		return nil, err
	}
	for _, name := range c.rawHeaders {
		if !validToken([]byte(name)) {
			return nil, fmt.Errorf("antivirus: icap: invalid infection header name %q", name)
		}
		c.headers = append(c.headers, textproto.CanonicalMIMEHeaderKey(name))
	}
	return c, nil
}

// setURL validates u and derives the dial address, Host header, request URI
// and TLS configuration.
func (c *ICAPClient) setURL(u *url.URL) error {
	var port string
	switch u.Scheme {
	case "icap":
		port = DefaultICAPPort
		if c.caPEM != nil {
			return errors.New("antivirus: icap: a CA file requires an icaps:// URL")
		}
	case "icaps":
		port = DefaultICAPSPort
	default:
		return errors.New("antivirus: icap: the URL scheme must be icap or icaps")
	}
	switch {
	case u.User != nil:
		return errors.New("antivirus: icap: the URL must not contain credentials")
	case u.Opaque != "" || u.Hostname() == "":
		return errors.New("antivirus: icap: the URL must name a host")
	case u.RawQuery != "" || u.ForceQuery:
		return errors.New("antivirus: icap: the URL must not contain a query")
	case u.Fragment != "" || u.RawFragment != "":
		return errors.New("antivirus: icap: the URL must not contain a fragment")
	}
	path := u.EscapedPath()
	if path == "" || path == "/" {
		return fmt.Errorf("antivirus: icap: the URL of %s must name a service (e.g. /avscan)", u.Host)
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("antivirus: icap: invalid port in the URL of %s", u.Host)
		}
		port = p
	}
	c.host = u.Host
	c.address = net.JoinHostPort(u.Hostname(), port)
	c.uri = u.Scheme + "://" + u.Host + path
	if u.Scheme == "icap" {
		return nil
	}
	c.tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname()}
	if c.caPEM != nil {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(c.caPEM) {
			return errors.New("antivirus: icap: the CA file contains no PEM certificate")
		}
		c.tlsConfig.RootCAs = pool
	}
	return nil
}

// Host returns the host (and port, when the URL gives one) of the server,
// safe to log.
func (c *ICAPClient) Host() string { return c.host }

// connect opens a connection to the server, with a verified TLS handshake
// for icaps://.
func (c *ICAPClient) connect(ctx context.Context) (net.Conn, error) {
	conn, err := c.dial(ctx, "tcp", c.address)
	if err != nil {
		return nil, err
	}
	if c.tlsConfig == nil {
		return conn, nil
	}
	tc := tls.Client(conn, c.tlsConfig)
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("tls handshake with %s: %w", c.host, err)
	}
	return tc, nil
}

// Ping sends an OPTIONS request for the service and checks that the server
// answers 200 and supports RESPMOD. The reply (Preview size, Options-TTL) is
// kept for the following scans. The exchange is bounded by the ping timeout
// and by ctx.
//
// A non-nil error wraps ErrUnavailable (server unreachable, overloaded or
// cut) or ErrProtocol (unexpected reply).
func (c *ICAPClient) Ping(ctx context.Context) error {
	o, err := c.queryOptions(ctx)
	if err != nil {
		return err
	}
	c.store(o)
	return nil
}

// store caches the OPTIONS reply o.
func (c *ICAPClient) store(o icapOptions) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.options, c.cached = o, true
}

// currentOptions returns the cached OPTIONS reply, or fetches it when it is
// missing or expired. Every error wraps ErrUnavailable: a server that does
// not answer OPTIONS correctly is down, which says nothing about the file.
func (c *ICAPClient) currentOptions(ctx context.Context) (icapOptions, error) {
	c.mu.Lock()
	o, ok := c.options, c.cached
	c.mu.Unlock()
	if ok && c.now().Before(o.expires) {
		return o, nil
	}
	o, err := c.queryOptions(ctx)
	if err != nil {
		if errors.Is(err, ErrProtocol) {
			return icapOptions{}, fmt.Errorf("%w: %s", ErrUnavailable, err.Error())
		}
		return icapOptions{}, err
	}
	c.store(o)
	return o, nil
}

// queryOptions runs an OPTIONS exchange and parses the reply.
func (c *ICAPClient) queryOptions(parent context.Context) (icapOptions, error) {
	ctx, cancel := context.WithTimeout(parent, c.pingTimeout)
	defer cancel()

	conn, err := c.connect(ctx)
	if err != nil {
		return icapOptions{}, unavailable(parent, "options: dial", err)
	}
	defer func() { _ = conn.Close() }()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return icapOptions{}, unavailable(parent, "options", err)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(aLongTimeAgo) })
	defer stop()

	req := fmt.Sprintf("OPTIONS %s ICAP/1.0\r\nHost: %s\r\nUser-Agent: %s\r\nEncapsulated: null-body=0\r\n\r\n",
		c.uri, c.host, icapUserAgent)
	if _, err := io.WriteString(conn, req); err != nil {
		return icapOptions{}, unavailable(parent, "options: write", err)
	}
	head, err := readICAPHead(bufio.NewReaderSize(conn, 4<<10))
	if err != nil {
		if errors.Is(err, ErrProtocol) {
			return icapOptions{}, fmt.Errorf("%w from %s to OPTIONS", err, c.host)
		}
		return icapOptions{}, unavailable(parent, "options: read", err)
	}
	return parseOptions(head, c.now(), c.host)
}

// parseOptions checks an OPTIONS reply and extracts the Preview size and
// the expiry of the reply.
func parseOptions(head icapHead, now time.Time, host string) (icapOptions, error) {
	switch head.status {
	case 200:
	case 503:
		return icapOptions{}, fmt.Errorf("%w: %s answered ICAP 503 to OPTIONS", ErrUnavailable, host)
	default:
		return icapOptions{}, fmt.Errorf("%w: %s answered ICAP %d to OPTIONS", ErrProtocol, host, head.status)
	}
	if !hasToken(head.header.Values("Methods"), "RESPMOD") {
		return icapOptions{}, fmt.Errorf("%w: the service on %s does not support RESPMOD", ErrProtocol, host)
	}
	o := icapOptions{preview: -1, expires: now.Add(DefaultOptionsTTL)}
	if v := head.header.Values("Preview"); len(v) > 0 {
		n, ok := parseDecimal(v[0], 9)
		if !ok || len(v) > 1 {
			return icapOptions{}, fmt.Errorf("%w: invalid Preview from %s", ErrProtocol, host)
		}
		o.preview = min(n, maxICAPPreview)
	}
	if v := head.header.Values("Options-Ttl"); len(v) > 0 {
		n, ok := parseDecimal(v[0], 9)
		if !ok || len(v) > 1 {
			return icapOptions{}, fmt.Errorf("%w: invalid Options-TTL from %s", ErrProtocol, host)
		}
		o.expires = now.Add(min(time.Duration(n)*time.Second, maxOptionsTTL))
	}
	return o, nil
}

// Scan analyzes the size bytes read from r with an ICAP RESPMOD request.
//
// A content larger than the client limit (WithICAPMaxScanBytes) is reported
// TooLarge without contacting the server. Otherwise the content is sent as
// the body of a synthetic HTTP response (no file name), with a preview when
// the server advertises one; r must yield exactly size bytes, so that what
// is analyzed is what will be served (threat T-44). The exchange is bounded
// by ctx, by the scan timeout and, for each write, by the idle timeout.
//
// The verdict is fail-closed (decision P44): Infected when a configured
// infection header is present in the ICAP reply headers, whatever the ICAP
// status (even 204, 503 or an unexpected one), or in the encapsulated HTTP
// reply headers of an ICAP 200 or 204; Clean only on ICAP 204, or on ICAP
// 200 carrying a 2xx HTTP response whose body is byte-identical to the
// content sent. A final reply to a preview is evaluated as such: the
// server decided on the preview alone. ICAP 503 is ErrUnavailable; any
// other reply is ErrProtocol.
//
// A non-nil error wraps ErrUnavailable, ErrTimeout, ErrProtocol or
// ErrSource.
func (c *ICAPClient) Scan(ctx context.Context, r io.Reader, size int64) (Result, error) {
	if size < 0 {
		return Result{}, fmt.Errorf("%w: negative size %d", ErrSource, size)
	}
	if size > c.maxScanBytes {
		return Result{Verdict: TooLarge, Detail: DetailClientLimit}, nil
	}
	parent := ctx
	ctx, cancel := context.WithTimeout(ctx, c.scanTimeout)
	defer cancel()

	opts, err := c.currentOptions(ctx)
	if err != nil {
		return Result{}, err
	}
	conn, err := c.connect(ctx)
	if err != nil {
		return Result{}, unavailable(parent, "dial", err)
	}
	defer func() { _ = conn.Close() }()
	sc := &scanConn{conn: conn}
	stop := context.AfterFunc(ctx, sc.expire)
	defer stop()
	overall, _ := ctx.Deadline()

	x := &icapExchange{
		c: c, parent: parent, ctx: ctx, sc: sc, size: size,
		done: make(chan error, 1), cont: make(chan struct{}, 1), quit: make(chan struct{}),
		sender: &icapSender{
			sc: sc, r: r, size: size, idle: c.idleTimeout, overall: overall,
			hash: sha256.New(), buf: make([]byte, 16+chunkSize+2),
		},
	}
	defer x.cleanup()
	return x.run(c.respmodHead(size, opts.preview), opts.preview, overall)
}

// respmodHead builds the ICAP request head and the encapsulated HTTP headers
// of a RESPMOD request for a content of size bytes.
func (c *ICAPClient) respmodHead(size, preview int64) []byte {
	res := fmt.Sprintf(icapResHeader, size)
	var b bytes.Buffer
	fmt.Fprintf(&b, "RESPMOD %s ICAP/1.0\r\nHost: %s\r\nUser-Agent: %s\r\nAllow: 204\r\n", c.uri, c.host, icapUserAgent)
	if preview >= 0 {
		fmt.Fprintf(&b, "Preview: %d\r\n", min(preview, size))
	}
	fmt.Fprintf(&b, "Encapsulated: req-hdr=0, res-hdr=%d, res-body=%d\r\n\r\n",
		len(icapReqHeader), len(icapReqHeader)+len(res))
	b.WriteString(icapReqHeader)
	b.WriteString(res)
	return b.Bytes()
}

// icapExchange is the state of one RESPMOD exchange: the request is written
// by a goroutine (icapSender) while the reply is read, because a server may
// answer, or echo the content back, before it has read all of it.
type icapExchange struct {
	c           *ICAPClient
	parent, ctx context.Context
	sc          *scanConn
	size        int64
	sender      *icapSender

	done     chan error    // result of the sender
	cont     chan struct{} // 100 Continue received: send the rest
	quit     chan struct{} // closed to stop the sender after the preview
	quitOnce sync.Once
	finished bool
	werr     error
}

// run starts the sender, reads the reply and maps it to a Result.
func (x *icapExchange) run(request []byte, preview int64, overall time.Time) (Result, error) {
	go func() {
		err := x.sender.run(request, preview, x.cont, x.quit)
		x.done <- err
		switch {
		case err == nil, errors.Is(err, errPreviewStopped):
		case errors.Is(err, ErrSource):
			x.sc.expire()
		default:
			// The server stopped reading: give it a moment to send the
			// reply it may have written before closing.
			_ = x.sc.setReadDeadline(earliest(time.Now().Add(earlyReplyWait), overall))
		}
	}()
	if err := x.sc.setReadDeadline(overall); err != nil {
		return Result{}, x.readFailure(err)
	}
	br := bufio.NewReaderSize(x.sc.conn, 32<<10)
	head, err := readICAPHead(br)
	if err != nil {
		return Result{}, x.readFailure(err)
	}
	pending := preview >= 0 && x.size > preview
	if head.status == 100 {
		if !pending {
			return Result{}, fmt.Errorf("%w: unexpected ICAP 100 from %s", ErrProtocol, x.c.host)
		}
		pending = false
		x.cont <- struct{}{}
		if head, err = readICAPHead(br); err != nil {
			return Result{}, x.readFailure(err)
		}
	}
	if pending {
		x.stop()
	}
	return x.verdict(head, br, pending)
}

// verdict maps the final reply head (and what follows it on br) to a
// Result. partial reports a final reply to the preview alone.
func (x *icapExchange) verdict(head icapHead, br *bufio.Reader, partial bool) (Result, error) {
	host := x.c.host
	if sig, ok := x.c.infection(head.header); ok {
		return Result{Verdict: Infected, Signature: sig}, nil
	}
	switch head.status {
	case 200, 204:
	case 503:
		return Result{}, fmt.Errorf("%w: %s answered ICAP 503", ErrUnavailable, host)
	default:
		return Result{}, fmt.Errorf("%w: %s answered ICAP %d", ErrProtocol, host, head.status)
	}
	reply, err := readRESPMODReply(br, head)
	if err != nil {
		return Result{}, x.readFailure(err)
	}
	if sig, ok := x.c.infection(reply.httpHeader); ok {
		return Result{Verdict: Infected, Signature: sig}, nil
	}
	if head.status == 204 {
		if reply.body == encResBody {
			return Result{}, fmt.Errorf("%w: ICAP 204 with a body from %s", ErrProtocol, host)
		}
		return x.clean(partial)
	}
	switch {
	case partial:
		return Result{}, fmt.Errorf("%w: ICAP 200 to a preview from %s", ErrProtocol, host)
	case reply.body != encResBody || reply.httpHeader == nil:
		return Result{}, fmt.Errorf("%w: ICAP 200 without the content from %s", ErrProtocol, host)
	case reply.httpStatus < 200 || reply.httpStatus > 299:
		return Result{}, fmt.Errorf("%w: %s answered HTTP %d in ICAP 200", ErrProtocol, host, reply.httpStatus)
	case len(reply.httpHeader.Values("Transfer-Encoding")) > 0:
		return Result{}, fmt.Errorf("%w: unexpected transfer encoding from %s", ErrProtocol, host)
	}
	if v := reply.httpHeader.Values("Content-Length"); len(v) > 0 {
		if n, ok := parseDecimal(v[0], 19); !ok || len(v) > 1 || n != x.size {
			return Result{}, fmt.Errorf("%w: content modified by %s (length)", ErrProtocol, host)
		}
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(&chunkedReader{br: br}, x.size+1))
	if err != nil {
		return Result{}, x.readFailure(err)
	}
	if werr := x.wait(); werr != nil {
		return Result{}, x.writeFailure(werr)
	}
	if n != x.size || !bytes.Equal(h.Sum(nil), x.sender.hash.Sum(nil)) {
		return Result{}, fmt.Errorf("%w: content modified by %s", ErrProtocol, host)
	}
	return Result{Verdict: Clean}, nil
}

// clean returns a Clean result once the whole content was sent (or, after
// a final reply to the preview, without sending the rest).
func (x *icapExchange) clean(partial bool) (Result, error) {
	if partial {
		return Result{Verdict: Clean}, nil
	}
	switch werr := x.wait(); {
	case werr == nil:
		return Result{Verdict: Clean}, nil
	case errors.Is(werr, ErrSource):
		return Result{}, werr
	default:
		return Result{}, fmt.Errorf("%w: clean verdict from %s before the whole content was sent: %s",
			ErrProtocol, x.c.host, werr.Error())
	}
}

// readFailure classifies an error met while reading the reply: protocol
// errors as such, a sender failure that caused it as that failure, anything
// else as a lost connection or a timeout.
func (x *icapExchange) readFailure(err error) error {
	if errors.Is(err, ErrProtocol) {
		return fmt.Errorf("%w (from %s)", err, x.c.host)
	}
	if ok, werr := x.tryWait(); ok && werr != nil && !errors.Is(werr, errPreviewStopped) {
		return x.writeFailure(werr)
	}
	return exchangeError(x.parent, x.ctx, "read", err)
}

// writeFailure classifies a sender error.
func (x *icapExchange) writeFailure(werr error) error {
	if errors.Is(werr, ErrSource) {
		return werr
	}
	return exchangeError(x.parent, x.ctx, "write", werr)
}

// stop tells the sender not to send the rest of the content.
func (x *icapExchange) stop() { x.quitOnce.Do(func() { close(x.quit) }) }

// wait waits for the sender and returns its result.
func (x *icapExchange) wait() error {
	if !x.finished {
		x.werr, x.finished = <-x.done, true
	}
	return x.werr
}

// tryWait returns the result of the sender if it has finished.
func (x *icapExchange) tryWait() (bool, error) {
	if x.finished {
		return true, x.werr
	}
	select {
	case x.werr = <-x.done:
		x.finished = true
		return true, x.werr
	default:
		return false, nil
	}
}

// cleanup cuts the connection and waits for the sender, so that r is never
// read after Scan returns.
func (x *icapExchange) cleanup() {
	x.sc.expire()
	x.stop()
	_ = x.wait()
}

// infection returns the signature reported by the first configured
// infection header present in h.
func (c *ICAPClient) infection(h textproto.MIMEHeader) (string, bool) {
	for _, name := range c.headers {
		values, ok := h[name]
		if !ok {
			continue
		}
		for _, v := range values {
			if sig := infectionSignature(v); sig != "" {
				return sig, true
			}
		}
		return "unknown", true
	}
	return "", false
}

// infectionSignature extracts the signature name from an infection header
// value: the Threat= field of an X-Infection-Found value
// ("Type=0; Resolution=2; Threat=Eicar-Test-Signature;"), the threat line of
// a folded X-Violations-Found value, or else the raw value. The result is
// sanitized and may be empty.
func infectionSignature(v string) string {
	for _, field := range strings.Split(v, ";") {
		name, value, ok := strings.Cut(strings.TrimSpace(field), "=")
		if ok && strings.EqualFold(strings.TrimSpace(name), "threat") {
			if sig := sanitizeSignature(value); sig != "" {
				return sig
			}
		}
	}
	// X-Violations-Found: a count, then per violation the file name, the
	// threat name, a resolution and a threat id, on folded lines.
	if lines := strings.Split(v, "\n"); len(lines) >= 3 {
		if _, ok := parseDecimal(lines[0], 9); ok {
			if sig := sanitizeSignature(lines[2]); sig != "" {
				return sig
			}
		}
	}
	return sanitizeSignature(strings.ReplaceAll(v, "\n", " "))
}

// icapSender writes a RESPMOD request: head, then the content as chunks.
type icapSender struct {
	sc      *scanConn
	r       io.Reader
	size    int64
	idle    time.Duration
	overall time.Time
	hash    hash.Hash // of the content read from r
	sent    int64     // content bytes read from r and sent
	buf     []byte
}

// run writes the request. With a preview (preview >= 0), the content is sent
// whole with "0; ieof" when it fits, else the preview is sent and the rest
// only after cont, unless quit is closed first (errPreviewStopped).
func (s *icapSender) run(head []byte, preview int64, cont <-chan struct{}, quit <-chan struct{}) error {
	if err := s.write(head); err != nil {
		return err
	}
	if preview >= 0 && s.size > preview {
		if err := s.body(preview); err != nil {
			return err
		}
		if err := s.write([]byte("0\r\n\r\n")); err != nil {
			return err
		}
		select {
		case <-cont:
		case <-quit:
			return errPreviewStopped
		}
		preview = -1
	}
	if err := s.body(s.size - s.sent); err != nil {
		return err
	}
	if err := s.atEOF(); err != nil {
		return err
	}
	if preview >= 0 {
		return s.write([]byte("0; ieof\r\n\r\n"))
	}
	return s.write([]byte("0\r\n\r\n"))
}

// write writes p within the idle timeout, capped by the overall deadline.
func (s *icapSender) write(p []byte) error {
	return s.sc.writeStream(p, s.idle, s.overall)
}

// body reads n bytes from r and writes them as chunks of at most chunkSize
// bytes.
func (s *icapSender) body(n int64) error {
	for n > 0 {
		k := int(min(n, chunkSize))
		chunk := strconv.AppendInt(s.buf[:0], int64(k), 16)
		chunk = append(chunk, '\r', '\n')
		h := len(chunk)
		if _, err := io.ReadFull(s.r, s.buf[h:h+k]); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return fmt.Errorf("%w: content shorter than its declared size %d", ErrSource, s.size)
			}
			return fmt.Errorf("%w: %w", ErrSource, err)
		}
		_, _ = s.hash.Write(s.buf[h : h+k])
		s.sent += int64(k)
		if err := s.write(append(s.buf[:h+k], '\r', '\n')); err != nil {
			return err
		}
		n -= int64(k)
	}
	return nil
}

// atEOF checks that r has no byte beyond the declared size.
func (s *icapSender) atEOF() error {
	var extra [1]byte
	switch _, err := io.ReadFull(s.r, extra[:]); {
	case err == nil:
		return fmt.Errorf("%w: content longer than its declared size %d", ErrSource, s.size)
	case !errors.Is(err, io.EOF):
		return fmt.Errorf("%w: %w", ErrSource, err)
	}
	return nil
}

// setReadDeadline sets the read deadline, unless the exchange expired.
func (s *scanConn) setReadDeadline(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.expired {
		t = aLongTimeAgo
	}
	return s.conn.SetReadDeadline(t)
}

// writeStream writes p with a write deadline of idle, capped by overall,
// leaving the read deadline alone (the reply is read concurrently).
func (s *scanConn) writeStream(p []byte, idle time.Duration, overall time.Time) error {
	s.mu.Lock()
	t := earliest(time.Now().Add(idle), overall)
	if s.expired {
		t = aLongTimeAgo
	}
	err := s.conn.SetWriteDeadline(t)
	s.mu.Unlock()
	if err != nil {
		return err
	}
	_, err = s.conn.Write(p)
	return err
}

// --- Reply parser. Every function reads a bounded amount of data; malformed
// input gives an error wrapping ErrProtocol, I/O failures are returned as
// is (io.EOF when the connection closed before any byte of a head).

// protocolf returns an ErrProtocol error.
func protocolf(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrProtocol}, args...)...)
}

// icapHead is the status and headers of an ICAP reply.
type icapHead struct {
	status int
	header textproto.MIMEHeader
}

// readICAPHead reads the status line and the headers of an ICAP reply.
func readICAPHead(br *bufio.Reader) (icapHead, error) {
	line, err := readCRLFLine(br, maxICAPLineLen)
	if err != nil {
		return icapHead{}, err
	}
	status, err := parseStatusLine(line, "ICAP/1.0")
	if err != nil {
		return icapHead{}, err
	}
	header, _, err := readHeaderBlock(br, maxICAPHeadLen-len(line)-2)
	if err != nil {
		return icapHead{}, err
	}
	if len(header.Values("Transfer-Encoding")) > 0 || len(header.Values("Content-Length")) > 0 {
		return icapHead{}, protocolf("HTTP framing header in an ICAP head")
	}
	return icapHead{status: status, header: header}, nil
}

// respmodReply is the encapsulated part of a RESPMOD reply, up to its body.
type respmodReply struct {
	// httpStatus and httpHeader describe the encapsulated HTTP response;
	// they are zero when the reply has no res-hdr section.
	httpStatus int
	httpHeader textproto.MIMEHeader
	// body is encResBody, encNullBody, or empty for a 204 without
	// Encapsulated header.
	body string
}

// readRESPMODReply reads the encapsulated header sections of a 200 or 204
// RESPMOD reply, checking them against its Encapsulated header, and stops at
// the start of the body.
func readRESPMODReply(br *bufio.Reader, head icapHead) (respmodReply, error) {
	values := head.header.Values("Encapsulated")
	if len(values) == 0 && head.status == 204 {
		return respmodReply{}, nil
	}
	if len(values) != 1 {
		return respmodReply{}, protocolf("%d Encapsulated headers", len(values))
	}
	parts, err := parseEncapsulated(values[0])
	if err != nil {
		return respmodReply{}, err
	}
	var reply respmodReply
	for i, p := range parts {
		switch p.name {
		case encReqHdr, encResHdr:
		case encResBody, encNullBody:
			reply.body = p.name
			continue
		default:
			return respmodReply{}, protocolf("unexpected %s in a RESPMOD reply", p.name)
		}
		length := parts[i+1].offset - p.offset
		if length > maxICAPHeadLen {
			return respmodReply{}, protocolf("encapsulated %s of %d bytes", p.name, length)
		}
		status, header, err := readEncapsulatedHead(br, length, p.name == encResHdr)
		if err != nil {
			return respmodReply{}, err
		}
		if p.name == encResHdr {
			reply.httpStatus, reply.httpHeader = status, header
		}
	}
	return reply, nil
}

// encPart is one entry of an Encapsulated header.
type encPart struct {
	name   string
	offset int
}

// parseEncapsulated parses and validates an Encapsulated header value: known
// names, no duplicate, header sections (req-hdr before res-hdr) followed by
// exactly one body section, offsets starting at 0 and strictly increasing.
func parseEncapsulated(v string) ([]encPart, error) {
	fields := strings.Split(v, ",")
	if len(fields) > 3 {
		return nil, protocolf("Encapsulated with %d entries", len(fields))
	}
	parts := make([]encPart, 0, len(fields))
	for i, f := range fields {
		name, off, ok := strings.Cut(strings.TrimSpace(f), "=")
		n, valid := parseDecimal(off, 6)
		if !ok || !valid || n > 2*maxICAPHeadLen {
			return nil, protocolf("invalid Encapsulated entry")
		}
		name = strings.ToLower(name)
		last := i == len(fields)-1
		switch name {
		case encReqHdr, encResHdr:
			if last {
				return nil, protocolf("Encapsulated without a body entry")
			}
		case encReqBody, encResBody, encNullBody, encOptBody:
			if !last {
				return nil, protocolf("Encapsulated body entry before the end")
			}
		default:
			return nil, protocolf("unknown Encapsulated entry")
		}
		switch {
		case i == 0 && n != 0:
			return nil, protocolf("Encapsulated not starting at offset 0")
		case i > 0 && int(n) <= parts[i-1].offset:
			return nil, protocolf("Encapsulated offsets not increasing")
		case i > 0 && name == parts[i-1].name, i > 0 && name == encReqHdr:
			return nil, protocolf("Encapsulated entries out of order")
		}
		parts = append(parts, encPart{name: name, offset: int(n)})
	}
	return parts, nil
}

// readEncapsulatedHead reads an encapsulated HTTP head of exactly length
// bytes: a status line (response) or a request line, then headers.
func readEncapsulatedHead(br *bufio.Reader, length int, response bool) (int, textproto.MIMEHeader, error) {
	line, err := readCRLFLine(br, min(maxICAPLineLen, length))
	if err != nil {
		return 0, nil, err
	}
	status := 0
	if response {
		if status, err = parseHTTPStatusLine(line); err != nil {
			return 0, nil, err
		}
	} else if len(line) == 0 || hasCTL(line) {
		return 0, nil, protocolf("invalid encapsulated request line")
	}
	used := len(line) + 2
	header, n, err := readHeaderBlock(br, length-used)
	if err != nil {
		return 0, nil, err
	}
	if used+n != length {
		return 0, nil, protocolf("encapsulated head shorter than its Encapsulated offset")
	}
	return status, header, nil
}

// readCRLFLine reads a line terminated by CRLF of at most limit bytes,
// terminator included, and returns it without the terminator.
func readCRLFLine(br *bufio.Reader, limit int) ([]byte, error) {
	var line []byte
	for {
		frag, err := br.ReadSlice('\n')
		if len(line)+len(frag) > limit {
			return nil, protocolf("line longer than %d bytes", limit)
		}
		line = append(line, frag...)
		if err == nil {
			break
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if errors.Is(err, io.EOF) && len(line) > 0 {
			return nil, io.ErrUnexpectedEOF
		}
		return nil, err
	}
	if len(line) < 2 || line[len(line)-2] != '\r' {
		return nil, protocolf("line not terminated by CRLF")
	}
	return line[:len(line)-2], nil
}

// readHeaderBlock reads header lines up to the empty line, in at most budget
// bytes, and returns the headers (canonical names; folded lines joined with
// "\n") and the number of bytes read.
func readHeaderBlock(br *bufio.Reader, budget int) (textproto.MIMEHeader, int, error) {
	header := textproto.MIMEHeader{}
	used := 0
	var lastKey string
	for {
		if budget-used < 2 {
			return nil, 0, protocolf("header block longer than allowed")
		}
		line, err := readCRLFLine(br, min(maxICAPLineLen, budget-used))
		if err != nil {
			return nil, 0, err
		}
		used += len(line) + 2
		if len(line) == 0 {
			return header, used, nil
		}
		if hasCTL(line) {
			return nil, 0, protocolf("control character in a header")
		}
		if line[0] == ' ' || line[0] == '\t' {
			// Obsolete line folding, used by X-Violations-Found.
			vals := header[lastKey]
			if len(vals) == 0 {
				return nil, 0, protocolf("folded line without header")
			}
			vals[len(vals)-1] += "\n" + strings.Trim(string(line), " \t")
			continue
		}
		name, value, ok := bytes.Cut(line, []byte(":"))
		if !ok || !validToken(name) {
			return nil, 0, protocolf("invalid header line")
		}
		lastKey = textproto.CanonicalMIMEHeaderKey(string(name))
		header[lastKey] = append(header[lastKey], strings.Trim(string(value), " \t"))
	}
}

// parseStatusLine parses "<proto> <3 digits>[ <reason>]".
func parseStatusLine(line []byte, proto string) (int, error) {
	rest, ok := bytes.CutPrefix(line, []byte(proto+" "))
	if !ok || len(rest) < 3 || (len(rest) > 3 && rest[3] != ' ') || hasCTL(rest) {
		return 0, protocolf("invalid status line")
	}
	code, valid := parseDecimal(string(rest[:3]), 3)
	if !valid || code < 100 {
		return 0, protocolf("invalid status code")
	}
	return int(code), nil
}

// parseHTTPStatusLine parses the status line of an encapsulated HTTP/1.0 or
// HTTP/1.1 response.
func parseHTTPStatusLine(line []byte) (int, error) {
	if bytes.HasPrefix(line, []byte("HTTP/1.0 ")) {
		return parseStatusLine(line, "HTTP/1.0")
	}
	return parseStatusLine(line, "HTTP/1.1")
}

// chunkedReader decodes an ICAP chunked body (RFC 3507, section 4.5): hex
// chunk sizes with optional extensions, no trailer. It returns io.EOF after
// the last chunk, and an error wrapping ErrProtocol on malformed framing.
type chunkedReader struct {
	br  *bufio.Reader
	n   int64 // bytes left in the current chunk
	err error
}

// Read implements io.Reader.
func (cr *chunkedReader) Read(p []byte) (int, error) {
	if cr.err != nil {
		return 0, cr.err
	}
	if len(p) == 0 {
		return 0, nil
	}
	if cr.n == 0 {
		size, err := readChunkSize(cr.br)
		if err == nil && size == 0 {
			err = readChunkedEnd(cr.br)
		} else if errors.Is(err, io.EOF) {
			// The connection closed before the last chunk.
			err = io.ErrUnexpectedEOF
		}
		if err != nil {
			cr.err = err
			return 0, err
		}
		cr.n = size
	}
	if int64(len(p)) > cr.n {
		p = p[:cr.n]
	}
	n, err := cr.br.Read(p)
	cr.n -= int64(n)
	if err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		cr.err = err
		return n, err
	}
	if cr.n == 0 {
		var crlf [2]byte
		if _, err := io.ReadFull(cr.br, crlf[:]); err != nil {
			if errors.Is(err, io.EOF) {
				err = io.ErrUnexpectedEOF
			}
			cr.err = err
			return n, err
		}
		if crlf != [2]byte{'\r', '\n'} {
			cr.err = protocolf("chunk not terminated by CRLF")
			return n, cr.err
		}
	}
	return n, nil
}

// readChunkSize reads a chunk-size line: 1 to 16 hex digits, optionally
// followed by ";" and extensions (such as "ieof").
func readChunkSize(br *bufio.Reader) (int64, error) {
	line, err := readCRLFLine(br, maxChunkLineLen)
	if err != nil {
		return 0, err
	}
	digits, ext, _ := bytes.Cut(line, []byte(";"))
	digits = bytes.TrimRight(digits, " \t")
	if len(digits) == 0 || len(digits) > 16 || hasCTL(ext) {
		return 0, protocolf("invalid chunk size")
	}
	for _, b := range digits {
		if !isHex(b) {
			return 0, protocolf("invalid chunk size")
		}
	}
	n, err := strconv.ParseInt(string(digits), 16, 64)
	if err != nil {
		return 0, protocolf("chunk size out of range")
	}
	return n, nil
}

// readChunkedEnd reads the empty line that ends a chunked body (trailers are
// not supported).
func readChunkedEnd(br *bufio.Reader) error {
	line, err := readCRLFLine(br, maxChunkLineLen)
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	if err != nil {
		return err
	}
	if len(line) != 0 {
		return protocolf("unexpected trailer after the last chunk")
	}
	return io.EOF
}

// parseDecimal parses a non-negative decimal integer of 1 to maxDigits
// digits, surrounding spaces allowed.
func parseDecimal(s string, maxDigits int) (int64, bool) {
	s = strings.TrimSpace(s)
	if len(s) == 0 || len(s) > maxDigits {
		return 0, false
	}
	var n int64
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		n = n*10 + int64(s[i]-'0')
	}
	return n, true
}

// hasToken reports whether one of the comma-separated values contains tok
// (case-insensitive).
func hasToken(values []string, tok string) bool {
	for _, v := range values {
		for _, f := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(f), tok) {
				return true
			}
		}
	}
	return false
}

// validToken reports whether b is a non-empty RFC 9110 token.
func validToken(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
}

// hasCTL reports whether b contains a control character other than tab.
func hasCTL(b []byte) bool {
	for _, c := range b {
		if (c < 0x20 && c != '\t') || c == 0x7f {
			return true
		}
	}
	return false
}

// isHex reports whether b is a hexadecimal digit.
func isHex(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}
