package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"github.com/ed-fr/transteira/internal/version"
)

// MaxCAFileBytes is the largest CA file accepted.
const MaxCAFileBytes = 1 << 20

// ErrForeignOrigin is returned when a request or a reference returned by
// the server points to another origin than the configured one. Nothing is
// sent: the token and the cookies only ever go to the configured host.
var ErrForeignOrigin = errors.New("refusing a URL outside the configured server")

// systemCertPool is replaced by the tests to reach the fallback path.
var systemCertPool = x509.SystemCertPool

// Client sends requests to the configured TransTeira server. It is safe for
// concurrent use.
type Client struct {
	cfg       Config
	origin    *url.URL
	http      *http.Client
	sleep     func(context.Context, time.Duration) error
	now       func() time.Time
	log       io.Writer
	userAgent string
}

// options collects the [Option] values given to [New].
type options struct {
	rootCAs   *x509.CertPool
	dial      func(ctx context.Context, network, addr string) (net.Conn, error)
	sleep     func(context.Context, time.Duration) error
	now       func() time.Time
	log       io.Writer
	userAgent string
}

// Option changes a [Client] built by [New].
type Option func(*options)

// WithRootCAs replaces the system certificate pool (tests, embedded use).
// The CA file of the configuration is still added to it.
func WithRootCAs(pool *x509.CertPool) Option { return func(o *options) { o.rootCAs = pool } }

// WithDialContext replaces the dialer of the transport (tests that route a
// real host name to a local server).
func WithDialContext(dial func(ctx context.Context, network, addr string) (net.Conn, error)) Option {
	return func(o *options) { o.dial = dial }
}

// WithSleep replaces the pause between attempts; it must return ctx.Err()
// when the context ends first. Tests use it to run retries instantly.
func WithSleep(sleep func(ctx context.Context, d time.Duration) error) Option {
	return func(o *options) { o.sleep = sleep }
}

// WithClock replaces the clock used to read Retry-After dates and to
// measure durations in the verbose log.
func WithClock(now func() time.Time) Option { return func(o *options) { o.now = now } }

// WithLogger enables the verbose log (--verbose): one line per attempt,
// see [Redact] for what is never written.
func WithLogger(w io.Writer) Option { return func(o *options) { o.log = w } }

// WithUserAgent sets the User-Agent header; the default is
// "transteira-cli/<version>".
func WithUserAgent(ua string) Option { return func(o *options) { o.userAgent = ua } }

// New returns a client for cfg (from [Load]). The transport is a clone of
// http.DefaultTransport with HTTPS_PROXY honored, TLS 1.2 at least, the
// system roots (or [WithRootCAs]) plus cfg.CAFile, and no way to skip
// certificate verification. Redirects are never followed: a 3xx answer is
// returned as a [*Problem]. Cookies (download grants) are kept in memory
// for the configured host only.
func New(cfg Config, opts ...Option) (*Client, error) {
	o := options{
		sleep:     sleepContext,
		now:       time.Now,
		userAgent: "transteira-cli/" + version.Get().Version,
	}
	for _, opt := range opts {
		opt(&o)
	}
	base, err := NormalizeURL(cfg.URL)
	if err != nil {
		return nil, err
	}
	origin, _ := url.Parse(base)
	pool, err := rootPool(o.rootCAs, cfg.CAFile)
	if err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = http.ProxyFromEnvironment
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}
	if o.dial != nil {
		transport.DialContext = o.dial
	}
	jar, _ := cookiejar.New(nil) // never fails with nil options
	cfg.URL = base
	return &Client{
		cfg:    cfg,
		origin: origin,
		http: &http.Client{
			Transport:     transport,
			Jar:           jar,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		sleep:     o.sleep,
		now:       o.now,
		log:       o.log,
		userAgent: o.userAgent,
	}, nil
}

// rootPool returns the certificate pool: base (or the system pool, or an
// empty one when the system has none) plus the certificates of caFile.
func rootPool(base *x509.CertPool, caFile string) (*x509.CertPool, error) {
	pool := base
	if pool == nil {
		var err error
		if pool, err = systemCertPool(); err != nil {
			pool = x509.NewCertPool()
		}
	} else {
		pool = pool.Clone()
	}
	if caFile == "" {
		return pool, nil
	}
	data, err := readCAFile(caFile)
	if err != nil {
		return nil, err
	}
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("CA file %s holds no PEM certificate", caFile)
	}
	return pool, nil
}

// readCAFile reads a CA file of at most MaxCAFileBytes.
func readCAFile(path string) ([]byte, error) {
	f, err := openFile(path)
	if err != nil {
		return nil, fmt.Errorf("CA file: %w", err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, MaxCAFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("CA file %s: %w", path, err)
	}
	if len(data) > MaxCAFileBytes {
		return nil, fmt.Errorf("CA file %s is larger than %d bytes", path, MaxCAFileBytes)
	}
	return data, nil
}

// sleepContext waits for d or the end of ctx.
func sleepContext(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Config returns the configuration of the client (URL normalized).
func (c *Client) Config() Config { return c.cfg }

// BaseURL returns the normalized origin, "https://host[:port]".
func (c *Client) BaseURL() string { return c.cfg.URL }

// HTTPClient returns the underlying http.Client, for callers that need a
// raw stream; prefer [Client.Do], which applies the origin check and the
// Authorization rules.
func (c *Client) HTTPClient() *http.Client { return c.http }

// Resolve turns a reference into an absolute URL on the configured origin.
// A reference is either an absolute path ("/api/v1/uploads/upl_..."), with
// an optional query, or an absolute https URL on the same origin (an
// uploadUrl or downloadUrl returned by the server). Anything else (another
// host or port, http, a user name, a scheme-relative "//host", a relative
// path, a fragment) gives [ErrForeignOrigin] or a format error.
func (c *Client) Resolve(ref string) (*url.URL, error) {
	u, err := url.Parse(ref)
	if err != nil {
		return nil, fmt.Errorf("invalid reference %q", Redact(ref))
	}
	switch {
	case u.Fragment != "" || strings.Contains(ref, "#"):
		return nil, fmt.Errorf("reference %q carries a fragment", Redact(ref))
	case u.User != nil:
		return nil, ErrForeignOrigin
	case u.Scheme == "" && u.Host == "":
		if !strings.HasPrefix(u.Path, "/") {
			return nil, fmt.Errorf("reference %q is not an absolute path", Redact(ref))
		}
	case !c.sameOrigin(u):
		return nil, ErrForeignOrigin
	}
	out := *c.origin
	out.Path, out.RawPath, out.RawQuery = u.Path, u.RawPath, u.RawQuery
	return &out, nil
}

// sameOrigin reports whether u is an https URL on the configured origin
// (default port 443 equivalent to no port).
func (c *Client) sameOrigin(u *url.URL) bool {
	if !strings.EqualFold(u.Scheme, "https") || u.User != nil || u.Opaque != "" {
		return false
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	want := c.origin.Port()
	if want == "" {
		want = "443"
	}
	return strings.EqualFold(u.Hostname(), c.origin.Hostname()) && port == want
}

// NewRequest builds a request to ref ([Client.Resolve]) for [Client.Do].
// For a body from bytes.Reader, bytes.Buffer or strings.Reader, GetBody is
// set by net/http; for any other body (a file section), set req.GetBody
// yourself so that Do can send it again.
func (c *Client) NewRequest(ctx context.Context, method, ref string, body io.Reader) (*http.Request, error) {
	u, err := c.Resolve(ref)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", method, Redact(u.Path), err)
	}
	return req, nil
}
