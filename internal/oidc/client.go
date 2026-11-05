package oidc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"sync"
	"time"

	"github.com/ed-fr/transteira/internal/netpolicy"
)

// Limits of the HTTP client (T-295).
const (
	// DefaultTimeout bounds one request to the provider, from the
	// connection to the last byte of the answer.
	DefaultTimeout = 10 * time.Second
	// MaxBody is the largest answer accepted from the provider, in bytes
	// (discovery document, key set, token response).
	MaxBody = 64 << 10
	// maxResponseHeader bounds the response headers.
	maxResponseHeader = 64 << 10
	// providerTTL is how long a validated discovery document is reused.
	providerTTL = time.Hour
	// MaxProviders bounds the cache of discovery documents; the oldest
	// entry is evicted beyond it.
	MaxProviders = 256
)

// errBodyTooLarge reports an answer longer than MaxBody.
var errBodyTooLarge = errors.New("oidc: answer too large")

// Options configures a [Client]. The zero value is a production client
// with the default egress guard.
type Options struct {
	// Guard checks every connection (egress policy, T-295). Nil uses
	// [DefaultGuard].
	Guard *netpolicy.DialGuard
	// UseProxy makes the client use the proxy of the environment
	// (HTTPS_PROXY), TT_SSO_USE_PROXY (decision A5). By default it is
	// ignored. With a proxy, the guard only sees the proxy, which reaches
	// the provider itself.
	UseProxy bool
	// Timeout bounds one request (DefaultTimeout when zero or negative).
	Timeout time.Duration
	// RootCAs replaces the system roots (tests only).
	RootCAs *x509.CertPool
	// Now is the clock (time.Now when nil): key reload rate, token times,
	// flow expiry and caches.
	Now func() time.Time
}

// DefaultGuard returns the egress guard used when [Options.Guard] is nil:
// the static webhook policy, refusing the networks no setting can open
// (link-local and cloud metadata, multicast, reserved...) and the
// built-in deny list (loopback, private and shared ranges). The
// application builds its own guard to add the container networks and the
// networks opened by the installation.
func DefaultGuard() *netpolicy.DialGuard {
	return netpolicy.NewDialGuardPolicy("sso", netpolicy.Policy{
		Deny:   netpolicy.BuiltinWebhookDenyNetworks(),
		Always: netpolicy.WebhookAlwaysDenyNetworks(),
	}, nil)
}

// Client talks to the identity providers: discovery, keys and code
// exchange. It caches the validated discovery document and the keys of
// each issuer. It is safe for concurrent use.
type Client struct {
	http    *http.Client
	timeout time.Duration
	now     func() time.Time
	// maxProviders is MaxProviders (lowered by the tests).
	maxProviders int

	mu        sync.Mutex
	providers map[string]*provider
}

// NewClient returns a client applying o: every connection through the
// guard, TLS 1.2 or later verified (no option to skip the verification),
// no redirect followed, no connection kept, answers capped at MaxBody
// bytes and their headers at 64 KiB.
func NewClient(o Options) *Client {
	if o.Guard == nil {
		o.Guard = DefaultGuard()
	}
	if o.Timeout <= 0 {
		o.Timeout = DefaultTimeout
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	transport := &http.Transport{
		DialContext:            o.Guard.DialContext,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: o.RootCAs},
		TLSHandshakeTimeout:    o.Timeout,
		ResponseHeaderTimeout:  o.Timeout,
		DisableKeepAlives:      true,
		ForceAttemptHTTP2:      true,
		MaxResponseHeaderBytes: maxResponseHeader,
	}
	if o.UseProxy {
		transport.Proxy = http.ProxyFromEnvironment
	}
	return &Client{
		http: &http.Client{
			Transport:     cappedTransport{transport},
			Timeout:       o.Timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		timeout:      o.Timeout,
		now:          o.Now,
		maxProviders: MaxProviders,
		providers:    map[string]*provider{},
	}
}

// cappedTransport caps the body of every answer at MaxBody bytes.
type cappedTransport struct{ next http.RoundTripper }

// RoundTrip performs the request and wraps the body of the answer.
func (t cappedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.next.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	resp.Body = &cappedBody{rc: resp.Body, left: MaxBody}
	return resp, nil
}

// cappedBody fails with errBodyTooLarge past its limit.
type cappedBody struct {
	rc   io.ReadCloser
	left int64
}

// Read reads at most left+1 bytes in total, and fails once more than left
// bytes came.
func (b *cappedBody) Read(p []byte) (int, error) {
	if int64(len(p)) > b.left+1 {
		p = p[:b.left+1]
	}
	n, err := b.rc.Read(p)
	b.left -= int64(n)
	if b.left < 0 {
		return 0, errBodyTooLarge
	}
	return n, err
}

// Close closes the underlying body.
func (b *cappedBody) Close() error { return b.rc.Close() }

// progress records how far a request went, to classify its failure.
type progress struct {
	mu                 sync.Mutex
	connected, tlsDone bool
}

// trace returns the client trace updating p.
func (p *progress) trace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		ConnectDone: func(_, _ string, err error) {
			if err == nil {
				p.mu.Lock()
				p.connected = true
				p.mu.Unlock()
			}
		},
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			if err == nil {
				p.mu.Lock()
				p.tlsDone = true
				p.mu.Unlock()
			}
		},
	}
}

// stage returns the stage reached: connect, tls or discovery (the
// answer).
func (p *progress) stage() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	switch {
	case !p.connected:
		return StageConnect
	case !p.tlsDone:
		return StageTLS
	default:
		return StageDiscovery
	}
}

// get requests url and returns the body of a 200 answer, or the stage and
// category of the failure (reason ReasonIssuerError).
func (c *Client) get(ctx context.Context, url string) ([]byte, *Error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	var p progress
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, p.trace()), http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, &Error{Reason: ReasonIssuerError, Stage: StageSettings, Category: CategoryInternal}
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, classify(ctx, err, p.stage())
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, &Error{Reason: ReasonIssuerError, Stage: StageDiscovery, Category: CategoryHTTPStatus}
	}
	body, err := io.ReadAll(resp.Body)
	if errors.Is(err, errBodyTooLarge) {
		return nil, &Error{Reason: ReasonIssuerError, Stage: StageDiscovery, Category: CategoryInvalidDocument}
	}
	if err != nil {
		return nil, classify(ctx, err, StageDiscovery)
	}
	// A body cut short without error does not parse: invalid_document.
	return body, nil
}

// classify maps a failed request, at stage, to a category. The error
// itself is dropped: it may hold remote or internal details.
func classify(ctx context.Context, err error, stage string) *Error {
	e := &Error{Reason: ReasonIssuerError, Stage: stage}
	var netErr net.Error
	var dnsErr *net.DNSError
	switch {
	case errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) ||
		(errors.As(err, &netErr) && netErr.Timeout()):
		e.Category = CategoryTimeout
	case errors.Is(err, context.Canceled):
		e.Category = CategoryInternal
	case errors.Is(err, netpolicy.ErrResolve) || errors.Is(err, netpolicy.ErrNoAddress) || errors.As(err, &dnsErr):
		e.Category = CategoryDNS
	case stage == StageTLS:
		e.Category = CategoryTLS
	default:
		// Refused, reset, denied by the egress guard, or cut after the
		// handshake.
		e.Category = CategoryConnect
	}
	return e
}
