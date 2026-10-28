package webhook

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
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ed-fr/transteira/internal/events"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/netpolicy"
)

// Limits of the client.
const (
	// MaxURLLength is the maximum length of a webhook URL.
	MaxURLLength = 2048
	// MaxHintLength is the maximum length of the hint returned by
	// [Client.ValidateURL].
	MaxHintLength = 300
	// maxHostLength is the maximum length of a host name (DNS limit).
	maxHostLength = 253
	// MaxResponseBody is the number of bytes of a response read before the
	// connection is closed.
	MaxResponseBody = 4 << 10
	// maxResponseHeader bounds the response headers.
	maxResponseHeader = 64 << 10
)

// ClientOptions configure a [Client]. The zero value is valid: public HTTPS
// receivers only.
type ClientOptions struct {
	// Allow opens networks of the built-in deny list
	// (TT_WEBHOOK_ALLOW_NETWORKS). A prefix overlapping the core of the
	// egress policy (netpolicy.WebhookAlwaysDenyNetworks and the networks
	// of the container) is refused by [NewClient].
	Allow []netip.Prefix
	// AllowHTTP lists the networks towards which plain http is accepted
	// (TT_WEBHOOK_ALLOW_HTTP_NETWORKS). A prefix overlapping the built-in
	// deny list must also be covered by Allow, and one overlapping the
	// core is refused, by [NewClient].
	AllowHTTP []netip.Prefix
	// Deny adds networks that are always refused, even when Allow lists
	// them (TT_WEBHOOK_DENY_NETWORKS).
	Deny []netip.Prefix
	// AdminURL is the absolute base URL of the administration (for example
	// "https://admin.transfer.example.com"), prefixed to the AdminPath of
	// the events in the payloads; "" leaves the payloads without a link.
	AdminURL string
	// Resolver resolves the host names (net.DefaultResolver when nil).
	Resolver netpolicy.Resolver
	// Now is the clock (time.Now when nil).
	Now func() time.Time
	// Timeout bounds one attempt ([RequestTimeout] when <= 0).
	Timeout time.Duration
	// InterfaceAddrs lists the addresses of the local interfaces, whose
	// networks are denied (net.InterfaceAddrs when nil; a test seam).
	InterfaceAddrs func() ([]net.Addr, error)
	// TLSConfig is the base TLS configuration (a test seam for RootCAs;
	// nil for the system roots). It is cloned and its minimum version
	// raised to TLS 1.2.
	TLSConfig *tls.Config
}

// Client calls the webhook receivers behind the egress guard (T-181): it
// validates the URLs, formats the payloads and makes one attempt per call.
// It is safe for concurrent use.
type Client struct {
	https, plain netpolicy.Policy
	allowHTTP    []netip.Prefix
	adminURL     string
	resolver     netpolicy.Resolver
	now          func() time.Time
	httpsClient  *http.Client
	plainClient  *http.Client
}

// NewClient returns a client applying opts. Its egress policy refuses the
// core (netpolicy.WebhookAlwaysDenyNetworks, the networks of the
// container but loopback, and Deny) whatever Allow says, and the built-in
// deny list (netpolicy.BuiltinWebhookDenyNetworks) unless Allow opens it.
// It fails when the local interfaces cannot be listed, Allow or AllowHTTP
// break the rules of netpolicy.CheckWebhookAllow, or AdminURL is not an
// absolute http(s) URL without query nor fragment.
func NewClient(opts ClientOptions) (*Client, error) {
	admin, err := checkAdminURL(opts.AdminURL)
	if err != nil {
		return nil, err
	}
	own, err := netpolicy.WebhookInterfaceNetworks(opts.InterfaceAddrs)
	if err != nil {
		return nil, fmt.Errorf("webhook: %w", err)
	}
	core := append(netpolicy.WebhookAlwaysDenyNetworks(), own...)
	if err := netpolicy.CheckWebhookAllow(opts.Allow, opts.AllowHTTP, core); err != nil {
		return nil, fmt.Errorf("webhook: TT_WEBHOOK_ALLOW_NETWORKS or TT_WEBHOOK_ALLOW_HTTP_NETWORKS: %w", err)
	}
	if opts.Resolver == nil {
		opts.Resolver = net.DefaultResolver
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Timeout <= 0 {
		opts.Timeout = RequestTimeout
	}
	https := netpolicy.Policy{
		Deny: netpolicy.BuiltinWebhookDenyNetworks(), Allow: opts.Allow, Always: append(core, opts.Deny...),
	}
	plain := https
	plain.Only = opts.AllowHTTP
	c := &Client{
		https: https, plain: plain, allowHTTP: opts.AllowHTTP, adminURL: admin,
		resolver: opts.Resolver, now: opts.Now,
	}
	c.httpsClient = newHTTPClient(netpolicy.NewDialGuardPolicy("webhook", https, opts.Resolver), opts)
	c.plainClient = newHTTPClient(netpolicy.NewDialGuardPolicy("webhook", plain, opts.Resolver), opts)
	return c, nil
}

// checkAdminURL validates the administration base URL and returns it
// without its trailing slash.
func checkAdminURL(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" ||
		u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("webhook: the administration URL must be an absolute http(s) URL")
	}
	return strings.TrimRight(raw, "/"), nil
}

// newHTTPClient returns an HTTP client dialing through guard: no proxy, no
// redirect followed, no connection reused (the guard checks the address of
// every connection), TLS 1.2 at least.
func newHTTPClient(guard *netpolicy.DialGuard, opts ClientOptions) *http.Client {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if opts.TLSConfig != nil {
		tlsConfig = opts.TLSConfig.Clone()
		tlsConfig.MinVersion = max(tlsConfig.MinVersion, tls.VersionTLS12)
	}
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            guard.DialContext,
		TLSClientConfig:        tlsConfig,
		TLSHandshakeTimeout:    opts.Timeout,
		ResponseHeaderTimeout:  opts.Timeout,
		DisableKeepAlives:      true,
		ForceAttemptHTTP2:      true,
		MaxResponseHeaderBytes: maxResponseHeader,
	}
	return &http.Client{
		Transport:     transport,
		Timeout:       opts.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// ValidateURL checks a webhook URL entered by an admin: at most
// [MaxURLLength] characters, https (or http when every address of the host
// is in ClientOptions.AllowHTTP), a host, no user information, no
// fragment; it resolves the host now. It returns [ErrURLInvalid] for a
// malformed URL (syntax only, plain http included when AllowHTTP is
// empty) and [ErrURLNotAllowed] for a host that does
// not resolve, resolves to a denied address or refuses plain http: the
// same answer for all three, so that the validation is no oracle on the
// internal DNS (T-181). On success, hint is "scheme://host[:port]",
// the only part of the URL that may be shown or logged (at most
// [MaxHintLength] characters). The errors never quote the URL.
func (c *Client) ValidateURL(ctx context.Context, raw string) (hint string, err error) {
	u, err := parseURL(raw)
	if err != nil {
		return "", err
	}
	if u.Scheme == "http" && len(c.allowHTTP) == 0 {
		return "", fmt.Errorf("%w: the scheme must be https", ErrURLInvalid)
	}
	addrs, err := c.resolve(ctx, u.Hostname())
	if err != nil {
		return "", err
	}
	for _, a := range addrs {
		if c.https.Denied(a) {
			return "", ErrURLNotAllowed
		}
	}
	if u.Scheme == "http" {
		for _, a := range addrs {
			if !netpolicy.Contains(c.allowHTTP, a) {
				return "", fmt.Errorf("%w: plain http is not allowed towards this host", ErrURLNotAllowed)
			}
		}
	}
	return u.Scheme + "://" + u.Host, nil
}

// parseURL checks the syntax of a webhook URL and returns it with a
// lowercase scheme and host.
func parseURL(raw string) (*url.URL, error) {
	if len(raw) > MaxURLLength {
		return nil, fmt.Errorf("%w: longer than %d characters", ErrURLInvalid, MaxURLLength)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: malformed", ErrURLInvalid)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	host := u.Hostname()
	switch {
	case u.Scheme != "https" && u.Scheme != "http":
		return nil, fmt.Errorf("%w: the scheme must be https", ErrURLInvalid)
	case u.Opaque != "" || host == "":
		return nil, fmt.Errorf("%w: a host is required", ErrURLInvalid)
	case u.User != nil:
		return nil, fmt.Errorf("%w: user information is not allowed", ErrURLInvalid)
	case u.Fragment != "" || strings.Contains(raw, "#"):
		return nil, fmt.Errorf("%w: a fragment is not allowed", ErrURLInvalid)
	case len(host) > maxHostLength || strings.Contains(host, "%"):
		return nil, fmt.Errorf("%w: invalid host", ErrURLInvalid)
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.ParseUint(p, 10, 16); err != nil || n == 0 {
			return nil, fmt.Errorf("%w: invalid port", ErrURLInvalid)
		}
	} else if strings.HasSuffix(u.Host, ":") {
		return nil, fmt.Errorf("%w: invalid port", ErrURLInvalid)
	}
	return u, nil
}

// resolve returns the addresses of host (an IP literal or a name).
func (c *Client) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip}, nil
	}
	addrs, err := c.resolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(addrs) == 0 {
		return nil, fmt.Errorf("%w: the host does not resolve", ErrURLNotAllowed)
	}
	return addrs, nil
}

// Send makes one attempt to deliver ev to t and returns its result. A
// failure only reports a coarse category: the URL, the addresses and the
// body of the receiver never leave this method. An unparsable URL or an
// unknown kind fails with [CategoryConnect]; plain http towards a network
// outside ClientOptions.AllowHTTP fails with [CategoryRefusedNetwork].
func (c *Client) Send(ctx context.Context, t Target, ev events.Event) Result {
	start := c.now()
	result := c.send(ctx, t, ev)
	result.Duration = max(c.now().Sub(start), 0)
	return result
}

// send is Send without the duration.
func (c *Client) send(ctx context.Context, t Target, ev events.Event) Result {
	u, err := parseURL(t.URL)
	if err != nil {
		return Result{Category: CategoryConnect}
	}
	client := c.httpsClient
	if u.Scheme == "http" {
		if len(c.allowHTTP) == 0 {
			return Result{Category: CategoryRefusedNetwork}
		}
		client = c.plainClient
	}
	body, header, ok := c.format(t, ev, c.now())
	if !ok {
		return Result{Category: CategoryConnect}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return Result{Category: CategoryConnect}
	}
	req.Header = header
	resp, err := client.Do(req)
	if err != nil {
		return Result{Category: classify(err)}
	}
	_, _ = io.CopyN(io.Discard, resp.Body, MaxResponseBody)
	_ = resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return Result{HTTPStatus: resp.StatusCode, Category: CategoryHTTPStatus}
	}
	return Result{Success: true, HTTPStatus: resp.StatusCode}
}

// SendTest makes one attempt to deliver a webhook.test event, occurring
// at now, to t (the test button of the administration).
func (c *Client) SendTest(ctx context.Context, t Target, now time.Time) Result {
	return c.Send(ctx, t, TestEvent(t, now))
}

// TestEvent returns the webhook.test event sent to t by [Client.SendTest].
func TestEvent(t Target, now time.Time) events.Event {
	path := events.AdminPathSystemWebhooks
	if t.TenantID != "" {
		path = events.AdminPathTenantWebhooks(t.TenantID)
	}
	return events.Event{
		ID: id.New(id.Event), Type: events.WebhookTest, Severity: events.SeverityInfo,
		OccurredAt: now, TenantID: t.TenantID, Counts: map[string]float64{}, AdminPath: path,
	}
}

// classify maps the error of an attempt to its category. The final string
// matches cover the TLS and certificate errors that crypto/tls and
// crypto/x509 do not export as types.
func classify(err error) ErrorCategory {
	var (
		dnsErr    *net.DNSError
		netErr    net.Error
		certErr   *tls.CertificateVerificationError
		alertErr  tls.AlertError
		recordErr tls.RecordHeaderError
		authErr   x509.UnknownAuthorityError
		hostErr   x509.HostnameError
		invErr    x509.CertificateInvalidError
	)
	switch {
	case errors.Is(err, netpolicy.ErrAddressDenied):
		return CategoryRefusedNetwork
	case errors.Is(err, netpolicy.ErrResolve), errors.Is(err, netpolicy.ErrNoAddress), errors.As(err, &dnsErr):
		return CategoryDNS
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled),
		errors.Is(err, os.ErrDeadlineExceeded), errors.As(err, &netErr) && netErr.Timeout():
		return CategoryTimeout
	case errors.As(err, &certErr), errors.As(err, &alertErr), errors.As(err, &recordErr),
		errors.As(err, &authErr), errors.As(err, &hostErr), errors.As(err, &invErr),
		strings.Contains(err.Error(), "tls: "), strings.Contains(err.Error(), "x509: "):
		return CategoryTLS
	default:
		return CategoryConnect
	}
}
