package updatecheck

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"time"
)

// ReleasesURL is the only address the update check ever requests. It is
// fixed in the code and not configurable (T-244).
const ReleasesURL = "https://api.github.com/repos/ed-fr/transteira/releases/latest"

// Limits of the client.
const (
	// Timeout bounds one check, from the connection to the last byte of
	// the answer.
	Timeout = 10 * time.Second
	// MaxBody is the largest answer accepted, in bytes; a longer one is
	// refused (CategoryParse).
	MaxBody = 64 << 10
	// maxResponseHeader bounds the response headers.
	maxResponseHeader = 64 << 10
)

// Category is the outcome of a check, the only part of an error ever
// stored, shown or logged (T-247): it never carries the raw message,
// which may hold internal addresses or details of the proxy. The values
// match the OpenAPI UpdateCheck.lastError.
type Category string

// Outcomes of a check.
const (
	// CategoryNone: the check succeeded.
	CategoryNone Category = "none"
	// CategoryNetwork: GitHub unreachable, timeout, TLS or proxy failure.
	CategoryNetwork Category = "network"
	// CategoryHTTP: an answer other than 200 (a redirection included,
	// never followed).
	CategoryHTTP Category = "http"
	// CategoryParse: an unreadable or too long answer, or a version that
	// is not a strict SemVer.
	CategoryParse Category = "parse"
)

// valid reports whether c is one of the categories.
func (c Category) valid() bool {
	switch c {
	case CategoryNone, CategoryNetwork, CategoryHTTP, CategoryParse:
		return true
	default:
		return false
	}
}

// clientOptions are the seams of the client: the defaults are the
// production values, the tests replace them.
type clientOptions struct {
	// url is the requested address (ReleasesURL).
	url string
	// userAgent is the User-Agent header.
	userAgent string
	// timeout bounds a check (Timeout).
	timeout time.Duration
	// tlsConfig is the base TLS configuration (nil: the system roots).
	tlsConfig *tls.Config
	// proxy picks the proxy of a request (http.ProxyFromEnvironment).
	proxy func(*http.Request) (*url.URL, error)
}

// client fetches the latest release.
type client struct {
	url, userAgent string
	http           *http.Client
}

// newClient returns a client applying o: TLS 1.2 at least, verified (no
// option to skip the verification), no redirect followed, no connection
// kept, the proxy of o.proxy.
func newClient(o clientOptions) *client {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if o.tlsConfig != nil {
		tlsConfig = o.tlsConfig.Clone()
		tlsConfig.MinVersion = max(tlsConfig.MinVersion, tls.VersionTLS12)
		tlsConfig.InsecureSkipVerify = false
	}
	transport := &http.Transport{
		Proxy:                  o.proxy,
		TLSClientConfig:        tlsConfig,
		TLSHandshakeTimeout:    o.timeout,
		ResponseHeaderTimeout:  o.timeout,
		DisableKeepAlives:      true,
		ForceAttemptHTTP2:      true,
		MaxResponseHeaderBytes: maxResponseHeader,
	}
	return &client{
		url: o.url, userAgent: o.userAgent,
		http: &http.Client{
			Transport:     transport,
			Timeout:       o.timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

// fetch requests the latest release and returns what is kept of it, or
// the category of the failure.
//
// The check carries its own deadline, the same as the client's Timeout:
// a body cut by the timeout may still end cleanly when the server closes
// its chunked response on seeing the client leave (io.ReadAll then
// returns a truncated body without error). Whatever ends after the
// deadline is a network failure, never a parse error.
func (c *client) fetch(ctx context.Context) (Release, Category) {
	ctx, cancel := context.WithTimeout(ctx, c.http.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, http.NoBody)
	if err != nil {
		return Release{}, CategoryNetwork
	}
	// The only header of our own (T-245); Go adds Host and
	// Accept-Encoding, nothing identifying.
	req.Header = http.Header{"User-Agent": {c.userAgent}}
	resp, err := c.http.Do(req)
	if err != nil {
		return Release{}, CategoryNetwork
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return Release{}, CategoryHTTP
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBody+1))
	// A body cut by the timeout can end cleanly: the deadline decides.
	if err != nil || ctx.Err() != nil {
		return Release{}, CategoryNetwork
	}
	if len(body) > MaxBody {
		return Release{}, CategoryParse
	}
	r, err := ParseRelease(body)
	if err != nil {
		return Release{}, CategoryParse
	}
	return r, CategoryNone
}
