package webhook

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/events"
	"github.com/ed-fr/transteira/internal/netpolicy"
)

var errBoom = errors.New("boom")

// fakeResolver answers from a function of the host and the call number.
type fakeResolver struct {
	mu    sync.Mutex
	calls map[string]int
	fn    func(host string, call int) ([]netip.Addr, error)
}

func (r *fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	r.mu.Lock()
	if r.calls == nil {
		r.calls = map[string]int{}
	}
	r.calls[host]++
	n := r.calls[host]
	r.mu.Unlock()
	return r.fn(host, n)
}

// staticResolver resolves every name in m, any other name to 192.0.2.10
// (a public-like address the built-in deny list leaves open).
func staticResolver(m map[string]string) *fakeResolver {
	return &fakeResolver{fn: func(host string, _ int) ([]netip.Addr, error) {
		if a, ok := m[host]; ok {
			if a == "" {
				return nil, nil
			}
			return []netip.Addr{netip.MustParseAddr(a)}, nil
		}
		if strings.HasSuffix(host, ".invalid") {
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		}
		return []netip.Addr{netip.MustParseAddr("192.0.2.10")}, nil
	}}
}

func mustPrefixes(s ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(s))
	for i, x := range s {
		out[i] = netip.MustParsePrefix(x)
	}
	return out
}

func noInterfaces() ([]net.Addr, error) { return nil, nil }

// receiver is an HTTPS test receiver reachable as example.com.
type receiver struct {
	srv  *httptest.Server
	mu   sync.Mutex
	reqs []*http.Request
	body [][]byte
	// status answers the n-th request (1-based); 204 when nil.
	status func(n int) int
}

func newReceiver(t *testing.T) *receiver {
	t.Helper()
	r := &receiver{}
	r.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.reqs = append(r.reqs, req)
		r.body = append(r.body, b)
		n := len(r.reqs)
		status := r.status
		r.mu.Unlock()
		code := http.StatusNoContent
		if status != nil {
			code = status(n)
		}
		if code == http.StatusFound {
			w.Header().Set("Location", "https://example.com/elsewhere")
		}
		w.WriteHeader(code)
		_, _ = w.Write([]byte(strings.Repeat("x", 10000)))
	}))
	r.srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	t.Cleanup(r.srv.Close)
	return r
}

func (r *receiver) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.reqs)
}

func (r *receiver) port() string {
	u, _ := url.Parse(r.srv.URL)
	return u.Port()
}

// url returns the URL of the receiver under the name example.com.
func (r *receiver) url() string {
	return "https://example.com:" + r.port() + "/hook/T000/B000?token=secret-part"
}

func (r *receiver) tlsConfig() *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(r.srv.Certificate())
	return &tls.Config{RootCAs: pool}
}

// testClient returns a client trusting r, resolving example.com to
// 127.0.0.1 and opening 127.0.0.1.
func testClient(t *testing.T, r *receiver, mod func(*ClientOptions)) *Client {
	t.Helper()
	opts := ClientOptions{
		Allow:          mustPrefixes("127.0.0.1/32"),
		AdminURL:       "https://admin.transfer.example.com/",
		Resolver:       staticResolver(map[string]string{"example.com": "127.0.0.1"}),
		InterfaceAddrs: noInterfaces,
		Timeout:        5 * time.Second,
	}
	if r != nil {
		opts.TLSConfig = r.tlsConfig()
	}
	if mod != nil {
		mod(&opts)
	}
	c, err := NewClient(opts)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestNewClient(t *testing.T) {
	for _, bad := range []string{
		"admin.example.com", "ftp://admin.example.com", "https://", "https://u:p@admin.example.com",
		"https://admin.example.com/?q=1", "https://admin.example.com/#x", "https://admin.example.com/%zz",
	} {
		if _, err := NewClient(ClientOptions{AdminURL: bad, InterfaceAddrs: noInterfaces}); err == nil {
			t.Errorf("admin URL %q accepted", bad)
		}
	}
	if _, err := NewClient(ClientOptions{InterfaceAddrs: func() ([]net.Addr, error) { return nil, errBoom }}); !errors.Is(err, errBoom) {
		t.Errorf("interfaces error: %v", err)
	}
	c, err := NewClient(ClientOptions{
		AdminURL: "http://admin.localhost:8080", InterfaceAddrs: noInterfaces,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS10, ServerName: "x"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if c.adminURL != "http://admin.localhost:8080" || c.resolver != net.DefaultResolver || c.now == nil {
		t.Errorf("defaults: %+v", c)
	}
	tr := c.httpsClient.Transport.(*http.Transport)
	if tr.TLSClientConfig.MinVersion != tls.VersionTLS12 || tr.Proxy != nil || !tr.DisableKeepAlives ||
		c.httpsClient.Timeout != RequestTimeout {
		t.Errorf("transport: %+v", tr)
	}
	if err := c.httpsClient.CheckRedirect(nil, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Error("redirects followed")
	}
	// The local interfaces' networks are denied.
	own, err := NewClient(ClientOptions{
		Resolver: staticResolver(nil),
		InterfaceAddrs: func() ([]net.Addr, error) {
			return []net.Addr{&net.IPNet{IP: net.ParseIP("192.0.2.10").To4(), Mask: net.CIDRMask(24, 32)}}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := own.ValidateURL(context.Background(), "https://hook.example.com/"); !errors.Is(err, ErrURLNotAllowed) {
		t.Errorf("own network: %v", err)
	}
	// The core cannot be opened: a container network, the metadata address,
	// and a plain http network that the allowed networks do not open.
	ownNet := func() ([]net.Addr, error) {
		return []net.Addr{
			&net.IPNet{IP: net.ParseIP("172.18.0.5").To4(), Mask: net.CIDRMask(16, 32)},
			&net.IPNet{IP: net.ParseIP("127.0.0.1").To4(), Mask: net.CIDRMask(8, 32)},
		}, nil
	}
	for name, o := range map[string]ClientOptions{
		"container network": {Allow: mustPrefixes("172.16.0.0/12"), InterfaceAddrs: ownNet},
		"metadata":          {Allow: mustPrefixes("169.254.169.254/32"), InterfaceAddrs: ownNet},
		"http not allowed":  {AllowHTTP: mustPrefixes("10.0.0.0/8"), InterfaceAddrs: ownNet},
	} {
		if _, err := NewClient(o); !errors.Is(err, netpolicy.ErrAllowCore) && !errors.Is(err, netpolicy.ErrAllowHTTPDenied) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// The loopback network of the container stays openable (tests only).
	if _, err := NewClient(ClientOptions{Allow: mustPrefixes("127.0.0.0/8"), InterfaceAddrs: ownNet}); err != nil {
		t.Errorf("loopback: %v", err)
	}
}

func TestValidateURL(t *testing.T) {
	ctx := context.Background()
	c := testClient(t, nil, func(o *ClientOptions) {
		o.Allow = mustPrefixes("10.1.0.0/16")
		o.AllowHTTP = mustPrefixes("10.1.2.0/24", "192.0.2.10/32")
		o.Deny = mustPrefixes("10.1.9.0/24", "203.0.113.0/24")
		o.Resolver = staticResolver(map[string]string{
			"internal.example.com": "10.1.2.3",
			"opened.example.com":   "10.1.5.5",
			"private.example.com":  "10.2.0.1",
			"metadata.example.com": "169.254.169.254",
			"mapped.example.com":   "::ffff:127.0.0.1",
			"closed.example.com":   "10.1.9.9",
			"extra.example.com":    "203.0.113.5",
			"empty.example.com":    "",
			"public.example.org":   "198.51.100.1",
		})
	})
	ok := map[string]string{
		"https://hooks.example.com/services/T0/B0/xyz":         "https://hooks.example.com",
		"HTTPS://Hooks.Example.COM:8443/a?b=c":                 "https://hooks.example.com:8443",
		"https://opened.example.com/x":                         "https://opened.example.com",
		"http://internal.example.com:8080/hook":                "http://internal.example.com:8080",
		"http://192.0.2.10/hook":                               "http://192.0.2.10",
		"https://[2001:db8::1]:443/":                           "https://[2001:db8::1]:443",
		"https://hooks.example.com":                            "https://hooks.example.com",
		"https://hooks.example.com/" + strings.Repeat("a", 64): "https://hooks.example.com",
	}
	for raw, want := range ok {
		hint, err := c.ValidateURL(ctx, raw)
		if err != nil || hint != want {
			t.Errorf("ValidateURL(%q) = %q, %v; want %q", raw, hint, err, want)
		}
	}
	// Plain http with no network allowed for it is refused on the syntax.
	https := testClient(t, nil, nil)
	if _, err := https.ValidateURL(ctx, "http://hooks.example.com/"); !errors.Is(err, ErrURLInvalid) {
		t.Errorf("http without AllowHTTP = %v, want ErrURLInvalid", err)
	}
	invalid := []string{
		"", "hooks.example.com/x", "ftp://hooks.example.com/", "https://", "https:///path",
		"https://user:pass@hooks.example.com/", "https://user@hooks.example.com/",
		"https://hooks.example.com/#frag", "https://hooks.example.com/#",
		"https://hooks.example.com:0/", "https://hooks.example.com:99999/", "https://hooks.example.com:/",
		"https://hooks.example.com:abc/", "https:opaque", "https://" + strings.Repeat("a", 254) + "/",
		"https://[fe80::1%25eth0]/", "https://hooks.example.com/" + strings.Repeat("a", MaxURLLength),
		"http://hooks.example.com\x7f/", "https://hooks example.com/",
	}
	for _, raw := range invalid {
		if _, err := c.ValidateURL(ctx, raw); !errors.Is(err, ErrURLInvalid) {
			t.Errorf("ValidateURL(%q) = %v, want ErrURLInvalid", raw, err)
		} else if raw != "" && strings.Contains(err.Error(), raw) {
			t.Errorf("error quotes the URL: %v", err)
		}
	}
	notAllowed := []string{
		"https://127.0.0.1/", "https://localhost.example.com.private.example.com/",
		"https://private.example.com/", "https://metadata.example.com/", "https://mapped.example.com/",
		"https://closed.example.com/", "https://extra.example.com/", "https://[::1]/", "https://[fd00:ec2::254]/",
		"https://10.0.0.1/", "https://100.64.1.1/", "https://[::ffff:10.0.0.1]/", "https://224.0.0.1/",
		"https://255.255.255.255/", "https://0.0.0.0/", "http://10.1.9.9/",
		// No oracle on the internal DNS: the same answer as a denied address.
		"https://no-such.invalid/", "https://empty.example.com/", "http://public.example.org/",
	}
	c.resolver = staticResolver(map[string]string{
		"localhost.example.com.private.example.com": "127.0.0.2",
		"private.example.com":                       "10.2.0.1",
		"metadata.example.com":                      "169.254.169.254",
		"mapped.example.com":                        "::ffff:127.0.0.1",
		"closed.example.com":                        "10.1.9.9",
		"extra.example.com":                         "203.0.113.5",
		"empty.example.com":                         "",
		"public.example.org":                        "198.51.100.1",
	})
	for _, raw := range notAllowed {
		if _, err := c.ValidateURL(ctx, raw); !errors.Is(err, ErrURLNotAllowed) {
			t.Errorf("ValidateURL(%q) = %v, want ErrURLNotAllowed", raw, err)
		}
	}
}

func FuzzValidateURL(f *testing.F) {
	for _, s := range []string{
		"https://hooks.example.com/services/T0?x=1", "http://hooks.example.com/", "https://u:p@hooks.example.com/",
		"https://[::1]:443/", "https://hooks.example.com:65535/a#b", "javascript:alert(1)", "//hooks.example.com",
		"https://hooks.example.com\\@evil.example.org/",
	} {
		f.Add(s)
	}
	c, err := NewClient(ClientOptions{Resolver: staticResolver(nil), InterfaceAddrs: noInterfaces})
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		hint, err := c.ValidateURL(context.Background(), raw)
		if err != nil {
			if hint != "" {
				t.Fatalf("hint %q with error", hint)
			}
			return
		}
		u, perr := url.Parse(raw)
		if perr != nil || u.User != nil || !strings.EqualFold(u.Scheme, "https") {
			t.Fatalf("accepted %q", raw)
		}
		if !strings.HasPrefix(hint, "https://") || len(hint) > MaxHintLength ||
			strings.ContainsAny(hint[len("https://"):], "/?#@") {
			t.Fatalf("hint %q of %q", hint, raw)
		}
	})
}

func genericTarget(r *receiver) Target {
	return Target{
		ID: "whk_1", TenantID: "ten_a", TenantName: "Entity A", Kind: KindGeneric, URL: r.url(),
		Secret: []byte(strings.Repeat("ab", 32)), Events: []events.Type{events.VirusDetected, events.DiskAlertRaised},
		Version: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC),
	}
}

func testEvent() events.Event {
	return events.Event{
		ID: "evt_1", Type: events.VirusDetected, Severity: events.SeverityCritical,
		OccurredAt: time.Date(2026, 10, 27, 9, 0, 0, 0, time.UTC), TenantID: "ten_a",
		Counts: map[string]float64{"files": 1}, AdminPath: "/admin/tenants/ten_a/audit",
		Addresses: &events.Addresses{Sender: "alice@entity-a.example.com"},
	}
}

func TestSendSuccess(t *testing.T) {
	r := newReceiver(t)
	c := testClient(t, r, nil)
	res := c.Send(context.Background(), genericTarget(r), testEvent())
	if !res.Success || res.HTTPStatus != http.StatusNoContent || res.Category != CategoryNone {
		t.Fatalf("result %+v", res)
	}
	req := r.reqs[0]
	if req.Method != http.MethodPost || req.Header.Get("Content-Type") != "application/json" ||
		!strings.HasPrefix(req.Header.Get("User-Agent"), "TransTeira/") ||
		req.Header.Get(HeaderEvent) != "virus.detected" || req.Header.Get(HeaderDelivery) != "evt_1" ||
		req.URL.RawQuery != "token=secret-part" {
		t.Errorf("request %v %v", req.Header, req.URL)
	}
	if err := verifySignature(req.Header.Get(HeaderSignature), []byte(strings.Repeat("ab", 32)), r.body[0], time.Now()); err != nil {
		t.Errorf("signature: %v", err)
	}
	for _, kind := range []Kind{KindTeams, KindSlack} {
		tg := genericTarget(r)
		tg.Kind, tg.Secret = kind, nil
		if res := c.Send(context.Background(), tg, testEvent()); !res.Success {
			t.Errorf("%s: %+v", kind, res)
		}
	}
	if got := r.reqs[1].Header.Get(HeaderSignature); got != "" {
		t.Errorf("teams signed: %q", got)
	}
	// A generic webhook without secret is sent unsigned.
	tg := genericTarget(r)
	tg.Secret = nil
	if res := c.Send(context.Background(), tg, testEvent()); !res.Success || r.reqs[3].Header.Get(HeaderSignature) != "" {
		t.Errorf("unsigned: %+v", res)
	}
	// The test event.
	if res := c.SendTest(context.Background(), genericTarget(r), time.Now()); !res.Success ||
		r.reqs[4].Header.Get(HeaderEvent) != "webhook.test" {
		t.Errorf("test: %+v", res)
	}
}

func TestSendFailures(t *testing.T) {
	ctx := context.Background()
	r := newReceiver(t)
	r.status = func(int) int { return http.StatusInternalServerError }
	c := testClient(t, r, nil)
	res := c.Send(ctx, genericTarget(r), testEvent())
	if res.Success || res.HTTPStatus != 500 || res.Category != CategoryHTTPStatus {
		t.Errorf("500: %+v", res)
	}
	// A redirect is not followed and counts as a failure.
	r.status = func(int) int { return http.StatusFound }
	before := r.count()
	res = c.Send(ctx, genericTarget(r), testEvent())
	if res.Success || res.HTTPStatus != http.StatusFound || res.Category != CategoryHTTPStatus || r.count() != before+1 {
		t.Errorf("redirect: %+v", res)
	}

	// The receiver on a private address is refused without the allow list.
	closed := testClient(t, r, func(o *ClientOptions) { o.Allow = nil })
	if res := closed.Send(ctx, genericTarget(r), testEvent()); res.Category != CategoryRefusedNetwork {
		t.Errorf("private: %+v", res)
	}
	// DNS rebinding: public at validation, loopback at connection.
	rebind := testClient(t, r, func(o *ClientOptions) {
		o.Allow = nil
		o.Resolver = &fakeResolver{fn: func(_ string, call int) ([]netip.Addr, error) {
			if call == 1 {
				return []netip.Addr{netip.MustParseAddr("192.0.2.10")}, nil
			}
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		}}
	})
	if _, err := rebind.ValidateURL(ctx, r.url()); err != nil {
		t.Fatalf("validation: %v", err)
	}
	if res := rebind.Send(ctx, genericTarget(r), testEvent()); res.Category != CategoryRefusedNetwork {
		t.Errorf("rebinding: %+v", res)
	}

	// Untrusted certificate.
	untrusted := testClient(t, r, func(o *ClientOptions) { o.TLSConfig = nil })
	if res := untrusted.Send(ctx, genericTarget(r), testEvent()); res.Category != CategoryTLS {
		t.Errorf("tls: %+v", res)
	}
	// Name resolution failures.
	tg := genericTarget(r)
	tg.URL = "https://no-such.invalid/"
	if res := c.Send(ctx, tg, testEvent()); res.Category != CategoryDNS {
		t.Errorf("dns: %+v", res)
	}
	// Connection refused.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	tg.URL = fmt.Sprintf("https://example.com:%d/", port)
	if res := c.Send(ctx, tg, testEvent()); res.Category != CategoryConnect {
		t.Errorf("connect: %+v", res)
	}
	// Timeout.
	slow := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
		_, _ = io.Copy(io.Discard, req.Body)
		select {
		case <-req.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
	defer slow.Close()
	pool := x509.NewCertPool()
	pool.AddCert(slow.Certificate())
	fast := testClient(t, nil, func(o *ClientOptions) {
		o.Timeout = 200 * time.Millisecond
		o.TLSConfig = &tls.Config{RootCAs: pool}
	})
	su, _ := url.Parse(slow.URL)
	tg.URL = "https://example.com:" + su.Port() + "/"
	if res := fast.Send(ctx, tg, testEvent()); res.Category != CategoryTimeout {
		t.Errorf("timeout: %+v", res)
	}

	// Unusable targets.
	for _, bad := range []Target{
		{Kind: KindGeneric, URL: "ftp://example.com/"},
		{Kind: "pager", URL: r.url()},
	} {
		if res := c.Send(ctx, bad, testEvent()); res.Category != CategoryConnect {
			t.Errorf("target %+v: %+v", bad, res)
		}
	}
	// Plain http without an http allow list.
	tg.URL = "http://example.com:" + r.port() + "/"
	if res := c.Send(ctx, tg, testEvent()); res.Category != CategoryRefusedNetwork {
		t.Errorf("http: %+v", res)
	}
	// Request creation failure: a nil context.
	var nilCtx context.Context
	if res := c.Send(nilCtx, genericTarget(r), testEvent()); res.Category != CategoryConnect {
		t.Errorf("nil ctx: %+v", res)
	}
}

func TestSendPlainHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	tg := Target{ID: "whk_1", Kind: KindSlack, URL: "http://example.com:" + u.Port() + "/"}
	c := testClient(t, nil, func(o *ClientOptions) { o.AllowHTTP = mustPrefixes("127.0.0.1/32") })
	if res := c.Send(context.Background(), tg, testEvent()); !res.Success || res.HTTPStatus != 200 {
		t.Errorf("http allowed: %+v", res)
	}
	// The http guard refuses an address outside the http allow list, even
	// when the https policy opens it.
	other := testClient(t, nil, func(o *ClientOptions) { o.AllowHTTP = mustPrefixes("192.0.2.0/24") })
	if res := other.Send(context.Background(), tg, testEvent()); res.Category != CategoryRefusedNetwork {
		t.Errorf("http outside: %+v", res)
	}
}

// timeoutError is a net.Error reporting a timeout.
type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func TestClassify(t *testing.T) {
	for err, want := range map[error]ErrorCategory{
		fmt.Errorf("x: %w", netpolicy.ErrAddressDenied):               CategoryRefusedNetwork,
		fmt.Errorf("x: %w", netpolicy.ErrResolve):                     CategoryDNS,
		fmt.Errorf("x: %w", netpolicy.ErrNoAddress):                   CategoryDNS,
		&net.DNSError{Err: "x", Name: "example.com"}:                  CategoryDNS,
		context.DeadlineExceeded:                                      CategoryTimeout,
		context.Canceled:                                              CategoryTimeout,
		os.ErrDeadlineExceeded:                                        CategoryTimeout,
		timeoutError{}:                                                CategoryTimeout,
		&tls.CertificateVerificationError{Err: errBoom}:               CategoryTLS,
		tls.AlertError(40):                                            CategoryTLS,
		tls.RecordHeaderError{Msg: "x"}:                               CategoryTLS,
		x509.UnknownAuthorityError{}:                                  CategoryTLS,
		x509.HostnameError{Certificate: &x509.Certificate{}}:          CategoryTLS,
		x509.CertificateInvalidError{Cert: &x509.Certificate{}}:       CategoryTLS,
		errors.New("remote error: tls: handshake failure"):            CategoryTLS,
		errors.New("x509: certificate signed by unknown authority"):   CategoryTLS,
		&net.OpError{Op: "dial", Err: errors.New("connection reset")}: CategoryConnect,
	} {
		if got := classify(err); got != want {
			t.Errorf("classify(%v) = %q, want %q", err, got, want)
		}
	}
}

func TestTestEvent(t *testing.T) {
	now := time.Date(2026, 10, 27, 9, 0, 0, 0, time.UTC)
	ev := TestEvent(Target{TenantID: "ten_a"}, now)
	if ev.Type != events.WebhookTest || ev.TenantID != "ten_a" || ev.AdminPath != "/admin/tenants/ten_a/webhooks" ||
		!strings.HasPrefix(ev.ID, "evt_") || !ev.OccurredAt.Equal(now) || ev.Counts == nil {
		t.Errorf("tenant test event %+v", ev)
	}
	if ev := TestEvent(Target{}, now); ev.TenantID != "" || ev.AdminPath != "/admin/system/webhooks" {
		t.Errorf("system test event %+v", ev)
	}
}
