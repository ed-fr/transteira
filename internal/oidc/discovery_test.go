package oidc

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/netpolicy"
	"github.com/ed-fr/transteira/internal/oidc/oidctest"
)

// wantTest fails unless r is a failure at stage with category.
func wantTest(t *testing.T, r TestResult, stage, category string) {
	t.Helper()
	if r.Success || r.Stage != stage || r.Error != category {
		t.Fatalf("Test = %+v, want %s/%s", r, stage, category)
	}
}

func TestTestSuccess(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	r := e.c.Test(context.Background(), e.idp.Issuer())
	if !r.Success || r.Stage != StageDone || r.Error != "" || r.Duration < 0 {
		t.Fatalf("Test = %+v", r)
	}
	// The test never fills the cache.
	if len(e.c.providers) != 0 {
		t.Error("Test cached the provider")
	}
}

func TestTestDocumentFailures(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name            string
		b               oidctest.Behavior
		stage, category string
	}{
		{"status", oidctest.Behavior{Status: map[string]int{oidctest.DiscoveryPath: 500}}, StageDiscovery, CategoryHTTPStatus},
		{"redirect not followed", oidctest.Behavior{Redirect: map[string]bool{oidctest.DiscoveryPath: true}}, StageDiscovery, CategoryHTTPStatus},
		{"oversized", oidctest.Behavior{Oversize: map[string]bool{oidctest.DiscoveryPath: true}}, StageDiscovery, CategoryInvalidDocument},
		{"not json", oidctest.Behavior{DiscoveryBody: []byte("<html>")}, StageDiscovery, CategoryInvalidDocument},
		{"wrong issuer", oidctest.Behavior{Discovery: func(d map[string]any) { d["issuer"] = "https://evil.example.com" }}, StageIssuer, CategoryIssuerMismatch},
		{"no jwks", oidctest.Behavior{Discovery: func(d map[string]any) { delete(d, "jwks_uri") }}, StageEndpoints, CategoryMissingEndpoint},
		{"http token endpoint", oidctest.Behavior{Discovery: func(d map[string]any) {
			d["token_endpoint"] = strings.Replace(d["token_endpoint"].(string), "https:", "http:", 1)
		}}, StageEndpoints, CategoryMissingEndpoint},
		{"credentials in authorize", oidctest.Behavior{Discovery: func(d map[string]any) {
			d["authorization_endpoint"] = "https://u:p@idp.example.com/a"
		}}, StageEndpoints, CategoryMissingEndpoint},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			e.idp.SetBehavior(tc.b)
			wantTest(t, e.c.Test(context.Background(), e.idp.Issuer()), tc.stage, tc.category)
		})
	}
}

func TestTestSettings(t *testing.T) {
	t.Parallel()
	c := NewClient(Options{})
	wantTest(t, c.Test(context.Background(), "https://login.microsoftonline.com/common/v2.0"), StageSettings, CategoryInternal)
}

func TestTestTimeout(t *testing.T) {
	t.Parallel()
	idp := oidctest.New(t)
	idp.SetBehavior(oidctest.Behavior{Delay: 3 * time.Second})
	c := NewClient(Options{Guard: loopbackGuard(), RootCAs: idp.CertPool(), Timeout: 200 * time.Millisecond})
	wantTest(t, c.Test(context.Background(), idp.Issuer()), StageDiscovery, CategoryTimeout)
}

func TestTestTLS(t *testing.T) {
	t.Parallel()
	idp := oidctest.New(t)
	// The system roots do not trust the test certificate.
	c := NewClient(Options{Guard: loopbackGuard()})
	wantTest(t, c.Test(context.Background(), idp.Issuer()), StageTLS, CategoryTLS)
}

func TestTestConnect(t *testing.T) {
	t.Parallel()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	c := NewClient(Options{Guard: loopbackGuard()})
	wantTest(t, c.Test(context.Background(), "https://"+addr+"/idp"), StageConnect, CategoryConnect)
}

func TestTestDNS(t *testing.T) {
	t.Parallel()
	for _, r := range []resolver{{err: errors.New("no such host")}, {}} {
		g := netpolicy.NewDialGuardPolicy("sso", netpolicy.Policy{}, r)
		c := NewClient(Options{Guard: g})
		wantTest(t, c.Test(context.Background(), "https://idp.example.test/x"), StageConnect, CategoryDNS)
	}
}

// TestDefaultGuardRefusesInternal proves the default guard refuses
// loopback, private and metadata targets (T-295), whatever the name
// resolves to.
func TestDefaultGuardRefusesInternal(t *testing.T) {
	t.Parallel()
	idp := oidctest.New(t)
	c := NewClient(Options{RootCAs: idp.CertPool()})
	wantTest(t, c.Test(context.Background(), idp.Issuer()), StageConnect, CategoryConnect)
	g := DefaultGuard()
	for _, a := range []string{"127.0.0.1", "10.1.2.3", "192.168.1.1", "172.16.0.1", "169.254.169.254", "::1", "fd00::1"} {
		if !g.Denied(netip.MustParseAddr(a)) {
			t.Errorf("default guard allows %s", a)
		}
	}
	if g.Denied(netip.MustParseAddr("203.0.113.10")) {
		t.Error("default guard refuses a public address")
	}
	_, err := g.DialContext(context.Background(), "tcp", "127.0.0.1:443")
	if !errors.Is(err, netpolicy.ErrAddressDenied) {
		t.Errorf("dial loopback = %v", err)
	}
}

func TestUseProxy(t *testing.T) {
	t.Parallel()
	proxyOf := func(c *Client) any {
		return c.http.Transport.(cappedTransport).next.(*http.Transport).Proxy
	}
	if p := proxyOf(NewClient(Options{})); p.(func(*http.Request) (*url.URL, error)) != nil {
		t.Error("the proxy of the environment is used by default")
	}
	if p := proxyOf(NewClient(Options{UseProxy: true})); p.(func(*http.Request) (*url.URL, error)) == nil {
		t.Error("UseProxy ignored")
	}
}

func TestGetBadURLAndCancel(t *testing.T) {
	t.Parallel()
	c := NewClient(Options{Guard: loopbackGuard()})
	if _, err := c.get(context.Background(), "://bad"); err == nil || err.Category != CategoryInternal {
		t.Errorf("get(bad URL) = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.get(ctx, "https://127.0.0.1:1/x"); err == nil || err.Category != CategoryInternal {
		t.Errorf("get(canceled) = %v", err)
	}
}

func TestGetBodyStall(t *testing.T) {
	t.Parallel()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{"))
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	t.Cleanup(srv.Close)
	pool := srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	c := NewClient(Options{Guard: loopbackGuard(), RootCAs: pool, Timeout: 200 * time.Millisecond})
	_, err := c.get(context.Background(), srv.URL)
	if err == nil || err.Stage != StageDiscovery || err.Category != CategoryTimeout {
		t.Fatalf("get = %v", err)
	}
}

func TestClassify(t *testing.T) {
	t.Parallel()
	bg := context.Background()
	for _, tc := range []struct {
		err   error
		stage string
		want  string
	}{
		{context.DeadlineExceeded, StageConnect, CategoryTimeout},
		{&net.OpError{Err: timeoutError{}}, StageTLS, CategoryTimeout},
		{context.Canceled, StageConnect, CategoryInternal},
		{&net.DNSError{Err: "x"}, StageConnect, CategoryDNS},
		{netpolicy.ErrNoAddress, StageConnect, CategoryDNS},
		{errors.New("handshake"), StageTLS, CategoryTLS},
		{errors.New("reset"), StageDiscovery, CategoryConnect},
		{netpolicy.ErrAddressDenied, StageConnect, CategoryConnect},
	} {
		if got := classify(bg, tc.err, tc.stage); got.Category != tc.want || got.Stage != tc.stage || got.Reason != ReasonIssuerError {
			t.Errorf("classify(%v) = %+v, want %s", tc.err, got, tc.want)
		}
	}
	ctx, cancel := context.WithDeadline(bg, time.Now().Add(-time.Second))
	defer cancel()
	if got := classify(ctx, errors.New("x"), StageConnect); got.Category != CategoryTimeout {
		t.Errorf("classify(expired ctx) = %+v", got)
	}
}

// timeoutError is a net.Error reporting a timeout.
type timeoutError struct{}

func (timeoutError) Error() string   { return "timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return false }

func TestCappedBody(t *testing.T) {
	t.Parallel()
	b := &cappedBody{rc: nopCloser{strings.NewReader(strings.Repeat("a", 10))}, left: 4}
	buf := make([]byte, 100)
	n, err := b.Read(buf)
	if n != 0 || !errors.Is(err, errBodyTooLarge) {
		t.Fatalf("Read = %d, %v", n, err)
	}
	if _, err := b.Read(buf); !errors.Is(err, errBodyTooLarge) {
		t.Fatalf("second Read = %v", err)
	}
	ok := &cappedBody{rc: nopCloser{strings.NewReader("abcd")}, left: 4}
	if n, err := ok.Read(buf); n != 4 || err != nil {
		t.Fatalf("Read at the limit = %d, %v", n, err)
	}
	if err := ok.Close(); err != nil {
		t.Fatal(err)
	}
}

// nopCloser adds a Close to a reader.
type nopCloser struct{ *strings.Reader }

func (nopCloser) Close() error { return nil }

func TestParseDocument(t *testing.T) {
	t.Parallel()
	iss := "https://idp.example.com"
	good := `{"issuer":"https://idp.example.com","authorization_endpoint":"https://idp.example.com/a",` +
		`"token_endpoint":"https://idp.example.com/t","jwks_uri":"https://idp.example.com/k"`
	for _, tc := range []struct {
		body, category string
	}{
		{good + `}`, ""},
		{good + `,"token_endpoint_auth_methods_supported":["client_secret_post"]}`, ""},
		{`[]`, CategoryInvalidDocument},
		{good + `}{}`, CategoryInvalidDocument},
		{`{"jwks_uri":"https://x"}`, CategoryInvalidDocument},
		{`{"issuer":"https://idp.example.com/"}`, CategoryIssuerMismatch},
		{`{"issuer":"https://idp.example.com"}`, CategoryMissingEndpoint},
	} {
		d, err := ParseDocument(iss, []byte(tc.body))
		switch {
		case tc.category == "" && (err != nil || d.Issuer != iss):
			t.Errorf("ParseDocument(%s) = %v", tc.body, err)
		case tc.category != "" && (err == nil || err.Category != tc.category || err.Reason != ReasonIssuerError):
			t.Errorf("ParseDocument(%s) = %v, want %s", tc.body, err, tc.category)
		}
	}
}

func TestClientSecretPost(t *testing.T) {
	t.Parallel()
	for methods, want := range map[string]bool{
		"":                                       false,
		"client_secret_post":                     true,
		"client_secret_basic client_secret_post": false,
		"private_key_jwt":                        false,
	} {
		d := &Document{TokenAuthMethods: strings.Fields(methods)}
		if got := d.clientSecretPost(); got != want {
			t.Errorf("clientSecretPost(%q) = %v", methods, got)
		}
	}
}

func TestProviderCache(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ctx := context.Background()
	p1, err := e.c.provider(ctx, e.idp.Issuer())
	if err != nil {
		t.Fatal(err)
	}
	p2, _ := e.c.provider(ctx, e.idp.Issuer())
	if p1 != p2 || e.idp.Requests(oidctest.DiscoveryPath) != 1 {
		t.Fatalf("cache not used: %d requests", e.idp.Requests(oidctest.DiscoveryPath))
	}
	// After the TTL, the document is fetched again, the key set kept.
	e.clk.Advance(providerTTL)
	p3, err := e.c.provider(ctx, e.idp.Issuer())
	if err != nil || p3 == p1 || p3.keys != p1.keys || e.idp.Requests(oidctest.DiscoveryPath) != 2 {
		t.Fatalf("refresh: %v, same=%v", err, p3 == p1)
	}
	// A clock gone back refreshes too.
	e.clk.Advance(-time.Hour)
	// A new jwks_uri gets a new key set.
	e.idp.SetBehavior(oidctest.Behavior{Discovery: func(d map[string]any) { d["jwks_uri"] = d["jwks_uri"].(string) + "?v=2" }})
	p4, err := e.c.provider(ctx, e.idp.Issuer())
	if err != nil || p4.keys == p3.keys {
		t.Fatalf("new jwks_uri: %v", err)
	}
	// A failing refresh is an error.
	e.clk.Advance(2 * providerTTL)
	e.idp.SetBehavior(oidctest.Behavior{Status: map[string]int{oidctest.DiscoveryPath: 503}})
	if _, err := e.c.provider(ctx, e.idp.Issuer()); err == nil || err.Category != CategoryHTTPStatus {
		t.Fatalf("failing refresh = %v", err)
	}
}

func TestProviderEviction(t *testing.T) {
	t.Parallel()
	a, b, c := oidctest.New(t), oidctest.New(t), oidctest.New(t)
	clk := newClock()
	pool := a.CertPool()
	pool.AddCert(b.Server.Certificate())
	pool.AddCert(c.Server.Certificate())
	cl := NewClient(Options{Guard: loopbackGuard(), RootCAs: pool, Now: clk.Now})
	cl.maxProviders = 2
	ctx := context.Background()
	for _, idp := range []*oidctest.Provider{a, b, c} {
		if _, err := cl.provider(ctx, idp.Issuer()); err != nil {
			t.Fatal(err)
		}
		clk.Advance(time.Second)
	}
	if len(cl.providers) != 2 || cl.providers[b.Issuer()] == nil || cl.providers[c.Issuer()] == nil {
		t.Fatalf("eviction kept %v", cl.providers)
	}
	// Refreshing an entry at the bound evicts nothing.
	clk.Advance(providerTTL)
	if _, err := cl.provider(ctx, b.Issuer()); err != nil || len(cl.providers) != 2 || cl.providers[c.Issuer()] == nil {
		t.Fatalf("refresh at the bound: %v %v", err, cl.providers)
	}
}
