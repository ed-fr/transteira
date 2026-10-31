package updatecheck

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/store"
)

const releasePage = "https://github.com/ed-fr/transteira/releases/tag/v1.2.1"

// memStore is an in-memory Store with injectable errors.
type memStore struct {
	mu       sync.Mutex
	value    []byte
	updated  time.Time
	puts     int
	getErr   error
	putErr   error
	putClock func() time.Time
}

func (m *memStore) Get(_ context.Context, key string) (store.SystemStateValue, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if key != store.SystemStateUpdateCheck {
		return store.SystemStateValue{}, store.ErrInvalid
	}
	if m.getErr != nil {
		return store.SystemStateValue{}, m.getErr
	}
	if m.value == nil {
		return store.SystemStateValue{}, store.ErrNotFound
	}
	return store.SystemStateValue{Value: append([]byte(nil), m.value...), UpdatedAt: m.updated}, nil
}

func (m *memStore) Put(_ context.Context, key string, value []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if key != store.SystemStateUpdateCheck {
		return store.ErrInvalid
	}
	if m.putErr != nil {
		return m.putErr
	}
	m.value, m.puts = append([]byte(nil), value...), m.puts+1
	if m.putClock != nil {
		m.updated = m.putClock()
	}
	return nil
}

func (m *memStore) stored() (string, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return string(m.value), m.puts
}

func superAdmin() adminauth.Principal {
	return adminauth.Principal{
		SessionID: "as_1", State: store.SessionAuthenticated,
		Admin: adminauth.Account{Username: "root", Role: store.RoleSuperAdmin},
	}
}

func delegated() adminauth.Principal {
	p := superAdmin()
	p.Admin.Role = store.RoleDelegatedAdmin
	return p
}

// fakeClock is a settable clock.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *fakeClock { return &fakeClock{t: time.Date(2026, 10, 31, 6, 0, 0, 0, time.UTC)} }

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// github is a fake GitHub API over TLS, recording the requests.
type github struct {
	srv      *httptest.Server
	hits     atomic.Int32
	mu       sync.Mutex
	requests []*http.Request
	handler  http.HandlerFunc
}

func newGitHub(t *testing.T, h http.HandlerFunc) *github {
	t.Helper()
	g := &github{handler: h}
	g.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.hits.Add(1)
		g.mu.Lock()
		g.requests = append(g.requests, r.Clone(r.Context()))
		h := g.handler
		g.mu.Unlock()
		h(w, r)
	}))
	g.srv.Config.ErrorLog = log.New(io.Discard, "", 0) // refused handshakes are expected
	g.srv.StartTLS()
	t.Cleanup(g.srv.Close)
	return g
}

func (g *github) set(h http.HandlerFunc) {
	g.mu.Lock()
	g.handler = h
	g.mu.Unlock()
}

// roots trusts the certificate of the fake server.
func (g *github) roots() *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(g.srv.Certificate())
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
}

func answer(status int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}
}

func release(tag, page string) string {
	return `{"tag_name":"` + tag + `","html_url":"` + page + `","draft":false,"prerelease":false,` +
		`"name":"<img src=x onerror=alert(1)>","body":"## Notes with [a link](https://evil.example.com)"}`
}

// fixture is a service wired to a fake GitHub.
type fixture struct {
	svc   *Service
	gh    *github
	st    *memStore
	clock *fakeClock
	logs  *syncBuffer
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func newFixture(t *testing.T, h http.HandlerFunc, edit func(*Options)) *fixture {
	t.Helper()
	f := &fixture{gh: newGitHub(t, h), st: &memStore{}, clock: newClock(), logs: &syncBuffer{}}
	f.st.putClock = f.clock.now
	opts := Options{
		Enabled: true, Current: "1.2.0", Now: f.clock.now,
		Logger: slog.New(slog.NewTextHandler(f.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		client: clientOptions{
			url: f.gh.srv.URL + "/repos/ed-fr/transteira/releases/latest", tlsConfig: f.gh.roots(),
			proxy: func(*http.Request) (*url.URL, error) { return nil, nil },
		},
		random: func(time.Duration) time.Duration { return 0 },
	}
	if edit != nil {
		edit(&opts)
	}
	f.svc = New(f.st, opts)
	t.Cleanup(func() { _ = f.svc.Close(context.Background()) })
	return f
}

func (f *fixture) check(t *testing.T) Status {
	t.Helper()
	st, err := f.svc.CheckNow(t.Context(), superAdmin())
	if err != nil {
		t.Fatalf("CheckNow = %v", err)
	}
	f.clock.advance(time.Minute) // past the manual limit
	return st
}

func TestCheckSuccess(t *testing.T) {
	t.Parallel()
	f := newFixture(t, answer(http.StatusOK, release("v1.2.1", releasePage)), nil)
	got := f.check(t)
	want := Status{
		Enabled: true, LatestVersion: "1.2.1", ReleaseURL: releasePage, UpdateAvailable: true,
		CheckedAt: newClock().now(), LastError: CategoryNone,
	}
	if got != want {
		t.Errorf("CheckNow = %+v, want %+v", got, want)
	}
	if st, err := f.svc.Status(t.Context(), superAdmin()); err != nil || st != want {
		t.Errorf("Status = %+v, %v; want %+v", st, err, want)
	}
	// Only the kept fields are stored: never the name nor the notes.
	stored, puts := f.st.stored()
	if puts != 1 || strings.Contains(stored, "img") || strings.Contains(stored, "Notes") || strings.Contains(stored, "evil") {
		t.Errorf("stored %q (%d writes)", stored, puts)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(stored), &doc); err != nil || len(doc) != 4 {
		t.Errorf("stored document %q: %v", stored, err)
	}
	// The request: GET, the fixed path, only the User-Agent of our own.
	f.gh.mu.Lock()
	r := f.gh.requests[0]
	f.gh.mu.Unlock()
	if r.Method != http.MethodGet || r.URL.Path != "/repos/ed-fr/transteira/releases/latest" || r.URL.RawQuery != "" {
		t.Errorf("request %s %s", r.Method, r.URL)
	}
	if ua := r.Header.Get("User-Agent"); ua != "TransTeira/1.2.0" {
		t.Errorf("User-Agent = %q", ua)
	}
	for name := range r.Header {
		// Accept-Encoding and Connection: close are added by the Go
		// transport, nothing identifying.
		if name != "User-Agent" && name != "Accept-Encoding" && name != "Connection" {
			t.Errorf("unexpected header %s: %q", name, r.Header.Get(name))
		}
	}
	if r.ContentLength > 0 {
		t.Errorf("request with a body")
	}
}

func TestCheckVersions(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, body    string
		wantLatest    string
		wantURL       string
		wantAvailable bool
		wantErr       Category
	}{
		{"equal", release("v1.2.0", ReleasePagePrefix+"tag/v1.2.0"), "1.2.0", ReleasePagePrefix + "tag/v1.2.0", false, CategoryNone},
		{"lower", release("v1.1.9", ReleasePagePrefix+"tag/v1.1.9"), "1.1.9", ReleasePagePrefix + "tag/v1.1.9", false, CategoryNone},
		{"newer, foreign url", release("v1.3.0", "https://evil.example.com/ed-fr/transteira/releases/tag/v1.3.0"), "1.3.0", "", true, CategoryNone},
		{"newer, port", release("v1.3.0", "https://github.com:8443/ed-fr/transteira/releases/tag/v1.3.0"), "1.3.0", "", true, CategoryNone},
		{"newer, userinfo", release("v1.3.0", "https://a@github.com/ed-fr/transteira/releases/tag/v1.3.0"), "1.3.0", "", true, CategoryNone},
		{"newer, dot dot", release("v1.3.0", ReleasePagePrefix+"../../evil"), "1.3.0", "", true, CategoryNone},
		{"not semver", release("latest", releasePage), "", "", false, CategoryParse},
		{"too long", release("v1.2.3+"+strings.Repeat("a", 60), releasePage), "", "", false, CategoryParse},
		{"draft", `{"tag_name":"v9.0.0","draft":true}`, "", "", false, CategoryNone},
		{"prerelease", `{"tag_name":"v9.0.0","prerelease":true}`, "", "", false, CategoryNone},
		{"prerelease suffix", `{"tag_name":"v9.0.0-beta.1"}`, "", "", false, CategoryNone},
		{"not json", `<html>rate limited</html>`, "", "", false, CategoryParse},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t, answer(http.StatusOK, tt.body), nil)
			got := f.check(t)
			if got.LatestVersion != tt.wantLatest || got.ReleaseURL != tt.wantURL ||
				got.UpdateAvailable != tt.wantAvailable || got.LastError != tt.wantErr {
				t.Errorf("CheckNow = %+v", got)
			}
			if (tt.wantErr == CategoryNone) == got.CheckedAt.IsZero() {
				t.Errorf("CheckedAt = %v with lastError %s", got.CheckedAt, got.LastError)
			}
		})
	}
}

// A failure keeps the last good result and only updates lastError; a
// draft keeps it too, with a new date.
func TestCheckKeepsLastGoodResult(t *testing.T) {
	t.Parallel()
	f := newFixture(t, answer(http.StatusOK, release("v1.2.1", releasePage)), nil)
	first := f.check(t)
	for _, c := range []struct {
		h    http.HandlerFunc
		want Category
	}{
		{answer(http.StatusForbidden, `{"message":"API rate limit exceeded for 203.0.113.7"}`), CategoryHTTP},
		{answer(http.StatusOK, `{"tag_name":"nope"}`), CategoryParse},
		{answer(http.StatusInternalServerError, ``), CategoryHTTP},
	} {
		f.gh.set(c.h)
		got := f.check(t)
		if got.LatestVersion != "1.2.1" || got.ReleaseURL != releasePage || !got.UpdateAvailable ||
			!got.CheckedAt.Equal(first.CheckedAt) || got.LastError != c.want {
			t.Errorf("after a %s failure: %+v", c.want, got)
		}
	}
	f.gh.set(answer(http.StatusOK, `{"tag_name":"v2.0.0","draft":true}`))
	got := f.check(t)
	if got.LatestVersion != "1.2.1" || got.LastError != CategoryNone || !got.CheckedAt.After(first.CheckedAt) {
		t.Errorf("after a draft: %+v", got)
	}
	if strings.Contains(f.logs.String(), "203.0.113.7") || strings.Contains(f.logs.String(), "rate limit") {
		t.Errorf("the answer leaked into the logs: %s", f.logs.String())
	}
}

func TestCheckRedirectNotFollowed(t *testing.T) {
	t.Parallel()
	var followed atomic.Bool
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		followed.Store(true)
		_, _ = io.WriteString(w, release("v9.9.9", releasePage))
	}))
	t.Cleanup(target.Close)
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/latest", http.StatusFound)
	}, nil)
	got := f.check(t)
	if got.LastError != CategoryHTTP || got.LatestVersion != "" || followed.Load() {
		t.Errorf("CheckNow after a redirection = %+v (followed %v)", got, followed.Load())
	}
}

func TestCheckBodyLimit(t *testing.T) {
	t.Parallel()
	// Exactly MaxBody bytes are accepted, one more is refused.
	pad := func(n int) string {
		base := `{"tag_name":"v1.2.1","body":""}`
		return `{"tag_name":"v1.2.1","body":"` + strings.Repeat("a", n-len(base)) + `"}`
	}
	f := newFixture(t, answer(http.StatusOK, pad(MaxBody)), nil)
	if got := f.check(t); got.LastError != CategoryNone || got.LatestVersion != "1.2.1" {
		t.Errorf("CheckNow(%d bytes) = %+v", MaxBody, got)
	}
	f.gh.set(answer(http.StatusOK, pad(MaxBody+1)))
	if got := f.check(t); got.LastError != CategoryParse {
		t.Errorf("CheckNow(%d bytes) = %+v", MaxBody+1, got)
	}
}

func TestCheckTimeout(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	f := newFixture(t, func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}, func(o *Options) { o.client.timeout = 200 * time.Millisecond })
	start := time.Now()
	got := f.check(t)
	if got.LastError != CategoryNetwork || time.Since(start) > 5*time.Second {
		t.Errorf("CheckNow against a silent server = %+v after %v", got, time.Since(start))
	}
	// A body that stalls after the headers is cut by the same timeout.
	f.gh.set(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"tag_name":`)
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	if got := f.check(t); got.LastError != CategoryNetwork {
		t.Errorf("CheckNow against a stalled body = %+v", got)
	}
	if New(f.st, Options{}).client.http.Timeout != Timeout {
		t.Errorf("the default timeout is not %v", Timeout)
	}
}

// The certificate of the fake server is not trusted by the system roots:
// the check fails, and no option disables the verification.
func TestCheckInvalidCertificate(t *testing.T) {
	t.Parallel()
	f := newFixture(t, answer(http.StatusOK, release("v1.2.1", releasePage)), func(o *Options) {
		o.client.tlsConfig = &tls.Config{InsecureSkipVerify: true} // the client must reset it
	})
	if got := f.check(t); got.LastError != CategoryNetwork || got.LatestVersion != "" {
		t.Errorf("CheckNow with an untrusted certificate = %+v", got)
	}
	f.svc = New(f.st, Options{Enabled: true, Current: "1.2.0", Now: f.clock.now, Logger: slog.New(slog.DiscardHandler), client: clientOptions{
		url: f.gh.srv.URL, proxy: func(*http.Request) (*url.URL, error) { return nil, nil },
	}})
	if got := f.check(t); got.LastError != CategoryNetwork {
		t.Errorf("CheckNow with the system roots = %+v", got)
	}
	if f.gh.hits.Load() != 0 {
		t.Errorf("the server answered %d requests over an untrusted TLS session", f.gh.hits.Load())
	}
}

// A network failure reports the category only, never the address.
func TestCheckNetworkError(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	f := newFixture(t, nil, func(o *Options) { o.client.url = "https://" + addr + "/latest" })
	got := f.check(t)
	if got.LastError != CategoryNetwork {
		t.Errorf("CheckNow = %+v", got)
	}
	stored, _ := f.st.stored()
	for _, out := range []string{stored, f.logs.String()} {
		if strings.Contains(out, "127.0.0.1") || strings.Contains(out, "refused") || strings.Contains(out, "dial") {
			t.Errorf("the raw error leaked: %s", out)
		}
	}
	if !strings.Contains(f.logs.String(), "category=network") {
		t.Errorf("the failure is not logged with its category: %s", f.logs.String())
	}
	// A malformed request URL (never the case with ReleasesURL) is a
	// network failure too.
	f.svc.client.url = "://bad"
	if r, c := f.svc.client.fetch(t.Context()); c != CategoryNetwork || r != (Release{}) {
		t.Errorf("fetch(bad URL) = %+v, %s", r, c)
	}
}

// connectProxy is a minimal HTTPS proxy (CONNECT only), recording the
// tunnels it opened.
func connectProxy(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var tunnels atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT only", http.StatusMethodNotAllowed)
			return
		}
		upstream, err := net.Dial("tcp", r.Host)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		tunnels.Add(1)
		w.WriteHeader(http.StatusOK)
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			_ = upstream.Close()
			return
		}
		go func() { _, _ = io.Copy(upstream, rw); _ = upstream.Close() }()
		_, _ = io.Copy(conn, bufio.NewReader(upstream))
		_ = conn.Close()
	}))
	t.Cleanup(srv.Close)
	return srv, &tunnels
}

// Through a proxy (HTTPS_PROXY), the request goes through a CONNECT
// tunnel and TLS is still verified end to end; the proxy may sit on a
// private network (no egress guard on this client).
func TestCheckThroughProxy(t *testing.T) {
	t.Parallel()
	proxy, tunnels := connectProxy(t)
	proxyURL, _ := url.Parse(proxy.URL)
	f := newFixture(t, answer(http.StatusOK, release("v1.2.1", releasePage)), func(o *Options) {
		o.client.proxy = http.ProxyURL(proxyURL)
	})
	if got := f.check(t); got.LastError != CategoryNone || got.LatestVersion != "1.2.1" || tunnels.Load() != 1 {
		t.Errorf("CheckNow through the proxy = %+v (%d tunnels)", got, tunnels.Load())
	}
	// A proxy that fails is a network failure.
	f.svc.client.http.Transport.(*http.Transport).Proxy = func(*http.Request) (*url.URL, error) {
		return nil, errors.New("proxy secret.internal:3128 refused")
	}
	if got := f.check(t); got.LastError != CategoryNetwork || strings.Contains(f.logs.String(), "secret.internal") {
		t.Errorf("CheckNow with a failing proxy = %+v", got)
	}
}

// TT_UPDATE_CHECK=false: no connection at all, nothing written, 409 on a
// manual check.
func TestDisabled(t *testing.T) {
	t.Parallel()
	f := newFixture(t, answer(http.StatusOK, release("v1.2.1", releasePage)), func(o *Options) {
		o.Enabled = false
		o.StartDelay = time.Millisecond
	})
	f.st.value = []byte(`{"latestVersion":"1.2.1","releaseUrl":null,"checkedAt":null,"lastError":"none"}`)
	if err := f.svc.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.CheckNow(t.Context(), superAdmin()); !errors.Is(err, ErrDisabled) {
		t.Errorf("CheckNow = %v, want ErrDisabled", err)
	}
	st, err := f.svc.Status(t.Context(), superAdmin())
	if err != nil || st != (Status{LastError: CategoryNone}) || f.svc.Enabled() {
		t.Errorf("Status = %+v, %v", st, err)
	}
	time.Sleep(50 * time.Millisecond)
	if err := f.svc.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, puts := f.st.stored(); f.gh.hits.Load() != 0 || puts != 0 {
		t.Errorf("disabled: %d requests, %d writes", f.gh.hits.Load(), puts)
	}
}

func TestRolesAndRateLimit(t *testing.T) {
	t.Parallel()
	f := newFixture(t, answer(http.StatusOK, release("v1.2.1", releasePage)), nil)
	for _, p := range []adminauth.Principal{delegated(), {}} {
		if _, err := f.svc.CheckNow(t.Context(), p); err == nil {
			t.Errorf("CheckNow(%s) succeeded", p.Admin.Role)
		}
		if _, err := f.svc.Status(t.Context(), p); err == nil {
			t.Errorf("Status(%s) succeeded", p.Admin.Role)
		}
	}
	if _, err := f.svc.CheckNow(t.Context(), delegated()); !errors.Is(err, adminauth.ErrForbidden) {
		t.Errorf("CheckNow(delegated) = %v, want ErrForbidden", err)
	}
	if _, err := f.svc.CheckNow(t.Context(), superAdmin()); err != nil {
		t.Fatal(err)
	}
	f.clock.advance(20 * time.Second)
	var limited *RateLimitError
	if _, err := f.svc.CheckNow(t.Context(), superAdmin()); !errors.As(err, &limited) || limited.RetryAfter != 40*time.Second {
		t.Fatalf("second CheckNow = %v, want a rate limit of 40s", err)
	}
	if limited.Error() == "" {
		t.Error("empty error message")
	}
	f.clock.advance(40 * time.Second)
	if _, err := f.svc.CheckNow(t.Context(), superAdmin()); err != nil {
		t.Errorf("CheckNow a minute later = %v", err)
	}
	// A clock set back does not lock the manual check.
	f.clock.advance(-time.Hour)
	if _, err := f.svc.CheckNow(t.Context(), superAdmin()); err != nil {
		t.Errorf("CheckNow after the clock went back = %v", err)
	}
	if n := f.gh.hits.Load(); n != 3 {
		t.Errorf("%d requests, want 3", n)
	}
}

// One check at a time: callers asking meanwhile share it.
func TestOneCheckInFlight(t *testing.T) {
	t.Parallel()
	gate := make(chan struct{})
	entered := make(chan struct{}, 4)
	f := newFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		entered <- struct{}{}
		<-gate
		_, _ = io.WriteString(w, release("v1.2.1", releasePage))
	}, nil)
	results := make(chan Status, 3)
	go func() {
		st, _ := f.svc.CheckNow(context.Background(), superAdmin())
		results <- st
	}()
	<-entered
	for range 2 {
		go func() {
			st, _ := f.svc.run(context.Background())
			results <- f.svc.status(st)
		}()
	}
	// A caller giving up does not stop the shared check.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := f.svc.run(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("run(canceled) = %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	close(gate)
	for range 3 {
		if st := <-results; st.LatestVersion != "1.2.1" {
			t.Errorf("shared result %+v", st)
		}
	}
	if n := f.gh.hits.Load(); n != 1 {
		t.Errorf("%d requests, want 1", n)
	}
}

func TestStoredStateRevalidated(t *testing.T) {
	t.Parallel()
	valid := `{"latestVersion":"1.2.1","releaseUrl":"` + releasePage + `","checkedAt":"2026-10-30T06:00:00Z","lastError":"network"}`
	f := newFixture(t, nil, nil)
	f.st.value = []byte(valid)
	st, err := f.svc.Status(t.Context(), superAdmin())
	if err != nil || st.LatestVersion != "1.2.1" || st.ReleaseURL != releasePage || !st.UpdateAvailable ||
		st.LastError != CategoryNetwork || !st.CheckedAt.Equal(time.Date(2026, 10, 30, 6, 0, 0, 0, time.UTC)) {
		t.Errorf("Status(valid) = %+v, %v", st, err)
	}
	for name, raw := range map[string]string{
		"not json":         `{`,
		"null":             `null`,
		"array":            `[]`,
		"unknown member":   `{"lastError":"none","name":"<b>x</b>"}`,
		"trailing":         `{"lastError":"none"} {}`,
		"unknown error":    `{"lastError":"boom"}`,
		"missing error":    `{"latestVersion":"1.2.1"}`,
		"prerelease":       `{"latestVersion":"9.0.0-rc.1","lastError":"none"}`,
		"not semver":       `{"latestVersion":"<script>","lastError":"none"}`,
		"foreign url":      `{"latestVersion":"1.2.1","releaseUrl":"https://evil.example.com/x","lastError":"none"}`,
		"url sans version": `{"releaseUrl":"` + releasePage + `","lastError":"none"}`,
		"zero date":        `{"checkedAt":"0001-01-01T00:00:00Z","lastError":"none"}`,
		"bad date":         `{"checkedAt":"yesterday","lastError":"none"}`,
	} {
		f.st.value = []byte(raw)
		st, err := f.svc.Status(t.Context(), superAdmin())
		if err != nil || st != (Status{Enabled: true, LastError: CategoryNone}) {
			t.Errorf("Status(%s) = %+v, %v; want never checked", name, st, err)
		}
	}
	if !strings.Contains(f.logs.String(), "invalid") {
		t.Errorf("an invalid stored value is not logged: %s", f.logs.String())
	}
	// A database failure is an error of Status.
	f.st.getErr = errors.New("database down")
	if _, err := f.svc.Status(t.Context(), superAdmin()); err == nil {
		t.Error("Status with a failing store succeeded")
	}
	// Never checked.
	f.st.getErr, f.st.value = nil, nil
	if st, err := f.svc.Status(t.Context(), superAdmin()); err != nil || st != (Status{Enabled: true, LastError: CategoryNone}) {
		t.Errorf("Status(never checked) = %+v, %v", st, err)
	}
}

// A failing store does not prevent the check from answering.
func TestCheckWithFailingStore(t *testing.T) {
	t.Parallel()
	f := newFixture(t, answer(http.StatusOK, release("v1.2.1", releasePage)), nil)
	f.st.getErr, f.st.putErr = errors.New("read failed"), errors.New("write failed")
	if got := f.check(t); got.LatestVersion != "1.2.1" || got.LastError != CategoryNone {
		t.Errorf("CheckNow = %+v", got)
	}
	logs := f.logs.String()
	if !strings.Contains(logs, "failed to read") || !strings.Contains(logs, "failed to record") {
		t.Errorf("store failures not logged: %s", logs)
	}
}

func TestBackgroundLoop(t *testing.T) {
	t.Parallel()
	f := newFixture(t, answer(http.StatusOK, release("v1.2.1", releasePage)), func(o *Options) {
		o.StartDelay, o.Interval, o.Jitter = 10*time.Millisecond, 20*time.Millisecond, time.Millisecond
	})
	if err := f.svc.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Start(t.Context()); !errors.Is(err, ErrStarted) {
		t.Errorf("second Start = %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for f.gh.hits.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if err := f.svc.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	n := f.gh.hits.Load()
	if n < 2 {
		t.Fatalf("%d background checks, want at least 2", n)
	}
	time.Sleep(50 * time.Millisecond)
	if f.gh.hits.Load() != n {
		t.Error("the loop kept running after Close")
	}
	if err := f.svc.Start(t.Context()); !errors.Is(err, ErrClosed) {
		t.Errorf("Start after Close = %v", err)
	}
	if _, err := f.svc.CheckNow(t.Context(), superAdmin()); !errors.Is(err, ErrClosed) {
		t.Errorf("CheckNow after Close = %v", err)
	}
	if err := f.svc.Close(t.Context()); err != nil {
		t.Errorf("second Close = %v", err)
	}
}

// The start-up makes no request: the first check waits StartDelay at
// least, and Interval after the last attempt recorded.
func TestFirstDelay(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil, func(o *Options) {
		o.StartDelay, o.Interval, o.Jitter = 5*time.Minute, 24*time.Hour, time.Hour
		o.random = func(n time.Duration) time.Duration { return n / 2 }
	})
	if d := f.svc.firstDelay(); d != 7*time.Minute+30*time.Second {
		t.Errorf("firstDelay(never checked) = %v", d)
	}
	f.st.value, f.st.updated = []byte(`{"lastError":"network"}`), f.clock.now().Add(-2*time.Hour)
	if d := f.svc.firstDelay(); d != 22*time.Hour+30*time.Minute {
		t.Errorf("firstDelay(2 h after an attempt) = %v", d)
	}
	f.st.updated = f.clock.now().Add(-48 * time.Hour)
	if d := f.svc.firstDelay(); d != 7*time.Minute+30*time.Second {
		t.Errorf("firstDelay(overdue) = %v", d)
	}
	f.st.updated = f.clock.now().Add(30 * 24 * time.Hour) // the clock went back
	if d := f.svc.firstDelay(); d != 25*time.Hour {
		t.Errorf("firstDelay(clock back) = %v", d)
	}
	f.st.getErr = errors.New("database down")
	if d := f.svc.firstDelay(); d != 7*time.Minute+30*time.Second {
		t.Errorf("firstDelay(store error) = %v", d)
	}
	time.Sleep(20 * time.Millisecond)
	if f.gh.hits.Load() != 0 {
		t.Error("a request was made")
	}
}

// Close cancels a check in progress, which records nothing, and gives up
// waiting when its context ends.
func TestCloseCancelsCheck(t *testing.T) {
	t.Parallel()
	entered := make(chan struct{})
	f := newFixture(t, func(_ http.ResponseWriter, r *http.Request) {
		close(entered)
		<-r.Context().Done()
	}, nil)
	errs := make(chan error, 1)
	go func() {
		_, err := f.svc.CheckNow(context.Background(), superAdmin())
		errs <- err
	}()
	<-entered
	if err := f.svc.Close(t.Context()); err != nil {
		t.Fatalf("Close = %v", err)
	}
	if err := <-errs; err != nil {
		t.Errorf("CheckNow cut by Close = %v", err)
	}
	if _, puts := f.st.stored(); puts != 0 {
		t.Errorf("%d writes after Close", puts)
	}

	// Close gives up when its context ends before the checks stop.
	g := newFixture(t, nil, nil)
	g.svc.wg.Add(1)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := g.svc.Close(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("Close(canceled) = %v", err)
	}
	g.svc.wg.Done()
}

func TestDefaults(t *testing.T) {
	t.Parallel()
	s := New(&memStore{}, Options{})
	t.Cleanup(func() { _ = s.Close(context.Background()) })
	if s.client.url != ReleasesURL || s.client.userAgent == "TransTeira/" || !strings.HasPrefix(s.client.userAgent, "TransTeira/") ||
		s.interval != DefaultInterval || s.jitter != DefaultJitter || s.startDelay != DefaultStartDelay ||
		s.manual != DefaultManualInterval || s.enabled {
		t.Errorf("defaults: %+v", s)
	}
	tr := s.client.http.Transport.(*http.Transport)
	if tr.Proxy == nil || !tr.DisableKeepAlives || tr.TLSClientConfig.InsecureSkipVerify ||
		tr.TLSClientConfig.MinVersion != tls.VersionTLS12 || s.client.http.CheckRedirect == nil {
		t.Errorf("transport: %+v", tr)
	}
	for range 100 {
		if d := cryptoRandom(time.Second); d < 0 || d > time.Second {
			t.Fatalf("cryptoRandom = %v", d)
		}
	}
	if cryptoRandom(0) != 0 || cryptoRandom(-1) != 0 {
		t.Error("cryptoRandom of a non-positive bound")
	}
	if Category("boom").valid() {
		t.Error("unknown category valid")
	}
}
