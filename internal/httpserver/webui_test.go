package httpserver

import (
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/web"
)

// Bodies of the test build.
const (
	publicPage = "<!doctype html><title>public</title>"
	adminPage  = "<!doctype html><title>admin</title>"
	assetJS    = "console.log(1)"
)

// testWebUI is a build of the web interface with, besides the expected
// files, files that must never be served: a disallowed extension, a nested
// directory, hidden files and an HTML file at the root.
func testWebUI() fstest.MapFS {
	return fstest.MapFS{
		"public/index.html":     {Data: []byte(publicPage)},
		"admin/index.html":      {Data: []byte(adminPage)},
		"assets/public-abc.js":  {Data: []byte(assetJS)},
		"assets/public-abc.css": {Data: []byte("body{margin:0}")},
		"assets/img-abc.png":    {Data: []byte("png")},
		"assets/icon-abc.ico":   {Data: []byte("ico")},
		"assets/evil-abc.html":  {Data: []byte("<script>alert(1)</script>")},
		"assets/sub/deep.js":    {Data: []byte("nested")},
		"assets/.hidden.js":     {Data: []byte("hidden")},
		"favicon.svg":           {Data: []byte("<svg/>")},
		"robots.txt":            {Data: []byte("User-agent: *\nDisallow: /\n")},
		"index.html":            {Data: []byte("root html")},
		".gitkeep":              {Data: nil},
		".hidden.txt":           {Data: []byte("hidden")},
	}
}

// uiResponse checks a response of the web interface: status, body (empty
// for HEAD), media type, CSP, cache policy, robots header, security headers
// and the presence of an ETag.
func uiResponse(t *testing.T, rec *httptest.ResponseRecorder, method string, status int, body, contentType, csp, cache string, etag bool) {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("status %d, want %d; body %q", rec.Code, status, rec.Body.String())
	}
	h := rec.Header()
	wantBody := body
	if method == http.MethodHead {
		wantBody = ""
	}
	if rec.Body.String() != wantBody {
		t.Errorf("body %q, want %q", rec.Body.String(), wantBody)
	}
	if got := h.Get("Content-Length"); got != strconv.Itoa(len(body)) {
		t.Errorf("Content-Length %q, want %d", got, len(body))
	}
	for name, want := range map[string]string{
		"Content-Type": contentType, "Content-Security-Policy": csp, "Cache-Control": cache, "X-Robots-Tag": UIRobots,
	} {
		if got := h.Get(name); got != want {
			t.Errorf("%s %q, want %q", name, got, want)
		}
	}
	if (h.Get("ETag") != "") != etag {
		t.Errorf("ETag %q, want present=%v", h.Get("ETag"), etag)
	}
	assertSecurityHeaders(t, rec)
}

func TestWebUITenantHost(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envConfig{})
	const html, cache = htmlContentType, "private, no-cache"
	tests := []struct {
		target          string
		status          int
		body, ctype, cc string
		etag            bool
	}{
		{"/", 200, publicPage, html, cache, true},
		{"/d/tok_abc", 200, publicPage, html, cache, true},
		{"/i/inv_abc", 200, publicPage, html, cache, true},
		{"/legal/privacy", 200, publicPage, html, cache, true},
		{"/invite", 200, publicPage, html, cache, true},
		{"/me", 200, publicPage, html, cache, true},
		{"/help", 200, publicPage, html, cache, true},
		{"/help/", 200, publicPage, html, cache, true},
		{"/help/depositor/start", 200, publicPage, html, cache, true},
		{"/?lang=fr", 200, publicPage, html, cache, true},
		{"/assets/public-abc.js", 200, assetJS, jsContentType, AssetCacheControl, true},
		{"/assets/public-abc.css", 200, "body{margin:0}", "text/css; charset=utf-8", AssetCacheControl, true},
		{"/assets/img-abc.png", 200, "png", "image/png", AssetCacheControl, true},
		{"/assets/icon-abc.ico", 200, "ico", "image/x-icon", AssetCacheControl, true},
		{"/favicon.svg", 200, "<svg/>", "image/svg+xml", cache, true},
		{"/robots.txt", 200, "User-agent: *\nDisallow: /\n", "text/plain; charset=utf-8", cache, true},
		// Any other path is the public application with 404, never the
		// admin one nor an unlisted build file.
		{"/nope", 404, publicPage, html, cache, false},
		{"/d/", 404, publicPage, html, cache, false},
		{"/d/a/b", 404, publicPage, html, cache, false},
		{"/i/", 404, publicPage, html, cache, false},
		{"/legal/a/b", 404, publicPage, html, cache, false},
		{"/invite/x", 404, publicPage, html, cache, false},
		{"/helpx", 404, publicPage, html, cache, false},
		{"/admin", 404, publicPage, html, cache, false},
		{"/admin/", 404, publicPage, html, cache, false},
		{"/admin/index.html", 404, publicPage, html, cache, false},
		{"/public/index.html", 404, publicPage, html, cache, false},
		{"/assets", 404, publicPage, html, cache, false},
		{"/index.html", 404, publicPage, html, cache, false},
		{"/.gitkeep", 404, publicPage, html, cache, false},
		{"/.hidden.txt", 404, publicPage, html, cache, false},
		{"/apix", 404, publicPage, html, cache, false},
		{"/wp-login.php", 404, publicPage, html, cache, false},
		{"/healthz/", 404, publicPage, html, cache, false},
	}
	for _, tt := range tests {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			t.Run(method+" "+tt.target, func(t *testing.T) {
				t.Parallel()
				rec := e.do(t, method, tt.target, hostA, nil)
				uiResponse(t, rec, method, tt.status, tt.body, tt.ctype, PublicUICSP, tt.cc, tt.etag)
			})
		}
	}
	t.Cleanup(func() {
		if s := e.secLog.String(); s != "" {
			t.Errorf("unexpected security events %q", s)
		}
	})
}

func TestWebUIAdminHost(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envConfig{})
	const html, cache = htmlContentType, "no-store"
	tests := []struct {
		target          string
		status          int
		body, ctype, cc string
		etag            bool
	}{
		{"/admin/", 200, adminPage, html, cache, true},
		{"/admin/tenants/ten_a", 200, adminPage, html, cache, true},
		{"/admin/login?next=x", 200, adminPage, html, cache, true},
		// The fingerprinted assets override the no-store of the admin host.
		{"/assets/public-abc.js", 200, assetJS, jsContentType, AssetCacheControl, true},
		{"/favicon.svg", 200, "<svg/>", "image/svg+xml", cache, true},
		{"/nope", 404, adminPage, html, cache, false},
		{"/d/tok_abc", 404, adminPage, html, cache, false},
		{"/invite", 404, adminPage, html, cache, false},
		{"/me", 404, adminPage, html, cache, false},
		{"/public/index.html", 404, adminPage, html, cache, false},
		{"/index.html", 404, adminPage, html, cache, false},
	}
	for _, tt := range tests {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			t.Run(method+" "+tt.target, func(t *testing.T) {
				t.Parallel()
				rec := e.do(t, method, tt.target, hostAdmin, nil)
				uiResponse(t, rec, method, tt.status, tt.body, tt.ctype, AdminUICSP, tt.cc, tt.etag)
			})
		}
	}
}

func TestWebUIAdminRedirect(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envConfig{})
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		for _, target := range []string{"/", "/?x=1", "/admin"} {
			rec := e.do(t, method, target, hostAdmin, nil)
			if rec.Code != http.StatusFound || rec.Header().Get("Location") != AdminUIPath || rec.Body.Len() != 0 {
				t.Errorf("%s %s: %d Location %q body %q", method, target, rec.Code, rec.Header().Get("Location"), rec.Body.String())
			}
			if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("X-Robots-Tag") != UIRobots {
				t.Errorf("%s %s: headers %v", method, target, rec.Header())
			}
			assertSecurityHeaders(t, rec)
		}
	}
	// The redirect is the admin host's only: a tenant host serves its root.
	if rec := e.do(t, http.MethodGet, "/", hostA, nil); rec.Code != http.StatusOK || rec.Body.String() != publicPage {
		t.Errorf("tenant root %d %q", rec.Code, rec.Body.String())
	}
}

// TestWebUIProblems checks the answers of the web interface handlers that
// are Problems: unknown or disallowed build files, paths under /api and
// methods other than GET and HEAD, on both hosts.
func TestWebUIProblems(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envConfig{})
	tests := []struct {
		method, target, host string
		status               int
		code                 problem.Code
		robots               bool
	}{
		{http.MethodGet, "/assets/nope.js", hostA, 404, problem.CodeNotFound, true},
		{http.MethodGet, "/assets/", hostA, 404, problem.CodeNotFound, true},
		{http.MethodGet, "/assets/evil-abc.html", hostA, 404, problem.CodeNotFound, true},
		{http.MethodGet, "/assets/sub/deep.js", hostA, 404, problem.CodeNotFound, true},
		{http.MethodGet, "/assets/sub", hostA, 404, problem.CodeNotFound, true},
		{http.MethodGet, "/assets/.hidden.js", hostA, 404, problem.CodeNotFound, true},
		{http.MethodHead, "/assets/nope.css", hostA, 404, problem.CodeNotFound, true},
		{http.MethodGet, "/assets/nope.js", hostAdmin, 404, problem.CodeNotFound, true},
		{http.MethodGet, "/api", hostA, 404, problem.CodeNotFound, false},
		{http.MethodGet, "/api/", hostA, 404, problem.CodeNotFound, false},
		{http.MethodGet, "/api/nope", hostA, 404, problem.CodeNotFound, false},
		{http.MethodGet, "/api/docs", hostA, 404, problem.CodeNotFound, false},
		{http.MethodPost, "/api/nope", hostA, 404, problem.CodeNotFound, false},
		{http.MethodDelete, "/api/v2/x", hostA, 404, problem.CodeNotFound, false},
		{http.MethodGet, "/api", hostAdmin, 404, problem.CodeNotFound, false},
		{http.MethodGet, "/api/nope", hostAdmin, 404, problem.CodeNotFound, false},
		{http.MethodPut, "/api/v1/nope", hostAdmin, 404, problem.CodeNotFound, false},
		{http.MethodPost, "/", hostA, 405, problem.CodeMethodNotAllowed, true},
		{http.MethodPut, "/d/tok_abc", hostA, 405, problem.CodeMethodNotAllowed, true},
		{http.MethodDelete, "/assets/public-abc.js", hostA, 405, problem.CodeMethodNotAllowed, true},
		{http.MethodPost, "/nope", hostA, 405, problem.CodeMethodNotAllowed, true},
		{http.MethodOptions, "/favicon.svg", hostA, 405, problem.CodeMethodNotAllowed, true},
		{http.MethodPost, "/", hostAdmin, 405, problem.CodeMethodNotAllowed, true},
		{http.MethodPatch, "/admin/", hostAdmin, 405, problem.CodeMethodNotAllowed, true},
		{http.MethodPost, "/nope", hostAdmin, 405, problem.CodeMethodNotAllowed, true},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.host+tt.target, func(t *testing.T) {
			t.Parallel()
			rec := e.do(t, tt.method, tt.target, tt.host, nil)
			// The recorder keeps the body of a HEAD response, which
			// net/http discards.
			if tt.method == http.MethodHead {
				if rec.Code != tt.status {
					t.Fatalf("HEAD %d %q", rec.Code, rec.Body.String())
				}
			} else {
				decodeProblem(t, rec, tt.status, tt.code)
			}
			if allow := rec.Header().Get("Allow"); (tt.status == 405) != (allow == "GET, HEAD") {
				t.Errorf("Allow %q", allow)
			}
			if csp := rec.Header().Get("Content-Security-Policy"); csp == PublicUICSP || csp == AdminUICSP {
				t.Errorf("Problem served with the CSP of an application")
			}
			if (rec.Header().Get("X-Robots-Tag") == UIRobots) != tt.robots {
				t.Errorf("X-Robots-Tag %q", rec.Header().Get("X-Robots-Tag"))
			}
			if tt.host == hostAdmin && rec.Header().Get("Cache-Control") != "no-store" {
				t.Errorf("Cache-Control %q on the admin host", rec.Header().Get("Cache-Control"))
			}
		})
	}
}

func TestWebUIUnknownHost(t *testing.T) {
	t.Parallel()
	for _, target := range []string{"/", "/d/x", "/assets/public-abc.js", "/favicon.svg", "/admin/", "/nope"} {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			t.Run(method+" "+target, func(t *testing.T) {
				t.Parallel()
				e := newEnv(t, envConfig{})
				rec := e.do(t, method, target, hostUnknown, nil)
				decodeProblem(t, rec, http.StatusMisdirectedRequest, problem.CodeUnknownTenant)
				if !strings.Contains(e.secLog.String(), "event=unknown_fqdn") {
					t.Errorf("security log %q", e.secLog.String())
				}
				if rec.Header().Get("X-Robots-Tag") != "" {
					t.Errorf("X-Robots-Tag on an unknown host")
				}
			})
		}
	}
}

func TestWebUIConditionalRequests(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envConfig{})
	for _, c := range []struct{ target, host string }{
		{"/", hostA},
		{"/d/tok", hostA},
		{"/assets/public-abc.js", hostA},
		{"/robots.txt", hostA},
		{"/admin/", hostAdmin},
		{"/assets/public-abc.js", hostAdmin},
	} {
		t.Run(c.host+c.target, func(t *testing.T) {
			t.Parallel()
			first := e.do(t, http.MethodGet, c.target, c.host, nil)
			etag := first.Header().Get("ETag")
			if first.Code != http.StatusOK || !strings.HasPrefix(etag, `"`) || len(etag) != 34 {
				t.Fatalf("first %d ETag %q", first.Code, etag)
			}
			for _, inm := range []string{etag, "W/" + etag, "*", `"other", ` + etag, `"a",W/` + etag} {
				for _, method := range []string{http.MethodGet, http.MethodHead} {
					rec := e.do(t, method, c.target, c.host, nil, "If-None-Match", inm)
					if rec.Code != http.StatusNotModified || rec.Body.Len() != 0 || rec.Header().Get("ETag") != etag ||
						rec.Header().Get("Content-Type") != "" || rec.Header().Get("Cache-Control") != first.Header().Get("Cache-Control") {
						t.Errorf("%s If-None-Match %s: %d %v", method, inm, rec.Code, rec.Header())
					}
				}
			}
			for _, inm := range []string{`"other"`, "W/\"other\"", ""} {
				rec := e.do(t, http.MethodGet, c.target, c.host, nil, "If-None-Match", inm)
				if rec.Code != http.StatusOK || rec.Body.String() != first.Body.String() {
					t.Errorf("If-None-Match %q: %d", inm, rec.Code)
				}
			}
		})
	}
	// A 404 page carries no ETag and ignores If-None-Match.
	if rec := e.do(t, http.MethodGet, "/nope", hostA, nil, "If-None-Match", "*"); rec.Code != http.StatusNotFound || rec.Body.String() != publicPage {
		t.Errorf("404 with If-None-Match: %d", rec.Code)
	}
}

// TestWebUICrossApp checks that each host only ever serves its own
// application, whatever the path.
func TestWebUICrossApp(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envConfig{})
	for _, target := range []string{"/admin/", "/admin/tenants", "/admin", "/admin/index.html", "/nope"} {
		if rec := e.do(t, http.MethodGet, target, hostA, nil); strings.Contains(rec.Body.String(), "admin</title>") ||
			rec.Header().Get("Content-Security-Policy") == AdminUICSP {
			t.Errorf("tenant host %s served the admin application", target)
		}
	}
	for _, target := range []string{"/d/tok", "/i/inv", "/legal/privacy", "/invite", "/help", "/help/x", "/nope"} {
		if rec := e.do(t, http.MethodGet, target, hostAdmin, nil); strings.Contains(rec.Body.String(), "public</title>") ||
			rec.Header().Get("Content-Security-Policy") == PublicUICSP {
			t.Errorf("admin host %s served the public application", target)
		}
	}
}

func TestWebUIUncleanPaths(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envConfig{})
	// Outside /api, the mux's clean-path redirect is kept.
	for _, c := range []struct{ target, host, location string }{
		{"/d/../invite", hostA, "/invite"},
		{"//assets/public-abc.js", hostA, "/assets/public-abc.js"},
		{"/help//x", hostA, "/help/x"},
		{"/admin/../admin/", hostAdmin, "/admin/"},
		{"//", hostAdmin, "/"},
	} {
		rec := e.do(t, http.MethodGet, c.target, c.host, nil)
		if rec.Code/100 != 3 || rec.Header().Get("Location") != c.location {
			t.Errorf("%s %s: %d Location %q", c.host, c.target, rec.Code, rec.Header().Get("Location"))
		}
	}
	// Under /api, a Problem.
	for _, c := range []struct{ target, host string }{
		{"/api//nope", hostA},
		{"/x/../api/nope", hostA},
		{"/api/./", hostA},
		{"/api//nope", hostAdmin},
		{"/assets/../api/v1", hostAdmin},
	} {
		decodeProblem(t, e.do(t, http.MethodGet, c.target, c.host, nil), http.StatusNotFound, problem.CodeNotFound)
	}
}

func TestWebUIMissingIndex(t *testing.T) {
	t.Parallel()
	build := testWebUI()
	delete(build, publicIndexName)
	delete(build, adminIndexName)
	e := newEnv(t, envConfig{webUI: build})
	fallback := string(uiFallbackPage.body)
	for _, c := range []struct{ target, host, csp string }{
		{"/", hostA, PublicUICSP},
		{"/d/tok", hostA, PublicUICSP},
		{"/nope", hostA, PublicUICSP},
		{"/admin/", hostAdmin, AdminUICSP},
		{"/nope", hostAdmin, AdminUICSP},
	} {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			rec := e.do(t, method, c.target, c.host, nil, "If-None-Match", "*")
			uiResponse(t, rec, method, http.StatusServiceUnavailable, fallback, htmlContentType, c.csp, "no-store", false)
		}
	}
	// The other build files are still served, and the redirect still works.
	if rec := e.do(t, http.MethodGet, "/assets/public-abc.js", hostA, nil); rec.Code != http.StatusOK {
		t.Errorf("asset %d", rec.Code)
	}
	if rec := e.do(t, http.MethodGet, "/", hostAdmin, nil); rec.Code != http.StatusFound {
		t.Errorf("admin root %d", rec.Code)
	}
	logs := e.appLog.String()
	for _, want := range []string{`"level":"WARN"`, "web interface not built", publicIndexName, adminIndexName} {
		if !strings.Contains(logs, want) {
			t.Errorf("logs lack %q: %s", want, logs)
		}
	}
	// The fallback page complies with the CSP of the applications.
	for _, banned := range []string{"<script", "style", "http://", "https://"} {
		if strings.Contains(fallback, banned) {
			t.Errorf("fallback page contains %q", banned)
		}
	}
}

func TestWebUIEmptyBuildServesFallback(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envConfig{webUI: fstest.MapFS{}})
	if rec := e.do(t, http.MethodGet, "/", hostA, nil); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status %d", rec.Code)
	}
	if rec := e.do(t, http.MethodGet, "/favicon.svg", hostA, nil); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("favicon %d", rec.Code)
	}
}

func TestWebUILoadedWithoutWarning(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envConfig{})
	if logs := e.appLog.String(); strings.Contains(logs, "web interface") {
		t.Errorf("unexpected warning: %s", logs)
	}
}

// TestWebUIEmbeddedBuild checks that a nil Deps.WebUI serves the build
// embedded in package web: the public application when it is built, the
// fallback page otherwise.
func TestWebUIEmbeddedBuild(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envConfig{embeddedWebUI: true})
	want, built := http.StatusOK, true
	if _, err := fs.Stat(web.Dist(), publicIndexName); err != nil {
		want, built = http.StatusServiceUnavailable, false
	}
	rec := e.do(t, http.MethodGet, "/", hostA, nil)
	if rec.Code != want || rec.Header().Get("Content-Security-Policy") != PublicUICSP {
		t.Fatalf("status %d (built %v), CSP %q", rec.Code, built, rec.Header().Get("Content-Security-Policy"))
	}
}

// failFS fails to open the names in fail.
type failFS struct {
	fs.FS
	fail map[string]bool
}

var errFailFS = errors.New("injected failure")

func (f failFS) Open(name string) (fs.File, error) {
	if f.fail[name] {
		return nil, &fs.PathError{Op: "open", Path: name, Err: errFailFS}
	}
	return f.FS.Open(name)
}

func TestNewWebUILoadErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		fail []string
		// assets and root are the numbers of files loaded.
		assets, root int
	}{
		{"unreadable asset", []string{"assets/public-abc.js"}, 3, 2},
		{"unreadable assets directory", []string{"assets"}, 0, 2},
		{"unreadable root file", []string{"robots.txt"}, 4, 1},
		{"unreadable root directory", []string{"."}, 4, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fail := map[string]bool{}
			for _, n := range tt.fail {
				fail[n] = true
			}
			ui, err := newWebUI(failFS{FS: testWebUI(), fail: fail})
			if !errors.Is(err, errFailFS) {
				t.Fatalf("error %v", err)
			}
			if ui.public.index == nil || ui.admin.index == nil || len(ui.assets) != tt.assets || len(ui.root) != tt.root {
				t.Errorf("loaded %d assets, %d root files", len(ui.assets), len(ui.root))
			}
		})
	}
	ui, err := newWebUI(testWebUI())
	if err != nil {
		t.Fatal(err)
	}
	if len(ui.assets) != 4 || len(ui.root) != 2 {
		t.Errorf("loaded %v assets, %v root files", len(ui.assets), len(ui.root))
	}
	for name := range ui.root {
		if name != "favicon.svg" && name != "robots.txt" {
			t.Errorf("unexpected root file %q", name)
		}
	}
}

func TestEtagMatches(t *testing.T) {
	t.Parallel()
	const etag = `"abc"`
	for header, want := range map[string]bool{
		"": false, etag: true, "W/" + etag: true, "*": true, ` "x" , "abc" `: true, `"x"`: false, `abc`: false, `W/"x", *`: true, `"abcd"`: false,
	} {
		if got := etagMatches(header, etag); got != want {
			t.Errorf("etagMatches(%q) = %v", header, got)
		}
	}
}

func TestIsPublicRoute(t *testing.T) {
	t.Parallel()
	for p, want := range map[string]bool{
		"/": true, "/invite": true, "/me": true, "/help": true, "/help/": true, "/help/a/b": true, "/d/x": true, "/i/x": true, "/legal/terms": true,
		"": false, "/helpx": false, "/invite/": false, "/d/": false, "/d/x/": false, "/d": false, "/legal/a/b": false,
		"/admin/": false, "/x": false, "/dx": false, "/me/": false, "/me/x": false,
	} {
		if got := isPublicRoute(p); got != want {
			t.Errorf("isPublicRoute(%q) = %v", p, got)
		}
	}
}

// TestTokenAPIRobots checks that the public API responses of the paths
// named after a link or invitation token carry the X-Robots-Tag, whatever
// the status, and that the other API paths do not.
func TestTokenAPIRobots(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envConfig{})
	for target, want := range map[string]bool{
		"/api/v1/downloads/dl_Xk4Lm9Qp2Zr7Vb1Nt6Yc3Hd8Jf":         true,
		"/api/v1/downloads/dl_Xk4Lm9Qp2Zr7Vb1Nt6Yc3Hd8Jf/archive": true,
		"/api/v1/invitations/inv_Xk4Lm9Qp2Zr7Vb1Nt6Yc3Hd8Jf":      true,
		"/api/v1/invitations": false,
		"/api/v1/downloads":   false,
		"/api/v1/version":     false,
		"/api/v1/tenant":      false,
	} {
		t.Run(target, func(t *testing.T) {
			t.Parallel()
			rec := e.do(t, http.MethodGet, target, hostA, nil)
			if got := rec.Header().Get("X-Robots-Tag"); (got == UIRobots) != want || (!want && got != "") {
				t.Errorf("GET %s: %d X-Robots-Tag %q, want robots %v", target, rec.Code, got, want)
			}
		})
	}
}
