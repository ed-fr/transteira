package httpserver

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/httpserver/middleware"
	"github.com/ed-fr/transteira/web/apidocs"
)

// wantDocsCSP is the exact Content-Security-Policy of the documentation.
const wantDocsCSP = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; " +
	"img-src 'self' data:; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"

// adminCookieHeader returns the Cookie header of the admin session token.
func adminCookieHeader(token string) []string {
	return []string{"Cookie", middleware.AdminCookie + "=" + token}
}

// assertDocsFile checks a successful documentation response.
func assertDocsFile(t *testing.T, rec *httptest.ResponseRecorder, body []byte, contentType, cacheControl string) {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d; body %s", rec.Code, rec.Body.String())
	}
	h := rec.Header()
	if got := h.Get("Content-Security-Policy"); got != wantDocsCSP {
		t.Errorf("CSP %q", got)
	}
	if got := h.Get("Content-Type"); got != contentType {
		t.Errorf("Content-Type %q, want %q", got, contentType)
	}
	if got := h.Get("Cache-Control"); got != cacheControl {
		t.Errorf("Cache-Control %q, want %q", got, cacheControl)
	}
	if h.Get("ETag") == "" {
		t.Error("missing ETag")
	}
	if h.Get("X-Content-Type-Options") != "nosniff" || h.Get("X-Frame-Options") != "DENY" ||
		h.Get("Referrer-Policy") != "no-referrer" {
		t.Errorf("security headers %v", h)
	}
	assertSecurityHeaders(t, rec)
	if body != nil && !bytes.Equal(rec.Body.Bytes(), body) {
		t.Errorf("body of %d bytes, want %d", rec.Body.Len(), len(body))
	}
}

func TestDocsAdminHost(t *testing.T) {
	t.Parallel()
	for _, public := range []bool{false, true} {
		e := newEnv(t, envConfig{adminSessions: fakeAdminSessions{}, docsPublic: public})
		good := adminCookieHeader(adminGoodToken)

		// Without a completed login: 401 under the default CSP.
		for _, hdr := range [][]string{nil, adminCookieHeader("as_unknown"), adminCookieHeader(adminPendingToken)} {
			for _, target := range []string{DocsPath, DocsPath + "/scalar.js", DocsPath + "/nope"} {
				rec := e.do(t, http.MethodGet, target, hostAdmin, nil, hdr...)
				decodeProblem(t, rec, http.StatusUnauthorized, problem.CodeUnauthenticated)
				if got := rec.Header().Get("Content-Security-Policy"); got != middleware.DefaultCSP {
					t.Errorf("%s: CSP %q", target, got)
				}
				if rec.Header().Get("Cache-Control") != "no-store" {
					t.Errorf("%s: Cache-Control %q", target, rec.Header().Get("Cache-Control"))
				}
			}
		}
		rec := e.do(t, http.MethodGet, DocsPath, hostAdmin, nil, adminCookieHeader(adminBoomToken)...)
		decodeProblem(t, rec, http.StatusInternalServerError, problem.CodeInternalError)

		// With the authenticated session.
		rec = e.do(t, http.MethodGet, DocsPath, hostAdmin, nil, good...)
		assertDocsFile(t, rec, apidocs.IndexHTML, "text/html; charset=utf-8", "no-store")
		rec = e.do(t, http.MethodGet, DocsPath+"/init.js", hostAdmin, nil, good...)
		assertDocsFile(t, rec, apidocs.InitJS, "text/javascript; charset=utf-8", "no-store")
		rec = e.do(t, http.MethodGet, DocsPath+"/scalar.js", hostAdmin, nil, good...)
		assertDocsFile(t, rec, apidocs.ScalarJS, "text/javascript; charset=utf-8", "no-store")

		rec = e.do(t, http.MethodHead, DocsPath+"/scalar.js", hostAdmin, nil, good...)
		assertDocsFile(t, rec, nil, "text/javascript; charset=utf-8", "no-store")
		if rec.Body.Len() != 0 {
			t.Errorf("HEAD body of %d bytes", rec.Body.Len())
		}

		for _, target := range []string{
			DocsPath + "/nope.js", DocsPath + "/", DocsPath + "/a/b", DocsPath + "/index.html",
			DocsPath + "/../openapi.yaml", "/api//docs", DocsPath + "/./init.js",
		} {
			rec = e.do(t, http.MethodGet, target, hostAdmin, nil, good...)
			decodeProblem(t, rec, http.StatusNotFound, problem.CodeNotFound)
		}
		rec = e.do(t, http.MethodPost, DocsPath, hostAdmin, strings.NewReader("{}"), good...)
		decodeProblem(t, rec, http.StatusMethodNotAllowed, problem.CodeMethodNotAllowed)
	}
}

func TestDocsNotPublic(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envConfig{})
	for _, target := range []string{DocsPath, DocsPath + "/scalar.js", DocsPath + "/init.js"} {
		rec := e.do(t, http.MethodGet, target, hostA, nil)
		decodeProblem(t, rec, http.StatusNotFound, problem.CodeNotFound)
		rec = e.do(t, http.MethodGet, target, hostUnknown, nil)
		decodeProblem(t, rec, http.StatusMisdirectedRequest, problem.CodeUnknownTenant)
	}
}

func TestDocsPublic(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envConfig{docsPublic: true})
	for _, host := range []string{hostA} {
		rec := e.do(t, http.MethodGet, DocsPath, host, nil)
		assertDocsFile(t, rec, apidocs.IndexHTML, "text/html; charset=utf-8", "no-cache")
		rec = e.do(t, http.MethodGet, DocsPath+"/init.js", host, nil)
		assertDocsFile(t, rec, apidocs.InitJS, "text/javascript; charset=utf-8", "no-cache")
		rec = e.do(t, http.MethodHead, DocsPath+"/scalar.js", host, nil)
		assertDocsFile(t, rec, nil, "text/javascript; charset=utf-8", "no-cache")
		if rec.Body.Len() != 0 {
			t.Errorf("HEAD body of %d bytes", rec.Body.Len())
		}

		// Revalidation.
		etag := rec.Header().Get("ETag")
		rec = e.do(t, http.MethodGet, DocsPath+"/scalar.js", host, nil, "If-None-Match", etag)
		if rec.Code != http.StatusNotModified {
			t.Errorf("revalidation status %d", rec.Code)
		}

		rec = e.do(t, http.MethodPost, DocsPath, host, strings.NewReader("{}"))
		decodeProblem(t, rec, http.StatusMethodNotAllowed, problem.CodeMethodNotAllowed)
	}
	if e.secLog.String() != "" {
		t.Errorf("unexpected security events %q", e.secLog.String())
	}

	// An unknown host never gets the page: 421 and an unknown_fqdn event.
	for _, target := range []string{DocsPath, DocsPath + "/init.js", DocsPath + "/scalar.js"} {
		rec := e.do(t, http.MethodGet, target, hostUnknown, nil)
		decodeProblem(t, rec, http.StatusMisdirectedRequest, problem.CodeUnknownTenant)
	}
	if !strings.Contains(e.secLog.String(), "unknown_fqdn") {
		t.Errorf("no unknown_fqdn event in %q", e.secLog.String())
	}

	// Anything else under the prefix is routed as usual.
	for _, target := range []string{DocsPath + "/nope.js", DocsPath + "/", DocsPath + "/init.js/", DocsPath + "/../openapi.yaml", "/api//docs"} {
		rec := e.do(t, http.MethodGet, target, hostA, nil)
		decodeProblem(t, rec, http.StatusNotFound, problem.CodeNotFound)
		rec = e.do(t, http.MethodGet, target, hostUnknown, nil)
		decodeProblem(t, rec, http.StatusMisdirectedRequest, problem.CodeUnknownTenant)
	}
}

func TestDocsHandlerUnknownAsset(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodGet, DocsPath+"/nope", nil)
	req.SetPathValue("asset", "nope")
	rec := httptest.NewRecorder()
	docsHandler("no-cache").ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound || rec.Header().Get("Content-Security-Policy") == wantDocsCSP {
		t.Fatalf("status %d, CSP %q", rec.Code, rec.Header().Get("Content-Security-Policy"))
	}
}

func TestIsDocsPath(t *testing.T) {
	t.Parallel()
	cases := map[string]bool{
		DocsPath: true, DocsPath + "/init.js": true, DocsPath + "/scalar.js": true,
		DocsPath + "/": false, DocsPath + "/index.html": false, DocsPath + "/nope": false,
		DocsPath + "/init.js/": false, "/api/docsx": false, "/api//docs": false, "/x" + DocsPath + "/init.js": false, "": false,
	}
	for p, want := range cases {
		if got := isDocsPath(p); got != want {
			t.Errorf("isDocsPath(%q) = %v, want %v", p, got, want)
		}
	}
}

// TestDocsPageHasNoInlineCode checks that the page works under DocsCSP:
// no inline script, no event handler attribute, and only same-origin
// scripts that are actually served.
func TestDocsPageHasNoInlineCode(t *testing.T) {
	t.Parallel()
	page := string(apidocs.IndexHTML)
	if regexp.MustCompile(`(?i)<script(\s[^>]*)?>\s*[^<\s]`).MatchString(page) {
		t.Error("inline script in index.html")
	}
	if regexp.MustCompile(`(?i)\son[a-z]+\s*=`).MatchString(page) {
		t.Error("inline event handler in index.html")
	}
	srcs := regexp.MustCompile(`<script src="([^"]+)"></script>`).FindAllStringSubmatch(page, -1)
	if len(srcs) != 2 {
		t.Fatalf("scripts %v", srcs)
	}
	for _, m := range srcs {
		if !isDocsPath(m[1]) || m[1] == DocsPath {
			t.Errorf("script %q is not a served documentation file", m[1])
		}
	}
	if strings.Contains(page, "http://") || strings.Contains(page, "https://") {
		t.Error("absolute URL in index.html")
	}
	init := string(apidocs.InitJS)
	for _, want := range []string{"withDefaultFonts: false", "telemetry: false", "proxyUrl: ''", "url: '/api/openapi.yaml'"} {
		if !strings.Contains(init, want) {
			t.Errorf("init.js lacks %q", want)
		}
	}
}
