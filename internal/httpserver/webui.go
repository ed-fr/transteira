package httpserver

import (
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"path"
	"strconv"
	"strings"

	"github.com/ed-fr/transteira/internal/api/problem"
)

// Web interface (CLAUDE.md sections 4 and 16.2): the public application on
// the tenant hosts and the admin application on the admin hosts, built by
// `make web-build` into web/dist and embedded in the binary (package web).
const (
	// PublicUICSP is the Content-Security-Policy of the public application,
	// replacing middleware.DefaultCSP on its pages and files: same-origin
	// scripts, styles, images, requests and manifest only, no inline code.
	PublicUICSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; " +
		"manifest-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
	// AdminUICSP is the Content-Security-Policy of the admin application:
	// PublicUICSP, plus data: images for the QR code of the TOTP
	// enrollment.
	AdminUICSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; " +
		"manifest-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
	// UIRobots is the X-Robots-Tag of every response of the web interface:
	// its pages carry tokens in their paths and must never be indexed.
	UIRobots = "noindex, nofollow"
	// AssetsPrefix is the path prefix of the fingerprinted build files
	// (web/dist/assets), served on both kinds of host.
	AssetsPrefix = "/assets/"
	// AdminUIPath is the root of the admin application on the admin hosts.
	AdminUIPath = "/admin/"
	// AssetCacheControl is the Cache-Control of the fingerprinted build
	// files: their name changes with their content.
	AssetCacheControl = "public, max-age=31536000, immutable"
	// PublicUICacheControl is the Cache-Control of the public entry page
	// and of the root files on the tenant hosts: revalidated on every use
	// (ETag) and never stored by a shared cache, whose entries would be
	// keyed by URLs carrying link and invitation tokens (/d/{token},
	// /i/{token}).
	PublicUICacheControl = "private, no-cache"
)

// Paths of the entry pages inside the build.
const (
	publicIndexName = "public/index.html"
	adminIndexName  = "admin/index.html"
	assetsDir       = "assets"
)

// htmlContentType is the media type of the entry pages.
const htmlContentType = "text/html; charset=utf-8"

// uiContentTypes is the allowlist of the build files served, by extension.
// A file with any other extension is not loaded, hence never served.
var uiContentTypes = map[string]string{
	".js":  jsContentType,
	".css": "text/css; charset=utf-8",
	".svg": "image/svg+xml",
	".png": "image/png",
	".ico": "image/x-icon",
	".txt": "text/plain; charset=utf-8",
}

// uiFallbackPage is served with 503 in place of an entry page missing from
// the build (a binary built without `make web-build`). It holds no inline
// script nor style, to comply with the CSP of the applications.
var uiFallbackPage = newDocsFile([]byte(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>TransTeira</title>
</head>
<body>
<main>
<h1>Service temporarily unavailable</h1>
<p>The web interface of this server is not available. Please try again later.</p>
<p lang="fr">L'interface web de ce serveur n'est pas disponible. Veuillez réessayer plus tard.</p>
</main>
</body>
</html>
`), htmlContentType)

// webApp is one of the two applications of the web interface.
type webApp struct {
	// index is the entry page, nil when it is missing from the build.
	index *docsFile
	// csp is the Content-Security-Policy of the application.
	csp string
	// cacheControl is the Cache-Control of the entry page and of the root
	// files on the hosts of the application.
	cacheControl string
}

// webUI is the web interface, loaded in memory from the build at start-up.
type webUI struct {
	public, admin webApp
	// assets are the files of the assets directory, by name.
	assets map[string]docsFile
	// root are the files at the root of the build (favicon.svg,
	// robots.txt), by name.
	root map[string]docsFile
}

// newWebUI loads the build fsys in memory: both entry pages, the files of
// the assets directory and the files at the root, keeping only the allowed
// extensions (uiContentTypes) and skipping hidden files and directories.
// The returned error, to be logged, reports the missing entry pages and
// the unreadable files; the interface is usable anyway, a missing entry page
// being replaced by the fallback page.
func newWebUI(fsys fs.FS) (*webUI, error) {
	ui := &webUI{
		public: webApp{csp: PublicUICSP, cacheControl: PublicUICacheControl},
		admin:  webApp{csp: AdminUICSP, cacheControl: "no-store"},
		assets: map[string]docsFile{},
		root:   map[string]docsFile{},
	}
	var errs []error
	for _, a := range []struct {
		app  *webApp
		name string
	}{{&ui.public, publicIndexName}, {&ui.admin, adminIndexName}} {
		b, err := fs.ReadFile(fsys, a.name)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		f := newDocsFile(b, htmlContentType)
		a.app.index = &f
	}
	errs = append(errs, loadUIDir(fsys, assetsDir, ui.assets), loadUIDir(fsys, ".", ui.root))
	return ui, errors.Join(errs...)
}

// loadUIDir loads the allowed regular files of dir into files. A missing
// directory is not an error.
func loadUIDir(fsys fs.FS, dir string, files map[string]docsFile) error {
	entries, err := fs.ReadDir(fsys, dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var errs []error
	for _, e := range entries {
		name := e.Name()
		ct, ok := uiContentTypes[path.Ext(name)]
		if !ok || !e.Type().IsRegular() || strings.HasPrefix(name, ".") {
			continue
		}
		b, err := fs.ReadFile(fsys, path.Join(dir, name))
		if err != nil {
			errs = append(errs, err)
			continue
		}
		files[name] = newDocsFile(b, ct)
	}
	return errors.Join(errs...)
}

// tenantHandler serves the public application on a known tenant host, for
// the paths no other route of the tenant router matches, whatever the
// method: a path under /api is a 404 Problem, any method but GET and HEAD a
// 405 Problem, then the build files, and the public entry page for any
// other path (200 for a route of the application, 404 otherwise). The admin
// application is never served there.
func (ui *webUI) tenantHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !ui.precheck(w, r) || ui.serveBuildFile(w, r, ui.public) {
			return
		}
		status := http.StatusOK
		if !isPublicRoute(r.URL.Path) {
			status = http.StatusNotFound
		}
		ui.serveApp(w, r, ui.public, status)
	})
}

// adminHandler serves the admin application on an admin host, for the
// paths no other route of the admin router matches: like tenantHandler,
// except that / and /admin redirect to AdminUIPath and the entry page is the admin
// one (200 under AdminUIPath, 404 elsewhere).
func (ui *webUI) adminHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !ui.precheck(w, r) {
			return
		}
		if r.URL.Path == "/" || r.URL.Path == strings.TrimSuffix(AdminUIPath, "/") {
			w.Header().Set("Location", AdminUIPath)
			w.WriteHeader(http.StatusFound)
			return
		}
		if ui.serveBuildFile(w, r, ui.admin) {
			return
		}
		status := http.StatusOK
		if !strings.HasPrefix(r.URL.Path, AdminUIPath) {
			status = http.StatusNotFound
		}
		ui.serveApp(w, r, ui.admin, status)
	})
}

// precheck answers a 404 Problem for a path under /api and a 405 Problem,
// with Allow: GET, HEAD, for any other method than GET and HEAD. It
// reports whether the request may go on. Every response of the web
// interface gets the X-Robots-Tag.
func (ui *webUI) precheck(w http.ResponseWriter, r *http.Request) bool {
	p := r.URL.Path
	if p == apiPrefix || strings.HasPrefix(p, apiPrefix+"/") {
		notFound(w, r)
		return false
	}
	w.Header().Set("X-Robots-Tag", UIRobots)
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeProblem(w, r, problem.New(problem.CodeMethodNotAllowed))
		return false
	}
	return true
}

// serveBuildFile serves a file of the assets directory (cached for a year;
// an unknown name is a 404 Problem) or a root file of the build (with the
// cache policy of app). It reports whether the path named such a file.
func (ui *webUI) serveBuildFile(w http.ResponseWriter, r *http.Request, app webApp) bool {
	if name, ok := strings.CutPrefix(r.URL.Path, AssetsPrefix); ok {
		f, known := ui.assets[name]
		if !known {
			notFound(w, r)
			return true
		}
		serveUIFile(w, r, f, app.csp, AssetCacheControl, http.StatusOK)
		return true
	}
	f, ok := ui.root[strings.TrimPrefix(r.URL.Path, "/")]
	if ok {
		serveUIFile(w, r, f, app.csp, app.cacheControl, http.StatusOK)
	}
	return ok
}

// serveApp serves the entry page of app with status, or the fallback page
// with 503 when the page is missing from the build.
func (ui *webUI) serveApp(w http.ResponseWriter, r *http.Request, app webApp, status int) {
	if app.index == nil {
		serveUIFile(w, r, uiFallbackPage, app.csp, "no-store", http.StatusServiceUnavailable)
		return
	}
	serveUIFile(w, r, *app.index, app.csp, app.cacheControl, status)
}

// serveUIFile writes f with status, csp and cacheControl. A 200 response
// carries the ETag of f and becomes 304 Not Modified when If-None-Match
// matches it; HEAD gets the headers without the body.
func serveUIFile(w http.ResponseWriter, r *http.Request, f docsFile, csp, cacheControl string, status int) {
	h := w.Header()
	h.Set("Content-Security-Policy", csp)
	h.Set("Cache-Control", cacheControl)
	if status == http.StatusOK {
		h.Set("ETag", f.etag)
		if etagMatches(r.Header.Get("If-None-Match"), f.etag) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}
	h.Set("Content-Type", f.contentType)
	h.Set("Content-Length", strconv.Itoa(len(f.body)))
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		_, _ = w.Write(f.body)
	}
}

// etagMatches reports whether the If-None-Match header value matches etag,
// with the weak comparison of RFC 9110 section 13.1.2.
func etagMatches(header, etag string) bool {
	for part := range strings.SplitSeq(header, ",") {
		t := strings.TrimSpace(part)
		if t == "*" || strings.TrimPrefix(t, "W/") == etag {
			return true
		}
	}
	return false
}

// isPublicRoute reports whether p is a route of the public application: /,
// /d/{token}, /i/{token}, /legal/{document}, /invite, /me ("my transfers",
// since 1.1; its access token travels in the URL fragment, never in the
// path), /help and anything under /help/.
func isPublicRoute(p string) bool {
	if p == "/" || p == "/invite" || p == "/me" || p == "/help" || strings.HasPrefix(p, "/help/") {
		return true
	}
	for _, prefix := range []string{"/d/", "/i/", "/legal/"} {
		if rest, ok := strings.CutPrefix(p, prefix); ok {
			return rest != "" && !strings.Contains(rest, "/")
		}
	}
	return false
}

// logWebUILoad logs at warning level the error of newWebUI, if any.
func logWebUILoad(logger *slog.Logger, err error) {
	if err != nil {
		logger.Warn("web interface not built or incomplete: missing pages answer 503 (build the binary with make build)",
			slog.String("error", err.Error()))
	}
}

// robotsAPIPrefixes are the public API paths named after a secret link
// token (download links, invitations): their responses get the
// X-Robots-Tag of the web interface, so that a crawler that came across
// such a link never indexes what it answers.
var robotsAPIPrefixes = []string{APIBaseURL + "/downloads/", APIBaseURL + "/invitations/"}

// tokenRobots sets the X-Robots-Tag UIRobots on the responses of the API
// paths under robotsAPIPrefixes, whatever the method and the status, then
// calls next.
func tokenRobots(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, prefix := range robotsAPIPrefixes {
			if strings.HasPrefix(r.URL.Path, prefix) {
				w.Header().Set("X-Robots-Tag", UIRobots)
				break
			}
		}
		next.ServeHTTP(w, r)
	})
}
