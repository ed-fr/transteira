package httpserver

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/httpserver/middleware"
	"github.com/ed-fr/transteira/web/apidocs"
)

// Interactive API documentation (CLAUDE.md section 4.1).
const (
	// DocsPath is the page of the interactive API documentation; its
	// scripts are served under DocsPath + "/".
	DocsPath = "/api/docs"
	// DocsCSP is the Content-Security-Policy of the documentation page and
	// its scripts, replacing middleware.DefaultCSP: same-origin scripts,
	// fonts, images (and data: URIs) and requests, and the inline styles
	// injected by the vendored Scalar bundle. Nothing else of the
	// application relaxes the default policy.
	DocsCSP = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; " +
		"img-src 'self' data:; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
	// DocsDeadline bounds reading the request and writing the response of a
	// documentation file (the Scalar bundle weighs about 4.5 MB).
	DocsDeadline = 2 * time.Minute
)

// docsFile is one file of the documentation, served with an ETag.
type docsFile struct {
	body        []byte
	contentType string
	etag        string
}

// newDocsFile computes the ETag of body.
func newDocsFile(body []byte, contentType string) docsFile {
	sum := sha256.Sum256(body)
	return docsFile{body: body, contentType: contentType, etag: `"` + hex.EncodeToString(sum[:16]) + `"`}
}

// jsContentType is the media type of the documentation scripts
// (text/javascript, RFC 9239), which X-Content-Type-Options: nosniff
// requires for a script to run.
const jsContentType = "text/javascript; charset=utf-8"

// docsIndex is the page served at DocsPath.
var docsIndex = newDocsFile(apidocs.IndexHTML, "text/html; charset=utf-8")

// docsAssets are the files served under DocsPath + "/", by name. Any other
// name is a 404.
var docsAssets = map[string]docsFile{
	"init.js":   newDocsFile(apidocs.InitJS, jsContentType),
	"scalar.js": newDocsFile(apidocs.ScalarJS, jsContentType),
}

// isDocsPath reports whether p is exactly the documentation page or one of
// its files (no cleaning: an unclean path is routed as any other).
func isDocsPath(p string) bool {
	if p == DocsPath {
		return true
	}
	name, ok := strings.CutPrefix(p, DocsPath+"/")
	_, known := docsAssets[name]
	return ok && known
}

// docsHandler serves the documentation page (no {asset} path value) and its
// files with DocsCSP, their ETag and cacheControl. An unknown file is a 404
// Problem under the default CSP.
func docsHandler(cacheControl string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f := docsIndex
		if name := r.PathValue("asset"); name != "" {
			var ok bool
			if f, ok = docsAssets[name]; !ok {
				notFound(w, r)
				return
			}
		}
		h := w.Header()
		h.Set("Content-Security-Policy", DocsCSP)
		h.Set("Content-Type", f.contentType)
		h.Set("ETag", f.etag)
		h.Set("Cache-Control", cacheControl)
		http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(f.body))
	})
}

// newDocsMux routes GET (and HEAD) DocsPath and DocsPath/{asset} to h; any
// other method is a 405 Problem.
func newDocsMux(h http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(http.MethodGet+" "+DocsPath, h)
	mux.Handle(http.MethodGet+" "+DocsPath+"/{asset}", h)
	return withProblemFallback(mux)
}

// docsPathsOnly passes the exact documentation paths (isDocsPath) to h and
// answers a 404 Problem for any other path under its prefix.
func docsPathsOnly(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isDocsPath(r.URL.Path) {
			notFound(w, r)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// publicDocsHandler serves the documentation without authentication on the
// known tenant hosts, when TT_API_DOCS_PUBLIC is set: the files are
// identical for everyone and are revalidated on every use.
func publicDocsHandler(logger *slog.Logger) http.Handler {
	return newDocsMux(middleware.Chain(docsHandler("no-cache"), fixedDeadline(DocsDeadline, logger)))
}

// adminDocsHandler serves the documentation on the admin host to an
// authenticated admin session only (401 unauthenticated otherwise, as the
// admin operations), never cached.
func adminDocsHandler(sessions middleware.SessionResolver, logger *slog.Logger) http.Handler {
	h := middleware.Chain(docsHandler("no-store"),
		fixedDeadline(DocsDeadline, logger),
		middleware.AdminSession(sessions, func(*http.Request) bool { return true }, logger),
		requireAuthenticatedAdmin,
	)
	return newDocsMux(h)
}

// requireAuthenticatedAdmin answers 401 unauthenticated unless the admin
// session stored by middleware.AdminSession has completed the login (an
// intermediate step, such as an awaited second factor, is refused).
func requireAuthenticatedAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, _ := middleware.AdminSessionFrom[adminauth.Principal](r.Context())
		if adminauth.RequireAuthenticated(p) != nil {
			writeProblem(w, r, problem.New(problem.CodeUnauthenticated))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// fixedDeadline sets the read and write deadlines of the connection to d
// from now, like deadlineMiddleware for the routes outside the API router.
func fixedDeadline(d time.Duration, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			deadline := time.Now().Add(d)
			rc := http.NewResponseController(w)
			logDeadlineError(r, logger, rc.SetReadDeadline(deadline))
			logDeadlineError(r, logger, rc.SetWriteDeadline(deadline))
			next.ServeHTTP(w, r)
		})
	}
}
