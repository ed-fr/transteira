package public

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/download"
	"github.com/ed-fr/transteira/internal/httpserver/middleware"
	"github.com/ed-fr/transteira/internal/tenant"
)

// DownloadService serves the recipients' side. The app package adapts
// *download.Service to it (OpenFile and PrepareArchive return the narrow
// views below, so that the handlers can be tested without storage).
type DownloadService interface {
	Resolve(ctx context.Context, t *tenant.Tenant, rawToken, grantCookie string) (download.View, error)
	Unlock(ctx context.Context, t *tenant.Tenant, rawToken string, clientIP netip.Addr, password, grantCookie string) (string, error)
	OpenFile(ctx context.Context, t *tenant.Tenant, rawToken string, clientIP netip.Addr, grantCookie, fileID string) (DownloadFile, error)
	PrepareArchive(ctx context.Context, t *tenant.Tenant, rawToken string, clientIP netip.Addr, grantCookie string) (DownloadArchive, error)
}

// DownloadFile is a deliverable file opened for download (download.File).
type DownloadFile struct {
	// Name is the original file name, for Content-Disposition only.
	Name string
	// SHA256 is the lowercase hexadecimal SHA-256 of the clear file: the
	// strong ETag of the response, which makes If-Range safe.
	SHA256 string
	// Content streams the clear file (*download.Content).
	Content DownloadContent
}

// DownloadContent is the decrypted content of a file (*download.Content).
type DownloadContent interface {
	io.ReadSeeker
	// Delivered tells that the response was written without error.
	Delivered()
	// Close releases the file and records the ranges served.
	Close(ctx context.Context) error
}

// DownloadArchive is the ZIP archive of a transfer (*download.Archive).
type DownloadArchive interface {
	Size() int64
	Write(ctx context.Context, w io.Writer) error
	// Close releases the stream slot; it is idempotent.
	Close()
}

// errNoDownloadService reports a server built without WithDownloads, and
// errNoRequest a strict handler run without RequestMiddleware: wiring
// errors, answered 500.
var (
	errNoDownloadService = errors.New("public: no download service configured")
	errNoRequest         = errors.New("public: request not in the context (RequestMiddleware missing)")
)

// downloadPath is the path of the download resources; the link token
// follows it.
const downloadPath = apiBase + "/downloads/"

// archiveName is the file name of the ZIP archive.
const archiveName = "transfer.zip"

// requestKey is the context key of the HTTP request.
type requestKey struct{}

// requestOperations are the operations given the HTTP request by
// RequestMiddleware (strict handler operation names).
var requestOperations = map[string]bool{
	"GetDownload": true, "UnlockDownload": true, "DownloadFile": true, "DownloadArchive": true,
}

// RequestMiddleware is a strict middleware putting the HTTP request in the
// context of the download operations, and of them only: the grant cookie
// is read from it, and the file is served with http.ServeContent, which
// handles the Range and conditional headers of the request.
func RequestMiddleware(f gen.StrictHandlerFunc, operationID string) gen.StrictHandlerFunc {
	if !requestOperations[operationID] {
		return f
	}
	return func(ctx context.Context, w http.ResponseWriter, r *http.Request, request any) (any, error) {
		return f(context.WithValue(ctx, requestKey{}, r), w, r, request)
	}
}

// requestOf returns the HTTP request put in ctx by RequestMiddleware.
func requestOf(ctx context.Context) (*http.Request, bool) {
	r, ok := ctx.Value(requestKey{}).(*http.Request)
	return r, ok
}

// grantCookie returns the raw value of the download grant cookie of the
// request in ctx, "" when absent.
func grantCookie(ctx context.Context) string {
	r, ok := requestOf(ctx)
	if !ok {
		return ""
	}
	c, err := r.Cookie(download.GrantCookieName)
	if err != nil {
		return ""
	}
	return c.Value
}

// downloadTenant returns the tenant of the request and checks the wiring.
func (s *Server) downloadTenant(ctx context.Context) (*tenant.Tenant, error) {
	t, ok := tenant.FromContext(ctx)
	if !ok {
		return nil, problem.New(problem.CodeUnknownTenant)
	}
	if s.downloads == nil {
		return nil, errNoDownloadService
	}
	return t, nil
}

// GetDownload returns the download page of a link (getDownload).
func (s *Server) GetDownload(ctx context.Context, req gen.GetDownloadRequestObject) (gen.GetDownloadResponseObject, error) {
	t, err := s.downloadTenant(ctx)
	if err != nil {
		return nil, err
	}
	v, err := s.downloads.Resolve(ctx, t, req.LinkToken, grantCookie(ctx))
	if err != nil {
		return nil, downloadError(err)
	}
	return gen.GetDownload200JSONResponse(publicTransfer(req.LinkToken, v)), nil
}

// publicTransfer renders a view as the OpenAPI PublicTransfer. A locked
// view only carries the sender, the expiry and the flags.
func publicTransfer(token string, v download.View) gen.PublicTransfer {
	out := gen.PublicTransfer{
		SenderEmail: gen.Email(v.SenderEmail), ExpiresAt: v.ExpiresAt, PasswordProtected: v.PasswordProtected, Locked: v.Locked,
	}
	if v.Locked {
		return out
	}
	del, total := v.DeleteAfterFirstDownload, v.TotalBytes
	out.Message, out.DeleteAfterFirstDownload, out.TotalBytes = optional(v.Message), &del, &total
	if v.ArchiveAvailable {
		u := downloadPath + token + "/archive"
		out.ArchiveUrl = &u
	}
	files := make([]gen.PublicFile, len(v.Files))
	for i, f := range v.Files {
		files[i] = gen.PublicFile{
			Id: f.ID, Name: f.Name, Size: f.Size, MediaType: optional(f.MediaType), Sha256: f.SHA256,
			ScanStatus: gen.ScanStatus(f.ScanStatus), DownloadUrl: downloadPath + token + "/files/" + f.ID,
		}
	}
	out.Files = &files
	return out
}

// UnlockDownload checks a transfer password and sets the grant cookie
// (204).
func (s *Server) UnlockDownload(ctx context.Context, req gen.UnlockDownloadRequestObject) (gen.UnlockDownloadResponseObject, error) {
	t, err := s.downloadTenant(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil || req.Body.Password == "" {
		return nil, validationFailed(fieldPassword, fieldRequired)
	}
	cookie, err := s.downloads.Unlock(ctx, t, req.LinkToken, middleware.ClientIP(ctx), req.Body.Password, grantCookie(ctx))
	if err != nil {
		return nil, downloadError(err)
	}
	var resp gen.UnlockDownload204Response
	if cookie != "" {
		v := technicalCookie(download.GrantCookieName, cookie, download.GrantTTL)
		resp.Headers.SetCookie = &v
	}
	return resp, nil
}

// DownloadFile streams one file (downloadFile).
func (s *Server) DownloadFile(ctx context.Context, req gen.DownloadFileRequestObject) (gen.DownloadFileResponseObject, error) {
	t, err := s.downloadTenant(ctx)
	if err != nil {
		return nil, err
	}
	r, ok := requestOf(ctx)
	if !ok {
		return nil, errNoRequest
	}
	f, err := s.downloads.OpenFile(ctx, t, req.LinkToken, middleware.ClientIP(ctx), grantCookie(ctx), req.FileId)
	if err != nil {
		return nil, downloadError(err)
	}
	return fileResponse{r: r, file: f}, nil
}

// DownloadArchive streams the ZIP archive (downloadArchive).
func (s *Server) DownloadArchive(ctx context.Context, req gen.DownloadArchiveRequestObject) (gen.DownloadArchiveResponseObject, error) {
	t, err := s.downloadTenant(ctx)
	if err != nil {
		return nil, err
	}
	r, ok := requestOf(ctx)
	if !ok {
		return nil, errNoRequest
	}
	a, err := s.downloads.PrepareArchive(ctx, t, req.LinkToken, middleware.ClientIP(ctx), grantCookie(ctx))
	if err != nil {
		return nil, downloadError(err)
	}
	return archiveResponse{r: r, archive: a}, nil
}

// fieldPassword is the JSON pointer of the unlock password.
const fieldPassword = "/password"

// downloadError maps an error of the download service to the error the
// strict handler renders. Anything unknown (ErrNoClientIP included) is
// passed through: 500, logged.
func downloadError(err error) error {
	var (
		wrong   *download.WrongPasswordError
		locked  *download.LockedError
		streams *download.TooManyStreamsError
	)
	switch {
	case errors.Is(err, download.ErrPasswordRequired): // before ErrInvalid, which it matches
		return validationFailed(fieldPassword, fieldRequired)
	case errors.As(err, &streams):
		return problem.New(problem.CodeRateLimited, problem.WithRetryAfter(streams.RetryAfter))
	case errors.As(err, &wrong):
		return problem.New(problem.CodeTransferPasswordInvalid, problem.WithAttemptsRemaining(wrong.Remaining))
	case errors.As(err, &locked):
		return problem.New(problem.CodeTransferLocked, problem.WithRetryAfter(locked.RetryAfter))
	case errors.Is(err, download.ErrInvalid):
		return validationFailed(fieldPassword, fieldInvalidFormat)
	case errors.Is(err, download.ErrNotFound):
		return problem.New(problem.CodeNotFound)
	case errors.Is(err, download.ErrGone):
		return problem.New(problem.CodeTransferGone)
	case errors.Is(err, download.ErrDownloadLocked):
		return problem.New(problem.CodeDownloadLocked)
	default:
		return err
	}
}

// attachmentCSP is the Content-Security-Policy of file and archive
// responses: should a browser ever render one, it loads nothing, runs in a
// sandbox and cannot be framed.
const attachmentCSP = "default-src 'none'; sandbox; frame-ancestors 'none'"

// setAttachmentHeaders sets the headers forcing a download: the content is
// never rendered nor sniffed by a browser (CLAUDE.md section 10).
func setAttachmentHeaders(h http.Header, contentType, disposition string) {
	h.Set("Content-Type", contentType)
	h.Set("Content-Disposition", disposition)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", attachmentCSP)
	h.Set("Cache-Control", "no-store")
}

// fileResponse serves a file with http.ServeContent. It implements the
// generated response interface of downloadFile.
type fileResponse struct {
	r    *http.Request
	file DownloadFile
}

// VisitDownloadFileResponse implements gen.DownloadFileResponseObject.
//
// The strong ETag is the SHA-256 of the file, so that If-Range and
// If-None-Match are safe. A request for several ranges gets the full file
// (single ranges only); the request itself is never modified. An
// unsatisfiable range gets a range-not-satisfiable Problem. The content is
// credited as delivered only for a GET answered 200 or 206 whose response
// was written and flushed without error; it is always closed.
func (resp fileResponse) VisitDownloadFileResponse(w http.ResponseWriter) error {
	h := w.Header()
	setAttachmentHeaders(h, "application/octet-stream", attachment(resp.file.Name))
	if resp.file.SHA256 != "" {
		h.Set("ETag", `"`+resp.file.SHA256+`"`)
	}
	r := resp.r
	if strings.Contains(r.Header.Get("Range"), ",") {
		clone := *r
		clone.Header = r.Header.Clone()
		clone.Header.Del("Range")
		r = &clone
	}
	ew := &errorWriter{ResponseWriter: w, instance: middleware.RequestID(r.Context())}
	http.ServeContent(ew, r, "", time.Time{}, resp.file.Content)
	err := ew.err
	if err == nil && !ew.problem {
		err = http.NewResponseController(ew).Flush()
	}
	if err == nil && r.Method == http.MethodGet && (ew.status == http.StatusOK || ew.status == http.StatusPartialContent) {
		resp.file.Content.Delivered()
	}
	// Closing a read-only file cannot lose data; the recording failures
	// are logged by the download service.
	_ = resp.file.Content.Close(resp.r.Context())
	return err
}

// errorWriter records the status and the first write error of a file
// response, and turns the plain-text 416 answer of http.ServeContent into
// a range-not-satisfiable Problem (keeping its Content-Range).
type errorWriter struct {
	http.ResponseWriter
	instance string
	status   int
	err      error
	// problem is set once the Problem replaced the answer: the text that
	// http.ServeContent writes after it is dropped.
	problem bool
}

// WriteHeader implements http.ResponseWriter.
func (w *errorWriter) WriteHeader(code int) {
	if w.status != 0 {
		return // superfluous call, ignored as net/http does
	}
	w.status = code
	if code != http.StatusRequestedRangeNotSatisfiable {
		w.ResponseWriter.WriteHeader(code)
		return
	}
	w.problem = true
	w.Header().Del("Content-Disposition")
	w.Header().Del("ETag")
	problem.Write(w.ResponseWriter, problem.New(problem.CodeRangeNotSatisfiable, problem.WithInstance(w.instance)))
}

// Write implements http.ResponseWriter.
func (w *errorWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	if w.problem {
		return len(b), nil
	}
	n, err := w.ResponseWriter.Write(b)
	if err != nil && w.err == nil {
		w.err = err
	}
	return n, err
}

// Unwrap returns the wrapped writer (http.ResponseController).
func (w *errorWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// archiveResponse streams the ZIP archive. It implements the generated
// response interface of downloadArchive.
type archiveResponse struct {
	r       *http.Request
	archive DownloadArchive
}

// VisitDownloadArchiveResponse implements gen.DownloadArchiveResponseObject.
// A HEAD request gets the headers only. The archive is written through a
// writer that flushes the response as soon as its last byte is written,
// so that the completion that Archive.Write records after it (first
// download, deletion after the first download) never counts bytes still
// buffered on the server. The stream slot is always released.
func (resp archiveResponse) VisitDownloadArchiveResponse(w http.ResponseWriter) error {
	defer resp.archive.Close()
	size := resp.archive.Size()
	h := w.Header()
	setAttachmentHeaders(h, "application/zip", attachment(archiveName))
	h.Set("Content-Length", strconv.FormatInt(size, 10))
	w.WriteHeader(http.StatusOK)
	if resp.r.Method == http.MethodHead {
		return nil
	}
	return resp.archive.Write(resp.r.Context(), &flushAtEnd{w: w, rc: http.NewResponseController(w), remaining: size})
}

// flushAtEnd writes to w and flushes the response once remaining bytes
// were written: a failed flush fails that last write.
type flushAtEnd struct {
	w         io.Writer
	rc        *http.ResponseController
	remaining int64
}

// Write implements io.Writer.
func (f *flushAtEnd) Write(b []byte) (int, error) {
	n, err := f.w.Write(b)
	f.remaining -= int64(n)
	if err == nil && f.remaining <= 0 {
		err = f.rc.Flush()
	}
	return n, err
}

// attachment returns the Content-Disposition of a download named name:
// an ASCII filename fallback, in which non-ASCII characters, quotes,
// backslashes and control characters become "_", then the exact name as an
// RFC 5987 filename* (UTF-8, percent-encoded).
func attachment(name string) string {
	if name == "" || !utf8.ValidString(name) {
		name = "download"
	}
	var ascii, ext strings.Builder
	for _, c := range name {
		if c < 0x20 || c > 0x7e || c == '"' || c == '\\' {
			ascii.WriteByte('_')
		} else {
			ascii.WriteRune(c)
		}
	}
	for _, b := range []byte(name) {
		if isAttrChar(b) {
			ext.WriteByte(b)
		} else {
			fmt.Fprintf(&ext, "%%%02X", b)
		}
	}
	return `attachment; filename="` + ascii.String() + `"; filename*=UTF-8''` + ext.String()
}

// isAttrChar reports whether b may appear unencoded in an RFC 5987 value.
func isAttrChar(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		return true
	}
	return strings.IndexByte("!#$&+-.^_`|~", b) >= 0
}
