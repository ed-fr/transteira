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
	"github.com/ed-fr/transteira/internal/deposit"
	"github.com/ed-fr/transteira/internal/download"
	"github.com/ed-fr/transteira/internal/httpserver/middleware"
	"github.com/ed-fr/transteira/internal/i18n"
	"github.com/ed-fr/transteira/internal/tenant"
)

// DownloadService serves the recipients' side. The app package adapts
// *download.Service to it (OpenFile and PrepareArchive return the narrow
// views below, so that the handlers can be tested without storage).
type DownloadService interface {
	Resolve(ctx context.Context, t *tenant.Tenant, rawToken string, cookies download.Cookies) (download.View, error)
	Unlock(ctx context.Context, t *tenant.Tenant, rawToken string, clientIP netip.Addr, password string, cookies download.Cookies) (string, error)
	OpenFile(ctx context.Context, t *tenant.Tenant, rawToken string, clientIP netip.Addr, cookies download.Cookies, fileID string) (DownloadFile, error)
	PrepareArchive(ctx context.Context, t *tenant.Tenant, rawToken string, clientIP netip.Addr, cookies download.Cookies) (DownloadArchive, error)
	StartVerification(ctx context.Context, t *tenant.Tenant, rawToken string, clientIP netip.Addr, reply bool, acceptLanguage, verificationCookie string) (*download.Challenge, error)
	ConfirmVerification(ctx context.Context, t *tenant.Tenant, rawToken string, clientIP netip.Addr, code, verificationCookie string) (string, error)
	ReportAbuse(ctx context.Context, t *tenant.Tenant, rawToken string, clientIP netip.Addr, verificationCookie, category, message string) error
	ReplyAccess(ctx context.Context, t *tenant.Tenant, rawToken, verificationCookie string, clientIP netip.Addr) (download.ReplyTarget, error)
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
	// Begin decides the response (download limit) once it is about to be
	// answered 200 or 206, before its headers; get is false for HEAD.
	Begin(get bool) error
	// Delivered tells that the response was written without error.
	Delivered()
	// Close releases the file and records the ranges served.
	Close(ctx context.Context) error
}

// DownloadArchive is the ZIP archive of a transfer (*download.Archive).
type DownloadArchive interface {
	// Begin decides the response (download limit) before its headers; get
	// is false for HEAD.
	Begin(ctx context.Context, get bool) error
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
	"StartRecipientVerification": true, "ConfirmRecipientVerification": true, "ReportAbuse": true,
	"StartTransferReply": true,
}

// RequestMiddleware is a strict middleware putting the HTTP request in the
// context of the download operations, and of them only: the grant and
// recipient verification cookies are read from it, and the file is served
// with http.ServeContent, which handles the Range and conditional headers
// of the request.
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

// cookieValue returns the raw value of the cookie name of the request in
// ctx, "" when absent.
func cookieValue(ctx context.Context, name string) string {
	r, ok := requestOf(ctx)
	if !ok {
		return ""
	}
	c, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return c.Value
}

// downloadCookies returns the raw values of the download grant and recipient
// verification cookies of the request in ctx ("" when absent); the
// download service parses them defensively.
func downloadCookies(ctx context.Context) download.Cookies {
	return download.Cookies{
		Grant:        cookieValue(ctx, download.GrantCookieName),
		Verification: cookieValue(ctx, download.VerificationCookieName),
	}
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
	v, err := s.downloads.Resolve(ctx, t, req.LinkToken, downloadCookies(ctx))
	if err != nil {
		return nil, downloadError(err)
	}
	return gen.GetDownload200JSONResponse(publicTransfer(req.LinkToken, v, downloadLanguage(ctx, t))), nil
}

// downloadLanguage returns the language of the download page: the
// Accept-Language of the request in ctx when supported, else the default
// language of t.
func downloadLanguage(ctx context.Context, t *tenant.Tenant) string {
	accept := ""
	if r, ok := requestOf(ctx); ok {
		accept = r.Header.Get("Accept-Language")
	}
	return i18n.Negotiate(accept, t.DefaultLanguage)
}

// publicTransfer renders a view as the OpenAPI PublicTransfer, the label
// of its confidentiality level in lang (else in English, else in any
// language). A locked view only carries the sender, the expiry and the
// flags (with the masked address of a link awaiting its verification),
// never the confidentiality level.
func publicTransfer(token string, v download.View, lang string) gen.PublicTransfer {
	out := gen.PublicTransfer{
		SenderEmail: gen.Email(v.SenderEmail), ExpiresAt: v.ExpiresAt, PasswordProtected: v.PasswordProtected, Locked: v.Locked,
		ConfidentialityLevel: downloadLevel(v.Confidentiality, lang),
	}
	if v.VerificationRequired {
		required, verified := true, v.Verified
		out.VerificationRequired, out.Verified = &required, &verified
		out.RecipientEmailMasked = optional(v.RecipientEmailMasked)
	}
	if v.Locked {
		out.ConfidentialityLevel = nil
		return out
	}
	allowed := v.ReplyAllowed
	out.ReplyAllowed = &allowed
	if v.Reply {
		reply := true
		out.Reply = &reply
	}
	del, total := v.DeleteAfterFirstDownload, v.TotalBytes
	out.Message, out.DeleteAfterFirstDownload, out.TotalBytes = optional(v.Message), &del, &total
	if v.DownloadsRemaining != nil {
		left := max(*v.DownloadsRemaining, 0)
		out.DownloadsRemaining = &left
	}
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

// downloadLevel renders the confidentiality level of a download page, nil
// without level.
func downloadLevel(c *download.Confidentiality, lang string) *gen.ConfidentialityLevelRef {
	if c == nil {
		return nil
	}
	out := &gen.ConfidentialityLevelRef{Key: gen.ConfidentialityLevelKey(c.Key), Label: c.Label(lang, "en")}
	if r := c.Rules; r != nil {
		days := []gen.ExpiryDays{}
		for _, d := range r.AllowedExpiryDays() {
			days = append(days, gen.ExpiryDays(d))
		}
		out.Rules = &gen.ConfidentialityRules{
			AllowedExpiryDays: days, ForceDeleteAfterFirstDownload: r.ForceDeleteAfterFirstDownload,
			InternalRecipientsOnly: r.InternalRecipientsOnly, MaxDownloads: r.MaxDownloadsCap,
			RequirePassword: r.RequirePassword, RequireRecipientVerification: r.RequireRecipientVerification,
		}
	}
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
	cookie, err := s.downloads.Unlock(ctx, t, req.LinkToken, middleware.ClientIP(ctx), req.Body.Password, downloadCookies(ctx))
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
	f, err := s.downloads.OpenFile(ctx, t, req.LinkToken, middleware.ClientIP(ctx), downloadCookies(ctx), req.FileId)
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
	a, err := s.downloads.PrepareArchive(ctx, t, req.LinkToken, middleware.ClientIP(ctx), downloadCookies(ctx))
	if err != nil {
		return nil, downloadError(err)
	}
	return archiveResponse{r: r, archive: a}, nil
}

// StartRecipientVerification sends a code to the recipient of a link
// (startRecipientVerification): 202 with the masked address, or 204 when
// this browser is already verified for the link. The mail is in the
// language of the body when given (a supported one, else 400), else the
// one negotiated from Accept-Language, else the tenant default.
func (s *Server) StartRecipientVerification(ctx context.Context, req gen.StartRecipientVerificationRequestObject) (gen.StartRecipientVerificationResponseObject, error) {
	t, err := s.downloadTenant(ctx)
	if err != nil {
		return nil, err
	}
	reply := false
	language := deref(req.Params.AcceptLanguage)
	if req.Body != nil && req.Body.Purpose != nil {
		switch *req.Body.Purpose {
		case gen.RecipientVerificationStartPurposeDownload:
		case gen.RecipientVerificationStartPurposeReply:
			reply = true
		default:
			return nil, validationFailed(fieldPurpose, fieldInvalidFormat)
		}
	}
	if req.Body != nil && req.Body.Language != nil {
		// An exact supported code negotiates to itself.
		if language = string(*req.Body.Language); !i18n.IsSupported(language) {
			return nil, validationFailed(fieldLanguage, fieldInvalidFormat)
		}
	}
	ch, err := s.downloads.StartVerification(ctx, t, req.LinkToken, middleware.ClientIP(ctx), reply,
		language, cookieValue(ctx, download.VerificationCookieName))
	switch {
	case err != nil:
		return nil, downloadError(err)
	case ch == nil:
		return gen.StartRecipientVerification204Response{}, nil
	}
	return gen.StartRecipientVerification202JSONResponse{
		EmailMasked: ch.EmailMasked, ExpiresAt: ch.ExpiresAt, AttemptsRemaining: ch.AttemptsRemaining,
	}, nil
}

// StartTransferReply opens a reply deposit session for the recipient of a
// link (startTransferReply, 201 with the session cookie): the download
// service checks the tenant option, the link, the recipient verification
// and the original sender, then the deposit service opens the session. The
// body only carries an optional language, validated like the one of a
// recipient verification; the cross-site protections are those of
// unlockDownload (see internal/httpserver).
func (s *Server) StartTransferReply(ctx context.Context, req gen.StartTransferReplyRequestObject) (gen.StartTransferReplyResponseObject, error) {
	t, err := s.downloadTenant(ctx)
	if err != nil {
		return nil, err
	}
	if s.deposit == nil {
		return nil, errNoDepositService
	}
	if req.Body != nil && req.Body.Language != nil && !i18n.IsSupported(string(*req.Body.Language)) {
		return nil, validationFailed(fieldLanguage, fieldInvalidFormat)
	}
	clientIP := middleware.ClientIP(ctx)
	target, err := s.downloads.ReplyAccess(ctx, t, req.LinkToken, cookieValue(ctx, download.VerificationCookieName), clientIP)
	if err != nil {
		return nil, downloadError(err)
	}
	sess, err := s.deposit.OpenReply(ctx, t, clientIP, deposit.ReplyTarget{
		TransferID: target.TransferID, LinkID: target.LinkID, Email: target.Email, Recipient: target.Recipient,
		TransferExpiresAt: target.TransferExpiresAt,
	})
	if err != nil {
		return nil, depositError(err)
	}
	return sessionCreated{body: sessionBody(sess.SessionInfo), cookies: s.sessionCookies(sess)}, nil
}

// ConfirmRecipientVerification checks the code of the recipient of a link
// and sets the recipient verification cookie
// (confirmRecipientVerification, 204).
func (s *Server) ConfirmRecipientVerification(ctx context.Context, req gen.ConfirmRecipientVerificationRequestObject) (gen.ConfirmRecipientVerificationResponseObject, error) {
	t, err := s.downloadTenant(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil || req.Body.Code == "" {
		return nil, validationFailed(fieldCode, fieldRequired)
	}
	cookie, err := s.downloads.ConfirmVerification(ctx, t, req.LinkToken, middleware.ClientIP(ctx), req.Body.Code,
		cookieValue(ctx, download.VerificationCookieName))
	if err != nil {
		return nil, downloadError(err)
	}
	v := technicalCookie(download.VerificationCookieName, cookie, download.VerificationTTL)
	return gen.ConfirmRecipientVerification204Response{
		Headers: gen.ConfirmRecipientVerification204ResponseHeaders{SetCookie: &v},
	}, nil
}

// JSON pointers of the download request fields.
const (
	// fieldPassword is the JSON pointer of the unlock password.
	fieldPassword = "/password"
	// fieldPurpose is the JSON pointer of the purpose of a recipient
	// verification.
	fieldPurpose = "/purpose"
	// fieldCode is the JSON pointer of a recipient verification code.
	fieldCode = "/code"
	// fieldLanguage is the JSON pointer of the language of a recipient
	// verification mail.
	fieldLanguage = "/language"
	// fieldCategory and fieldMessage are the JSON pointers of an abuse report.
	fieldCategory = "/category"
	fieldMessage  = "/message"
)

// downloadError maps an error of the download service to the error the
// strict handler renders. Anything unknown (ErrNoClientIP included) is
// passed through: 500, logged.
func downloadError(err error) error {
	var (
		wrong     *download.WrongPasswordError
		locked    *download.LockedError
		streams   *download.TooManyStreamsError
		wrongCode *download.WrongCodeError
		limited   *download.RateLimitError
	)
	switch {
	case errors.Is(err, download.ErrReplyNotAllowed):
		return problem.New(problem.CodeReplyNotAllowed)
	case errors.Is(err, download.ErrRecipientVerificationRequired):
		return problem.New(problem.CodeRecipientVerificationRequired)
	case errors.Is(err, download.ErrVerificationRequired):
		return problem.New(problem.CodeRecipientVerificationRequired)
	case errors.Is(err, download.ErrVerificationNotNeeded), errors.Is(err, download.ErrNoChallenge):
		return problem.New(problem.CodeStateConflict)
	case errors.Is(err, download.ErrVerificationExhausted):
		return problem.New(problem.CodeVerificationExhausted)
	case errors.As(err, &wrongCode):
		return problem.New(problem.CodeVerificationCodeInvalid, problem.WithAttemptsRemaining(wrongCode.Remaining))
	case errors.Is(err, download.ErrInvalidCode):
		return validationFailed(fieldCode, fieldInvalidFormat)
	case errors.As(err, &limited):
		return problem.New(problem.CodeRateLimited, problem.WithRetryAfter(limited.RetryAfter))
	case errors.Is(err, download.ErrMailUnavailable):
		return fmt.Errorf("%w: %w", problem.New(problem.CodeMailUnavailable), err)
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
	case errors.Is(err, download.ErrInvalidCategory):
		return validationFailed(fieldCategory, fieldInvalidFormat)
	case errors.Is(err, download.ErrInvalidMessage):
		return validationFailed(fieldMessage, fieldInvalidFormat)
	case errors.Is(err, download.ErrNotFound):
		return problem.New(problem.CodeNotFound)
	case errors.Is(err, download.ErrGone):
		return problem.New(problem.CodeTransferGone)
	case errors.Is(err, download.ErrMaxDownloads):
		return problem.New(problem.CodeMaxDownloadsReached)
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
// unsatisfiable range gets a range-not-satisfiable Problem. Before a 200
// or 206 is written, the content decides the response (Begin, the
// download limit): a refusal replaces it with its Problem
// (max-downloads-reached), nothing of the file being sent. The content is
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
	ew := &errorWriter{
		ResponseWriter: w, instance: middleware.RequestID(r.Context()),
		begin: func() error { return resp.file.Content.Begin(r.Method == http.MethodGet) },
	}
	http.ServeContent(ew, r, "", time.Time{}, resp.file.Content)
	if ew.refused != nil {
		_ = resp.file.Content.Close(resp.r.Context())
		return downloadError(ew.refused)
	}
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
// a range-not-satisfiable Problem (keeping its Content-Range). Before a
// 200 or 206, it calls begin: a refusal is kept in refused, nothing is
// written, and the caller answers it.
type errorWriter struct {
	http.ResponseWriter
	instance string
	begin    func() error
	status   int
	err      error
	// refused is the refusal of begin.
	refused error
	// problem is set once the Problem replaced the answer, or the answer
	// was refused: what http.ServeContent writes after it is dropped.
	problem bool
}

// fileHeaders are the headers of a file answer, removed when it is
// refused.
var fileHeaders = []string{"Content-Length", "Content-Range", "Content-Disposition", "ETag", "Accept-Ranges", "Last-Modified"}

// WriteHeader implements http.ResponseWriter.
func (w *errorWriter) WriteHeader(code int) {
	if w.status != 0 {
		return // superfluous call, ignored as net/http does
	}
	w.status = code
	if (code == http.StatusOK || code == http.StatusPartialContent) && w.begin != nil {
		if err := w.begin(); err != nil {
			w.refused, w.problem = err, true
			for _, k := range fileHeaders {
				w.Header().Del(k)
			}
			return
		}
	}
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
// The archive first decides the response (Begin, the download limit): a
// refusal is answered as its Problem (max-downloads-reached). A HEAD
// request gets the headers only. The archive is written through a
// writer that flushes the response as soon as its last byte is written,
// so that the completion that Archive.Write records after it (first
// download, deletion after the first download) never counts bytes still
// buffered on the server. The stream slot is always released.
func (resp archiveResponse) VisitDownloadArchiveResponse(w http.ResponseWriter) error {
	defer resp.archive.Close()
	if err := resp.archive.Begin(resp.r.Context(), resp.r.Method == http.MethodGet); err != nil {
		return downloadError(err)
	}
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

// ReportAbuse records an abuse report on the transfer of a link
// (reportAbuse, 202). The recipient verification cookie is passed as is:
// the service ignores it unless it proves the reporter. The cross-site
// protections are those of unlockDownload (see internal/httpserver).
func (s *Server) ReportAbuse(ctx context.Context, req gen.ReportAbuseRequestObject) (gen.ReportAbuseResponseObject, error) {
	t, err := s.downloadTenant(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil || req.Body.Category == "" {
		return nil, validationFailed(fieldCategory, fieldRequired)
	}
	err = s.downloads.ReportAbuse(ctx, t, req.LinkToken, middleware.ClientIP(ctx),
		cookieValue(ctx, download.VerificationCookieName), string(req.Body.Category), deref(req.Body.Message))
	if err != nil {
		return nil, downloadError(err)
	}
	return gen.ReportAbuse202Response{}, nil
}
