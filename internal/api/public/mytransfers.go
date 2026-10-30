package public

import (
	"context"
	"errors"
	"net/netip"
	"slices"

	"github.com/ed-fr/transteira/internal/api/apiutil"
	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/httpserver/middleware"
	"github.com/ed-fr/transteira/internal/mytransfers"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// MyTransfersService implements "My transfers". *mytransfers.Service
// implements it; the session lookup and the CSRF check are done by the
// middlewares (see httpserver), not by the handlers.
type MyTransfersService interface {
	RequestLink(ctx context.Context, t *tenant.Tenant, ip netip.Addr, acceptLanguage, email, language string) error
	StartSession(ctx context.Context, t *tenant.Tenant, ip netip.Addr, linkToken string) (mytransfers.Session, error)
	End(ctx context.Context, t *tenant.Tenant, rawToken string) error
	List(ctx context.Context, t *tenant.Tenant, sess mytransfers.SessionInfo, cursor string, limit int) (store.Page[mytransfers.Transfer], error)
	Get(ctx context.Context, t *tenant.Tenant, sess mytransfers.SessionInfo, trfID string) (mytransfers.TransferDetail, error)
	Delete(ctx context.Context, t *tenant.Tenant, sess mytransfers.SessionInfo, ip netip.Addr, trfID string) error
	Extend(ctx context.Context, t *tenant.Tenant, sess mytransfers.SessionInfo, ip netip.Addr, trfID string, days int) (mytransfers.TransferDetail, error)
}

// WithMyTransfers serves the "my transfers" operations with svc. Without
// it they answer 500.
func WithMyTransfers(svc MyTransfersService) Option {
	return func(s *Server) { s.myTransfers = svc }
}

// errNoMyTransfersService reports a server built without WithMyTransfers:
// a wiring error, answered 500.
var errNoMyTransfersService = errors.New("public: no my transfers service configured")

// Field error code of an extension duration that is not allowed.
const fieldNotAllowed = "not-allowed"

// myTransfersTenant returns the tenant of the request, or the error to
// answer.
func (s *Server) myTransfersTenant(ctx context.Context) (*tenant.Tenant, error) {
	t, ok := tenant.FromContext(ctx)
	if !ok {
		return nil, problem.New(problem.CodeUnknownTenant)
	}
	if s.myTransfers == nil {
		return nil, errNoMyTransfersService
	}
	return t, nil
}

// mySession returns the tenant, the "my transfers" session and its cookie
// token stored by the session middleware. Their absence means the route
// was wired without it: the request is refused as unauthenticated.
func (s *Server) mySession(ctx context.Context) (*tenant.Tenant, mytransfers.SessionInfo, string, error) {
	t, err := s.myTransfersTenant(ctx)
	if err != nil {
		return nil, mytransfers.SessionInfo{}, "", err
	}
	info, ok := middleware.MyTransfersSessionFrom[mytransfers.SessionInfo](ctx)
	token, tokOK := middleware.MyTransfersSessionToken(ctx)
	if !ok || !tokOK {
		return nil, mytransfers.SessionInfo{}, "", problem.New(problem.CodeUnauthenticated)
	}
	return t, info, token, nil
}

// myTransfersCookie returns the Set-Cookie value of the "my transfers"
// session cookie, valid until the session expires.
func (s *Server) myTransfersCookie(sess mytransfers.Session) string {
	return technicalCookie(middleware.MyTransfersCookie, sess.Token, sess.ExpiresAt.Sub(s.now()))
}

// RequestMyTransfersLink asks for an access link mailed to the address:
// 202 whatever the address (no enumeration).
func (s *Server) RequestMyTransfersLink(ctx context.Context, req gen.RequestMyTransfersLinkRequestObject) (gen.RequestMyTransfersLinkResponseObject, error) {
	t, err := s.myTransfersTenant(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, validationFailed(mytransfers.FieldEmail, fieldRequired)
	}
	language := ""
	if req.Body.Language != nil {
		language = string(*req.Body.Language)
	}
	err = s.myTransfers.RequestLink(ctx, t, middleware.ClientIP(ctx), deref(req.Params.AcceptLanguage),
		string(req.Body.Email), language)
	if err != nil {
		return nil, myTransfersError(err)
	}
	return gen.RequestMyTransfersLink202Response{}, nil
}

// StartMyTransfersSession exchanges the token of an access link for a
// session: 201 with the session cookie.
func (s *Server) StartMyTransfersSession(ctx context.Context, req gen.StartMyTransfersSessionRequestObject) (gen.StartMyTransfersSessionResponseObject, error) {
	t, err := s.myTransfersTenant(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil || req.Body.Token == "" {
		return nil, validationFailed(mytransfers.FieldToken, fieldRequired)
	}
	sess, err := s.myTransfers.StartSession(ctx, t, middleware.ClientIP(ctx), req.Body.Token)
	if err != nil {
		return nil, myTransfersError(err)
	}
	cookie := s.myTransfersCookie(sess)
	return gen.StartMyTransfersSession201JSONResponse{
		Body:    mySessionBody(sess.SessionInfo),
		Headers: gen.StartMyTransfersSession201ResponseHeaders{SetCookie: &cookie},
	}, nil
}

// GetCurrentMyTransfersSession returns the session authenticated by the
// session middleware, with its CSRF token.
func (s *Server) GetCurrentMyTransfersSession(ctx context.Context, _ gen.GetCurrentMyTransfersSessionRequestObject) (gen.GetCurrentMyTransfersSessionResponseObject, error) {
	_, info, _, err := s.mySession(ctx)
	if err != nil {
		return nil, err
	}
	return gen.GetCurrentMyTransfersSession200JSONResponse(mySessionBody(info)), nil
}

// EndMyTransfersSession ends the current session and clears its cookie
// (204).
func (s *Server) EndMyTransfersSession(ctx context.Context, _ gen.EndMyTransfersSessionRequestObject) (gen.EndMyTransfersSessionResponseObject, error) {
	t, _, token, err := s.mySession(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.myTransfers.End(ctx, t, token); err != nil {
		return nil, myTransfersError(err)
	}
	cookie := middleware.ExpiredCookie(middleware.MyTransfersCookie)
	return gen.EndMyTransfersSession204Response{Headers: gen.EndMyTransfersSession204ResponseHeaders{SetCookie: &cookie}}, nil
}

// ListMyTransfers lists the transfers in progress of the session address.
func (s *Server) ListMyTransfers(ctx context.Context, req gen.ListMyTransfersRequestObject) (gen.ListMyTransfersResponseObject, error) {
	t, info, _, err := s.mySession(ctx)
	if err != nil {
		return nil, err
	}
	page, err := s.myTransfers.List(ctx, t, info, deref(req.Params.Cursor), deref(req.Params.Limit))
	if err != nil {
		return nil, myTransfersError(err)
	}
	resp := gen.ListMyTransfers200JSONResponse{Items: make([]gen.MyTransfer, len(page.Items))}
	for i, it := range page.Items {
		resp.Items[i] = myTransferBody(it.Transfer, it.Recipients, it.FileCount, it.DownloadedBy, it.LevelLabel)
	}
	if page.NextCursor != "" {
		next := page.NextCursor
		resp.NextCursor = &next
	}
	return resp, nil
}

// GetMyTransfer returns a transfer of the session address with its files
// and per-recipient tracking.
func (s *Server) GetMyTransfer(ctx context.Context, req gen.GetMyTransferRequestObject) (gen.GetMyTransferResponseObject, error) {
	t, info, _, err := s.mySession(ctx)
	if err != nil {
		return nil, err
	}
	d, err := s.myTransfers.Get(ctx, t, info, req.TransferId)
	if err != nil {
		return nil, myTransfersError(err)
	}
	return gen.GetMyTransfer200JSONResponse(myTransferDetailBody(d)), nil
}

// DeleteMyTransfer deletes a transfer of the session address (204, also
// when it already ended).
func (s *Server) DeleteMyTransfer(ctx context.Context, req gen.DeleteMyTransferRequestObject) (gen.DeleteMyTransferResponseObject, error) {
	t, info, _, err := s.mySession(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.myTransfers.Delete(ctx, t, info, middleware.ClientIP(ctx), req.TransferId); err != nil {
		return nil, myTransfersError(err)
	}
	return gen.DeleteMyTransfer204Response{}, nil
}

// ExtendMyTransfer extends the validity of a transfer of the session
// address and returns it.
func (s *Server) ExtendMyTransfer(ctx context.Context, req gen.ExtendMyTransferRequestObject) (gen.ExtendMyTransferResponseObject, error) {
	t, info, _, err := s.mySession(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, validationFailed(mytransfers.FieldExpiryDays, fieldRequired)
	}
	d, err := s.myTransfers.Extend(ctx, t, info, middleware.ClientIP(ctx), req.TransferId, int(req.Body.ExpiryDays))
	if err != nil {
		return nil, myTransfersError(err)
	}
	return gen.ExtendMyTransfer200JSONResponse(myTransferDetailBody(d)), nil
}

// mySessionBody renders a session as the OpenAPI MyTransfersSession. The
// session record identifier stays on the server.
func mySessionBody(info mytransfers.SessionInfo) gen.MyTransfersSession {
	return gen.MyTransfersSession{Email: gen.Email(info.Email), CsrfToken: info.CSRFToken, ExpiresAt: info.ExpiresAt}
}

// myTransferBody renders a transfer as the OpenAPI MyTransfer: never a
// link nor a token.
func myTransferBody(t store.Transfer, recipients []string, fileCount, downloadedBy int, label string) gen.MyTransfer {
	body := gen.MyTransfer{
		Id: t.ID, Status: gen.TransferStatus(t.Status), Recipients: make([]gen.Email, len(recipients)),
		FileCount: fileCount, TotalBytes: t.TotalBytes, ExpiryDays: gen.ExpiryDays(t.ExpiryDays),
		CreatedAt: t.CreatedAt, PasswordProtected: t.PasswordProtected(), RecipientVerification: t.RecipientVerification,
		ConfidentialityLevel: levelRef(t.ConfidentialityLevel, label, t.Rules), DownloadedBy: downloadedBy,
	}
	// A transfer still scanning has only a provisional expiry, never
	// enforced: it is not shown.
	if t.Status != store.TransferScanning {
		body.ExpiresAt = optionalTime(t.ExpiresAt)
	}
	for i, r := range recipients {
		body.Recipients[i] = gen.Email(r)
	}
	return body
}

// myTransferDetailBody renders a transfer as the OpenAPI MyTransferDetail:
// files and per-recipient tracking, never a link nor a token.
func myTransferDetailBody(d mytransfers.TransferDetail) gen.MyTransferDetail {
	t := d.Transfer
	head := myTransferBody(t, d.Recipients, len(d.Files), d.DownloadedBy, d.LevelLabel)
	count := t.ExtensionCount
	body := gen.MyTransferDetail{
		Id: head.Id, Status: head.Status, Recipients: head.Recipients, FileCount: head.FileCount,
		TotalBytes: head.TotalBytes, ExpiryDays: head.ExpiryDays, CreatedAt: head.CreatedAt, ExpiresAt: head.ExpiresAt,
		PasswordProtected: head.PasswordProtected, RecipientVerification: head.RecipientVerification,
		ConfidentialityLevel: head.ConfidentialityLevel, DownloadedBy: head.DownloadedBy,
		Message: optional(t.Message), DeleteAfterFirstDownload: t.DeleteAfterFirstDownload, MaxDownloads: t.MaxDownloads,
		DownloadCount: int(t.DownloadCount), ExtensionCount: &count, ExtendableTo: optionalTime(d.ExtendableTo),
		RecipientTracking: apiutil.RecipientTracking(d.Tracking),
	}
	// The generated item type is anonymous: grow the slice rather than
	// spelling it out; max(.., 1) keeps it non-nil, so that the JSON is [].
	body.Files = slices.Grow(body.Files, max(len(d.Files), 1))[:len(d.Files)]
	for i, f := range d.Files {
		file := &body.Files[i]
		file.Id, file.Name, file.Size, file.ScanStatus = f.ID, f.Name, f.Size, gen.ScanStatus(f.ScanStatus)
		// The folder (since 1.1) is absent at the root.
		file.Path = optional(f.Path)
		if f.SHA256 != "" {
			sum := f.SHA256
			file.Sha256 = &sum
		}
	}
	return body
}

// myTransfersError maps an error of the "my transfers" service to the
// error the strict handler renders. Anything unknown is passed through
// (500, logged; the service never puts an address or a token in it).
func myTransfersError(err error) error {
	var (
		invalid    *mytransfers.InvalidError
		limited    *mytransfers.RateLimitError
		notAllowed *mytransfers.NotAllowedError
		busy       *mytransfers.BusyError
	)
	switch {
	case errors.As(err, &invalid):
		code := fieldInvalidFormat
		if invalid.Field == mytransfers.FieldEmail {
			code = fieldInvalidEmail
		}
		return validationFailed(invalid.Field, code)
	case errors.As(err, &notAllowed):
		fe := problem.FieldError{Field: mytransfers.FieldExpiryDays, Code: fieldNotAllowed}
		for _, d := range notAllowed.Allowed {
			fe.Allowed = append(fe.Allowed, d)
		}
		return problem.New(problem.CodeValidationFailed, problem.WithFieldErrors(fe))
	case errors.As(err, &limited):
		return problem.New(problem.CodeRateLimited, problem.WithRetryAfter(limited.RetryAfter))
	case errors.As(err, &busy):
		return problem.New(problem.CodeStateConflict, problem.WithRetryAfter(busy.RetryAfter))
	case errors.Is(err, mytransfers.ErrMailUnavailable):
		return problem.New(problem.CodeMailUnavailable)
	case errors.Is(err, mytransfers.ErrAccessLinkInvalid):
		return problem.New(problem.CodeAccessLinkInvalid)
	case errors.Is(err, mytransfers.ErrUnauthenticated):
		return problem.New(problem.CodeUnauthenticated)
	case errors.Is(err, mytransfers.ErrNotFound):
		return problem.New(problem.CodeNotFound)
	case errors.Is(err, mytransfers.ErrNotExtendable):
		return problem.New(problem.CodeStateConflict)
	case errors.Is(err, mytransfers.ErrExtensionLimit):
		return problem.New(problem.CodeExtensionLimitReached,
			problem.WithDetail("A transfer cannot stay available more than 90 days after its creation."))
	default:
		return err
	}
}
