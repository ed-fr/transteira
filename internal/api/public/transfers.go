package public

import (
	"context"
	"errors"
	"time"

	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/deposit"
	"github.com/ed-fr/transteira/internal/httpserver/middleware"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/transfer"
)

// TransferService creates, follows, cancels and finalizes transfers.
// *transfer.Service implements it.
type TransferService interface {
	Create(ctx context.Context, t *tenant.Tenant, sender transfer.Sender, req transfer.CreateRequest, idempotencyKey string) (transfer.Details, error)
	Get(ctx context.Context, t *tenant.Tenant, sender transfer.Sender, trfID string) (transfer.Details, error)
	Cancel(ctx context.Context, t *tenant.Tenant, sender transfer.Sender, trfID string) error
	Finalize(ctx context.Context, t *tenant.Tenant, sender transfer.Sender, trfID string) (transfer.Details, error)
}

// errNoTransferService reports a server built without WithTransfers: a
// wiring error, answered 500.
var errNoTransferService = errors.New("public: no transfer service configured")

// Resource paths built by the handlers, under the versioned API base.
const (
	// apiBase is the base path of the API (OpenAPI servers).
	apiBase = "/api/v1"
	// transferPath is the path of a transfer resource; its identifier
	// follows (Location header of createTransfer).
	transferPath = apiBase + "/transfers/"
	// uploadPath is the path of a tus upload resource; its identifier
	// follows (uploadUrl of the files).
	uploadPath = apiBase + "/uploads/"
)

// transferSender returns the tenant and the sender of the request: the
// deposit session set by the session middleware and the real client IP.
// The API token path is not implemented yet: without a session the
// request is unauthenticated.
func (s *Server) transferSender(ctx context.Context) (*tenant.Tenant, transfer.Sender, error) {
	t, ok := tenant.FromContext(ctx)
	if !ok {
		return nil, transfer.Sender{}, problem.New(problem.CodeUnknownTenant)
	}
	if s.transfers == nil {
		return nil, transfer.Sender{}, errNoTransferService
	}
	info, _, err := currentSession(ctx)
	if err != nil {
		return nil, transfer.Sender{}, err
	}
	return t, senderOf(ctx, info), nil
}

// senderOf builds the transfer sender of a deposit session.
func senderOf(ctx context.Context, info deposit.SessionInfo) transfer.Sender {
	sender := transfer.Sender{
		Depositor: store.Depositor{Email: info.Email, Kind: info.Kind}, ClientIP: middleware.ClientIP(ctx),
	}
	if info.Invitation != nil {
		sender.InvitationID = info.Invitation.ID
	}
	return sender
}

// CreateTransfer declares a transfer and its files (201 with Location).
func (s *Server) CreateTransfer(ctx context.Context, req gen.CreateTransferRequestObject) (gen.CreateTransferResponseObject, error) {
	t, sender, err := s.transferSender(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, validationFailed(transfer.FieldFiles, transfer.CodeRequired)
	}
	d, err := s.transfers.Create(ctx, t, sender, createRequest(req.Body), deref(req.Params.IdempotencyKey))
	if err != nil {
		return nil, transferError(err)
	}
	location := transferPath + d.ID
	return gen.CreateTransfer201JSONResponse{
		Body:    transferBody(d),
		Headers: gen.CreateTransfer201ResponseHeaders{Location: &location},
	}, nil
}

// GetTransfer returns a transfer to its sender.
func (s *Server) GetTransfer(ctx context.Context, req gen.GetTransferRequestObject) (gen.GetTransferResponseObject, error) {
	t, sender, err := s.transferSender(ctx)
	if err != nil {
		return nil, err
	}
	d, err := s.transfers.Get(ctx, t, sender, req.TransferId)
	if err != nil {
		return nil, transferError(err)
	}
	return gen.GetTransfer200JSONResponse(transferBody(d)), nil
}

// CancelTransfer deletes a transfer that is still uploading (204).
func (s *Server) CancelTransfer(ctx context.Context, req gen.CancelTransferRequestObject) (gen.CancelTransferResponseObject, error) {
	t, sender, err := s.transferSender(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.transfers.Cancel(ctx, t, sender, req.TransferId); err != nil {
		return nil, transferError(err)
	}
	return gen.CancelTransfer204Response{}, nil
}

// FinalizeTransfer closes the uploads and hands the transfer to the
// antivirus (202).
func (s *Server) FinalizeTransfer(ctx context.Context, req gen.FinalizeTransferRequestObject) (gen.FinalizeTransferResponseObject, error) {
	t, sender, err := s.transferSender(ctx)
	if err != nil {
		return nil, err
	}
	d, err := s.transfers.Finalize(ctx, t, sender, req.TransferId)
	if err != nil {
		return nil, transferError(err)
	}
	return gen.FinalizeTransfer202JSONResponse(transferBody(d)), nil
}

// createRequest converts the OpenAPI TransferCreate body.
func createRequest(b *gen.TransferCreate) transfer.CreateRequest {
	req := transfer.CreateRequest{
		SenderEmail:              string(deref(b.SenderEmail)),
		Message:                  deref(b.Message),
		ExpiryDays:               int(b.ExpiryDays),
		Password:                 b.Password,
		DeleteAfterFirstDownload: deref(b.DeleteAfterFirstDownload),
		Language:                 string(deref(b.Language)),
		Files:                    make([]transfer.FileDeclaration, len(b.Files)),
	}
	if b.Recipients != nil {
		req.Recipients = make([]string, len(*b.Recipients))
		for i, r := range *b.Recipients {
			req.Recipients[i] = string(r)
		}
	}
	for i, f := range b.Files {
		req.Files[i] = transfer.FileDeclaration{
			Name: f.Name, Size: f.Size, MediaType: deref(f.MediaType), ExpectedSHA256: deref(f.ExpectedSha256),
		}
	}
	return req
}

// transferBody renders a transfer as the OpenAPI SenderTransfer. Optional
// members are omitted when empty or zero.
func transferBody(d transfer.Details) gen.SenderTransfer {
	body := gen.SenderTransfer{
		Id: d.ID, Status: gen.TransferStatus(d.Status), SenderEmail: gen.Email(d.SenderEmail),
		Recipients: make([]gen.Email, len(d.Recipients)), Message: optional(d.Message),
		ExpiryDays: gen.ExpiryDays(d.ExpiryDays), ExpiresAt: optionalTime(d.ExpiresAt),
		PasswordProtected: d.PasswordProtected, DeleteAfterFirstDownload: d.DeleteAfterFirstDownload,
		TotalBytes: d.TotalBytes, CreatedAt: d.CreatedAt, UploadExpiresAt: optionalTime(d.UploadExpiresAt),
		FinalizedAt: optionalTime(d.FinalizedAt), DownloadUrl: optional(d.DownloadURL),
		Files: make([]gen.SenderFile, len(d.Files)),
	}
	for i, r := range d.Recipients {
		body.Recipients[i] = gen.Email(r)
	}
	for i, f := range d.Files {
		file := gen.SenderFile{
			Id: f.ID, Name: f.Name, Size: f.Size, MediaType: optional(f.MediaType), Sha256: optional(f.SHA256),
			ScanStatus: gen.ScanStatus(f.ScanStatus), ScanSignature: optional(f.ScanSignature),
		}
		if f.UploadID != "" {
			url, offset := uploadPath+f.UploadID, f.UploadOffset
			file.UploadUrl, file.UploadOffset = &url, &offset
		}
		body.Files[i] = file
	}
	return body
}

// optional returns &v, or nil for the empty string.
func optional(v string) *string {
	if v == "" {
		return nil
	}
	return &v
}

// optionalTime returns &t, or nil for the zero time.
func optionalTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// transferError maps an error of the transfer service to the error the
// strict handler renders. Anything unknown is passed through (500, logged).
func transferError(err error) error {
	var (
		invalid  *transfer.ValidationError
		tooLarge *transfer.TooLargeError
		files    *transfer.FilesError
		limited  *transfer.RateLimitError
	)
	switch {
	case errors.As(err, &invalid):
		fields := make([]problem.FieldError, len(invalid.Fields))
		for i, f := range invalid.Fields {
			fields[i] = problem.FieldError{Field: f.Pointer, Code: f.Code}
		}
		return problem.New(problem.CodeValidationFailed, problem.WithFieldErrors(fields...))
	case errors.As(err, &limited):
		return problem.New(problem.CodeRateLimited, problem.WithRetryAfter(limited.RetryAfter))
	case errors.As(err, &tooLarge):
		return problem.New(problem.CodeTransferTooLarge, problem.WithMaxTransferBytes(tooLarge.MaxTransferBytes))
	case errors.As(err, &files):
		code := problem.CodeUploadIncomplete
		if errors.Is(files.Kind, transfer.ErrChecksumMismatch) {
			code = problem.CodeChecksumMismatch
		}
		return problem.New(code, problem.WithFiles(files.FileIDs...))
	case errors.Is(err, transfer.ErrIncomplete):
		return problem.New(problem.CodeUploadIncomplete)
	case errors.Is(err, transfer.ErrChecksumMismatch):
		return problem.New(problem.CodeChecksumMismatch)
	case errors.Is(err, transfer.ErrBlockedFile):
		return problem.New(problem.CodeBlockedFile)
	case errors.Is(err, transfer.ErrForbidden):
		return problem.New(problem.CodeDepositNotAllowed)
	case errors.Is(err, transfer.ErrNotFound):
		return problem.New(problem.CodeNotFound)
	case errors.Is(err, transfer.ErrConflict): // ErrBusy and ErrIdempotencyMismatch included
		return problem.New(problem.CodeStateConflict)
	case errors.Is(err, transfer.ErrQuotaExceeded):
		return problem.New(problem.CodeQuotaExceeded)
	default:
		return err
	}
}
