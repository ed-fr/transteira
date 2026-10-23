package public

import (
	"context"
	"errors"
	"io"
	"net/http"

	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/upload"
)

// UploadService runs the tus uploads. *upload.Engine implements it.
type UploadService interface {
	Status(ctx context.Context, tid tenant.ID, p upload.Principal, uploadID string) (upload.Status, error)
	Append(ctx context.Context, tid tenant.ID, p upload.Principal, uploadID string, offset int64, body io.Reader) (upload.Status, error)
	Terminate(ctx context.Context, tid tenant.ID, p upload.Principal, uploadID string) error
}

// errNoUploadService reports a server built without WithUploads: a wiring
// error, answered 500.
var errNoUploadService = errors.New("public: no upload service configured")

// tus protocol values (tus 1.0.0, extensions expiration and termination).
const (
	// TusVersion is the only tus version served, the value of the
	// Tus-Resumable and Tus-Version headers.
	TusVersion = "1.0.0"
	// TusExtensions are the supported tus extensions (Tus-Extension).
	TusExtensions = "expiration,termination"
)

// uploadPrincipal returns the tenant and the principal of a tus request:
// the API token or the deposit session of the request (requestSender).
func (s *Server) uploadPrincipal(ctx context.Context) (*tenant.Tenant, upload.Principal, error) {
	t, ok := tenant.FromContext(ctx)
	if !ok {
		return nil, upload.Principal{}, problem.New(problem.CodeUnknownTenant)
	}
	if s.uploads == nil {
		return nil, upload.Principal{}, errNoUploadService
	}
	sender, err := requestSender(ctx)
	if err != nil {
		return nil, upload.Principal{}, err
	}
	return t, sender.Depositor, nil
}

// uploadExpires formats the Upload-Expires header (RFC 9110 date), nil for
// a completed upload, which does not expire.
func uploadExpires(st upload.Status) *string {
	if st.Completed || st.ExpiresAt.IsZero() {
		return nil
	}
	v := st.ExpiresAt.UTC().Format(http.TimeFormat)
	return &v
}

// tusVersion returns a fresh pointer to TusVersion for the generated
// response headers.
func tusVersion() *string {
	v := TusVersion
	return &v
}

// GetTusCapabilities describes the tus server (204): version, extensions
// and the maximum upload size, the per-transfer limit of the tenant.
func (s *Server) GetTusCapabilities(ctx context.Context, _ gen.GetTusCapabilitiesRequestObject) (gen.GetTusCapabilitiesResponseObject, error) {
	t, ok := tenant.FromContext(ctx)
	if !ok {
		return nil, problem.New(problem.CodeUnknownTenant)
	}
	maxSize := t.MaxTransferBytes
	ext := TusExtensions
	return gen.GetTusCapabilities204Response{Headers: gen.GetTusCapabilities204ResponseHeaders{
		TusResumable: tusVersion(), TusVersion: tusVersion(), TusExtension: &ext, TusMaxSize: &maxSize,
	}}, nil
}

// GetUploadOffset returns the durable offset of an upload (tus HEAD).
// Errors have no body, as tus requires.
func (s *Server) GetUploadOffset(ctx context.Context, req gen.GetUploadOffsetRequestObject) (gen.GetUploadOffsetResponseObject, error) {
	t, p, err := s.uploadPrincipal(ctx)
	if err != nil {
		return nil, err
	}
	st, err := s.uploads.Status(ctx, t.ID, p, req.UploadId)
	switch {
	case errors.Is(err, upload.ErrNotFound):
		return gen.GetUploadOffset404Response{}, nil
	case errors.Is(err, upload.ErrExpired), errors.Is(err, upload.ErrFinalized):
		return gen.GetUploadOffset410Response{}, nil
	case err != nil:
		return nil, err
	}
	offset, length := st.Offset, st.Length
	return gen.GetUploadOffset200Response{Headers: gen.GetUploadOffset200ResponseHeaders{
		TusResumable: tusVersion(), UploadOffset: &offset, UploadLength: &length, UploadExpires: uploadExpires(st),
	}}, nil
}

// AppendUploadChunk streams the request body into an upload (tus PATCH).
// The tus version, the media type and the idle read timeout are enforced
// by the HTTP layer before the handler runs. Errors have no body.
func (s *Server) AppendUploadChunk(ctx context.Context, req gen.AppendUploadChunkRequestObject) (gen.AppendUploadChunkResponseObject, error) {
	t, p, err := s.uploadPrincipal(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return gen.AppendUploadChunk400Response{}, nil
	}
	st, err := s.uploads.Append(ctx, t.ID, p, req.UploadId, req.Params.UploadOffset, req.Body)
	switch {
	case errors.Is(err, upload.ErrNotFound):
		return gen.AppendUploadChunk404Response{}, nil
	case errors.Is(err, upload.ErrBusy), errors.Is(err, upload.ErrOffsetMismatch), errors.Is(err, upload.ErrFinalized):
		return gen.AppendUploadChunk409Response{}, nil
	case errors.Is(err, upload.ErrExpired):
		return gen.AppendUploadChunk410Response{}, nil
	case errors.Is(err, upload.ErrTooLarge):
		return gen.AppendUploadChunk413Response{}, nil
	case errors.Is(err, upload.ErrInvalid), errors.Is(err, upload.ErrInterrupted):
		// For an interrupted body the progress is saved; the client, if
		// still there, resumes after a HEAD.
		return gen.AppendUploadChunk400Response{}, nil
	case err != nil:
		return nil, err
	}
	offset := st.Offset
	return gen.AppendUploadChunk204Response{Headers: gen.AppendUploadChunk204ResponseHeaders{
		TusResumable: tusVersion(), UploadOffset: &offset, UploadExpires: uploadExpires(st),
	}}, nil
}

// TerminateUpload removes an upload (tus termination, 204). Errors have no
// body.
func (s *Server) TerminateUpload(ctx context.Context, req gen.TerminateUploadRequestObject) (gen.TerminateUploadResponseObject, error) {
	t, p, err := s.uploadPrincipal(ctx)
	if err != nil {
		return nil, err
	}
	err = s.uploads.Terminate(ctx, t.ID, p, req.UploadId)
	switch {
	case errors.Is(err, upload.ErrNotFound):
		return gen.TerminateUpload404Response{}, nil
	case errors.Is(err, upload.ErrBusy), errors.Is(err, upload.ErrFinalized):
		return gen.TerminateUpload409Response{}, nil
	case err != nil:
		return nil, err
	}
	return gen.TerminateUpload204Response{Headers: gen.TerminateUpload204ResponseHeaders{TusResumable: tusVersion()}}, nil
}
