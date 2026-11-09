package public

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strconv"

	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/httpserver/middleware"
	"github.com/ed-fr/transteira/internal/mytransfers"
	"github.com/ed-fr/transteira/internal/secret"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/transfer"
)

// SecretService serves the one-time secrets (since 2.1). *secret.Service
// implements it.
type SecretService interface {
	Create(ctx context.Context, t *tenant.Tenant, sender transfer.Sender, req secret.CreateRequest) (secret.Created, error)
	Status(ctx context.Context, t *tenant.Tenant, ip netip.Addr, token string) (secret.Status, error)
	Reveal(ctx context.Context, t *tenant.Tenant, ip netip.Addr, token, keyProof, proof string) (secret.Revealed, error)
	ListMine(ctx context.Context, t *tenant.Tenant, email, cursor string, limit int) (store.Page[store.Secret], error)
	DeleteMine(ctx context.Context, t *tenant.Tenant, email string, ip netip.Addr, secID string) error
	UploadFile(ctx context.Context, t *tenant.Tenant, sender transfer.Sender, secID string, body io.Reader) (store.Secret, error)
	DownloadFile(ctx context.Context, t *tenant.Tenant, ip netip.Addr, token, grant string) (secret.FileStream, error)
	Send(ctx context.Context, t *tenant.Tenant, sender transfer.Sender, secID, secretToken, fragmentKey string) (store.Secret, error)
}

// WithSecrets serves the one-time secret operations with svc. Without it
// they answer 500.
func WithSecrets(svc SecretService) Option {
	return func(s *Server) { s.secrets = svc }
}

// errNoSecretService reports a server built without WithSecrets: a wiring
// error, answered 500.
var errNoSecretService = errors.New("public: no secret service configured")

// noStore is the Cache-Control of the answers of the secret links.
const noStore = "no-store"

// secretTenant returns the tenant of the request, or the error to answer.
func (s *Server) secretTenant(ctx context.Context) (*tenant.Tenant, error) {
	t, ok := tenant.FromContext(ctx)
	if !ok {
		return nil, problem.New(problem.CodeUnknownTenant)
	}
	if s.secrets == nil {
		return nil, errNoSecretService
	}
	return t, nil
}

// CreateSecret declares a one-time secret sealed in the browser of its
// creator, a deposit session or an API token (201 with its token, once).
func (s *Server) CreateSecret(ctx context.Context, req gen.CreateSecretRequestObject) (gen.CreateSecretResponseObject, error) {
	t, err := s.secretTenant(ctx)
	if err != nil {
		return nil, err
	}
	sender, err := requestSender(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, validationFailed(secret.FieldEncryptedText, fieldRequired)
	}
	c, err := s.secrets.Create(ctx, t, sender, secretCreateRequest(req.Body))
	if err != nil {
		return nil, secretError(err)
	}
	resp := gen.CreateSecret201JSONResponse{Id: c.ID, Token: c.Token, State: gen.SecretCreatedState(c.State)}
	resp.ExpiresAt = optionalTime(c.ExpiresAt)
	return resp, nil
}

// secretCreateRequest converts the OpenAPI SecretCreate body.
func secretCreateRequest(b *gen.SecretCreate) secret.CreateRequest {
	req := secret.CreateRequest{
		EncryptedText: b.EncryptedText, Verifier: b.Verifier, KeyVerifier: b.KeyVerifier,
		ExpiresIn: string(b.ExpiresIn), Delivery: string(b.Delivery), Recipient: b.Recipient,
		ReadReceipt: deref(b.ReadReceipt), SenderEmail: b.SenderEmail,
	}
	if p := b.Passphrase; p != nil {
		req.Passphrase = &secret.Passphrase{KDF: string(p.Kdf), Iterations: int(p.Iterations), Salt: p.Salt}
	}
	if f := b.File; f != nil {
		req.File = &secret.File{Size: f.Size, EncryptedMetadata: f.EncryptedMetadata}
	}
	return req
}

// GetSecretLink returns the status of a secret link (it consumes nothing
// and returns nothing sealed).
func (s *Server) GetSecretLink(ctx context.Context, req gen.GetSecretLinkRequestObject) (gen.GetSecretLinkResponseObject, error) {
	t, err := s.secretTenant(ctx)
	if err != nil {
		return nil, err
	}
	st, err := s.secrets.Status(ctx, t, middleware.ClientIP(ctx), req.SecretToken)
	if err != nil {
		return nil, secretError(err)
	}
	cc := noStore
	resp := gen.GetSecretLink200JSONResponse{
		Body:    gen.SecretStatus{State: gen.SecretStatusState(store.SecretActive), ExpiresAt: st.ExpiresAt.UTC()},
		Headers: gen.GetSecretLink200ResponseHeaders{CacheControl: &cc},
	}
	if p := st.Passphrase; p != nil {
		resp.Body.Passphrase = &gen.SecretPassphrase{
			Kdf: gen.SecretPassphraseKdf(p.KDF), Iterations: gen.SecretPassphraseIterations(p.Iterations), Salt: p.Salt,
		}
	}
	if st.FileSize > 0 {
		resp.Body.File = &struct {
			Size int64 `json:"size"`
		}{Size: st.FileSize}
	}
	return resp, nil
}

// RevealSecret reveals a secret, once, with the proofs of the recipient.
func (s *Server) RevealSecret(ctx context.Context, req gen.RevealSecretRequestObject) (gen.RevealSecretResponseObject, error) {
	t, err := s.secretTenant(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, validationFailed(secret.FieldKeyProof, fieldRequired)
	}
	out, err := s.secrets.Reveal(ctx, t, middleware.ClientIP(ctx), req.SecretToken, req.Body.KeyProof, req.Body.Proof)
	if err != nil {
		return nil, secretError(err)
	}
	cc := noStore
	resp := gen.RevealSecret200JSONResponse{
		Body:    gen.SecretRevealed{EncryptedText: out.EncryptedText},
		Headers: gen.RevealSecret200ResponseHeaders{CacheControl: &cc},
	}
	resp.Body.EncryptedMetadata = optional(out.EncryptedMetadata)
	if out.FileGrant != "" {
		resp.Body.FileGrant = &out.FileGrant
		resp.Body.FileGrantExpiresAt = optionalTime(out.FileGrantExpiresAt.UTC())
	}
	return resp, nil
}

// UploadSecretFile stores the file of a pending secret, sent as the raw
// body (the TTE2 ciphertext of the file), for its creator.
func (s *Server) UploadSecretFile(ctx context.Context, req gen.UploadSecretFileRequestObject) (gen.UploadSecretFileResponseObject, error) {
	t, err := s.secretTenant(ctx)
	if err != nil {
		return nil, err
	}
	sender, err := requestSender(ctx)
	if err != nil {
		return nil, err
	}
	sec, err := s.secrets.UploadFile(ctx, t, sender, req.SecretId, req.Body)
	if err != nil {
		return nil, secretError(err)
	}
	return gen.UploadSecretFile200JSONResponse(secretBody(sec)), nil
}

// SendSecret activates a pending e-mail secret and mails its link, for its
// creator. The body carries the token and the key of the link, used only to
// compose the mail: neither is logged nor kept (threat model T-363).
func (s *Server) SendSecret(ctx context.Context, req gen.SendSecretRequestObject) (gen.SendSecretResponseObject, error) {
	t, err := s.secretTenant(ctx)
	if err != nil {
		return nil, err
	}
	sender, err := requestSender(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, validationFailed(secret.FieldSecretToken, fieldRequired)
	}
	sec, err := s.secrets.Send(ctx, t, sender, req.SecretId, req.Body.SecretToken, req.Body.FragmentKey)
	if err != nil {
		return nil, secretError(err)
	}
	return gen.SendSecret200JSONResponse(secretBody(sec)), nil
}

// DownloadSecretFile streams the file of a revealed secret, once, with the
// one-time grant of the TransTeira-Secret-Grant header.
func (s *Server) DownloadSecretFile(ctx context.Context, req gen.DownloadSecretFileRequestObject) (gen.DownloadSecretFileResponseObject, error) {
	t, err := s.secretTenant(ctx)
	if err != nil {
		return nil, err
	}
	f, err := s.secrets.DownloadFile(ctx, t, middleware.ClientIP(ctx), req.SecretToken, req.Params.TransTeiraSecretGrant)
	if err != nil {
		return nil, secretError(err)
	}
	return secretFileResponse{ctx: ctx, file: f}, nil
}

// secretFileResponse streams the file of a secret as a forced download. It
// implements the generated response interface of downloadSecretFile.
type secretFileResponse struct {
	ctx  context.Context
	file secret.FileStream
}

// VisitDownloadSecretFileResponse implements
// gen.DownloadSecretFileResponseObject. The content is never rendered nor
// sniffed nor cached (T-358), and no range is served. The grant is ended
// only when the whole stream was written and flushed without error: an
// interrupted download can be retried with the same grant while it is
// valid. The file is always closed.
func (r secretFileResponse) VisitDownloadSecretFileResponse(w http.ResponseWriter) error {
	defer func() { _ = r.file.Close() }()
	h := w.Header()
	setAttachmentHeaders(h, "application/octet-stream", "attachment")
	h.Set("Content-Length", strconv.FormatInt(r.file.Size(), 10))
	h.Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(http.StatusOK)
	_, err := io.Copy(w, r.file)
	if err == nil {
		err = http.NewResponseController(w).Flush()
	}
	if err == nil {
		// A successful flush means the last bytes left this server, not
		// that the client received them all (a proxy or the network may
		// still drop them). The grant then ends anyway: the creator is
		// told nothing more, and a client that lost the tail retries
		// within the grant window only if it failed before this point
		// (threat model T-359).
		r.file.Delivered(r.ctx)
	}
	return err
}

// ListMySecrets lists the secrets of the "my transfers" session address.
func (s *Server) ListMySecrets(ctx context.Context, req gen.ListMySecretsRequestObject) (gen.ListMySecretsResponseObject, error) {
	t, email, err := s.mySecretSession(ctx)
	if err != nil {
		return nil, err
	}
	page, err := s.secrets.ListMine(ctx, t, email, deref(req.Params.Cursor), deref(req.Params.Limit))
	if err != nil {
		return nil, secretError(err)
	}
	resp := gen.ListMySecrets200JSONResponse{Items: make([]gen.Secret, len(page.Items))}
	for i, it := range page.Items {
		resp.Items[i] = secretBody(it)
	}
	resp.NextCursor = optional(page.NextCursor)
	return resp, nil
}

// DeleteMySecret deletes a secret of the "my transfers" session address
// before it is read (204, also when it already ended).
func (s *Server) DeleteMySecret(ctx context.Context, req gen.DeleteMySecretRequestObject) (gen.DeleteMySecretResponseObject, error) {
	t, email, err := s.mySecretSession(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.secrets.DeleteMine(ctx, t, email, middleware.ClientIP(ctx), req.SecretId); err != nil {
		return nil, secretError(err)
	}
	return gen.DeleteMySecret204Response{}, nil
}

// mySecretSession returns the tenant and the address of the "my transfers"
// session of the request, or the error to answer.
func (s *Server) mySecretSession(ctx context.Context) (*tenant.Tenant, string, error) {
	t, err := s.secretTenant(ctx)
	if err != nil {
		return nil, "", err
	}
	info, ok := middleware.MyTransfersSessionFrom[mytransfers.SessionInfo](ctx)
	if !ok {
		return nil, "", problem.New(problem.CodeUnauthenticated)
	}
	return t, info.Email, nil
}

// secretBody converts a secret for its creator (OpenAPI Secret): metadata
// only.
func secretBody(it store.Secret) gen.Secret {
	out := gen.Secret{
		Id: it.ID, State: gen.SecretState(it.State), Delivery: gen.SecretDelivery(it.Delivery),
		ReadReceipt: it.ReadReceipt, HasFile: it.FileSize > 0, CreatedAt: it.CreatedAt.UTC(),
		Recipient: optional(it.RecipientEmail), ExpiresAt: optionalTime(it.ExpiresAt.UTC()),
		ReadAt: optionalTime(it.ReadAt.UTC()), EndedAt: optionalTime(it.EndedAt.UTC()),
	}
	if it.FileSize > 0 {
		size := it.FileSize
		out.FileSize = &size
	}
	if it.EndReason != "" {
		r := gen.SecretEndReason(secret.APIReason(it.EndReason))
		out.EndReason = &r
	}
	return out
}

// secretError maps an error of the secret service to the error the strict
// handler renders. Anything unknown is passed through (500, logged).
func secretError(err error) error {
	var (
		invalid  *secret.ValidationError
		format   *secret.FormatError
		duration *secret.DurationError
		tooLarge *secret.FileTooLargeError
		limit    *secret.LimitError
		limited  *secret.RateLimitError
		gone     *secret.GoneError
		proof    *secret.ProofError
	)
	switch {
	case errors.As(err, &invalid):
		return problem.New(problem.CodeValidationFailed, problem.WithFieldErrors(secretFields(invalid.Fields)...))
	case errors.As(err, &format):
		return problem.New(problem.CodeSecretFormatInvalid, problem.WithFieldErrors(secretFields(format.Fields)...))
	case errors.As(err, &duration):
		fe := problem.FieldError{Field: secret.FieldExpiresIn, Code: secret.CodeNotAllowed}
		for _, d := range duration.Allowed {
			fe.Allowed = append(fe.Allowed, d)
		}
		return problem.New(problem.CodeSecretDurationNotOffered, problem.WithFieldErrors(fe))
	case errors.As(err, &tooLarge):
		return problem.New(problem.CodeSecretFileTooLarge, problem.WithMaxTransferBytes(tooLarge.MaxBytes))
	case errors.As(err, &limit):
		if limit.RetryAfter > 0 {
			return problem.New(problem.CodeSecretLimitReached, problem.WithRetryAfter(limit.RetryAfter))
		}
		return problem.New(problem.CodeSecretLimitReached)
	case errors.As(err, &limited):
		return problem.New(problem.CodeRateLimited, problem.WithRetryAfter(limited.RetryAfter))
	case errors.As(err, &gone):
		return problem.New(problem.CodeSecretGone, problem.WithReason(gone.Reason))
	case errors.As(err, &proof):
		if proof.Counted {
			return problem.New(problem.CodeSecretProofInvalid, problem.WithAttemptsRemaining(proof.Remaining))
		}
		return problem.New(problem.CodeSecretProofInvalid)
	case errors.Is(err, secret.ErrForbidden):
		return problem.New(problem.CodeDepositNotAllowed)
	case errors.Is(err, secret.ErrNotFound):
		return problem.New(problem.CodeNotFound)
	case errors.Is(err, secret.ErrDisabled):
		return problem.New(problem.CodeSecretsDisabled)
	case errors.Is(err, secret.ErrEmailNotAllowed):
		return problem.New(problem.CodeSecretEmailNotAllowed)
	case errors.Is(err, secret.ErrPassphraseRequired):
		return problem.New(problem.CodeSecretPassphraseRequired)
	case errors.Is(err, secret.ErrFileNotAllowed):
		return problem.New(problem.CodeSecretFileNotAllowed)
	case errors.Is(err, secret.ErrConflict):
		return problem.New(problem.CodeStateConflict)
	case errors.Is(err, secret.ErrQuotaExceeded):
		return problem.New(problem.CodeQuotaExceeded)
	case errors.Is(err, secret.ErrRecipientRefused): // a policy refusal, never in the security log
		return problem.New(problem.CodeRecipientDomainRefused,
			problem.WithFieldErrors(problem.FieldError{Field: secret.FieldRecipient, Code: secret.CodeDomainDenied}))
	case errors.Is(err, secret.ErrMailUnavailable):
		return problem.New(problem.CodeMailUnavailable)
	default:
		return err
	}
}

// secretFields converts the field errors of the secret service, with
// their accepted values.
func secretFields(in []secret.FieldError) []problem.FieldError {
	out := make([]problem.FieldError, len(in))
	for i, f := range in {
		out[i] = problem.FieldError{Field: f.Pointer, Code: f.Code}
		for _, v := range f.Allowed {
			out[i].Allowed = append(out[i].Allowed, v)
		}
	}
	return out
}
