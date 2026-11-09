package secret

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/download"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/transfer"
)

// actorOf returns the creator identity of sender on the creator side
// (data-model-v2.1.md 2.1 "Creator identity"): its API token, or its
// verified address and creator kind. A reply or drop link session owns no
// secret (false).
func actorOf(sender transfer.Sender) (store.SecretActor, bool) {
	switch {
	case sender.Kind == store.DepositorReply || sender.Kind == store.DepositorDropLink:
		return store.SecretActor{}, false
	case sender.APITokenID != "":
		return store.SecretActor{APITokenID: sender.APITokenID}, true
	}
	return store.SecretActor{Email: sender.Email, Kind: creatorKind(sender)}, true
}

// UploadFile stores the file declared at the creation of the pending
// secret secID of tenant t, read from body, for its creator sender: a
// deposit session of the same verified address and creator kind, or the
// same API token (e2e-format.md 4.1). The body is the TTE2 ciphertext of
// the file, checked by the keyless validator while it is streamed and
// encrypted again at rest; it is never scanned by the antivirus. A link
// secret becomes active (its expiry starts now), an e-mail secret stays
// pending until the send call.
//
// It returns ErrNotFound for an unknown secret, another tenant's, another
// creator's, or a reply or drop link sender; ErrConflict for a secret
// that is not pending, has no declared file, has it already or is
// receiving it; a *FormatError (without fields) for a body that is not
// exactly a TTE2 stream of the declared size. After a failed upload the
// partial file is removed and the secret stays pending for a new attempt.
// A link secret activated by the upload is reported to Options.Abuse
// (alert only).
func (s *Service) UploadFile(ctx context.Context, t *tenant.Tenant, sender transfer.Sender, secID string, body io.Reader) (store.Secret, error) {
	actor, ok := actorOf(sender)
	if !ok {
		return store.Secret{}, ErrNotFound
	}
	sec, err := s.repo.UploadFile(ctx, t.ID, secID, actor, s.files, body, s.now)
	if err == nil {
		if sec.State == store.SecretActive {
			s.activated(ctx, t, sender, sec)
		}
		return sec, nil
	}
	if errors.Is(err, store.ErrSecretUploadAborted) {
		// The data key of the failed upload was destroyed, also when the
		// secret changed during the upload (a conflict).
		s.erased(ctx, t, "")
	}
	switch {
	case errors.Is(err, store.ErrSecretState):
		return store.Secret{}, ErrConflict
	case errors.Is(err, store.ErrNotFound):
		return store.Secret{}, ErrNotFound
	case errors.Is(err, store.ErrSecretFileFormat):
		return store.Secret{}, &FormatError{}
	}
	return store.Secret{}, fmt.Errorf("secret: upload file: %w", err)
}

// FileStream streams the file of a revealed secret: the TTE2 ciphertext of
// the creator, which the recipient decrypts with the key of the link. The
// caller reads it, calls Delivered once the whole stream reached the
// client, and always closes it.
type FileStream interface {
	io.ReadCloser
	// Size returns the size of the stream, in bytes.
	Size() int64
	// Delivered ends the one-time grant after a complete download: the
	// file is deleted and its key destroyed, and secret.file_downloaded is
	// audited. When a concurrent download completed first, nothing more
	// happens. A failure is only logged (the grant then expires and the
	// lifecycle task destroys the file).
	Delivered(ctx context.Context)
}

// fileDownload implements FileStream.
type fileDownload struct {
	file    *store.SecretFileDownload
	svc     *Service
	t       *tenant.Tenant
	ip      netip.Addr
	grant   string
	release func()
}

// Read implements io.Reader.
func (d *fileDownload) Read(p []byte) (int, error) { return d.file.Read(p) }

// Close closes the stored file and releases the stream slots.
func (d *fileDownload) Close() error {
	d.release()
	return d.file.Close()
}

// Size implements FileStream.
func (d *fileDownload) Size() int64 { return d.file.Size }

// Delivered implements FileStream.
func (d *fileDownload) Delivered(ctx context.Context) {
	s := d.svc
	ctx = context.WithoutCancel(ctx)
	ended, ok, err := s.repo.CompleteFileDownload(ctx, d.t.ID, d.file.ID, d.grant, s.now())
	if err != nil {
		s.logger.ErrorContext(ctx, "secret: ending a file grant failed",
			slog.String("tenant", d.t.FQDN), slog.String("error", err.Error()))
		return
	}
	if !ok {
		return
	}
	s.erased(ctx, d.t, ended.RemovedFile)
	s.record(ctx, d.t, audit.Event{
		ActorKind: store.ActorRecipient, Actor: linkActor, IP: d.ip, Action: audit.ActionSecretFileDownloaded,
		ObjectID: d.file.ID,
	})
}

// DownloadFile opens, for the client ip, the file of the revealed secret
// of tenant t whose link carries token, with the one-time grant returned
// by the reveal. In order:
//
//   - the limits of the client (*RateLimitError);
//   - a grant that is not "ttg_" and 43 base62 characters: a
//     *ValidationError on FieldGrant;
//   - an unknown token: ErrNotFound with secret_invalid and a failure of
//     the client; a pending secret: ErrNotFound alone;
//   - a secret without grant (no file, downloaded already, grant expired
//     or swept) or a wrong grant: ErrNotFound without security event
//     (the grant has 256 bits and the request limit bounds the attempts,
//     threat model T-359);
//   - the concurrent stream limits of Options.Streams (T-55): a
//     *RateLimitError with the Retry-After of the refusal.
//
// It consumes nothing until [FileStream.Delivered]; closing the stream
// releases its slots.
func (s *Service) DownloadFile(ctx context.Context, t *tenant.Tenant, ip netip.Addr, token, grant string) (FileStream, error) {
	key, err := s.admit(ctx, t, ip)
	if err != nil {
		return nil, err
	}
	if !id.SecretGrantValid(grant) {
		return nil, &ValidationError{Fields: []FieldError{{Pointer: FieldGrant, Code: CodeInvalidFormat}}}
	}
	f, err := s.repo.OpenFile(ctx, t.ID, token, grant, s.files, s.now())
	switch {
	case errors.Is(err, store.ErrSecretGrant):
		return nil, ErrNotFound
	case errors.Is(err, store.ErrNotFound):
		return nil, s.unknown(ctx, t, ip, key, err)
	case err != nil:
		return nil, fmt.Errorf("secret: download file: %w", err)
	}
	release := func() {}
	if s.streams != nil {
		release, err = s.streams.AcquireStream(ctx, t, f.ID, ip)
		var tooMany *download.TooManyStreamsError
		switch {
		case errors.As(err, &tooMany):
			_ = f.Close()
			return nil, &RateLimitError{RetryAfter: tooMany.RetryAfter}
		case err != nil:
			_ = f.Close()
			return nil, fmt.Errorf("secret: download file: %w", err)
		}
	}
	return &fileDownload{file: f, svc: s, t: t, ip: ip, grant: grant, release: release}, nil
}
