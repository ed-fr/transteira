package secret

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/tte2"
)

// Status is what the page of a link needs before the reveal (OpenAPI
// SecretStatus): never anything sealed.
type Status struct {
	// ExpiresAt is the expiry of the active secret.
	ExpiresAt time.Time
	// Passphrase is the public passphrase descriptor, nil without
	// passphrase.
	Passphrase *Passphrase
	// FileSize is the ciphertext size of the file, 0 without file.
	FileSize int64
	// Express marks an express secret (since 2.3): third-party content,
	// which the read page says, with the link to [Service.ReportAbuse].
	Express bool
	// Anonymous marks an express secret created without credential (not
	// with an API token).
	Anonymous bool
}

// Revealed is the content of a revealed secret (OpenAPI SecretRevealed).
type Revealed struct {
	// EncryptedText is the sealed text, as sent at creation.
	EncryptedText string
	// EncryptedMetadata is the sealed file metadata, "" without file.
	EncryptedMetadata string
	// FileGrant is the one-time grant of the file download ("" without
	// file), and FileGrantExpiresAt its end of validity.
	FileGrant          string
	FileGrantExpiresAt time.Time
}

// admit applies the limits of the client ip to a status or reveal call of
// tenant t: the request rate, then the lockout after failures. Each refusal
// is written as rate_limited and returned as a *RateLimitError.
func (s *Service) admit(ctx context.Context, t *tenant.Tenant, ip netip.Addr) (string, error) {
	key := clientKey(ip)
	if ok, retry := s.requests.Allow(key); !ok {
		s.logEvent(ctx, t, ip, securitylog.RateLimited, securitylog.Field{Key: securitylog.KeyScope, Value: ScopeLinkIP})
		return key, &RateLimitError{RetryAfter: retry}
	}
	if locked, retry := s.failures.Locked(key); locked {
		s.logEvent(ctx, t, ip, securitylog.RateLimited, securitylog.Field{Key: securitylog.KeyScope, Value: ScopeLink})
		return key, &RateLimitError{RetryAfter: retry}
	}
	return key, nil
}

// unknown answers a token that matches no secret of the tenant: a
// secret_invalid event, a failure of the client key, and ErrNotFound. A
// token of a pending secret (store.ErrSecretPending) is answered alike,
// without event nor failure.
func (s *Service) unknown(ctx context.Context, t *tenant.Tenant, ip netip.Addr, key string, err error) error {
	if !errors.Is(err, store.ErrSecretPending) {
		s.logEvent(ctx, t, ip, securitylog.SecretInvalid)
		s.failures.Fail(key)
	}
	return ErrNotFound
}

// Status returns the status of the secret of tenant t whose link carries
// token, for the client ip. It consumes nothing. It returns a
// *RateLimitError over the limits of the client, ErrNotFound for an unknown
// token (secret_invalid, counted as a failure of the client), a token of
// another tenant or of a pending secret, ErrExpressDisabled for an express
// secret while the express service is closed to it (see [Service.gate]),
// and a *GoneError for a secret that ended or is past its expiry.
func (s *Service) Status(ctx context.Context, t *tenant.Tenant, ip netip.Addr, token string) (Status, error) {
	key, err := s.admit(ctx, t, ip)
	if err != nil {
		return Status{}, err
	}
	sec, err := s.repo.StatusByToken(ctx, t.ID, token, s.gate(), s.now())
	switch {
	case errors.Is(err, store.ErrNotFound):
		return Status{}, s.unknown(ctx, t, ip, key, err)
	case errors.Is(err, store.ErrExpressClosed):
		return Status{}, ErrExpressDisabled
	case err != nil:
		return Status{}, fmt.Errorf("secret: status: %w", err)
	case sec.State != store.SecretActive:
		return Status{}, &GoneError{Reason: APIReason(sec.EndReason)}
	}
	st := Status{ExpiresAt: sec.ExpiresAt, FileSize: sec.FileSize, Express: sec.Express, Anonymous: sec.Anonymous()}
	if sec.HasPassphrase() {
		st.Passphrase = &Passphrase{
			KDF: tte2.PassphraseKDF, Iterations: sec.KDFIterations,
			Salt: tte2.PassphraseDescriptor{Salt: sec.KDFSalt}.EncodedSalt(),
		}
	}
	return st, nil
}

// Reveal reveals, once, the secret of tenant t whose link carries token,
// for the client ip, with the key proof and the proof of the recipient (64
// lowercase hexadecimal characters each). In order:
//
//   - the limits of the client (*RateLimitError);
//   - the proofs (*ValidationError on FieldKeyProof and FieldProof);
//   - an unknown token: ErrNotFound with secret_invalid and a failure of
//     the client; a pending secret: ErrNotFound alone; an express secret
//     while the express service is closed to it: ErrExpressDisabled (see
//     [Service.gate]); a secret that ended: a *GoneError;
//   - a wrong key proof: a *ProofError not counted against the secret,
//     with secret_proof_invalid (reason key) and a failure of the client;
//   - a wrong proof with a right key proof: counted against the secret,
//     with secret_proof_invalid (reason passphrase) and a failure of the
//     client: a *ProofError with the attempts left, or, at the fifth, a
//     *GoneError with ReasonLocked (audited secret.locked, the content
//     destroyed).
//
// On success the secret is read: its sealed text is returned, the server
// key destroyed, secret.revealed audited and the read receipt sent when
// the creator asked for one (also after the lock). For a secret with a file, the
// sealed file metadata and the one-time grant of [Service.DownloadFile]
// are returned too.
func (s *Service) Reveal(ctx context.Context, t *tenant.Tenant, ip netip.Addr, token, keyProof, proof string) (Revealed, error) {
	key, err := s.admit(ctx, t, ip)
	if err != nil {
		return Revealed{}, err
	}
	var v validator
	kp, pr := decodeProof(&v, FieldKeyProof, keyProof), decodeProof(&v, FieldProof, proof)
	if len(v.errs) > 0 {
		return Revealed{}, &ValidationError{Fields: v.errs}
	}
	out, err := s.repo.Reveal(ctx, t.ID, token, s.gate(), kp, pr, s.now())
	var (
		gone  *store.SecretGoneError
		wrong *store.SecretProofError
	)
	switch {
	case err == nil:
		s.erased(ctx, t, "")
		s.record(ctx, t, audit.Event{
			ActorKind: store.ActorRecipient, Actor: linkActor, IP: ip, Action: audit.ActionSecretRevealed, ObjectID: out.Secret.ID,
		})
		s.usage.SecretRead(t.ID)
		s.receipt(ctx, t, out.Secret, mail.SecretOutcomeRead, out.Secret.ReadAt)
		return Revealed{
			EncryptedText: out.SealedText, EncryptedMetadata: out.FileMetadata,
			FileGrant: out.FileGrant, FileGrantExpiresAt: out.FileGrantExpiresAt,
		}, nil
	case errors.Is(err, store.ErrNotFound):
		return Revealed{}, s.unknown(ctx, t, ip, key, err)
	case errors.Is(err, store.ErrExpressClosed):
		return Revealed{}, ErrExpressDisabled
	case errors.As(err, &gone):
		return Revealed{}, &GoneError{Reason: APIReason(gone.Reason)}
	case errors.Is(err, store.ErrSecretKeyProof):
		s.wrongProof(ctx, t, ip, key, securitylog.ReasonKey)
		return Revealed{}, &ProofError{}
	case errors.As(err, &wrong):
		s.wrongProof(ctx, t, ip, key, securitylog.ReasonPassphrase)
		if wrong.Remaining > 0 {
			return Revealed{}, &ProofError{Counted: true, Remaining: wrong.Remaining}
		}
		// The lock removes the stored file at once (threat model T-355).
		s.erased(ctx, t, wrong.RemovedFile)
		s.record(ctx, t, audit.Event{
			ActorKind: store.ActorRecipient, Actor: linkActor, IP: ip, Action: audit.ActionSecretLocked, ObjectID: wrong.ID,
		})
		s.usage.SecretLocked(t.ID)
		s.lockedReceipt(ctx, t, wrong.ID)
		return Revealed{}, &GoneError{Reason: ReasonLocked}
	}
	return Revealed{}, fmt.Errorf("secret: reveal: %w", err)
}

// gate returns the read gate of the express secrets (since 2.3, threat
// model T-389, decision P90): under the instance kill switch every express
// secret is closed, and the store also closes the anonymous ones of a
// tenant whose anonymous mode is off. A closed secret is answered
// ErrExpressDisabled once its token is found (an unknown token stays
// ErrNotFound first, so the gate is no oracle), whatever its state; nothing
// is consumed, no failure is counted and no security event is written:
// the reader holds a valid link, readable again if the service reopens
// before its expiry. The 2.1 secrets are never closed.
func (s *Service) gate() store.ExpressGate {
	return store.ExpressGate{KillSwitch: s.killSwitch}
}

// wrongProof writes a secret_proof_invalid event with reason and counts a
// failure of the client key.
func (s *Service) wrongProof(ctx context.Context, t *tenant.Tenant, ip netip.Addr, key, reason string) {
	s.logEvent(ctx, t, ip, securitylog.SecretProofInvalid, securitylog.Field{Key: securitylog.KeyReason, Value: reason})
	s.failures.Fail(key)
}

// APIReason returns the API reason of a store end reason: both deletions
// are "deleted" (the actor is in the audit, never in the public answer).
// It is the one mapping shared by the public and the administration
// answers; an unknown reason is "expired".
func APIReason(r store.SecretEndReason) string {
	switch r {
	case store.SecretEndDeletedByCreator, store.SecretEndDeletedByAdmin:
		return ReasonDeleted
	case store.SecretEndRead:
		return ReasonRead
	case store.SecretEndLocked:
		return ReasonLocked
	}
	return ReasonExpired
}
