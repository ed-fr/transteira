package secret

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/storage"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/transfer"
	"github.com/ed-fr/transteira/internal/tte2"
)

// Bounds of a declared file (OpenAPI SecretFileDeclaration).
const (
	// MinFileSize is the smallest ciphertext of a file: a TTE2 header and
	// an empty final chunk.
	MinFileSize = tte2.MinFileSize
	// MaxFileSize is the instance limit of a secret file.
	MaxFileSize = tenant.MaxSecretFileBytes
	// MaxFileMetadataLen bounds the sealed metadata of the file, in
	// characters.
	MaxFileMetadataLen = store.MaxSecretFileMetadataLen
)

// Delivery modes (OpenAPI SecretCreate.delivery).
const (
	DeliveryLink  = string(store.SecretDeliveryLink)
	DeliveryEmail = string(store.SecretDeliveryEmail)
)

// Passphrase is the public descriptor of the passphrase of a secret
// (OpenAPI SecretPassphrase).
type Passphrase struct {
	KDF        string
	Iterations int
	Salt       string
}

// File declares the optional file of a secret (OpenAPI
// SecretFileDeclaration).
type File struct {
	// Size is the ciphertext size, in bytes.
	Size int64
	// EncryptedMetadata is the sealed metadata of the file.
	EncryptedMetadata string
}

// CreateRequest is the body of a creation (OpenAPI SecretCreate). The
// optional members are nil when absent.
type CreateRequest struct {
	EncryptedText string
	Verifier      string
	KeyVerifier   string
	Passphrase    *Passphrase
	ExpiresIn     string
	Delivery      string
	Recipient     *string
	ReadReceipt   bool
	File          *File
	// SenderEmail is mandatory with an API token and refused with a
	// deposit session.
	SenderEmail *string
}

// Created is a new secret (OpenAPI SecretCreated).
type Created struct {
	// ID is the "sec_" identifier.
	ID string
	// Token is the bearer token of the link, shown once.
	Token string
	// State is pending or active.
	State store.SecretState
	// ExpiresAt is set when State is active.
	ExpiresAt time.Time
}

// plan is a validated creation request.
type plan struct {
	sender      string
	verifier    []byte
	keyVerifier []byte
	salt        []byte
	duration    tenant.SecretDuration
	delivery    store.SecretDelivery
	recipient   string
}

// validator collects the field errors of a request.
type validator struct {
	errs []FieldError
}

func (v *validator) add(pointer, code string, allowed ...string) {
	v.errs = append(v.errs, FieldError{Pointer: pointer, Code: code, Allowed: allowed})
}

// Create declares a secret of tenant t for its creator sender (built by the
// HTTP layer from the deposit session or the API token of the request, see
// package doc). In order:
//
//  1. a reply or drop link session is ErrForbidden; a deposit session is
//     checked by Eligibility, then the request validated; an API token's
//     request is validated first (its senderEmail is the address
//     Eligibility checks);
//  2. the schema rules (*ValidationError), then the keyless framing of
//     the sealed values (*FormatError);
//  3. the settings of the tenant: ErrDisabled, ErrEmailNotAllowed for an
//     invited external when the e-mail delivery is off, a *ValidationError
//     on FieldDelivery for an invited external using the link delivery, a
//     *DurationError, ErrEmailNotAllowed, ErrPassphraseRequired,
//     ErrFileNotAllowed, a *FileTooLargeError; then, for an e-mail
//     delivery, the blocklist and the recipient domain rules applied to
//     the recipient (ErrRecipientRefused, see checkRecipient), except for
//     an invited external, whose recipient the store forces to its
//     inviter;
//  4. the store, which counts the creator limits (*LimitError), checks the
//     settings again in its transaction, and, for a declared file, the
//     storage quota of the tenant (ErrQuotaExceeded, reported to
//     Options.OnQuota with refused true, as a refused transfer).
//
// A secret with a file starts pending (its storage name drawn here, see
// [Service.UploadFile]), as does a secret delivered by e-mail. After a
// creation with a file, Options.OnQuota is called with refused false. It
// audits secret.created (and api_token.used for a token), counts it in
// Options.Usage, and reports a secret active at once to Options.Abuse
// (alert only).
func (s *Service) Create(ctx context.Context, t *tenant.Tenant, sender transfer.Sender, req CreateRequest) (Created, error) {
	if sender.Kind == store.DepositorReply || sender.Kind == store.DepositorDropLink {
		return Created{}, ErrForbidden
	}
	token := sender.APITokenID != ""
	var (
		p     plan
		email string
		err   error
	)
	if token {
		if p, err = validate(req, true); err != nil {
			return Created{}, err
		}
		sender.Email = p.sender
	}
	email, err = s.creators.CheckCreator(ctx, t, sender)
	switch {
	case errors.Is(err, transfer.ErrForbidden):
		return Created{}, ErrForbidden
	case err != nil:
		return Created{}, fmt.Errorf("secret: check creator: %w", err)
	}
	if !token {
		if p, err = validate(req, false); err != nil {
			return Created{}, err
		}
	}
	if err := checkFraming(req); err != nil {
		return Created{}, err
	}
	if err := checkSettings(t.Secrets, creatorKind(sender), p, req); err != nil {
		return Created{}, err
	}
	if p.delivery == store.SecretDeliveryEmail && creatorKind(sender) != store.SecretCreatorExternal {
		if err := s.checkRecipient(ctx, t, sender, email, p.recipient); err != nil {
			return Created{}, err
		}
	}
	out, err := s.repo.Create(ctx, t.ID, s.storeInput(sender, email, p, req))
	if errors.Is(err, store.ErrSecretQuotaExceeded) {
		s.onQuota(t.ID, true)
	}
	if err != nil {
		return Created{}, createError(t.Secrets, err)
	}
	if req.File != nil {
		s.onQuota(t.ID, false)
	}
	s.recordCreated(ctx, t, sender, email, out.Secret)
	s.usage.SecretCreated(t.ID, out.Secret.CreatedAt)
	if out.Secret.State == store.SecretActive {
		s.activated(ctx, t, sender, out.Secret)
	}
	return Created{ID: out.Secret.ID, Token: out.Token, State: out.Secret.State, ExpiresAt: out.Secret.ExpiresAt}, nil
}

// storeInput returns the store input of the creation req by sender, whose
// normalized address is email, validated as p.
func (s *Service) storeInput(sender transfer.Sender, email string, p plan, req CreateRequest) store.CreateSecret {
	in := store.CreateSecret{
		CreatorKind: creatorKind(sender), SenderEmail: email, Delivery: p.delivery, RecipientEmail: p.recipient,
		ReadReceipt: req.ReadReceipt, Verifier: p.verifier, KeyVerifier: p.keyVerifier, KDFSalt: p.salt,
		SealedText: req.EncryptedText, Duration: p.duration, Now: s.now(),
	}
	if f := req.File; f != nil {
		in.FileSize, in.FileMetadata, in.FileStorageName = f.Size, f.EncryptedMetadata, storage.NewName()
	}
	switch in.CreatorKind {
	case store.SecretCreatorAPIToken:
		in.APITokenID = sender.APITokenID
	case store.SecretCreatorExternal:
		in.InvitationID = sender.InvitationID
	}
	return in
}

// recordCreated audits the creation of sec: secret.created (actor the
// depositor, or the API token), and api_token.used for a token, whose
// declared sender address is then the actor.
func (s *Service) recordCreated(ctx context.Context, t *tenant.Tenant, sender transfer.Sender, email string, sec store.Secret) {
	ev := audit.Event{
		ActorKind: store.ActorDepositor, Actor: email, IP: sender.ClientIP,
		Action: audit.ActionSecretCreated, ObjectID: sec.ID,
		Details: map[string]any{
			"creatorKind": string(sec.CreatorKind), "delivery": string(sec.Delivery), "hasFile": sec.FileSize > 0,
			"expiresIn": string(sec.Duration), "readReceipt": sec.ReadReceipt,
		},
	}
	if sender.APITokenID != "" {
		ev.ActorKind, ev.Actor = store.ActorAPIToken, sender.APITokenID
	}
	s.record(ctx, t, ev)
	if sender.APITokenID != "" {
		s.record(ctx, t, audit.Event{
			ActorKind: store.ActorDepositor, Actor: email, IP: sender.ClientIP, Action: audit.ActionAPITokenUsed,
			ObjectKind: audit.ObjectAPIToken, ObjectID: sender.APITokenID,
			Details: map[string]any{"object": audit.ObjectSecret, "objectId": sec.ID},
		})
	}
}

// creatorKind returns the creator kind of sender (not a reply or drop link
// sender).
func creatorKind(sender transfer.Sender) store.SecretCreatorKind {
	switch {
	case sender.APITokenID != "":
		return store.SecretCreatorAPIToken
	case sender.Kind == store.DepositorExternal:
		return store.SecretCreatorExternal
	case sender.Kind == store.DepositorInternalRemote:
		return store.SecretCreatorInternalRemote
	}
	return store.SecretCreatorInternal
}

// validate checks req against the rules of the OpenAPI schema, collecting
// every invalid field, and returns the decoded values. token tells whether
// the creator is an API token (senderEmail mandatory) or a deposit session
// (senderEmail refused).
func validate(req CreateRequest, token bool) (plan, error) {
	var (
		v validator
		p plan
	)
	switch t := req.EncryptedText; {
	case t == "":
		v.add(FieldEncryptedText, CodeRequired)
	case len(t) > store.MaxSecretSealedTextLen:
		v.add(FieldEncryptedText, CodeTooLong)
	case len(t) < store.MinSecretSealedTextLen || !isBase64URL(t):
		v.add(FieldEncryptedText, CodeInvalidFormat)
	}
	p.verifier = parseVerifier(&v, FieldVerifier, req.Verifier)
	p.keyVerifier = parseVerifier(&v, FieldKeyVerifier, req.KeyVerifier)
	if d := req.Passphrase; d != nil {
		if d.KDF != tte2.PassphraseKDF {
			v.add(FieldPassphraseKDF, CodeNotAllowed, tte2.PassphraseKDF)
		}
		if d.Iterations != tte2.PassphraseIterations {
			v.add(FieldPassphraseIterations, CodeNotAllowed, fmt.Sprint(tte2.PassphraseIterations))
		}
		salt, err := tte2.DecodePassphraseSalt(d.Salt)
		if err != nil {
			v.add(FieldPassphraseSalt, CodeInvalidFormat)
		}
		p.salt = salt
	}
	switch d := tenant.SecretDuration(req.ExpiresIn); {
	case d == "":
		v.add(FieldExpiresIn, CodeRequired)
	case !d.Valid():
		v.add(FieldExpiresIn, CodeNotAllowed, durationCodes(tenant.AllSecretDurations())...)
	default:
		p.duration = d
	}
	switch req.Delivery {
	case "":
		v.add(FieldDelivery, CodeRequired)
	case DeliveryLink, DeliveryEmail:
		p.delivery = store.SecretDelivery(req.Delivery)
	default:
		v.add(FieldDelivery, CodeNotAllowed, DeliveryLink, DeliveryEmail)
	}
	switch {
	case p.delivery == store.SecretDeliveryLink && req.Recipient != nil:
		v.add(FieldRecipient, CodeNotAllowed)
	case p.delivery == store.SecretDeliveryEmail && (req.Recipient == nil || *req.Recipient == ""):
		v.add(FieldRecipient, CodeRequired)
	case p.delivery == store.SecretDeliveryEmail:
		addr, ok := parseAddress(*req.Recipient)
		if !ok {
			v.add(FieldRecipient, CodeInvalidEmail)
		}
		p.recipient = addr
	}
	if f := req.File; f != nil {
		if f.Size < MinFileSize || f.Size > MaxFileSize {
			v.add(FieldFileSize, CodeNotAllowed)
		}
		switch m := f.EncryptedMetadata; {
		case m == "":
			v.add(FieldFileMetadata, CodeRequired)
		case len(m) > MaxFileMetadataLen:
			v.add(FieldFileMetadata, CodeTooLong)
		case !isBase64URL(m):
			v.add(FieldFileMetadata, CodeInvalidFormat)
		}
	}
	switch {
	case !token && req.SenderEmail != nil:
		v.add(FieldSenderEmail, CodeNotAllowed)
	case token && (req.SenderEmail == nil || *req.SenderEmail == ""):
		v.add(FieldSenderEmail, CodeRequired)
	case token:
		addr, ok := parseAddress(*req.SenderEmail)
		if !ok {
			v.add(FieldSenderEmail, CodeInvalidEmail)
		}
		p.sender = addr
	}
	if len(v.errs) > 0 {
		return plan{}, &ValidationError{Fields: v.errs}
	}
	return p, nil
}

// parseVerifier decodes a verifier: 64 lowercase hexadecimal characters.
func parseVerifier(v *validator, pointer, s string) []byte {
	if s == "" {
		v.add(pointer, CodeRequired)
		return nil
	}
	b, err := tte2.ParseProof(s)
	if err != nil {
		v.add(pointer, CodeInvalidFormat)
	}
	return b
}

// checkFraming applies the keyless checks the schema cannot express to the
// sealed values of a request that passed validate (e2e-format.md 4.1): the
// sealed text (canonical, version byte, not empty without a file) and the
// sealed metadata of the file.
func checkFraming(req CreateRequest) error {
	var v validator
	switch {
	case tte2.CheckSecretFraming(req.EncryptedText) != nil:
		v.add(FieldEncryptedText, CodeInvalidFormat)
	case req.File == nil && tte2.SecretTextIsEmpty(req.EncryptedText):
		v.add(FieldEncryptedText, CodeInvalidFormat)
	}
	if req.File != nil && tte2.CheckMetadataFraming(req.File.EncryptedMetadata) != nil {
		v.add(FieldFileMetadata, CodeInvalidFormat)
	}
	if len(v.errs) > 0 {
		return &FormatError{Fields: v.errs}
	}
	return nil
}

// checkSettings applies the secret settings set of the tenant to a
// creation of kind kind (step 3 of Create).
func checkSettings(set tenant.SecretSettings, kind store.SecretCreatorKind, p plan, req CreateRequest) error {
	email := p.delivery == store.SecretDeliveryEmail
	switch {
	case !set.Enabled:
		return ErrDisabled
	case kind == store.SecretCreatorExternal && !set.EmailAllowed:
		// An invited external can only mail its inviter.
		return ErrEmailNotAllowed
	case kind == store.SecretCreatorExternal && !email:
		return &ValidationError{Fields: []FieldError{{Pointer: FieldDelivery, Code: CodeNotAllowed, Allowed: []string{DeliveryEmail}}}}
	case !set.Durations.Has(p.duration):
		return &DurationError{Allowed: durationCodes(set.Durations.Codes())}
	case email && !set.EmailAllowed:
		return ErrEmailNotAllowed
	case email && set.EmailRequiresPassphrase && p.salt == nil:
		return ErrPassphraseRequired
	case req.File != nil && !set.FileAllowed:
		return ErrFileNotAllowed
	case req.File != nil && req.File.Size > set.FileMaxBytes:
		return &FileTooLargeError{MaxBytes: set.FileMaxBytes}
	}
	return nil
}

// createError maps an error of the store creation, whose settings set
// were read in its transaction.
func createError(set tenant.SecretSettings, err error) error {
	switch {
	case errors.Is(err, store.ErrSecretOpenLimit):
		return &LimitError{}
	case errors.Is(err, store.ErrSecretDailyLimit):
		return &LimitError{RetryAfter: DailyLimitRetryAfter}
	case errors.Is(err, store.ErrSecretsDisabled):
		return ErrDisabled
	case errors.Is(err, store.ErrSecretDurationNotOffered):
		return &DurationError{Allowed: durationCodes(set.Durations.Codes())}
	case errors.Is(err, store.ErrSecretEmailNotAllowed):
		return ErrEmailNotAllowed
	case errors.Is(err, store.ErrSecretPassphraseRequired):
		return ErrPassphraseRequired
	case errors.Is(err, store.ErrSecretFileNotAllowed):
		return ErrFileNotAllowed
	case errors.Is(err, store.ErrSecretFileTooLarge):
		return &FileTooLargeError{MaxBytes: set.FileMaxBytes}
	case errors.Is(err, store.ErrSecretQuotaExceeded):
		return ErrQuotaExceeded
	case errors.Is(err, store.ErrNotFound):
		// The API token was revoked, the invitation deleted or the tenant
		// deletion started since the eligibility check: nothing created.
		return ErrForbidden
	}
	return fmt.Errorf("secret: create: %w", err)
}

// durationCodes returns the codes of ds as strings.
func durationCodes(ds []tenant.SecretDuration) []string {
	out := make([]string, len(ds))
	for i, d := range ds {
		out[i] = string(d)
	}
	return out
}

// parseAddress validates an address with the restricted syntax of
// mail.ParseAddress, then normalizes it like the store (as the transfers
// do: each check refuses what the other accepts).
func parseAddress(raw string) (string, bool) {
	mailbox, err := mail.ParseAddress(strings.TrimSpace(raw))
	if err != nil {
		return "", false
	}
	email, err := store.NormalizeEmail(mailbox)
	return email, err == nil
}

// isBase64URL reports whether s holds base64url characters only (without
// padding).
func isBase64URL(s string) bool {
	for i := range len(s) {
		c := s[i]
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
			return false
		}
	}
	return true
}

// decodeProof decodes a proof of a reveal into its array form.
func decodeProof(v *validator, pointer, s string) [32]byte {
	var out [32]byte
	switch b, err := tte2.ParseProof(s); {
	case s == "":
		v.add(pointer, CodeRequired)
	case err != nil:
		v.add(pointer, CodeInvalidFormat)
	default:
		copy(out[:], b)
	}
	return out
}
