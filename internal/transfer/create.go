package transfer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/filename"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/storage"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/textsafe"
)

// Limits of a creation request (OpenAPI TransferCreate and FileDeclaration).
const (
	// MaxMessageRunes bounds the message, after the removal of the control
	// and invisible characters.
	MaxMessageRunes = store.MaxTransferMessageLen
	// MaxPasswordRunes bounds the password, in characters.
	MaxPasswordRunes = 1024
	// MaxFiles bounds the files of a transfer.
	MaxFiles = store.MaxTransferFiles
	// MaxMediaTypeRunes bounds the informational media type of a file.
	MaxMediaTypeRunes = store.MaxMediaTypeLen
	// MaxIdempotencyKeyLen bounds the Idempotency-Key header, in bytes.
	MaxIdempotencyKeyLen = store.MaxIdempotencyKeyLen
)

// sha256HexLen is the length of a SHA-256 in hexadecimal.
const sha256HexLen = 64

// expiryDays are the allowed validities (spec 8.2).
var expiryDays = map[int]bool{1: true, 7: true, 30: true}

// CreateRequest is the body of a creation request (OpenAPI TransferCreate).
type CreateRequest struct {
	// SenderEmail is mandatory with an API token and forbidden with a
	// deposit session. Only the session path exists today: a non-empty
	// value is refused. The API token path (a later step) will add a Sender
	// kind whose address comes from this field, checked against the tenant
	// internal domains, without changing this type.
	SenderEmail string
	// Recipients are the recipient addresses: mandatory for an internal
	// sender, ignored for an external one (the inviter is the recipient).
	Recipients []string
	// Message is the optional plain-text message.
	Message string
	// ExpiryDays is the validity: 1, 7 or 30 days after the finalization.
	ExpiryDays int
	// Password is the optional transfer password; nil for none (an empty
	// password is refused).
	Password *string
	// DeleteAfterFirstDownload deletes the transfer after its first
	// download.
	DeleteAfterFirstDownload bool
	// Language is the language of the mails, "" for the tenant default.
	Language string
	// Files are the declared files.
	Files []FileDeclaration
}

// FileDeclaration declares one file of a transfer (OpenAPI
// FileDeclaration).
type FileDeclaration struct {
	// Name is the original file name (decision P8).
	Name string
	// Size is the size of the file, in bytes.
	Size int64
	// MediaType is the informational media type, "" when unknown.
	MediaType string
	// ExpectedSHA256 is the optional SHA-256 announced by the sender, in
	// hexadecimal (either case).
	ExpectedSHA256 string
}

// plan is a validated creation request.
type plan struct {
	recipients []string
	message    string
	password   []byte
	files      []store.TransferFile
	total      int64
}

// validator collects the field errors of a request.
type validator struct {
	errs []FieldError
}

func (v *validator) add(pointer, code string) {
	v.errs = append(v.errs, FieldError{Pointer: pointer, Code: code})
}

// err returns the *ValidationError of the collected errors, or nil.
func (v *validator) err() error {
	if len(v.errs) == 0 {
		return nil
	}
	return &ValidationError{Fields: v.errs}
}

// validate checks req for a sender of kind kind, collecting every invalid
// field, and returns the normalized plan: recipients (internal senders
// only), sanitized message, NFC file names, lowercase expected SHA-256 and
// the declared total (math.MaxInt64 when it overflows, which no limit
// allows).
func (s *Service) validate(req CreateRequest, kind store.DepositorKind, key string) (plan, error) {
	var (
		v validator
		p plan
	)
	if key != "" && !validIdempotencyKey(key) {
		v.add(FieldIdempotencyKey, CodeInvalidFormat)
	}
	if req.SenderEmail != "" {
		v.add(FieldSenderEmail, CodeNotAllowed)
	}
	if kind == store.DepositorInternal {
		p.recipients = s.validateRecipients(&v, req.Recipients)
	}
	switch {
	case !utf8.ValidString(req.Message):
		v.add(FieldMessage, CodeInvalidFormat)
	case utf8.RuneCountInString(textsafe.SanitizeMessage(req.Message)) > MaxMessageRunes:
		v.add(FieldMessage, CodeTooLong)
	default:
		p.message = textsafe.SanitizeMessage(req.Message)
	}
	if !expiryDays[req.ExpiryDays] {
		v.add(FieldExpiryDays, CodeNotAllowed)
	}
	if pw := req.Password; pw != nil {
		n := utf8.RuneCountInString(*pw)
		switch {
		case n == 0:
			v.add(FieldPassword, CodeRequired)
		case n > MaxPasswordRunes || len(*pw) > crypto.MaxPasswordSize:
			v.add(FieldPassword, CodeTooLong)
		case !utf8.ValidString(*pw):
			v.add(FieldPassword, CodeInvalidFormat)
		default:
			p.password = []byte(*pw)
		}
	}
	if req.Language != "" && !tenant.IsLanguage(req.Language) {
		v.add(FieldLanguage, CodeNotAllowed)
	}
	p.files, p.total = validateFiles(&v, req.Files)
	return p, v.err()
}

// validateRecipients checks the recipients of an internal sender and
// returns them normalized.
func (s *Service) validateRecipients(v *validator, raw []string) []string {
	switch {
	case len(raw) == 0:
		v.add(FieldRecipients, CodeRequired)
		return nil
	case len(raw) > s.maxRecipients:
		v.add(FieldRecipients, CodeTooMany)
		return nil
	}
	out := make([]string, 0, len(raw))
	seen := make(map[string]bool, len(raw))
	for i, r := range raw {
		pointer := FieldRecipients + "/" + strconv.Itoa(i)
		email, ok := parseRecipient(r)
		switch {
		case !ok:
			v.add(pointer, CodeInvalidEmail)
		case seen[email]:
			v.add(pointer, CodeDuplicate)
		default:
			seen[email] = true
			out = append(out, email)
		}
	}
	return out
}

// parseRecipient validates a recipient address with the restricted syntax
// of mail.ParseAddress (threat T-80), then normalizes it like the store.
// Both checks run because each one refuses what the other accepts.
func parseRecipient(raw string) (string, bool) {
	mailbox, err := mail.ParseAddress(strings.TrimSpace(raw))
	if err != nil {
		return "", false
	}
	email, err := store.NormalizeEmail(mailbox)
	return email, err == nil
}

// validateFiles checks the file declarations and returns them as store
// files (without identifiers or keys) with the declared total.
func validateFiles(v *validator, decls []FileDeclaration) ([]store.TransferFile, int64) {
	switch {
	case len(decls) == 0:
		v.add(FieldFiles, CodeRequired)
		return nil, 0
	case len(decls) > MaxFiles:
		v.add(FieldFiles, CodeTooMany)
		return nil, 0
	}
	files := make([]store.TransferFile, len(decls))
	var total int64
	for i, d := range decls {
		pointer := FieldFiles + "/" + strconv.Itoa(i) + "/"
		name, err := filename.Validate(d.Name)
		if err != nil {
			v.add(pointer+"name", CodeInvalidFileName)
		}
		if d.Size < 0 {
			v.add(pointer+"size", CodeInvalidFormat)
		} else {
			total = addCapped(total, d.Size)
		}
		if !validMediaType(d.MediaType) {
			v.add(pointer+"mediaType", CodeInvalidFormat)
		}
		sum := strings.ToLower(d.ExpectedSHA256)
		if sum != "" && (len(sum) != sha256HexLen || strings.Trim(sum, "0123456789abcdef") != "") {
			v.add(pointer+"expectedSha256", CodeInvalidFormat)
		}
		files[i] = store.TransferFile{Name: name, Size: d.Size, MediaType: d.MediaType, ExpectedSHA256: sum}
	}
	return files, total
}

// addCapped returns a + b (both >= 0), capped at math.MaxInt64.
func addCapped(a, b int64) int64 {
	if b > math.MaxInt64-a {
		return math.MaxInt64
	}
	return a + b
}

// validMediaType reports whether m is a single line of valid UTF-8 of at
// most MaxMediaTypeRunes characters, the rule of the store.
func validMediaType(m string) bool {
	return utf8.ValidString(m) && utf8.RuneCountInString(m) <= MaxMediaTypeRunes &&
		!strings.ContainsFunc(m, func(r rune) bool { return textsafe.IsControl(r) || textsafe.IsLineSeparator(r) })
}

// validIdempotencyKey reports whether k holds 1 to MaxIdempotencyKeyLen
// visible ASCII characters, the rule of the store.
func validIdempotencyKey(k string) bool {
	if k == "" || len(k) > MaxIdempotencyKeyLen {
		return false
	}
	for i := range len(k) {
		if k[i] < 0x21 || k[i] > 0x7e {
			return false
		}
	}
	return true
}

// Sentinels aborting the creation transaction.
var (
	errQuota   = errors.New("transfer: quota reached")
	errOpenCap = errors.New("transfer: open transfer cap reached")
)

// scopeOpenTransfers is the security log scope of the open transfer cap.
const scopeOpenTransfers = "open_transfers"

// fingerprint returns the SHA-256, in lowercase hexadecimal, of the
// canonical form of a validated request, kept with its idempotency key: the
// sorted normalized recipients, the sanitized message, the validity, the
// presence of a password (never its value), the deletion option, the
// language and the files in order (NFC name, size, media type, lowercase
// expected SHA-256).
func fingerprint(p plan, req CreateRequest) string {
	type file struct {
		Name      string `json:"n"`
		Size      int64  `json:"s"`
		MediaType string `json:"m"`
		SHA256    string `json:"h"`
	}
	canonical := struct {
		Recipients []string `json:"r"`
		Message    string   `json:"m"`
		ExpiryDays int      `json:"e"`
		Password   bool     `json:"p"`
		Delete     bool     `json:"d"`
		Language   string   `json:"l"`
		Files      []file   `json:"f"`
	}{
		Recipients: slices.Sorted(slices.Values(p.recipients)), Message: p.message, ExpiryDays: req.ExpiryDays,
		Password: p.password != nil, Delete: req.DeleteAfterFirstDownload, Language: req.Language,
		Files: make([]file, len(p.files)),
	}
	for i, f := range p.files {
		canonical.Files[i] = file{Name: f.Name, Size: f.Size, MediaType: f.MediaType, SHA256: f.ExpectedSHA256}
	}
	b, _ := json.Marshal(canonical) //nolint:errchkjson // strings, integers and booleans only: it cannot fail
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Create declares a transfer and its files for sender (OpenAPI
// createTransfer) and returns it with one upload identifier per file.
// idempotencyKey is the optional Idempotency-Key header.
//
// Steps, in order:
//
//  1. eligibility, checked again (threat T-25): blocklist (address and
//     domain), internal rule from the current client IP for an internal
//     sender, active invitation for an external one; ErrForbidden, logged
//     as deposit_refused;
//  2. validation of every field (*ValidationError): the recipients of an
//     external sender are ignored and replaced by the inviter (T-17);
//  3. per-transfer limit of the tenant (*TooLargeError);
//  4. with an idempotency key, a transfer the same sender created with it
//     in the last store.IdempotencyRetention is returned as is, provided
//     the request has the same fingerprint (see fingerprint);
//     ErrIdempotencyMismatch otherwise;
//  5. the password is hashed with argon2id (bounded concurrency, T-125),
//     before the transaction so that the lock is not held meanwhile; its
//     plaintext bytes are cleared afterwards;
//  6. in one transaction, under the tenant lock: the cap on the unfinished
//     transfers of the sender (Options.MaxOpenTransfers for an internal
//     sender, MaxOpenTransfersExternal for an external one; until the
//     cleanup job exists, nothing else frees the quota held by a transfer
//     that is never uploaded): *RateLimitError, logged as rate_limited
//     with scope open_transfers; the quota check (a total exactly at the
//     quota fits; ErrQuotaExceeded otherwise, T-124); a data key per file
//     (decision P6); the rows.
//
// After the commit, Options.OnQuota is called (refused false) and the
// transfer.created audit event is recorded (best effort); a quota refusal
// calls Options.OnQuota with refused true. A replayed request does neither.
// The client IP is stored as the sender IP of the transfer.
//
// A zero-length file is completed after the commit: the upload engine
// writes its encrypted form and the store records its completion. If that
// fails, the failure is logged and the file stays incomplete (it is
// returned with offset 0 and its upload identifier): the upload engine
// completes it on the first empty PATCH, and until then the finalization
// answers ErrIncomplete.
func (s *Service) Create(ctx context.Context, t *tenant.Tenant, sender Sender, req CreateRequest, idempotencyKey string) (Details, error) {
	email, inv, err := s.checkEligible(ctx, t, sender)
	if err != nil {
		return Details{}, err
	}
	p, err := s.validate(req, sender.Kind, idempotencyKey)
	defer clear(p.password) // the paths that return before hashing
	if err != nil {
		return Details{}, err
	}
	if sender.Kind == store.DepositorExternal {
		p.recipients = []string{inv.InvitedBy}
	}
	limits, err := s.repo.tenant(ctx, t.ID)
	if err != nil {
		return Details{}, fmt.Errorf("transfer: read tenant: %w", err)
	}
	if p.total > limits.MaxTransferBytes {
		return Details{}, &TooLargeError{MaxTransferBytes: limits.MaxTransferBytes}
	}
	var fp string
	if idempotencyKey != "" {
		fp = fingerprint(p, req)
		if d, ok, err := s.replay(ctx, t, sender, email, idempotencyKey, fp); ok || err != nil {
			return d, err
		}
	}
	var hash string
	if p.password != nil {
		hash, err = s.hasher.HashPassword(ctx, p.password)
		clear(p.password) // the plaintext is not needed any more
		if err != nil {
			return Details{}, fmt.Errorf("transfer: hash password: %w", err)
		}
	}
	trfID, err := s.prepare(&p)
	if err != nil {
		return Details{}, err
	}
	now := s.now()
	rec := store.Transfer{
		ID: trfID, SenderEmail: email, SenderKind: sender.Kind, InvitationID: sender.InvitationID,
		Message: p.message, Language: req.Language, ExpiryDays: req.ExpiryDays, PasswordHash: hash,
		DeleteAfterFirstDownload: req.DeleteAfterFirstDownload, IdempotencyKey: idempotencyKey,
		RequestFingerprint: fp, CreatedAt: now, SenderIP: sender.ClientIP,
	}
	deks := make([][]byte, len(p.files))
	defer func() {
		for _, k := range deks {
			clear(k)
		}
	}()
	err = s.repo.tx(ctx, t.ID, func(tx txRepo) error {
		used, err := tx.usedBytes(ctx)
		if err != nil {
			return err
		}
		if err := s.checkOpenCap(ctx, t.ID, tx, sender, email, now); err != nil {
			return err
		}
		if p.total > limits.StorageQuotaBytes-used {
			return errQuota
		}
		for i := range p.files {
			wk, dek, err := tx.newDEK(ctx)
			if err != nil {
				return err
			}
			p.files[i].DEKKeyID, deks[i] = wk, dek
		}
		return tx.createTransfer(ctx, rec, p.recipients, p.files)
	})
	// With a key, store.ErrConflict means that a concurrent request with
	// the same key committed first. Any other store.ErrConflict (an
	// identifier, upload identifier or storage name collision, of
	// probability about 2^-128) falls through to the internal error below
	// and answers 500: intended, the client simply retries.
	if errors.Is(err, store.ErrConflict) && idempotencyKey != "" {
		if d, ok, rerr := s.replay(ctx, t, sender, email, idempotencyKey, fp); ok || rerr != nil {
			return d, rerr
		}
	}
	switch {
	case errors.Is(err, errOpenCap):
		s.logEvent(ctx, t, sender.ClientIP, securitylog.RateLimited,
			securitylog.Field{Key: securitylog.KeyScope, Value: scopeOpenTransfers})
		return Details{}, &RateLimitError{RetryAfter: OpenTransfersRetryAfter}
	case errors.Is(err, errQuota):
		s.onQuota(t.ID, true)
		return Details{}, ErrQuotaExceeded
	case errors.Is(err, store.ErrNotFound):
		// The tenant's deletion started after its resolution (or the
		// invitation was deleted meanwhile): nothing was created.
		return Details{}, ErrForbidden
	case err != nil:
		return Details{}, fmt.Errorf("transfer: create transfer: %w", err)
	}
	s.onQuota(t.ID, false)
	s.record(ctx, t, sender, email, audit.ActionTransferCreated, trfID,
		map[string]any{"fileCount": len(p.files), "totalBytes": p.total, "origin": origin(sender)})
	s.completeEmpty(ctx, t, p.files, deks, now)
	d, err := s.repo.transfer(ctx, t.ID, trfID)
	if err != nil {
		return Details{}, fmt.Errorf("transfer: read created transfer: %w", err)
	}
	return s.details(ctx, t, d)
}

// checkOpenCap refuses a new transfer of sender (normalized address email)
// when it already has as many unfinished transfers as its cap, inside the
// creation transaction (under the tenant lock). Transfers created more
// than Options.UploadMaxAge ago are expired and never counted. When the
// count reaches the cap, the recent ones are examined (at most
// maxOpenScan, newest first) and those whose uploads expired, according to
// the upload engine, are ignored: with no cleanup job yet, a sender who
// abandoned transfers is not locked out. A transfer refused at
// finalization for a blocked file is not expired and still counts; the
// sender can cancel it.
func (s *Service) checkOpenCap(ctx context.Context, tid tenant.ID, tx txRepo, sender Sender, email string, now time.Time) error {
	limit, since := s.openCap(sender), now.Add(-s.uploadMaxAge)
	open, err := tx.countUploading(ctx, email, since)
	if err != nil || open < limit {
		return err
	}
	list, err := tx.listUploading(ctx, email, since, maxOpenScan)
	if err != nil {
		return err
	}
	active := open - len(list) // beyond the scan: counted as active
	for _, tr := range list {
		files, err := tx.listFiles(ctx, tr.ID)
		if err != nil {
			return err
		}
		_, expires, err := s.uploads.TransferActivity(ctx, tid, files, tr.CreatedAt)
		if err != nil {
			return err
		}
		if now.Before(expires) {
			active++
		}
	}
	if active >= limit {
		return errOpenCap
	}
	return nil
}

// prepare draws the transfer identifier and, for each file, its identifier,
// its upload identifier and its storage name.
func (s *Service) prepare(p *plan) (string, error) {
	trfID, err := s.newID(id.Transfer)
	if err != nil {
		return "", fmt.Errorf("transfer: new transfer id: %w", err)
	}
	for i := range p.files {
		f := &p.files[i]
		if f.ID, err = s.newID(id.File); err != nil {
			return "", fmt.Errorf("transfer: new file id: %w", err)
		}
		if f.UploadID, err = s.newUploadID(); err != nil {
			return "", fmt.Errorf("transfer: new upload id: %w", err)
		}
		f.StorageName = storage.NewName()
	}
	return trfID, nil
}

// completeEmpty writes and completes the zero-length files of a new
// transfer. A failure is logged: the file stays incomplete.
func (s *Service) completeEmpty(ctx context.Context, t *tenant.Tenant, files []store.TransferFile, deks [][]byte, now time.Time) {
	for i, f := range files {
		if f.Size != 0 {
			continue
		}
		sum, size, err := s.uploads.WriteEmpty(ctx, t.ID, f.ID, deks[i], f.StorageName)
		if err == nil {
			err = s.repo.completeUpload(ctx, t.ID, f.ID, sum, size, now)
		}
		if err != nil {
			s.logger.ErrorContext(ctx, "transfer: completing an empty file failed",
				slog.String("tenant", t.FQDN), slog.String("file", f.ID), slog.String("error", err.Error()))
		}
	}
}

// replay returns the transfer that sender (whose normalized address is
// email) created with key in the last store.IdempotencyRetention, with ok
// true, or ok false when there is none. The same address under another
// invitation gets ErrConflict, and a request whose fingerprint fp differs
// from the recorded one ErrIdempotencyMismatch.
func (s *Service) replay(ctx context.Context, t *tenant.Tenant, sender Sender, email, key, fp string) (Details, bool, error) {
	d, err := s.repo.transferByKey(ctx, t.ID, email, key, s.now().Add(-store.IdempotencyRetention))
	switch {
	case errors.Is(err, store.ErrNotFound):
		return Details{}, false, nil
	case err != nil:
		return Details{}, false, fmt.Errorf("transfer: read transfer by idempotency key: %w", err)
	case !sender.Owns(d.Transfer):
		return Details{}, false, ErrConflict
	case d.RequestFingerprint != fp:
		return Details{}, false, ErrIdempotencyMismatch
	}
	out, err := s.details(ctx, t, d)
	return out, true, err
}
