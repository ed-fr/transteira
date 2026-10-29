package download

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/i18n"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/notify"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/vcode"
)

// Recipient verification cookie (OpenAPI security scheme
// recipientVerification): the browser proof that the recipient of a link
// entered the code sent to its address (spec 10, threat model T-200,
// T-204). It has the layout of the grant cookie (see [entryCookie]), its
// entries bound by a MAC of their own purpose to a recipient link, a tenant
// and an expiry.
const (
	// VerificationCookieName is the name of the cookie. The __Host- prefix
	// requires Secure, Path=/ and no Domain attribute; the HTTP layer also
	// sets HttpOnly and SameSite=Strict.
	VerificationCookieName = "__Host-tt_rv"
	// VerificationCookiePrefix starts the cookie value.
	VerificationCookiePrefix = "rv_"
	// VerificationTTL is the lifetime of an entry, and the Max-Age of the
	// cookie (3600 seconds); it equals GrantTTL.
	VerificationTTL = GrantTTL
)

// Security log values of the recipient codes.
const (
	// scopeCodesPerLink names the budget of codes per recipient link (and
	// so per address) in the rate_limited events.
	scopeCodesPerLink = "verification_link"
	// scopeCodesPerIP names the budget of codes per client IP, shared with
	// the deposit codes.
	scopeCodesPerIP = "verification_ip"
	// maskedLocal replaces the local part of an address after its first
	// character.
	maskedLocal = "***"
)

// verificationSpec is the recipient verification cookie.
var verificationSpec = entryCookie{
	prefix: VerificationCookiePrefix, purpose: crypto.MACPurposeRecipientVerification, what: "verification cookie",
}

// parseVerifications decodes the raw value of the verification cookie (see
// [entryCookie.parse]).
func parseVerifications(raw string) [][]byte { return verificationSpec.parse(raw) }

// Challenge is a recipient code sent by mail (OpenAPI
// RecipientVerificationChallenge).
type Challenge struct {
	// EmailMasked is the masked address the code was sent to.
	EmailMasked string
	// ExpiresAt is the end of validity of the code.
	ExpiresAt time.Time
	// AttemptsRemaining is the number of wrong codes still tolerated.
	AttemptsRemaining int
}

// MaskEmail returns the masked form of a mail address shown to the holder
// of a recipient link: its first character, "***", then the domain
// ("c***@customer.example.net"). An input without "@" is masked whole.
func MaskEmail(addr string) string {
	local, domain, ok := strings.Cut(addr, "@")
	if !ok {
		return maskedLocal
	}
	r, size := utf8.DecodeRuneInString(local)
	if size == 0 || r == utf8.RuneError {
		return maskedLocal + "@" + domain
	}
	return string(r) + maskedLocal + "@" + domain
}

// StartVerification sends a verification code to the recipient of the link
// rawToken of tenant t (startRecipientVerification), requested from the
// client IP clientIP. reply tells a verification before a reply (purpose
// reply). acceptLanguage, an Accept-Language value or the exact language
// the client asked for, chooses the language of the mail (else the default
// language of the tenant). verificationCookie is the raw value of the
// VerificationCookieName cookie, "" when absent.
//
// A download verification (reply false) is for a recipient link whose
// transfer has the recipient verification option. A reply verification is
// for any link the recipient may reply through (see [Service.ReplyAccess]),
// with or without the option: replying always requires the code (threat
// model P33). The challenge records the intent; [Service.ConfirmVerification]
// accepts either, and both give the same cookie entry.
//
// The code goes to the address of the link only, never to an address of
// the request. It is valid vcode.TTL with store.MaxChallengeAttempts
// attempts; requesting a new code replaces the previous one. The budgets
// are counted in the transaction that stores the challenge, after the
// tenant lock: vcode.MaxPerAddress codes per link (so per address and
// link, whatever the intent) and vcode.MaxPerIP codes per client IP, the
// latter shared with the deposit codes, per vcode.Window. The mail is queued
// after the commit; when the queue refuses it, the challenge is deleted,
// best effort, so that a code nobody received neither stays usable nor
// counts against the budgets.
//
// It returns a nil *Challenge, without error, when the browser already
// holds a valid entry of the link (nothing is sent). Errors: ErrNotFound,
// ErrGone and ErrMaxDownloads as Resolve does, for a reply too (no code is
// sent for a link that cannot start a download any more: such a transfer
// cannot be replied to either); ErrVerificationNotNeeded for a download
// verification on a shared link or a transfer without the option;
// ErrReplyNotAllowed for a reply verification on a link that cannot be
// replied to (the blocklist is left to ReplyAccess); ErrNoClientIP for an
// invalid clientIP; a *RateLimitError (ErrRateLimited) over a budget,
// written to the security log, or when the mail queue is full;
// ErrMailUnavailable when the tenant cannot send mail.
func (s *Service) StartVerification(ctx context.Context, t *tenant.Tenant, rawToken string, clientIP netip.Addr, reply bool, acceptLanguage, verificationCookie string) (*Challenge, error) {
	a, err := s.resolve(ctx, t, rawToken, Cookies{Verification: verificationCookie}, true)
	if err != nil {
		return nil, err
	}
	intent, held := store.IntentDownload, a.verified
	switch {
	case reply:
		ok, err := s.replyEligible(ctx, t.ID, a.d, a.link)
		switch {
		case err != nil:
			return nil, err
		case !ok:
			return nil, ErrReplyNotAllowed
		}
		intent = store.IntentReply
		if !a.verify {
			// resolve only reads the cookie for a transfer with the option.
			if held, err = s.holds(verificationSpec, verificationCookie, t.ID, a.link.ID, s.now()); err != nil {
				return nil, err
			}
		}
	case !a.verify:
		return nil, ErrVerificationNotNeeded
	}
	switch {
	case held:
		return nil, nil
	case !clientIP.IsValid():
		return nil, ErrNoClientIP
	}
	code, err := vcode.New(s.rand)
	if err != nil {
		return nil, fmt.Errorf("download: %w", err)
	}
	tr := notify.ViewOf(a.d)
	tr.Language = i18n.Negotiate(acceptLanguage, t.DefaultLanguage)
	job, err := s.notifier.RecipientVerificationCode(ctx, t, tr, a.link.Email, code)
	switch {
	case errors.Is(err, notify.ErrNoSMTP):
		return nil, fmt.Errorf("%w: %w", ErrMailUnavailable, err)
	case err != nil:
		return nil, fmt.Errorf("download: build verification mail: %w", err)
	}
	now := s.now()
	ch, err := s.storeChallenge(ctx, t, a, intent, clientIP, code, now)
	if err != nil {
		return nil, err
	}
	if err := s.enqueue(job); err != nil {
		if derr := s.repo.deleteChallenge(context.WithoutCancel(ctx), t.ID, ch.ID); derr != nil {
			s.log(ctx, slog.LevelError, "unsent verification challenge not discarded", t.ID, a.d.ID, slog.Any("error", derr))
		}
		return nil, err
	}
	return &Challenge{EmailMasked: MaskEmail(a.link.Email), ExpiresAt: ch.ExpiresAt, AttemptsRemaining: ch.AttemptsRemaining}, nil
}

// storeChallenge stores the challenge of code with intent for the
// recipient link of a, requested from clientIP at now, under a new random
// identifier. Over a budget it writes a rate_limited event and returns a
// *RateLimitError.
func (s *Service) storeChallenge(ctx context.Context, t *tenant.Tenant, a access, intent store.RecipientIntent, clientIP netip.Addr, code string, now time.Time) (store.Challenge, error) {
	chID, err := s.newToken(id.ChallengeTokenPrefix, id.ChallengeTokenBytes)
	if err != nil {
		return store.Challenge{}, fmt.Errorf("download: new challenge id: %w", err)
	}
	mac, err := s.keys.MAC(crypto.MACPurposeOTP, []byte(chID), []byte(code))
	if err != nil {
		return store.Challenge{}, fmt.Errorf("download: compute code mac: %w", err)
	}
	ch := store.Challenge{
		ID: chID, Email: a.link.Email, CodeMAC: mac, AttemptsRemaining: store.MaxChallengeAttempts,
		ClientIP: clientIP, CreatedAt: now, ExpiresAt: now.Add(vcode.TTL),
		Purpose: store.ChallengeRecipient, RecipientLinkID: a.link.ID, RecipientIntent: intent,
	}
	scope, err := s.repo.createChallenge(ctx, t.ID, ch, now.Add(-vcode.Window))
	switch {
	case err == nil:
		return ch, nil
	case !errors.Is(err, errLimited):
		return store.Challenge{}, fmt.Errorf("download: create challenge: %w", err)
	}
	s.logEvent(ctx, t, clientIP, a.d.ID, securitylog.RateLimited, securitylog.Field{Key: securitylog.KeyScope, Value: scope})
	return store.Challenge{}, &RateLimitError{RetryAfter: vcode.Window}
}

// enqueue queues the mail of a code, mapping the refusals of the queue.
func (s *Service) enqueue(job mail.Job) error {
	err := s.queue.Enqueue(job)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, mail.ErrQueueFull):
		return &RateLimitError{RetryAfter: vcode.QueueFullRetryAfter}
	case errors.Is(err, mail.ErrQueueClosed), errors.Is(err, mail.ErrInvalidSettings), errors.Is(err, mail.ErrCircuitOpen):
		return fmt.Errorf("%w: %w", ErrMailUnavailable, err)
	}
	return fmt.Errorf("download: queue verification mail: %w", err)
}

// ConfirmVerification checks the code entered by the recipient of the link
// rawToken of tenant t (confirmRecipientVerification), from the client IP
// clientIP. verificationCookie is the raw value of the
// VerificationCookieName cookie, "" when absent.
//
// The code is checked against the most recent code of the link only
// (store.Challenges.LatestByLink), by a constant-time MAC comparison,
// whatever its intent (download or reply): both prove the mailbox of the
// link and open the page, the files and the reply. On a link whose transfer
// does not have the recipient verification option, only a reply code is
// accepted, and only while the link may be replied to. On success the code
// is consumed, the link marked verified and the recipient.verified audit
// event recorded (detail intent "reply" for a reply code), in one
// transaction, so that concurrent confirmations cannot both succeed; it
// returns the new value of the cookie, with a new entry of the link valid
// VerificationTTL (the other live entries kept). Every wrong code spends an
// attempt and writes a verification_code_invalid event with purpose
// "recipient" to the security log (never the code).
//
// Errors: ErrInvalidCode for a code that is not 6 digits and ErrNoClientIP
// for an invalid clientIP (no attempt spent); ErrNotFound and ErrGone as
// Resolve does; ErrVerificationNotNeeded for a shared link, or a link
// without the option that cannot be replied to; ErrNoChallenge when no code
// is pending (never requested, used or expired, or a download code on a link
// without the option); ErrVerificationExhausted when the code is exhausted,
// including by this wrong code; a *WrongCodeError (ErrWrongCode) for a wrong
// code while attempts remain.
func (s *Service) ConfirmVerification(ctx context.Context, t *tenant.Tenant, rawToken string, clientIP netip.Addr, code, verificationCookie string) (string, error) {
	if !vcode.Valid(code) {
		return "", ErrInvalidCode
	}
	if !clientIP.IsValid() {
		return "", ErrNoClientIP
	}
	a, err := s.resolve(ctx, t, rawToken, Cookies{Verification: verificationCookie}, false)
	if err != nil {
		return "", err
	}
	replyOnly := !a.verify
	if replyOnly {
		ok, err := s.replyEligible(ctx, t.ID, a.d, a.link)
		switch {
		case err != nil:
			return "", err
		case !ok:
			return "", ErrVerificationNotNeeded
		}
	}
	// The newest code of the link only: a new code replaces the previous
	// ones, whatever their intent.
	ch, err := s.repo.latestChallenge(ctx, t.ID, a.link.ID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return "", ErrNoChallenge
	case err != nil:
		return "", fmt.Errorf("download: read challenge: %w", err)
	}
	now := s.now()
	switch {
	case replyOnly && ch.RecipientIntent != store.IntentReply, !ch.ConsumedAt.IsZero(), !now.Before(ch.ExpiresAt):
		return "", ErrNoChallenge
	case ch.AttemptsRemaining <= 0:
		return "", ErrVerificationExhausted
	}
	valid, err := s.keys.VerifyMAC(crypto.MACPurposeOTP, ch.CodeMAC, []byte(ch.ID), []byte(code))
	if err != nil {
		return "", fmt.Errorf("download: verify code: %w", err)
	}
	if !valid {
		return "", s.wrongCode(ctx, t, clientIP, a.d.ID, ch.ID, now)
	}
	details := map[string]any{"link": a.link.ID}
	if ch.RecipientIntent == store.IntentReply {
		details["intent"] = string(store.IntentReply)
	}
	ev := audit.Event{
		ActorKind: store.ActorRecipient, Actor: a.link.Email, IP: clientIP,
		Action: audit.ActionRecipientVerified, ObjectKind: audit.ObjectTransfer, ObjectID: a.d.ID,
		Details: details,
	}
	err = s.repo.verified(ctx, t.ID, ch.ID, a.link.ID, now, ev)
	switch {
	case errors.Is(err, store.ErrNotFound):
		// Consumed, exhausted or expired concurrently.
		return "", ErrNoChallenge
	case err != nil:
		return "", fmt.Errorf("download: record verification: %w", err)
	}
	return s.add(verificationSpec, verificationCookie, t.ID, a.link.ID, now)
}

// wrongCode spends one attempt of the challenge chID of the transfer
// trfID, logs the failure (never the code) and returns the error to
// answer.
func (s *Service) wrongCode(ctx context.Context, t *tenant.Tenant, ip netip.Addr, trfID, chID string, now time.Time) error {
	s.logEvent(ctx, t, ip, trfID, securitylog.VerificationCodeInvalid,
		securitylog.Field{Key: securitylog.KeyPurpose, Value: securitylog.PurposeRecipient})
	remaining, err := s.repo.spend(ctx, t.ID, chID, now)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return ErrVerificationExhausted // spent, consumed or expired concurrently
	case err != nil:
		return fmt.Errorf("download: spend attempt: %w", err)
	case remaining == 0:
		return ErrVerificationExhausted
	}
	return &WrongCodeError{Remaining: remaining}
}
