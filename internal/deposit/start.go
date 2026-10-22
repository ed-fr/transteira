package deposit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/i18n"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Challenge is a verification code sent by mail (OpenAPI
// VerificationChallenge).
type Challenge struct {
	// ID identifies the challenge in the confirmation URL.
	ID string
	// Email is the address the code was sent to, normalized.
	Email string
	// ExpiresAt is the end of validity of the code.
	ExpiresAt time.Time
	// AttemptsRemaining is the number of wrong codes still tolerated.
	AttemptsRemaining int
}

// Result is the outcome of [Service.Start]: exactly one of Session (an
// internal depositor recognized by this browser, 201) and Challenge (a code
// was sent, 202) is set.
type Result struct {
	// Session is the new session of a recognized internal depositor.
	Session *Session
	// Challenge is the code sent otherwise.
	Challenge *Challenge
}

// Start identifies a depositor of tenant t by email address (OpenAPI
// startDepositSession), from clientIP, the real client IP. invitationToken
// is the token of an invitation link, or "" for an internal depositor.
// acceptLanguage is the Accept-Language header, choosing the language of
// the code mail. recognition is the raw value of the RecognitionCookie
// cookie sent by the browser, "" when absent; it is parsed defensively.
//
// A code is always sent, except to an internal depositor (no invitation)
// whose address is verified and still active for the tenant AND whose
// browser presents the recognition cookie entry of that address: the
// session then opens at once and Session.Recognition carries the renewed
// cookie value. An invitation-based depositor always gets a code, even when
// verified, so that a forwarded invitation link opens nothing by itself.
//
// Errors: *InvalidError (ErrInvalid) for a malformed address; ErrForbidden
// when the depositor is not eligible; ErrInvitationGone for an expired or
// revoked invitation; *RateLimitError (ErrRateLimited) when too many codes
// were requested or the mail queue is full; ErrMailUnavailable when the
// tenant cannot send mail.
func (s *Service) Start(ctx context.Context, t *tenant.Tenant, clientIP netip.Addr, acceptLanguage, email, invitationToken, recognition string) (Result, error) {
	addr, err := parseEmail(email)
	if err != nil {
		return Result{}, err
	}
	if !clientIP.IsValid() {
		// Without a client IP neither the network rule nor the per-IP
		// limit can apply: fail closed.
		return Result{}, s.refuse(ctx, t, clientIP, securitylog.ReasonIP)
	}
	if err := s.checkBlocklist(ctx, t, clientIP, addr.normalized); err != nil {
		return Result{}, err
	}
	var inv *store.Invitation
	if invitationToken != "" {
		found, err := s.checkInvitation(ctx, t, clientIP, invitationToken, addr.normalized)
		if err != nil {
			return Result{}, err
		}
		inv = &found
	} else if err := s.checkInternal(ctx, t, clientIP, addr.normalized); err != nil {
		return Result{}, err
	}

	if inv == nil {
		sess, ok, err := s.recognized(ctx, t, addr.normalized, recognition)
		if err != nil {
			return Result{}, err
		}
		if ok {
			return Result{Session: &sess}, nil
		}
	}
	ch, err := s.sendCode(ctx, t, clientIP, acceptLanguage, addr, inv)
	if err != nil {
		return Result{}, err
	}
	return Result{Challenge: &ch}, nil
}

// recognized opens a session for the internal depositor email when the
// address is verified and active for the tenant and the recognition cookie
// value holds its entry. ok is false, without error, otherwise.
func (s *Service) recognized(ctx context.Context, t *tenant.Tenant, email, recognition string) (sess Session, ok bool, err error) {
	entries := parseRecognition(recognition)
	if len(entries) == 0 {
		return Session{}, false, nil
	}
	v, verified, err := s.verifiedAddress(ctx, t.ID, email)
	if err != nil || !verified {
		return Session{}, false, err
	}
	if ok, err := s.recognizes(entries, t.ID, email, v.RecognitionSalt); err != nil || !ok {
		return Session{}, false, err
	}
	cookie, err := s.remember(entries, t.ID, email, v.RecognitionSalt)
	if err != nil {
		return Session{}, false, err
	}
	sess, err = s.openSession(ctx, t, email, nil, func(tx txRepo, now time.Time) error {
		if err := tx.touchVerified(ctx, email, now); err != nil {
			return fmt.Errorf("deposit: touch verified address: %w", err)
		}
		return nil
	})
	if err != nil {
		return Session{}, false, err
	}
	sess.Recognition = cookie
	return sess, true, nil
}

// verifiedAddress returns the verified address email of the tenant, with
// ok true when it was used within the last VerifiedRetentionMonths.
func (s *Service) verifiedAddress(ctx context.Context, tid tenant.ID, email string) (v store.VerifiedAddress, ok bool, err error) {
	v, err = s.repo.verified(ctx, tid, email)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return store.VerifiedAddress{}, false, nil
	case err != nil:
		return store.VerifiedAddress{}, false, fmt.Errorf("deposit: read verified address: %w", err)
	}
	return v, v.Active(s.now()), nil
}

// sendCode creates a verification challenge for addr and mails its code.
//
// The mail is prepared first: a tenant without SMTP settings gets
// ErrMailUnavailable before anything is written. The rate limits are then
// counted in the write transaction that inserts the challenge, after the
// tenant lock (see store.Challenges.CountSinceTx), so that concurrent
// requests cannot exceed them. The mail is queued after the commit; when
// the queue refuses it, the challenge is deleted, best effort, so that a
// code nobody received neither stays usable nor counts against the limits
// (see the package documentation for the remaining corner case).
func (s *Service) sendCode(ctx context.Context, t *tenant.Tenant, clientIP netip.Addr, acceptLanguage string, addr address, inv *store.Invitation) (Challenge, error) {
	chID, err := s.newToken(id.ChallengeTokenPrefix, id.ChallengeTokenBytes)
	if err != nil {
		return Challenge{}, fmt.Errorf("deposit: new challenge id: %w", err)
	}
	code, err := s.newCode()
	if err != nil {
		return Challenge{}, err
	}
	codeMAC, err := s.keys.MAC(crypto.MACPurposeOTP, []byte(chID), []byte(code))
	if err != nil {
		return Challenge{}, fmt.Errorf("deposit: compute code mac: %w", err)
	}
	defaultLang := t.DefaultLanguage
	if inv != nil && inv.Language != "" {
		defaultLang = inv.Language
	}
	job, err := s.prepareMail(ctx, t, mail.TemplateVerificationCode, i18n.Negotiate(acceptLanguage, defaultLang), addr.mailbox,
		mail.VerificationCodeData{TenantName: t.Name, Code: code, ValidityMinutes: int(CodeTTL / time.Minute)})
	if err != nil {
		return Challenge{}, err
	}
	now := s.now()
	rec := store.Challenge{
		ID: chID, Email: addr.normalized, CodeMAC: codeMAC, AttemptsRemaining: store.MaxChallengeAttempts,
		ClientIP: clientIP, CreatedAt: now, ExpiresAt: now.Add(CodeTTL),
	}
	if inv != nil {
		rec.InvitationID = inv.ID
	}
	since := now.Add(-RateWindow)
	scope := ""
	err = s.repo.tx(ctx, t.ID, func(tx txRepo) error {
		n, err := tx.countByEmail(ctx, addr.normalized, since)
		if err != nil {
			return fmt.Errorf("deposit: count codes per address: %w", err)
		}
		if n >= MaxCodesPerAddress {
			scope = scopeCodesPerAddress
			return errLimited
		}
		if n, err = tx.countByIP(ctx, clientIP, since); err != nil {
			return fmt.Errorf("deposit: count codes per ip: %w", err)
		}
		if n >= MaxCodesPerIP {
			scope = scopeCodesPerIP
			return errLimited
		}
		if err := tx.createChallenge(ctx, rec); err != nil {
			return fmt.Errorf("deposit: create challenge: %w", err)
		}
		return nil
	})
	if errors.Is(err, errLimited) {
		s.logEvent(ctx, t, clientIP, securitylog.RateLimited, securitylog.Field{Key: securitylog.KeyScope, Value: scope})
		return Challenge{}, &RateLimitError{RetryAfter: RateWindow}
	}
	if err != nil {
		return Challenge{}, err
	}

	if err := s.enqueue(job); err != nil {
		if derr := s.repo.deleteChallenge(context.WithoutCancel(ctx), t.ID, rec.ID); derr != nil {
			s.logger.ErrorContext(ctx, "deposit: discarding an unsent verification challenge failed",
				slog.String("tenant", t.FQDN), slog.String("error", derr.Error()))
		}
		return Challenge{}, err
	}
	return Challenge{ID: rec.ID, Email: rec.Email, ExpiresAt: rec.ExpiresAt, AttemptsRemaining: rec.AttemptsRemaining}, nil
}

// Confirm checks the code of the verification challenge challengeID of
// tenant t (OpenAPI confirmVerificationChallenge). On success the address is
// recorded as verified and a session is opened, in one transaction with the
// consumption of the challenge, so that concurrent confirmations cannot both
// succeed. recognition is the raw value of the RecognitionCookie cookie sent
// by the browser ("" when absent): for an internal depositor,
// Session.Recognition is that value with the entry of the address added in
// front (see [Service.Start]).
//
// The depositor kind comes from the challenge: external when it was created
// with an invitation, internal otherwise. Eligibility is checked again before
// the code: blocklist, then the network rule for an internal depositor or
// the invitation for an external one. A code confirmed by an internal
// depositor records the internal verification of the address (V1.1, spec
// 6.4) when it has none yet.
//
// Errors: *InvalidError (ErrInvalid) for a code that is not 6 digits;
// ErrNotFound for an unknown challenge (or one of another tenant);
// ErrChallengeGone when it is expired, used or exhausted (including after
// the last wrong code); *WrongCodeError (ErrWrongCode) for a wrong code with
// attempts left; ErrForbidden or ErrInvitationGone when the depositor is no
// longer eligible.
func (s *Service) Confirm(ctx context.Context, t *tenant.Tenant, clientIP netip.Addr, challengeID, code, recognition string) (Session, error) {
	if !validToken(id.ChallengeTokenPrefix, challengeID) {
		return Session{}, ErrNotFound
	}
	if !validCode(code) {
		return Session{}, invalid(FieldCode)
	}
	ch, err := s.repo.challenge(ctx, t.ID, challengeID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return Session{}, ErrNotFound
	case err != nil:
		return Session{}, fmt.Errorf("deposit: read challenge: %w", err)
	case !ch.Open(s.now()):
		return Session{}, ErrChallengeGone
	}
	inv, err := s.recheck(ctx, t, clientIP, ch)
	if err != nil {
		return Session{}, err
	}
	ok, err := s.keys.VerifyMAC(crypto.MACPurposeOTP, ch.CodeMAC, []byte(ch.ID), []byte(code))
	if err != nil {
		return Session{}, fmt.Errorf("deposit: verify code: %w", err)
	}
	if !ok {
		return Session{}, s.wrongCode(ctx, t, clientIP, ch.ID)
	}
	cookie := ""
	sess, err := s.openSession(ctx, t, ch.Email, inv, func(tx txRepo, now time.Time) error {
		if err := tx.consumeChallenge(ctx, ch.ID, now); errors.Is(err, store.ErrNotFound) {
			return ErrChallengeGone
		} else if err != nil {
			return fmt.Errorf("deposit: consume challenge: %w", err)
		}
		v := store.VerifiedAddress{Email: ch.Email, FirstVerifiedAt: now, FirstVerifiedIP: clientIP, LastUsedAt: now}
		if inv == nil {
			v.InternalVerifiedAt, v.InternalVerifiedIP = now, clientIP
		}
		salt, err := tx.upsertVerified(ctx, v)
		if err != nil {
			return fmt.Errorf("deposit: record verified address: %w", err)
		}
		if inv == nil {
			// In the transaction: a failure here never consumes the code.
			cookie, err = s.remember(parseRecognition(recognition), t.ID, ch.Email, salt)
		}
		return err
	})
	if err != nil {
		return Session{}, err
	}
	sess.Recognition = cookie
	s.recordConfirmed(ctx, t, clientIP, ch.Email, sess.ID, inv)
	return sess, nil
}

// recordConfirmed records the audit events of a confirmed code: the
// verification of the address, then the first use of the invitation of an
// external depositor (its LastUsedAt was zero when the challenge was
// checked).
func (s *Service) recordConfirmed(ctx context.Context, t *tenant.Tenant, clientIP netip.Addr, email, sessionID string, inv *store.Invitation) {
	origin := originInternal
	if inv != nil {
		origin = originInvitation
	}
	s.record(ctx, t, clientIP, email, audit.ActionAddressVerified, audit.ObjectDepositSession, sessionID,
		map[string]any{"origin": origin})
	if inv != nil && inv.LastUsedAt.IsZero() {
		s.record(ctx, t, clientIP, email, audit.ActionInvitationUsed, audit.ObjectInvitation, inv.ID,
			map[string]any{"sessionId": sessionID})
	}
}

// recheck verifies that the depositor of challenge ch is still eligible
// and returns the invitation of an external depositor (nil for an internal
// one).
func (s *Service) recheck(ctx context.Context, t *tenant.Tenant, clientIP netip.Addr, ch store.Challenge) (*store.Invitation, error) {
	if !clientIP.IsValid() {
		return nil, s.refuse(ctx, t, clientIP, securitylog.ReasonIP)
	}
	if err := s.checkBlocklist(ctx, t, clientIP, ch.Email); err != nil {
		return nil, err
	}
	if ch.InvitationID == "" {
		return nil, s.checkInternal(ctx, t, clientIP, ch.Email)
	}
	inv, err := s.activeInvitation(ctx, t.ID, ch.InvitationID)
	if errors.Is(err, ErrInvitationGone) {
		_ = s.refuse(ctx, t, clientIP, securitylog.ReasonInvitation)
	}
	if err != nil {
		return nil, err
	}
	return &inv, nil
}

// wrongCode spends one attempt of the challenge chID, logs the failure
// (never the code) and returns the error to answer.
func (s *Service) wrongCode(ctx context.Context, t *tenant.Tenant, clientIP netip.Addr, chID string) error {
	s.logEvent(ctx, t, clientIP, securitylog.VerificationCodeInvalid)
	remaining, err := s.repo.decrementAttempt(ctx, t.ID, chID, s.now())
	switch {
	case errors.Is(err, store.ErrNotFound):
		// Consumed, exhausted or expired concurrently.
		return ErrChallengeGone
	case err != nil:
		return fmt.Errorf("deposit: spend attempt: %w", err)
	case remaining == 0:
		return ErrChallengeGone
	}
	return &WrongCodeError{Remaining: remaining}
}
