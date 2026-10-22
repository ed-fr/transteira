package adminauth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"time"
	"unicode/utf8"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/store"
)

// loginRules returns the limits of a password check of username from ip:
// the (username, IP) pair first, then the IP.
func loginRules(username string, ip netip.Addr) []store.AdminLoginRule {
	return []store.AdminLoginRule{
		{Key: store.AdminLoginUserIPKey(username, ip), MaxFailures: LoginUserIPMaxFailures, Window: LoginWindow, LockDuration: LoginLockDuration},
		{Key: store.AdminLoginIPKey(ip), MaxFailures: LoginIPMaxFailures, Window: LoginWindow, LockDuration: LoginLockDuration},
	}
}

// totpRules returns the limits of a second factor check of adminID from ip:
// the administrator (from any IP, store scope admin_totp) first, then the
// IP.
func totpRules(adminID string, ip netip.Addr) []store.AdminLoginRule {
	return []store.AdminLoginRule{
		{Key: store.AdminLoginTOTPKey(adminID), MaxFailures: TOTPAdminMaxFailures, Window: LoginWindow, LockDuration: LoginLockDuration},
		{Key: store.AdminLoginIPKey(ip), MaxFailures: LoginIPMaxFailures, Window: LoginWindow, LockDuration: LoginLockDuration},
	}
}

// keysOf returns the keys of rules.
func keysOf(rules []store.AdminLoginRule) []store.AdminLoginKey {
	keys := make([]store.AdminLoginKey, len(rules))
	for i, r := range rules {
		keys[i] = r.Key
	}
	return keys
}

// reserve counts an attempt on rules at now before the secret is verified,
// so that concurrent attempts can never exceed a limit. It returns a
// *RateLimitError, after a rate_limited security event, when a counter is
// locked, including by a concurrent attempt between the check and the
// count (the attempt is then withdrawn).
func (s *Service) reserve(ctx context.Context, rules []store.AdminLoginRule, ip netip.Addr, now time.Time) (store.FailureOutcome, error) {
	until, err := s.repo.checkLogin(ctx, keysOf(rules), now)
	if err != nil {
		return store.FailureOutcome{}, fmt.Errorf("adminauth: check login limits: %w", err)
	}
	if !until.IsZero() {
		return store.FailureOutcome{}, s.limited(ctx, ip, until, now)
	}
	out, err := s.repo.recordLogin(ctx, rules, now)
	if err != nil {
		return store.FailureOutcome{}, fmt.Errorf("adminauth: count login attempt: %w", err)
	}
	// Every rule locks for LoginLockDuration: a lock ending at another time
	// was set by another attempt since the check.
	if !out.LockedUntil.IsZero() && !out.LockedUntil.Equal(now.Add(LoginLockDuration)) {
		s.refund(ctx, rules, now)
		return store.FailureOutcome{}, s.limited(ctx, ip, out.LockedUntil, now)
	}
	return out, nil
}

// limited writes a rate_limited security event and returns the
// *RateLimitError of a lock ending at until.
func (s *Service) limited(ctx context.Context, ip netip.Addr, until, now time.Time) error {
	s.logEvent(ctx, ip, securitylog.RateLimited, securitylog.Field{Key: securitylog.KeyScope, Value: logScope})
	return &RateLimitError{RetryAfter: retryAfter(until, now)}
}

// refund withdraws the attempt reserved at now on rules, even past the end
// of ctx; a failure is only logged (the attempt then stays counted).
func (s *Service) refund(ctx context.Context, rules []store.AdminLoginRule, now time.Time) {
	if err := s.repo.refundLogin(context.WithoutCancel(ctx), rules, now); err != nil {
		s.logger.ErrorContext(ctx, "admin login attempt not refunded", slog.String("error", err.Error()))
	}
}

// unknownActor names an unknown username, and its object, in the audit
// log.
const unknownActor = "unknown"

// failure records a failed login step of the account a (nil for an unknown
// username) for reason: an admin_login_failed security event, an audit
// event, and a rate_limited event when this failure set a lock. The audit
// event is written for unknown usernames too, so that a failure costs the
// same work whether the account exists or not (T-65); its actor and object
// are then "unknown" and its details never hold the typed username (often
// a password typed in the wrong field). It returns the *RateLimitError of
// that lock, or ErrInvalidCredentials.
func (s *Service) failure(ctx context.Context, a *store.Admin, ip netip.Addr, reason string,
	out store.FailureOutcome, now time.Time,
) error {
	s.logEvent(ctx, ip, securitylog.AdminLoginFailed, securitylog.Field{Key: securitylog.KeyReason, Value: reason})
	actor, object := unknownActor, unknownActor
	if a != nil {
		actor, object = a.Username, a.ID
	}
	s.record(ctx, adminEvent(actor, ip, audit.ActionAdminLoginFailed, object, map[string]any{"reason": reason}))
	if !out.LockedUntil.IsZero() {
		return s.limited(ctx, ip, out.LockedUntil, now)
	}
	return ErrInvalidCredentials
}

// checkPassword verifies password for the account a (nil for an unknown
// username, typed as username) from ip, the attempt being counted first
// on the login limits. An unknown username, a disabled account or one
// without a password is verified against dummyHash, for the same work, and
// fails the same way. On success, the (username, IP) counter is reset and
// the attempt is withdrawn from the IP counter.
func (s *Service) checkPassword(ctx context.Context, username string, a *store.Admin, password string, ip netip.Addr) error {
	rules := loginRules(username, ip)
	now := s.now()
	out, err := s.reserve(ctx, rules, ip, now)
	if err != nil {
		return err
	}
	hash, usable := dummyHash, false
	if a != nil && a.PasswordHash != "" && !a.Disabled {
		hash, usable = a.PasswordHash, true
	}
	ok, err := s.hasher.VerifyPassword(ctx, hash, []byte(password))
	if err != nil {
		// Not verified (canceled, no hashing slot): not a failure.
		s.refund(ctx, rules, now)
		return fmt.Errorf("adminauth: verify password: %w", err)
	}
	if !ok || !usable {
		return s.failure(ctx, a, ip, securitylog.ReasonPassword, out, now)
	}
	if err := s.repo.resetLogin(ctx, keysOf(rules[:1])); err != nil {
		return fmt.Errorf("adminauth: reset login limits: %w", err)
	}
	if err := s.repo.refundLogin(ctx, rules[1:], now); err != nil {
		return fmt.Errorf("adminauth: refund login attempt: %w", err)
	}
	return nil
}

// Login checks the username and password of an administrator connecting
// from clientIP (first factor) and opens a session whose state gives the
// next step: totp_required when TOTP is enrolled, totp_enrollment_required
// when it is required but not enrolled (always the case of a super admin
// without TOTP), authenticated only for an administrator whose TOTP is
// neither enrolled nor required.
//
// The limits are checked, then the attempt is counted before the password
// is verified: 5 failures per (username, IP) and 20 per IP within 15
// minutes lock for 15 minutes. There is no lock per username alone. Every
// failure writes an admin_login_failed security event, every lock a
// rate_limited one.
//
// It returns an *InvalidError for an over-long username or password,
// ErrNoClientIP for an invalid clientIP, a *RateLimitError while locked or
// when this failure sets a lock, and ErrInvalidCredentials for an unknown
// username, a wrong password, a disabled account or one not yet activated,
// without telling them apart.
func (s *Service) Login(ctx context.Context, username, password string, clientIP netip.Addr) (Session, error) {
	switch {
	case utf8.RuneCountInString(username) > MaxUsernameLen:
		return Session{}, invalid(FieldUsername)
	case utf8.RuneCountInString(password) > MaxPasswordLen:
		return Session{}, invalid(FieldPassword)
	case !clientIP.IsValid():
		return Session{}, ErrNoClientIP
	}
	var account *store.Admin
	a, err := s.repo.adminByUsername(ctx, username)
	switch {
	case err == nil:
		account = &a
	case !errors.Is(err, store.ErrNotFound):
		return Session{}, fmt.Errorf("adminauth: read admin: %w", err)
	}
	if err := s.checkPassword(ctx, username, account, password, clientIP); err != nil {
		return Session{}, err
	}
	state := stateFor(a)
	sess, err := s.openSession(ctx, a.ID, state, clientIP)
	if err != nil {
		return Session{}, err
	}
	if state == store.SessionAuthenticated {
		s.loggedIn(ctx, a, clientIP, "password")
	}
	return sess, nil
}

// loggedIn records a completed login of a with method: the last login time
// and an admin.login audit event. Failures are only logged: the session is
// already open.
func (s *Service) loggedIn(ctx context.Context, a store.Admin, ip netip.Addr, method string) {
	if err := s.repo.touchLogin(ctx, a.ID); err != nil {
		s.logger.ErrorContext(ctx, "admin last login not recorded", slog.String("admin_id", a.ID), slog.String("error", err.Error()))
	}
	s.record(ctx, adminEvent(a.Username, ip, audit.ActionAdminLogin, a.ID, map[string]any{"method": method}))
}

// VerifyTOTP checks the second factor of the session p, in state
// totp_required: a TOTP code (code) or a recovery code (recoveryCode),
// exactly one of them. On success the session is rotated to authenticated
// (new token, new CSRF token) and returned.
//
// A TOTP code is accepted once: its time step must be later than the last
// accepted one (T-60). A recovery code is consumed. The attempt is counted
// first on the limits of the administrator (5 wrong second factors within
// 15 minutes, from any IP, lock for 15 minutes) and of the IP (shared with
// the passwords), and on the session, which ends after 5 wrong codes.
//
// It returns ErrUnauthenticated when p is not in state totp_required (or
// its account lost its TOTP), an *InvalidError unless exactly one code is
// given, ErrNoClientIP, a *RateLimitError while locked or when this
// failure sets a lock, and ErrInvalidCredentials for a wrong, replayed or
// used code.
func (s *Service) VerifyTOTP(ctx context.Context, p Principal, code, recoveryCode string, clientIP netip.Addr) (Session, error) {
	if p.State != store.SessionTOTPRequired {
		return Session{}, ErrUnauthenticated
	}
	switch {
	case (code == "") == (recoveryCode == ""):
		return Session{}, invalid(FieldCode)
	case code != "" && !crypto.ValidTOTPCode(code):
		return Session{}, invalid(FieldCode)
	case len(recoveryCode) > MaxRecoveryCodeLen:
		return Session{}, invalid(FieldRecoveryCode)
	case !clientIP.IsValid():
		return Session{}, ErrNoClientIP
	}
	a, err := s.repo.admin(ctx, p.Admin.ID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return Session{}, ErrUnauthenticated
	case err != nil:
		return Session{}, fmt.Errorf("adminauth: read admin: %w", err)
	case !a.TOTPEnabled || a.Disabled:
		return Session{}, ErrUnauthenticated
	}
	rules := totpRules(a.ID, clientIP)
	now := s.now()
	out, err := s.reserve(ctx, rules, clientIP, now)
	if err != nil {
		return Session{}, err
	}
	reason, method := securitylog.ReasonTOTP, "totp"
	var ok bool
	if code != "" {
		ok, err = s.checkTOTPCode(ctx, a, code, now)
	} else {
		reason, method = securitylog.ReasonRecoveryCode, "recovery_code"
		ok, err = s.useRecoveryCode(ctx, a, recoveryCode, now)
	}
	if err != nil {
		s.refund(ctx, rules, now)
		return Session{}, err
	}
	if !ok {
		return Session{}, s.totpFailure(ctx, p, a, clientIP, reason, out, now)
	}
	s.refund(ctx, rules, now)
	sess, err := s.rotate(ctx, p, store.SessionAuthenticated)
	if err != nil {
		return Session{}, err
	}
	if method == "recovery_code" {
		s.record(ctx, adminEvent(a.Username, clientIP, audit.ActionAdminRecoveryCodeUsed, a.ID, nil))
	}
	s.loggedIn(ctx, a, clientIP, method)
	return sess, nil
}

// checkTOTPCode reports whether code is a TOTP code of a not used yet, and
// records its time step.
func (s *Service) checkTOTPCode(ctx context.Context, a store.Admin, code string, now time.Time) (bool, error) {
	secret, err := s.vault.OpenSystem(ctx, crypto.PurposeAdminTOTP, a.TOTPSecretID)
	if err != nil {
		return false, fmt.Errorf("adminauth: open totp secret: %w", err)
	}
	defer clear(secret)
	last := uint64(max(a.TOTPLastCounter, 0))
	counter, ok := crypto.VerifyTOTP(secret, code, now, last, a.TOTPLastCounter >= 0)
	if !ok {
		return false, nil
	}
	// The store accepts each step once, even for concurrent logins.
	accepted, err := s.repo.advanceTOTP(ctx, a.ID, int64(counter)) //nolint:gosec // a time step fits in int64 until year 10^11
	if err != nil {
		return false, fmt.Errorf("adminauth: record totp step: %w", err)
	}
	return accepted, nil
}

// useRecoveryCode reports whether code is an unused recovery code of a,
// and consumes it. Its MAC is keyed by the TOTP secret in use of a (see
// crypto.RecoveryCodeMAC).
func (s *Service) useRecoveryCode(ctx context.Context, a store.Admin, code string, now time.Time) (bool, error) {
	normalized, ok := crypto.NormalizeRecoveryCode(code)
	if !ok {
		return false, nil
	}
	secret, err := s.vault.OpenSystem(ctx, crypto.PurposeAdminTOTP, a.TOTPSecretID)
	if err != nil {
		return false, fmt.Errorf("adminauth: open totp secret: %w", err)
	}
	mac, err := s.recoveryMAC(secret, normalized)
	clear(secret)
	if err != nil {
		return false, fmt.Errorf("adminauth: recovery code mac: %w", err)
	}
	consumed, err := s.repo.consumeRecovery(ctx, a.ID, mac, now)
	if err != nil {
		return false, fmt.Errorf("adminauth: consume recovery code: %w", err)
	}
	return consumed, nil
}

// totpFailure records a wrong second factor on the session p: the
// failure events, then the session counter, which ends the session at
// MaxSessionTOTPFailures.
func (s *Service) totpFailure(ctx context.Context, p Principal, a store.Admin, ip netip.Addr, reason string,
	out store.FailureOutcome, now time.Time,
) error {
	ferr := s.failure(ctx, &a, ip, reason, out, now)
	n, err := s.repo.totpFailure(ctx, p.SessionID)
	if err != nil {
		return fmt.Errorf("adminauth: count totp failure: %w", err)
	}
	if n >= MaxSessionTOTPFailures {
		if err := s.repo.deleteSession(ctx, p.SessionID); err != nil && !errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("adminauth: end session: %w", err)
		}
	}
	return ferr
}
