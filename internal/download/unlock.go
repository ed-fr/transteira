package download

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"unicode/utf8"

	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Password input limits (OpenAPI TransferPassword).
const (
	// MaxPasswordRunes bounds the length of a transfer password, in
	// characters.
	MaxPasswordRunes = 1024
	// MaxPasswordBytes bounds its size in bytes.
	MaxPasswordBytes = 4 * MaxPasswordRunes
	// transferIDLogLen is the length of the transfer ID prefix written to
	// the security log: the prefix and the timestamp part of the ULID,
	// enough to correlate with the audit, never the token.
	transferIDLogLen = 14
	// keyTransfer is the security log field of the truncated transfer ID.
	keyTransfer = "transfer"
	// scopeTransferPassword names the lock in the rate_limited events.
	scopeTransferPassword = "transfer_password"
)

// checkPassword validates a password input.
func checkPassword(pw string) error {
	switch {
	case pw == "":
		return ErrPasswordRequired
	case len(pw) > MaxPasswordBytes || !utf8.ValidString(pw) || utf8.RuneCountInString(pw) > MaxPasswordRunes:
		return ErrInvalid
	}
	return nil
}

// Unlock checks the password of the protected transfer of the download
// token rawToken in tenant t (unlockDownload), entered from the client IP
// clientIP. grantCookie is the raw value of the GrantCookieName cookie, ""
// when absent.
//
// On success it returns the new value of the grant cookie, holding a grant
// of the transfer valid GrantTTL; the HTTP layer sets it with Max-Age
// GrantTTL. For a transfer without password it does nothing and returns
// "" (the cookie is left as it is).
//
// Two failure counters apply, each locking for store.PasswordLockDuration
// after store.MaxPasswordFailures wrong passwords: the transfer (all IPs)
// and the client IP (all transfers of the tenant; an IPv6 client by its
// /64). The attempt is counted against both before the password is
// verified, in one transaction with the lock check, so that concurrent
// attempts can never be verified beyond the limit. A right password clears
// the transfer counter and refunds the attempt on the IP counter (its
// earlier failures stay). An attempt whose password could not be verified
// (ctx canceled, hashing slot not obtained) is refunded on both counters.
// A locked transfer or IP costs no password hashing.
//
// It returns ErrPasswordRequired for an empty password, ErrInvalid for a
// malformed one, ErrNotFound, ErrGone and ErrMaxDownloads
// as Resolve does, ErrNoClientIP for an invalid clientIP, a *LockedError
// (ErrLocked) while locked or when this wrong password sets the lock, and
// a *WrongPasswordError (ErrWrongPassword) for a wrong password while
// attempts remain. Every wrong password writes a transfer_password_invalid
// security event, and every refusal on a lock a rate_limited event.
func (s *Service) Unlock(ctx context.Context, t *tenant.Tenant, rawToken string, clientIP netip.Addr, password, grantCookie string) (string, error) {
	if err := checkPassword(password); err != nil {
		return "", err
	}
	a, err := s.resolve(ctx, t, rawToken, grantCookie, true)
	if err != nil {
		return "", err
	}
	if !a.d.PasswordProtected() {
		return "", nil
	}
	if !clientIP.IsValid() {
		return "", ErrNoClientIP
	}
	trfKey, ipKey := store.TransferFailureKey(a.d.ID), store.IPFailureKey(clientIP)
	keys := []store.FailureKey{trfKey, ipKey}
	now := s.now()
	until, out, err := s.repo.reserve(ctx, t.ID, keys, now)
	if err != nil {
		return "", fmt.Errorf("download: count password attempt: %w", err)
	}
	if !until.IsZero() {
		s.logEvent(ctx, t, clientIP, a.d.ID, securitylog.RateLimited,
			securitylog.Field{Key: securitylog.KeyScope, Value: scopeTransferPassword})
		return "", &LockedError{RetryAfter: retryAfter(until, now)}
	}
	ok, err := s.passwords.VerifyPassword(ctx, a.d.PasswordHash, []byte(password))
	if err != nil {
		// Not verified (canceled, slot wait aborted): the attempt counted
		// in advance is refunded on both counters, even past ctx.
		if rerr := s.repo.refund(context.WithoutCancel(ctx), t.ID, keys, now); rerr != nil {
			s.log(ctx, slog.LevelError, "unverified password attempt not refunded", t.ID, a.d.ID, slog.Any("error", rerr))
		}
		return "", fmt.Errorf("download: verify transfer password: %w", err)
	}
	if !ok {
		s.logEvent(ctx, t, clientIP, a.d.ID, securitylog.TransferPasswordInvalid)
		if !out.LockedUntil.IsZero() {
			return "", &LockedError{RetryAfter: retryAfter(out.LockedUntil, now)}
		}
		return "", &WrongPasswordError{Remaining: out.Remaining}
	}
	if err := s.repo.unlocked(ctx, t.ID, trfKey, ipKey, now); err != nil {
		return "", fmt.Errorf("download: settle password failures: %w", err)
	}
	return s.grant(grantCookie, t.ID, a.d.ID, now)
}

// logEvent writes a security event about the transfer trfID, which is
// truncated; a write failure is only reported on the application log.
func (s *Service) logEvent(ctx context.Context, t *tenant.Tenant, ip netip.Addr, trfID string, typ securitylog.EventType, fields ...securitylog.Field) {
	fields = append([]securitylog.Field{{Key: keyTransfer, Value: trfID[:min(len(trfID), transferIDLogLen)]}}, fields...)
	ev := securitylog.Event{Type: typ, IP: ip, Tenant: t.FQDN, Fields: fields}
	if err := s.seclog.Log(ev); err != nil {
		s.log(ctx, slog.LevelError, "security log write failed", t.ID, trfID,
			slog.String("event", string(typ)), slog.String("error", err.Error()))
	}
}
