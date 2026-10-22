package adminauth

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"unicode/utf8"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/store"
)

// Resolve returns the session whose cookie token is rawToken, with its
// administrator, and records its use (sliding idle timeout). The session
// must be valid: before its absolute expiry, used within the idle timeout
// and, in an intermediate state, before the state expiry. The caller
// enforces the state: [RequireAuthenticated] for every operation but the
// login steps.
//
// It returns ErrUnauthenticated for a malformed, unknown, expired or
// revoked token, and for a session of a disabled or deleted account.
func (s *Service) Resolve(ctx context.Context, rawToken string) (Principal, error) {
	if !validToken(SessionTokenPrefix, rawToken) {
		return Principal{}, ErrUnauthenticated
	}
	hash := tokenHash(rawToken)
	now := s.now()
	sess, err := s.repo.session(ctx, hash, now, s.idle)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return Principal{}, ErrUnauthenticated
	case err != nil:
		return Principal{}, fmt.Errorf("adminauth: read session: %w", err)
	}
	a, err := s.repo.admin(ctx, sess.AdminID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return Principal{}, ErrUnauthenticated
	case err != nil:
		return Principal{}, fmt.Errorf("adminauth: read admin: %w", err)
	case a.Disabled:
		return Principal{}, ErrUnauthenticated
	}
	err = s.repo.touchSession(ctx, sess.ID, now, s.idle)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return Principal{}, ErrUnauthenticated
	case err != nil:
		return Principal{}, fmt.Errorf("adminauth: touch session: %w", err)
	}
	csrf, err := s.csrfToken(rawToken)
	if err != nil {
		return Principal{}, err
	}
	return Principal{
		SessionID: sess.ID, State: sess.State, CSRFToken: csrf, ExpiresAt: sess.ExpiresAt,
		Admin: accountOf(a), tokenHash: hash,
	}, nil
}

// RequireAuthenticated returns ErrUnauthenticated unless p is a session in
// the authenticated state: an intermediate state only opens the endpoint of
// the next login step.
func RequireAuthenticated(p Principal) error {
	if p.SessionID == "" || p.State != store.SessionAuthenticated {
		return ErrUnauthenticated
	}
	return nil
}

// Logout ends the session p, whatever its state, from clientIP. It returns
// ErrUnauthenticated when the session no longer exists.
func (s *Service) Logout(ctx context.Context, p Principal, clientIP netip.Addr) error {
	if p.SessionID == "" {
		return ErrUnauthenticated
	}
	err := s.repo.deleteSession(ctx, p.SessionID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return ErrUnauthenticated
	case err != nil:
		return fmt.Errorf("adminauth: delete session: %w", err)
	}
	s.record(ctx, adminEvent(p.Admin.Username, clientIP, audit.ActionAdminLogout, p.Admin.ID, nil))
	return nil
}

// ChangePassword replaces the password of the administrator of the
// authenticated session p by newPassword, after checking currentPassword
// (counted on the login limits like a login), and revokes their other
// sessions; p stays open.
//
// It returns ErrUnauthenticated unless p is authenticated, an
// *InvalidError on FieldNewPassword for a password outside the policy,
// ErrNoClientIP, a *RateLimitError and ErrInvalidCredentials for a wrong
// current password.
func (s *Service) ChangePassword(ctx context.Context, p Principal, currentPassword, newPassword string, clientIP netip.Addr) error {
	if err := RequireAuthenticated(p); err != nil {
		return err
	}
	if err := checkNewPassword(newPassword, FieldNewPassword); err != nil {
		return err
	}
	a, err := s.verifyOwnPassword(ctx, p, currentPassword, clientIP)
	if err != nil {
		return err
	}
	hash, err := s.hasher.HashPassword(ctx, []byte(newPassword))
	if err != nil {
		return fmt.Errorf("adminauth: hash password: %w", err)
	}
	err = s.repo.tx(ctx, func(tx txRepo) error {
		if err := tx.setPassword(ctx, a.ID, hash); err != nil {
			return err
		}
		if _, err := tx.deleteSessions(ctx, a.ID, p.SessionID); err != nil {
			return err
		}
		return tx.audit(ctx, adminEvent(a.Username, clientIP, audit.ActionAdminPasswordChanged, a.ID, nil))
	})
	if err != nil {
		return fmt.Errorf("adminauth: change password: %w", err)
	}
	return nil
}

// verifyOwnPassword reads the administrator of p and checks password (see
// checkPassword).
func (s *Service) verifyOwnPassword(ctx context.Context, p Principal, password string, clientIP netip.Addr) (store.Admin, error) {
	switch {
	case utf8.RuneCountInString(password) > MaxPasswordLen:
		return store.Admin{}, invalid(FieldCurrentPassword)
	case !clientIP.IsValid():
		return store.Admin{}, ErrNoClientIP
	}
	a, err := s.repo.admin(ctx, p.Admin.ID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return store.Admin{}, ErrUnauthenticated
	case err != nil:
		return store.Admin{}, fmt.Errorf("adminauth: read admin: %w", err)
	}
	if err := s.checkPassword(ctx, a.Username, &a, password, clientIP); err != nil {
		return store.Admin{}, err
	}
	return a, nil
}
