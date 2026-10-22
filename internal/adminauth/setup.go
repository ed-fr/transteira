package adminauth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/netip"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/store"
)

// SetupRequest is the first-run setup request (OpenAPI SetupRequest).
type SetupRequest struct {
	// Username, Email and Password are those of the super admin.
	Username string
	Email    string
	Password string
	// SetupToken is the setup token of the deployment.
	SetupToken string
}

// SetupResult is the outcome of the first-run setup: a session in state
// totp_enrollment_required and the TOTP enrollment it must confirm.
type SetupResult struct {
	// Session is the session to set as the cookie.
	Session Session
	// Enrollment is the TOTP secret to confirm.
	Enrollment Enrollment
}

// SetupRequired reports whether the first-run setup is still to be done:
// no administrator exists.
func (s *Service) SetupRequired(ctx context.Context) (bool, error) {
	n, err := s.repo.countAdmins(ctx)
	if err != nil {
		return false, fmt.Errorf("adminauth: count admins: %w", err)
	}
	return n == 0, nil
}

// checkSetupToken compares token with the configured setup token in
// constant time (of their SHA-256, so that the length does not leak
// either). An empty configured token matches nothing.
func (s *Service) checkSetupToken(token string) bool {
	want, got := sha256.Sum256([]byte(s.setupToken)), sha256.Sum256([]byte(token))
	return s.setupToken != "" && subtle.ConstantTimeCompare(want[:], got[:]) == 1
}

// CreateSuperAdmin performs the first-run setup from clientIP (CLAUDE.md
// section 6.6): it creates the super admin with req's password and a
// pending TOTP secret, and opens a session in state
// totp_enrollment_required, which only opens the TOTP confirmation. All of
// it happens in one transaction holding the administrators lock, after
// counting the administrators again: concurrent setups cannot both
// succeed.
//
// It returns ErrSetupDone when an administrator exists, an *InvalidError
// for a malformed username, mail address or password, and
// ErrSetupTokenInvalid for a wrong setup token, after an
// admin_login_failed security event (reason setup_token), which the
// fail2ban and CrowdSec integrations count like a wrong password.
func (s *Service) CreateSuperAdmin(ctx context.Context, req SetupRequest, clientIP netip.Addr) (SetupResult, error) {
	username, err := store.NormalizeUsername(req.Username)
	if err != nil {
		return SetupResult{}, invalid(FieldUsername)
	}
	email, err := store.NormalizeEmail(req.Email)
	if err != nil {
		return SetupResult{}, invalid(FieldEmail)
	}
	if err := checkNewPassword(req.Password, FieldPassword); err != nil {
		return SetupResult{}, err
	}
	required, err := s.SetupRequired(ctx)
	switch {
	case err != nil:
		return SetupResult{}, err
	case !required:
		return SetupResult{}, ErrSetupDone
	case !s.checkSetupToken(req.SetupToken):
		s.logEvent(ctx, clientIP, securitylog.AdminLoginFailed,
			securitylog.Field{Key: securitylog.KeyReason, Value: securitylog.ReasonSetupToken})
		return SetupResult{}, ErrSetupTokenInvalid
	}
	hash, err := s.hasher.HashPassword(ctx, []byte(req.Password))
	if err != nil {
		return SetupResult{}, fmt.Errorf("adminauth: hash password: %w", err)
	}
	sealed, enr, err := s.newEnrollment(username)
	if err != nil {
		return SetupResult{}, err
	}
	now := s.now()
	// The admin ID is assigned by the store: the session row gets it
	// inside the transaction.
	row, sess, err := s.newSession("", store.SessionTOTPEnrollmentRequired, clientIP, now)
	if err != nil {
		return SetupResult{}, err
	}
	err = s.repo.tx(ctx, func(tx txRepo) error {
		n, err := tx.countAdmins(ctx)
		if err != nil {
			return err
		}
		if n > 0 {
			return ErrSetupDone
		}
		a, err := tx.createAdmin(ctx, store.Admin{
			Username: username, Email: email, Role: store.RoleSuperAdmin, PasswordHash: hash, RequireTOTP: true,
		})
		if err != nil {
			return err
		}
		if err := tx.setPendingTOTP(ctx, a.ID, sealed); err != nil {
			return err
		}
		row.AdminID = a.ID
		if err := tx.createSession(ctx, row); err != nil {
			return err
		}
		return tx.audit(ctx, adminEvent(a.Username, clientIP, audit.ActionSetupCompleted, a.ID, nil))
	})
	switch {
	case errors.Is(err, ErrSetupDone):
		return SetupResult{}, ErrSetupDone
	case err != nil:
		return SetupResult{}, fmt.Errorf("adminauth: setup: %w", err)
	}
	return SetupResult{Session: sess, Enrollment: enr}, nil
}
