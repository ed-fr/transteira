package adminauth

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/store"
)

// Enrollment is a TOTP secret awaiting confirmation (OpenAPI
// TotpEnrollment). It is shown once and never logged.
type Enrollment struct {
	// Secret is the secret in base32, to type into an authenticator app.
	Secret string
	// URI is the otpauth key URI of the secret.
	URI string
	// QRPNG is the QR code of URI, a PNG image.
	QRPNG []byte
}

// Confirmed is the result of a TOTP confirmation (OpenAPI TotpConfirmed).
type Confirmed struct {
	// RecoveryCodes are the new single-use recovery codes, shown once.
	RecoveryCodes []string
	// Session is the rotated session when the confirmation completed a
	// login (state totp_enrollment_required), nil otherwise.
	Session *Session
}

// enrollable reports whether the state of p opens the enrollment: an
// authenticated session, or one whose enrollment is mandatory.
func enrollable(p Principal) bool {
	return p.SessionID != "" && (p.State == store.SessionAuthenticated || p.State == store.SessionTOTPEnrollmentRequired)
}

// newEnrollment generates a TOTP secret for the account username and
// seals it; the caller stores the returned system secret as the pending
// enrollment.
func (s *Service) newEnrollment(username string) (store.SystemSecret, Enrollment, error) {
	secret, err := s.newTOTPSecret()
	if err != nil {
		return store.SystemSecret{}, Enrollment{}, fmt.Errorf("adminauth: new totp secret: %w", err)
	}
	defer clear(secret)
	sealed, err := s.vault.WrapSystem(crypto.PurposeAdminTOTP, secret)
	if err != nil {
		return store.SystemSecret{}, Enrollment{}, fmt.Errorf("adminauth: seal totp secret: %w", err)
	}
	uri := crypto.TOTPURI(s.issuer, username, secret)
	png, err := s.qrPNG(uri)
	if err != nil {
		return store.SystemSecret{}, Enrollment{}, fmt.Errorf("adminauth: totp qr code: %w", err)
	}
	return sealed, Enrollment{Secret: crypto.EncodeTOTPSecret(secret), URI: uri, QRPNG: png}, nil
}

// StartEnrollment generates a new TOTP secret for the administrator of p,
// as the pending enrollment (a previous pending one is destroyed); the TOTP
// in use, if any, stays until the confirmation. p must be authenticated or
// in state totp_enrollment_required.
//
// From an authenticated session, enrolling (first enrollment or
// replacement of the TOTP in use) needs currentPassword, checked and
// counted on the login limits like a login, so that a stolen session alone
// can neither swap the second factor of its victim nor bind one of its own
// to the account. Only the mandatory enrollment of a session in state
// totp_enrollment_required, whose password was just proven, needs nothing
// more. The pending secret can be confirmed for PendingTOTPTTL.
//
// It returns ErrUnauthenticated unless p is authenticated or in state
// totp_enrollment_required, and, from an authenticated session, an
// *InvalidError on FieldCurrentPassword when currentPassword is missing or
// too long, and the errors of a password check (ErrNoClientIP,
// *RateLimitError, ErrInvalidCredentials).
func (s *Service) StartEnrollment(ctx context.Context, p Principal, currentPassword string, clientIP netip.Addr) (Enrollment, error) {
	if !enrollable(p) {
		return Enrollment{}, ErrUnauthenticated
	}
	if p.State == store.SessionAuthenticated {
		if currentPassword == "" {
			return Enrollment{}, invalid(FieldCurrentPassword)
		}
		if _, err := s.verifyOwnPassword(ctx, p, currentPassword, clientIP); err != nil {
			return Enrollment{}, err
		}
	}
	sealed, enr, err := s.newEnrollment(p.Admin.Username)
	if err != nil {
		return Enrollment{}, err
	}
	// The confirmation measures the validity of the secret from this time.
	sealed.CreatedAt = s.now()
	err = s.repo.setPendingTOTP(ctx, p.Admin.ID, sealed)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return Enrollment{}, ErrUnauthenticated
	case err != nil:
		return Enrollment{}, fmt.Errorf("adminauth: store pending totp: %w", err)
	}
	return enr, nil
}

// ConfirmEnrollment confirms the pending TOTP secret of the administrator
// of p with code: TOTP is enabled with that secret (the code cannot be
// replayed at login) and RecoveryCodeCount new recovery codes replace the
// old ones. When p was in state totp_enrollment_required, the session is
// rotated to authenticated; when TOTP was already enabled (re-enrollment),
// the other sessions of the account are revoked. All of it commits in one
// transaction, so that the recovery codes returned are always the ones
// stored.
//
// A pending secret older than PendingTOTPTTL is refused. The attempt is
// counted first on the second factor limits of the administrator and of
// the IP, like a login (VerifyTOTP): 5 wrong codes within 15 minutes lock
// the second factor of the account for 15 minutes. Every wrong code writes
// an admin_login_failed security event (reason totp) and an audit event.
//
// It returns ErrUnauthenticated unless p is authenticated or in state
// totp_enrollment_required (or when its session ended meanwhile), an
// *InvalidError for a malformed code, ErrNoClientIP for an invalid
// clientIP, ErrNoPendingEnrollment without a pending secret or when it
// expired, a *RateLimitError while locked or when this failure sets a
// lock, and ErrInvalidCredentials for a wrong code.
func (s *Service) ConfirmEnrollment(ctx context.Context, p Principal, code string, clientIP netip.Addr) (Confirmed, error) {
	switch {
	case !enrollable(p):
		return Confirmed{}, ErrUnauthenticated
	case !crypto.ValidTOTPCode(code):
		return Confirmed{}, invalid(FieldCode)
	case !clientIP.IsValid():
		return Confirmed{}, ErrNoClientIP
	}
	a, err := s.repo.admin(ctx, p.Admin.ID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return Confirmed{}, ErrUnauthenticated
	case err != nil:
		return Confirmed{}, fmt.Errorf("adminauth: read admin: %w", err)
	case a.PendingTOTPSecretID == "":
		return Confirmed{}, ErrNoPendingEnrollment
	}
	now := s.now()
	pending, err := s.repo.systemSecret(ctx, a.PendingTOTPSecretID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		// A concurrent enrollment replaced the pending secret.
		return Confirmed{}, ErrNoPendingEnrollment
	case err != nil:
		return Confirmed{}, fmt.Errorf("adminauth: read pending totp secret: %w", err)
	case now.Sub(pending.CreatedAt) > PendingTOTPTTL:
		return Confirmed{}, ErrNoPendingEnrollment
	}
	rules := totpRules(a.ID, clientIP)
	limits, err := s.reserve(ctx, rules, clientIP, now)
	if err != nil {
		return Confirmed{}, err
	}
	counter, hashes, codes, err := s.checkPending(ctx, a, code, now)
	switch {
	case errors.Is(err, ErrInvalidCredentials):
		return Confirmed{}, s.failure(ctx, &a, clientIP, securitylog.ReasonTOTP, limits, now)
	case err != nil:
		s.refund(ctx, rules, now)
		return Confirmed{}, err
	}
	s.refund(ctx, rules, now)
	var rot *rotation
	if p.State == store.SessionTOTPEnrollmentRequired {
		r, err := s.newRotation(p, store.SessionAuthenticated)
		if err != nil {
			return Confirmed{}, err
		}
		rot = &r
	}
	reenroll := a.TOTPEnabled
	err = s.repo.tx(ctx, func(tx txRepo) error {
		if err := tx.setTOTP(ctx, a.ID, a.PendingTOTPSecretID, counter); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				// A concurrent enrollment replaced the pending secret.
				return ErrNoPendingEnrollment
			}
			return err
		}
		if err := tx.replaceRecovery(ctx, a.ID, hashes); err != nil {
			return err
		}
		if reenroll {
			if _, err := tx.deleteSessions(ctx, a.ID, p.SessionID); err != nil {
				return err
			}
		}
		if rot != nil {
			err := tx.rotateSession(ctx, rot.sessionID, rot.oldHash, rot.newHash, rot.out.State, rot.out.StateExpiresAt, rot.now, s.idle)
			if errors.Is(err, store.ErrNotFound) {
				return ErrUnauthenticated
			}
			if err != nil {
				return err
			}
		}
		return tx.audit(ctx, adminEvent(a.Username, clientIP, audit.ActionAdminTOTPEnrolled, a.ID,
			map[string]any{"reenrollment": reenroll}))
	})
	switch {
	case errors.Is(err, ErrNoPendingEnrollment), errors.Is(err, ErrUnauthenticated):
		return Confirmed{}, err
	case err != nil:
		return Confirmed{}, fmt.Errorf("adminauth: enable totp: %w", err)
	}
	out := Confirmed{RecoveryCodes: codes}
	if rot != nil {
		out.Session = &rot.out
		s.loggedIn(ctx, a, clientIP, "totp_enrollment")
	}
	return out, nil
}

// checkPending verifies code against the pending secret of a and returns
// its time step, then generates the new recovery codes and their MACs,
// keyed by that secret (crypto.RecoveryCodeMAC). It returns
// ErrInvalidCredentials for a wrong code.
func (s *Service) checkPending(ctx context.Context, a store.Admin, code string, now time.Time) (int64, [][]byte, []string, error) {
	secret, err := s.vault.OpenSystem(ctx, crypto.PurposeAdminTOTP, a.PendingTOTPSecretID)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("adminauth: open pending totp secret: %w", err)
	}
	defer clear(secret)
	counter, ok := crypto.VerifyTOTP(secret, code, now, 0, false)
	if !ok {
		return 0, nil, nil, ErrInvalidCredentials
	}
	codes, err := s.newRecovery(RecoveryCodeCount)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("adminauth: new recovery codes: %w", err)
	}
	hashes := make([][]byte, len(codes))
	for i, c := range codes {
		if hashes[i], err = s.recoveryMAC(secret, c); err != nil {
			return 0, nil, nil, fmt.Errorf("adminauth: recovery code mac: %w", err)
		}
	}
	return int64(counter), hashes, codes, nil //nolint:gosec // a time step fits in int64 until year 10^11
}

// DisableTOTP removes the TOTP enrollment and the recovery codes of the
// administrator of the authenticated session p, after checking
// currentPassword (counted on the login limits), and revokes their other
// sessions; p stays open.
//
// It returns ErrUnauthenticated unless p is authenticated, ErrForbidden
// for a super admin or an administrator whose TOTP is required, and the
// errors of a password check (*InvalidError, ErrNoClientIP,
// *RateLimitError, ErrInvalidCredentials).
func (s *Service) DisableTOTP(ctx context.Context, p Principal, currentPassword string, clientIP netip.Addr) error {
	if err := RequireAuthenticated(p); err != nil {
		return err
	}
	if p.Admin.Role == store.RoleSuperAdmin || p.Admin.RequireTOTP {
		return ErrForbidden
	}
	a, err := s.verifyOwnPassword(ctx, p, currentPassword, clientIP)
	if err != nil {
		return err
	}
	if a.Role == store.RoleSuperAdmin || a.RequireTOTP {
		return ErrForbidden
	}
	err = s.repo.tx(ctx, func(tx txRepo) error {
		if err := tx.clearTOTP(ctx, a.ID); err != nil {
			return err
		}
		if _, err := tx.deleteSessions(ctx, a.ID, p.SessionID); err != nil {
			return err
		}
		return tx.audit(ctx, adminEvent(a.Username, clientIP, audit.ActionAdminTOTPDisabled, a.ID, nil))
	})
	if err != nil {
		return fmt.Errorf("adminauth: disable totp: %w", err)
	}
	return nil
}
