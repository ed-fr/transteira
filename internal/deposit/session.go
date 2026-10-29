package deposit

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Kind tells how a depositor was allowed to deposit (OpenAPI DepositorKind).
type Kind = store.DepositorKind

// Depositor kinds.
const (
	// KindInternal is an internal user: internal IP and domain.
	KindInternal = store.DepositorInternal
	// KindExternal is an external user holding an invitation.
	KindExternal = store.DepositorExternal
	// KindInternalRemote is an internal user depositing from outside the
	// tenant ranges (V1.1, spec 6.4): a code on every deposit, no
	// recognition cookie, no invitation.
	KindInternalRemote = store.DepositorInternalRemote
)

// Limits are the deposit limits shown to a depositor (OpenAPI
// DepositSession.limits).
type Limits struct {
	// MaxTransferBytes is the maximum total size of one transfer.
	MaxTransferBytes int64
	// ExpiryDays are the transfer lifetimes the depositor may choose.
	ExpiryDays []int
}

// InvitationInfo describes the invitation of an external depositor.
type InvitationInfo struct {
	// ID is the invitation record ("inv_" + ULID), for the server only.
	ID string
	// InvitedBy is the internal user who invited, the recipient of the
	// files.
	InvitedBy string
	// ExpiresAt is the end of validity of the invitation.
	ExpiresAt time.Time
}

// SessionInfo describes an active deposit session (OpenAPI DepositSession).
type SessionInfo struct {
	// ID is the session record ("ds_" + ULID), for the server only.
	ID string
	// Email is the verified address of the depositor, normalized.
	Email string
	// Kind is the depositor kind.
	Kind Kind
	// ExpiresAt is the absolute end of the session.
	ExpiresAt time.Time
	// Limits are the deposit limits of the tenant.
	Limits Limits
	// CanInvite is true for internal depositors (KindInternal only, never
	// KindInternalRemote). Invite still checks the client IP again.
	CanInvite bool
	// Invitation is set for external depositors only.
	Invitation *InvitationInfo
	// CSRFToken is the token the client must send in X-CSRF-Token with
	// every unsafe request.
	CSRFToken string
}

// Session is a newly opened deposit session.
type Session struct {
	// Token is the raw session token, the value of the session cookie. It
	// is only available when the session is created.
	Token string
	// Recognition is the new value of the recognition cookie
	// (RecognitionCookie) for an internal depositor: the HTTP layer sets it
	// with Max-Age RecognitionMaxAge. It is "" for an external depositor and
	// for an internal one depositing from outside, whose cookie is left
	// unchanged.
	Recognition string
	SessionInfo
}

// limits returns the deposit limits of t.
func limits(t *tenant.Tenant) Limits {
	return Limits{MaxTransferBytes: t.MaxTransferBytes, ExpiryDays: append([]int(nil), expiryDays...)}
}

// csrfToken derives the CSRF token of a session token.
func (s *Service) csrfToken(rawToken string) (string, error) {
	mac, err := s.keys.MAC(crypto.MACPurposeCSRF, []byte(rawToken))
	if err != nil {
		return "", fmt.Errorf("deposit: compute csrf token: %w", err)
	}
	return CSRFPrefix + base64.RawURLEncoding.EncodeToString(mac), nil
}

// openSession creates a session of kind for email in one transaction with
// prepare (the challenge consumption and address verification, or the use
// of an already verified address) and, for an external depositor, the use
// of the invitation inv (kind is then KindExternal).
func (s *Service) openSession(ctx context.Context, t *tenant.Tenant, email string, kind Kind, inv *store.Invitation, prepare func(txRepo, time.Time) error) (Session, error) {
	token, err := s.newToken(id.SessionTokenPrefix, id.SessionTokenBytes)
	if err != nil {
		return Session{}, fmt.Errorf("deposit: new session token: %w", err)
	}
	sessionID, err := s.newID(id.DepositSession)
	if err != nil {
		return Session{}, fmt.Errorf("deposit: new session id: %w", err)
	}
	csrf, err := s.csrfToken(token)
	if err != nil {
		return Session{}, err
	}
	now := s.now()
	rec := store.DepositSession{
		ID: sessionID, TokenHash: tokenHash(token), Email: email, Kind: kind,
		CreatedAt: now, ExpiresAt: now.Add(s.sessionTTL),
	}
	if inv != nil {
		rec.InvitationID = inv.ID
	}
	err = s.repo.tx(ctx, t.ID, func(tx txRepo) error {
		if err := prepare(tx, now); err != nil {
			return err
		}
		if err := tx.createSession(ctx, rec); err != nil {
			return fmt.Errorf("deposit: create session: %w", err)
		}
		if inv == nil {
			return nil
		}
		if err := tx.touchInvitation(ctx, inv.ID, now); errors.Is(err, store.ErrNotFound) {
			return ErrInvitationGone
		} else if err != nil {
			return fmt.Errorf("deposit: use invitation: %w", err)
		}
		return nil
	})
	if err != nil {
		return Session{}, err
	}
	info := SessionInfo{
		ID: rec.ID, Email: rec.Email, Kind: rec.Kind, ExpiresAt: rec.ExpiresAt, Limits: limits(t),
		CanInvite: rec.Kind == KindInternal, CSRFToken: csrf,
	}
	if inv != nil {
		// TouchTx moved the expiry to 12 months after this use when later.
		expires := inv.ExpiresAt
		if next := store.InvitationExpiry(now); next.After(expires) {
			expires = next
		}
		info.Invitation = &InvitationInfo{ID: inv.ID, InvitedBy: inv.InvitedBy, ExpiresAt: expires}
	}
	return Session{Token: token, SessionInfo: info}, nil
}

// Session returns the active session whose cookie token is rawToken, with
// its CSRF token. It returns ErrUnauthenticated when the token is malformed,
// unknown in the tenant, ended or expired, and for an external depositor
// whose invitation is no longer active (a revoked invitation ends its
// sessions).
func (s *Service) Session(ctx context.Context, t *tenant.Tenant, rawToken string) (SessionInfo, error) {
	if !validToken(id.SessionTokenPrefix, rawToken) {
		return SessionInfo{}, ErrUnauthenticated
	}
	rec, err := s.repo.session(ctx, t.ID, tokenHash(rawToken), s.now())
	switch {
	case errors.Is(err, store.ErrNotFound):
		return SessionInfo{}, ErrUnauthenticated
	case err != nil:
		return SessionInfo{}, fmt.Errorf("deposit: read session: %w", err)
	}
	info := SessionInfo{
		ID: rec.ID, Email: rec.Email, Kind: rec.Kind, ExpiresAt: rec.ExpiresAt, Limits: limits(t),
		CanInvite: rec.Kind == KindInternal,
	}
	if rec.Kind == KindExternal {
		inv, err := s.activeInvitation(ctx, t.ID, rec.InvitationID)
		switch {
		case errors.Is(err, ErrInvitationGone):
			return SessionInfo{}, ErrUnauthenticated
		case err != nil:
			return SessionInfo{}, err
		}
		info.Invitation = &InvitationInfo{ID: inv.ID, InvitedBy: inv.InvitedBy, ExpiresAt: inv.ExpiresAt}
	}
	if info.CSRFToken, err = s.csrfToken(rawToken); err != nil {
		return SessionInfo{}, err
	}
	return info, nil
}

// CheckCSRF reports whether header is the CSRF token of the session token
// rawToken. The MAC comparison runs in constant time.
func (s *Service) CheckCSRF(rawToken, header string) bool {
	encoded, ok := strings.CutPrefix(header, CSRFPrefix)
	if !ok || rawToken == "" {
		return false
	}
	mac, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return false
	}
	valid, err := s.keys.VerifyMAC(crypto.MACPurposeCSRF, mac, []byte(rawToken))
	return err == nil && valid
}

// End ends the session whose cookie token is rawToken. It returns
// ErrUnauthenticated when no such session is active in the tenant.
func (s *Service) End(ctx context.Context, t *tenant.Tenant, rawToken string) error {
	if !validToken(id.SessionTokenPrefix, rawToken) {
		return ErrUnauthenticated
	}
	err := s.repo.endSession(ctx, t.ID, tokenHash(rawToken), s.now())
	switch {
	case errors.Is(err, store.ErrNotFound):
		return ErrUnauthenticated
	case err != nil:
		return fmt.Errorf("deposit: end session: %w", err)
	}
	return nil
}
