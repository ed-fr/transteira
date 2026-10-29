package mytransfers

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// SessionInfo describes an active session (OpenAPI MyTransfersSession).
type SessionInfo struct {
	// ID is the session record ("mts_" + ULID), for the server only.
	ID string
	// Email is the normalized address of the sender; every transfer
	// operation is scoped to it.
	Email string
	// ExpiresAt is the absolute end of the session.
	ExpiresAt time.Time
	// CSRFToken is the token the client must send in X-CSRF-Token with
	// every unsafe request.
	CSRFToken string
}

// Session is a newly opened session.
type Session struct {
	// Token is the raw session token, the value of the session cookie. It
	// is only available when the session is opened.
	Token string
	SessionInfo
}

// clientKey returns the failure counter key of ip: the address for IPv4,
// its /64 for IPv6 (as the HTTP rate limits key their clients).
func clientKey(ip netip.Addr) string {
	if !ip.IsValid() {
		return "invalid"
	}
	ip = ip.Unmap().WithZone("")
	if ip.Is4() {
		return ip.String()
	}
	p, _ := ip.Prefix(64) // cannot fail: 64 bits fit an IPv6 address
	return p.String()
}

// csrfToken derives the CSRF token of a session token.
func (s *Service) csrfToken(rawToken string) (string, error) {
	mac, err := s.keys.MAC(crypto.MACPurposeMeCSRF, []byte(rawToken))
	if err != nil {
		return "", fmt.Errorf("mytransfers: compute csrf token: %w", err)
	}
	return CSRFPrefix + base64.RawURLEncoding.EncodeToString(mac), nil
}

// StartSession exchanges the access link token linkToken for a session of
// SessionTTL bound to the tenant and to the address of the link (T-208):
// the link is consumed and the session created in one transaction, then
// audited as my_transfers.signed_in.
//
// A malformed, unknown, expired, already used or foreign token returns
// ErrAccessLinkInvalid and writes access_link_invalid to the security log;
// it also counts against the client of ip, which is locked out after
// SessionFailureLimit failures within SessionFailureWindow: while locked,
// every attempt returns a *RateLimitError (logged as rate_limited, scope
// ScopeSessionIP) without looking the token up.
func (s *Service) StartSession(ctx context.Context, t *tenant.Tenant, ip netip.Addr, linkToken string) (Session, error) {
	key := clientKey(ip)
	if locked, retry := s.failures.Locked(key); locked {
		s.logEvent(ctx, t, ip, securitylog.RateLimited, securitylog.Field{Key: securitylog.KeyScope, Value: ScopeSessionIP})
		return Session{}, &RateLimitError{RetryAfter: retry}
	}
	if !validToken(id.AccessLinkTokenPrefix, linkToken) {
		return Session{}, s.linkInvalid(ctx, t, ip, key)
	}
	token, err := s.newToken(SessionTokenPrefix, SessionTokenBytes)
	if err != nil {
		return Session{}, fmt.Errorf("mytransfers: new session token: %w", err)
	}
	csrf, err := s.csrfToken(token)
	if err != nil {
		return Session{}, err
	}
	now := s.now()
	rec, err := s.repo.openSession(ctx, t.ID, tokenHash(linkToken), tokenHash(token), now, now.Add(SessionTTL))
	switch {
	case errors.Is(err, store.ErrNotFound):
		return Session{}, s.linkInvalid(ctx, t, ip, key)
	case err != nil:
		return Session{}, fmt.Errorf("mytransfers: open session: %w", err)
	}
	s.record(ctx, t, ip, rec.Email, audit.ActionMyTransfersSignedIn, audit.ObjectSenderSession, rec.ID, nil)
	return Session{Token: token, SessionInfo: SessionInfo{
		ID: rec.ID, Email: rec.Email, ExpiresAt: rec.ExpiresAt, CSRFToken: csrf,
	}}, nil
}

// linkInvalid logs an access_link_invalid event, counts the failure of the
// client key and returns ErrAccessLinkInvalid.
func (s *Service) linkInvalid(ctx context.Context, t *tenant.Tenant, ip netip.Addr, key string) error {
	s.logEvent(ctx, t, ip, securitylog.AccessLinkInvalid)
	s.failures.Fail(key)
	return ErrAccessLinkInvalid
}

// Session returns the active session of tenant t whose cookie token is
// rawToken, with its CSRF token. It returns ErrUnauthenticated when the
// token is malformed, unknown in the tenant, ended or expired.
func (s *Service) Session(ctx context.Context, t *tenant.Tenant, rawToken string) (SessionInfo, error) {
	if !validToken(SessionTokenPrefix, rawToken) {
		return SessionInfo{}, ErrUnauthenticated
	}
	rec, err := s.repo.session(ctx, t.ID, tokenHash(rawToken), s.now())
	switch {
	case errors.Is(err, store.ErrNotFound):
		return SessionInfo{}, ErrUnauthenticated
	case err != nil:
		return SessionInfo{}, fmt.Errorf("mytransfers: read session: %w", err)
	}
	csrf, err := s.csrfToken(rawToken)
	if err != nil {
		return SessionInfo{}, err
	}
	return SessionInfo{ID: rec.ID, Email: rec.Email, ExpiresAt: rec.ExpiresAt, CSRFToken: csrf}, nil
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
	valid, err := s.keys.VerifyMAC(crypto.MACPurposeMeCSRF, mac, []byte(rawToken))
	return err == nil && valid
}

// End ends the session of tenant t whose cookie token is rawToken. It
// returns ErrUnauthenticated when no such session is active in the tenant.
func (s *Service) End(ctx context.Context, t *tenant.Tenant, rawToken string) error {
	if !validToken(SessionTokenPrefix, rawToken) {
		return ErrUnauthenticated
	}
	err := s.repo.endSession(ctx, t.ID, tokenHash(rawToken), s.now())
	switch {
	case errors.Is(err, store.ErrNotFound):
		return ErrUnauthenticated
	case err != nil:
		return fmt.Errorf("mytransfers: end session: %w", err)
	}
	return nil
}
