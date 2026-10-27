package adminauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/notify"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Rules of the administrator authentication (CLAUDE.md sections 6.5, 6.6
// and 16.2; plan of step 10).
const (
	// DefaultIdleTimeout is the idle timeout of a session when
	// Options.IdleTimeout is not set (TT_ADMIN_SESSION_IDLE_TIMEOUT).
	DefaultIdleTimeout = 30 * time.Minute
	// DefaultMaxAge is the absolute lifetime of a session when
	// Options.MaxAge is not set (TT_ADMIN_SESSION_MAX_AGE).
	DefaultMaxAge = 12 * time.Hour
	// DefaultStateTTL is the lifetime of an intermediate session state
	// (TOTP awaited, enrollment required) when Options.StateTTL is not set.
	DefaultStateTTL = 5 * time.Minute
	// ActivationTTL is the validity of an activation link.
	ActivationTTL = 72 * time.Hour
	// PendingTOTPTTL is the validity of a pending TOTP secret: a secret
	// generated longer ago can no longer be confirmed, and the enrollment
	// must be restarted.
	PendingTOTPTTL = 15 * time.Minute

	// MinPasswordLen and MaxPasswordLen bound a new password, in characters
	// (Unicode code points). There is no other rule.
	MinPasswordLen = 12
	MaxPasswordLen = 1024
	// MaxUsernameLen bounds the username of a login attempt, in
	// characters (OpenAPI LoginRequest).
	MaxUsernameLen = 64
	// MaxRecoveryCodeLen bounds a typed recovery code, in bytes (OpenAPI
	// TotpCode.recoveryCode).
	MaxRecoveryCodeLen = 32

	// LoginUserIPMaxFailures failed logins of one username from one client
	// IP within LoginWindow lock that pair for LoginLockDuration.
	LoginUserIPMaxFailures = 5
	// LoginIPMaxFailures failed logins (password or second factor) from
	// one client IP within LoginWindow lock that IP for LoginLockDuration.
	LoginIPMaxFailures = 20
	// TOTPAdminMaxFailures wrong second factors of one administrator
	// within LoginWindow, from any IP, lock their second factor for
	// LoginLockDuration. Only a holder of the password reaches that step,
	// so this lock cannot be triggered anonymously; it bounds the guessing
	// of TOTP codes across sessions and IPs.
	TOTPAdminMaxFailures = 5
	// LoginWindow is the sliding window of the login limits.
	LoginWindow = 15 * time.Minute
	// LoginLockDuration is how long a login limit stays locked.
	LoginLockDuration = 15 * time.Minute
	// MaxSessionTOTPFailures wrong second factors end the session: the
	// intermediate session of a login, or an authenticated session through
	// its confirmations (Service.ConfirmTOTP).
	MaxSessionTOTPFailures = 5
	// RecoveryCodeCount is the number of recovery codes issued at each TOTP
	// confirmation.
	RecoveryCodeCount = 8

	// SessionTokenPrefix starts a session token (the __Host-tt_admin
	// cookie value): "as_" + 43 base62 characters (256 bits).
	SessionTokenPrefix = "as"
	// ActivationTokenPrefix starts an activation link token: "act_" + 43
	// base62 characters (256 bits).
	ActivationTokenPrefix = "act"
	// CSRFPrefix starts every CSRF token.
	CSRFPrefix = "csrf_"
	// ActivationPath is the path of the activation page of the web
	// interface on the admin host. The link is
	// AdminBaseURL + ActivationPath + "#" + token: the token is in the
	// fragment, so that it never reaches a server log or a Referer header;
	// the page posts it to /api/v1/admin/activation.
	ActivationPath = "/admin/activate"
	// DefaultIssuer names the TOTP account in authenticator apps.
	DefaultIssuer = "TransTeira"

	// tokenBytes is the entropy of the session and activation tokens.
	tokenBytes = 32
	// logScope names the admin login limits in the rate_limited security
	// events.
	logScope = "admin_login"
)

// dummyHash is an argon2id hash with the production parameters of an
// unknown password. An unknown username, a disabled account or one without
// a password is verified against it, so that a login costs the same work
// whether the account exists or not (threat T-65).
const dummyHash = "$argon2id$v=19$m=65536,t=3,p=1$dHJhbnN0ZWlyYS1kdW1teQ$Jx5O+O6jh9C1sCFsW2bS7tHDiO2+W7nl8w7cLOhqv0k" // gitleaks:allow

// Keys computes and verifies the MACs keyed by the master key (purpose
// crypto.MACPurposeAdminCSRF). *masterkey.Keyring implements it: its MACs
// use the current master key only, so that once a rotation switches
// TT_MASTER_KEY_FILE to the new key, the CSRF tokens of the open sessions
// no longer verify (see [Service.CheckCSRF]).
type Keys interface {
	MAC(p crypto.MACPurpose, parts ...[]byte) ([]byte, error)
	VerifyMAC(p crypto.MACPurpose, mac []byte, parts ...[]byte) (bool, error)
}

// Vault seals and opens the secrets protected by the master key.
// *masterkey.Vault implements it.
type Vault interface {
	// WrapSystem seals plaintext for purpose p (crypto.PurposeAdminTOTP)
	// and returns the system secret to store, with its ID; it stores
	// nothing.
	WrapSystem(p crypto.Purpose, plaintext []byte) (store.SystemSecret, error)
	// OpenSystem reads and unseals the system secret secretID.
	OpenSystem(ctx context.Context, p crypto.Purpose, secretID string) ([]byte, error)
}

// PasswordHasher hashes and verifies passwords with argon2id, with a
// bounded concurrency. *crypto.PasswordHasher implements it.
type PasswordHasher interface {
	HashPassword(ctx context.Context, password []byte) (string, error)
	VerifyPassword(ctx context.Context, encoded string, password []byte) (bool, error)
}

// SecurityLog writes security events. *securitylog.Logger implements it.
type SecurityLog interface {
	Log(ev securitylog.Event) error
}

// Options tunes a [Service].
type Options struct {
	// IdleTimeout ends a session unused for that long (DefaultIdleTimeout
	// when <= 0).
	IdleTimeout time.Duration
	// MaxAge ends a session that long after its creation (DefaultMaxAge
	// when <= 0).
	MaxAge time.Duration
	// StateTTL ends an intermediate session state that long after it began
	// (DefaultStateTTL when <= 0).
	StateTTL time.Duration
	// SetupToken is the first-run setup token (TT_SETUP_TOKEN, or the
	// token the application generated and logged while no administrator
	// exists). Empty, the setup is refused.
	SetupToken string
	// AdminBaseURL is the absolute URL of the admin host the activation
	// links point to, such as "https://admin.transfer.example.com" (the
	// first TT_ADMIN_HOSTS entry): an http or https URL without path, query
	// or fragment. It is required.
	AdminBaseURL string
	// Issuer names the TOTP account in authenticator apps (DefaultIssuer
	// when empty).
	Issuer string
	// Now is the clock (time.Now when nil).
	Now func() time.Time
	// Logger receives the failures that never fail a request (security log
	// and audit writes on refusals). Nil discards. It never receives a
	// username, a password, a token, a secret or a code.
	Logger *slog.Logger
	// Audit is the shared audit writer of the application, which publishes
	// the events it writes; nil means a writer of its own over the
	// database, publishing nothing.
	Audit *audit.Writer
}

// Service authenticates administrators and manages their accounts. It is
// safe for concurrent use.
type Service struct {
	repo       repo
	keys       Keys
	vault      Vault
	hasher     PasswordHasher
	seclog     SecurityLog
	logger     *slog.Logger
	idle       time.Duration
	maxAge     time.Duration
	stateTTL   time.Duration
	setupToken string
	baseURL    string
	issuer     string
	clock      func() time.Time
	// Random sources and encoders, replaced by the tests.
	newToken      func(prefix string, entropyBytes int) (string, error)
	newID         func(p id.Prefix) (string, error)
	newTOTPSecret func() ([]byte, error)
	newRecovery   func(n int) ([]string, error)
	qrPNG         func(text string) ([]byte, error)
	recoveryMAC   func(totpSecret []byte, normalized string) ([]byte, error)
}

// New returns a service over db. keys computes the CSRF tokens, vault seals
// and opens the TOTP secrets, hasher verifies the passwords and seclog
// receives the security events. Every dependency is required. It fails
// when opts.AdminBaseURL is not a valid base URL.
func New(db *store.DB, keys Keys, vault Vault, hasher PasswordHasher, seclog SecurityLog, opts Options) (*Service, error) {
	base, err := checkBaseURL(opts.AdminBaseURL)
	if err != nil {
		return nil, err
	}
	if opts.IdleTimeout <= 0 {
		opts.IdleTimeout = DefaultIdleTimeout
	}
	if opts.MaxAge <= 0 {
		opts.MaxAge = DefaultMaxAge
	}
	if opts.StateTTL <= 0 {
		opts.StateTTL = DefaultStateTTL
	}
	if opts.Issuer == "" {
		opts.Issuer = DefaultIssuer
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	s := &Service{
		repo: storeRepo{db: db, writer: audit.OrNew(opts.Audit, db)}, keys: keys, vault: vault, hasher: hasher,
		seclog: seclog, logger: opts.Logger, idle: opts.IdleTimeout, maxAge: opts.MaxAge, stateTTL: opts.StateTTL,
		setupToken: opts.SetupToken, baseURL: base, issuer: opts.Issuer, clock: opts.Now,
		newToken: id.NewToken, newTOTPSecret: crypto.GenerateTOTPSecret, newRecovery: crypto.GenerateRecoveryCodes,
		qrPNG: notify.QRPNG, recoveryMAC: crypto.RecoveryCodeMAC,
	}
	s.newID = id.NewGenerator(s.clock, nil).New
	return s, nil
}

// checkBaseURL validates the admin base URL and returns it without a
// trailing slash.
func checkBaseURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSuffix(raw, "/"))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil ||
		u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return "", errors.New("adminauth: the admin base url must be an http(s) url without path, query or fragment")
	}
	return u.String(), nil
}

// now returns the clock at the precision of the stored timestamps.
func (s *Service) now() time.Time {
	return s.clock().UTC().Truncate(time.Millisecond)
}

// tokenHash returns the SHA-256 of a bearer token, as the store keeps it.
func tokenHash(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

// validToken reports whether tok has the shape of a token with prefix p.
func validToken(p, tok string) bool {
	n := id.TokenLen(tokenBytes)
	return id.TokenValid(p, tok, n, n)
}

// checkNewPassword applies the password policy: MinPasswordLen to
// MaxPasswordLen characters, nothing else. field names the request field.
func checkNewPassword(password, field string) error {
	if n := utf8.RuneCountInString(password); n < MinPasswordLen || n > MaxPasswordLen {
		return invalid(field)
	}
	return nil
}

// Account is an administrator account as the service exposes it: the
// fields of the OpenAPI Admin and AdminMe schemas, without any credential.
type Account struct {
	// ID is the identifier ("adm_" + ULID).
	ID string
	// Username is the login, lower-case.
	Username string
	// Email is the mail address.
	Email string
	// Role is the role.
	Role store.AdminRole
	// TenantIDs are the tenants of a delegated admin, sorted; empty for a
	// super admin, which reaches every tenant.
	TenantIDs []tenant.ID
	// TOTPEnabled reports whether TOTP is enrolled.
	TOTPEnabled bool
	// RequireTOTP reports whether TOTP is mandatory (always for a super
	// admin).
	RequireTOTP bool
	// Disabled reports a blocked account.
	Disabled bool
	// Activated reports whether a password is set (false until the
	// activation link is used, and after a credentials reset).
	Activated bool
	// Language is the preferred language, "" for the default.
	Language string
	// LastLoginAt is the last completed login, zero if none.
	LastLoginAt time.Time
	// CreatedAt is the creation time.
	CreatedAt time.Time
}

// accountOf returns the public view of a.
func accountOf(a store.Admin) Account {
	return Account{
		ID: a.ID, Username: a.Username, Email: a.Email, Role: a.Role, TenantIDs: a.TenantIDs,
		TOTPEnabled: a.TOTPEnabled, RequireTOTP: a.RequireTOTP, Disabled: a.Disabled, Activated: a.PasswordHash != "",
		Language: a.Language, LastLoginAt: a.LastLoginAt, CreatedAt: a.CreatedAt,
	}
}

// Session is a session newly opened or rotated: the HTTP layer sets Token
// as the __Host-tt_admin cookie and returns State and CSRFToken (OpenAPI
// LoginState).
type Session struct {
	// Token is the bearer token of the cookie. It is never stored: only its
	// SHA-256 is.
	Token string
	// CSRFToken is the token to send in X-CSRF-Token with every request
	// with side effects.
	CSRFToken string
	// State is the login state: the next step, or authenticated.
	State store.AdminSessionState
	// ExpiresAt is the absolute end of the session (for the cookie).
	ExpiresAt time.Time
	// StateExpiresAt is the end of an intermediate login state (TOTP or
	// enrollment awaited), zero for the authenticated state. The cookie of
	// an intermediate session lasts until then.
	StateExpiresAt time.Time
}

// Principal is the session of a request, resolved by [Service.Resolve],
// with its administrator. The HTTP layer passes it back to the service
// methods; it can only be built by Resolve.
type Principal struct {
	// SessionID is the internal session ID ("as_" + ULID), for logs.
	SessionID string
	// State is the login state of the session.
	State store.AdminSessionState
	// CSRFToken is the CSRF token of the session.
	CSRFToken string
	// ExpiresAt is the absolute end of the session.
	ExpiresAt time.Time
	// Admin is the administrator of the session.
	Admin Account
	// tokenHash is the hash of the presented token, for the rotations.
	tokenHash []byte
}

// csrfToken derives the CSRF token of a session token.
func (s *Service) csrfToken(rawToken string) (string, error) {
	mac, err := s.keys.MAC(crypto.MACPurposeAdminCSRF, []byte(rawToken))
	if err != nil {
		return "", fmt.Errorf("adminauth: compute csrf token: %w", err)
	}
	return CSRFPrefix + base64.RawURLEncoding.EncodeToString(mac), nil
}

// CheckCSRF reports whether header is the CSRF token of the session token
// rawToken. The MAC comparison runs in constant time.
//
// The token is a MAC under the current master key, recomputed rather than
// stored. After a master key rotation, once TT_MASTER_KEY_FILE holds the
// new key, the tokens held by open sessions no longer verify: the session
// itself stays valid, its requests with side effects get 403 csrf-invalid,
// and the client must fetch GET /admin/me again to get the new token.
func (s *Service) CheckCSRF(rawToken, header string) bool {
	encoded, ok := strings.CutPrefix(header, CSRFPrefix)
	if !ok || !validToken(SessionTokenPrefix, rawToken) {
		return false
	}
	mac, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return false
	}
	valid, err := s.keys.VerifyMAC(crypto.MACPurposeAdminCSRF, mac, []byte(rawToken))
	return err == nil && valid
}

// stateFor returns the state of a session opened for a after its password:
// the TOTP code when TOTP is enrolled, the enrollment when TOTP is required
// but not enrolled, authenticated otherwise. A super admin always requires
// TOTP: a password alone never grants them a full session.
func stateFor(a store.Admin) store.AdminSessionState {
	switch {
	case a.TOTPEnabled:
		return store.SessionTOTPRequired
	case a.RequireTOTP || a.Role == store.RoleSuperAdmin:
		return store.SessionTOTPEnrollmentRequired
	}
	return store.SessionAuthenticated
}

// stateExpiry returns the end of state started at now: zero for the
// authenticated state.
func (s *Service) stateExpiry(state store.AdminSessionState, now time.Time) time.Time {
	if state == store.SessionAuthenticated {
		return time.Time{}
	}
	return now.Add(s.stateTTL)
}

// newSession prepares a session of adminID in state from clientIP, to be
// created by the caller, and the Session to return.
func (s *Service) newSession(adminID string, state store.AdminSessionState, clientIP netip.Addr, now time.Time) (store.AdminSession, Session, error) {
	token, err := s.newToken(SessionTokenPrefix, tokenBytes)
	if err != nil {
		return store.AdminSession{}, Session{}, fmt.Errorf("adminauth: new session token: %w", err)
	}
	sessionID, err := s.newID(id.AdminSession)
	if err != nil {
		return store.AdminSession{}, Session{}, fmt.Errorf("adminauth: new session id: %w", err)
	}
	csrf, err := s.csrfToken(token)
	if err != nil {
		return store.AdminSession{}, Session{}, err
	}
	row := store.AdminSession{
		ID: sessionID, TokenHash: tokenHash(token), AdminID: adminID, State: state, CreatedAt: now,
		ExpiresAt: now.Add(s.maxAge), StateExpiresAt: s.stateExpiry(state, now), ClientIP: clientIP,
	}
	return row, Session{
		Token: token, CSRFToken: csrf, State: state, ExpiresAt: row.ExpiresAt, StateExpiresAt: row.StateExpiresAt,
	}, nil
}

// openSession creates a session of adminID in state, in its own
// transaction.
func (s *Service) openSession(ctx context.Context, adminID string, state store.AdminSessionState, clientIP netip.Addr) (Session, error) {
	row, out, err := s.newSession(adminID, state, clientIP, s.now())
	if err != nil {
		return Session{}, err
	}
	err = s.repo.tx(ctx, func(tx txRepo) error { return tx.createSession(ctx, row) })
	if err != nil {
		return Session{}, fmt.Errorf("adminauth: create session: %w", err)
	}
	return out, nil
}

// rotation is a session rotation prepared by newRotation: the new token
// and the Session to return once the rotation is stored.
type rotation struct {
	sessionID string
	oldHash   []byte
	newHash   []byte
	now       time.Time
	out       Session
}

// newRotation prepares the move of the session of p to state with a new
// token (session fixation, T-59).
func (s *Service) newRotation(p Principal, state store.AdminSessionState) (rotation, error) {
	token, err := s.newToken(SessionTokenPrefix, tokenBytes)
	if err != nil {
		return rotation{}, fmt.Errorf("adminauth: new session token: %w", err)
	}
	csrf, err := s.csrfToken(token)
	if err != nil {
		return rotation{}, err
	}
	now := s.now()
	return rotation{
		sessionID: p.SessionID, oldHash: p.tokenHash, newHash: tokenHash(token), now: now,
		out: Session{
			Token: token, CSRFToken: csrf, State: state, ExpiresAt: p.ExpiresAt, StateExpiresAt: s.stateExpiry(state, now),
		},
	}, nil
}

// rotate moves the session of p to state with a new token, in its own
// transaction, and returns it.
func (s *Service) rotate(ctx context.Context, p Principal, state store.AdminSessionState) (Session, error) {
	r, err := s.newRotation(p, state)
	if err != nil {
		return Session{}, err
	}
	err = s.repo.rotateSession(ctx, r.sessionID, r.oldHash, r.newHash, state, r.out.StateExpiresAt, r.now, s.idle)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return Session{}, ErrUnauthenticated
	case err != nil:
		return Session{}, fmt.Errorf("adminauth: rotate session: %w", err)
	}
	return r.out, nil
}

// logEvent writes a security event (the admin host belongs to no tenant);
// a write failure is only reported on the application log.
func (s *Service) logEvent(ctx context.Context, ip netip.Addr, typ securitylog.EventType, fields ...securitylog.Field) {
	if err := s.seclog.Log(securitylog.Event{Type: typ, IP: ip, Fields: fields}); err != nil {
		s.logger.ErrorContext(ctx, "security log write failed",
			slog.String("event", string(typ)), slog.String("error", err.Error()))
	}
}

// adminEvent returns an audit event of actor (an administrator) on the
// account target.
func adminEvent(actor string, ip netip.Addr, action audit.Action, targetID string, details map[string]any) audit.Event {
	return audit.Event{
		ActorKind: store.ActorAdmin, Actor: actor, IP: ip, Action: action,
		ObjectKind: audit.ObjectAdmin, ObjectID: targetID, Details: details,
	}
}

// record writes an audit event outside a transaction, for events that
// must not change the outcome of the request (refusals, login steps
// already committed); a failure is only reported on the application log.
func (s *Service) record(ctx context.Context, ev audit.Event) {
	if err := s.repo.audit(ctx, ev); err != nil {
		s.logger.ErrorContext(ctx, "audit write failed",
			slog.String("action", string(ev.Action)), slog.String("admin_id", ev.ObjectID), slog.String("error", err.Error()))
	}
}
