package store

import (
	"context"
	"database/sql"
	"net/netip"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/tenant"
)

// AdminSessionState is the state of an administrator session.
type AdminSessionState string

// Administrator session states. An intermediate state only opens the
// endpoint of the next login step and expires on its own (StateExpiresAt).
const (
	// SessionTOTPRequired: the password was right, the TOTP code is
	// awaited.
	SessionTOTPRequired AdminSessionState = "totp_required"
	// SessionTOTPEnrollmentRequired: the password was right, the TOTP
	// enrollment is mandatory before anything else.
	SessionTOTPEnrollmentRequired AdminSessionState = "totp_enrollment_required"
	// SessionAuthenticated: the login is complete.
	SessionAuthenticated AdminSessionState = "authenticated"
)

// valid reports whether s is a known state.
func (s AdminSessionState) valid() bool {
	return s == SessionTOTPRequired || s == SessionTOTPEnrollmentRequired || s == SessionAuthenticated
}

// AdminAuthMethod is how an administrator session was opened (migration
// 0027, brief amendment A1).
type AdminAuthMethod string

// Session authentication methods.
const (
	// AuthPassword: the local password, then TOTP (every session before
	// 2.0).
	AuthPassword AdminAuthMethod = "password"
	// AuthOIDC: an OpenID Connect single sign-on login, opened directly in
	// SessionAuthenticated (the second factor is delegated to the
	// provider and recorded in SSOMFA).
	AuthOIDC AdminAuthMethod = "oidc"
)

// Limits of the recovery codes.
const (
	// MaxRecoveryCodes bounds the recovery codes of an administrator.
	MaxRecoveryCodes = 20
)

// adminSessionColumns is the column list read by the session queries.
const adminSessionColumns = `id, token_hash, admin_id, state, created_at, last_seen_at, expires_at, state_expires_at,
	totp_failures, client_ip, auth_method, sso_issuer, sso_client_id, sso_mfa`

// Statements of the AdminSessions, AdminRecoveryCodes and AdminActivations
// repositories. A session is valid while "expires_at > now AND
// last_seen_at > now - idle AND (state_expires_at IS NULL OR
// state_expires_at > now)", the three arguments following that order.
var (
	qAdminSessionInsert = systemQuery(
		`INSERT INTO admin_sessions (`+adminSessionColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		reasonAdminAuth)
	qAdminSessionGet = systemQuery(
		`SELECT `+adminSessionColumns+` FROM admin_sessions WHERE token_hash = ?
		AND expires_at > ? AND last_seen_at > ? AND (state_expires_at IS NULL OR state_expires_at > ?)`,
		reasonAdminAuth)
	qAdminSessionTouch = systemQuery(
		`UPDATE admin_sessions SET last_seen_at = ? WHERE id = ?
		AND expires_at > ? AND last_seen_at > ? AND (state_expires_at IS NULL OR state_expires_at > ?)`,
		reasonAdminAuth)
	qAdminSessionRotate = systemQuery(
		`UPDATE admin_sessions SET token_hash = ?, state = ?, state_expires_at = ?, totp_failures = 0, last_seen_at = ?
		WHERE id = ? AND token_hash = ?
		AND expires_at > ? AND last_seen_at > ? AND (state_expires_at IS NULL OR state_expires_at > ?)`,
		reasonAdminAuth)
	qAdminSessionFailure = systemQuery(
		`UPDATE admin_sessions SET totp_failures = totp_failures + 1 WHERE id = ? RETURNING totp_failures`,
		reasonAdminAuth)
	qAdminSessionDelete = systemQuery(
		`DELETE FROM admin_sessions WHERE id = ?`,
		reasonAdminAuth)
	qAdminSessionDeleteByAdmin = systemQuery(
		`DELETE FROM admin_sessions WHERE admin_id = ? AND id <> ?`,
		reasonAdminAuth)
	// qAdminSessionDeleteSSO revokes the single sign-on sessions opened
	// through an (issuer, client ID) pair by the accounts attached to a
	// tenant.
	qAdminSessionDeleteSSO = systemQuery(
		`DELETE FROM admin_sessions WHERE auth_method = 'oidc' AND sso_issuer = ? AND sso_client_id = ?
		AND admin_id IN (SELECT admin_id FROM admin_tenants WHERE tenant_id = ?)`,
		reasonAdminAuth)
	// qAdminSessionDeleteSSOForAdmin revokes the single sign-on sessions
	// of one account opened through an (issuer, client ID) pair.
	qAdminSessionDeleteSSOForAdmin = systemQuery(
		`DELETE FROM admin_sessions WHERE admin_id = ? AND auth_method = 'oidc' AND sso_issuer = ? AND sso_client_id = ?`,
		reasonAdminAuth)
	qAdminSessionPurge = systemQuery(
		`DELETE FROM admin_sessions WHERE id IN (SELECT id FROM admin_sessions
		WHERE expires_at <= ? OR last_seen_at <= ? OR state_expires_at <= ? ORDER BY id LIMIT ?)`,
		reasonAdminAuth)

	qRecoveryDeleteAll = systemQuery(
		`DELETE FROM admin_recovery_codes WHERE admin_id = ?`,
		reasonAdminAuth)
	qRecoveryInsert = systemQuery(
		`INSERT INTO admin_recovery_codes (admin_id, code_hash, used_at) VALUES (?, ?, NULL)`,
		reasonAdminAuth)
	qRecoveryConsume = systemQuery(
		`UPDATE admin_recovery_codes SET used_at = ? WHERE admin_id = ? AND code_hash = ? AND used_at IS NULL`,
		reasonAdminAuth)
	qRecoveryCountUnused = systemQuery(
		`SELECT count(*) FROM admin_recovery_codes WHERE admin_id = ? AND used_at IS NULL`,
		reasonAdminAuth)

	qActivationInsert = systemQuery(
		`INSERT INTO admin_activations (id, admin_id, token_hash, created_at, expires_at, used_at, delivery, language)
		VALUES (?, ?, ?, ?, ?, NULL, ?, ?)`,
		reasonAdminAuth)
	// qActivationConsume marks a link used, only once and only before it
	// expires, and returns its admin and its delivery.
	qActivationConsume = systemQuery(
		`UPDATE admin_activations SET used_at = ? WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?
		RETURNING admin_id, delivery`,
		reasonAdminAuth)
	qActivationDeleteByAdmin = systemQuery(
		`DELETE FROM admin_activations WHERE admin_id = ?`,
		reasonAdminAuth)
	qActivationPurge = systemQuery(
		`DELETE FROM admin_activations WHERE id IN (SELECT id FROM admin_activations
		WHERE used_at IS NOT NULL OR expires_at <= ? ORDER BY id LIMIT ?)`,
		reasonAdminAuth)
)

// authWrite runs fn in a write transaction for the authentication
// repositories and wraps its error with op.
func (db *DB) authWrite(ctx context.Context, op string, fn func(*SystemTx) error) error {
	if err := db.systemScope(reasonAdminAuth).Tx(ctx, fn); err != nil {
		return wrap(op, err)
	}
	return nil
}

// authRead runs fn in a read transaction for the authentication
// repositories and wraps its error with op.
func (db *DB) authRead(ctx context.Context, op string, fn func(*SystemTx) error) error {
	if err := db.systemScope(reasonAdminAuth).ReadTx(ctx, fn); err != nil {
		return wrap(op, err)
	}
	return nil
}

// purgeSystem runs the batched delete q (its arguments, then the batch
// size) in successive write transactions until a batch deletes fewer rows
// than the batch size, and returns the total deleted. With a lock name,
// each transaction first takes that lock.
func (db *DB) purgeSystem(ctx context.Context, reason, op string, lock lockName, q SystemQuery, args ...any) (int64, error) {
	var total int64
	for {
		var n int64
		err := db.systemScope(reason).Tx(ctx, func(tx *SystemTx) error {
			if lock != "" {
				if err := tx.lock(ctx, lock); err != nil {
					return err
				}
			}
			res, err := tx.Exec(ctx, q, append(args, db.purgeBatch)...)
			if err != nil {
				return err
			}
			n, err = res.RowsAffected()
			return err
		})
		if err != nil {
			return total, wrap(op, err)
		}
		total += n
		if n < int64(db.purgeBatch) {
			return total, nil
		}
	}
}

// AdminSession is an administrator session, carried by a cookie. Only the
// SHA-256 of the cookie token is stored.
type AdminSession struct {
	// ID is the internal identifier ("as_" + ULID), assigned by the caller.
	// It never leaves the server.
	ID string
	// TokenHash is the SHA-256 of the cookie token (TokenHashSize bytes).
	TokenHash []byte
	// AdminID is the administrator of the session.
	AdminID string
	// State is the login state.
	State AdminSessionState
	// CreatedAt is the creation time; the store's clock is used when it is
	// zero.
	CreatedAt time.Time
	// LastSeenAt is the last use, for the idle timeout; CreatedAt when it
	// is zero on creation.
	LastSeenAt time.Time
	// ExpiresAt is the absolute end of the session, after CreatedAt.
	ExpiresAt time.Time
	// StateExpiresAt is the end of an intermediate state (required for
	// them, zero for SessionAuthenticated).
	StateExpiresAt time.Time
	// TOTPFailures counts the wrong TOTP codes of the current state.
	TOTPFailures int
	// ClientIP is the client IP at creation (the zero Addr if unknown).
	ClientIP netip.Addr
	// AuthMethod is how the session was opened: AuthPassword when empty on
	// creation. An AuthOIDC session is created in SessionAuthenticated.
	AuthMethod AdminAuthMethod
	// SSOIssuer and SSOClientID are the issuer and the client ID of the
	// single sign-on login (AuthOIDC only, "" otherwise). The session
	// reaches a tenant only while the tenant's configuration admits them
	// ([TenantSSO.Admits]).
	SSOIssuer   string
	SSOClientID string
	// SSOMFA records whether the ID token of the login proved a
	// multi-factor authentication (AuthOIDC only, false otherwise).
	SSOMFA bool
}

// AdminSessions is the repository of administrator sessions. Its
// operations are system-scoped. Obtain it with [DB.AdminSessions].
//
// The idle timeout is a parameter of the lookups, so that the
// configuration (TT_ADMIN_SESSION_IDLE_TIMEOUT) applies to the sessions
// already open. Times are the caller's now.
type AdminSessions struct {
	db *DB
}

// AdminSessions returns the administrator session repository.
func (db *DB) AdminSessions() *AdminSessions { return &AdminSessions{db: db} }

// validity returns the three arguments of the validity condition at now.
func validity(now time.Time, idle time.Duration) []any {
	ms := toMillis(now)
	return []any{ms, toMillis(now.Add(-idle)), ms}
}

// checkStateExpiry checks the state and its expiry.
func checkStateExpiry(state AdminSessionState, stateExpires time.Time) error {
	switch {
	case !state.valid():
		return invalid("unknown session state")
	case (state == SessionAuthenticated) != stateExpires.IsZero():
		return invalid("an intermediate state needs an expiry, the authenticated state none")
	}
	return nil
}

// Create stores s in its own transaction (see [AdminSessions.CreateTx]).
func (r *AdminSessions) Create(ctx context.Context, s AdminSession) error {
	return r.db.authWrite(ctx, "create admin session", func(tx *SystemTx) error { return r.create(ctx, tx, s) })
}

// CreateTx stores s inside tx (the setup creates the super admin and its
// first session atomically). It returns ErrInvalid for a malformed field,
// ErrNotFound when the admin does not exist and ErrConflict when the ID or
// the token hash is already used.
func (r *AdminSessions) CreateTx(ctx context.Context, tx *SystemTx, s AdminSession) error {
	if err := r.create(ctx, tx, s); err != nil {
		return wrap("create admin session", err)
	}
	return nil
}

// create validates and inserts s in tx, returning raw errors.
func (r *AdminSessions) create(ctx context.Context, tx *SystemTx, s AdminSession) error {
	created := r.db.orNow(s.CreatedAt)
	seen := s.LastSeenAt
	if seen.IsZero() {
		seen = created
	}
	switch {
	case !id.Valid(id.AdminSession, s.ID):
		return invalid("malformed admin session id")
	case !validTokenHash(s.TokenHash):
		return invalid("token hash must hold %d bytes", TokenHashSize)
	case !id.Valid(id.Admin, s.AdminID):
		return invalid("malformed admin id")
	case !s.ExpiresAt.After(created):
		return invalid("session must expire after its creation")
	case s.TOTPFailures != 0:
		return invalid("a new session has no totp failure")
	}
	if err := checkStateExpiry(s.State, s.StateExpiresAt); err != nil {
		return err
	}
	method, issuer, clientID, mfa, err := sessionAuth(s)
	if err != nil {
		return err
	}
	var ip any
	if s.ClientIP.IsValid() {
		ip, _ = ipText(s.ClientIP)
	}
	var stateExpires any
	if !s.StateExpiresAt.IsZero() {
		stateExpires = toMillis(s.StateExpiresAt)
	}
	_, err = tx.Exec(ctx, qAdminSessionInsert, s.ID, s.TokenHash, s.AdminID, string(s.State), toMillis(created),
		toMillis(seen), toMillis(s.ExpiresAt), stateExpires, 0, ip, string(method), issuer, clientID, mfa)
	return err
}

// sessionAuth validates the authentication method of s and returns the
// values of auth_method, sso_issuer, sso_client_id and sso_mfa (NULL for
// a password session, as the constraints of migration 0027 require).
func sessionAuth(s AdminSession) (AdminAuthMethod, any, any, any, error) {
	switch s.AuthMethod {
	case "", AuthPassword:
		if s.SSOIssuer != "" || s.SSOClientID != "" || s.SSOMFA {
			return "", nil, nil, nil, invalid("a password session has no single sign-on fields")
		}
		return AuthPassword, nil, nil, nil, nil
	case AuthOIDC:
		switch {
		case s.State != SessionAuthenticated:
			return "", nil, nil, nil, invalid("a single sign-on session is created authenticated")
		case !validIdentityKey(s.SSOIssuer, s.SSOClientID):
			return "", nil, nil, nil, invalid("malformed single sign-on issuer or client id")
		}
		return AuthOIDC, s.SSOIssuer, s.SSOClientID, s.SSOMFA, nil
	}
	return "", nil, nil, nil, invalid("unknown session authentication method")
}

// GetByTokenHash returns the session whose cookie token hashes to hash,
// provided it is valid at now: before its absolute expiry, used within the
// last idle, and, in an intermediate state, before the state expiry. It
// returns ErrNotFound otherwise and ErrInvalid for a hash of the wrong
// size. It does not refresh LastSeenAt (see [AdminSessions.Touch]).
func (r *AdminSessions) GetByTokenHash(ctx context.Context, hash []byte, now time.Time, idle time.Duration) (AdminSession, error) {
	if !validTokenHash(hash) {
		return AdminSession{}, invalid("token hash must hold %d bytes", TokenHashSize)
	}
	var s AdminSession
	err := r.db.authRead(ctx, "get admin session", func(tx *SystemTx) error {
		var (
			state                  string
			created, seen, expires int64
			stateExpires           sql.NullInt64
			ip, issuer, clientID   sql.NullString
			method                 string
			mfa                    sql.NullBool
		)
		err := tx.QueryRow(ctx, qAdminSessionGet, append([]any{hash}, validity(now, idle)...)...).Scan(&s.ID, &s.TokenHash,
			&s.AdminID, &state, &created, &seen, &expires, &stateExpires, &s.TOTPFailures, &ip, &method, &issuer, &clientID, &mfa)
		s.State = AdminSessionState(state)
		s.AuthMethod, s.SSOIssuer, s.SSOClientID, s.SSOMFA = AdminAuthMethod(method), issuer.String, clientID.String, mfa.Bool
		s.CreatedAt, s.LastSeenAt, s.ExpiresAt = fromMillis(created), fromMillis(seen), fromMillis(expires)
		s.StateExpiresAt, s.ClientIP = nullMillis(stateExpires), parseIP(ip.String)
		return err
	})
	if err != nil {
		return AdminSession{}, err
	}
	return s, nil
}

// Touch records a use of the session sessionID at now (sliding idle
// timeout), provided it is still valid at now. It returns ErrNotFound
// otherwise: an expired session is never revived.
func (r *AdminSessions) Touch(ctx context.Context, sessionID string, now time.Time, idle time.Duration) error {
	return r.db.authWrite(ctx, "touch admin session", func(tx *SystemTx) error {
		res, err := tx.Exec(ctx, qAdminSessionTouch, append([]any{toMillis(now), sessionID}, validity(now, idle)...)...)
		if err != nil {
			return err
		}
		return expectOne(res)
	})
}

// Rotate replaces, atomically, the token hash of the session sessionID
// (oldHash, which the caller just presented, by newHash), its state and
// state expiry, at each login step (session fixation, T-59). It resets the
// TOTP failures and refreshes LastSeenAt. It returns ErrNotFound when the
// session is no longer valid at now or no longer carries oldHash (a
// concurrent rotation won), ErrInvalid for malformed arguments and
// ErrConflict when newHash is already used.
func (r *AdminSessions) Rotate(ctx context.Context, sessionID string, oldHash, newHash []byte,
	state AdminSessionState, stateExpiresAt, now time.Time, idle time.Duration,
) error {
	return r.db.authWrite(ctx, "rotate admin session", func(tx *SystemTx) error {
		return rotateSession(ctx, tx, sessionID, oldHash, newHash, state, stateExpiresAt, now, idle)
	})
}

// RotateTx is Rotate inside tx (a transaction of [Admins.Tx]), so that a
// rotation commits or fails with the change it completes (the TOTP
// confirmation of a mandatory enrollment).
func (r *AdminSessions) RotateTx(ctx context.Context, tx *SystemTx, sessionID string, oldHash, newHash []byte,
	state AdminSessionState, stateExpiresAt, now time.Time, idle time.Duration,
) error {
	if err := rotateSession(ctx, tx, sessionID, oldHash, newHash, state, stateExpiresAt, now, idle); err != nil {
		return wrap("rotate admin session", err)
	}
	return nil
}

// rotateSession implements Rotate and RotateTx, returning raw errors.
func rotateSession(ctx context.Context, tx *SystemTx, sessionID string, oldHash, newHash []byte,
	state AdminSessionState, stateExpiresAt, now time.Time, idle time.Duration,
) error {
	if !validTokenHash(oldHash) || !validTokenHash(newHash) {
		return invalid("token hash must hold %d bytes", TokenHashSize)
	}
	if err := checkStateExpiry(state, stateExpiresAt); err != nil {
		return err
	}
	var stateExpires any
	if !stateExpiresAt.IsZero() {
		stateExpires = toMillis(stateExpiresAt)
	}
	args := append([]any{newHash, string(state), stateExpires, toMillis(now), sessionID, oldHash}, validity(now, idle)...)
	res, err := tx.Exec(ctx, qAdminSessionRotate, args...)
	if err != nil {
		return err
	}
	return expectOne(res)
}

// IncrementTOTPFailures counts a wrong TOTP code on the session sessionID
// and returns the new count; the service deletes the session when it
// reaches its limit. It returns ErrNotFound for an unknown session.
func (r *AdminSessions) IncrementTOTPFailures(ctx context.Context, sessionID string) (int, error) {
	var n int
	err := r.db.authWrite(ctx, "count totp failure", func(tx *SystemTx) error {
		return tx.QueryRow(ctx, qAdminSessionFailure, sessionID).Scan(&n)
	})
	return n, err
}

// Delete removes the session sessionID (logout). It returns ErrNotFound
// for an unknown session.
func (r *AdminSessions) Delete(ctx context.Context, sessionID string) error {
	return r.db.authWrite(ctx, "delete admin session", func(tx *SystemTx) error {
		res, err := tx.Exec(ctx, qAdminSessionDelete, sessionID)
		if err != nil {
			return err
		}
		return expectOne(res)
	})
}

// DeleteByAdmin revokes the sessions of adminID in its own transaction
// (see [AdminSessions.DeleteByAdminTx]).
func (r *AdminSessions) DeleteByAdmin(ctx context.Context, adminID, exceptID string) (int64, error) {
	var n int64
	err := r.db.authWrite(ctx, "revoke admin sessions", func(tx *SystemTx) error {
		var err error
		n, err = deleteSessionsByAdmin(ctx, tx, adminID, exceptID)
		return err
	})
	return n, err
}

// DeleteByAdminTx revokes, inside tx, every session of adminID except the
// session exceptID ("" for none: password change keeps the current
// session, a disabling or a reset keeps none), and returns how many it
// deleted.
func (r *AdminSessions) DeleteByAdminTx(ctx context.Context, tx *SystemTx, adminID, exceptID string) (int64, error) {
	n, err := deleteSessionsByAdmin(ctx, tx, adminID, exceptID)
	if err != nil {
		return 0, wrap("revoke admin sessions", err)
	}
	return n, nil
}

// deleteSessionsByAdmin implements DeleteByAdminTx, returning raw errors.
func deleteSessionsByAdmin(ctx context.Context, tx *SystemTx, adminID, exceptID string) (int64, error) {
	res, err := tx.Exec(ctx, qAdminSessionDeleteByAdmin, adminID, exceptID)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// DeleteSSOForTenant revokes single sign-on sessions in its own
// transaction (see [AdminSessions.DeleteSSOForTenantTx]).
func (r *AdminSessions) DeleteSSOForTenant(ctx context.Context, tid tenant.ID, issuer, clientID string) (int64, error) {
	var n int64
	err := r.db.authWrite(ctx, "revoke sso sessions", func(tx *SystemTx) error {
		var err error
		n, err = deleteSSOSessions(ctx, tx, tid, issuer, clientID)
		return err
	})
	return n, err
}

// DeleteSSOForTenantTx revokes, inside tx, the single sign-on (AuthOIDC)
// sessions opened through (issuer, clientID) by the accounts attached to
// tenant tid, and returns how many it deleted. The caller runs it, with
// the previous pair, when the configuration of tid is disabled, deleted,
// or changes its issuer or its client ID (threats T-287, T-291). Password
// sessions and the sessions of other pairs are never touched. A session of
// an account also attached to another tenant trusting the same pair is
// revoked too (the account signs in again): the access layer would keep it
// out of tid anyway, revocation is the second line.
func (r *AdminSessions) DeleteSSOForTenantTx(ctx context.Context, tx *SystemTx, tid tenant.ID, issuer, clientID string) (int64, error) {
	n, err := deleteSSOSessions(ctx, tx, tid, issuer, clientID)
	if err != nil {
		return 0, wrap("revoke sso sessions", err)
	}
	return n, nil
}

// deleteSSOSessions implements DeleteSSOForTenantTx, returning raw errors.
func deleteSSOSessions(ctx context.Context, tx *SystemTx, tid tenant.ID, issuer, clientID string) (int64, error) {
	if tid.Validate() != nil {
		return 0, invalid("malformed tenant id")
	}
	res, err := tx.Exec(ctx, qAdminSessionDeleteSSO, issuer, clientID, string(tid))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// DeleteSSOForAdminTx revokes, inside tx, the single sign-on (AuthOIDC)
// sessions of the account adminID opened through (issuer, clientID), and
// returns how many it deleted. The caller runs it when an identity of that
// pair is unpinned from the account (OpenAPI deleteAdminIdentity): the
// sessions it opened go with it. Password sessions and the sessions of
// other pairs or accounts are never touched.
func (r *AdminSessions) DeleteSSOForAdminTx(ctx context.Context, tx *SystemTx, adminID, issuer, clientID string) (int64, error) {
	res, err := tx.Exec(ctx, qAdminSessionDeleteSSOForAdmin, adminID, issuer, clientID)
	if err != nil {
		return 0, wrap("revoke account sso sessions", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, wrap("revoke account sso sessions", err)
	}
	return n, nil
}

// Purge deletes the sessions invalid at now (absolute expiry, idle timeout
// idle or state expiry passed), in batches of PurgeBatchSize, and returns
// how many it deleted.
func (r *AdminSessions) Purge(ctx context.Context, now time.Time, idle time.Duration) (int64, error) {
	return r.db.purgeSystem(ctx, reasonAdminAuth, "purge admin sessions", "", qAdminSessionPurge, validity(now, idle)...)
}

// AdminRecoveryCodes is the repository of the TOTP recovery codes of the
// administrators, stored as 32-byte keyed MACs computed by the caller
// (crypto.RecoveryCodeMAC, keyed by the TOTP secret of the administrator).
// Its operations are system-scoped. Obtain it with [DB.AdminRecoveryCodes].
type AdminRecoveryCodes struct {
	db *DB
}

// AdminRecoveryCodes returns the recovery code repository.
func (db *DB) AdminRecoveryCodes() *AdminRecoveryCodes { return &AdminRecoveryCodes{db: db} }

// Replace sets the recovery codes of adminID in its own transaction (see
// [AdminRecoveryCodes.ReplaceTx]).
func (r *AdminRecoveryCodes) Replace(ctx context.Context, adminID string, hashes [][]byte) error {
	return r.db.authWrite(ctx, "replace recovery codes", func(tx *SystemTx) error {
		return replaceRecoveryCodes(ctx, tx, adminID, hashes)
	})
}

// ReplaceTx replaces, inside tx, every recovery code of adminID (used or
// not) by hashes: 0 to MaxRecoveryCodes distinct MACs (TokenHashSize
// bytes). It returns ErrInvalid for malformed or duplicate
// hashes and ErrNotFound for an unknown admin (with at least one hash).
func (r *AdminRecoveryCodes) ReplaceTx(ctx context.Context, tx *SystemTx, adminID string, hashes [][]byte) error {
	if err := replaceRecoveryCodes(ctx, tx, adminID, hashes); err != nil {
		return wrap("replace recovery codes", err)
	}
	return nil
}

// replaceRecoveryCodes implements ReplaceTx, returning raw errors.
func replaceRecoveryCodes(ctx context.Context, tx *SystemTx, adminID string, hashes [][]byte) error {
	if len(hashes) > MaxRecoveryCodes {
		return invalid("at most %d recovery codes", MaxRecoveryCodes)
	}
	seen := make(map[string]bool, len(hashes))
	for _, h := range hashes {
		if !validTokenHash(h) {
			return invalid("recovery code hash must hold %d bytes", TokenHashSize)
		}
		if seen[string(h)] {
			return invalid("duplicate recovery code")
		}
		seen[string(h)] = true
	}
	if _, err := tx.Exec(ctx, qRecoveryDeleteAll, adminID); err != nil {
		return err
	}
	for _, h := range hashes {
		if _, err := tx.Exec(ctx, qRecoveryInsert, adminID, h); err != nil {
			return err
		}
	}
	return nil
}

// Consume marks the unused recovery code of adminID hashing to hash as
// used at now, atomically, and reports whether it did: false when no such
// unused code exists (wrong, already used or of another admin). A code can
// be consumed only once, even by concurrent logins.
func (r *AdminRecoveryCodes) Consume(ctx context.Context, adminID string, hash []byte, now time.Time) (bool, error) {
	if !validTokenHash(hash) {
		return false, nil
	}
	var consumed bool
	err := r.db.authWrite(ctx, "consume recovery code", func(tx *SystemTx) error {
		res, err := tx.Exec(ctx, qRecoveryConsume, toMillis(now), adminID, hash)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		consumed = n == 1
		return err
	})
	return consumed, err
}

// CountUnused returns the number of unused recovery codes of adminID.
func (r *AdminRecoveryCodes) CountUnused(ctx context.Context, adminID string) (int, error) {
	var n int
	err := r.db.authRead(ctx, "count recovery codes", func(tx *SystemTx) error {
		return tx.QueryRow(ctx, qRecoveryCountUnused, adminID).Scan(&n)
	})
	return n, err
}

// AdminActivation is a single-use activation link of an administrator
// account (creation or credentials reset). Only the SHA-256 of the link
// token is stored.
type AdminActivation struct {
	// ID is the internal identifier ("act_" + ULID), assigned by the
	// caller.
	ID string
	// AdminID is the administrator to activate.
	AdminID string
	// TokenHash is the SHA-256 of the link token (TokenHashSize bytes).
	TokenHash []byte
	// CreatedAt is the creation time; the store's clock is used when it is
	// zero.
	CreatedAt time.Time
	// ExpiresAt is the end of validity, after CreatedAt.
	ExpiresAt time.Time
	// Delivery is how the link reaches the administrator: DeliveryCopy
	// (returned once to the super admin) when empty, or DeliveryMail
	// (mailed through the system SMTP, never returned).
	Delivery ActivationDelivery
	// Language is the language of the mail, "" for a copied link.
	Language string
}

// ActivationDelivery is how an activation link reaches the administrator
// (OpenAPI InvitationDelivery).
type ActivationDelivery string

// Activation deliveries.
const (
	// DeliveryCopy: the link is returned once to the super admin, who
	// hands it over out of band (the V1 behavior).
	DeliveryCopy ActivationDelivery = "copy"
	// DeliveryMail: the link is mailed through the system SMTP after the
	// commit and never returned.
	DeliveryMail ActivationDelivery = "mail"
)

// AdminActivations is the repository of activation links. Its operations
// are system-scoped. Obtain it with [DB.AdminActivations].
type AdminActivations struct {
	db *DB
}

// AdminActivations returns the activation link repository.
func (db *DB) AdminActivations() *AdminActivations { return &AdminActivations{db: db} }

// Create stores a in its own transaction (see [AdminActivations.CreateTx]).
func (r *AdminActivations) Create(ctx context.Context, a AdminActivation) error {
	return r.db.authWrite(ctx, "create admin activation", func(tx *SystemTx) error { return r.create(ctx, tx, a) })
}

// CreateTx stores a inside tx (with the account creation or reset). It
// returns ErrInvalid for a malformed field, ErrNotFound when the admin does
// not exist and ErrConflict when the ID or the token hash is already used.
// Callers revoke the previous links first ([AdminActivations.DeleteByAdminTx]).
func (r *AdminActivations) CreateTx(ctx context.Context, tx *SystemTx, a AdminActivation) error {
	if err := r.create(ctx, tx, a); err != nil {
		return wrap("create admin activation", err)
	}
	return nil
}

// create validates and inserts a in tx, returning raw errors.
func (r *AdminActivations) create(ctx context.Context, tx *SystemTx, a AdminActivation) error {
	created := r.db.orNow(a.CreatedAt)
	switch {
	case !id.Valid(id.AdminActivation, a.ID):
		return invalid("malformed admin activation id")
	case !id.Valid(id.Admin, a.AdminID):
		return invalid("malformed admin id")
	case !validTokenHash(a.TokenHash):
		return invalid("token hash must hold %d bytes", TokenHashSize)
	case !a.ExpiresAt.After(created):
		return invalid("activation must expire after its creation")
	}
	delivery := a.Delivery
	if delivery == "" {
		delivery = DeliveryCopy
	}
	switch {
	case delivery != DeliveryCopy && delivery != DeliveryMail:
		return invalid("unknown activation delivery")
	case delivery == DeliveryCopy && a.Language != "":
		return invalid("a copied activation link has no mail language")
	case delivery == DeliveryMail && (len(a.Language) < 2 || len(a.Language) > 16):
		return invalid("a mailed activation link needs a language of 2 to 16 bytes")
	}
	_, err := tx.Exec(ctx, qActivationInsert, a.ID, a.AdminID, a.TokenHash, toMillis(created), toMillis(a.ExpiresAt),
		string(delivery), nullText(a.Language))
	return err
}

// Consume uses the activation link in its own transaction (see
// [AdminActivations.ConsumeTx]).
func (r *AdminActivations) Consume(ctx context.Context, tokenHash []byte, now time.Time) (string, error) {
	var adminID string
	err := r.db.authWrite(ctx, "consume admin activation", func(tx *SystemTx) error {
		var err error
		adminID, _, err = consumeActivation(ctx, tx, tokenHash, now)
		return err
	})
	return adminID, err
}

// ConsumeTx marks, inside tx, the activation link whose token hashes to
// tokenHash as used at now, provided it is unused and not expired, and
// returns its administrator and how the link was delivered: the activation
// then sets the password in the same transaction, and requires TOTP for a
// mailed link. A link can be consumed only once, even concurrently. It
// returns ErrNotFound otherwise (unknown, used or expired) and ErrInvalid
// for a hash of the wrong size.
func (r *AdminActivations) ConsumeTx(ctx context.Context, tx *SystemTx, tokenHash []byte, now time.Time) (string, ActivationDelivery, error) {
	adminID, delivery, err := consumeActivation(ctx, tx, tokenHash, now)
	if err != nil {
		return "", "", wrap("consume admin activation", err)
	}
	return adminID, delivery, nil
}

// consumeActivation implements ConsumeTx, returning raw errors.
func consumeActivation(ctx context.Context, tx *SystemTx, tokenHash []byte, now time.Time) (string, ActivationDelivery, error) {
	if !validTokenHash(tokenHash) {
		return "", "", invalid("token hash must hold %d bytes", TokenHashSize)
	}
	ms := toMillis(now)
	var adminID, delivery string
	err := tx.QueryRow(ctx, qActivationConsume, ms, tokenHash, ms).Scan(&adminID, &delivery)
	return adminID, ActivationDelivery(delivery), err
}

// DeleteByAdmin revokes the activation links of adminID in its own
// transaction (see [AdminActivations.DeleteByAdminTx]).
func (r *AdminActivations) DeleteByAdmin(ctx context.Context, adminID string) (int64, error) {
	var n int64
	err := r.db.authWrite(ctx, "revoke admin activations", func(tx *SystemTx) error {
		var err error
		n, err = deleteActivations(ctx, tx, adminID)
		return err
	})
	return n, err
}

// DeleteByAdminTx revokes, inside tx, every activation link of adminID
// and returns how many it deleted.
func (r *AdminActivations) DeleteByAdminTx(ctx context.Context, tx *SystemTx, adminID string) (int64, error) {
	n, err := deleteActivations(ctx, tx, adminID)
	if err != nil {
		return 0, wrap("revoke admin activations", err)
	}
	return n, nil
}

// deleteActivations implements DeleteByAdminTx, returning raw errors.
func deleteActivations(ctx context.Context, tx *SystemTx, adminID string) (int64, error) {
	res, err := tx.Exec(ctx, qActivationDeleteByAdmin, adminID)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// Purge deletes the activation links used or expired at now, in batches of
// PurgeBatchSize, and returns how many it deleted.
func (r *AdminActivations) Purge(ctx context.Context, now time.Time) (int64, error) {
	return r.db.purgeSystem(ctx, reasonAdminAuth, "purge admin activations", "", qActivationPurge, toMillis(now))
}
