package store

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Reasons of the administration system queries. The administrator tables
// belong to no tenant: every statement on them is a system query.
const (
	reasonAdminAccounts = "administrator accounts (system tables, no tenant)"
	reasonAdminAuth     = "administrator authentication: sessions, recovery codes, activation links, login failures"
)

// lockName names a system lock (see dialect.lockSystem).
type lockName string

// System locks.
const (
	// lockAdmins serializes the first-run setup, the operations bound by
	// the last super admin rule and the changes of the TOTP secrets of an
	// account (which read the secret IDs to destroy, then replace them).
	lockAdmins lockName = "admins"
	// lockAdminLogin serializes the admin login failure counters.
	lockAdminLogin lockName = "admin-login"
)

// lock serializes tx with every other system transaction taking the lock
// name, until it ends. It is a no-op on SQLite, whose write transactions
// are serialized anyway.
func (t *SystemTx) lock(ctx context.Context, name lockName) error {
	if t.dialect.lockSystem == "" {
		return nil
	}
	if _, err := t.tx.ExecContext(ctx, t.dialect.lockSystem, string(name)); err != nil {
		return wrap("lock "+string(name), err)
	}
	return nil
}

// AdminRole is the role of an administrator (OpenAPI AdminRole). V2 adds
// "auditor", with a migration of the role constraint.
type AdminRole string

// Administrator roles.
const (
	// RoleSuperAdmin administers the whole instance (every tenant).
	RoleSuperAdmin AdminRole = "super_admin"
	// RoleDelegatedAdmin administers the tenants it is attached to.
	RoleDelegatedAdmin AdminRole = "delegated_admin"
)

// Limits of the administrator fields.
const (
	// MaxAdminTenants bounds the tenants an administrator is attached to.
	MaxAdminTenants = 1000
)

// ErrLastSuperAdmin reports an operation that would leave the instance
// without a usable super admin (not disabled, with a password and TOTP
// enabled: one who can sign in): deleting, disabling or demoting the last
// one. Nothing is changed.
var ErrLastSuperAdmin = errors.New("store: the last usable super admin cannot be deleted, disabled or demoted")

// ErrPromotionRefused reports a promotion to super admin of an account that
// is not activated (no password) or has no TOTP enrolled: a super admin
// must be able to sign in with both factors from the start. Nothing is
// changed.
var ErrPromotionRefused = errors.New("store: only an activated administrator with totp enabled can be promoted to super admin")

// usernamePattern is the syntax of a username (OpenAPI Username), case
// folded by NormalizeUsername.
var usernamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$`)

// NormalizeUsername validates an administrator username and returns the
// form the store keeps and compares: trimmed and lower-case ASCII, matching
// ^[a-z0-9][a-z0-9._-]{2,63}$. Non-ASCII input is refused rather than
// folded, so that no Unicode look-alike maps to another account. It
// returns ErrInvalid otherwise; the error never quotes the value.
func NormalizeUsername(s string) (string, error) {
	s = strings.TrimSpace(s)
	if !usernamePattern.MatchString(s) {
		return "", invalid("malformed username")
	}
	return strings.ToLower(s), nil
}

// Admin is an administrator account.
type Admin struct {
	// ID is the identifier ("adm_" + ULID), assigned by the store.
	ID string
	// Username is the login name, normalized by the store (see
	// NormalizeUsername). It is unique.
	Username string
	// Email is the mail address, normalized by the store.
	Email string
	// Role is the role of the administrator.
	Role AdminRole
	// TenantIDs are the tenants a delegated admin is attached to (at least
	// one), sorted; always empty for a super admin, which reaches every
	// tenant.
	TenantIDs []tenant.ID
	// PasswordHash is the password hash (PHC string), "" until the account
	// is activated.
	PasswordHash string
	// TOTPSecretID is the system secret holding the TOTP secret in use, ""
	// when TOTP is not enrolled.
	TOTPSecretID string
	// TOTPEnabled reports whether TOTP is enrolled and required at login.
	TOTPEnabled bool
	// TOTPLastCounter is the last accepted TOTP time step, -1 when none was
	// accepted yet (see [Admins.AdvanceTOTPCounter]).
	TOTPLastCounter int64
	// PendingTOTPSecretID is the system secret of an enrollment awaiting
	// confirmation, "" when none.
	PendingTOTPSecretID string
	// RequireTOTP makes the TOTP enrollment mandatory. It is always true
	// for a super admin.
	RequireTOTP bool
	// Disabled blocks the account.
	Disabled bool
	// Language is the preferred UI language, "" for the default.
	Language string
	// CreatedAt and UpdatedAt are set by the store.
	CreatedAt time.Time
	UpdatedAt time.Time
	// LastLoginAt is the time of the last successful login, zero if none.
	LastLoginAt time.Time
	// CredentialsChangedAt is when the password or the TOTP enrollment last
	// changed, zero if never.
	CredentialsChangedAt time.Time
}

// usableSuperAdmin reports whether a counts towards the last super admin
// rule: a super admin who can sign in (not disabled, password set, TOTP
// enabled).
func (a Admin) usableSuperAdmin() bool {
	return a.Role == RoleSuperAdmin && !a.Disabled && a.PasswordHash != "" && a.TOTPEnabled
}

// adminColumns is the column list read by the admin queries.
const adminColumns = `id, username, email, role, password_hash, totp_secret_id, totp_enabled, totp_last_counter,
	pending_totp_secret_id, require_totp, disabled, language, created_at, updated_at, last_login_at, credentials_changed_at`

// Statements of the Admins repository.
var (
	qAdminInsert = systemQuery(
		`INSERT INTO admins (id, username, email, role, password_hash, require_totp, disabled, language,
			created_at, updated_at, credentials_changed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		reasonAdminAccounts)
	qAdminGet = systemQuery(
		`SELECT `+adminColumns+` FROM admins WHERE id = ?`,
		reasonAdminAccounts)
	qAdminByUsername = systemQuery(
		`SELECT `+adminColumns+` FROM admins WHERE username = ?`,
		reasonAdminAccounts)
	qAdminList = systemQuery(
		`SELECT `+adminColumns+` FROM admins WHERE id > ? ORDER BY id LIMIT ?`,
		reasonAdminAccounts)
	qAdminUpdate = systemQuery(
		`UPDATE admins SET email = ?, role = ?, require_totp = ?, disabled = ?, language = ?, updated_at = ? WHERE id = ?`,
		reasonAdminAccounts)
	qAdminSetPassword = systemQuery(
		`UPDATE admins SET password_hash = ?, credentials_changed_at = ?, updated_at = ? WHERE id = ?`,
		reasonAdminAccounts)
	qAdminSetPending = systemQuery(
		`UPDATE admins SET pending_totp_secret_id = ?, updated_at = ? WHERE id = ?`,
		reasonAdminAccounts)
	// qAdminSetTOTP promotes the pending secret, only if it is still the
	// one the caller verified.
	qAdminSetTOTP = systemQuery(
		`UPDATE admins SET totp_secret_id = pending_totp_secret_id, pending_totp_secret_id = NULL, totp_enabled = true,
			totp_last_counter = ?, credentials_changed_at = ?, updated_at = ? WHERE id = ? AND pending_totp_secret_id = ?`,
		reasonAdminAccounts)
	qAdminClearTOTP = systemQuery(
		`UPDATE admins SET totp_secret_id = NULL, pending_totp_secret_id = NULL, totp_enabled = false,
			totp_last_counter = NULL, credentials_changed_at = ?, updated_at = ? WHERE id = ?`,
		reasonAdminAccounts)
	// qAdminAdvanceCounter only moves the counter forward: a replayed or
	// older time step affects no row (T-60).
	qAdminAdvanceCounter = systemQuery(
		`UPDATE admins SET totp_last_counter = ?
		WHERE id = ? AND totp_enabled = true AND (totp_last_counter IS NULL OR totp_last_counter < ?)`,
		reasonAdminAccounts)
	qAdminTouchLogin = systemQuery(
		`UPDATE admins SET last_login_at = ? WHERE id = ?`,
		reasonAdminAccounts)
	qAdminDelete = systemQuery(
		`DELETE FROM admins WHERE id = ?`,
		reasonAdminAccounts)
	// qAdminCountUsableSuper counts the super admins who can sign in (see
	// Admin.usableSuperAdmin).
	qAdminCountUsableSuper = systemQuery(
		`SELECT count(*) FROM admins
			WHERE role = 'super_admin' AND disabled = false AND password_hash IS NOT NULL AND totp_enabled = true`,
		reasonAdminAccounts)
	qAdminCountAll = systemQuery(
		`SELECT count(*) FROM admins`,
		reasonAdminAccounts)

	qAdminTenants = systemQuery(
		`SELECT tenant_id FROM admin_tenants WHERE admin_id = ? ORDER BY tenant_id`,
		reasonAdminAccounts)
	qAdminTenantsRange = systemQuery(
		`SELECT admin_id, tenant_id FROM admin_tenants WHERE admin_id > ? AND admin_id <= ? ORDER BY admin_id, tenant_id`,
		reasonAdminAccounts)
	qAdminTenantsDelete = systemQuery(
		`DELETE FROM admin_tenants WHERE admin_id = ?`,
		reasonAdminAccounts)
	qAdminTenantInsert = systemQuery(
		`INSERT INTO admin_tenants (admin_id, tenant_id) VALUES (?, ?)`,
		reasonAdminAccounts)
)

// Admins is the repository of administrator accounts. Its operations are
// system-scoped: callers must check the caller's rights first. Obtain it
// with [DB.Admins].
//
// Every method runs in its own transaction; the Tx variants run inside a
// transaction of [Admins.Tx], so that the service can combine them with the
// other administration repositories (setup, activation...) atomically.
// After an error from a Tx variant, the caller must abort the transaction.
type Admins struct {
	db *DB
}

// Admins returns the administrator repository.
func (db *DB) Admins() *Admins { return &Admins{db: db} }

// Tx runs fn in a read-write system transaction for the administration
// repositories (their Tx variants and [AuditEvents.AppendTx]). As with
// [Scoped.Tx], fn must not start another transaction.
func (r *Admins) Tx(ctx context.Context, fn func(*SystemTx) error) error {
	return r.db.systemScope(reasonAdminAccounts).Tx(ctx, fn)
}

// write runs fn in a write transaction and wraps its error with op.
func (r *Admins) write(ctx context.Context, op string, fn func(*SystemTx) error) error {
	if err := r.Tx(ctx, fn); err != nil {
		return wrap(op, err)
	}
	return nil
}

// read runs fn in a read transaction and wraps its error with op.
func (r *Admins) read(ctx context.Context, op string, fn func(*SystemTx) error) error {
	if err := r.db.systemScope(reasonAdminAccounts).ReadTx(ctx, fn); err != nil {
		return wrap(op, err)
	}
	return nil
}

// normalizeTenantIDs validates ids and returns them sorted, without
// duplicates.
func normalizeTenantIDs(ids []tenant.ID) ([]tenant.ID, error) {
	if len(ids) > MaxAdminTenants {
		return nil, invalid("at most %d tenants per administrator", MaxAdminTenants)
	}
	out := make([]tenant.ID, 0, len(ids))
	for _, t := range ids {
		if t.Validate() != nil {
			return nil, invalid("malformed tenant id")
		}
		out = append(out, t)
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

// normalizeAdmin validates the caller-set fields of a and normalizes them
// in place: username, email, sorted tenants, and RequireTOTP forced for a
// super admin.
func normalizeAdmin(a *Admin) error {
	var err error
	if a.Username, err = NormalizeUsername(a.Username); err != nil {
		return err
	}
	if a.Email, err = NormalizeEmail(a.Email); err != nil {
		return err
	}
	if a.TenantIDs, err = normalizeTenantIDs(a.TenantIDs); err != nil {
		return err
	}
	switch {
	case a.Role != RoleSuperAdmin && a.Role != RoleDelegatedAdmin:
		return invalid("unknown administrator role")
	case a.Role == RoleSuperAdmin && len(a.TenantIDs) > 0:
		return invalid("a super admin is attached to no tenant")
	case a.Role == RoleDelegatedAdmin && len(a.TenantIDs) == 0:
		return invalid("a delegated admin needs at least one tenant")
	case !validPasswordHash(a.PasswordHash):
		return invalid("password hash must be a PHC string of at most %d printable characters", MaxPasswordHashLen)
	case a.Language != "" && !tenant.IsLanguage(a.Language):
		return invalid("unsupported language")
	}
	if a.Role == RoleSuperAdmin {
		a.RequireTOTP = true
	}
	return nil
}

// validPasswordHash reports whether h is acceptable as a stored hash: a PHC
// string (printable ASCII starting with "$", at most MaxPasswordHashLen
// bytes, as for transfer passwords), or "" (no password yet).
func validPasswordHash(h string) bool {
	return h == "" || (h[0] == '$' && isPrintableASCII(h, MaxPasswordHashLen))
}

// scanAdmin reads one row of adminColumns (without the tenants).
func scanAdmin(sc interface{ Scan(...any) error }) (Admin, error) {
	var (
		a                       Admin
		role                    string
		hash, secret, pending   sql.NullString
		lang                    sql.NullString
		counter                 sql.NullInt64
		created, updated        int64
		lastLogin, credsChanged sql.NullInt64
	)
	if err := sc.Scan(&a.ID, &a.Username, &a.Email, &role, &hash, &secret, &a.TOTPEnabled, &counter, &pending,
		&a.RequireTOTP, &a.Disabled, &lang, &created, &updated, &lastLogin, &credsChanged); err != nil {
		return Admin{}, err
	}
	a.Role = AdminRole(role)
	a.PasswordHash, a.TOTPSecretID, a.PendingTOTPSecretID, a.Language = hash.String, secret.String, pending.String, lang.String
	a.TOTPLastCounter = -1
	if counter.Valid {
		a.TOTPLastCounter = counter.Int64
	}
	a.CreatedAt, a.UpdatedAt = fromMillis(created), fromMillis(updated)
	a.LastLoginAt, a.CredentialsChangedAt = nullMillis(lastLogin), nullMillis(credsChanged)
	a.TenantIDs = []tenant.ID{}
	return a, nil
}

// adminTenants returns the sorted tenants of adminID inside tx.
func adminTenants(ctx context.Context, tx *SystemTx, adminID string) ([]tenant.ID, error) {
	rows, err := tx.Query(ctx, qAdminTenants, adminID)
	if err != nil {
		return nil, err
	}
	return collect(rows, func(r *sql.Rows) (tenant.ID, error) {
		var s string
		err := r.Scan(&s)
		return tenant.ID(s), err
	})
}

// getAdmin reads the admin selected by q and arg, with its tenants, inside
// tx.
func getAdmin(ctx context.Context, tx *SystemTx, q SystemQuery, arg string) (Admin, error) {
	a, err := scanAdmin(tx.QueryRow(ctx, q, arg))
	if err != nil {
		return Admin{}, err
	}
	a.TenantIDs, err = adminTenants(ctx, tx, a.ID)
	return a, err
}

// replaceTenants sets the tenants of adminID inside tx.
func replaceTenants(ctx context.Context, tx *SystemTx, adminID string, ids []tenant.ID) error {
	if _, err := tx.Exec(ctx, qAdminTenantsDelete, adminID); err != nil {
		return err
	}
	for _, t := range ids {
		if _, err := tx.Exec(ctx, qAdminTenantInsert, adminID, string(t)); err != nil {
			return err
		}
	}
	return nil
}

// Create stores a new administrator in its own transaction (see
// [Admins.CreateTx]).
func (r *Admins) Create(ctx context.Context, a Admin) (Admin, error) {
	var out Admin
	err := r.write(ctx, "create admin", func(tx *SystemTx) error {
		var err error
		out, err = r.create(ctx, tx, a)
		return err
	})
	return out, err
}

// CreateTx validates a, assigns it an ID and timestamps, and stores it
// inside tx. The caller sets Username, Email, Role, TenantIDs, RequireTOTP
// (forced for a super admin), Disabled, Language and, for an account
// created with a password (setup), PasswordHash; the TOTP fields and the
// times are ignored. It returns the stored admin, ErrInvalid for a
// malformed field, ErrConflict when the username is taken and ErrNotFound
// when a tenant does not exist.
func (r *Admins) CreateTx(ctx context.Context, tx *SystemTx, a Admin) (Admin, error) {
	out, err := r.create(ctx, tx, a)
	if err != nil {
		return Admin{}, wrap("create admin", err)
	}
	return out, nil
}

// create implements CreateTx, returning raw errors.
func (r *Admins) create(ctx context.Context, tx *SystemTx, a Admin) (Admin, error) {
	if err := normalizeAdmin(&a); err != nil {
		return Admin{}, err
	}
	newID, err := r.db.newID(id.Admin)
	if err != nil {
		return Admin{}, err
	}
	now := fromMillis(toMillis(r.db.now()))
	out := Admin{
		ID: newID, Username: a.Username, Email: a.Email, Role: a.Role, TenantIDs: a.TenantIDs,
		PasswordHash: a.PasswordHash, TOTPLastCounter: -1, RequireTOTP: a.RequireTOTP, Disabled: a.Disabled,
		Language: a.Language, CreatedAt: now, UpdatedAt: now,
	}
	var creds any
	if a.PasswordHash != "" {
		out.CredentialsChangedAt = now
		creds = toMillis(now)
	}
	if _, err := tx.Exec(ctx, qAdminInsert, out.ID, out.Username, out.Email, string(out.Role), nullText(out.PasswordHash),
		out.RequireTOTP, out.Disabled, nullText(out.Language), toMillis(now), toMillis(now), creds); err != nil {
		return Admin{}, err
	}
	if err := replaceTenants(ctx, tx, out.ID, out.TenantIDs); err != nil {
		return Admin{}, err
	}
	return out, nil
}

// Get returns the administrator adminID with its tenants, or ErrNotFound.
func (r *Admins) Get(ctx context.Context, adminID string) (Admin, error) {
	var a Admin
	err := r.read(ctx, "get admin", func(tx *SystemTx) error {
		var err error
		a, err = getAdmin(ctx, tx, qAdminGet, adminID)
		return err
	})
	return a, err
}

// GetTx is Get inside tx.
func (r *Admins) GetTx(ctx context.Context, tx *SystemTx, adminID string) (Admin, error) {
	a, err := getAdmin(ctx, tx, qAdminGet, adminID)
	if err != nil {
		return Admin{}, wrap("get admin", err)
	}
	return a, nil
}

// GetByUsername returns the administrator whose username is username
// (normalized first: the lookup is case-insensitive), or ErrNotFound. A
// malformed username yields ErrNotFound too, so that the login layer
// handles every unknown username the same way.
func (r *Admins) GetByUsername(ctx context.Context, username string) (Admin, error) {
	u, err := NormalizeUsername(username)
	if err != nil {
		return Admin{}, wrap("get admin by username", ErrNotFound)
	}
	var a Admin
	err = r.read(ctx, "get admin by username", func(tx *SystemTx) error {
		var err error
		a, err = getAdmin(ctx, tx, qAdminByUsername, u)
		return err
	})
	return a, err
}

// AdminListOptions selects a page of administrators.
type AdminListOptions struct {
	// Cursor is the NextCursor of the previous page, or "" for the first.
	Cursor string
	// Limit is the page size (DefaultPageSize when <= 0, at most
	// MaxPageSize).
	Limit int
}

// List returns a page of administrators with their tenants, ordered by ID
// (approximately creation order). A malformed cursor yields ErrInvalid.
func (r *Admins) List(ctx context.Context, opts AdminListOptions) (Page[Admin], error) {
	if opts.Cursor != "" && !id.Valid(id.Admin, opts.Cursor) {
		return Page[Admin]{}, invalid("malformed cursor")
	}
	limit := pageLimit(opts.Limit)
	var items []Admin
	err := r.read(ctx, "list admins", func(tx *SystemTx) error {
		rows, err := tx.Query(ctx, qAdminList, opts.Cursor, limit+1)
		if err != nil {
			return err
		}
		if items, err = collect(rows, func(r *sql.Rows) (Admin, error) { return scanAdmin(r) }); err != nil || len(items) == 0 {
			return err
		}
		// The tenants of the whole page, in one statement.
		rows, err = tx.Query(ctx, qAdminTenantsRange, opts.Cursor, items[len(items)-1].ID)
		if err != nil {
			return err
		}
		type link struct{ admin, tenant string }
		links, err := collect(rows, func(r *sql.Rows) (link, error) {
			var l link
			err := r.Scan(&l.admin, &l.tenant)
			return l, err
		})
		if err != nil {
			return err
		}
		byAdmin := make(map[string][]tenant.ID, len(items))
		for _, l := range links {
			byAdmin[l.admin] = append(byAdmin[l.admin], tenant.ID(l.tenant))
		}
		for i := range items {
			if ts, ok := byAdmin[items[i].ID]; ok {
				items[i].TenantIDs = ts
			}
		}
		return nil
	})
	if err != nil {
		return Page[Admin]{}, err
	}
	return paginate(items, limit, func(a Admin) string { return a.ID }), nil
}

// AdminUpdate lists the fields of an administrator to change; nil fields
// are left unchanged.
type AdminUpdate struct {
	// Email is the new mail address.
	Email *string
	// Role is the new role. Promoting to super admin clears the tenants
	// (unless TenantIDs is also set, which must then be empty) and forces
	// RequireTOTP.
	Role *AdminRole
	// TenantIDs replaces the tenants.
	TenantIDs *[]tenant.ID
	// RequireTOTP is the new TOTP requirement (ignored for a super admin,
	// which always requires TOTP).
	RequireTOTP *bool
	// Disabled blocks or unblocks the account.
	Disabled *bool
	// Language is the new preferred language ("" for the default).
	Language *string
}

// Update changes the administrator adminID in its own transaction (see
// [Admins.UpdateTx]) and returns the stored admin.
func (r *Admins) Update(ctx context.Context, adminID string, u AdminUpdate) (Admin, error) {
	var out Admin
	err := r.write(ctx, "update admin", func(tx *SystemTx) error {
		var err error
		_, out, err = r.update(ctx, tx, adminID, u)
		return err
	})
	return out, err
}

// UpdateTx applies u to the administrator adminID inside tx and returns
// the admin before and after the change, both read under the
// administrators lock, so that the caller can tell exactly what changed.
// It enforces the last super admin rule: disabling or demoting the last
// usable super admin returns ErrLastSuperAdmin. Promoting an account that
// is not activated or has no TOTP enabled returns ErrPromotionRefused. It
// also returns ErrNotFound for an unknown admin or tenant and ErrInvalid
// for a malformed field or an inconsistent result (a super admin with
// tenants, a delegated admin without any).
func (r *Admins) UpdateTx(ctx context.Context, tx *SystemTx, adminID string, u AdminUpdate) (before, after Admin, err error) {
	before, after, err = r.update(ctx, tx, adminID, u)
	if err != nil {
		return Admin{}, Admin{}, wrap("update admin", err)
	}
	return before, after, nil
}

// update implements UpdateTx, returning raw errors.
func (r *Admins) update(ctx context.Context, tx *SystemTx, adminID string, u AdminUpdate) (Admin, Admin, error) {
	if err := tx.lock(ctx, lockAdmins); err != nil {
		return Admin{}, Admin{}, err
	}
	cur, err := getAdmin(ctx, tx, qAdminGet, adminID)
	if err != nil {
		return Admin{}, Admin{}, err
	}
	next := cur
	if u.Email != nil {
		next.Email = *u.Email
	}
	if u.Role != nil {
		next.Role = *u.Role
		if next.Role == RoleSuperAdmin && u.TenantIDs == nil {
			next.TenantIDs = nil
		}
	}
	if u.TenantIDs != nil {
		next.TenantIDs = *u.TenantIDs
	}
	if u.RequireTOTP != nil {
		next.RequireTOTP = *u.RequireTOTP
	}
	if u.Disabled != nil {
		next.Disabled = *u.Disabled
	}
	if u.Language != nil {
		next.Language = *u.Language
	}
	if err := normalizeAdmin(&next); err != nil {
		return Admin{}, Admin{}, err
	}
	if cur.Role != RoleSuperAdmin && next.Role == RoleSuperAdmin && (cur.PasswordHash == "" || !cur.TOTPEnabled) {
		return Admin{}, Admin{}, ErrPromotionRefused
	}
	if cur.usableSuperAdmin() && !next.usableSuperAdmin() {
		if err := guardLastSuperAdmin(ctx, tx); err != nil {
			return Admin{}, Admin{}, err
		}
	}
	now := fromMillis(toMillis(r.db.now()))
	next.UpdatedAt = now
	if _, err := tx.Exec(ctx, qAdminUpdate, next.Email, string(next.Role), next.RequireTOTP, next.Disabled,
		nullText(next.Language), toMillis(now), adminID); err != nil {
		return Admin{}, Admin{}, err
	}
	if !slices.Equal(cur.TenantIDs, next.TenantIDs) {
		if err := replaceTenants(ctx, tx, adminID, next.TenantIDs); err != nil {
			return Admin{}, Admin{}, err
		}
	}
	return cur, next, nil
}

// guardLastSuperAdmin returns ErrLastSuperAdmin unless another usable
// super admin exists besides the one being removed. The caller holds the
// administrators lock.
func guardLastSuperAdmin(ctx context.Context, tx *SystemTx) error {
	var n int64
	if err := tx.QueryRow(ctx, qAdminCountUsableSuper).Scan(&n); err != nil {
		return err
	}
	if n <= 1 {
		return ErrLastSuperAdmin
	}
	return nil
}

// SetPassword stores hash (a PHC string) as the password of the
// administrator adminID in its own transaction (see [Admins.SetPasswordTx]).
func (r *Admins) SetPassword(ctx context.Context, adminID, hash string) error {
	return r.write(ctx, "set admin password", func(tx *SystemTx) error { return r.setPassword(ctx, tx, adminID, hash) })
}

// SetPasswordTx stores hash as the password of adminID inside tx and sets
// CredentialsChangedAt. An empty hash removes the password (credentials
// reset: the account must be activated again). It returns ErrNotFound for
// an unknown admin and ErrInvalid for a malformed hash.
func (r *Admins) SetPasswordTx(ctx context.Context, tx *SystemTx, adminID, hash string) error {
	if err := r.setPassword(ctx, tx, adminID, hash); err != nil {
		return wrap("set admin password", err)
	}
	return nil
}

// setPassword implements SetPasswordTx, returning raw errors.
func (r *Admins) setPassword(ctx context.Context, tx *SystemTx, adminID, hash string) error {
	if !validPasswordHash(hash) {
		return invalid("password hash must be a PHC string of at most %d printable characters", MaxPasswordHashLen)
	}
	now := toMillis(r.db.now())
	res, err := tx.Exec(ctx, qAdminSetPassword, nullText(hash), now, now, adminID)
	if err != nil {
		return err
	}
	return expectOne(res)
}

// SetPendingTOTP starts a TOTP enrollment of adminID in its own
// transaction (see [Admins.SetPendingTOTPTx]).
func (r *Admins) SetPendingTOTP(ctx context.Context, adminID string, s SystemSecret) error {
	return r.write(ctx, "set pending totp", func(tx *SystemTx) error { return r.setPendingTOTP(ctx, tx, adminID, s) })
}

// SetPendingTOTPTx stores the sealed TOTP secret s (purpose
// SecretPurposeAdminTOTP) and makes it the pending enrollment of adminID,
// inside tx. A previous pending secret is destroyed; the TOTP in use, if
// any, is unchanged until [Admins.SetTOTP]. It returns ErrNotFound for an
// unknown admin, ErrInvalid for a malformed secret, ErrConflict when the
// secret ID is taken and ErrKeyRetired when s.KeyID is a retired master
// key.
func (r *Admins) SetPendingTOTPTx(ctx context.Context, tx *SystemTx, adminID string, s SystemSecret) error {
	if err := r.setPendingTOTP(ctx, tx, adminID, s); err != nil {
		return wrap("set pending totp", err)
	}
	return nil
}

// setPendingTOTP implements SetPendingTOTPTx, returning raw errors. The
// administrators lock is taken before the current secret IDs are read, so
// that concurrent enrollments cannot both replace the same pending secret
// and leave the other one orphaned.
func (r *Admins) setPendingTOTP(ctx context.Context, tx *SystemTx, adminID string, s SystemSecret) error {
	if err := tx.lock(ctx, lockAdmins); err != nil {
		return err
	}
	cur, err := scanAdmin(tx.QueryRow(ctx, qAdminGet, adminID))
	if err != nil {
		return err
	}
	if err := r.db.SystemSecrets().create(ctx, tx, s); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, qAdminSetPending, s.ID, toMillis(r.db.now()), adminID); err != nil {
		return err
	}
	return deleteSecrets(ctx, tx, cur.PendingTOTPSecretID)
}

// SetTOTP completes the TOTP enrollment of adminID in its own transaction
// (see [Admins.SetTOTPTx]).
func (r *Admins) SetTOTP(ctx context.Context, adminID, pendingSecretID string, counter int64) error {
	return r.write(ctx, "set totp", func(tx *SystemTx) error { return r.setTOTP(ctx, tx, adminID, pendingSecretID, counter) })
}

// SetTOTPTx completes a TOTP enrollment inside tx: the pending secret
// pendingSecretID (the one the confirmation code was verified against)
// becomes the TOTP secret in use, TOTP is enabled, counter (the time step
// of the confirmation code, >= 0) becomes the last accepted counter so the
// code cannot be replayed, and CredentialsChangedAt is set. The previous
// secret, if any, is destroyed. Recovery codes are not touched (see
// [AdminRecoveryCodes.ReplaceTx]). It returns ErrNotFound when adminID
// does not exist or pendingSecretID is no longer its pending secret, and
// ErrInvalid for a negative counter.
func (r *Admins) SetTOTPTx(ctx context.Context, tx *SystemTx, adminID, pendingSecretID string, counter int64) error {
	if err := r.setTOTP(ctx, tx, adminID, pendingSecretID, counter); err != nil {
		return wrap("set totp", err)
	}
	return nil
}

// setTOTP implements SetTOTPTx, returning raw errors. The administrators
// lock is taken before the secret in use is read (see setPendingTOTP).
func (r *Admins) setTOTP(ctx context.Context, tx *SystemTx, adminID, pendingSecretID string, counter int64) error {
	if counter < 0 {
		return invalid("negative totp counter")
	}
	if err := tx.lock(ctx, lockAdmins); err != nil {
		return err
	}
	cur, err := scanAdmin(tx.QueryRow(ctx, qAdminGet, adminID))
	if err != nil {
		return err
	}
	now := toMillis(r.db.now())
	res, err := tx.Exec(ctx, qAdminSetTOTP, counter, now, now, adminID, pendingSecretID)
	if err != nil {
		return err
	}
	if err := expectOne(res); err != nil {
		return err
	}
	return deleteSecrets(ctx, tx, cur.TOTPSecretID)
}

// ClearTOTP removes the TOTP enrollment of adminID in its own transaction
// (see [Admins.ClearTOTPTx]).
func (r *Admins) ClearTOTP(ctx context.Context, adminID string) error {
	return r.write(ctx, "clear totp", func(tx *SystemTx) error { return r.clearTOTP(ctx, tx, adminID) })
}

// ClearTOTPTx removes the TOTP enrollment of adminID inside tx (disabling
// TOTP, local reset-totp, credentials reset): TOTP is disabled, the secret
// in use and the pending one are destroyed (cryptographic erasure), the
// last counter is forgotten, every recovery code is deleted and
// CredentialsChangedAt is set. Sessions are not revoked (see
// [AdminSessions.DeleteByAdminTx]). It returns ErrNotFound for an unknown
// admin.
func (r *Admins) ClearTOTPTx(ctx context.Context, tx *SystemTx, adminID string) error {
	if err := r.clearTOTP(ctx, tx, adminID); err != nil {
		return wrap("clear totp", err)
	}
	return nil
}

// clearTOTP implements ClearTOTPTx, returning raw errors. The
// administrators lock is taken before the secret IDs are read (see
// setPendingTOTP).
func (r *Admins) clearTOTP(ctx context.Context, tx *SystemTx, adminID string) error {
	if err := tx.lock(ctx, lockAdmins); err != nil {
		return err
	}
	cur, err := scanAdmin(tx.QueryRow(ctx, qAdminGet, adminID))
	if err != nil {
		return err
	}
	now := toMillis(r.db.now())
	if _, err := tx.Exec(ctx, qAdminClearTOTP, now, now, adminID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, qRecoveryDeleteAll, adminID); err != nil {
		return err
	}
	return deleteSecrets(ctx, tx, cur.TOTPSecretID, cur.PendingTOTPSecretID)
}

// AdvanceTOTPCounter records counter as the last accepted TOTP time step
// of adminID, atomically and only if TOTP is enabled and counter is
// greater than the last accepted one. It reports whether the code was
// accepted: false means a replay (or an older step) and the login must be
// refused (T-60). Concurrent logins with the same code cannot both be
// accepted. It returns ErrInvalid for a negative counter.
func (r *Admins) AdvanceTOTPCounter(ctx context.Context, adminID string, counter int64) (bool, error) {
	if counter < 0 {
		return false, invalid("negative totp counter")
	}
	var accepted bool
	err := r.write(ctx, "advance totp counter", func(tx *SystemTx) error {
		res, err := tx.Exec(ctx, qAdminAdvanceCounter, counter, adminID, counter)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		accepted = n == 1
		return err
	})
	return accepted, err
}

// TouchLogin records a successful login of adminID now (LastLoginAt). It
// returns ErrNotFound for an unknown admin.
func (r *Admins) TouchLogin(ctx context.Context, adminID string) error {
	return r.write(ctx, "touch admin login", func(tx *SystemTx) error {
		res, err := tx.Exec(ctx, qAdminTouchLogin, toMillis(r.db.now()), adminID)
		if err != nil {
			return err
		}
		return expectOne(res)
	})
}

// Delete removes the administrator adminID in its own transaction (see
// [Admins.DeleteTx]).
func (r *Admins) Delete(ctx context.Context, adminID string) error {
	return r.write(ctx, "delete admin", func(tx *SystemTx) error { return r.deleteAdmin(ctx, tx, adminID) })
}

// DeleteTx removes the administrator adminID inside tx, with, by cascade,
// its tenant attachments, sessions, recovery codes and activation links,
// and destroys its TOTP secrets. It takes the administrators lock and
// returns ErrLastSuperAdmin for the last usable super admin, ErrNotFound
// for an unknown admin.
func (r *Admins) DeleteTx(ctx context.Context, tx *SystemTx, adminID string) error {
	if err := r.deleteAdmin(ctx, tx, adminID); err != nil {
		return wrap("delete admin", err)
	}
	return nil
}

// deleteAdmin implements DeleteTx, returning raw errors.
func (r *Admins) deleteAdmin(ctx context.Context, tx *SystemTx, adminID string) error {
	if err := tx.lock(ctx, lockAdmins); err != nil {
		return err
	}
	cur, err := scanAdmin(tx.QueryRow(ctx, qAdminGet, adminID))
	if err != nil {
		return err
	}
	if cur.usableSuperAdmin() {
		if err := guardLastSuperAdmin(ctx, tx); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, qAdminDelete, adminID); err != nil {
		return err
	}
	return deleteSecrets(ctx, tx, cur.TOTPSecretID, cur.PendingTOTPSecretID)
}

// CountUsableSuperAdminsTx returns, inside tx, the number of usable super
// admins (not disabled, password set, TOTP enabled: those who can sign in)
// after taking the administrators lock, so that the count stays true until
// tx ends. It serves a check the store does not enforce itself: the
// credentials reset of a super admin is refused when the target is the
// last usable one.
func (r *Admins) CountUsableSuperAdminsTx(ctx context.Context, tx *SystemTx) (int64, error) {
	return r.countLocked(ctx, tx, "count usable super admins", qAdminCountUsableSuper)
}

// CountAll returns the number of administrators (0 until the setup).
func (r *Admins) CountAll(ctx context.Context) (int64, error) {
	var n int64
	err := r.read(ctx, "count admins", func(tx *SystemTx) error {
		return tx.QueryRow(ctx, qAdminCountAll).Scan(&n)
	})
	return n, err
}

// CountAllTx returns, inside tx, the number of administrators after taking
// the administrators lock. The setup calls it, then creates the super
// admin with [Admins.CreateTx] only when it returned 0, in the same
// transaction: concurrent setups are serialized (advisory lock on
// PostgreSQL, single writer on SQLite), so only one can succeed.
func (r *Admins) CountAllTx(ctx context.Context, tx *SystemTx) (int64, error) {
	return r.countLocked(ctx, tx, "count admins", qAdminCountAll)
}

// countLocked takes the administrators lock and runs the count q.
func (r *Admins) countLocked(ctx context.Context, tx *SystemTx, op string, q SystemQuery) (int64, error) {
	if err := tx.lock(ctx, lockAdmins); err != nil {
		return 0, wrap(op, err)
	}
	var n int64
	if err := tx.QueryRow(ctx, q).Scan(&n); err != nil {
		return 0, wrap(op, err)
	}
	return n, nil
}

// TenantIDs returns the sorted tenants of the administrator adminID (empty
// for a super admin or an unknown admin).
func (r *Admins) TenantIDs(ctx context.Context, adminID string) ([]tenant.ID, error) {
	var ids []tenant.ID
	err := r.read(ctx, "list admin tenants", func(tx *SystemTx) error {
		var err error
		ids, err = adminTenants(ctx, tx, adminID)
		return err
	})
	return ids, err
}
