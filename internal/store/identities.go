package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/tenant"
)

// adminIdentityPrefix starts the identifier of a pinned single sign-on
// identity ("aid_" + ULID, migration 0027).
const adminIdentityPrefix id.Prefix = "aid"

// MaxSSOSubjectLen bounds the subject (sub claim) of a pinned identity, in
// bytes.
const MaxSSOSubjectLen = 255

// reasonAdminIdentities is the reason of the identity system queries.
const reasonAdminIdentities = "administrator single sign-on identities (system table, no tenant)"

// adminIdentityColumns is the column list read by the identity queries.
const adminIdentityColumns = `id, admin_id, issuer, client_id, subject, created_at, last_used_at`

// Statements of the AdminIdentities repository.
var (
	qIdentityInsert = systemQuery(
		`INSERT INTO admin_identities (id, admin_id, issuer, client_id, subject, created_at, last_used_at)
		VALUES (?, ?, ?, ?, ?, ?, NULL)`,
		reasonAdminIdentities)
	qIdentityFind = systemQuery(
		`SELECT `+adminIdentityColumns+` FROM admin_identities WHERE issuer = ? AND client_id = ? AND subject = ?`,
		reasonAdminIdentities)
	qIdentityForAdmin = systemQuery(
		`SELECT `+adminIdentityColumns+` FROM admin_identities WHERE admin_id = ? AND issuer = ? AND client_id = ?`,
		reasonAdminIdentities)
	qIdentityList = systemQuery(
		`SELECT `+adminIdentityColumns+` FROM admin_identities WHERE admin_id = ? ORDER BY id`,
		reasonAdminIdentities)
	qIdentityTouch = systemQuery(
		`UPDATE admin_identities SET last_used_at = ? WHERE id = ?`,
		reasonAdminIdentities)
	qIdentityDelete = systemQuery(
		`DELETE FROM admin_identities WHERE id = ? AND admin_id = ? RETURNING `+adminIdentityColumns,
		reasonAdminIdentities)
	qIdentityDeleteByAdmin = systemQuery(
		`DELETE FROM admin_identities WHERE admin_id = ? RETURNING `+adminIdentityColumns,
		reasonAdminIdentities)
	// qIdentityDeleteForTenantClient unpins the identities of an (issuer,
	// client ID) pair held by the accounts attached to a tenant, except for
	// the accounts attached to another tenant whose configuration still
	// uses that pair (their pin is still in use there).
	qIdentityDeleteForTenantClient = systemQuery(
		`DELETE FROM admin_identities WHERE issuer = ? AND client_id = ?
		AND admin_id IN (SELECT admin_id FROM admin_tenants WHERE tenant_id = ?)
		AND NOT EXISTS (SELECT 1 FROM admin_tenants o JOIN tenant_sso_settings s ON s.tenant_id = o.tenant_id
			WHERE o.admin_id = admin_identities.admin_id AND o.tenant_id <> ? AND s.issuer = ? AND s.client_id = ?)
		RETURNING `+adminIdentityColumns,
		reasonAdminIdentities)
)

// AdminIdentity is a single sign-on identity pinned to an administrator
// account at its first single sign-on login (OpenAPI AdminIdentity,
// threat T-286). Afterwards the account is matched by (Issuer, ClientID,
// Subject) only: Entra ID subjects are pairwise per application.
type AdminIdentity struct {
	// ID is the identifier ("aid_" + ULID), assigned by the store.
	ID string
	// AdminID is the account the identity is pinned to.
	AdminID string
	// Issuer is the iss claim of the ID token (MinSSOIssuerLen to
	// MaxSSOIssuerLen printable ASCII bytes).
	Issuer string
	// ClientID is the application (audience) the login went through (1 to
	// MaxSSOClientIDLen printable ASCII bytes).
	ClientID string
	// Subject is the sub claim of the ID token (1 to MaxSSOSubjectLen
	// printable ASCII bytes). It is a pseudonymous identifier.
	Subject string
	// CreatedAt is the pinning time (OpenAPI linkedAt), set by the store.
	CreatedAt time.Time
	// LastUsedAt is the last login through the identity, zero if none.
	LastUsedAt time.Time
}

// AdminIdentities is the repository of the pinned single sign-on
// identities. Instance table, like admins: its operations are
// system-scoped and callers check the caller's rights first. Obtain it
// with [DB.AdminIdentities]. The Tx variants run inside a transaction of
// [Admins.Tx], with the audit event of the change.
type AdminIdentities struct {
	db *DB
}

// AdminIdentities returns the identity repository.
func (db *DB) AdminIdentities() *AdminIdentities { return &AdminIdentities{db: db} }

// scanIdentity reads one row of adminIdentityColumns.
func scanIdentity(sc interface{ Scan(...any) error }) (AdminIdentity, error) {
	var (
		a       AdminIdentity
		created int64
		used    sql.NullInt64
	)
	if err := sc.Scan(&a.ID, &a.AdminID, &a.Issuer, &a.ClientID, &a.Subject, &created, &used); err != nil {
		return AdminIdentity{}, err
	}
	a.CreatedAt, a.LastUsedAt = fromMillis(created), nullMillis(used)
	return a, nil
}

// scanIdentities collects identity rows.
func scanIdentities(rows *sql.Rows, err error) ([]AdminIdentity, error) {
	if err != nil {
		return nil, err
	}
	return collect(rows, func(r *sql.Rows) (AdminIdentity, error) { return scanIdentity(r) })
}

// validIdentityKey reports whether issuer and clientID have the shape of
// stored values (the issuer is not re-validated as a URL: it comes from a
// stored configuration).
func validIdentityKey(issuer, clientID string) bool {
	return len(issuer) >= MinSSOIssuerLen && isPrintableASCII(issuer, MaxSSOIssuerLen) && validClientID(clientID)
}

// Find returns the identity pinned with (issuer, clientID, subject), or
// ErrNotFound (also for malformed arguments).
func (r *AdminIdentities) Find(ctx context.Context, issuer, clientID, subject string) (AdminIdentity, error) {
	if !validIdentityKey(issuer, clientID) || !isPrintableASCII(subject, MaxSSOSubjectLen) {
		return AdminIdentity{}, wrap("find admin identity", ErrNotFound)
	}
	var a AdminIdentity
	err := r.db.authRead(ctx, "find admin identity", func(tx *SystemTx) error {
		var err error
		a, err = scanIdentity(tx.QueryRow(ctx, qIdentityFind, issuer, clientID, subject))
		return err
	})
	return a, err
}

// ForAdmin returns the identity of adminID for (issuer, clientID), or
// ErrNotFound (also for malformed arguments): at most one exists.
func (r *AdminIdentities) ForAdmin(ctx context.Context, adminID, issuer, clientID string) (AdminIdentity, error) {
	if !validIdentityKey(issuer, clientID) {
		return AdminIdentity{}, wrap("get admin identity", ErrNotFound)
	}
	var a AdminIdentity
	err := r.db.authRead(ctx, "get admin identity", func(tx *SystemTx) error {
		var err error
		a, err = scanIdentity(tx.QueryRow(ctx, qIdentityForAdmin, adminID, issuer, clientID))
		return err
	})
	return a, err
}

// List returns the identities of adminID, in ID order (empty for an
// unknown admin).
func (r *AdminIdentities) List(ctx context.Context, adminID string) ([]AdminIdentity, error) {
	var out []AdminIdentity
	err := r.db.authRead(ctx, "list admin identities", func(tx *SystemTx) error {
		var err error
		out, err = scanIdentities(tx.Query(ctx, qIdentityList, adminID))
		return err
	})
	return out, err
}

// ListTx returns the identities of adminID inside tx, after taking the
// administrators lock, held until tx ends: no identity can be pinned to
// the account meanwhile. A promotion to super admin ([Admins.UpdateTx])
// deletes them all; calling ListTx first in the same transaction tells the
// caller exactly which ones, for the audit (admin.identity_unlinked).
func (r *AdminIdentities) ListTx(ctx context.Context, tx *SystemTx, adminID string) ([]AdminIdentity, error) {
	if err := tx.lock(ctx, lockAdmins); err != nil {
		return nil, err
	}
	out, err := scanIdentities(tx.Query(ctx, qIdentityList, adminID))
	if err != nil {
		return nil, wrap("list admin identities", err)
	}
	return out, nil
}

// Link pins an identity in its own transaction (see
// [AdminIdentities.LinkTx]).
func (r *AdminIdentities) Link(ctx context.Context, a AdminIdentity) (AdminIdentity, error) {
	var out AdminIdentity
	err := r.db.authWrite(ctx, "link admin identity", func(tx *SystemTx) error {
		var err error
		out, err = r.link(ctx, tx, a)
		return err
	})
	return out, err
}

// LinkTx pins the identity (a.Issuer, a.ClientID, a.Subject) to the
// account a.AdminID inside tx, under the administrators lock, assigns its
// ID and creation time, and returns it. It returns ErrInvalid for a
// malformed field or a super admin account (a super admin never signs in
// through single sign-on, threat T-293), ErrNotFound for an unknown admin
// and [ErrIdentityConflict] when the identity is already pinned (to this
// or another account) or the account already has an identity for (issuer,
// client ID).
func (r *AdminIdentities) LinkTx(ctx context.Context, tx *SystemTx, a AdminIdentity) (AdminIdentity, error) {
	out, err := r.link(ctx, tx, a)
	if err != nil {
		return AdminIdentity{}, wrap("link admin identity", err)
	}
	return out, nil
}

// link implements LinkTx, returning raw errors.
func (r *AdminIdentities) link(ctx context.Context, tx *SystemTx, a AdminIdentity) (AdminIdentity, error) {
	switch {
	case !id.Valid(id.Admin, a.AdminID):
		return AdminIdentity{}, invalid("malformed admin id")
	case !validIdentityKey(a.Issuer, a.ClientID):
		return AdminIdentity{}, invalid("malformed issuer or client id")
	case !isPrintableASCII(a.Subject, MaxSSOSubjectLen):
		return AdminIdentity{}, invalid("subject must be 1 to %d printable ascii bytes", MaxSSOSubjectLen)
	}
	if err := tx.lock(ctx, lockAdmins); err != nil {
		return AdminIdentity{}, err
	}
	adm, err := scanAdmin(tx.QueryRow(ctx, qAdminGet, a.AdminID))
	if err != nil {
		return AdminIdentity{}, err
	}
	if adm.Role == RoleSuperAdmin {
		return AdminIdentity{}, invalid("a super admin has no single sign-on identity")
	}
	newID, err := r.db.newID(adminIdentityPrefix)
	if err != nil {
		return AdminIdentity{}, err
	}
	out := AdminIdentity{
		ID: newID, AdminID: a.AdminID, Issuer: a.Issuer, ClientID: a.ClientID, Subject: a.Subject,
		CreatedAt: fromMillis(toMillis(r.db.now())),
	}
	if _, err := tx.Exec(ctx, qIdentityInsert, out.ID, out.AdminID, out.Issuer, out.ClientID, out.Subject,
		toMillis(out.CreatedAt)); err != nil {
		if errors.Is(classify(err), ErrConflict) {
			return AdminIdentity{}, ErrIdentityConflict
		}
		return AdminIdentity{}, err
	}
	return out, nil
}

// Touch records a login through the identity identityID at at
// (LastUsedAt). It returns ErrNotFound for an unknown identity.
func (r *AdminIdentities) Touch(ctx context.Context, identityID string, at time.Time) error {
	return r.db.authWrite(ctx, "touch admin identity", func(tx *SystemTx) error {
		res, err := tx.Exec(ctx, qIdentityTouch, toMillis(r.db.orNow(at)), identityID)
		if err != nil {
			return err
		}
		return expectOne(res)
	})
}

// Delete unpins an identity in its own transaction (see
// [AdminIdentities.DeleteTx]).
func (r *AdminIdentities) Delete(ctx context.Context, adminID, identityID string) (AdminIdentity, error) {
	var out AdminIdentity
	err := r.db.authWrite(ctx, "delete admin identity", func(tx *SystemTx) error {
		var err error
		out, err = scanIdentity(tx.QueryRow(ctx, qIdentityDelete, identityID, adminID))
		return err
	})
	return out, err
}

// DeleteTx unpins, inside tx, the identity identityID of the account
// adminID (OpenAPI deleteAdminIdentity) and returns it. It returns
// ErrNotFound when the identity does not exist or belongs to another
// account. The sessions it opened are not revoked (see
// [AdminSessions.DeleteByAdminTx]).
func (r *AdminIdentities) DeleteTx(ctx context.Context, tx *SystemTx, adminID, identityID string) (AdminIdentity, error) {
	out, err := scanIdentity(tx.QueryRow(ctx, qIdentityDelete, identityID, adminID))
	if err != nil {
		return AdminIdentity{}, wrap("delete admin identity", err)
	}
	return out, nil
}

// DeleteForTenantClient unpins identities in its own transaction (see
// [AdminIdentities.DeleteForTenantClientTx]).
func (r *AdminIdentities) DeleteForTenantClient(ctx context.Context, tid tenant.ID, issuer, clientID string) ([]AdminIdentity, error) {
	var out []AdminIdentity
	err := r.db.authWrite(ctx, "unpin tenant identities", func(tx *SystemTx) error {
		var err error
		out, err = deleteForTenantClient(ctx, tx, tid, issuer, clientID)
		return err
	})
	return out, err
}

// DeleteForTenantClientTx unpins, inside tx, the identities of the pair
// (issuer, clientID) held by the accounts attached to tenant tid, and
// returns them (for the audit, admin.identity_unlinked). The caller runs
// it when the configuration of tid changes its issuer or its client ID,
// with the previous pair (threat T-287, P57). An account also attached to
// another tenant whose configuration (enabled or not) still uses that pair
// keeps its identity: the pin is still in use there, and dropping it would
// only make the next login fall back to the weaker e-mail match (T-286).
// The accounts of other tenants are never touched.
func (r *AdminIdentities) DeleteForTenantClientTx(ctx context.Context, tx *SystemTx, tid tenant.ID, issuer, clientID string) ([]AdminIdentity, error) {
	out, err := deleteForTenantClient(ctx, tx, tid, issuer, clientID)
	if err != nil {
		return nil, wrap("unpin tenant identities", err)
	}
	return out, nil
}

// deleteForTenantClient implements DeleteForTenantClientTx, returning raw
// errors.
func deleteForTenantClient(ctx context.Context, tx *SystemTx, tid tenant.ID, issuer, clientID string) ([]AdminIdentity, error) {
	if tid.Validate() != nil {
		return nil, invalid("malformed tenant id")
	}
	return scanIdentities(tx.Query(ctx, qIdentityDeleteForTenantClient, issuer, clientID, string(tid), string(tid),
		issuer, clientID))
}

// deleteIdentitiesByAdmin unpins every identity of adminID inside tx (a
// promotion to super admin, threat T-293) and returns how many it deleted.
func deleteIdentitiesByAdmin(ctx context.Context, tx *SystemTx, adminID string) (int, error) {
	out, err := scanIdentities(tx.Query(ctx, qIdentityDeleteByAdmin, adminID))
	return len(out), err
}
