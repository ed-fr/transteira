package store

import (
	"context"
	"database/sql"

	"github.com/ed-fr/transteira/internal/tenant"
)

// reasonAdminContacts is the reason of the administrator contact queries.
const reasonAdminContacts = "administrator alerts: mail addresses and languages of the administrators to notify"

// Statements of the administrator contacts. A contact is an account that
// can sign in: enabled, with a password (activated).
var (
	qAdminTenantContacts = systemQuery(
		`SELECT a.id, a.email, a.language FROM admins a JOIN admin_tenants t ON t.admin_id = a.id
		WHERE t.tenant_id = ? AND a.role = 'delegated_admin' AND a.disabled = false AND a.password_hash IS NOT NULL
		ORDER BY a.id`,
		reasonAdminContacts)
	qAdminSuperContacts = systemQuery(
		`SELECT id, email, language FROM admins
		WHERE role = 'super_admin' AND disabled = false AND password_hash IS NOT NULL ORDER BY id`,
		reasonAdminContacts)
)

// AdminContact is an administrator to notify (quota alerts, disk alert).
type AdminContact struct {
	// AdminID is the identifier of the administrator.
	AdminID string
	// Email is its normalized mail address.
	Email string
	// Language is its preferred language, "" for the default.
	Language string
}

// contacts runs the contact query q with args.
func (r *Admins) contacts(ctx context.Context, op string, q SystemQuery, args ...any) ([]AdminContact, error) {
	var out []AdminContact
	err := r.db.systemScope(reasonAdminContacts).ReadTx(ctx, func(tx *SystemTx) error {
		rows, err := tx.Query(ctx, q, args...)
		if err != nil {
			return err
		}
		out, err = collect(rows, func(r *sql.Rows) (AdminContact, error) {
			var (
				c    AdminContact
				lang sql.NullString
			)
			err := r.Scan(&c.AdminID, &c.Email, &lang)
			c.Language = lang.String
			return c, err
		})
		return err
	})
	if err != nil {
		return nil, wrap(op, err)
	}
	return out, nil
}

// TenantContacts returns the delegated admins attached to tenant tid that
// can sign in (enabled and activated), by ID: the recipients of the tenant
// alerts. The list is empty when there is none (callers then notify the
// super admins). It returns ErrInvalid for a malformed tenant ID.
func (r *Admins) TenantContacts(ctx context.Context, tid tenant.ID) ([]AdminContact, error) {
	if err := tid.Validate(); err != nil {
		return nil, invalid("malformed tenant id")
	}
	return r.contacts(ctx, "list tenant contacts", qAdminTenantContacts, string(tid))
}

// SuperAdminContacts returns the super admins that can sign in (enabled
// and activated), by ID.
func (r *Admins) SuperAdminContacts(ctx context.Context) ([]AdminContact, error) {
	return r.contacts(ctx, "list super admin contacts", qAdminSuperContacts)
}
