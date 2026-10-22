package adminauth

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// FieldCursor names the cursor query parameter in an *InvalidError.
const FieldCursor = "cursor"

// cliActor is the actor of the audit events of the local command.
const cliActor = "cli"

// listAccountsPage is the page size of ListAccounts (a variable for the
// tests).
var listAccountsPage = store.MaxPageSize

// AdminCreate is a request to create an account (OpenAPI AdminCreate).
type AdminCreate struct {
	// Username and Email of the new administrator.
	Username string
	Email    string
	// Role must be store.RoleDelegatedAdmin: a super admin is created by
	// promoting an activated delegated admin with TOTP enabled
	// ([AdminUpdate].Role), so that no super admin account ever exists
	// without both factors.
	Role store.AdminRole
	// TenantIDs are the tenants of the administrator, at least one.
	TenantIDs []tenant.ID
	// RequireTOTP makes the TOTP enrollment mandatory (true when nil).
	RequireTOTP *bool
}

// AdminUpdate lists the changes of an account (OpenAPI AdminUpdate); nil
// fields are left unchanged.
type AdminUpdate struct {
	// Email is the new mail address.
	Email *string
	// Role is the new role. Promoting to super admin needs an activated
	// account with TOTP enabled and clears the tenants; demoting needs
	// TenantIDs.
	Role *store.AdminRole
	// TenantIDs replaces the tenants of a delegated admin.
	TenantIDs *[]tenant.ID
	// RequireTOTP is the new TOTP requirement (ignored for a super admin).
	RequireTOTP *bool
	// Disabled blocks or unblocks the account.
	Disabled *bool
}

// manager checks that p may manage accounts: an authenticated super admin.
func manager(p Principal) error {
	if err := RequireAuthenticated(p); err != nil {
		return err
	}
	return RequireSuperAdmin(p.Admin)
}

// checkTenantIDs validates a list of tenant IDs.
func checkTenantIDs(tids []tenant.ID) error {
	if len(tids) > store.MaxAdminTenants {
		return invalid(FieldTenantIDs)
	}
	for _, t := range tids {
		if t.Validate() != nil {
			return invalid(FieldTenantIDs)
		}
	}
	return nil
}

// List returns a page of accounts, for the super admin of p. cursor is the
// NextCursor of the previous page ("" for the first), limit the page size
// (store.DefaultPageSize when <= 0).
func (s *Service) List(ctx context.Context, p Principal, cursor string, limit int) (store.Page[Account], error) {
	if err := manager(p); err != nil {
		return store.Page[Account]{}, err
	}
	page, err := s.repo.listAdmins(ctx, store.AdminListOptions{Cursor: cursor, Limit: limit})
	switch {
	case errors.Is(err, store.ErrInvalid):
		return store.Page[Account]{}, invalid(FieldCursor)
	case err != nil:
		return store.Page[Account]{}, fmt.Errorf("adminauth: list admins: %w", err)
	}
	out := store.Page[Account]{Items: make([]Account, len(page.Items)), NextCursor: page.NextCursor}
	for i, a := range page.Items {
		out.Items[i] = accountOf(a)
	}
	return out, nil
}

// Get returns the account adminID, for the super admin of p, or
// ErrNotFound.
func (s *Service) Get(ctx context.Context, p Principal, adminID string) (Account, error) {
	if err := manager(p); err != nil {
		return Account{}, err
	}
	a, err := s.repo.admin(ctx, adminID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return Account{}, ErrNotFound
	case err != nil:
		return Account{}, fmt.Errorf("adminauth: read admin: %w", err)
	}
	return accountOf(a), nil
}

// Create creates a delegated admin for the super admin of p, from
// clientIP, with a single-use activation link valid ActivationTTL. The
// link is returned once and never mailed: the super admin hands it to the
// administrator out of band. The account has no password until the link
// is used.
//
// It returns ErrUnauthenticated or ErrForbidden for a caller who is not an
// authenticated super admin, an *InvalidError for a malformed field, a
// role other than delegated_admin, no tenant or an unknown tenant, and
// ErrAlreadyExists for a username taken.
func (s *Service) Create(ctx context.Context, p Principal, req AdminCreate, clientIP netip.Addr) (Account, Activation, error) {
	if err := manager(p); err != nil {
		return Account{}, Activation{}, err
	}
	username, err := store.NormalizeUsername(req.Username)
	if err != nil {
		return Account{}, Activation{}, invalid(FieldUsername)
	}
	email, err := store.NormalizeEmail(req.Email)
	if err != nil {
		return Account{}, Activation{}, invalid(FieldEmail)
	}
	if req.Role != store.RoleDelegatedAdmin {
		return Account{}, Activation{}, invalid(FieldRole)
	}
	if len(req.TenantIDs) == 0 {
		return Account{}, Activation{}, invalid(FieldTenantIDs)
	}
	if err := checkTenantIDs(req.TenantIDs); err != nil {
		return Account{}, Activation{}, err
	}
	requireTOTP := req.RequireTOTP == nil || *req.RequireTOTP
	var (
		created store.Admin
		link    Activation
	)
	err = s.repo.tx(ctx, func(tx txRepo) error {
		a, err := tx.createAdmin(ctx, store.Admin{
			Username: username, Email: email, Role: store.RoleDelegatedAdmin, TenantIDs: req.TenantIDs, RequireTOTP: requireTOTP,
		})
		if err != nil {
			return err
		}
		row, out, err := s.newActivation(a.ID, s.now())
		if err != nil {
			return err
		}
		if err := tx.createActivation(ctx, row); err != nil {
			return err
		}
		ev := adminEvent(p.Admin.Username, clientIP, audit.ActionAdminCreated, a.ID, map[string]any{
			"username": a.Username, "role": string(a.Role), "tenant_ids": a.TenantIDs, "require_totp": a.RequireTOTP,
		})
		if err := tx.audit(ctx, ev); err != nil {
			return err
		}
		created, link = a, out
		return nil
	})
	switch {
	case errors.Is(err, store.ErrConflict):
		return Account{}, Activation{}, ErrAlreadyExists
	case errors.Is(err, store.ErrNotFound):
		return Account{}, Activation{}, invalid(FieldTenantIDs)
	case err != nil:
		return Account{}, Activation{}, fmt.Errorf("adminauth: create admin: %w", err)
	}
	return accountOf(created), link, nil
}

// Update changes the account adminID for the super admin of p, from
// clientIP. Disabling the account, changing its role or tenants, or making
// TOTP mandatory while it is not enrolled revokes its sessions. Changing
// its role, tenants or mail address revokes its pending activation links,
// in the same transaction: a link handed out for the former account cannot
// open the changed one.
//
// It returns ErrUnauthenticated or ErrForbidden for a caller who is not an
// authenticated super admin, an *InvalidError for a malformed field or an
// inconsistent result (a delegated admin without tenant, a super admin
// with tenants, an unknown tenant), ErrNotFound for an unknown account,
// ErrSelfAction when the caller disables or demotes themselves,
// ErrNotPromotable when an account not activated or without TOTP would be
// promoted to super admin and ErrLastSuperAdmin when the last usable super
// admin would be disabled or demoted.
func (s *Service) Update(ctx context.Context, p Principal, adminID string, u AdminUpdate, clientIP netip.Addr) (Account, error) {
	if err := manager(p); err != nil {
		return Account{}, err
	}
	if u.Email != nil {
		if _, err := store.NormalizeEmail(*u.Email); err != nil {
			return Account{}, invalid(FieldEmail)
		}
	}
	if u.Role != nil && *u.Role != store.RoleSuperAdmin && *u.Role != store.RoleDelegatedAdmin {
		return Account{}, invalid(FieldRole)
	}
	if u.TenantIDs != nil {
		if err := checkTenantIDs(*u.TenantIDs); err != nil {
			return Account{}, err
		}
	}
	if adminID == p.Admin.ID && ((u.Disabled != nil && *u.Disabled) || (u.Role != nil && *u.Role != p.Admin.Role)) {
		return Account{}, ErrSelfAction
	}
	var next store.Admin
	err := s.repo.tx(ctx, func(tx txRepo) error {
		// An unknown account is told apart from an unknown tenant first.
		if _, err := tx.admin(ctx, adminID); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return ErrNotFound
			}
			return err
		}
		// The store reads the account again under the administrators lock:
		// cur and after describe exactly this change.
		cur, after, err := tx.updateAdmin(ctx, adminID, store.AdminUpdate{
			Email: u.Email, Role: u.Role, TenantIDs: u.TenantIDs, RequireTOTP: u.RequireTOTP, Disabled: u.Disabled,
		})
		switch {
		case errors.Is(err, store.ErrLastSuperAdmin):
			return ErrLastSuperAdmin
		case errors.Is(err, store.ErrPromotionRefused):
			return ErrNotPromotable
		case errors.Is(err, store.ErrNotFound), errors.Is(err, store.ErrInvalid):
			return invalid(FieldTenantIDs)
		case err != nil:
			return err
		}
		next = after
		changed, revoke, relink := diff(cur, after)
		if revoke {
			if _, err := tx.deleteSessions(ctx, adminID, ""); err != nil {
				return err
			}
		}
		if relink {
			if _, err := tx.deleteActivations(ctx, adminID); err != nil {
				return err
			}
		}
		return tx.audit(ctx, adminEvent(p.Admin.Username, clientIP, audit.ActionAdminUpdated, adminID,
			map[string]any{"changed": changed, "sessions_revoked": revoke}))
	})
	switch {
	case errors.Is(err, ErrNotFound), errors.Is(err, ErrStateConflict), errors.Is(err, ErrInvalid):
		return Account{}, err
	case err != nil:
		return Account{}, fmt.Errorf("adminauth: update admin: %w", err)
	}
	return accountOf(next), nil
}

// diff returns the fields that differ between cur and next, whether the
// sessions of the account must be revoked (disabled, role or tenants
// changed, or TOTP made mandatory while not enrolled) and whether its
// pending activation links must be revoked (role, tenants or mail address
// changed).
func diff(cur, next store.Admin) (changed []string, revoke, relink bool) {
	changed = []string{}
	if cur.Email != next.Email {
		changed, relink = append(changed, "email"), true
	}
	if cur.Role != next.Role {
		changed, revoke, relink = append(changed, "role"), true, true
	}
	if !slices.Equal(cur.TenantIDs, next.TenantIDs) {
		changed, revoke, relink = append(changed, "tenant_ids"), true, true
	}
	if cur.RequireTOTP != next.RequireTOTP {
		changed = append(changed, "require_totp")
		revoke = revoke || (next.RequireTOTP && !next.TOTPEnabled)
	}
	if cur.Disabled != next.Disabled {
		changed = append(changed, "disabled")
		revoke = revoke || next.Disabled
	}
	return changed, revoke, relink
}

// Delete deletes the account adminID for the super admin of p, from
// clientIP, with its sessions, recovery codes, activation links and TOTP
// secrets.
//
// It returns ErrUnauthenticated or ErrForbidden for a caller who is not an
// authenticated super admin, ErrSelfAction for the caller's own account,
// ErrNotFound for an unknown account and ErrLastSuperAdmin for the last
// usable super admin.
func (s *Service) Delete(ctx context.Context, p Principal, adminID string, clientIP netip.Addr) error {
	if err := manager(p); err != nil {
		return err
	}
	if adminID == p.Admin.ID {
		return ErrSelfAction
	}
	err := s.repo.tx(ctx, func(tx txRepo) error {
		cur, err := tx.admin(ctx, adminID)
		if errors.Is(err, store.ErrNotFound) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if err := tx.deleteAdmin(ctx, adminID); err != nil {
			if errors.Is(err, store.ErrLastSuperAdmin) {
				return ErrLastSuperAdmin
			}
			return err
		}
		return tx.audit(ctx, adminEvent(p.Admin.Username, clientIP, audit.ActionAdminDeleted, adminID,
			map[string]any{"username": cur.Username, "role": string(cur.Role)}))
	})
	switch {
	case errors.Is(err, ErrNotFound), errors.Is(err, ErrStateConflict):
		return err
	case err != nil:
		return fmt.Errorf("adminauth: delete admin: %w", err)
	}
	return nil
}

// ResetCredentials clears the password, TOTP and recovery codes of the
// account adminID for the super admin of p, from clientIP, revokes its
// sessions and activation links, and returns the account and a new
// activation link, shown once and never mailed: the super admin hands it
// to the administrator out of band. A super admin can be reset by another
// one.
//
// It returns ErrUnauthenticated or ErrForbidden for a caller who is not an
// authenticated super admin, ErrSelfAction for the caller's own account,
// ErrNotFound for an unknown account, ErrAccountDisabled for a disabled
// account and ErrLastSuperAdmin for the last usable super admin (nothing
// is changed then).
func (s *Service) ResetCredentials(ctx context.Context, p Principal, adminID string, clientIP netip.Addr) (Account, Activation, error) {
	if err := manager(p); err != nil {
		return Account{}, Activation{}, err
	}
	if adminID == p.Admin.ID {
		return Account{}, Activation{}, ErrSelfAction
	}
	var (
		reset store.Admin
		link  Activation
	)
	err := s.repo.tx(ctx, func(tx txRepo) error {
		// The count takes the administrators lock before the account is
		// read: two super admins resetting each other cannot both succeed.
		usable, err := tx.countUsableSuperAdmins(ctx)
		if err != nil {
			return err
		}
		a, err := tx.admin(ctx, adminID)
		switch {
		case errors.Is(err, store.ErrNotFound):
			return ErrNotFound
		case err != nil:
			return err
		case a.Disabled:
			return ErrAccountDisabled
		case usable <= 1 && a.Role == store.RoleSuperAdmin && a.PasswordHash != "" && a.TOTPEnabled:
			return ErrLastSuperAdmin
		}
		if reset, link, err = s.resetTx(ctx, tx, a); err != nil {
			return err
		}
		return tx.audit(ctx, adminEvent(p.Admin.Username, clientIP, audit.ActionAdminCredentialsReset, a.ID, nil))
	})
	switch {
	case errors.Is(err, ErrNotFound), errors.Is(err, ErrStateConflict):
		return Account{}, Activation{}, err
	case err != nil:
		return Account{}, Activation{}, fmt.Errorf("adminauth: reset credentials: %w", err)
	}
	return accountOf(reset), link, nil
}

// resetTx clears the password, TOTP, recovery codes, sessions and
// activation links of a inside tx, and creates a new activation link. It
// returns the account as reset and the link.
func (s *Service) resetTx(ctx context.Context, tx txRepo, a store.Admin) (store.Admin, Activation, error) {
	if err := tx.setPassword(ctx, a.ID, ""); err != nil {
		return store.Admin{}, Activation{}, err
	}
	if err := tx.clearTOTP(ctx, a.ID); err != nil {
		return store.Admin{}, Activation{}, err
	}
	if _, err := tx.deleteSessions(ctx, a.ID, ""); err != nil {
		return store.Admin{}, Activation{}, err
	}
	if _, err := tx.deleteActivations(ctx, a.ID); err != nil {
		return store.Admin{}, Activation{}, err
	}
	row, link, err := s.newActivation(a.ID, s.now())
	if err != nil {
		return store.Admin{}, Activation{}, err
	}
	if err := tx.createActivation(ctx, row); err != nil {
		return store.Admin{}, Activation{}, err
	}
	a.PasswordHash, a.TOTPEnabled, a.TOTPSecretID, a.PendingTOTPSecretID, a.TOTPLastCounter = "", false, "", "", -1
	return a, link, nil
}

// Activate uses the activation link token from clientIP: the account gets
// password and a session, in state totp_enrollment_required when TOTP is
// required, authenticated otherwise. The link is consumed and the other
// links of the account are revoked.
//
// It returns ErrNotFound for a malformed, unknown, used or expired token,
// or one of a disabled account, and an *InvalidError on FieldPassword for
// a password outside the policy.
func (s *Service) Activate(ctx context.Context, token, password string, clientIP netip.Addr) (Session, error) {
	if !validToken(ActivationTokenPrefix, token) {
		return Session{}, ErrNotFound
	}
	if err := checkNewPassword(password, FieldPassword); err != nil {
		return Session{}, err
	}
	hash, err := s.hasher.HashPassword(ctx, []byte(password))
	if err != nil {
		return Session{}, fmt.Errorf("adminauth: hash password: %w", err)
	}
	now := s.now()
	var (
		activated store.Admin
		sess      Session
	)
	err = s.repo.tx(ctx, func(tx txRepo) error {
		adminID, err := tx.consumeActivation(ctx, tokenHash(token), now)
		if err != nil {
			return err
		}
		a, err := tx.admin(ctx, adminID)
		if err != nil {
			return err
		}
		if a.Disabled {
			return store.ErrNotFound
		}
		if err := tx.setPassword(ctx, a.ID, hash); err != nil {
			return err
		}
		if _, err := tx.deleteActivations(ctx, a.ID); err != nil {
			return err
		}
		var row store.AdminSession
		row, sess, err = s.newSession(a.ID, stateFor(a), clientIP, now)
		if err != nil {
			return err
		}
		if err := tx.createSession(ctx, row); err != nil {
			return err
		}
		activated = a
		return tx.audit(ctx, adminEvent(a.Username, clientIP, audit.ActionAdminActivated, a.ID, nil))
	})
	switch {
	case errors.Is(err, store.ErrNotFound):
		return Session{}, ErrNotFound
	case err != nil:
		return Session{}, fmt.Errorf("adminauth: activate: %w", err)
	}
	if sess.State == store.SessionAuthenticated {
		s.loggedIn(ctx, activated, clientIP, "activation")
	}
	return sess, nil
}

// ResetTOTPLocal removes the TOTP enrollment and the recovery codes of the
// account username and revokes its sessions, for the local command
// (transteira admin reset-totp, run inside the container): the next login
// requires a new enrollment when TOTP is mandatory. The audit event names
// the system as the actor. It returns ErrNotFound for an unknown username.
func (s *Service) ResetTOTPLocal(ctx context.Context, username string) error {
	a, err := s.repo.adminByUsername(ctx, username)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return ErrNotFound
	case err != nil:
		return fmt.Errorf("adminauth: read admin: %w", err)
	}
	err = s.repo.tx(ctx, func(tx txRepo) error {
		if err := tx.clearTOTP(ctx, a.ID); err != nil {
			return err
		}
		if _, err := tx.deleteSessions(ctx, a.ID, ""); err != nil {
			return err
		}
		return tx.audit(ctx, audit.Event{
			ActorKind: store.ActorSystem, Actor: cliActor, Action: audit.ActionAdminTOTPResetLocal,
			ObjectKind: audit.ObjectAdmin, ObjectID: a.ID, Details: map[string]any{"username": a.Username},
		})
	})
	if err != nil {
		return fmt.Errorf("adminauth: reset totp: %w", err)
	}
	return nil
}

// ResetPasswordLocal clears the password, TOTP and recovery codes of the
// account username, revokes its sessions and activation links, and returns
// a new activation link valid ActivationTTL, for the local command
// (transteira admin reset-password, run inside the container), which
// prints it once. It works for any account, the last super admin included:
// it is the recovery path of a lost password. The audit event names the
// system as the actor.
//
// It returns ErrNotFound for an unknown username and ErrAccountDisabled
// for a disabled account, whose link could not be used.
func (s *Service) ResetPasswordLocal(ctx context.Context, username string) (Activation, error) {
	a, err := s.repo.adminByUsername(ctx, username)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return Activation{}, ErrNotFound
	case err != nil:
		return Activation{}, fmt.Errorf("adminauth: read admin: %w", err)
	case a.Disabled:
		return Activation{}, ErrAccountDisabled
	}
	var link Activation
	err = s.repo.tx(ctx, func(tx txRepo) error {
		var err error
		if _, link, err = s.resetTx(ctx, tx, a); err != nil {
			return err
		}
		return tx.audit(ctx, audit.Event{
			ActorKind: store.ActorSystem, Actor: cliActor, Action: audit.ActionAdminPasswordResetLocal,
			ObjectKind: audit.ObjectAdmin, ObjectID: a.ID, Details: map[string]any{"username": a.Username},
		})
	})
	if err != nil {
		return Activation{}, fmt.Errorf("adminauth: reset password: %w", err)
	}
	return link, nil
}

// ListAccounts returns every account, for the local command (transteira
// admin list). The accounts carry no credential.
func (s *Service) ListAccounts(ctx context.Context) ([]Account, error) {
	var (
		out    []Account
		cursor string
	)
	for {
		page, err := s.repo.listAdmins(ctx, store.AdminListOptions{Cursor: cursor, Limit: listAccountsPage})
		if err != nil {
			return nil, fmt.Errorf("adminauth: list admins: %w", err)
		}
		for _, a := range page.Items {
			out = append(out, accountOf(a))
		}
		if page.NextCursor == "" {
			return out, nil
		}
		cursor = page.NextCursor
	}
}
