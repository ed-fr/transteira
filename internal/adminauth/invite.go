package adminauth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/i18n"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Rules of the invitations of administrators by mail (V1.2, threat model
// section 6.43).
const (
	// InviteMaxPerHour bounds the activation links issued by Invite for one
	// account within InviteWindow (T-256).
	InviteMaxPerHour = 5
	// InviteWindow is the sliding window of InviteMaxPerHour.
	InviteWindow = time.Hour
)

// Fields of an invitation named by an [InvalidError], relative to the
// object holding them (the request body of Invite, "/invitation" of Create,
// "/delegatedAdmin" of a tenant creation).
const (
	FieldDelivery = "/delivery"
	FieldLanguage = "/language"
	// FieldInvitation prefixes the invitation fields of Create.
	FieldInvitation = "/invitation"
)

// ErrSystemSMTPUnavailable reports a link to mail while no system SMTP is
// configured (503 system-smtp-unavailable). Nothing is created or changed:
// the link is never mailed through the SMTP of a tenant (T-256).
var ErrSystemSMTPUnavailable = errors.New("adminauth: the system smtp is not configured")

// ErrAdminAlreadyActive reports an invitation of an account that is already
// activated (409 admin-already-active): its credentials must be reset
// instead.
var ErrAdminAlreadyActive = errors.New("adminauth: the account is already activated")

// NotAllowedError reports a field whose value is valid but not allowed
// here (400 validation-failed, code not-allowed): the mail delivery of a
// super admin account, whose link is always handed over out of band
// (threat model P47). It matches [ErrInvalid].
type NotAllowedError struct {
	// Field is the JSON pointer of the field.
	Field string
}

// Error implements error.
func (e *NotAllowedError) Error() string { return "adminauth: not allowed " + e.Field }

// Is makes errors.Is(err, ErrInvalid) true.
func (e *NotAllowedError) Is(target error) bool { return target == ErrInvalid }

// Invitation chooses how an activation link reaches the administrator
// (OpenAPI AdminInvitation).
type Invitation struct {
	// Delivery is store.DeliveryMail or store.DeliveryCopy (the default,
	// when empty).
	Delivery store.ActivationDelivery
	// Language is the language of the mail; when empty, the default
	// language of the first tenant of the account, else i18n.Default.
	// Ignored for a copied link.
	Language string
}

// mail reports whether the link is to be mailed.
func (inv Invitation) mail() bool { return inv.Delivery == store.DeliveryMail }

// check validates inv; prefix is the JSON pointer of the object holding it.
func (inv Invitation) check(prefix string) error {
	switch inv.Delivery {
	case "", store.DeliveryCopy, store.DeliveryMail:
	default:
		return invalid(prefix + FieldDelivery)
	}
	if inv.Language != "" && !i18n.IsSupported(inv.Language) {
		return invalid(prefix + FieldLanguage)
	}
	return nil
}

// InvitationMail is an activation link to mail through the system SMTP.
// It carries the link itself: it must never be logged.
type InvitationMail struct {
	// To is the mail address of the administrator.
	To string
	// Language is the language of the mail, supported by i18n.
	Language string
	// Username is the login of the account.
	Username string
	// TenantNames are the display names of the tenants of the account,
	// sorted.
	TenantNames []string
	// Link is the activation link (token in the fragment).
	Link string
	// ExpiresAt is the end of validity of the link.
	ExpiresAt time.Time
}

// Mailer queues the invitation mails on the system mail channel, without
// blocking; a failed delivery is logged by the channel. The application
// implements it over the system SMTP (TT_SYSTEM_SMTP_*).
type Mailer interface {
	SendInvitation(ctx context.Context, m InvitationMail)
}

// DelegatedAdmin is the first delegated admin of a new tenant (OpenAPI
// NewDelegatedAdmin): assigned to that tenant only, TOTP required.
type DelegatedAdmin struct {
	// Username and Email of the administrator.
	Username string
	Email    string
	// Language is the preferred language of the account and the language
	// of the mail; required.
	Language string
	// Delivery is how the link reaches the administrator (copy when
	// empty).
	Delivery store.ActivationDelivery
}

// tenantInfo is what an invitation mail says of a tenant.
type tenantInfo struct {
	name     string
	language string
}

// tenantInfos reads the names and default languages of tids, in order,
// skipping the unknown ones (the transaction then fails on them).
func (s *Service) tenantInfos(ctx context.Context, tids []tenant.ID) ([]tenantInfo, error) {
	out := make([]tenantInfo, 0, len(tids))
	for _, tid := range tids {
		t, err := s.repo.tenant(ctx, tid)
		switch {
		case errors.Is(err, store.ErrNotFound):
			continue
		case err != nil:
			return nil, fmt.Errorf("adminauth: read tenant: %w", err)
		}
		out = append(out, tenantInfo{name: t.Name, language: t.DefaultLanguage})
	}
	return out, nil
}

// mailLanguage returns the language of the invitation mail: inv.Language,
// else the default language of the first tenant, else i18n.Default.
func mailLanguage(inv Invitation, tenants []tenantInfo) string {
	if inv.Language != "" {
		return inv.Language
	}
	if len(tenants) > 0 && i18n.IsSupported(tenants[0].language) {
		return tenants[0].language
	}
	return i18n.Default
}

// tenantNames returns the sorted names of tenants.
func tenantNames(tenants []tenantInfo) []string {
	names := make([]string, len(tenants))
	for i, t := range tenants {
		names[i] = t.name
	}
	slices.Sort(names)
	return names
}

// issueTx revokes the pending links of a inside tx and creates a new one,
// delivered as inv says in language lang. For the mail delivery, the mail
// is queued once tx commits, never before, and the returned link carries
// no URL: it is never returned to the caller (T-255).
func (s *Service) issueTx(ctx context.Context, tx txRepo, a store.Admin, inv Invitation, lang string, names []string) (Activation, error) {
	if _, err := tx.deleteActivations(ctx, a.ID); err != nil {
		return Activation{}, err
	}
	row, link, err := s.newActivation(a.ID, s.now())
	if err != nil {
		return Activation{}, err
	}
	if inv.mail() {
		row.Delivery, row.Language = store.DeliveryMail, lang
		m := InvitationMail{
			To: a.Email, Language: lang, Username: a.Username, TenantNames: names, Link: link.URL, ExpiresAt: link.ExpiresAt,
		}
		mailer, logger := s.mailer, s.logger
		tx.afterCommit(func() {
			// The request may end before the queue picks the mail up.
			mailer.SendInvitation(context.WithoutCancel(ctx), m)
			logger.InfoContext(ctx, "admin invitation mail handed to the system mail channel", slog.String("admin_id", a.ID))
		})
		link.URL, link.Delivery = "", store.DeliveryMail
	}
	if err := tx.createActivation(ctx, row); err != nil {
		return Activation{}, err
	}
	return link, nil
}

// invitedEvent returns the admin.invited audit event: the delivery, the
// language and whether TOTP was made mandatory by the invitation, never the
// link (T-255).
func invitedEvent(actor string, ip netip.Addr, a store.Admin, link Activation, lang string, totpForced bool) audit.Event {
	details := map[string]any{"delivery": string(link.Delivery)}
	if link.Delivery == store.DeliveryMail {
		details["language"] = lang
	}
	if totpForced {
		details["require_totp_forced"] = true
	}
	return adminEvent(actor, ip, audit.ActionAdminInvited, a.ID, details)
}

// Invite issues a new activation link for the account adminID, for the
// super admin of p, from clientIP: its previous unused links are revoked,
// and the new one is mailed through the system SMTP or returned once, as
// inv says. A mailed invitation makes TOTP mandatory for the account
// (T-254). At most InviteMaxPerHour links are issued per account and per
// InviteWindow.
//
// It returns ErrUnauthenticated or ErrForbidden for a caller who is not an
// authenticated super admin, an *InvalidError for a malformed invitation,
// a *NotAllowedError on FieldDelivery for the mail delivery of a super
// admin account, ErrSystemSMTPUnavailable for the mail delivery without a
// system SMTP, ErrNotFound for an unknown account, ErrAccountDisabled for a
// disabled one, ErrSSOOnlyEnforced for a single sign-on only account while
// one of its tenants enforces single sign-on (T-292), ErrAdminAlreadyActive
// for an activated one and a *RateLimitError beyond the limit.
func (s *Service) Invite(ctx context.Context, p Principal, adminID string, inv Invitation, clientIP netip.Addr) (Account, Activation, error) {
	if err := manager(p); err != nil {
		return Account{}, Activation{}, err
	}
	if err := inv.check(""); err != nil {
		return Account{}, Activation{}, err
	}
	if inv.mail() && s.mailer == nil {
		return Account{}, Activation{}, ErrSystemSMTPUnavailable
	}
	cur, err := s.repo.admin(ctx, adminID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return Account{}, Activation{}, ErrNotFound
	case err != nil:
		return Account{}, Activation{}, fmt.Errorf("adminauth: read admin: %w", err)
	}
	if err := s.checkLinkAllowed(ctx, cur); err != nil {
		return Account{}, Activation{}, err
	}
	tenants, err := s.tenantInfos(ctx, cur.TenantIDs)
	if err != nil {
		return Account{}, Activation{}, err
	}
	lang := mailLanguage(inv, tenants)
	var (
		invited store.Admin
		link    Activation
	)
	err = s.repo.tx(ctx, func(tx txRepo) error {
		// Read again in the transaction: the checks hold for the account
		// the link is issued for.
		a, err := tx.admin(ctx, adminID)
		switch {
		case errors.Is(err, store.ErrNotFound):
			return ErrNotFound
		case err != nil:
			return err
		case a.Disabled:
			return ErrAccountDisabled
		case a.PasswordHash != "":
			return ErrAdminAlreadyActive
		case inv.mail() && a.Role == store.RoleSuperAdmin:
			return &NotAllowedError{Field: FieldDelivery}
		}
		if ok, wait := s.invites.Allow(a.ID); !ok {
			return &RateLimitError{RetryAfter: wait}
		}
		forced := inv.mail() && !a.RequireTOTP
		if forced {
			on := true
			if _, a, err = tx.updateAdmin(ctx, a.ID, store.AdminUpdate{RequireTOTP: &on}); err != nil {
				return err
			}
		}
		if link, err = s.issueTx(ctx, tx, a, inv, lang, tenantNames(tenants)); err != nil {
			return err
		}
		invited = a
		return tx.audit(ctx, invitedEvent(p.Admin.Username, clientIP, a, link, lang, forced))
	})
	switch {
	case errors.Is(err, ErrNotFound), errors.Is(err, ErrStateConflict), errors.Is(err, ErrInvalid),
		errors.Is(err, ErrAdminAlreadyActive), errors.Is(err, ErrRateLimited):
		return Account{}, Activation{}, err
	case err != nil:
		return Account{}, Activation{}, fmt.Errorf("adminauth: invite admin: %w", err)
	}
	return accountOf(invited), link, nil
}

// AuditActor identifies who acts in the audit events of an account
// creation that is not made by an administrator session: a provisioning
// token (Kind [store.ActorProvisioningToken], ID its "prv_" identifier).
type AuditActor struct {
	Kind store.AuditActorKind
	ID   string
}

// CreateDelegatedAdminTx creates, inside tx (the transaction creating the
// tenant t), the first delegated admin of t for the super admin of p, from
// clientIP: a new account assigned to t only, TOTP required, with an
// activation link delivered as in.Delivery says. The account, its tenant
// assignment, its link and the admin.created and admin.invited audit events
// are committed with the tenant or not at all; a mail is queued only once
// tx commits (T-257).
//
// It returns ErrUnauthenticated or ErrForbidden for a caller who is not an
// authenticated super admin, an *InvalidError (fields relative to the
// delegated admin object) for a malformed field, ErrSystemSMTPUnavailable
// for the mail delivery without a system SMTP and ErrAlreadyExists for a
// username taken. The caller must roll tx back on any error.
func (s *Service) CreateDelegatedAdminTx(ctx context.Context, tx *store.SystemTx, p Principal, t *tenant.Tenant, in DelegatedAdmin, clientIP netip.Addr) (Account, Activation, error) {
	if err := manager(p); err != nil {
		return Account{}, Activation{}, err
	}
	return s.createDelegatedAdminTx(ctx, tx, AuditActor{Kind: store.ActorAdmin, ID: p.Admin.Username}, t, in, clientIP)
}

// errProvisioningActor reports a provisioned admin creation without a
// provisioning token as its actor (a programming error).
var errProvisioningActor = errors.New("adminauth: a provisioned admin needs a provisioning token actor")

// CreateProvisionedAdminTx is [Service.CreateDelegatedAdminTx] for a tenant
// created through the provisioning API by the token actor (Kind
// store.ActorProvisioningToken), which is recorded as the actor of the
// admin.created and admin.invited events. The activation link is always
// mailed through the system SMTP, never returned (T-272): in.Delivery must
// be empty or mail, else a *NotAllowedError on FieldDelivery, and without a
// system SMTP it returns ErrSystemSMTPUnavailable. The other errors are
// those of CreateDelegatedAdminTx, without the role checks: the caller
// authenticated the token. The caller must roll tx back on any error, so
// that nothing is created.
func (s *Service) CreateProvisionedAdminTx(ctx context.Context, tx *store.SystemTx, actor AuditActor, t *tenant.Tenant, in DelegatedAdmin, clientIP netip.Addr) (Account, Activation, error) {
	if actor.Kind != store.ActorProvisioningToken || actor.ID == "" {
		return Account{}, Activation{}, errProvisioningActor
	}
	switch in.Delivery {
	case "", store.DeliveryMail:
	case store.DeliveryCopy:
		return Account{}, Activation{}, &NotAllowedError{Field: FieldDelivery}
	default:
		return Account{}, Activation{}, invalid(FieldDelivery)
	}
	if s.mailer == nil {
		return Account{}, Activation{}, ErrSystemSMTPUnavailable
	}
	in.Delivery = store.DeliveryMail
	return s.createDelegatedAdminTx(ctx, tx, actor, t, in, clientIP)
}

// createDelegatedAdminTx implements CreateDelegatedAdminTx and
// CreateProvisionedAdminTx, recording actor in the audit events.
func (s *Service) createDelegatedAdminTx(ctx context.Context, tx *store.SystemTx, actor AuditActor, t *tenant.Tenant, in DelegatedAdmin, clientIP netip.Addr) (Account, Activation, error) {
	username, err := store.NormalizeUsername(in.Username)
	if err != nil {
		return Account{}, Activation{}, invalid(FieldUsername)
	}
	email, err := parseEmail(in.Email)
	if err != nil {
		return Account{}, Activation{}, err
	}
	if in.Language == "" {
		return Account{}, Activation{}, invalid(FieldLanguage)
	}
	inv := Invitation{Delivery: in.Delivery, Language: in.Language}
	if err := inv.check(""); err != nil {
		return Account{}, Activation{}, err
	}
	if inv.mail() && s.mailer == nil {
		return Account{}, Activation{}, ErrSystemSMTPUnavailable
	}
	r := s.repo.wrapTx(tx)
	a, err := r.createAdmin(ctx, store.Admin{
		Username: username, Email: email, Role: store.RoleDelegatedAdmin, TenantIDs: []tenant.ID{t.ID},
		RequireTOTP: true, Language: in.Language,
	})
	switch {
	case errors.Is(err, store.ErrConflict):
		return Account{}, Activation{}, ErrAlreadyExists
	case err != nil:
		return Account{}, Activation{}, fmt.Errorf("adminauth: create delegated admin: %w", err)
	}
	link, err := s.issueTx(ctx, r, a, inv, in.Language, []string{t.Name})
	if err != nil {
		return Account{}, Activation{}, fmt.Errorf("adminauth: create delegated admin: %w", err)
	}
	for _, ev := range []audit.Event{
		adminEvent(actor.ID, clientIP, audit.ActionAdminCreated, a.ID, map[string]any{
			"username": a.Username, "role": string(a.Role), "tenant_ids": a.TenantIDs, "require_totp": a.RequireTOTP,
		}),
		invitedEvent(actor.ID, clientIP, a, link, in.Language, false),
	} {
		ev.ActorKind = actor.Kind
		if err := r.audit(ctx, ev); err != nil {
			return Account{}, Activation{}, fmt.Errorf("adminauth: create delegated admin: %w", err)
		}
	}
	return accountOf(a), link, nil
}
