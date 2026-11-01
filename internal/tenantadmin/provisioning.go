package tenantadmin

import (
	"context"
	"log/slog"
	"net/netip"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/events"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// FieldDelegatedAdmin is the JSON pointer of the delegated admin of a
// provisioned tenant, required there.
const FieldDelegatedAdmin = "/delegatedAdmin"

// ProvisioningNotice is what the super admins are told of a tenant created
// through the provisioning API (threat model P50). It holds no secret:
// neither the token secret nor any activation link.
type ProvisioningNotice struct {
	// TenantID, TenantName and FQDN identify the tenant.
	TenantID   tenant.ID
	TenantName string
	FQDN       string
	// TokenID, TokenName and TokenPrefix identify the provisioning token
	// that created the tenant (TokenName and TokenPrefix are empty when
	// the token could not be read at setup completion).
	TokenID     string
	TokenName   string
	TokenPrefix string
	// AdminUsername is the login of the delegated admin created with the
	// tenant (provisioning only, "" at setup completion).
	AdminUsername string
	// ClientIP is the real client IP of the request.
	ClientIP netip.Addr
	// At is when it happened.
	At time.Time
	// Forced tells that the setup was completed by the super admin with
	// required items still missing (setup completion only).
	Forced bool
}

// ProvisioningTokenNotice is what the super admins are told of a new
// provisioning token (threat model T-275). It holds no secret: neither the
// token secret nor its hash, only its non-secret display prefix.
type ProvisioningTokenNotice struct {
	// TokenID, TokenName and TokenPrefix identify the token.
	TokenID     string
	TokenName   string
	TokenPrefix string
	// CreatedBy is the login of the super admin who created it.
	CreatedBy string
	// ClientIP is the real client IP of the request.
	ClientIP netip.Addr
	// At is when it was created.
	At time.Time
	// CIDRCount and SuffixCount are the numbers of allowed IP ranges and
	// FQDN suffixes of the token.
	CIDRCount   int
	SuffixCount int
	// MaxTenants and MaxStorageQuotaBytes are its caps.
	MaxTenants           int
	MaxStorageQuotaBytes int64
	// ExpiresAt is its expiry, zero when it never expires.
	ExpiresAt time.Time
}

// ProvisioningNotifier tells the super admins, through the system SMTP,
// that a tenant was created through the provisioning API, that such a
// tenant completed its setup (threat model P50) or that a provisioning
// token was created (T-275). The methods are called once the change is
// committed; they must not block (queue the mail) and report their own
// failures.
type ProvisioningNotifier interface {
	TenantProvisioned(ctx context.Context, n ProvisioningNotice)
	TenantSetupCompleted(ctx context.Context, n ProvisioningNotice)
	TokenCreated(ctx context.Context, n ProvisioningTokenNotice)
}

// AdminPathTenant returns the path, on the administration host, of the page
// of tenant tid (events.Event.AdminPath).
func AdminPathTenant(tid tenant.ID) string { return "/admin/tenants/" + string(tid) }

// ProvisionTenant creates, for the provisioning token tokID acting as actor
// (Kind store.ActorProvisioningToken), from clientIP, a tenant in the setup
// state with its first delegated admin, in one transaction. The scope of
// the token (FQDN suffix, caps) is the caller's check; the creation itself
// runs [store.Tenants.CreateProvisioned], which checks again under a lock
// that the token is usable, below its maximum number of tenants and its
// creation rate.
//
// in is validated as by [Service.CreateTenant]; in.SetupState must be empty
// or setup (the tenant is always created in setup, T-271), and
// in.DelegatedAdmin is required (an *InvalidError on FieldDelegatedAdmin
// otherwise). The activation link is always mailed through the system
// SMTP, never returned ([adminauth.Service.CreateProvisionedAdminTx]). It
// returns the errors of CreateTenant, and errors matching
// store.ErrProvisioningTokenUnusable, store.ErrProvisioningMaxTenants or
// store.ErrProvisioningRateLimited (a *store.ProvisioningRateLimitError);
// nothing is created on any error. It records no tenant audit event: the
// caller records tenant.provisioned, and the account creation records
// admin.created and admin.invited with the token as actor.
func (s *Service) ProvisionTenant(ctx context.Context, actor adminauth.AuditActor, tokID string, in TenantCreate,
	clientIP netip.Addr,
) (TenantCreated, error) {
	if s.admins == nil {
		return TenantCreated{}, errNoAdminCreator
	}
	if in.DelegatedAdmin == nil {
		return TenantCreated{}, invalid(FieldDelegatedAdmin, "required")
	}
	if in.SetupState != "" && in.SetupState != tenant.SetupStateSetup {
		return TenantCreated{}, invalid(FieldSetupState, "a provisioned tenant starts in setup")
	}
	in.SetupState = tenant.SetupStateSetup
	nt, err := s.newTenant(in)
	if err != nil {
		return TenantCreated{}, err
	}
	var invited *InvitedAdmin
	t, err := s.repo.createProvisionedTenant(ctx, tokID, nt, func(tx *store.SystemTx, t *tenant.Tenant) error {
		a, link, err := s.admins.CreateProvisionedAdminTx(ctx, tx, actor, t, *in.DelegatedAdmin, clientIP)
		if err != nil {
			return err
		}
		invited = &InvitedAdmin{Account: a, Activation: link}
		return nil
	})
	if err != nil {
		return TenantCreated{}, createError("provision tenant", err)
	}
	s.invalidate(t.ID, t.FQDN)
	v, err := s.view(ctx, t)
	if err != nil {
		return TenantCreated{}, err
	}
	return TenantCreated{TenantView: v, DelegatedAdmin: invited}, nil
}

// setupCompleted tells the outside world that the provisioned tenant t
// completed its setup: the tenant.setup_completed system event and the
// notice to the super admins. A tenant created by a super admin tells
// nobody.
func (s *Service) setupCompleted(ctx context.Context, t *tenant.Tenant, forced bool, ip netip.Addr) {
	if t.ProvisionedBy == "" {
		return
	}
	now := s.now()
	s.events.Publish(events.Event{
		Type: events.TenantSetupCompleted, Severity: events.SeverityInfo, OccurredAt: now,
		TenantID: string(t.ID), AdminPath: AdminPathTenant(t.ID),
	})
	if s.notifier == nil {
		return
	}
	n := ProvisioningNotice{
		TenantID: t.ID, TenantName: t.Name, FQDN: t.FQDN, TokenID: t.ProvisionedBy, ClientIP: ip, At: now, Forced: forced,
	}
	tok, err := s.repo.provisioningToken(ctx, t.ProvisionedBy)
	if err != nil {
		s.logger.WarnContext(ctx, "provisioning token of a tenant not read for the setup notice",
			slog.String("tenant", string(t.ID)), slog.String("error", err.Error()))
	} else {
		n.TokenName, n.TokenPrefix = tok.Name, tok.Prefix
	}
	s.notifier.TenantSetupCompleted(context.WithoutCancel(ctx), n)
}
