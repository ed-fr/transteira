package tenantadmin

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/branding"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/ratelimit"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Defaults of the [Options].
const (
	// DefaultDNSTimeout bounds each DNS lookup of the mail DNS check.
	DefaultDNSTimeout = 2 * time.Second
	// DefaultSMTPTestLimit is the number of SMTP tests allowed per
	// administrator and tenant within DefaultSMTPTestWindow.
	DefaultSMTPTestLimit = 5
	// DefaultSMTPTestWindow is the period of the SMTP test limit.
	DefaultSMTPTestWindow = 10 * time.Minute
)

// objectTenant is the audit object kind of every event of this package
// (object ID: the tenant ID).
const objectTenant = "tenant"

// Audit actions of the tenant configuration.
const (
	ActionTenantCreated         audit.Action = "tenant.created"
	ActionTenantUpdated         audit.Action = "tenant.updated"
	ActionTenantDeletionStarted audit.Action = "tenant.deletion_started"
	ActionTenantBrandingUpdated audit.Action = "tenant.branding_updated"
	ActionTenantAssetUploaded   audit.Action = "tenant.asset_uploaded"
	ActionTenantAssetDeleted    audit.Action = "tenant.asset_deleted"
	ActionTenantNetworkUpdated  audit.Action = "tenant.network_updated"
	ActionTenantSMTPUpdated     audit.Action = "tenant.smtp_updated"
	ActionTenantSMTPTested      audit.Action = "tenant.smtp_tested"
	ActionTenantTemplateUpdated audit.Action = "tenant.template_updated"
	ActionTenantTemplateReset   audit.Action = "tenant.template_reset"
	ActionTenantLegalUpdated    audit.Action = "tenant.legal_updated"

	// ActionTenantConfidentialityUpdated records the replacement of the confidentiality levels.
	ActionTenantConfidentialityUpdated audit.Action = "tenant.confidentiality_updated"
	// ActionTenantRecipientRulesUpdated records the replacement of the recipient domain rules.
	ActionTenantRecipientRulesUpdated audit.Action = "tenant.recipient_rules_updated"
	// ActionTenantAbuseSettingsUpdated records a change of the abuse detection settings.
	ActionTenantAbuseSettingsUpdated audit.Action = "tenant.abuse_settings_updated"
)

// TenantEraser erases every piece of data of a tenant being deleted
// (*lifecycle.Sweeper): transfers through the crypto-erase path, remaining
// wrapped keys, the tenant row with its cascades, and its folder. It must
// be resumable: a call after an interruption finishes the job, and a call
// for a tenant already erased succeeds.
type TenantEraser interface {
	EraseTenant(ctx context.Context, tid tenant.ID) error
}

// AssetStore keeps the re-encoded branding images of the tenants, under a
// fixed name per kind in the folder of the tenant. Put replaces atomically;
// Get returns an error matching fs.ErrNotExist when the image is missing;
// Delete succeeds when the image is already missing.
type AssetStore interface {
	Put(tid tenant.ID, kind branding.Kind, data []byte) error
	Get(tid tenant.ID, kind branding.Kind) ([]byte, error)
	Delete(tid tenant.ID, kind branding.Kind) error
}

// Mailer delivers one message with the given SMTP settings
// (*mail.SMTPSender dialing through [netpolicy.DialGuard.DialContext]).
type Mailer interface {
	Send(ctx context.Context, s mail.Settings, msg mail.Message) error
}

// Resolver resolves the mail DNS records (*net.Resolver).
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// defaultResolver is the system resolver.
var defaultResolver Resolver = net.DefaultResolver

// ResolverCache is the cache of the tenant resolution by Host
// (*tenant.Resolver), invalidated after every change of a tenant row.
type ResolverCache interface {
	InvalidateTenant(tid tenant.ID)
	Invalidate(host string)
}

// Options configures a [Service].
type Options struct {
	// AdminHosts are the hosts of the administration (config.AdminHosts):
	// no tenant FQDN may equal one.
	AdminHosts []string
	// SMTPDenyNetworks are the networks no SMTP server may be in
	// (config.SMTPDenyNetworks), checked at save for IP literals.
	SMTPDenyNetworks []netip.Prefix
	// Vault seals the SMTP passwords (required).
	Vault Vault
	// Assets stores the branding images (required).
	Assets AssetStore
	// Eraser erases a deleted tenant (required).
	Eraser TenantEraser
	// Mailer sends the SMTP test mail (required). It must dial through a
	// [netpolicy.DialGuard] over SMTPDenyNetworks.
	Mailer Mailer
	// Resolver serves the mail DNS check; nil means net.DefaultResolver.
	Resolver Resolver
	// Cache is invalidated after every change of a tenant row; nil
	// disables the invalidation.
	Cache ResolverCache
	// Logger receives the audit write failures; nil means slog.Default().
	Logger *slog.Logger
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// DNSTimeout bounds each DNS lookup; <= 0 means DefaultDNSTimeout.
	DNSTimeout time.Duration
	// SMTPTestLimit and SMTPTestWindow bound the SMTP tests per
	// administrator and tenant; <= 0 means the defaults.
	SMTPTestLimit  int
	SMTPTestWindow time.Duration
	// Audit is the shared audit writer of the application, which publishes
	// the events it writes; nil means a writer of its own over the
	// database, publishing nothing.
	Audit *audit.Writer
}

// Service is the tenant configuration service. It is safe for concurrent
// use.
type Service struct {
	repo       repo
	assets     AssetStore
	eraser     TenantEraser
	mailer     Mailer
	resolver   Resolver
	cache      ResolverCache
	adminHosts []string
	deny       []netip.Prefix
	logger     *slog.Logger
	now        func() time.Time
	dnsTimeout time.Duration
	smtpTests  *ratelimit.Window

	// mu serializes the read-modify-write cycles of the tenant rows, so
	// that two concurrent changes of different fields do not lose one.
	mu sync.Mutex
}

// errMissingDependency reports a [New] call without a required option.
var errMissingDependency = errors.New("tenantadmin: Vault, Assets, Eraser and Mailer are required")

// New returns the service over db. It fails when a required option is
// missing.
func New(db *store.DB, opts Options) (*Service, error) {
	if db == nil || opts.Vault == nil || opts.Assets == nil || opts.Eraser == nil || opts.Mailer == nil {
		return nil, errMissingDependency
	}
	s := &Service{
		repo:       newStoreRepo(db, opts.Vault, opts.Audit),
		assets:     opts.Assets,
		eraser:     opts.Eraser,
		mailer:     opts.Mailer,
		resolver:   opts.Resolver,
		cache:      opts.Cache,
		deny:       opts.SMTPDenyNetworks,
		logger:     opts.Logger,
		now:        opts.Now,
		dnsTimeout: opts.DNSTimeout,
	}
	for _, h := range opts.AdminHosts {
		if n, err := tenant.NormalizeHost(h); err == nil {
			h = n
		}
		s.adminHosts = append(s.adminHosts, strings.ToLower(h))
	}
	if s.resolver == nil {
		s.resolver = defaultResolver
	}
	if s.logger == nil {
		s.logger = slog.Default()
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.dnsTimeout <= 0 {
		s.dnsTimeout = DefaultDNSTimeout
	}
	limit, window := opts.SMTPTestLimit, opts.SMTPTestWindow
	if limit <= 0 {
		limit = DefaultSMTPTestLimit
	}
	if window <= 0 {
		window = DefaultSMTPTestWindow
	}
	s.smtpTests = ratelimit.NewWindow(limit, window, ratelimit.WithClock(s.now))
	return s, nil
}

// --- Authorization -----------------------------------------------------------

// readable checks that p may read tenant tid and returns the tenant, which
// must be active.
func (s *Service) readable(ctx context.Context, p adminauth.Principal, tid tenant.ID) (*tenant.Tenant, error) {
	if err := adminauth.RequireAuthenticated(p); err != nil {
		return nil, err
	}
	if err := adminauth.RequireTenantAccess(p.Admin, tid); err != nil {
		return nil, err
	}
	return s.activeTenant(ctx, tid)
}

// writable checks that p may change tenant tid and returns the tenant,
// which must be active.
func (s *Service) writable(ctx context.Context, p adminauth.Principal, tid tenant.ID) (*tenant.Tenant, error) {
	if err := adminauth.RequireAuthenticated(p); err != nil {
		return nil, err
	}
	if err := adminauth.RequireTenantWrite(p.Admin, tid); err != nil {
		return nil, err
	}
	return s.activeTenant(ctx, tid)
}

// superAdmin checks that p is an authenticated super admin.
func superAdmin(p adminauth.Principal) error {
	if err := adminauth.RequireAuthenticated(p); err != nil {
		return err
	}
	return adminauth.RequireSuperAdmin(p.Admin)
}

// activeTenant returns the active tenant tid; a tenant being deleted is
// answered like a missing one.
func (s *Service) activeTenant(ctx context.Context, tid tenant.ID) (*tenant.Tenant, error) {
	t, err := s.tenant(ctx, tid)
	if err != nil {
		return nil, err
	}
	if t.Status != tenant.StatusActive {
		return nil, ErrNotFound
	}
	return t, nil
}

// tenant returns the tenant tid, whatever its status.
func (s *Service) tenant(ctx context.Context, tid tenant.ID) (*tenant.Tenant, error) {
	t, err := s.repo.getTenant(ctx, tid)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil, ErrNotFound
	case err != nil:
		return nil, fmt.Errorf("tenantadmin: get tenant: %w", err)
	}
	return t, nil
}

// --- Audit and cache ---------------------------------------------------------

// record writes the audit event of a change made by p on tenant tid. The
// change is committed already: a failure is logged, never returned.
func (s *Service) record(ctx context.Context, p adminauth.Principal, ip netip.Addr, tid tenant.ID,
	action audit.Action, details map[string]any,
) {
	ev := audit.Event{
		TenantID: tid, ActorKind: store.ActorAdmin, Actor: p.Admin.Username, IP: ip,
		Action: action, ObjectKind: objectTenant, ObjectID: string(tid), Details: details,
	}
	if err := s.repo.audit(ctx, ev); err != nil {
		s.logger.ErrorContext(ctx, "audit write failed", slog.String("action", string(action)),
			slog.String("tenant", string(tid)), slog.String("error", err.Error()))
	}
}

// invalidate drops the cached resolutions of tenant tid and of the given
// hosts.
func (s *Service) invalidate(tid tenant.ID, hosts ...string) {
	if s.cache == nil {
		return
	}
	s.cache.InvalidateTenant(tid)
	for _, h := range hosts {
		s.cache.Invalidate(h)
	}
}
