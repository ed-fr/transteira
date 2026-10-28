// Package admin implements the administration operations of the TransTeira
// API (gen.StrictServerInterface) served on the admin host: first-run
// setup, login with TOTP, own account and administrator accounts
// (CLAUDE.md sections 6.5 and 6.6), and the configuration of the tenants
// (sections 5, 12, 13 and 14: general settings, branding, network rules,
// SMTP, mail templates and legal documents) over internal/tenantadmin, and
// the operation of the tenants (sections 6.5, 9, 15.2, 20 and 21:
// transfers, invitations, blocklist, audit log, statistics and the rights
// of the data subjects) over internal/tenantops, internal/stats and
// internal/datasubject, and the API tokens of the tenants (section 16.4)
// over internal/apitoken, and the system operations of the super admin
// (sections 4, 16.1 and 19: maintenance mode, instance settings and master
// key rotation) over internal/maintenance, internal/systemsettings and
// internal/keyrotation, and the alert webhooks of the tenants and of the
// instance (section 12.4) over internal/webhookadmin.
//
// Server embeds stubs.Unimplemented, so that every operation not written
// yet answers 404 not-found; each real method defined here replaces its
// stub. The tenant operations of the public API are never implemented
// here: the admin host serves only /api/v1/admin/* and /api/v1/version
// (see internal/httpserver), and answers 404 for anything else.
//
// The handlers hold no authentication logic of their own: the session
// cookie is resolved, and the CSRF token checked, by the middlewares of the
// admin router (internal/httpserver), which put the session
// (adminauth.Principal) in the request context; internal/adminauth then
// enforces the login state and the role of every operation. The handlers
// map the requests and answers between the OpenAPI types and the service,
// set and clear the session cookie, and map the service errors to Problems.
// The session middleware expires the cookie when it no longer resolves to a
// session; a valid session whose login state does not open an operation
// gets 401 unauthenticated but keeps its cookie.
package admin

import (
	"context"
	"net/netip"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/stubs"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/version"
)

// unknownCommit is the commit reported by internal/version when the
// revision is not known; it is not exposed.
const unknownCommit = "unknown"

// Service authenticates the administrators and manages their accounts.
// *adminauth.Service implements it.
type Service interface {
	SetupRequired(ctx context.Context) (bool, error)
	CreateSuperAdmin(ctx context.Context, req adminauth.SetupRequest, clientIP netip.Addr) (adminauth.SetupResult, error)
	Login(ctx context.Context, username, password string, clientIP netip.Addr) (adminauth.Session, error)
	VerifyTOTP(ctx context.Context, p adminauth.Principal, code, recoveryCode string, clientIP netip.Addr) (adminauth.Session, error)
	Logout(ctx context.Context, p adminauth.Principal, clientIP netip.Addr) error
	ChangePassword(ctx context.Context, p adminauth.Principal, currentPassword, newPassword string, clientIP netip.Addr) error
	StartEnrollment(ctx context.Context, p adminauth.Principal, currentPassword string, clientIP netip.Addr) (adminauth.Enrollment, error)
	ConfirmEnrollment(ctx context.Context, p adminauth.Principal, code string, clientIP netip.Addr) (adminauth.Confirmed, error)
	DisableTOTP(ctx context.Context, p adminauth.Principal, currentPassword string, clientIP netip.Addr) error
	List(ctx context.Context, p adminauth.Principal, cursor string, limit int) (store.Page[adminauth.Account], error)
	Get(ctx context.Context, p adminauth.Principal, adminID string) (adminauth.Account, error)
	Create(ctx context.Context, p adminauth.Principal, req adminauth.AdminCreate, clientIP netip.Addr) (adminauth.Account, adminauth.Activation, error)
	Update(ctx context.Context, p adminauth.Principal, adminID string, u adminauth.AdminUpdate, clientIP netip.Addr) (adminauth.Account, error)
	Delete(ctx context.Context, p adminauth.Principal, adminID string, clientIP netip.Addr) error
	ResetCredentials(ctx context.Context, p adminauth.Principal, adminID string, clientIP netip.Addr) (adminauth.Account, adminauth.Activation, error)
	Activate(ctx context.Context, token, password string, clientIP netip.Addr) (adminauth.Session, error)
}

// Compile-time check that the authentication service fits.
var _ Service = (*adminauth.Service)(nil)

// Tenants reads the tenant registry, to name the tenants of an
// administrator (getAdminMe). *store.Tenants implements it.
type Tenants interface {
	Get(ctx context.Context, tid tenant.ID) (*tenant.Tenant, error)
	List(ctx context.Context, opts store.TenantListOptions) (store.Page[*tenant.Tenant], error)
}

// Compile-time check that the tenant repository fits.
var _ Tenants = (*store.Tenants)(nil)

// Server implements gen.StrictServerInterface for the admin host.
type Server struct {
	stubs.Unimplemented

	// svc authenticates the administrators; nil until WithService.
	svc Service
	// tenants names the tenants of an administrator; nil until
	// WithTenants.
	tenants Tenants
	// tenantSvc configures the tenants; nil until WithTenantService.
	tenantSvc TenantService
	// opsSvc serves the transfers, invitations, blocklist and audit log of
	// the tenants; nil until WithOperationsService.
	opsSvc OperationsService
	// subjectSvc serves the data subject rights; nil until
	// WithDataSubjectService.
	subjectSvc DataSubjectService
	// statsSvc computes the statistics; nil until WithStatsService.
	statsSvc StatsService
	// tokenSvc manages the API tokens of the tenants; nil until
	// WithAPITokenService.
	tokenSvc APITokenService
	// webhookSvc manages the webhooks of the tenants and of the instance;
	// nil until WithWebhookService.
	webhookSvc WebhookService
	// maintenance reads and changes the maintenance mode; nil until
	// WithMaintenance.
	maintenance MaintenanceService
	// settings serves the instance settings; nil until WithSystemSettings.
	settings SystemSettingsService
	// rotations serves the master key rotations; nil until
	// WithKeyRotation.
	rotations KeyRotationService
	// version returns the build information (replaceable in tests).
	version func() version.Info
	// now is the clock deriving the Max-Age of the session cookie from the
	// session and state expiries (replaceable in tests).
	now func() time.Time
}

// Option customizes NewServer.
type Option func(*Server)

// WithService serves the admin operations with svc. Without it they answer
// 500.
func WithService(svc Service) Option {
	return func(s *Server) { s.svc = svc }
}

// WithTenants names the tenants of the administrators (getAdminMe) from
// t. Without it getAdminMe answers 500.
func WithTenants(t Tenants) Option {
	return func(s *Server) { s.tenants = t }
}

// Compile-time check that Server implements the strict server interface.
var _ gen.StrictServerInterface = (*Server)(nil)

// NewServer returns a Server.
func NewServer(opts ...Option) *Server {
	s := &Server{version: version.Get, now: time.Now}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// GetVersion returns the version of the running instance and the API
// major version. On the admin host there is no tenant: the answer is the
// same as under any tenant FQDN.
func (s *Server) GetVersion(_ context.Context, _ gen.GetVersionRequestObject) (gen.GetVersionResponseObject, error) {
	info := s.version()
	resp := gen.GetVersion200JSONResponse{Version: info.Version, ApiVersion: gen.V1}
	if info.Commit != "" && info.Commit != unknownCommit {
		commit := info.Commit
		resp.Commit = &commit
	}
	return resp, nil
}
