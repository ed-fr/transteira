package adminauth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/oidc"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Single sign-on of the delegated admins and auditors (OpenID Connect,
// since 2.0, threat model section 6.48). The flow is:
//
//   - [Service.StartSSO] routes the domain of an e-mail address to the
//     enabled configuration of one tenant (no account lookup, T-296) and
//     starts an authorization code flow (PKCE, state, nonce) whose context
//     the browser keeps in a signed flow cookie;
//   - [Service.CompleteSSO], on the redirect back from the provider,
//     consumes the flow (single use), redeems the code with the
//     configuration of that tenant only, read again, checks the second
//     factor the tenant requires, matches the account (T-286) and opens a
//     session directly in the authenticated state, recording the issuer,
//     the client ID and whether multi-factor authentication was proven;
//   - [Service.Resolve] limits such a session, on every request, to the
//     tenants of the account whose current configuration admits that
//     login (T-287, T-291).
//
// A super admin never signs in through single sign-on (T-293).
const (
	// SSOCallbackPath is the path of the redirect URI registered at the
	// providers, on the admin host (completeAdminOidcLogin).
	SSOCallbackPath = "/api/v1/admin/auth/oidc/callback"
	// DeliveryNone is the delivery of an account created without any
	// activation link (OpenAPI InvitationDelivery none): it has no password
	// and signs in through single sign-on only. It is never stored as the
	// delivery of an activation link: no link exists.
	DeliveryNone store.ActivationDelivery = "none"
	// methodOIDC is the method of a single sign-on login in the admin.login
	// audit events.
	methodOIDC = "oidc"
	// reasonSSORequired is the reason of the admin.login_failed audit event
	// of a right password refused because single sign-on is enforced.
	reasonSSORequired = "sso_required"
)

// SSOFlows runs the OpenID Connect authorization code flows.
// *oidc.Flows implements it.
type SSOFlows interface {
	Begin(ctx context.Context, cfg oidc.Config) (redirectURL, cookie string, err error)
	Bound(cookie, state string) bool
	Consume(cookie, state, iss string) (oidc.Pending, error)
	Redeem(ctx context.Context, p oidc.Pending, cfg oidc.Config, code string) (oidc.Identity, error)
}

// Compile-time check that the flows of internal/oidc fit.
var _ SSOFlows = (*oidc.Flows)(nil)

// SecretOpener unseals the secrets of a tenant (the client secret of its
// single sign-on configuration, purpose crypto.PurposeSecret).
// *masterkey.Vault implements it.
type SecretOpener interface {
	Open(ctx context.Context, tid tenant.ID, p crypto.Purpose, wkID string) ([]byte, error)
}

// AuthMethods are the login methods offered by the admin host (OpenAPI
// AuthMethods).
type AuthMethods struct {
	// Password is always true: the local password with TOTP stays the way
	// in of the super admin.
	Password bool
	// SSO reports that at least one tenant has an enabled single sign-on
	// configuration with a client secret.
	SSO bool
}

// SSOStart is a single sign-on flow just started: the HTTP layer sets
// Cookie as the flow cookie (oidc.FlowCookie) and sends the browser to
// RedirectURL.
type SSOStart struct {
	// RedirectURL is the authorization endpoint of the provider with the
	// flow parameters.
	RedirectURL string
	// Cookie is the value of the flow cookie.
	Cookie string
}

// SSOCallback is the redirect of the browser back from the provider: the
// flow cookie and the query parameters of completeAdminOidcLogin.
type SSOCallback struct {
	// Cookie is the value of the flow cookie, "" when absent.
	Cookie string
	// Code, State, Iss and Error are the query parameters (the provider
	// text error_description is never used).
	Code, State, Iss, Error string
}

// Identity is a single sign-on identity pinned to an account (OpenAPI
// AdminIdentity). The subject is never exposed.
type Identity struct {
	// ID is the identifier ("aid_" + ULID).
	ID string
	// Issuer and ClientID are those of the login that pinned it.
	Issuer, ClientID string
	// LinkedAt is the pinning time.
	LinkedAt time.Time
	// LastUsedAt is the last login through it, zero if none.
	LastUsedAt time.Time
}

// identityOf returns the public view of i.
func identityOf(i store.AdminIdentity) Identity {
	return Identity{ID: i.ID, Issuer: i.Issuer, ClientID: i.ClientID, LinkedAt: i.CreatedAt, LastUsedAt: i.LastUsedAt}
}

// ssoRules returns the limits of a single sign-on step from ip: the
// failures per client IP of the admin login (shared with the passwords
// and second factors, so that a flood of failures is rate limited).
func ssoRules(ip netip.Addr) []store.AdminLoginRule {
	return []store.AdminLoginRule{
		{Key: store.AdminLoginIPKey(ip), MaxFailures: LoginIPMaxFailures, Window: LoginWindow, LockDuration: LoginLockDuration},
	}
}

// usable reports whether c is a configuration a single sign-on login can
// go through: enabled, with a client secret.
func usable(c store.TenantSSO) bool { return c.Enabled && c.HasClientSecret() }

// Methods returns the login methods offered by the admin host: the
// password always, single sign-on when at least one tenant has it enabled
// (never when the service has no single sign-on flows).
func (s *Service) Methods(ctx context.Context) (AuthMethods, error) {
	out := AuthMethods{Password: true}
	if s.flows == nil {
		return out, nil
	}
	enabled, err := s.repo.ssoAnyEnabled(ctx)
	if err != nil {
		return AuthMethods{}, fmt.Errorf("adminauth: check single sign-on: %w", err)
	}
	out.SSO = enabled
	return out, nil
}

// StartSSO starts a single sign-on login for the e-mail address email
// typed on the login page, from clientIP: the domain of the address is
// routed to the enabled configuration of one tenant, whose client secret
// is unsealed to check the configuration, and a flow is started at its
// provider (discovery document loaded and validated). No account is looked
// up (T-296).
//
// The attempt is counted first on the per-IP login limit (20 failures
// within 15 minutes lock the IP for 15 minutes, shared with the password
// login); a successful start is withdrawn, an unavailable one stays
// counted, so that probing the domains is rate limited.
//
// It returns an *InvalidError on FieldEmail for a malformed address,
// ErrNoClientIP, a *RateLimitError while the IP is locked or when this
// attempt locks it, and ErrSSONotAvailable when the domain is routed to
// no enabled configuration (unknown or disabled alike) or when the
// configuration cannot be used: its secret does not unseal, or its
// provider cannot be reached or misbehaves. The last two are reported on
// the application log, by tenant ID only; the client gets the same answer
// as for an unknown domain.
func (s *Service) StartSSO(ctx context.Context, email string, clientIP netip.Addr) (SSOStart, error) {
	addr, err := parseEmail(email)
	switch {
	case err != nil:
		return SSOStart{}, err
	case !clientIP.IsValid():
		return SSOStart{}, ErrNoClientIP
	case s.flows == nil:
		return SSOStart{}, ErrSSONotAvailable
	}
	rules := ssoRules(clientIP)
	now := s.now()
	out, err := s.reserve(ctx, rules, clientIP, now)
	if err != nil {
		return SSOStart{}, err
	}
	start, err := s.startSSO(ctx, addr)
	switch {
	case errors.Is(err, ErrSSONotAvailable):
		if !out.LockedUntil.IsZero() {
			return SSOStart{}, s.limited(ctx, clientIP, out.LockedUntil, now)
		}
		return SSOStart{}, ErrSSONotAvailable
	case err != nil:
		s.refund(ctx, rules, now)
		return SSOStart{}, err
	}
	s.refund(ctx, rules, now)
	return start, nil
}

// startSSO routes the domain of addr and begins the flow. It returns
// ErrSSONotAvailable for every reason the login cannot start.
func (s *Service) startSSO(ctx context.Context, addr string) (SSOStart, error) {
	cfg, err := s.repo.ssoRoute(ctx, addr[strings.LastIndexByte(addr, '@')+1:])
	switch {
	case errors.Is(err, store.ErrNotFound):
		return SSOStart{}, ErrSSONotAvailable
	case err != nil:
		return SSOStart{}, fmt.Errorf("adminauth: route single sign-on domain: %w", err)
	}
	oc, err := s.oidcConfig(ctx, cfg)
	if err != nil {
		return SSOStart{}, ErrSSONotAvailable
	}
	redirectURL, cookie, err := s.flows.Begin(ctx, oc)
	if err != nil {
		s.logger.WarnContext(ctx, "single sign-on start failed", slog.String("tenant_id", string(cfg.TenantID)),
			slog.String("error", err.Error()))
		return SSOStart{}, ErrSSONotAvailable
	}
	return SSOStart{RedirectURL: redirectURL, Cookie: cookie}, nil
}

// oidcConfig unseals the client secret of cfg and returns the flow
// configuration. A failure is logged by tenant ID only.
func (s *Service) oidcConfig(ctx context.Context, cfg store.TenantSSO) (oidc.Config, error) {
	secret, err := s.secrets.Open(ctx, cfg.TenantID, crypto.PurposeSecret, cfg.ClientSecretKeyID)
	if err != nil {
		s.logger.ErrorContext(ctx, "single sign-on client secret not unsealed", slog.String("tenant_id", string(cfg.TenantID)),
			slog.String("error", err.Error()))
		return oidc.Config{}, fmt.Errorf("adminauth: open client secret: %w", err)
	}
	defer clear(secret)
	return oidc.Config{
		TenantID: string(cfg.TenantID), Issuer: cfg.Issuer, ClientID: cfg.ClientID, ClientSecret: string(secret),
		RedirectURL: s.baseURL + SSOCallbackPath,
	}, nil
}

// ssoRefusalError is a failed single sign-on callback inside the package: the
// reason of the sso_failed security event, the tenant of the flow when
// known and the account when one was identified (for the audit).
type ssoRefusalError struct {
	reason  string
	tenant  *tenant.Tenant
	account *store.Admin
}

// Error implements error.
func (f *ssoRefusalError) Error() string { return "adminauth: single sign-on failed: " + f.reason }

// CompleteSSO completes a single sign-on login from clientIP with the
// redirect cb of the browser back from the provider, and opens a session
// directly in the authenticated state (the second factor is delegated to
// the provider, see the tenant's requireMfa).
//
// The checks run in this order: the binding of the flow cookie to state
// (a callback without a flow cookie whose MAC binds it to state is refused
// as state_invalid without being counted nor logged: a cross-site page can
// produce it, T-289); the per-IP login limit (the attempt is counted first,
// withdrawn on success); the flow, consumed whatever the
// outcome (single use, T-289), bound to the cookie and to state, and the
// RFC 9207 iss parameter; the error parameter of the provider; the
// configuration of the tenant of the flow, read again (never chosen from
// the answer, T-288), which must still be enabled with the same issuer and
// client ID; the code exchange and the ID token; the second factor when the
// tenant requires it; then the account (T-286): the one pinned to (issuer,
// client ID, subject), else, on a first login, the only active delegated
// admin or auditor attached to the tenant whose address is the verified
// address of the token, its domain among the routed domains of the
// configuration, unless that account is already pinned to another subject
// for (issuer, client ID). The role and the state are checked at every
// login: a super admin, a disabled account or one no longer attached to
// the tenant is refused (T-293). A first login pins the identity in the
// transaction of the session (audit admin.identity_linked).
//
// Every failure past the binding writes an sso_failed security event with
// its reason (and the tenant of the flow when known), an admin.login_failed
// audit event when an account was identified, and stays counted on the
// per-IP limit.
// A success writes admin.login (method oidc, issuer, tenant).
//
// It returns ErrNoClientIP, ErrSSONotAvailable when the service has no
// single sign-on, a *RateLimitError while the IP is locked or when this
// failure locks it, and an *SSOError (matching ErrSSOFailed) with the
// reason of the failure. Any other error is internal.
func (s *Service) CompleteSSO(ctx context.Context, cb SSOCallback, clientIP netip.Addr) (Session, error) {
	switch {
	case !clientIP.IsValid():
		return Session{}, ErrNoClientIP
	case s.flows == nil:
		return Session{}, ErrSSONotAvailable
	}
	if !s.flows.Bound(cb.Cookie, cb.State) {
		// No flow of this browser: a cross-site request (the SameSite=Lax
		// flow cookie is not sent) or a forged cookie. A third party can
		// produce it at will, so it neither counts on the per-IP limit nor
		// writes a security event, which would let it lock the admin login
		// out or have the IP banned.
		s.logger.DebugContext(ctx, "single sign-on callback without a valid flow cookie")
		return Session{}, &SSOError{Reason: securitylog.ReasonStateInvalid}
	}
	rules := ssoRules(clientIP)
	now := s.now()
	out, err := s.reserve(ctx, rules, clientIP, now)
	if err != nil {
		return Session{}, err
	}
	sess, err := s.completeSSO(ctx, cb, clientIP)
	if f, ok := errors.AsType[*ssoRefusalError](err); ok {
		return Session{}, s.ssoFailed(ctx, clientIP, f, out, now)
	}
	s.refund(ctx, rules, now)
	if err != nil {
		return Session{}, err
	}
	return sess, nil
}

// ssoFailed records the failure f of a callback from ip: the sso_failed
// security event, the audit event when an account was identified, and the
// rate_limited event when this failure set a lock. It returns the
// *RateLimitError of that lock, or the *SSOError of f.
func (s *Service) ssoFailed(ctx context.Context, ip netip.Addr, f *ssoRefusalError, out store.FailureOutcome, now time.Time) error {
	ev := securitylog.Event{
		Type: securitylog.SSOFailed, IP: ip, Fields: []securitylog.Field{{Key: securitylog.KeyReason, Value: f.reason}},
	}
	details := map[string]any{"reason": f.reason, "method": methodOIDC}
	if f.tenant != nil {
		ev.Tenant, ev.TenantID = f.tenant.FQDN, string(f.tenant.ID)
		details["tenant_id"] = string(f.tenant.ID)
	}
	if err := s.seclog.Log(ev); err != nil {
		s.logger.ErrorContext(ctx, "security log write failed",
			slog.String("event", string(ev.Type)), slog.String("error", err.Error()))
	}
	if f.account != nil {
		s.record(ctx, adminEvent(f.account.Username, ip, audit.ActionAdminLoginFailed, f.account.ID, details))
	}
	if !out.LockedUntil.IsZero() {
		return s.limited(ctx, ip, out.LockedUntil, now)
	}
	return &SSOError{Reason: f.reason}
}

// completeSSO implements CompleteSSO after the limit: it returns an
// *ssoRefusalError for a refused login, any other error for an internal
// failure.
func (s *Service) completeSSO(ctx context.Context, cb SSOCallback, ip netip.Addr) (Session, error) {
	p, err := s.flows.Consume(cb.Cookie, cb.State, cb.Iss)
	if err != nil {
		return Session{}, &ssoRefusalError{reason: oidc.ReasonOf(err)}
	}
	t, cfg, err := s.flowConfig(ctx, p)
	if err != nil {
		return Session{}, err
	}
	fail := func(reason string, a *store.Admin) error {
		return &ssoRefusalError{reason: reason, tenant: t, account: a}
	}
	if oidc.ProviderError(cb.Error) != nil {
		return Session{}, fail(securitylog.ReasonIssuerError, nil)
	}
	oc, err := s.oidcConfig(ctx, cfg)
	if err != nil {
		return Session{}, fail(securitylog.ReasonIssuerError, nil)
	}
	id, err := s.flows.Redeem(ctx, p, oc, cb.Code)
	if err != nil {
		s.logger.WarnContext(ctx, "single sign-on code not redeemed", slog.String("tenant_id", string(t.ID)),
			slog.String("error", err.Error()))
		return Session{}, fail(oidc.ReasonOf(err), nil)
	}
	if cfg.RequireMFA && !id.MFA {
		return Session{}, fail(securitylog.ReasonMFAMissing, nil)
	}
	a, pinned, err := s.ssoAccount(ctx, t.ID, cfg, id)
	if f, ok := errors.AsType[*ssoRefusalError](err); ok {
		return Session{}, fail(f.reason, f.account)
	}
	if err != nil {
		return Session{}, err
	}
	sess, err := s.openSSOSession(ctx, t.ID, a, pinned, id, ip)
	if f, ok := errors.AsType[*ssoRefusalError](err); ok {
		return Session{}, fail(f.reason, f.account)
	}
	return sess, err
}

// flowConfig reads the tenant of the flow p and its configuration, which
// must still be enabled, with a secret, the same issuer and the same
// client ID as at the start (else an *ssoRefusalError issuer_error).
func (s *Service) flowConfig(ctx context.Context, p oidc.Pending) (*tenant.Tenant, store.TenantSSO, error) {
	tid := tenant.ID(p.TenantID)
	t, err := s.repo.tenant(ctx, tid)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil, store.TenantSSO{}, &ssoRefusalError{reason: securitylog.ReasonIssuerError}
	case err != nil:
		return nil, store.TenantSSO{}, fmt.Errorf("adminauth: read tenant: %w", err)
	}
	cfg, err := s.repo.ssoGet(ctx, tid)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil, store.TenantSSO{}, &ssoRefusalError{reason: securitylog.ReasonIssuerError, tenant: t}
	case err != nil:
		return nil, store.TenantSSO{}, fmt.Errorf("adminauth: read single sign-on configuration: %w", err)
	case !usable(cfg) || cfg.Issuer != p.Issuer || cfg.ClientID != p.ClientID:
		return nil, store.TenantSSO{}, &ssoRefusalError{reason: securitylog.ReasonIssuerError, tenant: t}
	}
	return t, cfg, nil
}

// eligible reports whether a may sign in through the single sign-on of
// tenant tid: an active delegated admin or auditor attached to it.
func eligible(a store.Admin, tid tenant.ID) bool {
	return (a.Role == store.RoleDelegatedAdmin || a.Role == store.RoleAuditor) && !a.Disabled &&
		slices.Contains(a.TenantIDs, tid)
}

// ssoAccount matches the account of the identity id proven through the
// configuration cfg of tenant tid (T-286). It returns the account and its
// pinned identity, or a zero identity when the login is a first one to
// pin; an *ssoRefusalError account_unknown or identity_mismatch when no account
// may sign in.
func (s *Service) ssoAccount(ctx context.Context, tid tenant.ID, cfg store.TenantSSO, id oidc.Identity) (store.Admin, store.AdminIdentity, error) {
	unknown := func(a *store.Admin) error {
		return &ssoRefusalError{reason: securitylog.ReasonAccountUnknown, account: a}
	}
	pinned, err := s.repo.findIdentity(ctx, cfg.Issuer, cfg.ClientID, id.Subject)
	switch {
	case err == nil:
		a, err := s.repo.admin(ctx, pinned.AdminID)
		switch {
		case errors.Is(err, store.ErrNotFound):
			return store.Admin{}, store.AdminIdentity{}, unknown(nil)
		case err != nil:
			return store.Admin{}, store.AdminIdentity{}, fmt.Errorf("adminauth: read admin: %w", err)
		case !eligible(a, tid):
			return store.Admin{}, store.AdminIdentity{}, unknown(&a)
		}
		return a, pinned, nil
	case !errors.Is(err, store.ErrNotFound):
		return store.Admin{}, store.AdminIdentity{}, fmt.Errorf("adminauth: find identity: %w", err)
	}
	// First login: the verified address, in a routed domain, of exactly
	// one eligible account of the tenant.
	at := strings.LastIndexByte(id.Email, '@')
	if at < 0 {
		return store.Admin{}, store.AdminIdentity{}, unknown(nil)
	}
	domain, err := store.NormalizeSSODomain(id.Email[at+1:])
	if err != nil || !slices.Contains(cfg.EmailDomains, domain) {
		return store.Admin{}, store.AdminIdentity{}, unknown(nil)
	}
	candidates, err := s.repo.adminsByEmail(ctx, id.Email, tid)
	if err != nil {
		return store.Admin{}, store.AdminIdentity{}, fmt.Errorf("adminauth: find admin by email: %w", err)
	}
	var matches []store.Admin
	for _, a := range candidates {
		if eligible(a, tid) {
			matches = append(matches, a)
		}
	}
	switch {
	case len(matches) == 0 && len(candidates) == 1:
		return store.Admin{}, store.AdminIdentity{}, unknown(&candidates[0])
	case len(matches) != 1:
		return store.Admin{}, store.AdminIdentity{}, unknown(nil)
	}
	a := matches[0]
	_, err = s.repo.identityForAdmin(ctx, a.ID, cfg.Issuer, cfg.ClientID)
	switch {
	case err == nil:
		// Pinned to another subject (the triple was not found).
		return store.Admin{}, store.AdminIdentity{}, &ssoRefusalError{reason: securitylog.ReasonIdentityMismatch, account: &a}
	case !errors.Is(err, store.ErrNotFound):
		return store.Admin{}, store.AdminIdentity{}, fmt.Errorf("adminauth: read identity: %w", err)
	}
	return a, store.AdminIdentity{}, nil
}

// openSSOSession pins the identity id to a when pinned is zero (first
// login), and opens the authenticated single sign-on session of a from ip,
// in one transaction; then it records the login.
func (s *Service) openSSOSession(ctx context.Context, tid tenant.ID, a store.Admin, pinned store.AdminIdentity,
	id oidc.Identity, ip netip.Addr,
) (Session, error) {
	now := s.now()
	row, out, err := s.newSession(a.ID, store.SessionAuthenticated, ip, now)
	if err != nil {
		return Session{}, err
	}
	row.AuthMethod, row.SSOIssuer, row.SSOClientID, row.SSOMFA = store.AuthOIDC, id.Issuer, id.ClientID, id.MFA
	err = s.repo.tx(ctx, func(tx txRepo) error {
		if pinned.ID == "" {
			linked, err := tx.linkIdentity(ctx, store.AdminIdentity{
				AdminID: a.ID, Issuer: id.Issuer, ClientID: id.ClientID, Subject: id.Subject,
			})
			switch {
			case errors.Is(err, store.ErrIdentityConflict):
				return &ssoRefusalError{reason: securitylog.ReasonIdentityMismatch, account: &a}
			case errors.Is(err, store.ErrInvalid), errors.Is(err, store.ErrNotFound):
				// Promoted to super admin or deleted since the match.
				return &ssoRefusalError{reason: securitylog.ReasonAccountUnknown, account: &a}
			case err != nil:
				return err
			}
			pinned = linked
			if err := tx.audit(ctx, adminEvent(a.Username, ip, audit.ActionAdminIdentityLinked, a.ID, map[string]any{
				"identity_id": linked.ID, "issuer": linked.Issuer, "client_id": linked.ClientID, "tenant_id": string(tid),
			})); err != nil {
				return err
			}
		}
		return tx.createSession(ctx, row)
	})
	if _, ok := errors.AsType[*ssoRefusalError](err); ok {
		return Session{}, err
	}
	if err != nil {
		return Session{}, fmt.Errorf("adminauth: open single sign-on session: %w", err)
	}
	if err := s.repo.touchIdentity(ctx, pinned.ID, now); err != nil {
		s.logger.ErrorContext(ctx, "single sign-on identity use not recorded", slog.String("admin_id", a.ID),
			slog.String("error", err.Error()))
	}
	if err := s.repo.touchLogin(ctx, a.ID); err != nil {
		s.logger.ErrorContext(ctx, "admin last login not recorded", slog.String("admin_id", a.ID), slog.String("error", err.Error()))
	}
	s.record(ctx, adminEvent(a.Username, ip, audit.ActionAdminLogin, a.ID, map[string]any{
		"method": methodOIDC, "issuer": id.Issuer, "tenant_id": string(tid), "mfa": id.MFA,
	}))
	return out, nil
}

// ssoScope limits the account a of the single sign-on session sess to the
// tenants whose current configuration admits the login of the session
// (enabled, with a secret, same issuer and client ID, requireMfa met by
// the second factor proven at the login; T-287, T-291). A super admin
// never has such a session (T-293): it is refused as unauthenticated. An
// account left without any tenant keeps a valid session that reaches no
// tenant: a configuration enabled again with the same issuer and client
// ID gives the tenant back without a new login.
func (s *Service) ssoScope(ctx context.Context, a store.Admin, sess store.AdminSession) (store.Admin, error) {
	if a.Role == store.RoleSuperAdmin {
		return store.Admin{}, ErrUnauthenticated
	}
	configs, err := s.repo.ssoForAdmin(ctx, a.ID)
	if err != nil {
		return store.Admin{}, fmt.Errorf("adminauth: read single sign-on scope: %w", err)
	}
	kept := make([]tenant.ID, 0, len(a.TenantIDs))
	for _, tid := range a.TenantIDs {
		i := slices.IndexFunc(configs, func(c store.TenantSSO) bool { return c.TenantID == tid })
		if i >= 0 && configs[i].Admits(sess.SSOIssuer, sess.SSOClientID, sess.SSOMFA) {
			kept = append(kept, tid)
		}
	}
	a.TenantIDs = kept
	return a, nil
}

// passwordScope limits the account a of a password session to the
// tenants that do not enforce single sign-on: every tenant whose usable
// configuration is enforced is removed (T-292). This covers the sessions
// opened before the enforcement, through an activation link or after a
// password reset. A super admin keeps all its tenants (its local login is
// always available) and costs no query.
func (s *Service) passwordScope(ctx context.Context, a store.Admin) (store.Admin, error) {
	if a.Role == store.RoleSuperAdmin || len(a.TenantIDs) == 0 {
		return a, nil
	}
	configs, err := s.repo.ssoForAdmin(ctx, a.ID)
	if err != nil {
		return store.Admin{}, fmt.Errorf("adminauth: read single sign-on enforcement: %w", err)
	}
	kept := make([]tenant.ID, 0, len(a.TenantIDs))
	for _, tid := range a.TenantIDs {
		if !slices.ContainsFunc(configs, func(c store.TenantSSO) bool { return c.TenantID == tid && usable(c) && c.Enforced }) {
			kept = append(kept, tid)
		}
	}
	a.TenantIDs = kept
	return a, nil
}

// ssoEnforced reports whether a, a delegated admin or an auditor, is
// attached to at least one tenant whose usable single sign-on is enforced
// (T-292). It is false for a super admin, whose local login is always
// available.
func (s *Service) ssoEnforced(ctx context.Context, a store.Admin) (bool, error) {
	if a.Role == store.RoleSuperAdmin {
		return false, nil
	}
	configs, err := s.repo.ssoForAdmin(ctx, a.ID)
	if err != nil {
		return false, fmt.Errorf("adminauth: read single sign-on enforcement: %w", err)
	}
	return slices.ContainsFunc(configs, func(c store.TenantSSO) bool { return usable(c) && c.Enforced }), nil
}

// checkSSOConfigured returns ErrSSONotConfigured unless every tenant of
// tids has a usable single sign-on configuration (an account without
// activation link, delivery none).
func (s *Service) checkSSOConfigured(ctx context.Context, tids []tenant.ID) error {
	for _, tid := range tids {
		cfg, err := s.repo.ssoGet(ctx, tid)
		switch {
		case errors.Is(err, store.ErrNotFound):
			return ErrSSONotConfigured
		case err != nil:
			return fmt.Errorf("adminauth: read single sign-on configuration: %w", err)
		case !usable(cfg):
			return ErrSSONotConfigured
		}
	}
	return nil
}

// checkLinkAllowedID is checkLinkAllowed for the account adminID, read
// first. An unknown account passes: the caller reports it.
func (s *Service) checkLinkAllowedID(ctx context.Context, adminID string) error {
	a, err := s.repo.admin(ctx, adminID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil
	case err != nil:
		return fmt.Errorf("adminauth: read admin: %w", err)
	}
	return s.checkLinkAllowed(ctx, a)
}

// checkLinkAllowed returns ErrSSOOnlyEnforced when an activation link must
// not be issued for the account a: a single sign-on only account while one
// of its tenants enforces single sign-on (T-292).
func (s *Service) checkLinkAllowed(ctx context.Context, a store.Admin) error {
	if !a.SSOOnly {
		return nil
	}
	enforced, err := s.ssoEnforced(ctx, a)
	switch {
	case err != nil:
		return err
	case enforced:
		return ErrSSOOnlyEnforced
	}
	return nil
}

// withIdentities returns acc with the single sign-on identities of its
// account.
func (s *Service) withIdentities(ctx context.Context, acc Account) (Account, error) {
	ids, err := s.repo.identities(ctx, acc.ID)
	if err != nil {
		return Account{}, fmt.Errorf("adminauth: list identities: %w", err)
	}
	acc.Identities = make([]Identity, len(ids))
	for i, id := range ids {
		acc.Identities[i] = identityOf(id)
	}
	return acc, nil
}

// DeleteIdentity unpins the single sign-on identity identityID of the
// account adminID, for the super admin of p, from clientIP (OpenAPI
// deleteAdminIdentity, audit admin.identity_unlinked): the next single
// sign-on login of the account pins it again by its e-mail address. The
// single sign-on sessions of the account opened through the same issuer
// and client ID are revoked in the same transaction.
//
// It returns ErrUnauthenticated or ErrForbidden for a caller who is not an
// authenticated super admin, and ErrNotFound for an unknown identity or one
// of another account.
func (s *Service) DeleteIdentity(ctx context.Context, p Principal, adminID, identityID string, clientIP netip.Addr) error {
	if err := manager(p); err != nil {
		return err
	}
	err := s.repo.tx(ctx, func(tx txRepo) error {
		removed, err := tx.deleteIdentity(ctx, adminID, identityID)
		if err != nil {
			return err
		}
		if _, err := tx.deleteSSOSessions(ctx, adminID, removed.Issuer, removed.ClientID); err != nil {
			return err
		}
		return tx.audit(ctx, unlinkedEvent(p.Admin.Username, clientIP, adminID, removed, "unpinned"))
	})
	switch {
	case errors.Is(err, store.ErrNotFound):
		return ErrNotFound
	case err != nil:
		return fmt.Errorf("adminauth: delete identity: %w", err)
	}
	return nil
}

// unlinkedEvent returns the admin.identity_unlinked audit event of the
// identity i of the account adminID, removed by actor for reason
// ("unpinned" by the super admin, "promoted" to super admin): the issuer
// and the client ID, never the subject.
func unlinkedEvent(actor string, ip netip.Addr, adminID string, i store.AdminIdentity, reason string) audit.Event {
	return adminEvent(actor, ip, audit.ActionAdminIdentityUnlinked, adminID, map[string]any{
		"identity_id": i.ID, "issuer": i.Issuer, "client_id": i.ClientID, "reason": reason,
	})
}
