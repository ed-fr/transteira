package tenantadmin

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/oidc"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// maxSSOSecretLen bounds the client secret, in bytes (OpenAPI
// TenantSsoUpdate.clientSecret).
const maxSSOSecretLen = 1024

// Fields of the single sign-on configuration named by an [InvalidError]
// (OpenAPI TenantSsoUpdate). An e-mail domain is named by its index:
// FieldSSOEmailDomains + "/" + index.
const (
	FieldSSOIssuer       = "/issuer"
	FieldSSOClientID     = "/clientId"
	FieldSSOClientSecret = "/clientSecret"
	FieldSSOEmailDomains = "/emailDomains"
)

// Codes of an [InvalidError] of the single sign-on configuration.
const (
	// CodeRequired is a member required in this state: the client secret
	// on the first write, after its erasure, and whenever the issuer or
	// the client ID changes.
	CodeRequired = "required"
	// CodeNotInternalDomain is an e-mail domain that is not one of the
	// internal mail domains of the tenant (network rules).
	CodeNotInternalDomain = "not-internal-domain"
)

// Errors of the single sign-on configuration. Callers test them with
// errors.Is; the comment of each one gives the problem code it maps to.
var (
	// ErrSSOIssuerNotAllowed reports an issuer that is not an https URL, a
	// template issuer or a Microsoft Entra ID multi-tenant issuer (422
	// sso-issuer-not-allowed, threat T-288).
	ErrSSOIssuerNotAllowed = errors.New("tenantadmin: single sign-on issuer not allowed")
	// ErrSSODomainConflict reports an e-mail domain already routed to the
	// single sign-on of another tenant (409 sso-domain-conflict).
	ErrSSODomainConflict = errors.New("tenantadmin: e-mail domain routed to another tenant's single sign-on")
	// ErrSSONothingToTest reports a discovery test of a tenant without
	// single sign-on configuration (409 state-conflict).
	ErrSSONothingToTest = errors.New("tenantadmin: no single sign-on configuration to test")
)

// errNoSSOTester reports a [Service] built without Options.SSOTester: a
// wiring error (500).
var errNoSSOTester = errors.New("tenantadmin: no single sign-on tester configured")

// errSSOSecretRequired reports, from [ssoRepo.putSSO], a write without a
// new client secret while none is stored.
var errSSOSecretRequired = errors.New("tenantadmin: single sign-on client secret required")

// SSOTester runs the discovery test of an OpenID Connect issuer
// (*oidc.Client): it never signs anyone in nor sends a secret, and reports
// a failure as a result.
type SSOTester interface {
	Test(ctx context.Context, issuer string) oidc.TestResult
}

// SSOView is the single sign-on configuration of a tenant as returned to
// an administrator (OpenAPI TenantSso): the client secret never leaves the
// service, only whether one is stored.
type SSOView struct {
	Enabled         bool
	Issuer          string
	ClientID        string
	HasClientSecret bool
	// EmailDomains are the routed domains, normalized and sorted.
	EmailDomains []string
	Enforced     bool
	RequireMFA   bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// SSOUpdate is the input of [Service.PutSSO] (OpenAPI TenantSsoUpdate).
// The API defaults (enforced false, requireMfa true) are applied by the
// caller: every field here is taken as given.
type SSOUpdate struct {
	Enabled  bool
	Issuer   string
	ClientID string
	// ClientSecret is the new client secret; nil keeps the stored one,
	// which is only allowed when one is stored and neither the issuer nor
	// the client ID changes.
	ClientSecret *string
	EmailDomains []string
	Enforced     bool
	RequireMFA   bool
}

// ssoViewOf converts a stored configuration.
func ssoViewOf(c store.TenantSSO) SSOView {
	return SSOView{
		Enabled: c.Enabled, Issuer: c.Issuer, ClientID: c.ClientID, HasClientSecret: c.HasClientSecret(),
		EmailDomains: append([]string{}, c.EmailDomains...), Enforced: c.Enforced, RequireMFA: c.RequireMFA,
		CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt,
	}
}

// ssoWritable checks that p may change the single sign-on configuration of
// tenant tid (threat T-287, P57): the tenant must be within reach first
// (404 outside it, read-only-role for an auditor attached to it), then the
// caller must be the super admin (403 forbidden for a delegated admin), so
// that the refusal never tells that another tenant exists.
func (s *Service) ssoWritable(ctx context.Context, p adminauth.Principal, tid tenant.ID) error {
	if _, err := s.writable(ctx, p, tid); err != nil {
		return err
	}
	return adminauth.RequireSuperAdmin(p.Admin)
}

// GetSSO returns the single sign-on configuration of tenant tid, or
// ErrNotFound when it has none. The super admin, the delegated admins and
// the auditors of the tenant may read it ([adminauth.RequireTenantAuditRead]).
func (s *Service) GetSSO(ctx context.Context, p adminauth.Principal, tid tenant.ID) (SSOView, error) {
	if _, err := s.summaryReadable(ctx, p, tid); err != nil {
		return SSOView{}, err
	}
	c, err := s.ssoConfig(ctx, tid)
	if err != nil {
		return SSOView{}, err
	}
	return ssoViewOf(c), nil
}

// ssoConfig returns the stored configuration of tid, or ErrNotFound.
func (s *Service) ssoConfig(ctx context.Context, tid tenant.ID) (store.TenantSSO, error) {
	c, err := s.sso.getSSO(ctx, tid)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return store.TenantSSO{}, ErrNotFound
	case err != nil:
		return store.TenantSSO{}, fmt.Errorf("tenantadmin: get sso settings: %w", err)
	}
	return c, nil
}

// PutSSO creates or replaces the single sign-on configuration of tenant
// tid (super admin only). The issuer must be a tenant-specific https
// issuer (ErrSSOIssuerNotAllowed otherwise); each e-mail domain must be an
// internal mail domain of the tenant (CodeNotInternalDomain) and routed to
// no other tenant (ErrSSODomainConflict). A new client secret is required
// when none is stored and whenever the issuer or the client ID changes
// (CodeRequired on FieldSSOClientSecret): a secret is never carried over to
// another application. The secret is sealed with the master key, the
// configuration stored, the replaced secret erased and the
// tenant.sso_updated event (changed member names only) recorded in one
// transaction.
//
// After the commit, when the issuer or the client ID changed, or the
// configuration was disabled, the single sign-on sessions opened through
// the previous pair are revoked; when the pair changed, the identities
// pinned for it are unpinned too (admin.identity_unlinked each, threat
// T-287, P57). These steps run in the system scope: a failure is logged,
// not returned, the access layer refusing such sessions on every request
// anyway ([store.TenantSSO.Admits]).
func (s *Service) PutSSO(ctx context.Context, p adminauth.Principal, tid tenant.ID, in SSOUpdate, ip netip.Addr) (SSOView, error) {
	if err := s.ssoWritable(ctx, p, tid); err != nil {
		return SSOView{}, err
	}
	next, err := checkSSO(in)
	if err != nil {
		return SSOView{}, err
	}
	if err := s.checkInternalDomains(ctx, tid, next.EmailDomains); err != nil {
		return SSOView{}, err
	}
	next.UpdatedBy = p.Admin.ID
	var secret []byte
	if in.ClientSecret != nil {
		secret = []byte(*in.ClientSecret)
		defer clear(secret)
	}
	before, after, err := s.sso.putSSO(ctx, tid, next, secret, func(before, after store.TenantSSO) audit.Event {
		return s.ssoEvent(p, ip, tid, audit.ActionTenantSSOUpdated, ssoChanges(before, after))
	})
	switch {
	case errors.Is(err, errSSOSecretRequired), errors.Is(err, store.ErrSSOSecretRequired):
		return SSOView{}, &InvalidError{
			Field: FieldSSOClientSecret, Code: CodeRequired,
			Reason: "required on the first write and whenever the issuer or the client id changes",
		}
	case errors.Is(err, store.ErrSSODomainConflict):
		return SSOView{}, ErrSSODomainConflict
	case errors.Is(err, store.ErrSSOIssuerNotAllowed):
		return SSOView{}, ErrSSOIssuerNotAllowed
	case errors.Is(err, store.ErrNotFound):
		return SSOView{}, ErrNotFound
	case err != nil:
		return SSOView{}, fmt.Errorf("tenantadmin: put sso settings: %w", err)
	}
	if before.TenantID != "" {
		pairChanged := before.Issuer != after.Issuer || before.ClientID != after.ClientID
		if pairChanged || (before.Enabled && !after.Enabled) {
			s.revokeSSOSessions(ctx, tid, before)
		}
		if pairChanged {
			s.unpinIdentities(ctx, p, ip, tid, before)
		}
	}
	if before.ClientSecretKeyID != "" && before.ClientSecretKeyID != after.ClientSecretKeyID {
		s.scrub(ctx, tid)
	}
	return ssoViewOf(after), nil
}

// checkSSO validates in and returns the configuration to store, with its
// e-mail domains normalized in the order of the request (the store sorts
// them), without secret key.
func checkSSO(in SSOUpdate) (store.TenantSSO, error) {
	if err := checkIssuer(in.Issuer); err != nil {
		return store.TenantSSO{}, err
	}
	switch {
	case !printableASCII(in.ClientID, store.MaxSSOClientIDLen):
		return store.TenantSSO{}, invalid(FieldSSOClientID, "must be 1 to %d printable ascii characters", store.MaxSSOClientIDLen)
	case in.ClientSecret != nil &&
		(*in.ClientSecret == "" || len(*in.ClientSecret) > maxSSOSecretLen || !safeLine(*in.ClientSecret)):
		return store.TenantSSO{}, invalid(FieldSSOClientSecret, "must be 1 to %d bytes without control characters", maxSSOSecretLen)
	case len(in.EmailDomains) == 0 || len(in.EmailDomains) > store.MaxSSODomains:
		return store.TenantSSO{}, invalid(FieldSSOEmailDomains, "1 to %d domains", store.MaxSSODomains)
	}
	domains := make([]string, len(in.EmailDomains))
	for i, raw := range in.EmailDomains {
		d, err := store.NormalizeSSODomain(raw)
		if err != nil {
			return store.TenantSSO{}, invalid(domainField(i), "must be a mail domain")
		}
		if slices.Contains(domains[:i], d) {
			return store.TenantSSO{}, invalid(domainField(i), "duplicate domain")
		}
		domains[i] = d
	}
	return store.TenantSSO{
		Enabled: in.Enabled, Issuer: in.Issuer, ClientID: in.ClientID, EmailDomains: domains,
		Enforced: in.Enforced, RequireMFA: in.RequireMFA,
	}, nil
}

// checkIssuer applies the issuer rules of the login ([oidc.CheckIssuer])
// and of the store ([store.ValidateSSOIssuer]). A multi-tenant or template
// issuer, and a URL of another scheme than https, are ErrSSOIssuerNotAllowed;
// any other malformed value is an *InvalidError on FieldSSOIssuer.
func checkIssuer(issuer string) error {
	err := oidc.CheckIssuer(issuer)
	if err == nil {
		err = store.ValidateSSOIssuer(issuer)
	}
	switch {
	case err == nil:
		return nil
	case errors.Is(err, oidc.ErrIssuerNotAllowed), errors.Is(err, store.ErrSSOIssuerNotAllowed),
		len(issuer) <= oidc.MaxIssuerLength && strings.HasPrefix(strings.ToLower(issuer), "http://"):
		return ErrSSOIssuerNotAllowed
	default:
		return invalid(FieldSSOIssuer, "must be an https url without credentials, query or fragment")
	}
}

// printableASCII reports whether v is 1 to maxLen printable ASCII
// characters, without space (the client ID rule of the store).
func printableASCII(v string, maxLen int) bool {
	if v == "" || len(v) > maxLen {
		return false
	}
	for i := range len(v) {
		if v[i] < '!' || v[i] > '~' {
			return false
		}
	}
	return true
}

// domainField is the JSON pointer of the e-mail domain at index i.
func domainField(i int) string { return FieldSSOEmailDomains + "/" + strconv.Itoa(i) }

// checkInternalDomains checks that every domain (normalized, in the order
// of the request) is an internal mail domain of tenant tid, so that the
// single sign-on of a tenant never routes the addresses of a domain that
// the tenant does not own (P57). The internal domains are read before the
// transaction: a concurrent change of the network rules is not a threat,
// both being written by administrators of the tenant.
func (s *Service) checkInternalDomains(ctx context.Context, tid tenant.ID, domains []string) error {
	set, err := s.repo.networkRules(ctx, tid)
	if err != nil {
		return fmt.Errorf("tenantadmin: get network rules: %w", err)
	}
	for i, d := range domains {
		if !slices.Contains(set.Domains, d) {
			return &InvalidError{Field: domainField(i), Code: CodeNotInternalDomain, Reason: "not an internal mail domain of the tenant"}
		}
	}
	return nil
}

// ssoChanges returns the API names of the members that differ between a
// and b: never a value, the client secret being named when its key
// changes.
func ssoChanges(a, b store.TenantSSO) []string {
	out := []string{}
	for _, f := range []struct {
		diff bool
		name string
	}{
		{a.Enabled != b.Enabled, "enabled"},
		{a.Issuer != b.Issuer, "issuer"},
		{a.ClientID != b.ClientID, "clientId"},
		{a.ClientSecretKeyID != b.ClientSecretKeyID, "clientSecret"},
		{!slices.Equal(a.EmailDomains, b.EmailDomains), "emailDomains"},
		{a.Enforced != b.Enforced, "enforced"},
		{a.RequireMFA != b.RequireMFA, "requireMfa"},
	} {
		if f.diff {
			out = append(out, f.name)
		}
	}
	return out
}

// ssoEvent returns the audit event of a change of the configuration of
// tenant tid by p.
func (s *Service) ssoEvent(p adminauth.Principal, ip netip.Addr, tid tenant.ID, action audit.Action, fields []string) audit.Event {
	return audit.Event{
		TenantID: tid, ActorKind: store.ActorAdmin, Actor: p.Admin.Username, IP: ip,
		Action: action, ObjectKind: objectTenant, ObjectID: string(tid), Details: map[string]any{"fields": fields},
	}
}

// DeleteSSO removes the single sign-on configuration of tenant tid (super
// admin only), its routed domains and its client secret (cryptographic
// erasure), recording tenant.sso_deleted in the same transaction; it
// returns ErrNotFound when the tenant has none. After the commit the
// single sign-on sessions opened through the configuration are revoked
// and the database files scrubbed; a failure of these is logged. The
// pinned identities stay (OpenAPI deleteTenantSso): they are unusable
// until a configuration with the same pair is stored again.
func (s *Service) DeleteSSO(ctx context.Context, p adminauth.Principal, tid tenant.ID, ip netip.Addr) error {
	if err := s.ssoWritable(ctx, p, tid); err != nil {
		return err
	}
	old, err := s.sso.deleteSSO(ctx, tid, func(old store.TenantSSO) audit.Event {
		return s.ssoEvent(p, ip, tid, audit.ActionTenantSSODeleted, ssoChanges(old, store.TenantSSO{}))
	})
	switch {
	case errors.Is(err, store.ErrNotFound):
		return ErrNotFound
	case err != nil:
		return fmt.Errorf("tenantadmin: delete sso settings: %w", err)
	}
	s.revokeSSOSessions(ctx, tid, old)
	s.scrub(ctx, tid)
	return nil
}

// TestSSO fetches and checks the discovery document of the stored issuer
// of tenant tid (super admin only) and reports how it went: a failure of
// the discovery is a result, never an error. It returns
// ErrSSONothingToTest when the tenant has no configuration. The client
// secret is never read.
func (s *Service) TestSSO(ctx context.Context, p adminauth.Principal, tid tenant.ID) (oidc.TestResult, error) {
	if err := s.ssoWritable(ctx, p, tid); err != nil {
		return oidc.TestResult{}, err
	}
	c, err := s.ssoConfig(ctx, tid)
	switch {
	case errors.Is(err, ErrNotFound):
		return oidc.TestResult{}, ErrSSONothingToTest
	case err != nil:
		return oidc.TestResult{}, err
	}
	if s.ssoTester == nil {
		return oidc.TestResult{}, errNoSSOTester
	}
	return s.ssoTester.Test(ctx, c.Issuer), nil
}

// revokeSSOSessions revokes the single sign-on sessions opened through the
// pair of old by the accounts of tenant tid, logging a failure.
func (s *Service) revokeSSOSessions(ctx context.Context, tid tenant.ID, old store.TenantSSO) {
	if _, err := s.sso.revokeSSOSessions(ctx, tid, old.Issuer, old.ClientID); err != nil {
		s.logger.ErrorContext(ctx, "revoking the single sign-on sessions failed", slog.String("tenant", string(tid)),
			slog.String("error", err.Error()))
	}
}

// unpinIdentities unpins the identities of the pair of old held by the
// accounts of tenant tid and records admin.identity_unlinked for each
// (account and issuer, never the subject), logging a failure.
func (s *Service) unpinIdentities(ctx context.Context, p adminauth.Principal, ip netip.Addr, tid tenant.ID, old store.TenantSSO) {
	ids, err := s.sso.unpinIdentities(ctx, tid, old.Issuer, old.ClientID)
	if err != nil {
		s.logger.ErrorContext(ctx, "unpinning the single sign-on identities failed", slog.String("tenant", string(tid)),
			slog.String("error", err.Error()))
		return
	}
	for _, ident := range ids {
		ev := audit.Event{
			TenantID: tid, ActorKind: store.ActorAdmin, Actor: p.Admin.Username, IP: ip,
			Action: audit.ActionAdminIdentityUnlinked, ObjectKind: audit.ObjectAdmin, ObjectID: ident.AdminID,
			Details: map[string]any{
				"identity_id": ident.ID, "issuer": ident.Issuer, "client_id": ident.ClientID, "reason": "sso_changed",
			},
		}
		if err := s.repo.audit(ctx, ev); err != nil {
			s.logger.ErrorContext(ctx, "audit write failed", slog.String("action", string(ev.Action)),
				slog.String("tenant", string(tid)), slog.String("error", err.Error()))
		}
	}
}

// scrub purges the erased client secret from the database files; an
// incomplete checkpoint is retried by the cleanup task, a failure logged.
func (s *Service) scrub(ctx context.Context, tid tenant.ID) {
	if err := s.sso.scrub(ctx); err != nil && !errors.Is(err, store.ErrScrubBusy) {
		s.logger.ErrorContext(ctx, "scrubbing the erased single sign-on secret failed", slog.String("tenant", string(tid)),
			slog.String("error", err.Error()))
	}
}

// --- Persistence -------------------------------------------------------------

// ssoRepo is the persistence of the single sign-on configuration, behind
// an interface so that the tests can inject failures.
type ssoRepo interface {
	getSSO(ctx context.Context, tid tenant.ID) (store.TenantSSO, error)
	putSSO(ctx context.Context, tid tenant.ID, c store.TenantSSO, secret []byte,
		event func(before, after store.TenantSSO) audit.Event) (before, after store.TenantSSO, err error)
	deleteSSO(ctx context.Context, tid tenant.ID, event func(old store.TenantSSO) audit.Event) (store.TenantSSO, error)
	revokeSSOSessions(ctx context.Context, tid tenant.ID, issuer, clientID string) (int64, error)
	unpinIdentities(ctx context.Context, tid tenant.ID, issuer, clientID string) ([]store.AdminIdentity, error)
	scrub(ctx context.Context) error
}

// ssoStore implements ssoRepo with the store. The steps of the
// transactions are function fields so that the tests can make each one
// fail.
type ssoStore struct {
	db *store.DB

	sealTx   func(ctx context.Context, tx *store.ScopedTx, secret []byte) (string, error)
	putTx    func(ctx context.Context, tx *store.ScopedTx, c store.TenantSSO) (store.TenantSSO, store.TenantSSO, error)
	deleteTx func(ctx context.Context, tx *store.ScopedTx) (store.TenantSSO, error)
	recordTx func(ctx context.Context, tx *store.ScopedTx, ev audit.Event) error
}

// newSSOStore returns the store implementation of ssoRepo, sealing with
// vault and recording with writer.
func newSSOStore(db *store.DB, vault Vault, writer *audit.Writer) *ssoStore {
	return &ssoStore{
		db: db,
		sealTx: func(ctx context.Context, tx *store.ScopedTx, secret []byte) (string, error) {
			return vault.SealTx(ctx, tx, crypto.PurposeSecret, secret)
		},
		putTx:    db.SSOSettings().PutTx,
		deleteTx: db.SSOSettings().DeleteTx,
		recordTx: writer.RecordScopedTx,
	}
}

func (r *ssoStore) getSSO(ctx context.Context, tid tenant.ID) (store.TenantSSO, error) {
	return r.db.SSOSettings().Get(ctx, tid)
}

// putSSO seals secret (when not nil), stores c and records the event built
// from the configurations before and after the write, in one tenant-scoped
// transaction. Without a new secret, it returns errSSOSecretRequired when
// none was stored (first write, or secret erased).
func (r *ssoStore) putSSO(ctx context.Context, tid tenant.ID, c store.TenantSSO, secret []byte,
	event func(before, after store.TenantSSO) audit.Event,
) (before, after store.TenantSSO, err error) {
	sc, err := r.db.Scoped(tid)
	if err != nil {
		return store.TenantSSO{}, store.TenantSSO{}, err
	}
	err = sc.Tx(ctx, func(tx *store.ScopedTx) error {
		if secret != nil {
			var err error
			if c.ClientSecretKeyID, err = r.sealTx(ctx, tx, secret); err != nil {
				return err
			}
		}
		var err error
		if before, after, err = r.putTx(ctx, tx, c); err != nil {
			return err
		}
		if secret == nil && !before.HasClientSecret() {
			return errSSOSecretRequired
		}
		return r.recordTx(ctx, tx, event(before, after))
	})
	if err != nil {
		return store.TenantSSO{}, store.TenantSSO{}, err
	}
	return before, after, nil
}

// deleteSSO removes the configuration of tid and records the event built
// from it, in one tenant-scoped transaction.
func (r *ssoStore) deleteSSO(ctx context.Context, tid tenant.ID, event func(old store.TenantSSO) audit.Event) (store.TenantSSO, error) {
	sc, err := r.db.Scoped(tid)
	if err != nil {
		return store.TenantSSO{}, err
	}
	var old store.TenantSSO
	err = sc.Tx(ctx, func(tx *store.ScopedTx) error {
		var err error
		if old, err = r.deleteTx(ctx, tx); err != nil {
			return err
		}
		return r.recordTx(ctx, tx, event(old))
	})
	if err != nil {
		return store.TenantSSO{}, err
	}
	return old, nil
}

func (r *ssoStore) revokeSSOSessions(ctx context.Context, tid tenant.ID, issuer, clientID string) (int64, error) {
	return r.db.AdminSessions().DeleteSSOForTenant(ctx, tid, issuer, clientID)
}

func (r *ssoStore) unpinIdentities(ctx context.Context, tid tenant.ID, issuer, clientID string) ([]store.AdminIdentity, error) {
	return r.db.AdminIdentities().DeleteForTenantClient(ctx, tid, issuer, clientID)
}

func (r *ssoStore) scrub(ctx context.Context) error { return r.db.ScrubDeleted(ctx) }
