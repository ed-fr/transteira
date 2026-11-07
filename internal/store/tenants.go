package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Reasons of the tenant system queries.
const (
	reasonTenantAdmin   = "tenant administration by the super admin (tenants table is the tenant registry)"
	reasonTenantResolve = "resolve the tenant serving an HTTP Host before any tenant is known"
	reasonTenantResume  = "resume the interrupted tenant deletions (identifiers only)"
	reasonTenantErase   = "tenant deletion: refuse while a wrapped key of the tenant remains (T-110)"
	reasonTenantSeed    = "tenant creation: seed the default configuration rows of the new tenant"
	reasonTenantSetup   = "tenant setup completion: check in the same statement the tested SMTP settings, network rules and legal documents"
	reasonTenantNetwork = "network rules saved by an administrator: replace them and record their review on the tenant row (T-307)"
)

// tenantColumns is the column list read by the tenant queries.
const tenantColumns = `id, name, fqdn, default_language, max_transfer_bytes, max_transfer_ceiling, storage_quota_bytes, ` +
	`status, primary_color, accent_color, has_logo, has_background, background_preset, webhook_include_addresses, allow_remote_internal_deposit, allow_transfer_reply, ` +
	`antivirus_enabled, setup_state, smtp_tested_at, mail_templates_reviewed_at, network_reviewed_at, created_at, updated_at, provisioned_by, ` +
	`link_only_allowed, e2e_policy`

// Statements of the Tenants repository. The tenants table is the registry of
// tenants itself, so its statements are system queries.
var (
	qTenantInsert = systemQuery(
		// The setup state is always written explicitly, from the Go value
		// (migration 0022 drops its default on PostgreSQL, T-261).
		`INSERT INTO tenants (`+tenantColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		reasonTenantAdmin)
	qTenantGet = systemQuery(
		`SELECT `+tenantColumns+` FROM tenants WHERE id = ?`,
		reasonTenantAdmin)
	qTenantByFQDN = systemQuery(
		`SELECT `+tenantColumns+` FROM tenants WHERE fqdn = ? AND status = 'active'`,
		reasonTenantResolve)
	qTenantList = systemQuery(
		`SELECT `+tenantColumns+` FROM tenants WHERE id > ? ORDER BY id LIMIT ?`,
		reasonTenantAdmin)
	// qTenantUpdate only updates an active tenant: a tenant being deleted
	// is treated as gone.
	qTenantUpdate = systemQuery(
		`UPDATE tenants SET name = ?, fqdn = ?, default_language = ?, max_transfer_bytes = ?,
			max_transfer_ceiling = ?, storage_quota_bytes = ?, primary_color = ?, accent_color = ?,
			has_logo = ?, has_background = ?, background_preset = ?, webhook_include_addresses = ?,
			allow_remote_internal_deposit = ?, allow_transfer_reply = ?, updated_at = ?
			WHERE id = ? AND status = 'active'`,
		reasonTenantAdmin)
	// qTenantSetAntivirus switches the antivirus of an active tenant (super
	// admin only, decision D8).
	qTenantSetAntivirus = systemQuery(
		`UPDATE tenants SET antivirus_enabled = ?, updated_at = ? WHERE id = ? AND status = 'active'`,
		reasonTenantAdmin)
	// qTenantSetLinkOnly switches the link-only transfers of an active
	// tenant (super admin only, since 2.0).
	qTenantSetLinkOnly = systemQuery(
		`UPDATE tenants SET link_only_allowed = ?, updated_at = ? WHERE id = ? AND status = 'active'`,
		reasonTenantAdmin)
	// qTenantSetE2EPolicy sets the end-to-end encryption policy of an
	// active tenant (super admin only, since 2.0).
	qTenantSetE2EPolicy = systemQuery(
		`UPDATE tenants SET e2e_policy = ?, updated_at = ? WHERE id = ? AND status = 'active'`,
		reasonTenantAdmin)
	// qTenantSetSMTPTested records the SMTP configuration of an active
	// tenant that passed a test send (Tenants.SetSMTPTested).
	qTenantSetSMTPTested = systemQuery(
		`UPDATE tenants SET smtp_tested_at = ? WHERE id = ? AND status = 'active'`,
		reasonTenantAdmin)
	// qTenantSetNetworkReviewed records that an administrator saved the
	// network rules of an active tenant (NetworkRules.ReplaceReviewed).
	qTenantSetNetworkReviewed = systemQuery(
		`UPDATE tenants SET network_reviewed_at = ? WHERE id = ? AND status = 'active'`,
		reasonTenantNetwork)
	// qTenantCompleteSetup moves an active tenant from setup to active,
	// recording the review of the mail templates when given (NULL keeps
	// the current mark): the forced completion of the super admin.
	qTenantCompleteSetup = systemQuery(
		`UPDATE tenants SET setup_state = 'active', mail_templates_reviewed_at = COALESCE(?, mail_templates_reviewed_at),
			updated_at = ? WHERE id = ? AND status = 'active' AND setup_state = 'setup'`,
		reasonTenantAdmin)
	// qTenantCompleteSetupGuarded is qTenantCompleteSetup with the guards of
	// a completion that is not forced, read by the statement itself so that
	// a change committed before it makes it fail (Tenants.CompleteSetup):
	// the SMTP configuration that passed a test is still the current one
	// (its modification time equals the stamp), at least one internal IP
	// range and one internal domain exist and were saved by an
	// administrator since (network_reviewed_at, T-307: an import leaves it
	// NULL), and the legal notice and the
	// privacy policy exist with a non-blank content in the default language
	// of the tenant. Every subquery names the tenant explicitly (system
	// scope, which the row-level security policies let read every tenant).
	qTenantCompleteSetupGuarded = systemQuery(
		`UPDATE tenants SET setup_state = 'active', mail_templates_reviewed_at = COALESCE(?, mail_templates_reviewed_at),
			updated_at = ? WHERE id = ? AND status = 'active' AND setup_state = 'setup'
			AND smtp_tested_at = (SELECT updated_at FROM tenant_smtp_settings WHERE tenant_id = ?)
			AND network_reviewed_at IS NOT NULL
			AND EXISTS (SELECT 1 FROM tenant_network_rules WHERE tenant_id = ? AND kind = 'cidr')
			AND EXISTS (SELECT 1 FROM tenant_network_rules WHERE tenant_id = ? AND kind = 'domain')
			AND EXISTS (SELECT 1 FROM tenant_legal_documents WHERE tenant_id = ? AND document = 'legal-notice'
				AND language = tenants.default_language AND trim(content) <> '')
			AND EXISTS (SELECT 1 FROM tenant_legal_documents WHERE tenant_id = ? AND document = 'privacy-policy'
				AND language = tenants.default_language AND trim(content) <> '')`,
		reasonTenantSetup)
	qTenantSetStatus = systemQuery(
		`UPDATE tenants SET status = ?, updated_at = ? WHERE id = ?`,
		reasonTenantAdmin)
	qTenantListDeleting = systemQuery(
		`SELECT id FROM tenants WHERE status = 'deleting' ORDER BY id`,
		reasonTenantResume)
	qTenantKeyCount = systemQuery(
		`SELECT count(*) FROM wrapped_keys WHERE tenant_id = ?`,
		reasonTenantErase)
	qTenantDelete = systemQuery(
		`DELETE FROM tenants WHERE id = ?`,
		reasonTenantAdmin)
	qTenantSeedLevel = systemQuery(
		`INSERT INTO confidentiality_levels (tenant_id, key, position, labels, is_default,
			require_recipient_verification, require_password, allowed_validity_days, internal_recipients_only, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)`,
		reasonTenantSeed)
	qTenantSeedAbuse = systemQuery(
		`INSERT INTO tenant_abuse_settings (tenant_id, updated_at) VALUES (?, 0)`,
		reasonTenantSeed)
)

// seedLevel is a default confidentiality level of a tenant.
type seedLevel struct {
	key                   string
	position              int
	labels                string // JSON object by language
	isDefault             bool
	requireVerification   bool
	requirePassword       bool
	validityMask          int // 1 = 1 day, 2 = 7 days, 4 = 30 days
	internalRecipientOnly bool
}

// defaultConfidentialityLevels are the levels every tenant starts with:
// Tenants.Create seeds them, and migration 0016 seeded the same rows for
// the tenants that existed before it (keep both in sync; a test compares
// them). The default level is "internal" without any rule. The seeded rows
// have updated_at 0 and no updater: they were never edited.
var defaultConfidentialityLevels = []seedLevel{
	{key: "public", position: 0, labels: `{"fr":"Public","en":"Public"}`, validityMask: 7},
	{key: "internal", position: 1, labels: `{"fr":"Interne","en":"Internal"}`, isDefault: true, validityMask: 7},
	{
		key: "confidential", position: 2, labels: `{"fr":"Confidentiel","en":"Confidential"}`, //nolint:misspell // French label
		requireVerification: true, requirePassword: true, validityMask: 3, internalRecipientOnly: true,
	},
}

// seedTenant inserts the default configuration rows of the new tenant tid
// inside tx: its confidentiality levels and its abuse settings (every
// threshold disabled, the column defaults), as migrations 0016 and 0017 did
// for the existing tenants.
func seedTenant(ctx context.Context, tx *SystemTx, tid tenant.ID) error {
	for _, l := range defaultConfidentialityLevels {
		if _, err := tx.Exec(ctx, qTenantSeedLevel, string(tid), l.key, l.position, l.labels, l.isDefault,
			l.requireVerification, l.requirePassword, l.validityMask, l.internalRecipientOnly); err != nil {
			return err
		}
	}
	_, err := tx.Exec(ctx, qTenantSeedAbuse, string(tid))
	return err
}

// Tenants is the repository of tenants. Its operations are system-scoped:
// it serves the super admin and the Host resolution. Callers must check the
// caller's scope before using it. Obtain it with [DB.Tenants].
type Tenants struct {
	db *DB
}

// Tenants returns the tenant repository.
func (db *DB) Tenants() *Tenants { return &Tenants{db: db} }

// compile-time check: Tenants resolves hosts for tenant.Resolver.
var _ tenant.Lookup = (*Tenants)(nil)

// presetArg is the statement argument of a background preset: NULL (the
// default preset) for "".
func presetArg(preset string) any {
	if preset == "" {
		return nil
	}
	return preset
}

// scanTenant reads one row of tenantColumns.
func scanTenant(sc interface{ Scan(...any) error }) (*tenant.Tenant, error) {
	var (
		t                       tenant.Tenant
		tid, status, setup, e2e string
		created, updated        int64
		preset, provBy          sql.NullString
		tested, reviewed        sql.NullInt64
		networkReviewed         sql.NullInt64
	)
	if err := sc.Scan(&tid, &t.Name, &t.FQDN, &t.DefaultLanguage, &t.MaxTransferBytes, &t.MaxTransferCeiling,
		&t.StorageQuotaBytes, &status, &t.PrimaryColor, &t.AccentColor, &t.HasLogo, &t.HasBackground, &preset,
		&t.WebhookIncludeAddresses, &t.AllowRemoteInternalDeposit, &t.AllowTransferReply, &t.AntivirusEnabled,
		&setup, &tested, &reviewed, &networkReviewed, &created, &updated, &provBy, &t.LinkOnlyAllowed, &e2e); err != nil {
		return nil, err
	}
	t.BackgroundPreset = preset.String // NULL is the default preset, ""
	t.ProvisionedBy = provBy.String    // NULL for a tenant created by a super admin
	t.ID = tenant.ID(tid)
	t.Status = tenant.Status(status)
	t.SetupState = tenant.SetupState(setup)
	t.E2EPolicy = tenant.E2EPolicy(e2e)
	if tested.Valid {
		t.SMTPTestedAt = fromMillis(tested.Int64)
	}
	if reviewed.Valid {
		t.MailTemplatesReviewedAt = fromMillis(reviewed.Int64)
	}
	if networkReviewed.Valid {
		t.NetworkReviewedAt = fromMillis(networkReviewed.Int64)
	}
	t.CreatedAt = fromMillis(created)
	t.UpdatedAt = fromMillis(updated)
	return &t, nil
}

// Create validates t, assigns it a new ID and timestamps, and stores it,
// with its default configuration rows in the same transaction (the default
// confidentiality levels and abuse settings). Unset settings take their
// defaults ([tenant.Tenant.WithDefaults]): the ceiling is the transfer
// limit, the colors are the default ones and the status is active. The
// setup state has no default: t.SetupState must name one explicitly
// (T-261, P51), else ErrInvalid. A new tenant always starts with its
// antivirus enabled, whatever t.AntivirusEnabled
// ([Tenants.SetAntivirusEnabled] changes it), with no SMTP test and no
// review of its mail templates or of its network rules recorded. It stores
// t.LinkOnlyAllowed and t.E2EPolicy as given (false and
// [tenant.E2EForbidden] for the zero values): the caller checks that only a
// super admin sets them. It returns the stored tenant,
// ErrInvalid for invalid fields (including a preset ID, a status other
// than active, a missing or unknown setup state, a transfer limit above
// the ceiling, the ceiling being at most [tenant.MaxTransferLimit], or a
// background preset of invalid syntax) and ErrConflict when the FQDN is
// already used.
func (r *Tenants) Create(ctx context.Context, t *tenant.Tenant) (*tenant.Tenant, error) {
	return r.CreateWith(ctx, t, nil)
}

// CreateWith is Create, then runs then (when not nil) inside the same
// transaction with the stored tenant, so that rows depending on the new
// tenant (its first delegated admin and activation link) are committed with
// it or not at all. An error of then rolls everything back and is returned
// wrapped. then must not start another transaction; it may register
// [SystemTx.AfterCommit] hooks.
func (r *Tenants) CreateWith(ctx context.Context, t *tenant.Tenant, then func(tx *SystemTx, created *tenant.Tenant) error) (*tenant.Tenant, error) {
	if t.ProvisionedBy != "" {
		return nil, invalid("only a provisioned creation names its provisioning token")
	}
	return r.create(ctx, t, nil, then)
}

// create implements CreateWith and CreateProvisioned: before the insertion,
// inside the transaction, it runs guard when not nil (the checks of a
// provisioned creation under the provisioning lock).
func (r *Tenants) create(ctx context.Context, t *tenant.Tenant, guard func(tx *SystemTx) error,
	then func(tx *SystemTx, created *tenant.Tenant) error,
) (*tenant.Tenant, error) {
	if !t.ID.IsZero() {
		return nil, invalid("tenant id is assigned by the store")
	}
	c := t.WithDefaults()
	if c.E2EPolicy == "" {
		c.E2EPolicy = tenant.E2EForbidden
	}
	if c.Status != tenant.StatusActive {
		return nil, invalid("a new tenant is active")
	}
	if !c.SetupState.Valid() {
		// Never a fallback to the column default (T-261, P51).
		return nil, invalid("a new tenant needs an explicit setup state")
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	newID, err := r.db.newID(id.Tenant)
	if err != nil {
		return nil, wrap("create tenant", err)
	}
	c.ID = tenant.ID(newID)
	c.AntivirusEnabled = true
	c.SMTPTestedAt, c.MailTemplatesReviewedAt, c.NetworkReviewedAt = time.Time{}, time.Time{}, time.Time{}
	now := r.db.now().UTC().Truncate(time.Millisecond) // millisecond precision, as stored
	c.CreatedAt, c.UpdatedAt = now, now
	err = r.db.systemScope(reasonTenantAdmin).Tx(ctx, func(tx *SystemTx) error {
		if guard != nil {
			if err := guard(tx); err != nil {
				return err
			}
		}
		_, err := tx.Exec(ctx, qTenantInsert, string(c.ID), c.Name, c.FQDN, c.DefaultLanguage,
			c.MaxTransferBytes, c.MaxTransferCeiling, c.StorageQuotaBytes, string(c.Status),
			c.PrimaryColor, c.AccentColor, c.HasLogo, c.HasBackground, presetArg(c.BackgroundPreset), c.WebhookIncludeAddresses, c.AllowRemoteInternalDeposit,
			c.AllowTransferReply, c.AntivirusEnabled, string(c.SetupState), nil, nil, nil,
			toMillis(now), toMillis(now), nullText(c.ProvisionedBy), c.LinkOnlyAllowed, string(c.E2EPolicy))
		if err != nil {
			return err
		}
		if err := seedTenant(ctx, tx, c.ID); err != nil {
			return err
		}
		if then == nil {
			return nil
		}
		return then(tx, c)
	})
	if err != nil {
		return nil, wrap("create tenant", err)
	}
	return c, nil
}

// Get returns the tenant tid, whatever its status, or ErrNotFound.
func (r *Tenants) Get(ctx context.Context, tid tenant.ID) (*tenant.Tenant, error) {
	if err := tid.Validate(); err != nil {
		return nil, fmt.Errorf("store: get tenant: %w", ErrNotFound)
	}
	var t *tenant.Tenant
	err := r.db.systemScope(reasonTenantAdmin).ReadTx(ctx, func(tx *SystemTx) error {
		var err error
		t, err = scanTenant(tx.QueryRow(ctx, qTenantGet, string(tid)))
		return err
	})
	if err != nil {
		return nil, wrap("get tenant", err)
	}
	return t, nil
}

// TenantByFQDN returns the active tenant served by the normalized host name
// fqdn. It implements [tenant.Lookup]: an unknown host, or the host of a
// tenant being deleted ([tenant.StatusDeleting]), yields an error wrapping
// both tenant.ErrUnknownTenant and ErrNotFound.
func (r *Tenants) TenantByFQDN(ctx context.Context, fqdn string) (*tenant.Tenant, error) {
	var t *tenant.Tenant
	err := r.db.systemScope(reasonTenantResolve).ReadTx(ctx, func(tx *SystemTx) error {
		var err error
		t, err = scanTenant(tx.QueryRow(ctx, qTenantByFQDN, fqdn))
		return err
	})
	switch {
	case errors.Is(err, ErrNotFound):
		return nil, fmt.Errorf("%w: %w", tenant.ErrUnknownTenant, ErrNotFound)
	case err != nil:
		return nil, wrap("resolve tenant", err)
	}
	return t, nil
}

// TenantListOptions selects a page of tenants.
type TenantListOptions struct {
	// Cursor is the NextCursor of the previous page, or "" for the first.
	Cursor string
	// Limit is the page size (DefaultPageSize when <= 0, at most
	// MaxPageSize).
	Limit int
}

// List returns a page of tenants, whatever their status, ordered by ID, which is approximately
// creation order (IDs created in the same millisecond sort randomly). A
// malformed cursor yields ErrInvalid.
func (r *Tenants) List(ctx context.Context, opts TenantListOptions) (Page[*tenant.Tenant], error) {
	if opts.Cursor != "" && tenant.ID(opts.Cursor).Validate() != nil {
		return Page[*tenant.Tenant]{}, invalid("malformed cursor")
	}
	limit := pageLimit(opts.Limit)
	var items []*tenant.Tenant
	err := r.db.systemScope(reasonTenantAdmin).ReadTx(ctx, func(tx *SystemTx) error {
		rows, err := tx.Query(ctx, qTenantList, opts.Cursor, limit+1)
		if err != nil {
			return err
		}
		items, err = collect(rows, func(r *sql.Rows) (*tenant.Tenant, error) { return scanTenant(r) })
		return err
	})
	if err != nil {
		return Page[*tenant.Tenant]{}, wrap("list tenants", err)
	}
	return paginate(items, limit, func(t *tenant.Tenant) string { return string(t.ID) }), nil
}

// Update stores the modifiable fields of t (name, FQDN, language, limits,
// colors, asset flags, background preset (syntax checked by
// [tenant.Tenant.Validate]; "" is stored as NULL), webhook address option, remote internal deposit
// and reply options) and refreshes UpdatedAt. It never writes the setup
// state, which only [Tenants.CompleteSetup] changes, nor the SMTP test
// stamp and the review marks of the mail templates and network rules: t.SetupState must
// merely be valid. The status only changes with
// [Tenants.SetStatus] and the antivirus switch with
// [Tenants.UpdateWithAntivirus] or [Tenants.SetAntivirusEnabled]
// (t.AntivirusEnabled is ignored here), and the link-only switch with
// [Tenants.UpdateWithPolicies] or [Tenants.SetLinkOnlyAllowed]
// (t.LinkOnlyAllowed is ignored here), and the end-to-end encryption
// policy with [Tenants.UpdateWithPolicies] or [Tenants.SetE2EPolicy]
// (t.E2EPolicy is ignored here), so t.Status must merely be valid.
// The transfer limit must not exceed the ceiling, itself at most
// [tenant.MaxTransferLimit]; who may change which field is the caller's
// rule. It returns the stored tenant, ErrInvalid for invalid fields,
// ErrNotFound when the tenant does not exist or is being deleted, and
// ErrConflict when the new FQDN is already used. Callers must invalidate
// the tenant.Resolver cache for the old and new FQDN.
func (r *Tenants) Update(ctx context.Context, t *tenant.Tenant) (*tenant.Tenant, error) {
	return r.update(ctx, t, TenantParts{General: true}, "update tenant")
}

// TenantParts selects the parts of a tenant written by
// [Tenants.UpdateWithPolicies].
type TenantParts struct {
	// General writes the fields of [Tenants.Update].
	General bool
	// Antivirus writes t.AntivirusEnabled (super admin only).
	Antivirus bool
	// LinkOnly writes t.LinkOnlyAllowed (super admin only, since 2.0).
	LinkOnly bool
	// E2E writes t.E2EPolicy (super admin only, since 2.0), which must be a
	// valid [tenant.E2EPolicy].
	E2E bool
}

// UpdateWithPolicies writes the parts of t selected by parts in one
// transaction (a failure stores nothing) and refreshes UpdatedAt: the
// general fields as [Tenants.Update] does, and the super admin switches
// (antivirus, link-only transfers, end-to-end encryption policy) as
// [Tenants.SetAntivirusEnabled], [Tenants.SetLinkOnlyAllowed] and
// [Tenants.SetE2EPolicy] do. Callers check the caller's scope for
// each switch. It returns the stored tenant and the errors of
// [Tenants.Update]; selecting no part only reads the tenant back.
func (r *Tenants) UpdateWithPolicies(ctx context.Context, t *tenant.Tenant, parts TenantParts) (*tenant.Tenant, error) {
	return r.update(ctx, t, parts, "update tenant")
}

// UpdateWithAntivirus is [Tenants.Update] when general is set, and also
// stores t.AntivirusEnabled when antivirus is set, in one transaction: a
// failure stores nothing. The antivirus switch is the super admin's only
// (callers check the caller's scope); it applies to the transfers
// finalized afterwards (decision D8).
func (r *Tenants) UpdateWithAntivirus(ctx context.Context, t *tenant.Tenant, general, antivirus bool) (*tenant.Tenant, error) {
	return r.update(ctx, t, TenantParts{General: general, Antivirus: antivirus}, "update tenant")
}

// SetAntivirusEnabled turns the antivirus analysis of the active tenant
// tid on or off and refreshes UpdatedAt (super admin only: callers check
// the caller's scope). It applies to the transfers finalized afterwards
// (decision D8): files already waiting for the engine keep waiting, and
// turning it back on never rescans past files. It returns the stored
// tenant, and ErrNotFound when the tenant does not exist or is being
// deleted. Callers must invalidate the tenant.Resolver cache of its FQDN.
func (r *Tenants) SetAntivirusEnabled(ctx context.Context, tid tenant.ID, enabled bool) (*tenant.Tenant, error) {
	if err := tid.Validate(); err != nil {
		return nil, fmt.Errorf("store: set tenant antivirus: %w", ErrNotFound)
	}
	return r.update(ctx, &tenant.Tenant{ID: tid, AntivirusEnabled: enabled}, TenantParts{Antivirus: true}, "set tenant antivirus")
}

// SetLinkOnlyAllowed allows or forbids the link-only transfers of the
// active tenant tid (since 2.0) and refreshes UpdatedAt (super admin only:
// callers check the caller's scope). It applies to the transfers created
// afterwards. It returns the stored tenant, and ErrNotFound when the
// tenant does not exist or is being deleted. Callers must invalidate the
// tenant.Resolver cache of its FQDN.
func (r *Tenants) SetLinkOnlyAllowed(ctx context.Context, tid tenant.ID, allowed bool) (*tenant.Tenant, error) {
	if err := tid.Validate(); err != nil {
		return nil, fmt.Errorf("store: set tenant link-only: %w", ErrNotFound)
	}
	return r.update(ctx, &tenant.Tenant{ID: tid, LinkOnlyAllowed: allowed}, TenantParts{LinkOnly: true}, "set tenant link-only")
}

// SetE2EPolicy sets the end-to-end encryption policy of the active tenant
// tid (since 2.0, spec 22) and refreshes UpdatedAt (super admin only:
// callers check the caller's scope). It applies to the transfers created
// afterwards. It returns the stored tenant, ErrInvalid for an unknown
// policy, and ErrNotFound when the tenant does not exist or is being
// deleted. Callers must invalidate the tenant.Resolver cache of its FQDN.
func (r *Tenants) SetE2EPolicy(ctx context.Context, tid tenant.ID, policy tenant.E2EPolicy) (*tenant.Tenant, error) {
	if err := tid.Validate(); err != nil {
		return nil, fmt.Errorf("store: set tenant e2e policy: %w", ErrNotFound)
	}
	return r.update(ctx, &tenant.Tenant{ID: tid, E2EPolicy: policy}, TenantParts{E2E: true}, "set tenant e2e policy")
}

// update implements Update, UpdateWithAntivirus, UpdateWithPolicies,
// SetAntivirusEnabled, SetLinkOnlyAllowed and SetE2EPolicy: the parts of t
// selected by parts, in one transaction.
func (r *Tenants) update(ctx context.Context, t *tenant.Tenant, parts TenantParts, op string) (*tenant.Tenant, error) {
	if t.ID.IsZero() {
		return nil, invalid("tenant id is required")
	}
	if parts.General {
		if err := t.Validate(); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
		}
	}
	if parts.E2E && !t.E2EPolicy.Valid() {
		return nil, invalid("unknown end-to-end encryption policy")
	}
	now := toMillis(r.db.now())
	var out *tenant.Tenant
	err := r.db.systemScope(reasonTenantAdmin).Tx(ctx, func(tx *SystemTx) error {
		if parts.General {
			res, err := tx.Exec(ctx, qTenantUpdate, t.Name, t.FQDN, t.DefaultLanguage,
				t.MaxTransferBytes, t.MaxTransferCeiling, t.StorageQuotaBytes, t.PrimaryColor, t.AccentColor,
				t.HasLogo, t.HasBackground, presetArg(t.BackgroundPreset), t.WebhookIncludeAddresses, t.AllowRemoteInternalDeposit, t.AllowTransferReply, now,
				string(t.ID))
			if err == nil {
				err = expectOne(res)
			}
			if err != nil {
				return err
			}
		}
		if parts.Antivirus {
			res, err := tx.Exec(ctx, qTenantSetAntivirus, t.AntivirusEnabled, now, string(t.ID))
			if err == nil {
				err = expectOne(res)
			}
			if err != nil {
				return err
			}
		}
		if parts.LinkOnly {
			res, err := tx.Exec(ctx, qTenantSetLinkOnly, t.LinkOnlyAllowed, now, string(t.ID))
			if err == nil {
				err = expectOne(res)
			}
			if err != nil {
				return err
			}
		}
		if parts.E2E {
			res, err := tx.Exec(ctx, qTenantSetE2EPolicy, string(t.E2EPolicy), now, string(t.ID))
			if err == nil {
				err = expectOne(res)
			}
			if err != nil {
				return err
			}
		}
		var err error
		out, err = scanTenant(tx.QueryRow(ctx, qTenantGet, string(t.ID)))
		return err
	})
	if err != nil {
		return nil, wrap(op, err)
	}
	return out, nil
}

// SetStatus moves the tenant tid to status and refreshes UpdatedAt.
// [tenant.StatusDeleting] starts a deletion: the tenant stops resolving
// from its FQDN at once (callers also invalidate the tenant.Resolver
// cache), refuses [Tenants.Update], and [Tenants.ListDeleting] finds it
// again if the deletion is interrupted. It takes the tenant lock, so that a
// transfer creation in progress either commits first (and is erased with
// the tenant) or sees the new status and fails. It returns ErrInvalid for an
// unknown status and ErrNotFound when the tenant does not exist.
func (r *Tenants) SetStatus(ctx context.Context, tid tenant.ID, status tenant.Status) error {
	if !status.Valid() {
		return invalid("unknown tenant status")
	}
	err := r.db.systemScope(reasonTenantAdmin).Tx(ctx, func(tx *SystemTx) error {
		// Ordered with the transfer creations of the tenant, which check
		// under this lock that it is still active (Transfers.CreateTx).
		if err := tx.lockTenant(ctx, tid); err != nil {
			return err
		}
		res, err := tx.Exec(ctx, qTenantSetStatus, string(status), toMillis(r.db.now()), string(tid))
		if err != nil {
			return err
		}
		return expectOne(res)
	})
	if err != nil {
		return wrap("set tenant status", err)
	}
	return nil
}

// SetSMTPTested records that the SMTP configuration of the active tenant
// tid whose modification time is version ([SMTPConfig.UpdatedAt], read
// before the test) passed a test send. The setup checklist counts the SMTP
// item as done only while this stamp equals the modification time of the
// current settings: every change of the settings moves that time strictly
// forward in the statement that writes them ([SMTPSettings.PutTx]), so a
// change invalidates the stamp atomically, and a test of a configuration
// replaced meanwhile records a stamp that never matches. A zero version is
// ErrInvalid; it returns ErrNotFound when the tenant does not exist or is
// being deleted.
func (r *Tenants) SetSMTPTested(ctx context.Context, tid tenant.ID, version time.Time) error {
	if err := tid.Validate(); err != nil {
		return fmt.Errorf("store: set smtp tested: %w", ErrNotFound)
	}
	if version.IsZero() {
		return invalid("smtp configuration version is required")
	}
	err := r.db.systemScope(reasonTenantAdmin).Tx(ctx, func(tx *SystemTx) error {
		res, err := tx.Exec(ctx, qTenantSetSMTPTested, toMillis(version), string(tid))
		if err != nil {
			return err
		}
		return expectOne(res)
	})
	if err != nil {
		return wrap("set smtp tested", err)
	}
	return nil
}

// CompleteSetup moves the active tenant tid from [tenant.SetupStateSetup]
// to [tenant.SetupStateActive] (the only transition of the setup state) and
// refreshes UpdatedAt; a non-zero reviewedAt also records the review of the
// mail templates. Unless force is set, the statement itself requires the
// SMTP configuration that passed a test to be the current one (see
// [Tenants.SetSMTPTested]), at least one internal IP range and one internal
// domain saved by an administrator ([NetworkRules.ReplaceReviewed]: the
// rules written by a configuration import must be confirmed first,
// T-307), and a non-blank legal notice and privacy policy in the default
// language of the tenant: a change committed between the checks of the
// caller and this call makes it fail with ErrConflict, and the caller
// computes the checklist again. Only the absence of a "to complete" marker
// in the legal documents is checked by the caller alone, just before. It
// runs under the tenant lock, ordered with the SMTP and network rule
// changes. It returns the stored tenant, ErrSetupComplete when the tenant
// is already active, ErrConflict when a guard fails, and ErrNotFound when
// the tenant does not exist or is being deleted. Callers must invalidate
// the tenant.Resolver cache of its FQDN.
func (r *Tenants) CompleteSetup(ctx context.Context, tid tenant.ID, force bool, reviewedAt time.Time) (*tenant.Tenant, error) {
	if err := tid.Validate(); err != nil {
		return nil, fmt.Errorf("store: complete tenant setup: %w", ErrNotFound)
	}
	var reviewed any
	if !reviewedAt.IsZero() {
		reviewed = toMillis(reviewedAt)
	}
	now := toMillis(r.db.now())
	var out *tenant.Tenant
	err := r.db.systemScope(reasonTenantSetup).Tx(ctx, func(tx *SystemTx) error {
		if err := tx.lockTenant(ctx, tid); err != nil {
			return err
		}
		var (
			res sql.Result
			err error
		)
		if force {
			res, err = tx.Exec(ctx, qTenantCompleteSetup, reviewed, now, string(tid))
		} else {
			id := string(tid)
			res, err = tx.Exec(ctx, qTenantCompleteSetupGuarded, reviewed, now, id, id, id, id, id, id)
		}
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		out, err = scanTenant(tx.QueryRow(ctx, qTenantGet, string(tid)))
		switch {
		case err != nil:
			return err
		case out.Status != tenant.StatusActive:
			return ErrNotFound
		case n == 1:
			return nil
		case out.SetupState == tenant.SetupStateActive:
			return ErrSetupComplete
		}
		return ErrConflict
	})
	if err != nil {
		return nil, wrap("complete tenant setup", err)
	}
	return out, nil
}

// ListDeleting returns the IDs of the tenants in [tenant.StatusDeleting],
// sorted, so that the deletions interrupted by a stop resume at start-up
// or from the cleanup task. It returns identifiers only.
func (r *Tenants) ListDeleting(ctx context.Context) ([]tenant.ID, error) {
	var ids []tenant.ID
	err := r.db.systemScope(reasonTenantResume).ReadTx(ctx, func(tx *SystemTx) error {
		rows, err := tx.Query(ctx, qTenantListDeleting)
		if err != nil {
			return err
		}
		ids, err = collect(rows, func(r *sql.Rows) (tenant.ID, error) {
			var s string
			err := r.Scan(&s)
			return tenant.ID(s), err
		})
		return err
	})
	if err != nil {
		return nil, wrap("list deleting tenants", err)
	}
	return ids, nil
}

// Delete removes the tenant tid and, by cascade, every row it owns, then
// scrubs the database files ([DB.ScrubDeleted]). The cryptographic erasure
// comes first (spec 16.1, T-110): every wrapped key of the tenant (file
// keys, SMTP password, sealed tokens) must have been destroyed beforehand
// ([WrappedKeys.ListIDs], [WrappedKeys.Delete]); otherwise it returns
// [ErrKeysRemain] and deletes nothing. It returns ErrNotFound when the
// tenant does not exist. A scrub left incomplete by active readers
// (ErrScrubBusy) is logged as a warning, not returned; any other scrub
// failure is returned, the tenant being deleted. Erasing the tenant's
// files on disk is the caller's job.
func (r *Tenants) Delete(ctx context.Context, tid tenant.ID) error {
	err := r.db.systemScope(reasonTenantAdmin).Tx(ctx, func(tx *SystemTx) error {
		var keys int64
		if err := tx.QueryRow(ctx, qTenantKeyCount, string(tid)).Scan(&keys); err != nil {
			return err
		}
		if keys > 0 {
			return ErrKeysRemain
		}
		res, err := tx.Exec(ctx, qTenantDelete, string(tid))
		if err != nil {
			return err
		}
		return expectOne(res)
	})
	if err != nil {
		return wrap("delete tenant", err)
	}
	err = r.db.ScrubDeleted(ctx)
	if errors.Is(err, ErrScrubBusy) {
		r.db.logger.WarnContext(ctx, "deleted tenant data may remain in the database WAL until the next checkpoint",
			slog.String("tenant", string(tid)))
		return nil
	}
	return err
}

// expectOne returns ErrNotFound unless res reports at least one affected row.
func expectOne(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
