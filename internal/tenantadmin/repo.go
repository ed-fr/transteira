package tenantadmin

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// repo is the persistence used by the service: the store repositories
// behind one interface, so that the tests can inject failures.
type repo interface {
	getTenant(ctx context.Context, tid tenant.ID) (*tenant.Tenant, error)
	listTenants(ctx context.Context, opts store.TenantListOptions) (store.Page[*tenant.Tenant], error)
	createTenant(ctx context.Context, t *tenant.Tenant, then func(tx *store.SystemTx, t *tenant.Tenant) error) (*tenant.Tenant, error)
	createProvisionedTenant(ctx context.Context, tokID string, t *tenant.Tenant, then func(tx *store.SystemTx, t *tenant.Tenant) error) (*tenant.Tenant, error)
	provisioningToken(ctx context.Context, tokID string) (store.ProvisioningToken, error)
	updateTenant(ctx context.Context, t *tenant.Tenant) (*tenant.Tenant, error)
	setTenantStatus(ctx context.Context, tid tenant.ID, status tenant.Status) error
	setSMTPTested(ctx context.Context, tid tenant.ID, version time.Time) error
	completeSetup(ctx context.Context, tid tenant.ID, force bool, reviewedAt time.Time) (*tenant.Tenant, error)
	// updateTenantParts writes the parts of t selected by parts in one
	// transaction (store.Tenants.UpdateWithPolicies).
	updateTenantParts(ctx context.Context, t *tenant.Tenant, parts store.TenantParts) (*tenant.Tenant, error)
	setSecretSettings(ctx context.Context, tid tenant.ID, s tenant.SecretSettings) (*tenant.Tenant, error)
	usedBytes(ctx context.Context, tid tenant.ID) (int64, error)
	networkRules(ctx context.Context, tid tenant.ID) (store.NetworkRuleSet, error)
	// replaceNetworkRules also records the review of the rules
	// (store.NetworkRules.ReplaceReviewed, T-307).
	replaceNetworkRules(ctx context.Context, tid tenant.ID, cidrs []netip.Prefix, domains []string) (store.NetworkRuleSet, error)
	confidentialityLevels(ctx context.Context, tid tenant.ID) ([]store.ConfidentialityLevel, error)
	replaceConfidentialityLevels(ctx context.Context, tid tenant.ID, levels []store.ConfidentialityLevel, by string, now time.Time) ([]store.ConfidentialityLevel, error)
	recipientRules(ctx context.Context, tid tenant.ID) (store.RecipientRuleSet, error)
	replaceRecipientRules(ctx context.Context, tid tenant.ID, set store.RecipientRuleSet, now time.Time) (store.RecipientRuleSet, error)
	abuseSettings(ctx context.Context, tid tenant.ID) (store.AbuseSettings, error)
	putAbuseSettings(ctx context.Context, tid tenant.ID, s store.AbuseSettings) (store.AbuseSettings, error)
	smtp(ctx context.Context, tid tenant.ID) (store.SMTPConfig, error)
	putSMTP(ctx context.Context, tid tenant.ID, c store.SMTPConfig, update passwordUpdate) error
	openSecret(ctx context.Context, tid tenant.ID, wkID string) ([]byte, error)
	template(ctx context.Context, tid tenant.ID, key, lang string) (store.EmailTemplate, error)
	listTemplates(ctx context.Context, tid tenant.ID) ([]store.EmailTemplateSummary, error)
	putTemplate(ctx context.Context, tid tenant.ID, t store.EmailTemplate) (store.EmailTemplate, error)
	deleteTemplate(ctx context.Context, tid tenant.ID, key, lang string) error
	legal(ctx context.Context, tid tenant.ID, doc, lang string) (store.LegalDocument, error)
	putLegal(ctx context.Context, tid tenant.ID, d store.LegalDocument) (store.LegalDocument, error)
	deleteLegal(ctx context.Context, tid tenant.ID, doc, lang string) error
	listLegal(ctx context.Context, tid tenant.ID) ([]store.LegalDocumentKey, error)
	audit(ctx context.Context, ev audit.Event) error

	// Reads of the configuration export (since V2).
	listWebhooks(ctx context.Context, tid tenant.ID) ([]store.Webhook, error)
	listBlocklist(ctx context.Context, tid tenant.ID, cursor string) (store.Page[store.BlocklistEntry], error)

	// Writes of the configuration import, inside the transaction creating
	// the tenant, under its scope (since V2).
	replaceNetworkRulesTx(ctx context.Context, tx *store.ScopedTx, cidrs []netip.Prefix, domains []string) error
	replaceRecipientRulesTx(ctx context.Context, tx *store.ScopedTx, set store.RecipientRuleSet, now time.Time) error
	replaceConfidentialityLevelsTx(ctx context.Context, tx *store.ScopedTx, levels []store.ConfidentialityLevel, by string, now time.Time) error
	putAbuseSettingsTx(ctx context.Context, tx *store.ScopedTx, s store.AbuseSettings) error
	putSMTPConfigTx(ctx context.Context, tx *store.ScopedTx, c store.SMTPConfig) error
	putTemplateTx(ctx context.Context, tx *store.ScopedTx, t store.EmailTemplate) error
	putLegalTx(ctx context.Context, tx *store.ScopedTx, d store.LegalDocument) error
	createBlocklistEntryTx(ctx context.Context, tx *store.ScopedTx, e store.BlocklistEntry) error
}

// errPasswordRequired reports, from [repo.putSMTP], a stored password kept
// while the host, port or username of the stored settings changes.
var errPasswordRequired = errors.New("tenantadmin: smtp password required for new server or username")

// passwordUpdate tells what [repo.putSMTP] does with the SMTP password.
type passwordUpdate struct {
	// keep keeps the stored password. Otherwise the stored one is
	// destroyed and replaced by password, or by none when password is nil.
	keep     bool
	password []byte
}

// Vault seals and opens the secrets of a tenant (*masterkey.Vault).
type Vault interface {
	// SealTx wraps plaintext for purpose p, stores it inside tx for the
	// tenant tx is bound to and returns its wrapped key ID.
	SealTx(ctx context.Context, tx *store.ScopedTx, p crypto.Purpose, plaintext []byte) (string, error)
	// Open unwraps the wrapped key wkID of tenant tid.
	Open(ctx context.Context, tid tenant.ID, p crypto.Purpose, wkID string) ([]byte, error)
}

// storeRepo implements repo with the store. The steps of the SMTP
// transaction are function fields so that the tests can make each one fail.
type storeRepo struct {
	db     *store.DB
	vault  Vault
	writer *audit.Writer

	sealTx      func(ctx context.Context, tx *store.ScopedTx, password []byte) (string, error)
	getSMTPTx   func(ctx context.Context, tx *store.ScopedTx) (store.SMTPConfig, error)
	putSMTPTx   func(ctx context.Context, tx *store.ScopedTx, c store.SMTPConfig) error
	deleteKeyTx func(ctx context.Context, tx *store.ScopedTx, wkID string) error
	usedTx      func(ctx context.Context, tx *store.ScopedTx) (int64, error)
}

// newStoreRepo returns the store implementation of repo, recording with
// writer (a writer of its own when nil).
func newStoreRepo(db *store.DB, vault Vault, writer *audit.Writer) *storeRepo {
	r := &storeRepo{db: db, vault: vault, writer: audit.OrNew(writer, db)}
	r.sealTx = func(ctx context.Context, tx *store.ScopedTx, password []byte) (string, error) {
		return r.vault.SealTx(ctx, tx, crypto.PurposeSecret, password)
	}
	r.getSMTPTx = db.SMTPSettings().GetTx
	r.putSMTPTx = db.SMTPSettings().PutTx
	r.deleteKeyTx = db.WrappedKeys().DeleteTx
	r.usedTx = db.Transfers().UsedBytesTx
	return r
}

func (r *storeRepo) getTenant(ctx context.Context, tid tenant.ID) (*tenant.Tenant, error) {
	return r.db.Tenants().Get(ctx, tid)
}

func (r *storeRepo) listTenants(ctx context.Context, opts store.TenantListOptions) (store.Page[*tenant.Tenant], error) {
	return r.db.Tenants().List(ctx, opts)
}

func (r *storeRepo) createTenant(ctx context.Context, t *tenant.Tenant, then func(tx *store.SystemTx, t *tenant.Tenant) error) (*tenant.Tenant, error) {
	return r.db.Tenants().CreateWith(ctx, t, then)
}

func (r *storeRepo) createProvisionedTenant(ctx context.Context, tokID string, t *tenant.Tenant, then func(tx *store.SystemTx, t *tenant.Tenant) error) (*tenant.Tenant, error) {
	return r.db.Tenants().CreateProvisioned(ctx, tokID, t, then)
}

func (r *storeRepo) provisioningToken(ctx context.Context, tokID string) (store.ProvisioningToken, error) {
	return r.db.ProvisioningTokens().Get(ctx, tokID)
}

func (r *storeRepo) updateTenant(ctx context.Context, t *tenant.Tenant) (*tenant.Tenant, error) {
	return r.db.Tenants().Update(ctx, t)
}

func (r *storeRepo) updateTenantParts(ctx context.Context, t *tenant.Tenant, parts store.TenantParts) (*tenant.Tenant, error) {
	return r.db.Tenants().UpdateWithPolicies(ctx, t, parts)
}

func (r *storeRepo) setSecretSettings(ctx context.Context, tid tenant.ID, s tenant.SecretSettings) (*tenant.Tenant, error) {
	return r.db.Tenants().SetSecretSettings(ctx, tid, s)
}

func (r *storeRepo) setTenantStatus(ctx context.Context, tid tenant.ID, status tenant.Status) error {
	return r.db.Tenants().SetStatus(ctx, tid, status)
}

func (r *storeRepo) setSMTPTested(ctx context.Context, tid tenant.ID, version time.Time) error {
	return r.db.Tenants().SetSMTPTested(ctx, tid, version)
}

func (r *storeRepo) completeSetup(ctx context.Context, tid tenant.ID, force bool, reviewedAt time.Time) (*tenant.Tenant, error) {
	return r.db.Tenants().CompleteSetup(ctx, tid, force, reviewedAt)
}

// usedBytes returns the storage used by tenant tid (spec 8.5).
func (r *storeRepo) usedBytes(ctx context.Context, tid tenant.ID) (int64, error) {
	sc, err := r.db.Scoped(tid)
	if err != nil {
		return 0, err
	}
	var n int64
	err = sc.ReadTx(ctx, func(tx *store.ScopedTx) error {
		var err error
		n, err = r.usedTx(ctx, tx)
		return err
	})
	return n, err
}

func (r *storeRepo) networkRules(ctx context.Context, tid tenant.ID) (store.NetworkRuleSet, error) {
	return r.db.NetworkRules().Get(ctx, tid)
}

func (r *storeRepo) replaceNetworkRules(ctx context.Context, tid tenant.ID, cidrs []netip.Prefix, domains []string) (store.NetworkRuleSet, error) {
	return r.db.NetworkRules().ReplaceReviewed(ctx, tid, cidrs, domains)
}

func (r *storeRepo) smtp(ctx context.Context, tid tenant.ID) (store.SMTPConfig, error) {
	return r.db.SMTPSettings().Get(ctx, tid)
}

// putSMTP stores c in one transaction with the new password secret, and
// destroys the previous secret when it is replaced or removed, so that a
// replaced password cannot be read from a backup (spec 16.1). Keeping a
// stored password is refused with errPasswordRequired when the host, port
// or username differs from the row read inside the transaction, so that a
// concurrent change cannot send the password to another server.
func (r *storeRepo) putSMTP(ctx context.Context, tid tenant.ID, c store.SMTPConfig, update passwordUpdate) error {
	sc, err := r.db.Scoped(tid)
	if err != nil {
		return err
	}
	return sc.Tx(ctx, func(tx *store.ScopedTx) error {
		old, err := r.getSMTPTx(ctx, tx)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		if update.keep && old.PasswordKeyID != "" &&
			(old.Host != c.Host || old.Port != c.Port || old.Username != c.Username) {
			return errPasswordRequired
		}
		c.PasswordKeyID = old.PasswordKeyID
		if !update.keep {
			c.PasswordKeyID = ""
			if update.password != nil {
				if c.PasswordKeyID, err = r.sealTx(ctx, tx, update.password); err != nil {
					return err
				}
			}
		}
		if err := r.putSMTPTx(ctx, tx, c); err != nil {
			return err
		}
		if old.PasswordKeyID != "" && old.PasswordKeyID != c.PasswordKeyID {
			return r.deleteKeyTx(ctx, tx, old.PasswordKeyID)
		}
		return nil
	})
}

func (r *storeRepo) openSecret(ctx context.Context, tid tenant.ID, wkID string) ([]byte, error) {
	return r.vault.Open(ctx, tid, crypto.PurposeSecret, wkID)
}

func (r *storeRepo) template(ctx context.Context, tid tenant.ID, key, lang string) (store.EmailTemplate, error) {
	return r.db.TenantEmailTemplates().Get(ctx, tid, key, lang)
}

func (r *storeRepo) listTemplates(ctx context.Context, tid tenant.ID) ([]store.EmailTemplateSummary, error) {
	return r.db.TenantEmailTemplates().List(ctx, tid)
}

func (r *storeRepo) putTemplate(ctx context.Context, tid tenant.ID, t store.EmailTemplate) (store.EmailTemplate, error) {
	return r.db.TenantEmailTemplates().Put(ctx, tid, t)
}

func (r *storeRepo) deleteTemplate(ctx context.Context, tid tenant.ID, key, lang string) error {
	return r.db.TenantEmailTemplates().Delete(ctx, tid, key, lang)
}

func (r *storeRepo) legal(ctx context.Context, tid tenant.ID, doc, lang string) (store.LegalDocument, error) {
	return r.db.TenantLegalDocuments().Get(ctx, tid, doc, lang)
}

func (r *storeRepo) putLegal(ctx context.Context, tid tenant.ID, d store.LegalDocument) (store.LegalDocument, error) {
	return r.db.TenantLegalDocuments().Put(ctx, tid, d)
}

func (r *storeRepo) deleteLegal(ctx context.Context, tid tenant.ID, doc, lang string) error {
	return r.db.TenantLegalDocuments().Delete(ctx, tid, doc, lang)
}

func (r *storeRepo) listLegal(ctx context.Context, tid tenant.ID) ([]store.LegalDocumentKey, error) {
	return r.db.TenantLegalDocuments().List(ctx, tid)
}

func (r *storeRepo) audit(ctx context.Context, ev audit.Event) error { return r.writer.Record(ctx, ev) }

func (r *storeRepo) confidentialityLevels(ctx context.Context, tid tenant.ID) ([]store.ConfidentialityLevel, error) {
	return r.db.ConfidentialityLevels().List(ctx, tid)
}

func (r *storeRepo) replaceConfidentialityLevels(ctx context.Context, tid tenant.ID, levels []store.ConfidentialityLevel, by string, now time.Time) ([]store.ConfidentialityLevel, error) {
	return r.db.ConfidentialityLevels().Replace(ctx, tid, levels, by, now)
}

func (r *storeRepo) recipientRules(ctx context.Context, tid tenant.ID) (store.RecipientRuleSet, error) {
	return r.db.RecipientRules().Get(ctx, tid)
}

func (r *storeRepo) replaceRecipientRules(ctx context.Context, tid tenant.ID, set store.RecipientRuleSet, now time.Time) (store.RecipientRuleSet, error) {
	return r.db.RecipientRules().Replace(ctx, tid, set, now)
}

func (r *storeRepo) abuseSettings(ctx context.Context, tid tenant.ID) (store.AbuseSettings, error) {
	return r.db.AbuseSettings().Get(ctx, tid)
}

func (r *storeRepo) putAbuseSettings(ctx context.Context, tid tenant.ID, s store.AbuseSettings) (store.AbuseSettings, error) {
	return r.db.AbuseSettings().Put(ctx, tid, s)
}

func (r *storeRepo) listWebhooks(ctx context.Context, tid tenant.ID) ([]store.Webhook, error) {
	return r.db.Webhooks().List(ctx, tid)
}

func (r *storeRepo) listBlocklist(ctx context.Context, tid tenant.ID, cursor string) (store.Page[store.BlocklistEntry], error) {
	return r.db.Blocklist().List(ctx, tid, store.BlocklistFilter{Cursor: cursor, Limit: store.MaxPageSize})
}

func (r *storeRepo) replaceNetworkRulesTx(ctx context.Context, tx *store.ScopedTx, cidrs []netip.Prefix, domains []string) error {
	_, err := r.db.NetworkRules().ReplaceTx(ctx, tx, cidrs, domains)
	return err
}

func (r *storeRepo) replaceRecipientRulesTx(ctx context.Context, tx *store.ScopedTx, set store.RecipientRuleSet, now time.Time) error {
	_, err := r.db.RecipientRules().ReplaceTx(ctx, tx, set, now)
	return err
}

func (r *storeRepo) replaceConfidentialityLevelsTx(ctx context.Context, tx *store.ScopedTx, levels []store.ConfidentialityLevel, by string, now time.Time) error {
	_, err := r.db.ConfidentialityLevels().ReplaceTx(ctx, tx, levels, by, now)
	return err
}

func (r *storeRepo) putAbuseSettingsTx(ctx context.Context, tx *store.ScopedTx, s store.AbuseSettings) error {
	_, err := r.db.AbuseSettings().PutTx(ctx, tx, s)
	return err
}

func (r *storeRepo) putSMTPConfigTx(ctx context.Context, tx *store.ScopedTx, c store.SMTPConfig) error {
	return r.db.SMTPSettings().PutTx(ctx, tx, c)
}

func (r *storeRepo) putTemplateTx(ctx context.Context, tx *store.ScopedTx, t store.EmailTemplate) error {
	_, err := r.db.TenantEmailTemplates().PutTx(ctx, tx, t)
	return err
}

func (r *storeRepo) putLegalTx(ctx context.Context, tx *store.ScopedTx, d store.LegalDocument) error {
	_, err := r.db.TenantLegalDocuments().PutTx(ctx, tx, d)
	return err
}

func (r *storeRepo) createBlocklistEntryTx(ctx context.Context, tx *store.ScopedTx, e store.BlocklistEntry) error {
	_, err := r.db.Blocklist().CreateTx(ctx, tx, e)
	return err
}
