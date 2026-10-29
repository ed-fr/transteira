package tenantops

import (
	"context"
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
	listTransfers(ctx context.Context, tid tenant.ID, f store.AdminTransferFilter) (store.Page[store.AdminTransfer], error)
	getTransfer(ctx context.Context, tid tenant.ID, trfID string) (store.TransferDetails, error)
	listInvitations(ctx context.Context, tid tenant.ID, f store.InvitationFilter) (store.Page[store.Invitation], error)
	getInvitation(ctx context.Context, tid tenant.ID, invID string) (store.Invitation, error)
	revokeInvitation(ctx context.Context, tid tenant.ID, invID string, now time.Time) error
	listBlocklist(ctx context.Context, tid tenant.ID, f store.BlocklistFilter) (store.Page[store.BlocklistEntry], error)
	getBlocklistEntry(ctx context.Context, tid tenant.ID, entryID string) (store.BlocklistEntry, error)
	createBlocklistEntry(ctx context.Context, tid tenant.ID, e store.BlocklistEntry) (store.BlocklistEntry, error)
	deleteBlocklistEntry(ctx context.Context, tid tenant.ID, entryID string) error
	listAbuseReports(ctx context.Context, tid tenant.ID, status store.AbuseReportStatus, limit int, cursor string) (store.Page[store.AbuseReport], error)
	getAbuseReport(ctx context.Context, tid tenant.ID, repID string) (store.AbuseReport, error)
	setAbuseReportStatus(ctx context.Context, tid tenant.ID, repID string, status store.AbuseReportStatus, by string, note *string, now time.Time) (store.AbuseReport, bool, error)
	listAudit(ctx context.Context, f store.AuditFilter) (store.Page[store.AuditEvent], error)
	recipientLinks(ctx context.Context, tid tenant.ID, trfID string) ([]store.RecipientLink, error)
	tracking(ctx context.Context, tid tenant.ID, trfID string) ([]store.RecipientTracking, error)
	openSecret(ctx context.Context, tid tenant.ID, wkID string) ([]byte, error)
	audit(ctx context.Context, tid tenant.ID, ev audit.Event) error
}

// Vault opens the secrets of a tenant (*masterkey.Vault): here the sealed
// download token of a transfer, or of each recipient link.
type Vault interface {
	// Open unwraps the wrapped key wkID of tenant tid.
	Open(ctx context.Context, tid tenant.ID, p crypto.Purpose, wkID string) ([]byte, error)
}

// storeRepo implements repo with the store.
type storeRepo struct {
	db     *store.DB
	vault  Vault
	writer *audit.Writer
}

// newStoreRepo returns the store implementation of repo, recording with
// writer (a writer of its own when nil).
func newStoreRepo(db *store.DB, vault Vault, writer *audit.Writer) *storeRepo {
	return &storeRepo{db: db, vault: vault, writer: audit.OrNew(writer, db)}
}

func (r *storeRepo) getTenant(ctx context.Context, tid tenant.ID) (*tenant.Tenant, error) {
	return r.db.Tenants().Get(ctx, tid)
}

func (r *storeRepo) listTransfers(ctx context.Context, tid tenant.ID, f store.AdminTransferFilter) (store.Page[store.AdminTransfer], error) {
	return r.db.Transfers().AdminList(ctx, tid, f)
}

func (r *storeRepo) getTransfer(ctx context.Context, tid tenant.ID, trfID string) (store.TransferDetails, error) {
	return r.db.Transfers().Get(ctx, tid, trfID)
}

func (r *storeRepo) listInvitations(ctx context.Context, tid tenant.ID, f store.InvitationFilter) (store.Page[store.Invitation], error) {
	return r.db.Invitations().List(ctx, tid, f)
}

func (r *storeRepo) getInvitation(ctx context.Context, tid tenant.ID, invID string) (store.Invitation, error) {
	return r.db.Invitations().Get(ctx, tid, invID)
}

func (r *storeRepo) revokeInvitation(ctx context.Context, tid tenant.ID, invID string, now time.Time) error {
	return r.db.Invitations().Revoke(ctx, tid, invID, now)
}

func (r *storeRepo) listBlocklist(ctx context.Context, tid tenant.ID, f store.BlocklistFilter) (store.Page[store.BlocklistEntry], error) {
	return r.db.Blocklist().List(ctx, tid, f)
}

func (r *storeRepo) getBlocklistEntry(ctx context.Context, tid tenant.ID, entryID string) (store.BlocklistEntry, error) {
	return r.db.Blocklist().Get(ctx, tid, entryID)
}

func (r *storeRepo) createBlocklistEntry(ctx context.Context, tid tenant.ID, e store.BlocklistEntry) (store.BlocklistEntry, error) {
	return r.db.Blocklist().Create(ctx, tid, e)
}

func (r *storeRepo) deleteBlocklistEntry(ctx context.Context, tid tenant.ID, entryID string) error {
	return r.db.Blocklist().Delete(ctx, tid, entryID)
}

func (r *storeRepo) listAudit(ctx context.Context, f store.AuditFilter) (store.Page[store.AuditEvent], error) {
	return r.db.AuditEvents().List(ctx, f)
}

func (r *storeRepo) recipientLinks(ctx context.Context, tid tenant.ID, trfID string) ([]store.RecipientLink, error) {
	return r.db.RecipientLinks().ListByTransfer(ctx, tid, trfID)
}

func (r *storeRepo) tracking(ctx context.Context, tid tenant.ID, trfID string) ([]store.RecipientTracking, error) {
	return r.db.RecipientLinks().TrackingByTransfer(ctx, tid, trfID)
}

func (r *storeRepo) openSecret(ctx context.Context, tid tenant.ID, wkID string) ([]byte, error) {
	return r.vault.Open(ctx, tid, crypto.PurposeSecret, wkID)
}

func (r *storeRepo) audit(ctx context.Context, tid tenant.ID, ev audit.Event) error {
	return r.writer.RecordScoped(ctx, tid, ev)
}

func (r *storeRepo) listAbuseReports(ctx context.Context, tid tenant.ID, status store.AbuseReportStatus, limit int, cursor string) (store.Page[store.AbuseReport], error) {
	return r.db.AbuseReports().List(ctx, tid, status, limit, cursor)
}

func (r *storeRepo) getAbuseReport(ctx context.Context, tid tenant.ID, repID string) (store.AbuseReport, error) {
	return r.db.AbuseReports().Get(ctx, tid, repID)
}

func (r *storeRepo) setAbuseReportStatus(ctx context.Context, tid tenant.ID, repID string, status store.AbuseReportStatus, by string, note *string, now time.Time) (store.AbuseReport, bool, error) {
	return r.db.AbuseReports().SetStatus(ctx, tid, repID, status, by, note, now)
}
