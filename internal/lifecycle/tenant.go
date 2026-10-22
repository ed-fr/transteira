package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Audit log of the tenant erasure.
const (
	// SystemActor is the actor (store.ActorSystem) of the audit events
	// recorded by the sweeper.
	SystemActor = "lifecycle"
	// ActionTenantDeleted is recorded once per tenant, by the erasure that
	// deletes its row (OpenAPI AuditAction tenant.deleted), whether it was
	// started by the super admin or resumed by TaskTenantDeletions.
	ActionTenantDeleted audit.Action = "tenant.deleted"
	// objectTenant is the object kind of ActionTenantDeleted.
	objectTenant = "tenant"
)

// liveStatuses are the statuses of the transfers that did not end. They are
// bounded by the tenant's quota and listed at once; the ended transfers are
// walked page after page ([store.Transfers.ListEnded]).
var liveStatuses = []store.TransferStatus{store.TransferUploading, store.TransferScanning, store.TransferAvailable}

// endOfTime is the endedBefore bound that lists every ended transfer.
var endOfTime = time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC)

// EraseTenant erases the tenant tid, whose deletion was started with
// store.Tenants.SetStatus(tenant.StatusDeleting), in this order (CLAUDE.md
// sections 16.1 and 20, T-110):
//
//  1. every transfer of the tenant, whatever its status, goes through the
//     erasure path of the cleanup task (file keys destroyed, then the files,
//     checkpoints and download state removed, then the sealed download token
//     destroyed), and its row is deleted;
//  2. every wrapped key left to the tenant (SMTP password, any other) is
//     destroyed;
//  3. the tenant's directory is removed from the data volume, with
//     everything left in it (branding assets included);
//  4. the tenant row is deleted ([store.Tenants.Delete]), which cascades to
//     every row it still owns; the audit events stay until their purge;
//  5. the directory is removed again (a request that resolved the tenant
//     before its deletion started may have recreated it; a failure is
//     logged), then ActionTenantDeleted is recorded by SystemActor with
//     the tenant's name and FQDN, read before the row was deleted, by the
//     run that deleted the row only (exactly once per tenant; an audit
//     failure is logged and does not undo the erasure);
//  6. the database is scrubbed.
//
// It runs after the task in progress and never overlaps a task. Every step
// is idempotent: a failure returns an error, and the next call (or
// TaskTenantDeletions) resumes; a tenant already gone yields nil. It
// returns ErrTenantNotDeleting, and touches nothing, for an existing tenant
// whose deletion was not started, and ctx.Err() when ctx is done. Logs hold
// identifiers and counts only.
func (s *Sweeper) EraseTenant(ctx context.Context, tid tenant.ID) error {
	s.runMu.Lock()
	defer s.runMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.eraseTenant(ctx, tid)
}

// tenantDeletions is TaskTenantDeletions: it erases every tenant left in
// tenant.StatusDeleting, so that a deletion interrupted by a failure or a
// crash completes. A failure is logged and the next tenant goes on; the
// failures are returned joined.
func (s *Sweeper) tenantDeletions(ctx context.Context) error {
	tids, err := s.repo.deletingTenants(ctx)
	if err != nil {
		return fmt.Errorf("lifecycle: list the tenants being deleted: %w", err)
	}
	var errs []error
	for _, tid := range tids {
		if err := s.eraseTenant(ctx, tid); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			s.logger.WarnContext(ctx, "lifecycle: tenant erasure left for the next run",
				slog.String("tenant", string(tid)), slog.Any("error", err))
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// eraseTenant implements EraseTenant, under the run mutex.
func (s *Sweeper) eraseTenant(ctx context.Context, tid tenant.ID) error {
	t, err := s.repo.getTenant(ctx, tid)
	switch {
	case errors.Is(err, store.ErrNotFound):
		// Already deleted, or never existed: the steps below find nothing,
		// or complete what an earlier run left (a directory, a scrub).
		t = nil
	case err != nil:
		return fmt.Errorf("lifecycle: erase tenant %s: read the tenant: %w", tid, err)
	case t.Status != tenant.StatusDeleting:
		return fmt.Errorf("%w: tenant %s", ErrTenantNotDeleting, tid)
	}
	// The keys destroyed by a failed run are scrubbed as well.
	defer s.scrub(context.WithoutCancel(ctx))
	transfers, err := s.eraseTenantTransfers(ctx, tid)
	if err != nil {
		return fmt.Errorf("lifecycle: erase tenant %s: transfers: %w", tid, err)
	}
	keys, err := s.destroyTenantKeys(ctx, tid)
	if err != nil {
		return fmt.Errorf("lifecycle: erase tenant %s: keys: %w", tid, err)
	}
	if err := s.files.RemoveTenantDir(tid); err != nil {
		return fmt.Errorf("lifecycle: erase tenant %s: directory: %w", tid, err)
	}
	err = s.repo.deleteTenant(ctx, tid)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("lifecycle: erase tenant %s: row: %w", tid, err)
	}
	deleted := err == nil && t != nil
	// A request that resolved the tenant before its deletion started may
	// have recreated the directory meanwhile (an upload of a transfer
	// erased above); no new transfer can appear (store.Transfers.CreateTx
	// requires an active tenant), so this second pass leaves nothing. A
	// failure is only logged: the rows are gone, and TaskOrphans reports a
	// directory left without tenant.
	if err := s.files.RemoveTenantDir(tid); err != nil {
		s.logger.WarnContext(ctx, "lifecycle: tenant directory left after the erasure",
			slog.String("tenant", string(tid)), slog.Any("error", err))
	}
	if deleted {
		s.recordTenantDeleted(ctx, t)
	}
	s.logger.InfoContext(ctx, "lifecycle: tenant erased", slog.String("tenant", string(tid)),
		slog.Int("transfers", transfers), slog.Int("keys", keys))
	return nil
}

// recordTenantDeleted records ActionTenantDeleted for t, whose row this run
// deleted, with the name and FQDN read before. A failure is logged and does
// not undo the erasure.
func (s *Sweeper) recordTenantDeleted(ctx context.Context, t *tenant.Tenant) {
	ev := audit.Event{
		TenantID: t.ID, ActorKind: store.ActorSystem, Actor: SystemActor, Action: ActionTenantDeleted,
		ObjectKind: objectTenant, ObjectID: string(t.ID),
		Details: map[string]any{"name": audit.RedactAddresses(t.Name), "fqdn": t.FQDN},
	}
	if err := s.repo.audit(ctx, ev); err != nil {
		s.logger.ErrorContext(ctx, "lifecycle: audit write failed", slog.String("action", string(ActionTenantDeleted)),
			slog.String("tenant", string(t.ID)), slog.Any("error", err))
	}
}

// eraseTenantTransfers erases every transfer of tid with kindTenant: the
// live ones, then the ended ones page after page (each erasure deletes the
// row, so the next page starts over). It returns how many it erased, and an
// error when a transfer is left for the next run.
func (s *Sweeper) eraseTenantTransfers(ctx context.Context, tid tenant.ID) (int, error) {
	now := s.now()
	var done, left int
	eraseAll := func(ids []string) error {
		for _, trfID := range ids {
			if err := ctx.Err(); err != nil {
				return err
			}
			switch s.erase(ctx, kindTenant, store.TenantTransfer{TenantID: tid, TransferID: trfID}, now) {
			case erased:
				done++
			case failed:
				left++
			}
		}
		if left > 0 {
			return fmt.Errorf("%d transfer(s) left for the next run", left)
		}
		return nil
	}
	ids, err := s.repo.transferIDs(ctx, tid, liveStatuses...)
	if err != nil {
		return done, fmt.Errorf("list the transfers: %w", err)
	}
	if err := eraseAll(ids); err != nil {
		return done, err
	}
	for {
		ids, err := s.repo.listEnded(ctx, tid, endOfTime, s.purgeBatch)
		if err != nil {
			return done, fmt.Errorf("list the ended transfers: %w", err)
		}
		if err := eraseAll(ids); err != nil {
			return done, err
		}
		if len(ids) < s.purgeBatch {
			return done, nil
		}
	}
}

// destroyTenantKeys destroys every wrapped key left to tid, one
// transaction per page of keyBatch identifiers, and returns how
// many it destroyed.
func (s *Sweeper) destroyTenantKeys(ctx context.Context, tid tenant.ID) (int, error) {
	var n int
	after := ""
	for {
		ids, err := s.repo.keyIDs(ctx, tid, after, s.keyBatch)
		if err != nil {
			return n, fmt.Errorf("list the keys: %w", err)
		}
		if len(ids) == 0 {
			return n, nil
		}
		if err := s.repo.destroyKeys(ctx, tid, ids); err != nil {
			return n, fmt.Errorf("destroy the keys: %w", err)
		}
		n += len(ids)
		if len(ids) < s.keyBatch {
			return n, nil
		}
		after = ids[len(ids)-1]
	}
}
