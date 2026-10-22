package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// rowPurge is one purge of TaskPurgeRows after the ended transfers.
type rowPurge struct {
	// name names the purge in the logs.
	name string
	run  func(ctx context.Context, db *store.DB, tid tenant.ID, now time.Time) (int64, error)
}

// endedTransfers names the deletion of the ended transfer rows in the logs.
const endedTransfers = "transfers"

// rowPurges are the purges of TaskPurgeRows, in order, after the ended
// transfers. The invitations come last: a transfer row references its
// invitation without cascade, so an invitation goes only once the rows of
// its transfers are deleted.
var rowPurges = []rowPurge{
	{"challenges", func(ctx context.Context, db *store.DB, tid tenant.ID, now time.Time) (int64, error) {
		return db.Challenges().Purge(ctx, tid, now)
	}},
	{"sessions", func(ctx context.Context, db *store.DB, tid tenant.ID, now time.Time) (int64, error) {
		return db.DepositSessions().Purge(ctx, tid, now)
	}},
	{"password_failures", func(ctx context.Context, db *store.DB, tid tenant.ID, now time.Time) (int64, error) {
		return db.PasswordFailures().Purge(ctx, tid, now)
	}},
	{"verified_addresses", func(ctx context.Context, db *store.DB, tid tenant.ID, now time.Time) (int64, error) {
		return db.VerifiedAddresses().Purge(ctx, tid, now)
	}},
	{"invitations", func(ctx context.Context, db *store.DB, tid tenant.ID, now time.Time) (int64, error) {
		return db.Invitations().Purge(ctx, tid, now)
	}},
}

// systemPurge is one global purge of TaskPurgeRows, run in the system
// scope after the purges of the tenants: the rows it deletes belong to no
// tenant (administrator sessions, activation links, login failures) or to
// any tenant (the audit log).
type systemPurge struct {
	// name names the purge in the logs.
	name string
	run  func(ctx context.Context, db *store.DB, now time.Time) (int64, error)
}

// systemPurges returns the global purges of TaskPurgeRows, in order, with
// the retention settings of s.
func (s *Sweeper) systemPurges() []systemPurge {
	return []systemPurge{
		{"admin_sessions", func(ctx context.Context, db *store.DB, now time.Time) (int64, error) {
			return db.AdminSessions().Purge(ctx, now, s.adminIdleTimeout)
		}},
		{"admin_activations", func(ctx context.Context, db *store.DB, now time.Time) (int64, error) {
			return db.AdminActivations().Purge(ctx, now)
		}},
		{"admin_login_failures", func(ctx context.Context, db *store.DB, now time.Time) (int64, error) {
			return db.AdminLoginFailures().Purge(ctx, now, AdminLoginFailureWindow)
		}},
		{"audit_events", func(ctx context.Context, db *store.DB, now time.Time) (int64, error) {
			return db.AuditEvents().Purge(ctx, now.AddDate(0, -s.auditRetentionMonths, 0))
		}},
	}
}

// purgeRows is TaskPurgeRows: for each tenant, in its own scope, it deletes
// the transfers ended more than EndedRetention ago, then runs rowPurges;
// then it runs the global systemPurges. A failure is logged and the next
// purge and tenant go on; the failures are returned joined (a failed
// listing of the tenants only skips the tenant phase). The database is
// scrubbed once at the end when anything was deleted.
func (s *Sweeper) purgeRows(ctx context.Context) error {
	now := s.now()
	var errs []error
	tids, err := s.repo.tenantIDs(ctx)
	if err != nil {
		errs = append(errs, fmt.Errorf("lifecycle: list the tenants: %w", err))
	}
	counts := make(map[string]int64, len(rowPurges)+len(s.sysPurges)+1)
	record := func(tid tenant.ID, name string, n int64, err error) {
		counts[name] += n
		if err != nil && ctx.Err() == nil {
			attrs := []any{slog.String("kind", name), slog.Any("error", err)}
			if tid != "" {
				attrs = append([]any{slog.String("tenant", string(tid))}, attrs...)
			}
			s.logger.WarnContext(ctx, "lifecycle: purge failed, left for the next run", attrs...)
			errs = append(errs, err)
		}
	}
	for _, tid := range tids {
		if ctx.Err() != nil {
			break
		}
		n, err := s.purgeEnded(ctx, tid, now.Add(-s.endedRetention))
		record(tid, endedTransfers, n, err)
		for _, p := range rowPurges {
			n, err := s.repo.purge(ctx, p, tid, now)
			record(tid, p.name, n, err)
		}
	}
	for _, p := range s.sysPurges {
		if ctx.Err() != nil {
			break
		}
		n, err := s.repo.purgeSystem(ctx, p, now)
		record("", p.name, n, err)
	}
	var total int64
	attrs := []any{slog.Int64(endedTransfers, counts[endedTransfers])}
	for _, p := range rowPurges {
		attrs = append(attrs, slog.Int64(p.name, counts[p.name]))
	}
	for _, p := range s.sysPurges {
		attrs = append(attrs, slog.Int64(p.name, counts[p.name]))
	}
	for _, n := range counts {
		total += n
	}
	if total > 0 {
		s.scrub(context.WithoutCancel(ctx))
		s.logger.InfoContext(ctx, "lifecycle: rows purged", attrs...)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return errors.Join(errs...)
}

// purgeEnded deletes the rows of the transfers of tid ended at or before
// endedBefore, one transaction each, page after page while a full page
// made progress, and returns how many it deleted. A rejected transfer that
// still holds a file key is refused by the store (store.ErrKeysRemain)
// until TaskExpire erased it, and one gone meanwhile is skipped.
func (s *Sweeper) purgeEnded(ctx context.Context, tid tenant.ID, endedBefore time.Time) (int64, error) {
	var total int64
	for {
		ids, err := s.repo.listEnded(ctx, tid, endedBefore, s.purgeBatch)
		if err != nil {
			return total, err
		}
		var n int64
		for _, trfID := range ids {
			if err := ctx.Err(); err != nil {
				return total + n, err
			}
			err := s.repo.deleteEnded(ctx, tid, trfID)
			switch {
			case err == nil:
				n++
			case errors.Is(err, store.ErrKeysRemain), errors.Is(err, store.ErrNotFound):
			default:
				return total + n, err
			}
		}
		total += n
		if len(ids) < s.purgeBatch || n == 0 {
			return total, nil
		}
	}
}
