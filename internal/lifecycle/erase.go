package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/ed-fr/transteira/internal/storage"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// kind is the kind of an erasure task: what makes a transfer due and which
// status it ends in.
type kind int

const (
	// kindDelete erases the transfers whose DeleteAfter passed; they end
	// deleted.
	kindDelete kind = iota
	// kindExpire erases the transfers past their expiry, which end expired,
	// and the files of the rejected transfers, which stay rejected.
	kindExpire
	// kindAbandoned erases the uploading transfers whose uploads expired;
	// they end expired.
	kindAbandoned
	// kindTenant erases every transfer of a tenant being deleted, whatever
	// its status, and deletes its row ([Sweeper.EraseTenant]).
	kindTenant
	kindCount
)

// task returns the task of k.
func (k kind) task() Task {
	return [kindCount]Task{TaskDeleteAfterDownload, TaskExpire, TaskAbandonedUploads, TaskTenantDeletions}[k]
}

// stats counts what one run of an erasure task did.
type stats struct {
	// due is the number of due transfers listed.
	due int
	// erased is the number of transfers erased.
	erased int
	// skipped is the number of transfers found no longer due (erased,
	// changed or gone in the meantime).
	skipped int
	// failed is the number of transfers left for the next run after a
	// failure.
	failed int
}

// outcome is the result of the erasure of one transfer.
type outcome int

const (
	erased outcome = iota
	skipped
	failed
)

// erasureTask returns the run function of the erasure task of kind k. A
// run that left a transfer for the next one after a failure returns an
// error, so that LastRun only records the runs that erased everything due.
func (s *Sweeper) erasureTask(k kind) func(context.Context) error {
	return func(ctx context.Context) error {
		_, err := s.sweepTask(ctx, k)
		return err
	}
}

// sweepTask runs sweep for k and returns what it did, with an error when
// the sweep failed or left a transfer for the next run.
func (s *Sweeper) sweepTask(ctx context.Context, k kind) (stats, error) {
	st, err := s.sweep(ctx, k)
	if err == nil && st.failed > 0 {
		err = fmt.Errorf("lifecycle: %s: %d transfer(s) left for the next run", k.task(), st.failed)
	}
	return st, err
}

// sweep erases the transfers of kind k due at the current time, page after
// page, and returns what it did. A failure on a transfer is logged and
// counted, and leaves the transfer for the next run. It returns an error
// when the due transfers cannot be listed, or ctx.Err() when ctx is done
// before the end; what was done until then is counted, and scrubbed.
func (s *Sweeper) sweep(ctx context.Context, k kind) (stats, error) {
	var st stats
	err := s.sweepPages(ctx, k, &st)
	if st.erased > 0 {
		s.scrub(context.WithoutCancel(ctx))
	}
	if st.due > 0 {
		s.logger.InfoContext(ctx, "lifecycle: erasure done", slog.String("task", string(k.task())),
			slog.Int("due", st.due), slog.Int("erased", st.erased),
			slog.Int("skipped", st.skipped), slog.Int("failed", st.failed))
	}
	return st, err
}

// lister lists one page of the transfers due at now.
type lister func(ctx context.Context, now time.Time, page store.SweepPage) ([]store.TenantTransfer, error)

// listers returns the listings of the transfers of kind k, in order: the
// expiry walks the expired transfers, then the rejected ones that kept a
// file key.
func (s *Sweeper) listers(k kind) []lister {
	switch k {
	case kindDelete:
		return []lister{s.repo.dueDeletions}
	case kindExpire:
		return []lister{
			func(ctx context.Context, now time.Time, page store.SweepPage) ([]store.TenantTransfer, error) {
				return s.repo.dueExpirations(ctx, now, s.scanningMaxAge, page)
			},
			func(ctx context.Context, _ time.Time, page store.SweepPage) ([]store.TenantTransfer, error) {
				return s.repo.rejectedKeyed(ctx, page)
			},
		}
	default:
		return []lister{func(ctx context.Context, now time.Time, page store.SweepPage) ([]store.TenantTransfer, error) {
			return s.repo.abandonedUploads(ctx, now.Add(-s.uploadTTL), page)
		}}
	}
}

// sweepPages lists and erases the due transfers of kind k into st. Each
// listing is walked with a keyset cursor: the next page starts after the
// last transfer of the previous one, while the pages are full, whatever
// happened to their transfers, so that a full page of transfers that stay
// listed (not due any more, or failing) never hides the later ones.
func (s *Sweeper) sweepPages(ctx context.Context, k kind, st *stats) error {
	size := s.pageSizes[k]
	for _, list := range s.listers(k) {
		var after store.TenantTransfer
		for {
			now := s.now()
			page, err := list(ctx, now, store.SweepPage{After: after, Limit: size})
			if err != nil {
				return fmt.Errorf("lifecycle: list the transfers of %s: %w", k.task(), err)
			}
			for _, tt := range page {
				if err := ctx.Err(); err != nil {
					return err
				}
				st.due++
				switch s.erase(ctx, k, tt, now) {
				case erased:
					st.erased++
				case skipped:
					st.skipped++
				default:
					st.failed++
				}
			}
			if len(page) < size {
				break
			}
			after = page[len(page)-1]
		}
	}
	return nil
}

// erase erases the due transfer tt in the scope of its tenant (see the
// package documentation for the steps).
func (s *Sweeper) erase(ctx context.Context, k kind, tt store.TenantTransfer, now time.Time) outcome {
	d, out, ok := s.check(ctx, k, tt, now, "read transfer")
	if !ok {
		return out
	}
	ids := make([]string, len(d.Files))
	for i, f := range d.Files {
		ids[i] = f.ID
	}
	unlock, err := s.remover.LockFiles(ids)
	if err != nil {
		return s.fail(ctx, k, tt, "lock files", err)
	}
	defer unlock()
	// Read again under the locks: a finalization, an upload or a
	// cancellation may have changed the transfer meanwhile.
	if d, out, ok = s.check(ctx, k, tt, now, "read transfer under lock"); !ok {
		return out
	}
	// Every file is passed, keyed or not: the keys still present are
	// destroyed, and the removal of a file left on disk by an earlier
	// failure (an open file on Windows) is retried. The erasure of a tenant
	// skips the transfers without any key left (already erased): their
	// leftovers go with the tenant directory.
	if len(d.Files) > 0 && (k != kindTenant || anyKeyed(d.Files)) {
		if err := s.remover.RemoveFiles(ctx, tt.TenantID, d.Files); err != nil {
			return s.fail(ctx, k, tt, "remove files", err)
		}
	}
	if k == kindExpire && d.Status == store.TransferRejected {
		return erased
	}
	if err := s.files.RemoveState(tt.TenantID, storage.StateName(tt.TransferID)); err != nil {
		return s.fail(ctx, k, tt, "remove download state", err)
	}
	started := d.Status
	err = s.repo.finish(ctx, k, tt.TenantID, tt.TransferID, now, func(t store.Transfer) bool {
		return finalDue(k, t, now, started, s.scanningMaxAge)
	})
	if errors.Is(err, errNotDue) || errors.Is(err, store.ErrNotFound) {
		return skipped
	}
	if err != nil {
		return s.fail(ctx, k, tt, "final transaction", err)
	}
	if k == kindExpire && started == store.TransferScanning {
		s.logger.WarnContext(ctx, "lifecycle: transfer expired while still scanning (stuck analysis)",
			slog.String("tenant", string(tt.TenantID)), slog.String("transfer", tt.TransferID),
			slog.Duration("finalized_age", now.Sub(d.FinalizedAt)))
	}
	return erased
}

// check reads the transfer tt and decides whether it is due for k at now.
// ok is false when it is not; out is then skipped or failed (logged as
// step).
func (s *Sweeper) check(ctx context.Context, k kind, tt store.TenantTransfer, now time.Time, step string) (d store.TransferDetails, out outcome, ok bool) {
	d, err := s.repo.transfer(ctx, tt.TenantID, tt.TransferID)
	if errors.Is(err, store.ErrNotFound) {
		return d, skipped, false
	}
	if err != nil {
		return d, s.fail(ctx, k, tt, step, err), false
	}
	due, err := s.due(ctx, k, tt.TenantID, d, now)
	if err != nil {
		return d, s.fail(ctx, k, tt, "upload activity", err), false
	}
	if !due {
		return d, skipped, false
	}
	return d, erased, true
}

// due reports whether d must be erased by k at now:
//
//   - kindDelete: available, with a DeleteAfter at or before now;
//   - kindExpire: past its expiry (see dueExpiry), or rejected with a file
//     that still has its data key;
//   - kindAbandoned: uploading, with uploads that expired at or before now
//     according to the upload engine;
//   - kindTenant: always.
func (s *Sweeper) due(ctx context.Context, k kind, tid tenant.ID, d store.TransferDetails, now time.Time) (bool, error) {
	switch k {
	case kindDelete:
		return dueDeletion(d.Transfer, now), nil
	case kindExpire:
		return dueExpiry(d.Transfer, now, s.scanningMaxAge) || rejectedKeyed(d), nil
	case kindTenant:
		return true, nil
	}
	if d.Status != store.TransferUploading {
		return false, nil
	}
	_, expires, err := s.remover.TransferActivity(ctx, tid, d.Files, d.CreatedAt)
	if err != nil {
		return false, err
	}
	return !expires.After(now), nil
}

// finalDue reports whether t, read inside the final transaction of its
// erasure by k at now, must end deleted or expired, with the same rules as
// due (scanningMaxAge for a stuck analysis). started is the status of t
// when its files were erased. A transfer that went from scanning to
// available meanwhile (the antivirus concluded, which restarts its expiry)
// is expired anyway: its file keys are already destroyed.
func finalDue(k kind, t store.Transfer, now time.Time, started store.TransferStatus, scanningMaxAge time.Duration) bool {
	switch k {
	case kindDelete:
		return dueDeletion(t, now)
	case kindExpire:
		return dueExpiry(t, now, scanningMaxAge) || (started == store.TransferScanning && t.Status == store.TransferAvailable)
	case kindTenant:
		return true
	default:
		return t.Status == store.TransferUploading
	}
}

// dueDeletion reports whether t must be deleted at now: available, with a
// DeleteAfter at or before now.
func dueDeletion(t store.Transfer, now time.Time) bool {
	return t.Status == store.TransferAvailable && !t.DeleteAfter.IsZero() && !t.DeleteAfter.After(now)
}

// dueExpiry reports whether t is past its expiry at now: available with an
// ExpiresAt at or before now, or scanning since its finalization at or
// before now - scanningMaxAge (a stuck analysis). The provisional ExpiresAt
// of a scanning transfer is never enforced: the validity starts when the
// transfer becomes available (store.Transfer.ExpiresAt).
func dueExpiry(t store.Transfer, now time.Time, scanningMaxAge time.Duration) bool {
	switch t.Status {
	case store.TransferAvailable:
		return !t.ExpiresAt.IsZero() && !t.ExpiresAt.After(now)
	case store.TransferScanning:
		return !t.FinalizedAt.IsZero() && !t.FinalizedAt.After(now.Add(-scanningMaxAge))
	default:
		return false
	}
}

// rejectedKeyed reports whether d is rejected with a file that still has
// its data key.
func rejectedKeyed(d store.TransferDetails) bool {
	return d.Status == store.TransferRejected && anyKeyed(d.Files)
}

// anyKeyed reports whether a file of files still has its data key.
func anyKeyed(files []store.TransferFile) bool {
	for _, f := range files {
		if f.DEKKeyID != "" {
			return true
		}
	}
	return false
}

// fail logs the failure of step on tt and returns failed.
func (s *Sweeper) fail(ctx context.Context, k kind, tt store.TenantTransfer, step string, err error) outcome {
	s.logger.WarnContext(ctx, "lifecycle: transfer erasure left for the next run",
		slog.String("task", string(k.task())), slog.String("tenant", string(tt.TenantID)),
		slog.String("transfer", tt.TransferID), slog.String("step", step), slog.Any("error", err))
	return failed
}
