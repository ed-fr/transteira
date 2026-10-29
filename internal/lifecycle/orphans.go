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

// orphanCounts counts what TaskOrphans did.
type orphanCounts struct {
	data, checkpoints, states, temps, unknown int
}

// orphans is TaskOrphans: it reconciles the directory of every known tenant
// with the database and removes, past OrphanGrace, the entries the database
// proves orphaned (see reconcile). A directory with no tenant row is only
// logged, never touched. A failure is logged and the next tenant goes on;
// the failures are returned joined.
func (s *Sweeper) orphans(ctx context.Context) error {
	now := s.now()
	dirs, err := s.files.TenantDirs()
	if err != nil {
		return fmt.Errorf("lifecycle: list the tenant directories: %w", err)
	}
	tids, err := s.repo.tenantIDs(ctx)
	if err != nil {
		return fmt.Errorf("lifecycle: list the tenants: %w", err)
	}
	known := make(map[tenant.ID]bool, len(tids))
	for _, tid := range tids {
		known[tid] = true
	}
	var (
		c    orphanCounts
		errs []error
	)
	for _, tid := range dirs {
		if ctx.Err() != nil {
			break
		}
		if !known[tid] {
			s.logger.WarnContext(ctx, "lifecycle: directory of an unknown tenant left in place", slog.String("tenant", string(tid)))
			continue
		}
		if err := s.reconcile(ctx, tid, now, &c); err != nil && ctx.Err() == nil {
			s.logger.WarnContext(ctx, "lifecycle: orphan removal incomplete, left for the next run",
				slog.String("tenant", string(tid)), slog.Any("error", err))
			errs = append(errs, err)
		}
	}
	if c.data+c.checkpoints+c.states+c.temps+c.unknown > 0 {
		s.logger.InfoContext(ctx, "lifecycle: orphan files removed", slog.Int("data", c.data),
			slog.Int("checkpoints", c.checkpoints), slog.Int("states", c.states), slog.Int("temps", c.temps),
			slog.Int("unknown", c.unknown))
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return errors.Join(errs...)
}

// reconcile removes the orphan entries of the directory of tid older than
// the grace period, counting them into c:
//
//   - an encrypted file with no file row, or whose file has no data key
//     any more (unreadable);
//   - a checkpoint with no file row, or whose file is complete or whose
//     transfer is no longer uploading;
//   - a download state that matches no available transfer, nor any
//     recipient link of one;
//   - a leftover temporary file.
//
// Unknown entries are counted and logged, never removed. A tenant with
// more rows than store.MaxReconcileRows is skipped with a warning. A
// removal failure is collected and the next entry goes on.
func (s *Sweeper) reconcile(ctx context.Context, tid tenant.ID, now time.Time, c *orphanCounts) error {
	entries, err := s.files.List(tid)
	if err != nil {
		return err
	}
	refs, states, err := s.references(ctx, tid)
	switch {
	case errors.Is(err, store.ErrTooManyRows):
		s.logger.WarnContext(ctx, "lifecycle: tenant skipped by the orphan removal: too many rows", slog.String("tenant", string(tid)))
		return nil
	case err != nil:
		return err
	}
	return s.removeOrphans(ctx, tid, now, entries, refs, states, c)
}

// references reads what the directory of tid must keep: refs, the storage
// names of its files, and states, the names of the download states of its
// available transfers and of their recipient links (each link keeps its
// own, storage.StateName(linkID)).
func (s *Sweeper) references(ctx context.Context, tid tenant.ID) (map[string]store.StorageRef, map[string]bool, error) {
	refs, err := s.repo.storageRefs(ctx, tid)
	if err != nil {
		return nil, nil, err
	}
	ids, err := s.repo.availableIDs(ctx, tid)
	if err != nil {
		return nil, nil, err
	}
	links, err := s.repo.linkTransfers(ctx, tid)
	if err != nil {
		return nil, nil, err
	}
	available := make(map[string]bool, len(ids))
	states := make(map[string]bool, len(ids)+len(links))
	for _, trfID := range ids {
		available[trfID] = true
		states[storage.StateName(trfID)] = true
	}
	for linkID, trfID := range links {
		if available[trfID] {
			states[storage.StateName(linkID)] = true
		}
	}
	return refs, states, nil
}

// removeOrphans applies the rules of reconcile to entries, with refs the
// storage names of the files of tid and states the names of the download
// states to keep (see [Sweeper.references]).
func (s *Sweeper) removeOrphans(ctx context.Context, tid tenant.ID, now time.Time, entries []storage.Entry,
	refs map[string]store.StorageRef, states map[string]bool, c *orphanCounts,
) error {
	cutoff := now.Add(-s.orphanGrace)
	unknown := 0
	var errs []error
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		if e.Kind == storage.KindUnknown {
			unknown++
			continue
		}
		if e.Kind == storage.KindAsset {
			// Branding images belong to the tenant, not to a transfer.
			continue
		}
		if e.ModTime.After(cutoff) {
			continue
		}
		var (
			removed bool
			err     error
			count   *int
		)
		switch e.Kind {
		case storage.KindData:
			count = &c.data
			removed, err = s.removeFile(ctx, tid, e, refs)
		case storage.KindCheckpoint:
			count = &c.checkpoints
			removed, err = s.removeFile(ctx, tid, e, refs)
		case storage.KindState:
			if states[e.Name] {
				continue
			}
			count, removed, err = &c.states, true, s.files.RemoveState(tid, e.Name)
		default: // storage.KindTemp
			count, removed, err = &c.temps, true, s.files.RemoveTemp(tid, e.File)
		}
		switch {
		case err != nil:
			errs = append(errs, err)
		case removed:
			*count++
		}
	}
	if unknown > 0 {
		c.unknown += unknown
		s.logger.WarnContext(ctx, "lifecycle: unknown entries left in a tenant directory",
			slog.String("tenant", string(tid)), slog.Int("count", unknown))
	}
	return errors.Join(errs...)
}

// orphaned reports whether an entry of kind k (KindData or KindCheckpoint)
// is an orphan for a file whose state is keyed, completed and status (the
// status of its transfer).
func orphaned(k storage.Kind, keyed, completed bool, status store.TransferStatus) bool {
	if k == storage.KindData {
		return !keyed
	}
	return completed || status != store.TransferUploading
}

// removeFile removes the encrypted file or the checkpoint e of tid when it
// is an orphan according to refs. When a file row refers to it, the upload
// lock of the file is taken and the row read again first, so that an
// upload is never disturbed (a busy file is left for the next run).
func (s *Sweeper) removeFile(ctx context.Context, tid tenant.ID, e storage.Entry, refs map[string]store.StorageRef) (bool, error) {
	ref, ok := refs[e.Name]
	if ok {
		if !orphaned(e.Kind, ref.Keyed, ref.Completed, ref.TransferStatus) {
			return false, nil
		}
		unlock, err := s.remover.LockFiles([]string{ref.FileID})
		if err != nil {
			return false, err
		}
		defer unlock()
		d, err := s.repo.transfer(ctx, tid, ref.TransferID)
		switch {
		case errors.Is(err, store.ErrNotFound):
		case err != nil:
			return false, err
		default:
			for _, f := range d.Files {
				if f.ID == ref.FileID && f.StorageName == e.Name &&
					!orphaned(e.Kind, f.DEKKeyID != "", f.Completed(), d.Status) {
					return false, nil
				}
			}
		}
	}
	if e.Kind == storage.KindData {
		return true, s.files.Remove(tid, e.Name)
	}
	return true, s.files.RemoveCheckpoint(tid, e.Name)
}
