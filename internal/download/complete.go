package download

import (
	"context"
	"errors"
	"log/slog"
	"maps"
	"slices"
	"time"

	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/notify"
	"github.com/ed-fr/transteira/internal/storage"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Coalescing of the range state writes (threat model T-55): a client
// requesting many small ranges must not cause one atomic file write
// (temporary file, fsync, rename) per request. A state is written when the
// bytes newly served since its last write reach flushBytes, when a file or
// the whole transfer becomes complete, or when it holds too many spans;
// otherwise the merged state stays in memory and is written with the next
// qualifying request, once idle for idleFlush (checked after the commits,
// see tidy), when it is among the oldest beyond maxPendingTransfers states,
// or by Close. The trade-off: a crash loses the ranges kept in memory,
// which only delays the completion (the client downloads them again); it
// never credits bytes not served.
const (
	// flushBytes is the newly served bytes that make a state worth writing.
	flushBytes = 1 << 20
	// maxPendingTransfers bounds the states kept in memory: beyond, the
	// oldest are written and evicted after each commit. Concurrent commits
	// may exceed it briefly, by at most one state each.
	maxPendingTransfers = 256
	// maxPendingSpans bounds the spans of one state kept in memory.
	maxPendingSpans = 4096
	// idleFlush is how long a state may stay in memory without new ranges
	// before it is written.
	idleFlush = time.Minute
	// tidyInterval is how often, at most, the commits look for idle
	// states.
	tidyInterval = 15 * time.Second
)

// pendingState is a range state with ranges not written yet. Its fields
// other than st are never modified once it is kept; st is used under the
// lock of its transfer.
type pendingState struct {
	st served
	// unflushed is the bytes newly covered since the last write.
	unflushed int64
	// touched is when the state was last kept in memory.
	touched time.Time
}

// loadState returns the range state of the transfer k: the one kept in
// memory, else the one on disk (empty when there is none or when it is
// corrupt, which is logged). ok is false when the state could not be read
// (logged): the caller must not overwrite it. The caller holds the lock of
// the transfer.
func (s *Service) loadState(ctx context.Context, k key) (st served, unflushed int64, ok bool) {
	s.mu.Lock()
	p := s.pending[k]
	s.mu.Unlock()
	if p != nil {
		return p.st, p.unflushed, true
	}
	raw, err := s.files.ReadState(k.tid, storage.StateName(k.id))
	switch {
	case errors.Is(err, storage.ErrNotFound):
		return served{}, 0, true
	case err != nil:
		s.log(ctx, slog.LevelError, "served ranges not recorded: state unreadable", k.tid, k.id, slog.Any("error", err))
		return nil, 0, false
	}
	if st, err = decodeServed(raw); err != nil {
		s.log(ctx, slog.LevelWarn, "corrupt served range state replaced", k.tid, k.id)
		return served{}, 0, true
	}
	return st, 0, true
}

// keep keeps st in memory for the transfer k, with unflushed bytes not
// written, touched now. The bound on the states kept is enforced by tidy.
// The caller holds the lock of the transfer.
func (s *Service) keep(k key, st served, unflushed int64) {
	p := &pendingState{st: st, unflushed: unflushed, touched: s.clock()}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pending[k] = p
}

// forget drops the state of the transfer k kept in memory, if any.
func (s *Service) forget(k key) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.pending, k)
}

// commit records that the spans of the file f of the transfer d were
// served (see commitLocked), then writes the states kept in memory that
// are idle or over the bound (see tidy).
func (s *Service) commit(ctx context.Context, t *tenant.Tenant, d store.TransferDetails, files []store.TransferFile, f store.TransferFile, spans []span) {
	s.commitLocked(ctx, t, d, files, f, spans)
	s.tidy(ctx)
}

// commitLocked records that the spans of the file f of the transfer d were
// served, under the lock of the transfer: it merges them into the range
// state, records the first download when every deliverable file (files) is
// now fully served, and otherwise writes the state or keeps it in memory
// (see flushBytes). Failures are logged; a state that could not be read is
// never overwritten.
func (s *Service) commitLocked(ctx context.Context, t *tenant.Tenant, d store.TransferDetails, files []store.TransferFile, f store.TransferFile, spans []span) {
	k := key{tid: t.ID, id: d.ID}
	release := s.lock(k)
	defer release()
	st, unflushed, ok := s.loadState(ctx, k)
	if !ok {
		return
	}
	wasDone := st.fileDone(f)
	gained, changed := st.add(f.ID, f.Size, spans)
	force := false
	if st.complete(files) {
		if s.downloaded(ctx, t, d) {
			s.forget(k)
			return
		}
		force = true // keep what was served for a later attempt
	}
	if !changed && !force {
		return
	}
	unflushed += gained
	if !force && unflushed < s.flushBytes && (wasDone || !st.fileDone(f)) && st.spanCount() <= maxPendingSpans {
		s.keep(k, st, unflushed)
		return
	}
	s.write(ctx, k, st, unflushed)
}

// write writes the range state st of the transfer k, which has unflushed
// bytes not written yet, and drops it from memory. Nothing is written when
// the transfer is gone, no longer available or already downloaded (a
// response may end after the deletion: nothing is resurrected), nor when
// the state cannot be encoded. When the transfer cannot be read or the
// state file cannot be written, the failure is logged and the state is
// kept in memory, touched now, for a later attempt; write then reports
// false. The caller holds the lock of the transfer.
func (s *Service) write(ctx context.Context, k key, st served, unflushed int64) bool {
	d, err := s.repo.transfer(ctx, k.tid, k.id)
	switch {
	case errors.Is(err, store.ErrNotFound):
	case err != nil:
		s.log(ctx, slog.LevelError, "served ranges not recorded: transfer unreadable", k.tid, k.id, slog.Any("error", err))
		s.keep(k, st, unflushed)
		return false
	case d.Status != store.TransferAvailable || !d.FirstDownloadedAt.IsZero():
	default:
		b, err := st.encode()
		if err != nil {
			s.log(ctx, slog.LevelError, "served ranges not recorded", k.tid, k.id, slog.Any("error", err))
			break
		}
		if err := s.files.WriteState(k.tid, storage.StateName(k.id), b); err != nil {
			s.log(ctx, slog.LevelError, "served ranges not recorded", k.tid, k.id, slog.Any("error", err))
			s.keep(k, st, unflushed)
			return false
		}
	}
	s.forget(k)
	return true
}

// tidy writes the states kept in memory that have been idle for idleFlush
// (looked for at most every tidyInterval) and, while more than
// maxPendingTransfers states are kept, the oldest ones. It runs without any
// transfer lock held, so that it can take the lock of each state it
// writes. A state over the bound that cannot be written is dropped, which
// is logged, so that the memory stays bounded; an idle one stays for a
// later attempt.
func (s *Service) tidy(ctx context.Context) {
	now := s.clock()
	s.mu.Lock()
	over := len(s.pending) - maxPendingTransfers
	if over <= 0 && now.Sub(s.tidied) < tidyInterval {
		s.mu.Unlock()
		return
	}
	s.tidied = now
	type entry struct {
		k key
		p *pendingState
	}
	all := make([]entry, 0, len(s.pending))
	for k, p := range s.pending {
		all = append(all, entry{k: k, p: p})
	}
	s.mu.Unlock()
	slices.SortFunc(all, func(a, b entry) int { return a.p.touched.Compare(b.p.touched) })
	for i, e := range all {
		evict := i < over
		if !evict && now.Sub(e.p.touched) < idleFlush {
			break // the others are more recent
		}
		s.flushPending(ctx, e.k, e.p, evict)
	}
}

// flushPending writes the state p of the transfer k, unless it was
// written or replaced meanwhile. When evict is set and it cannot be
// written, it is dropped from memory.
func (s *Service) flushPending(ctx context.Context, k key, p *pendingState, evict bool) {
	release := s.lock(k)
	defer release()
	s.mu.Lock()
	cur := s.pending[k]
	s.mu.Unlock()
	if cur != p {
		return
	}
	if !s.write(ctx, k, p.st, p.unflushed) && evict {
		s.forget(k)
		s.log(ctx, slog.LevelWarn, "served ranges dropped from memory: too many states kept", k.tid, k.id)
	}
}

// flushAll writes every range state kept in memory, as long as ctx allows:
// once ctx is done, it stops and logs the number of states left unwritten
// in one warning. It is best effort: a state that cannot be written is
// lost, which only delays the completion of its transfer.
func (s *Service) flushAll(ctx context.Context) {
	s.mu.Lock()
	keys := slices.Collect(maps.Keys(s.pending))
	s.mu.Unlock()
	for _, k := range keys {
		if ctx.Err() != nil {
			s.mu.Lock()
			left := len(s.pending)
			s.mu.Unlock()
			s.logger.LogAttrs(ctx, slog.LevelWarn, "served ranges not written at shutdown", slog.Int("states", left))
			return
		}
		release := s.lock(k)
		s.mu.Lock()
		p := s.pending[k]
		s.mu.Unlock()
		if p != nil {
			s.write(ctx, k, p.st, p.unflushed)
		}
		release()
	}
}

// completeArchive counts the transfer d as downloaded once its archive was
// written to its end, under the lock of the transfer.
func (s *Service) completeArchive(ctx context.Context, t *tenant.Tenant, d store.TransferDetails) {
	k := key{tid: t.ID, id: d.ID}
	release := s.lock(k)
	defer release()
	if s.downloaded(ctx, t, d) {
		s.forget(k)
	}
}

// downloaded records the first complete download of the transfer d at now,
// with its deletion time when it is deleted after its first download, and
// removes its range state, which is no longer needed. Only the request that
// records it sends the first download mail. It reports whether the
// transfer is settled: recorded now or before, or no longer available
// (MarkFirstDownloadTx refuses a transfer that is not available: nothing is
// recorded then). On a database failure it returns false, so that the
// caller keeps the range state for a later request. The caller holds the
// lock of the transfer.
func (s *Service) downloaded(ctx context.Context, t *tenant.Tenant, d store.TransferDetails) bool {
	now := s.now()
	var deleteAfter time.Time
	if d.DeleteAfterFirstDownload {
		deleteAfter = now.Add(s.opts.Grace)
	}
	first, err := s.repo.markFirst(ctx, t.ID, d.ID, now, deleteAfter)
	switch {
	case errors.Is(err, store.ErrConflict), errors.Is(err, store.ErrNotFound):
		s.log(ctx, slog.LevelInfo, "download completed on a transfer no longer available", t.ID, d.ID)
	case err != nil:
		s.log(ctx, slog.LevelError, "first download not recorded", t.ID, d.ID, slog.Any("error", err))
		return false
	}
	if err := s.files.RemoveState(t.ID, storage.StateName(d.ID)); err != nil {
		s.log(ctx, slog.LevelWarn, "served range state not removed", t.ID, d.ID, slog.Any("error", err))
	}
	if first {
		s.log(ctx, slog.LevelInfo, "transfer downloaded for the first time", t.ID, d.ID,
			slog.Bool("delete_after_download", d.DeleteAfterFirstDownload))
		s.notifyFirstDownload(ctx, t, d, now, deleteAfter)
	}
	return true
}

// notifyFirstDownload builds the first download mail of the transfer d,
// downloaded at at, and sends it through the retrier. deleteAt is when the
// transfer is erased, zero when it stays until its expiry.
func (s *Service) notifyFirstDownload(ctx context.Context, t *tenant.Tenant, d store.TransferDetails, at, deleteAt time.Time) {
	job, err := s.notifier.FirstDownload(ctx, t, notify.ViewOf(d), at, deleteAt)
	switch {
	case errors.Is(err, notify.ErrNoSMTP):
		s.log(ctx, slog.LevelError, "no first download mail sent: the tenant has no SMTP settings, an administrator must configure them", t.ID, d.ID)
		return
	case err != nil:
		s.log(ctx, slog.LevelError, "first download mail not built", t.ID, d.ID, slog.Any("error", err))
		return
	}
	s.mails.Send(ctx, []mail.Job{job}, slog.String("tenant", t.ID.String()), slog.String("transfer", d.ID))
}
