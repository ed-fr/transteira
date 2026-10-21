package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/ed-fr/transteira/internal/storage"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// DefaultInterval is the default delay between two sweeps.
const DefaultInterval = time.Minute

// Errors of [Sweeper.Start].
var (
	// ErrStarted is returned when the sweeper was already started.
	ErrStarted = errors.New("lifecycle: sweeper already started")
	// ErrClosed is returned when the sweeper was closed.
	ErrClosed = errors.New("lifecycle: sweeper closed")
)

// Vault destroys wrapped keys inside a transaction. *masterkey.Vault
// implements it.
type Vault interface {
	DestroyTx(ctx context.Context, tx *store.ScopedTx, wkID string) error
}

// Remover erases the files of a transfer: their data keys in one
// transaction first (a file without key is skipped), then the files on disk,
// keeping the rows, then one scrub. *upload.Engine implements it.
type Remover interface {
	LockFiles(fileIDs []string) (unlock func(), err error)
	RemoveFiles(ctx context.Context, tid tenant.ID, files []store.TransferFile) error
}

// States removes the state files of the download layer. *storage.Store
// implements it.
type States interface {
	RemoveState(tid tenant.ID, name string) error
}

// Deps are the components the sweeper relies on. Every field is required.
type Deps struct {
	// DB stores the transfers.
	DB *store.DB
	// Vault destroys the sealed download tokens.
	Vault Vault
	// Remover erases the files.
	Remover Remover
	// States removes the byte range states of the transfers.
	States States
}

// Options tunes a [Sweeper]. Zero values select the defaults.
type Options struct {
	// Interval is the delay between two sweeps (DefaultInterval).
	Interval time.Duration
	// Now is the clock that decides which transfers are due (time.Now when
	// nil).
	Now func() time.Time
	// Logger receives the operational logs, identifiers and counts only
	// (nil discards).
	Logger *slog.Logger
}

// Stats counts what a sweep did.
type Stats struct {
	// Due is the number of due transfers listed.
	Due int
	// Deleted is the number of transfers deleted.
	Deleted int
	// Skipped is the number of transfers found no longer due (deleted,
	// expired or gone in the meantime).
	Skipped int
	// Failed is the number of transfers left for the next sweep after a
	// failure.
	Failed int
}

// outcome is the result of the erasure of one transfer.
type outcome int

const (
	deleted outcome = iota
	skipped
	failed
)

// Sweeper deletes the transfers due for deletion. Create it with [New],
// start it with [Sweeper.Start] and stop it with [Sweeper.Close]. It is safe
// for concurrent use; one Sweeper serves the whole instance.
type Sweeper struct {
	repo     repo
	remover  Remover
	states   States
	interval time.Duration
	now      func() time.Time
	logger   *slog.Logger
	// pageSize is the page size of the store's listing: a page this long
	// means more transfers may be due.
	pageSize int
	// newTicker returns the channel that triggers the periodic sweeps and
	// the function stopping it; the tests replace it.
	newTicker func(d time.Duration) (<-chan time.Time, func())
	// afterSweep, when set, is called at the end of each periodic sweep
	// (tests).
	afterSweep func(Stats, error)

	// sweepMu serializes the sweeps.
	sweepMu sync.Mutex

	mu      sync.Mutex
	started bool
	closed  bool
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

// New returns a stopped sweeper over deps.
func New(deps Deps, opts Options) *Sweeper {
	if opts.Interval <= 0 {
		opts.Interval = DefaultInterval
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	return &Sweeper{
		repo:    storeRepo{db: deps.DB, vault: deps.Vault},
		remover: deps.Remover, states: deps.States,
		interval: opts.Interval, now: opts.Now, logger: opts.Logger,
		pageSize:  store.DeletionSweepLimit,
		newTicker: realTicker,
	}
}

// realTicker is the default newTicker, over a time.Ticker.
func realTicker(d time.Duration) (<-chan time.Time, func()) {
	t := time.NewTicker(d)
	return t.C, t.Stop
}

// Start runs a sweep at once, in the background, then one every
// Options.Interval, until ctx is done or [Sweeper.Close] is called. It
// returns ErrStarted when called twice and ErrClosed after Close. The errors
// of the sweeps are logged.
func (s *Sweeper) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case s.closed:
		return ErrClosed
	case s.started:
		return ErrStarted
	}
	s.started = true
	ctx, s.cancel = context.WithCancel(ctx)
	ticks, stop := s.newTicker(s.interval)
	s.wg.Go(func() {
		defer stop()
		s.periodic(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticks:
				s.periodic(ctx)
			}
		}
	})
	return nil
}

// periodic runs a sweep of the background loop and logs its error.
func (s *Sweeper) periodic(ctx context.Context) {
	st, err := s.Sweep(ctx)
	if err != nil && ctx.Err() == nil {
		s.logger.ErrorContext(ctx, "lifecycle: sweep failed", slog.Any("error", err))
	}
	if s.afterSweep != nil {
		s.afterSweep(st, err)
	}
}

// Close stops the sweeps: a sweep in progress stops before its next
// transfer (an interrupted erasure is completed by a later sweep). Close
// waits for the background loop to return, at most until ctx is done, and
// returns ctx.Err() then. Calling it more than once, or before Start, is
// harmless.
func (s *Sweeper) Close(ctx context.Context) error {
	s.mu.Lock()
	s.closed = true
	if s.cancel != nil {
		s.cancel()
	}
	s.mu.Unlock()
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Sweep deletes the transfers due at the current time, page after page while
// a full page made progress, and returns what it did. A failure on a
// transfer is logged and counted, and leaves the transfer for the next
// sweep. Sweep returns an error when the due transfers cannot be listed, or
// ctx.Err() when ctx is done before the end; what was done until then is
// counted, and scrubbed.
func (s *Sweeper) Sweep(ctx context.Context) (Stats, error) {
	s.sweepMu.Lock()
	defer s.sweepMu.Unlock()
	var st Stats
	err := s.sweepPages(ctx, &st)
	if st.Deleted > 0 {
		s.scrub(context.WithoutCancel(ctx))
	}
	if st.Due > 0 {
		s.logger.InfoContext(ctx, "lifecycle: deletion sweep done",
			slog.Int("due", st.Due), slog.Int("deleted", st.Deleted),
			slog.Int("skipped", st.Skipped), slog.Int("failed", st.Failed))
	}
	return st, err
}

// sweepPages lists and erases the due transfers into st.
func (s *Sweeper) sweepPages(ctx context.Context, st *Stats) error {
	for {
		now := s.now()
		page, err := s.repo.due(ctx, now)
		if err != nil {
			return fmt.Errorf("lifecycle: list due deletions: %w", err)
		}
		before := st.Deleted
		for _, tt := range page {
			if err := ctx.Err(); err != nil {
				return err
			}
			st.Due++
			switch s.erase(ctx, tt, now) {
			case deleted:
				st.Deleted++
			case skipped:
				st.Skipped++
			default:
				st.Failed++
			}
		}
		if len(page) < s.pageSize || st.Deleted == before {
			return nil
		}
	}
}

// erase deletes the due transfer tt in the scope of its tenant (see the
// package documentation for the steps).
func (s *Sweeper) erase(ctx context.Context, tt store.TenantTransfer, now time.Time) outcome {
	tid, trfID := tt.TenantID, tt.TransferID
	d, err := s.repo.transfer(ctx, tid, trfID)
	if errors.Is(err, store.ErrNotFound) {
		return skipped
	}
	if err != nil {
		return s.fail(ctx, tt, "read transfer", err)
	}
	if !due(d.Transfer, now) {
		return skipped
	}
	ids := make([]string, len(d.Files))
	for i, f := range d.Files {
		ids[i] = f.ID
	}
	unlock, err := s.remover.LockFiles(ids)
	if err != nil {
		return s.fail(ctx, tt, "lock files", err)
	}
	defer unlock()
	// Every file is passed, keyed or not: the keys still present are
	// destroyed, and the removal of a file left on disk by an earlier
	// failure (an open file on Windows) is retried.
	if len(d.Files) > 0 {
		if err := s.remover.RemoveFiles(ctx, tid, d.Files); err != nil {
			return s.fail(ctx, tt, "remove files", err)
		}
	}
	if err := s.states.RemoveState(tid, storage.StateName(trfID)); err != nil {
		return s.fail(ctx, tt, "remove download state", err)
	}
	err = s.repo.finish(ctx, tid, trfID, now)
	if errors.Is(err, errNotDue) || errors.Is(err, store.ErrNotFound) {
		return skipped
	}
	if err != nil {
		return s.fail(ctx, tt, "mark deleted", err)
	}
	return deleted
}

// fail logs the failure of step on tt and returns failed.
func (s *Sweeper) fail(ctx context.Context, tt store.TenantTransfer, step string, err error) outcome {
	s.logger.WarnContext(ctx, "lifecycle: transfer deletion left for the next sweep",
		slog.String("tenant", string(tt.TenantID)), slog.String("transfer", tt.TransferID),
		slog.String("step", step), slog.Any("error", err))
	return failed
}

// scrub purges the destroyed keys from the database files; an incomplete
// checkpoint is only a warning.
func (s *Sweeper) scrub(ctx context.Context) {
	err := s.repo.scrub(ctx)
	switch {
	case errors.Is(err, store.ErrScrubBusy):
		s.logger.WarnContext(ctx, "lifecycle: destroyed keys may remain in the database WAL until the next checkpoint",
			slog.Any("error", err))
	case err != nil:
		s.logger.ErrorContext(ctx, "lifecycle: scrub of the destroyed keys failed", slog.Any("error", err))
	}
}
