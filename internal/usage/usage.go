// Package usage counts the activity of the tenants for the statistics of
// the administration (CLAUDE.md section 21.2): transfers finalized and
// their bytes, download starts, bytes served and virus detections, per
// tenant and per UTC day.
//
// A [Recorder] accumulates the counters in memory, without touching the
// database on the request path, and adds them to the store
// ([store.TenantUsage.Add]) every Options.Interval (30 s by default), when
// [Recorder.Flush] is called and when [Recorder.Close] stops it. The
// counters hold no personal data.
//
// # Shutdown
//
// The background flushes started by [Recorder.Start] stop only with
// [Recorder.Close], never with the context given to Start (the signal
// context of the server): the counters recorded while the server shuts
// down (bytes of the downloads finishing during the HTTP shutdown,
// transfers finalized, viruses detected by the antivirus workers being
// stopped) are flushed by the final flush of Close, which runs within the
// deadline of its own context, while the database is still open. Once
// Close has returned, the recorder never writes on its own.
//
// # Failures
//
// A flush that fails for a (tenant, day) keeps its counters in memory for
// the next attempt, merged with what was recorded meanwhile. The pending
// counters are bounded by Options.MaxPending (tenant, day) entries: beyond
// it, the entry of the oldest day is dropped with a warning, so a database
// unavailable for a long time cannot make the memory grow without bound.
// The counters of a tenant that no longer exists (deleted meanwhile, the
// store answers ErrNotFound) or of an invalid tenant ID (ErrInvalid) are
// dropped with a warning, without delaying the other tenants.
//
// The counters of a stop cut short (database unavailable at shutdown) are
// lost: statistics are indicative, never a billing record.
package usage

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/ed-fr/transteira/internal/metrics/metricstate"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Defaults of the Options.
const (
	// DefaultInterval is the default delay between two flushes.
	DefaultInterval = 30 * time.Second
	// DefaultMaxPending is the default bound of the pending (tenant, day)
	// entries.
	DefaultMaxPending = 10000
)

var (
	// ErrStarted is returned when the recorder was already started.
	ErrStarted = errors.New("usage: recorder already started")
	// ErrClosed is returned when the recorder was closed.
	ErrClosed = errors.New("usage: recorder closed")
)

// adder adds counters to the store: *store.TenantUsage.
type adder interface {
	Add(ctx context.Context, tid tenant.ID, day time.Time, delta store.UsageCounts) error
}

// Sink receives every increment recorded, for the in-memory counters of the
// supervision endpoints (*metrics.Counters implements it).
type Sink interface {
	AddUsage(tenantID string, u metricstate.Usage)
}

// Options tune a Recorder. The zero value uses the defaults.
type Options struct {
	// Interval is the delay between two flushes of [Recorder.Run]
	// (DefaultInterval).
	Interval time.Duration
	// MaxPending bounds the pending (tenant, day) entries
	// (DefaultMaxPending).
	MaxPending int
	// Now is the clock used for a zero event time (time.Now).
	Now func() time.Time
	// Logger receives the flush failures and the dropped counters
	// (discarded when nil).
	Logger *slog.Logger
	// Sink, when not nil, receives each increment as it is recorded, whatever
	// the later flushes do.
	Sink Sink
}

// key identifies a pending entry: a tenant and a UTC day (Unix seconds of
// its 00:00 UTC).
type key struct {
	tid tenant.ID
	day int64
}

// Recorder accumulates the usage counters of the tenants and flushes them
// to the store. Its recording methods never block on the database and are
// safe for concurrent use. A nil *Recorder records nothing.
type Recorder struct {
	db         adder
	interval   time.Duration
	maxPending int
	now        func() time.Time
	logger     *slog.Logger
	sink       Sink

	mu      sync.Mutex
	pending map[key]store.UsageCounts

	// flushMu serializes the flushes.
	flushMu sync.Mutex

	runMu   sync.Mutex
	started bool
	closed  bool
	cancel  context.CancelFunc
	done    chan struct{}
}

// New returns a Recorder adding its counters to db.
func New(db *store.DB, opts Options) *Recorder {
	return newRecorder(db.TenantUsage(), opts)
}

// newRecorder returns a Recorder adding its counters through a.
func newRecorder(a adder, opts Options) *Recorder {
	r := &Recorder{
		db: a, interval: opts.Interval, maxPending: opts.MaxPending, now: opts.Now, logger: opts.Logger, sink: opts.Sink, pending: map[key]store.UsageCounts{},
	}
	if r.interval <= 0 {
		r.interval = DefaultInterval
	}
	if r.maxPending <= 0 {
		r.maxPending = DefaultMaxPending
	}
	if r.now == nil {
		r.now = time.Now
	}
	if r.logger == nil {
		r.logger = slog.New(slog.DiscardHandler)
	}
	return r
}

// TransferFinalized counts a transfer of tenant tid finalized at at, with
// its declared size in bytes (a negative size counts as zero). A zero at
// means now.
func (r *Recorder) TransferFinalized(tid tenant.ID, bytes int64, at time.Time) {
	r.record(tid, at, store.UsageCounts{Transfers: 1, BytesUploaded: max(bytes, 0)})
}

// DownloadStarted counts a download start (a file or the archive) of
// tenant tid at at. A zero at means now.
func (r *Recorder) DownloadStarted(tid tenant.ID, at time.Time) {
	r.record(tid, at, store.UsageCounts{Downloads: 1})
}

// BytesServed adds n clear bytes served by tenant tid at at; zero or
// negative n is ignored. A zero at means now.
func (r *Recorder) BytesServed(tid tenant.ID, n int64, at time.Time) {
	if n <= 0 {
		return
	}
	r.record(tid, at, store.UsageCounts{BytesDownloaded: n})
}

// VirusDetected counts an infected file of tenant tid detected at at. A
// zero at means now.
func (r *Recorder) VirusDetected(tid tenant.ID, at time.Time) {
	r.record(tid, at, store.UsageCounts{VirusDetections: 1})
}

// record adds c to the pending entry of tid for the day of at.
func (r *Recorder) record(tid tenant.ID, at time.Time, c store.UsageCounts) {
	if r == nil || tid == "" {
		return
	}
	if at.IsZero() {
		at = r.now()
	}
	k := key{tid: tid, day: store.DayOf(at).Unix()}
	r.mu.Lock()
	dropped, dc, ok := r.add(k, c)
	r.mu.Unlock()
	if ok {
		r.logDropped(dropped, dc)
	}
	if r.sink != nil {
		r.sink.AddUsage(string(tid), metricstate.Usage{
			Transfers: c.Transfers, UploadedBytes: c.BytesUploaded, Downloads: c.Downloads,
			DownloadedBytes: c.BytesDownloaded, VirusDetections: c.VirusDetections,
		})
	}
}

// add adds c to the pending entry k. When k is new and the bound is
// reached, the entry of the oldest day (then smallest tenant ID), k
// included, is dropped and returned with ok true. r.mu must be held.
func (r *Recorder) add(k key, c store.UsageCounts) (dropped key, dc store.UsageCounts, ok bool) {
	cur, exists := r.pending[k]
	if !exists && len(r.pending) >= r.maxPending {
		dropped = k
		for pk := range r.pending {
			if pk.day < dropped.day || (pk.day == dropped.day && pk.tid < dropped.tid) {
				dropped = pk
			}
		}
		if dropped == k {
			return k, c, true
		}
		dc, ok = r.pending[dropped], true
		delete(r.pending, dropped)
	}
	r.pending[k] = sum(cur, c)
	return dropped, dc, ok
}

// logDropped logs the counters of an entry dropped by the bound.
func (r *Recorder) logDropped(k key, c store.UsageCounts) {
	r.logger.Warn("usage: pending counters bound reached, oldest counters dropped",
		slog.String("tenant", string(k.tid)), slog.Time("day", time.Unix(k.day, 0).UTC()),
		slog.Int("max_pending", r.maxPending), countsAttr(c))
}

// sum returns the counters a + b.
func sum(a, b store.UsageCounts) store.UsageCounts {
	return store.UsageCounts{
		Transfers:       a.Transfers + b.Transfers,
		BytesUploaded:   a.BytesUploaded + b.BytesUploaded,
		Downloads:       a.Downloads + b.Downloads,
		BytesDownloaded: a.BytesDownloaded + b.BytesDownloaded,
		VirusDetections: a.VirusDetections + b.VirusDetections,
	}
}

// countsAttr is the log attribute of counters.
func countsAttr(c store.UsageCounts) slog.Attr {
	return slog.Group("counts",
		slog.Int64("transfers", c.Transfers), slog.Int64("bytes_uploaded", c.BytesUploaded),
		slog.Int64("downloads", c.Downloads), slog.Int64("bytes_downloaded", c.BytesDownloaded),
		slog.Int64("virus_detections", c.VirusDetections))
}

// Flush adds the pending counters to the store, by day then tenant. The
// counters of an entry that fails are kept for the next flush (see the
// package documentation), those of an unknown tenant are dropped. It
// returns an error wrapping the first failure when any entry failed.
func (r *Recorder) Flush(ctx context.Context) error {
	if r == nil {
		return nil
	}
	r.flushMu.Lock()
	defer r.flushMu.Unlock()
	r.mu.Lock()
	batch := r.pending
	r.pending = make(map[key]store.UsageCounts, len(batch))
	r.mu.Unlock()

	keys := make([]key, 0, len(batch))
	for k := range batch {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b key) int {
		return cmp.Or(cmp.Compare(a.day, b.day), cmp.Compare(a.tid, b.tid))
	})
	var (
		failed []key
		first  error
	)
	for _, k := range keys {
		c := batch[k]
		err := r.db.Add(ctx, k.tid, time.Unix(k.day, 0).UTC(), c)
		switch {
		case err == nil:
		case errors.Is(err, store.ErrNotFound), errors.Is(err, store.ErrInvalid):
			r.logger.WarnContext(ctx, "usage: counters of an unknown tenant dropped",
				slog.String("tenant", string(k.tid)), slog.Time("day", time.Unix(k.day, 0).UTC()),
				countsAttr(c), slog.String("error", err.Error()))
		default:
			failed = append(failed, k)
			if first == nil {
				first = err
			}
		}
	}
	if first == nil {
		return nil
	}
	r.mu.Lock()
	var drops []key
	var dropCounts []store.UsageCounts
	for _, k := range failed {
		if dk, dc, ok := r.add(k, batch[k]); ok {
			drops, dropCounts = append(drops, dk), append(dropCounts, dc)
		}
	}
	r.mu.Unlock()
	for i, dk := range drops {
		r.logDropped(dk, dropCounts[i])
	}
	return fmt.Errorf("usage: flush of %d of %d counter entries failed, kept for the next attempt: %w",
		len(failed), len(keys), first)
}

// Run flushes the counters every Options.Interval until ctx is done, and
// returns without a final flush: the caller flushes the counters left
// with [Recorder.Flush] (as [Recorder.Close] does). A failed flush is
// logged, unless ctx was canceled meanwhile (the counters are kept for the
// next flush).
func (r *Recorder) Run(ctx context.Context) {
	t := time.NewTicker(r.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := r.Flush(ctx); err != nil && ctx.Err() == nil {
				r.logger.ErrorContext(ctx, "usage: flush failed", slog.String("error", err.Error()))
			}
		}
	}
}

// Start runs [Recorder.Run] in the background until [Recorder.Close]. The
// cancellation of ctx does not stop it (only its values are kept), so that
// the counters recorded during a shutdown reach the final flush of Close.
// It returns ErrStarted when already started and ErrClosed once closed.
func (r *Recorder) Start(ctx context.Context) error {
	r.runMu.Lock()
	defer r.runMu.Unlock()
	switch {
	case r.closed:
		return ErrClosed
	case r.started:
		return ErrStarted
	}
	r.started = true
	ctx, r.cancel = context.WithCancel(context.WithoutCancel(ctx))
	r.done = make(chan struct{})
	go func() {
		defer close(r.done)
		r.Run(ctx)
	}()
	return nil
}

// Close stops the background flushes, waits for [Recorder.Run] to return
// (a periodic flush in progress is canceled, its counters kept), then
// flushes the pending counters a last time with ctx and returns the flush
// error. When ctx is done before Run returns, it returns ctx.Err() without
// flushing. Calling it more than once is harmless: each call flushes what
// was recorded meanwhile. Counters recorded after the last Close stay in
// memory until a [Recorder.Flush].
func (r *Recorder) Close(ctx context.Context) error {
	r.runMu.Lock()
	r.closed = true
	done := r.done
	if r.cancel != nil {
		r.cancel()
	}
	r.runMu.Unlock()
	if done != nil {
		select {
		case <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return r.Flush(ctx)
}
