package metrics

import (
	"cmp"
	"context"
	"errors"
	"io"
	"log/slog"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ed-fr/transteira/internal/health"
	"github.com/ed-fr/transteira/internal/version"
)

// CollectTimeout bounds one collection, so that a stuck source cannot hold
// the collector (and the start of the application) forever.
const CollectTimeout = 10 * time.Second

// Errors of [Collector.Start].
var (
	// ErrStarted is returned by Start when the collector already runs.
	ErrStarted = errors.New("metrics: collector already started")
	// ErrClosed is returned by Start once the collector is closed.
	ErrClosed = errors.New("metrics: collector closed")
)

// webhookCounts is a copy of the webhook delivery counters.
type webhookCounts struct {
	delivered, failed, dropped, skippedOpenCircuit uint64
}

// syslogCounts is a copy of the syslog export counters.
type syslogCounts struct {
	sent, failed, dropped uint64
}

// snapshot is the immutable result of one collection. The has* flags are
// false when the matching source is nil (or, for the state, never read
// successfully): the metrics and fields are then left out.
type snapshot struct {
	at, started     time.Time
	version, commit string
	engine          string

	hasState bool
	state    InstanceState

	hasHealth bool
	health    health.Report

	hasAntivirus bool
	antivirusUp  bool

	hasAVAlert bool
	avAlert    bool

	hasMaintenance bool
	maintenance    bool

	hasMail     bool
	mailLength  int64
	mailDropped uint64

	hasBus        bool
	eventsDropped map[string]uint64

	hasWebhook bool
	webhook    webhookCounts

	hasSyslog bool
	syslog    syslogCounts

	// lifecycle maps each task that succeeded to the end of its last run.
	lifecycle map[string]time.Time
}

// uptime returns the time between the start of the process and the
// collection, never negative.
func (s *snapshot) uptime() time.Duration {
	return max(s.at.Sub(s.started), 0)
}

// CollectorOption configures a [Collector].
type CollectorOption func(*Collector)

// WithClock sets the clock of the collection timestamps (time.Now by
// default).
func WithClock(now func() time.Time) CollectorOption {
	return func(c *Collector) { c.now = now }
}

// WithInterval sets the collection period ([CollectInterval] by default).
// A non-positive d is ignored.
func WithInterval(d time.Duration) CollectorOption {
	return func(c *Collector) {
		if d > 0 {
			c.interval = d
		}
	}
}

// WithStartTime sets the start of the process, the origin of
// transteira_uptime_seconds (the creation of the collector by default).
func WithStartTime(t time.Time) CollectorOption {
	return func(c *Collector) { c.started = t }
}

// WithLogger sets the logger of the collection failures (discarded by
// default).
func WithLogger(l *slog.Logger) CollectorOption {
	return func(c *Collector) {
		if l != nil {
			c.logger = l
		}
	}
}

// Collector reads the [Sources] every interval into an immutable snapshot
// served by the handlers: a request never queries a source (threat T-192).
type Collector struct {
	src      Sources
	counters *Counters
	now      func() time.Time
	interval time.Duration
	started  time.Time
	logger   *slog.Logger
	build    version.Info

	snap atomic.Pointer[snapshot]

	runMu     sync.Mutex
	running   bool
	closed    bool
	cancel    context.CancelFunc
	done      chan struct{}
	collectMu sync.Mutex // serializes the collections
}

// NewCollector returns a collector of src. counters are the in-memory
// counters served with the snapshot (fresh empty ones when nil).
func NewCollector(src Sources, counters *Counters, opts ...CollectorOption) *Collector {
	if counters == nil {
		counters = NewCounters()
	}
	c := &Collector{
		src:      src,
		counters: counters,
		now:      time.Now,
		interval: CollectInterval,
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		build:    version.Get(),
	}
	for _, opt := range opts {
		opt(c)
	}
	if c.started.IsZero() {
		c.started = c.now()
	}
	return c
}

// Counters returns the counters served with the snapshot.
func (c *Collector) Counters() *Counters { return c.counters }

// snapshot returns the last snapshot, nil before the first collection.
func (c *Collector) snapshot() *snapshot { return c.snap.Load() }

// Start runs one collection synchronously, so that the handlers always
// have a snapshot once the server is up, then collects every interval in
// the background until [Collector.Close]. The cancellation of ctx does not
// stop the loop (only its values are kept). It returns ErrStarted when
// already started and ErrClosed once closed.
func (c *Collector) Start(ctx context.Context) error {
	c.runMu.Lock()
	defer c.runMu.Unlock()
	switch {
	case c.closed:
		return ErrClosed
	case c.running:
		return ErrStarted
	}
	c.running = true
	ctx, c.cancel = context.WithCancel(context.WithoutCancel(ctx))
	c.done = make(chan struct{})
	c.collect(ctx)
	go func() {
		defer close(c.done)
		c.run(ctx)
	}()
	return nil
}

// run collects every interval until ctx is done.
func (c *Collector) run(ctx context.Context) {
	t := time.NewTicker(c.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.collect(ctx)
		}
	}
}

// Close stops the collector. When started, it waits for the loop to
// return, at most until ctx is done, and returns ctx.Err() then. Calling
// it more than once is harmless.
func (c *Collector) Close(ctx context.Context) error {
	c.runMu.Lock()
	c.closed = true
	running, done := c.running, c.done
	if c.cancel != nil {
		c.cancel()
	}
	c.runMu.Unlock()
	if !running {
		return nil
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// collect reads every non-nil source into a new snapshot. A state read
// failure keeps the previous state and is logged at Warn level.
func (c *Collector) collect(ctx context.Context) {
	c.collectMu.Lock()
	defer c.collectMu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, CollectTimeout)
	defer cancel()

	src := c.src
	prev := c.snap.Load()
	s := &snapshot{
		started: c.started,
		version: c.build.Version,
		commit:  c.build.Commit,
		engine:  src.AntivirusEngine,
	}
	if src.State != nil {
		st, err := src.State.InstanceState(ctx)
		switch {
		case err == nil:
			st.Tenants = slices.Clone(st.Tenants)
			slices.SortFunc(st.Tenants, func(a, b TenantState) int { return cmp.Compare(a.ID, b.ID) })
			s.hasState, s.state = true, st
		case prev != nil:
			s.hasState, s.state = prev.hasState, prev.state
		}
		if err != nil {
			c.logger.WarnContext(ctx, "metrics: failed to read the instance state, keeping the previous one",
				slog.String("error", err.Error()))
		}
	}
	if src.Health != nil {
		s.hasHealth, s.health = true, src.Health(ctx)
	}
	if src.Antivirus != nil {
		s.hasAntivirus, s.antivirusUp = true, src.Antivirus.Up()
	}
	if src.AVAlert != nil {
		s.hasAVAlert, s.avAlert = true, src.AVAlert.Active()
	}
	if src.Maintenance != nil {
		s.hasMaintenance, s.maintenance = true, src.Maintenance.Active()
	}
	for _, q := range src.Mail {
		if q == nil {
			continue
		}
		s.hasMail = true
		s.mailLength += int64(q.Len())
		s.mailDropped += q.Dropped()
	}
	if src.Bus != nil {
		s.hasBus = true
		s.eventsDropped = make(map[string]uint64, len(src.Subscribers))
		for _, name := range src.Subscribers {
			s.eventsDropped[name] = src.Bus.Dropped(name)
		}
	}
	if w := src.Webhook; w != nil {
		s.hasWebhook = true
		s.webhook = webhookCounts{w.Delivered(), w.Failed(), w.Dropped(), w.SkippedOpenCircuit()}
	}
	if l := src.Syslog; l != nil {
		s.hasSyslog = true
		s.syslog = syslogCounts{l.Sent(), l.Failed(), l.Dropped()}
	}
	if src.LastRun != nil {
		s.lifecycle = map[string]time.Time{}
		for _, task := range src.Tasks {
			if t := src.LastRun(task); !t.IsZero() {
				s.lifecycle[task] = t.UTC()
			}
		}
	}
	s.at = c.now()
	c.snap.Store(s)
}
