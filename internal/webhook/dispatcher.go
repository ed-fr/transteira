package webhook

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ed-fr/transteira/internal/events"
	"github.com/ed-fr/transteira/internal/mail"
)

// SubscriberName is the name of the dispatcher on the event bus.
const SubscriberName = "webhook"

// Defaults of [DispatcherOptions].
const (
	// DefaultQueueSize is the length of the queue of one webhook.
	DefaultQueueSize = 64
	// DefaultTenantParallelism is the number of deliveries of one tenant
	// (or of the system webhooks) in progress at the same time.
	DefaultTenantParallelism = 2
	// DefaultWarnInterval is the shortest delay between two warnings of
	// the same kind for one webhook.
	DefaultWarnInterval = time.Minute
	// DefaultBackoffMin and DefaultBackoffMax bound the delay between two
	// attempts of a delivery.
	DefaultBackoffMin = time.Second
	DefaultBackoffMax = 5 * time.Minute
	// storeTimeout bounds a read of a webhook and the recording of a
	// delivery.
	storeTimeout = 10 * time.Second
)

// DispatcherOptions configure a [Dispatcher].
type DispatcherOptions struct {
	// Store gives the webhooks and records the deliveries (required).
	Store Store
	// Client delivers (required).
	Client *Client
	// Logger receives the rate-limited warnings, which name the webhook
	// and the error category only, never the URL (discarded when nil).
	Logger *slog.Logger
	// Now is the clock (time.Now when nil).
	Now func() time.Time
	// Backoff returns the delay before attempt n+1 after a failed attempt
	// n (mail.Backoff(DefaultBackoffMin, DefaultBackoffMax, n) when nil).
	Backoff func(n int) time.Duration
	// QueueSize is the queue length of one webhook (DefaultQueueSize when
	// <= 0).
	QueueSize int
	// TenantParallelism is the number of attempts of one tenant in
	// progress at the same time (DefaultTenantParallelism when <= 0).
	TenantParallelism int
	// Buffer is the length of the bus queue of the dispatcher
	// (events.DefaultBuffer when <= 0).
	Buffer int
	// WarnInterval is the shortest delay between two warnings of the same
	// kind for one webhook (DefaultWarnInterval when <= 0).
	WarnInterval time.Duration
}

// job is a delivery waiting in the queue of a webhook. It names the
// webhook only: its URL, secret and settings are read again before every
// attempt, so that an unsealed secret lives in memory for one attempt at
// most and a change of the webhook applies to the pending deliveries.
type job struct {
	// ctx keeps the values of the bus context, without its cancellation.
	ctx context.Context
	// tenantID is the owner of the webhook, "" for a system webhook.
	tenantID string
	// id is the webhook.
	id string
	ev events.Event
}

// key returns the key of the queue of the webhook of j.
func (j job) key() string { return j.tenantID + "/" + j.id }

// Dispatcher is the bus subscriber delivering the alert events to the
// webhooks (T-179, T-185). For each event it reads the subscribed webhooks
// of the tenant of the event only (the system webhooks for a system
// event), queues one delivery per webhook on a bounded queue, and delivers
// with up to [MaxAttempts] attempts, a limited parallelism per tenant and a
// circuit breaker per webhook. Before every attempt it reads the webhook
// again: a webhook deleted, disabled or no longer subscribed meanwhile
// abandons the delivery, an open circuit skips it, and the attempt uses the
// current URL, secret and settings. The breaker state lives in the store
// only, recorded conditionally on the version it was computed from, so
// that a change by an admin (re-enabling closes the circuit) always wins.
// Pending deliveries live in memory only: they are abandoned at
// [Dispatcher.Close] (accepted residual risk, T-178).
type Dispatcher struct {
	store        Store
	client       *Client
	logger       *slog.Logger
	now          func() time.Time
	backoff      func(int) time.Duration
	queueSize    int
	parallelism  int
	buffer       int
	warnInterval time.Duration

	// stop is closed by Close: no new attempt starts.
	stop chan struct{}
	// attemptCtx is the context of the attempts, canceled when the Close
	// deadline passes.
	attemptCtx    context.Context
	cancelAttempt context.CancelFunc
	wg            sync.WaitGroup

	mu     sync.Mutex
	closed bool
	queues map[string]chan job
	sems   map[string]chan struct{}

	warnMu sync.Mutex
	warned map[string]time.Time

	delivered, failed, dropped, skipped atomic.Uint64
}

// NewDispatcher returns a dispatcher applying opts. It fails without a
// Store or a Client.
func NewDispatcher(opts DispatcherOptions) (*Dispatcher, error) {
	if opts.Store == nil || opts.Client == nil {
		return nil, errors.New("webhook: the dispatcher needs a store and a client")
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Backoff == nil {
		opts.Backoff = func(n int) time.Duration { return mail.Backoff(DefaultBackoffMin, DefaultBackoffMax, n) }
	}
	if opts.QueueSize <= 0 {
		opts.QueueSize = DefaultQueueSize
	}
	if opts.TenantParallelism <= 0 {
		opts.TenantParallelism = DefaultTenantParallelism
	}
	if opts.WarnInterval <= 0 {
		opts.WarnInterval = DefaultWarnInterval
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Dispatcher{
		store: opts.Store, client: opts.Client, logger: opts.Logger, now: opts.Now, backoff: opts.Backoff,
		queueSize: opts.QueueSize, parallelism: opts.TenantParallelism, buffer: opts.Buffer,
		warnInterval: opts.WarnInterval,
		stop:         make(chan struct{}), attemptCtx: ctx, cancelAttempt: cancel,
		queues: map[string]chan job{}, sems: map[string]chan struct{}{}, warned: map[string]time.Time{},
	}, nil
}

// Register subscribes the dispatcher to bus for the subscribable alert
// types ([events.IsSubscribable]), under [SubscriberName].
func (d *Dispatcher) Register(bus *events.Bus) error {
	return bus.Subscribe(SubscriberName, events.IsSubscribable, d.buffer, d.Handle)
}

// Handle routes ev to the subscribed webhooks: a system event to the
// system webhooks only, a tenant event to the webhooks of its tenant only
// (an event without tenant is dropped); webhooks whose circuit is open are
// skipped. It never waits for a delivery. It is the bus handler.
func (d *Dispatcher) Handle(ctx context.Context, ev events.Event) {
	var tenantID string
	switch {
	case events.IsSystem(ev.Type):
	case events.IsTenant(ev.Type) && ev.TenantID != "":
		tenantID = ev.TenantID
	case events.IsTenant(ev.Type):
		d.dropped.Add(1)
		d.warn(ctx, "tenant-event-without-tenant", "webhook: tenant event without tenant dropped",
			slog.String("type", string(ev.Type)), slog.String("event", ev.ID))
		return
	default:
		return
	}
	refs, err := d.store.Subscribers(ctx, tenantID, ev.Type)
	if err != nil {
		d.warn(ctx, "subscribers:"+tenantID, "webhook: cannot read the subscribed webhooks",
			slog.String("tenant", tenantID), slog.String("type", string(ev.Type)), slog.String("error", err.Error()))
		return
	}
	now := d.now()
	for _, t := range refs {
		switch {
		case t.TenantID != tenantID:
			// Never cross tenants, whatever the store answers (T-179).
			d.dropped.Add(1)
			d.warn(ctx, "foreign:"+t.ID, "webhook: webhook of another owner ignored", slog.String("webhook", t.ID))
		case now.Before(t.CircuitOpenUntil):
			d.skipped.Add(1)
		default:
			d.enqueue(job{ctx: context.WithoutCancel(ctx), tenantID: t.TenantID, id: t.ID, ev: ev}) //nolint:contextcheck // the job keeps the values of ctx; its store calls and attempts are also bound to the dispatcher context, canceled by Close
		}
	}
}

// enqueue puts j on the queue of its webhook, starting its worker when
// idle; a full queue, or a closed dispatcher, drops it.
func (d *Dispatcher) enqueue(j job) {
	key := j.key()
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		d.dropped.Add(1)
		return
	}
	q := d.queues[key]
	if q == nil {
		q = make(chan job, d.queueSize)
		d.queues[key] = q
		sem := d.sems[j.tenantID]
		if sem == nil {
			sem = make(chan struct{}, d.parallelism)
			d.sems[j.tenantID] = sem
		}
		d.wg.Go(func() { d.work(key, q, sem) })
	}
	select {
	case q <- j:
	default:
		d.dropped.Add(1)
		d.warn(j.ctx, "full:"+j.id, "webhook: queue full, delivery dropped", slog.String("webhook", j.id))
	}
}

// work delivers the queue q of the webhook key until it is empty (the
// queue is then removed, and a later event starts a new worker) or the
// dispatcher is closed (the pending deliveries are abandoned). There is
// one worker per webhook: its deliveries, and their breaker updates, never
// overlap.
func (d *Dispatcher) work(key string, q chan job, sem chan struct{}) {
	for {
		if d.stopped() {
			d.abandon(key, q)
			return
		}
		d.mu.Lock()
		if len(q) == 0 {
			delete(d.queues, key)
			d.mu.Unlock()
			return
		}
		// Only this worker receives from q: it cannot block.
		j := <-q
		d.mu.Unlock()
		d.deliver(sem, j)
	}
}

// abandon counts the deliveries left in q as dropped and removes it.
func (d *Dispatcher) abandon(key string, q chan job) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.dropped.Add(uint64(len(q)))
	delete(d.queues, key)
}

// deliver makes the attempts of j, each one on the webhook read again
// just before, and records the delivery. Only the version and the failure
// count of the target outlive an attempt, never its URL nor its secret.
func (d *Dispatcher) deliver(sem chan struct{}, j job) {
	var (
		result   Result
		version  time.Time
		failures int
	)
	for n := 1; ; n++ {
		t, ok := d.current(j)
		if !ok {
			return
		}
		version, failures = t.Version, t.ConsecutiveFailures
		r, ok := d.attempt(sem, t, j.ev)
		if !ok {
			d.dropped.Add(1)
			return
		}
		result = r
		if result.Success || n == MaxAttempts {
			break
		}
		if !d.wait(d.backoff(n)) {
			d.dropped.Add(1)
			return
		}
	}
	d.record(j, version, failures, result)
}

// storeContext returns the context of a store call for j: it keeps the
// values of the bus context, is bounded by storeTimeout and is cut short
// by the Close deadline.
func (d *Dispatcher) storeContext(j job) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(j.ctx, storeTimeout)
	stop := context.AfterFunc(d.attemptCtx, cancel)
	return ctx, func() {
		stop()
		cancel()
	}
}

// current reads the webhook of j before an attempt. ok is false, and the
// delivery is over, when the webhook cannot be read, is gone, disabled or
// no longer subscribed to the event (dropped), or when its circuit is open
// (skipped): the state read here is authoritative.
func (d *Dispatcher) current(j job) (Target, bool) {
	ctx, cancel := d.storeContext(j)
	defer cancel()
	t, ok, err := d.store.Target(ctx, j.tenantID, j.id)
	switch {
	case err != nil:
		d.dropped.Add(1)
		d.warn(j.ctx, "target:"+j.id, "webhook: cannot read the webhook, delivery dropped",
			slog.String("webhook", j.id), slog.String("error", err.Error()))
		return Target{}, false
	case !ok || t.TenantID != j.tenantID || t.ID != j.id || !t.Subscribed(j.ev.Type):
		// Deleted, disabled or unsubscribed meanwhile: the delivery is
		// abandoned. A target of another webhook is never used (T-179).
		d.dropped.Add(1)
		return Target{}, false
	case d.now().Before(t.CircuitOpenUntil):
		d.skipped.Add(1)
		return Target{}, false
	}
	return t, true
}

// record computes the new breaker state from the failures in a row read
// with version and the result of the delivery, and records it while the
// webhook keeps that version.
func (d *Dispatcher) record(j job, version time.Time, failures int, result Result) {
	at := d.now()
	var openUntil time.Time
	if result.Success {
		d.delivered.Add(1)
		failures = 0
	} else {
		d.failed.Add(1)
		failures++
		if failures >= BreakerThreshold {
			openUntil = at.Add(BreakerCooldown)
		}
		d.warn(j.ctx, "failed:"+j.id, "webhook: delivery failed",
			slog.String("webhook", j.id), slog.String("category", string(result.Category)),
			slog.Int("http_status", result.HTTPStatus), slog.Int("consecutive_failures", failures))
	}
	ctx, cancel := d.storeContext(j)
	defer cancel()
	err := d.store.RecordDelivery(ctx, j.tenantID, j.id, Delivery{
		Version: version, At: at, Result: result, ConsecutiveFailures: failures, CircuitOpenUntil: openUntil,
	})
	if err != nil {
		d.warn(j.ctx, "record:"+j.id, "webhook: cannot record the delivery",
			slog.String("webhook", j.id), slog.String("error", err.Error()))
	}
}

// attempt makes one attempt to deliver ev to t once a slot of its tenant
// is free; ok is false when the dispatcher was closed before the slot was
// free, or during an attempt that did not succeed.
func (d *Dispatcher) attempt(sem chan struct{}, t Target, ev events.Event) (Result, bool) {
	select {
	case <-d.stop:
		return Result{}, false
	case sem <- struct{}{}:
	}
	defer func() { <-sem }()
	r := d.client.Send(d.attemptCtx, t, ev)
	if !r.Success && d.stopped() {
		return r, false
	}
	return r, true
}

// wait sleeps for delay; it returns false when the dispatcher is closed
// meanwhile.
func (d *Dispatcher) wait(delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-d.stop:
		return false
	case <-timer.C:
		return true
	}
}

// stopped reports whether Close was called.
func (d *Dispatcher) stopped() bool {
	select {
	case <-d.stop:
		return true
	default:
		return false
	}
}

// warn logs msg with attrs at most once per warning interval for key.
func (d *Dispatcher) warn(ctx context.Context, key, msg string, attrs ...slog.Attr) {
	now := d.now()
	d.warnMu.Lock()
	last, seen := d.warned[key]
	if seen && now.Sub(last) < d.warnInterval {
		d.warnMu.Unlock()
		return
	}
	d.warned[key] = now
	d.warnMu.Unlock()
	d.logger.LogAttrs(ctx, slog.LevelWarn, msg, attrs...)
}

// Close stops the dispatcher: no delivery is queued nor attempted any
// more, the pending deliveries are abandoned (and counted as dropped), and
// the attempts in progress may end until ctx is done, when they are
// canceled; it then returns ctx.Err(). Calling it more than once is
// harmless.
func (d *Dispatcher) Close(ctx context.Context) error {
	d.mu.Lock()
	if !d.closed {
		d.closed = true
		close(d.stop)
	}
	d.mu.Unlock()
	done := make(chan struct{})
	go func() {
		d.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		d.cancelAttempt()
		return nil
	case <-ctx.Done():
		d.cancelAttempt()
		<-done
		return ctx.Err()
	}
}

// Delivered returns the number of deliveries that succeeded.
func (d *Dispatcher) Delivered() uint64 { return d.delivered.Load() }

// Failed returns the number of deliveries that failed after all their
// attempts.
func (d *Dispatcher) Failed() uint64 { return d.failed.Load() }

// Dropped returns the number of deliveries dropped: queue full, dispatcher
// closed, delivery abandoned at Close, tenant event without tenant,
// webhook of another owner, webhook unreadable, deleted, disabled or no
// longer subscribed before an attempt.
func (d *Dispatcher) Dropped() uint64 { return d.dropped.Load() }

// SkippedOpenCircuit returns the number of deliveries skipped because the
// circuit breaker of the webhook was open, when the event arrived or
// before an attempt.
func (d *Dispatcher) SkippedOpenCircuit() uint64 { return d.skipped.Load() }
