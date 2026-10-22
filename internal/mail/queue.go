package mail

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/textproto"
	"strings"
	"sync"
	"time"
)

// Queue defaults.
const (
	// DefaultQueueSize is the capacity used when NewQueue gets size <= 0
	// (TT_MAIL_QUEUE_SIZE).
	DefaultQueueSize = 1000
	// DefaultWorkers is the number of delivery goroutines.
	DefaultWorkers = 4
	// DefaultTenantConcurrency is the number of deliveries one tenant may
	// have in flight at once.
	DefaultTenantConcurrency = 1
	// DefaultRetryDelay is the back-off before the single retry.
	DefaultRetryDelay = 2 * time.Second
	// DefaultBreakerThreshold is the number of consecutive failed delivery
	// attempts of a tenant that opens its circuit breaker.
	DefaultBreakerThreshold = 3
	// DefaultBreakerCooldown is how long an open circuit fails fast.
	DefaultBreakerCooldown = time.Minute
	// maxAttempts is the number of delivery attempts of a job.
	maxAttempts = 2
)

// ErrCircuitOpen is returned by Enqueue when the SMTP server of the tenant
// failed repeatedly and its circuit breaker is open: the job is refused
// without trying until the cool-down ends, and while the single probe job of
// the half-open circuit is pending. The caller should answer "mail
// unavailable" (503).
var ErrCircuitOpen = errors.New("mail: tenant SMTP circuit open")

// Job is one mail to deliver asynchronously.
//
// Settings carries the clear-text SMTP password, unsealed by the caller. A
// job lives in memory only (the queue is never persisted), so the password
// never leaves the process memory; a job still queued at shutdown is lost,
// which is acceptable for verification codes and invitations that the user
// can request again.
type Job struct {
	// TenantID identifies the tenant: fairness, limits and circuit breaker
	// are per TenantID, which also appears in logs.
	TenantID string
	// Template names the template the message was rendered from, for logs.
	Template string
	// Settings is the SMTP configuration of the tenant.
	Settings Settings
	// Message is the mail to send.
	Message Message
}

// QueueOptions tunes a [Queue]. Zero values select the defaults.
type QueueOptions struct {
	// Workers is the number of delivery goroutines (default DefaultWorkers).
	Workers int
	// TenantConcurrency caps the deliveries of one tenant in flight at once
	// (default DefaultTenantConcurrency), so that a slow SMTP server only
	// ties up that many workers.
	TenantConcurrency int
	// TenantQueued caps the jobs one tenant may have waiting (default: a
	// quarter of the queue size, at least 1). Beyond it, Enqueue returns
	// ErrQueueFull for that tenant only.
	TenantQueued int
	// RetryDelay is the back-off before the retry (default DefaultRetryDelay).
	RetryDelay time.Duration
	// BreakerThreshold is the number of consecutive failed attempts that
	// opens the circuit of a tenant (default DefaultBreakerThreshold).
	BreakerThreshold int
	// BreakerCooldown is how long an open circuit refuses jobs (default
	// DefaultBreakerCooldown). Afterwards one job is tried: success closes
	// the circuit, failure opens it again.
	BreakerCooldown time.Duration
}

// tenantState is the per-tenant part of the queue.
type tenantState struct {
	jobs      []Job
	active    int       // deliveries in flight
	failures  int       // consecutive failed attempts
	openUntil time.Time // zero: closed; now < openUntil: open; else half-open
	probing   bool      // half-open: the single probe job is queued or in flight
}

// idle reports whether the state carries nothing worth keeping.
func (ts *tenantState) idle() bool {
	return len(ts.jobs) == 0 && ts.active == 0 && ts.failures == 0
}

// Queue is a bounded, fair, in-memory mail queue: HTTP handlers enqueue and
// return at once, and workers deliver in the background, so a slow or
// unreachable SMTP server never blocks a request (threat T-89).
//
// Fairness between tenants (one tenant must not delay the verification
// codes of the others):
//   - each tenant has its own FIFO, served round-robin;
//   - a tenant has at most TenantConcurrency deliveries in flight, so an
//     unreachable server holds at most that many workers;
//   - a tenant has at most TenantQueued waiting jobs: a flood fills its own
//     share and gets ErrQueueFull, the others still enqueue;
//   - after BreakerThreshold consecutive failed attempts (connection,
//     timeout, TLS, authentication; an SMTP rejection by a reachable server
//     does not count), the tenant's circuit opens for BreakerCooldown: its
//     queued jobs are dropped at once and Enqueue returns ErrCircuitOpen.
//     After the cool-down the circuit is half-open: Enqueue accepts exactly
//     one probe job and refuses the others with ErrCircuitOpen until the
//     probe succeeds (the circuit closes) or fails (it reopens). One warning
//     is logged when it opens, with the number of accepted jobs it dropped,
//     and one line when it closes.
//
// Each job is tried at most twice. Failures are logged with the tenant, the
// template and a hash of the recipients, never with the body, the subject or
// the address itself.
type Queue struct {
	sender Sender
	logger *slog.Logger
	opts   QueueOptions
	size   int
	now    func() time.Time

	mu      sync.Mutex
	cond    *sync.Cond
	tenants map[string]*tenantState
	order   []string // tenants with waiting jobs, round-robin order
	total   int      // waiting jobs, all tenants
	closed  bool

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewQueue starts a queue of the given total capacity (DefaultQueueSize when
// size <= 0) delivering through sender. A nil logger discards the logs.
func NewQueue(sender Sender, size int, logger *slog.Logger, opts QueueOptions) *Queue {
	if size <= 0 {
		size = DefaultQueueSize
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	if opts.Workers <= 0 {
		opts.Workers = DefaultWorkers
	}
	if opts.TenantConcurrency <= 0 {
		opts.TenantConcurrency = DefaultTenantConcurrency
	}
	if opts.TenantQueued <= 0 {
		opts.TenantQueued = max(size/4, 1)
	}
	if opts.RetryDelay <= 0 {
		opts.RetryDelay = DefaultRetryDelay
	}
	if opts.BreakerThreshold <= 0 {
		opts.BreakerThreshold = DefaultBreakerThreshold
	}
	if opts.BreakerCooldown <= 0 {
		opts.BreakerCooldown = DefaultBreakerCooldown
	}
	ctx, cancel := context.WithCancel(context.Background())
	q := &Queue{
		sender:  sender,
		logger:  logger,
		opts:    opts,
		size:    size,
		now:     time.Now,
		tenants: map[string]*tenantState{},
		ctx:     ctx,
		cancel:  cancel,
	}
	q.cond = sync.NewCond(&q.mu)
	q.wg.Add(opts.Workers)
	for range opts.Workers {
		go q.worker()
	}
	return q
}

// Enqueue validates the job (settings and message, so that the caller gets
// configuration errors synchronously) and queues it without blocking. It
// returns [ErrQueueFull] when the queue or the tenant's share is full,
// [ErrCircuitOpen] while the tenant's circuit is open and [ErrQueueClosed]
// after Close.
func (q *Queue) Enqueue(job Job) error {
	if err := job.Settings.Validate(); err != nil {
		return err
	}
	if _, err := job.Message.validate(); err != nil {
		return err
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return ErrQueueClosed
	}
	ts := q.tenants[job.TenantID]
	if ts == nil {
		ts = &tenantState{}
		q.tenants[job.TenantID] = ts
	}
	if !ts.openUntil.IsZero() {
		// Open, or half-open with its probe already taken.
		if q.now().Before(ts.openUntil) || ts.probing {
			return ErrCircuitOpen
		}
	}
	if q.total >= q.size || len(ts.jobs) >= q.opts.TenantQueued {
		if ts.idle() {
			delete(q.tenants, job.TenantID)
		}
		return ErrQueueFull
	}
	if !ts.openUntil.IsZero() {
		ts.probing = true // this job is the half-open probe
	}
	if len(ts.jobs) == 0 {
		q.order = append(q.order, job.TenantID)
	}
	ts.jobs = append(ts.jobs, job)
	q.total++
	q.cond.Signal()
	return nil
}

// Len returns the number of jobs waiting, all tenants.
func (q *Queue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.total
}

// Close stops accepting jobs and waits for the workers to deliver what is
// queued. If ctx ends first, in-flight deliveries are canceled, the jobs
// still queued are dropped (and counted in the log) and ctx.Err() is
// returned. Close is idempotent.
func (q *Queue) Close(ctx context.Context) error {
	q.mu.Lock()
	q.closed = true
	q.cond.Broadcast()
	q.mu.Unlock()

	done := make(chan struct{})
	go func() {
		q.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		q.cancel()
		return nil
	case <-ctx.Done():
		q.cancel()
		<-done
		return ctx.Err()
	}
}

// next blocks until a job may be delivered and returns it with the tenant
// marked active; ok is false when the queue is closed and empty.
func (q *Queue) next() (job Job, ok bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for {
		for i, id := range q.order {
			ts := q.tenants[id]
			if ts.active >= q.opts.TenantConcurrency {
				continue
			}
			// Clear the slot: the backing array must not keep the job, and
			// with it the SMTP password, alive.
			job = ts.jobs[0]
			ts.jobs[0] = Job{}
			ts.jobs = ts.jobs[1:]
			ts.active++
			q.total--
			// Round-robin: the tenant goes to the back if it still waits.
			q.order = append(q.order[:i:i], q.order[i+1:]...)
			if len(ts.jobs) > 0 {
				q.order = append(q.order, id)
			}
			return job, true
		}
		if q.closed && q.total == 0 {
			return Job{}, false
		}
		q.cond.Wait()
	}
}

// done releases the tenant slot taken by next.
func (q *Queue) done(tenantID string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	ts := q.tenants[tenantID]
	ts.active--
	if ts.idle() && ts.openUntil.IsZero() {
		delete(q.tenants, tenantID)
	}
	q.cond.Broadcast()
}

// worker delivers jobs until the queue is closed and drained.
func (q *Queue) worker() {
	defer q.wg.Done()
	for {
		job, ok := q.next()
		if !ok {
			return
		}
		q.process(job)
		q.done(job.TenantID)
	}
}

// process handles one dequeued job. Jobs of an open circuit never get here:
// they are dropped when it opens.
func (q *Queue) process(job Job) {
	if q.ctx.Err() != nil {
		q.logger.LogAttrs(context.Background(), slog.LevelWarn, "mail dropped at shutdown", jobAttrs(job)...)
		return
	}
	q.deliver(job)
}

// circuitOpen reports whether the tenant's circuit is open now.
func (q *Queue) circuitOpen(tenantID string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.now().Before(q.tenants[tenantID].openUntil)
}

// record updates the circuit breaker of a tenant after one attempt and
// reports whether the circuit is now open (the job must not be retried).
func (q *Queue) record(tenantID string, err error) (tripped bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	ts := q.tenants[tenantID]
	if err == nil || !countsAsFailure(err) {
		if !ts.openUntil.IsZero() {
			q.logger.LogAttrs(context.Background(), slog.LevelInfo, "mail circuit closed", slog.String("tenant", tenantID))
		}
		ts.failures, ts.openUntil, ts.probing = 0, time.Time{}, false
		return false
	}
	ts.failures++
	if ts.failures < q.opts.BreakerThreshold {
		return false
	}
	alreadyTripped := !ts.openUntil.IsZero()
	ts.openUntil, ts.probing = q.now().Add(q.opts.BreakerCooldown), false
	dropped := q.purge(tenantID, ts)
	if !alreadyTripped || dropped > 0 {
		// These jobs were accepted (the request was answered) and are lost:
		// the operator must know, once per incident.
		q.logger.LogAttrs(context.Background(), slog.LevelWarn, "mail circuit open",
			slog.String("tenant", tenantID),
			slog.Int("failures", ts.failures),
			slog.Int("dropped", dropped),
			slog.Duration("cooldown", q.opts.BreakerCooldown))
	}
	return true
}

// purge drops the waiting jobs of a tenant, clearing their slots, and
// returns how many there were. The caller holds q.mu.
func (q *Queue) purge(tenantID string, ts *tenantState) int {
	n := len(ts.jobs)
	if n == 0 {
		return 0
	}
	clear(ts.jobs)
	ts.jobs = nil
	q.total -= n
	for i, id := range q.order {
		if id == tenantID {
			q.order = append(q.order[:i:i], q.order[i+1:]...)
			break
		}
	}
	return n
}

// countsAsFailure reports whether a failed attempt says the SMTP service of
// the tenant is unusable: anything but a reply of a reachable server (for
// example a rejected recipient) and the shutdown of the queue.
func countsAsFailure(err error) bool {
	var te *textproto.Error
	if errors.As(err, &te) || errors.Is(err, context.Canceled) {
		return false
	}
	return true
}

// deliver tries a job at most maxAttempts times.
func (q *Queue) deliver(job Job) {
	var err error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if attempt > 1 {
			t := time.NewTimer(q.opts.RetryDelay)
			select {
			case <-t.C:
			case <-q.ctx.Done():
				t.Stop()
			}
		}
		if q.ctx.Err() != nil {
			err = q.ctx.Err()
			break
		}
		err = q.sender.Send(q.ctx, job.Settings, job.Message)
		tripped := q.record(job.TenantID, err)
		if tripped {
			break // the circuit is open: no retry, the job is logged as failed
		}
		if err == nil {
			q.logger.LogAttrs(context.Background(), slog.LevelDebug, "mail sent",
				append(jobAttrs(job), slog.Int("attempt", attempt))...)
			return
		}
	}
	q.logger.LogAttrs(context.Background(), slog.LevelError, "mail delivery failed",
		append(jobAttrs(job), slog.String("error", redactAddresses(err.Error(), job.Message.To)))...)
}

// jobAttrs returns the log attributes of a job: never the subject, the body
// or a clear-text address.
func jobAttrs(job Job) []slog.Attr {
	hashes := make([]string, len(job.Message.To))
	for i, a := range job.Message.To {
		hashes[i] = AddressHash(a)
	}
	return []slog.Attr{
		slog.String("tenant", job.TenantID),
		slog.String("template", job.Template),
		slog.Any("recipients", hashes),
	}
}

// addressHashKey keys [AddressHash]. It is drawn from crypto/rand when the
// process starts and only ever held in memory, so that a pseudonym cannot
// be linked to a known address once the process is gone (after a GDPR
// erasure, for instance), nor computed by anyone reading the logs.
var addressHashKey = newAddressHashKey()

// newAddressHashKey returns a random 32-byte key (crypto/rand.Read never
// fails and always fills its buffer).
func newAddressHashKey() []byte {
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	return k
}

// AddressHash returns a short pseudonym of an e-mail address for logs: the
// first 16 hex digits of the HMAC-SHA256 of the trimmed, lowercased address,
// keyed by a random per-process key. It is stable within one process run
// only: an operator can correlate the entries of one run (and, with the
// running process, those of a known address), but the hashes of two runs
// differ and a hash cannot be recomputed from an address once the process
// is gone, which keeps the logs unlinkable after an erasure.
func AddressHash(addr string) string {
	m := hmac.New(sha256.New, addressHashKey)
	m.Write([]byte(strings.ToLower(strings.TrimSpace(addr))))
	return hex.EncodeToString(m.Sum(nil)[:8])
}

// redactAddresses replaces the recipients, which an SMTP server often
// echoes in its rejections, by their hashes.
func redactAddresses(msg string, to []string) string {
	for _, a := range to {
		if a == "" {
			continue
		}
		msg = replaceFold(msg, a, fmt.Sprintf("[addr:%s]", AddressHash(a)))
	}
	return msg
}

// replaceFold replaces every ASCII case-insensitive occurrence of old in s.
func replaceFold(s, old, repl string) string {
	lower, lowerOld := strings.ToLower(s), strings.ToLower(old)
	if len(lower) != len(s) || len(lowerOld) != len(old) {
		// Non-ASCII case mapping changed lengths: fall back to exact match.
		return strings.ReplaceAll(s, old, repl)
	}
	var b strings.Builder
	for {
		i := strings.Index(lower, lowerOld)
		if i < 0 {
			b.WriteString(s)
			return b.String()
		}
		b.WriteString(s[:i])
		b.WriteString(repl)
		s, lower = s[i+len(old):], lower[i+len(old):]
	}
}
