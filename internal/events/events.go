// Package events is the internal event bus of TransTeira (CLAUDE.md
// section 4): the components that decide something worth telling the
// outside world (an alert raised, a virus found, an audit or security log
// line written) publish an [Event], and the outputs subscribe to it
// (webhooks, syslog export, metrics).
//
// The bus is an output channel only. The audit log stays the official
// record, written synchronously in the transaction of the operation; an
// event is published once that transaction committed, never for an
// operation rolled back. Delivery is best effort: [Bus.Publish] never
// blocks the publisher, and an event a subscriber cannot keep up with is
// dropped for that subscriber and counted ([Bus.Dropped]).
//
// # Lifecycle
//
// The subscribers register with [Bus.Subscribe] before [Bus.Start]. Each
// one has its own bounded queue and goroutine, so that a slow subscriber
// never delays the others; it receives the events of its queue in
// publication order. [Bus.Close] stops accepting events and lets every
// subscriber drain its queue within the deadline of its context.
package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ed-fr/transteira/internal/id"
)

// Type is the type of an event. The alert types are the values of the
// OpenAPI WebhookEventType enumeration; the log types feed the log
// exports.
type Type string

// Alert event types (OpenAPI WebhookEventType).
const (
	// VirusDetected: the antivirus found a virus in a deposited file,
	// which was deleted.
	VirusDetected Type = "virus.detected"
	// AbuseThresholdExceeded: a sender exceeded an abuse threshold of the
	// tenant.
	AbuseThresholdExceeded Type = "abuse.threshold_exceeded"
	// AbuseUnusualActivity: a sender behaved unusually.
	AbuseUnusualActivity Type = "abuse.unusual_activity"
	// AbuseReported: a recipient reported a transfer as abusive.
	AbuseReported Type = "abuse.reported"
	// QuotaWarning: a tenant reached 80 % of its storage quota.
	QuotaWarning Type = "quota.warning"
	// QuotaReached: a tenant reached its storage quota.
	QuotaReached Type = "quota.reached"
	// DiskAlertRaised: the disk usage reached the alert threshold.
	DiskAlertRaised Type = "disk.alert_raised"
	// DiskAlertCleared: the disk usage fell back below the alert threshold.
	DiskAlertCleared Type = "disk.alert_cleared"
	// AntivirusAlertRaised: clamd stayed unreachable beyond the grace
	// period.
	AntivirusAlertRaised Type = "antivirus.alert_raised"
	// AntivirusAlertCleared: clamd answers again after a raised alert.
	AntivirusAlertCleared Type = "antivirus.alert_cleared"
	// MaintenanceEnabled: the super admin enabled the maintenance mode.
	MaintenanceEnabled Type = "maintenance.enabled"
	// MaintenanceDisabled: the super admin disabled the maintenance mode.
	MaintenanceDisabled Type = "maintenance.disabled"
	// MasterKeyRotationCompleted: every key was rewrapped under the new
	// master key.
	MasterKeyRotationCompleted Type = "master_key.rotation_completed"
	// MasterKeyRotationFailed: a master key rotation stopped on an error.
	MasterKeyRotationFailed Type = "master_key.rotation_failed"
)

// Log event types, which carry a [LogRecord].
const (
	// LogAudit: an audit event was committed to the audit log.
	LogAudit Type = "log.audit"
	// LogSecurity: a line was written to the security log.
	LogSecurity Type = "log.security"
)

// Severity is the severity of an event (OpenAPI WebhookEvent severity).
type Severity string

// Severities.
const (
	// SeverityInfo is an event that needs no action.
	SeverityInfo Severity = "info"
	// SeverityWarning is an event that may need an action soon.
	SeverityWarning Severity = "warning"
	// SeverityCritical is an event that needs an action now.
	SeverityCritical Severity = "critical"
)

// Event is something that happened, as published on the bus. It mirrors
// the OpenAPI WebhookEvent payload; the subscribers decide what they pass
// on (the addresses, for example, only when the tenant allows it). Every
// subscriber receives the same value: a handler must not modify its maps,
// slices or pointed-to structures.
type Event struct {
	// ID is the identifier of the event ("evt_" + ULID), set by
	// [Bus.Publish] when empty.
	ID string
	// Type is the type of the event.
	Type Type
	// Severity is its severity.
	Severity Severity
	// OccurredAt is when it happened, set by [Bus.Publish] when zero.
	OccurredAt time.Time
	// TenantID is the tenant of the event, "" for a system event.
	TenantID string
	// Counts are the counters of the event (for example files for
	// virus.detected, usedRatio and threshold for a quota or disk alert,
	// waitingTransfers and outageSeconds for an antivirus outage). Never
	// nil once published: [Bus.Publish] sets an empty map when it is.
	Counts map[string]float64
	// Addresses are the mail addresses concerned, nil when none.
	Addresses *Addresses
	// AdminPath is the path, on the administration host, of the page where
	// the event can be examined (for example "/admin/system"; "" for
	// none). The consumers prefix it with the configured administration
	// URL, never with a request host.
	AdminPath string
	// Log is the log line of a log.audit or log.security event, nil for
	// the other types.
	Log *LogRecord
}

// Addresses are the mail addresses concerned by an event.
type Addresses struct {
	// Sender is the sender of the transfer concerned.
	Sender string
	// Recipients are its recipients.
	Recipients []string
	// Reporter is the author of an abuse report.
	Reporter string
}

// Stream is the log a [LogRecord] comes from.
type Stream string

// Streams.
const (
	// StreamAudit is the audit log.
	StreamAudit Stream = "audit"
	// StreamSecurity is the security log.
	StreamSecurity Stream = "security"
)

// LogRecord is a line of the audit or the security log, carried by the
// log.audit and log.security events for the log exports (syslog).
type LogRecord struct {
	// Stream is the log of the line.
	Stream Stream
	// Time is the time of the line.
	Time time.Time
	// Tenant is the tenant of the line: its ID for an audit event, its
	// normalized FQDN as written in the security log; "" when none.
	Tenant string
	// Action is the audit action ("admin.login"...) or the security event
	// type ("unknown_fqdn"...).
	Action string
	// ActorKind and Actor identify who acted (audit only).
	ActorKind string
	Actor     string
	// IP is the client IP, the zero Addr when there is none.
	IP netip.Addr
	// ObjectKind and ObjectID identify the object of the action (audit
	// only).
	ObjectKind string
	ObjectID   string
	// AuditID is the identifier of the audit entry ("aud_" + ULID; audit
	// only).
	AuditID string
	// Details are the JSON details of the audit event, nil when none.
	Details json.RawMessage
	// Fields are the extra fields of the security event, in line order
	// (security only). Their values are raw, attacker-controlled text,
	// only truncated to securitylog.MaxValueLen bytes: a consumer must
	// escape them for its own format (the syslog export builds RFC 5424
	// structured data with its own escaping).
	Fields []Field
	// Line is the security log line exactly as written, without its line
	// feed (security only): already escaped by the security log format.
	Line string
}

// Field is an extra key and value of a security log line.
type Field struct {
	Key   string
	Value string
}

// Publisher publishes events. *Bus implements it; [Discard] drops them.
// Publish must never block.
type Publisher interface {
	Publish(ev Event)
}

// discard is the Publisher behind [Discard].
type discard struct{}

// Publish drops ev.
func (discard) Publish(Event) {}

// Discard is a Publisher that drops every event, for the components built
// without a bus (tests, local commands).
var Discard Publisher = discard{}

// OrDiscard returns p, or [Discard] when p is nil: the components accept
// an optional Publisher.
func OrDiscard(p Publisher) Publisher {
	if p == nil {
		return Discard
	}
	return p
}

// Administration paths of the events (Event.AdminPath).
const (
	// AdminPathSystem is the instance page (disk, antivirus, maintenance).
	AdminPathSystem = "/admin/system"
	// AdminPathMasterKey is the master key page.
	AdminPathMasterKey = "/admin/system/master-key"
)

// AdminPathTenantAudit returns the path of the audit page of tenant tid.
func AdminPathTenantAudit(tid string) string {
	return "/admin/tenants/" + tid + "/audit"
}

// Defaults.
const (
	// DefaultBuffer is the queue length of a subscriber registered with a
	// buffer of 0 or less.
	DefaultBuffer = 256
	// DefaultWarnInterval is the shortest delay between two warnings about
	// the events dropped for one subscriber.
	DefaultWarnInterval = time.Minute
)

var (
	// ErrStarted is returned by [Bus.Start] when the bus was already
	// started, and by [Bus.Subscribe] once it is.
	ErrStarted = errors.New("events: bus already started")
	// ErrClosed is returned once the bus was closed.
	ErrClosed = errors.New("events: bus closed")
	// ErrInvalidSubscriber is returned by [Bus.Subscribe] for an empty or
	// duplicate name or a nil handler.
	ErrInvalidSubscriber = errors.New("events: invalid subscriber")
)

// Options configure a [Bus]. The zero value is valid.
type Options struct {
	// WarnInterval is the shortest delay between two warnings about the
	// events dropped for one subscriber (DefaultWarnInterval).
	WarnInterval time.Duration
	// Now is the clock (time.Now).
	Now func() time.Time
	// Logger receives the drop warnings and the handler panics (discarded
	// when nil).
	Logger *slog.Logger
}

// subscriber is a registered subscriber.
type subscriber struct {
	name    string
	filter  func(Type) bool
	handler func(context.Context, Event)
	queue   chan Event
	dropped atomic.Uint64

	// warnMu guards the drop warnings: when the last one was logged and
	// the drops counted since.
	warnMu   sync.Mutex
	lastWarn time.Time
	pending  uint64
}

// Bus is the event bus. Its methods are safe for concurrent use.
type Bus struct {
	warnInterval time.Duration
	now          func() time.Time
	logger       *slog.Logger

	// mu guards the subscribers and the state; Publish holds it in read
	// mode, so that no queue is closed under a send.
	mu      sync.RWMutex
	subs    []*subscriber
	byName  map[string]*subscriber
	started bool
	closed  bool
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	done    chan struct{}
}

// New returns a bus that is not started yet.
func New(opts Options) *Bus {
	b := &Bus{
		warnInterval: opts.WarnInterval, now: opts.Now, logger: opts.Logger,
		byName: map[string]*subscriber{},
	}
	if b.warnInterval <= 0 {
		b.warnInterval = DefaultWarnInterval
	}
	if b.now == nil {
		b.now = time.Now
	}
	if b.logger == nil {
		b.logger = slog.New(slog.DiscardHandler)
	}
	return b
}

// Subscribe registers the subscriber name, which receives the events whose
// type filter accepts (every event when filter is nil) through handler,
// one at a time and in publication order, from a queue of buffer events
// (DefaultBuffer when buffer is 0 or less). It must be called before
// [Bus.Start]: it returns ErrStarted once started, ErrClosed once closed
// and ErrInvalidSubscriber for an empty or duplicate name or a nil
// handler. A panic of handler is recovered and logged.
func (b *Bus) Subscribe(name string, filter func(Type) bool, buffer int, handler func(context.Context, Event)) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	switch {
	case b.closed:
		return ErrClosed
	case b.started:
		return ErrStarted
	case name == "" || handler == nil:
		return fmt.Errorf("%w: a name and a handler are required", ErrInvalidSubscriber)
	case b.byName[name] != nil:
		return fmt.Errorf("%w: %q is already subscribed", ErrInvalidSubscriber, name)
	}
	if buffer <= 0 {
		buffer = DefaultBuffer
	}
	if filter == nil {
		filter = func(Type) bool { return true }
	}
	s := &subscriber{name: name, filter: filter, handler: handler, queue: make(chan Event, buffer)}
	b.subs = append(b.subs, s)
	b.byName[name] = s
	return nil
}

// Publish queues ev for every subscriber that accepts its type, setting
// its ID and OccurredAt when they are empty and Counts to an empty map
// when nil. It never blocks: when the
// queue of a subscriber is full, the event is dropped for that subscriber,
// counted ([Bus.Dropped]) and a warning is logged at most once per
// Options.WarnInterval. Events published before [Bus.Start] wait in the
// queues; events published once the bus is closed are dropped silently.
// A panic of a subscriber filter is recovered: the event is dropped for
// that subscriber and counted like a full queue, and the publisher never
// sees it. It is a no-op on a nil bus.
func (b *Bus) Publish(ev Event) {
	if b == nil {
		return
	}
	if ev.ID == "" {
		ev.ID = id.New(id.Event)
	}
	if ev.OccurredAt.IsZero() {
		ev.OccurredAt = b.now()
	}
	if ev.Counts == nil {
		ev.Counts = map[string]float64{}
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.closed {
		return
	}
	for _, s := range b.subs {
		accepted, ok := b.accepts(s, ev.Type)
		switch {
		case !ok:
			b.drop(s, ev.Type, "events: subscriber filter panicked, event dropped")
		case !accepted:
		default:
			select {
			case s.queue <- ev:
			default:
				b.drop(s, ev.Type, "events: subscriber queue full, events dropped")
			}
		}
	}
}

// accepts reports whether the filter of s accepts the type t; ok is false
// when the filter panicked (the panic is recovered).
func (b *Bus) accepts(s *subscriber, t Type) (accepted, ok bool) {
	defer func() {
		if r := recover(); r != nil {
			accepted, ok = false, false
		}
	}()
	return s.filter(t), true
}

// drop counts an event of type t dropped for s and logs msg, at most once
// per warning interval, with the number of events dropped since the last
// warning.
func (b *Bus) drop(s *subscriber, t Type, msg string) {
	total := s.dropped.Add(1)
	now := b.now()
	s.warnMu.Lock()
	s.pending++
	if !s.lastWarn.IsZero() && now.Sub(s.lastWarn) < b.warnInterval {
		s.warnMu.Unlock()
		return
	}
	n := s.pending
	s.lastWarn, s.pending = now, 0
	s.warnMu.Unlock()
	b.logger.Warn(msg,
		slog.String("subscriber", s.name), slog.String("type", string(t)),
		slog.Uint64("dropped", n), slog.Uint64("dropped_total", total), slog.Int("queue", cap(s.queue)))
}

// Dropped returns the number of events dropped for the subscriber name
// because its queue was full or its filter panicked, 0 for an unknown
// name or a nil bus.
func (b *Bus) Dropped(name string) uint64 {
	if b == nil {
		return 0
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	if s := b.byName[name]; s != nil {
		return s.dropped.Load()
	}
	return 0
}

// Start starts the goroutine of every subscriber, which delivers its
// queue until [Bus.Close]. The cancellation of ctx does not stop them
// (only its values are kept, in the context given to the handlers), so
// that the shutdown order stays under the control of Close. It returns
// ErrStarted when already started and ErrClosed once closed.
func (b *Bus) Start(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	switch {
	case b.closed:
		return ErrClosed
	case b.started:
		return ErrStarted
	}
	b.started = true
	ctx, b.cancel = context.WithCancel(context.WithoutCancel(ctx))
	b.done = make(chan struct{})
	for _, s := range b.subs {
		b.wg.Go(func() { b.run(ctx, s) })
	}
	go func() {
		b.wg.Wait()
		close(b.done)
	}()
	return nil
}

// run delivers the queue of s until it is closed and drained. Once ctx is
// canceled (the Close deadline passed), the remaining events are
// discarded without calling the handler.
func (b *Bus) run(ctx context.Context, s *subscriber) {
	for ev := range s.queue {
		if ctx.Err() != nil {
			continue
		}
		b.deliver(ctx, s, ev)
	}
}

// deliver calls the handler of s with ev, recovering and logging a panic.
func (b *Bus) deliver(ctx context.Context, s *subscriber, ev Event) {
	defer func() {
		if r := recover(); r != nil {
			b.logger.ErrorContext(ctx, "events: subscriber panicked",
				slog.String("subscriber", s.name), slog.String("type", string(ev.Type)),
				slog.String("event", ev.ID), slog.Any("panic", r))
		}
	}()
	s.handler(ctx, ev)
}

// Close stops accepting events and, when started, waits for every
// subscriber to drain its queue, at most until ctx is done: it then
// cancels the context of the handlers, discards the events left and
// returns ctx.Err(). Calling it more than once is harmless.
func (b *Bus) Close(ctx context.Context) error {
	b.mu.Lock()
	if !b.closed {
		b.closed = true
		for _, s := range b.subs {
			close(s.queue)
		}
	}
	started, done, cancel := b.started, b.done, b.cancel
	b.mu.Unlock()
	if !started {
		return nil
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		cancel()
		return ctx.Err()
	}
}

// Recorder is a Publisher keeping every event it is given, in order. It
// lets the tests of the publishing components check what they publish. It
// is safe for concurrent use.
type Recorder struct {
	mu     sync.Mutex
	events []Event
}

// Publish keeps ev.
func (r *Recorder) Publish(ev Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev)
}

// Events returns a copy of the events kept so far.
func (r *Recorder) Events() []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Event(nil), r.events...)
}

// OfType returns the events kept so far whose type is t.
func (r *Recorder) OfType(t Type) []Event {
	var out []Event
	for _, ev := range r.Events() {
		if ev.Type == t {
			out = append(out, ev)
		}
	}
	return out
}
