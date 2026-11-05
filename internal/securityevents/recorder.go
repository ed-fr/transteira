// Package securityevents keeps a copy of the security log in the database
// (V2, decision P56, threat model T-283 to T-285), so that a delegated
// admin or an auditor can read the security events of a tenant from the
// administration, and the super admin those of the whole instance, without
// shell access.
//
// The security log file stays the reference: it is written first, in its
// unchanged format, and remains the only source of fail2ban and CrowdSec.
// Its writer (internal/securitylog) publishes every line written as an
// events.LogSecurity event; the [Recorder] subscribes to them on the event
// bus and writes them to the store asynchronously, never on the path of
// the request:
//
//   - the bus gives the recorder a bounded queue (QueueSize events): when
//     it is full, the event is dropped for the database copy only and
//     counted ([Recorder.Dropped], with the rows the recorder itself
//     could not keep, reported by the metrics as
//     transteira_events_dropped_total{subscriber="security_events"});
//   - identical events (same type, reason, client IP and tenant) within
//     Window of the first one are coalesced into one row, whose
//     occurrences and last_seen_at grow;
//   - the pending rows are written by batch, one transaction per batch,
//     every FlushInterval, when MaxPending rows are waiting, and when the
//     recorder is closed.
//
// A row only holds closed tokens and bounded values: the event type, the
// reason field when it is a token, the client IP, the tenant ID and, in a
// small JSON object, the scope, purpose and host fields; the host only
// when it is a well-formed host name (lowercase [a-z0-9.-], the grammar
// of a tenant in the security log). Any other field is dropped, and so is
// any value holding an "@" (or a backslash, which could spell one as a
// JSON escape): no e-mail address nor attacker free text is ever stored
// (T-285).
//
// [Service] lists the events for the administration: a tenant's own events
// for the administrators attached to it (never an event without tenant),
// the whole instance for the super admin.
package securityevents

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ed-fr/transteira/internal/events"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// SubscriberName is the name of the recorder on the event bus.
const SubscriberName = "security_events"

// Defaults of [Options].
const (
	// DefaultWindow is the coalescing window: an event identical to one
	// first seen less than this ago is counted in the same row.
	DefaultWindow = time.Minute
	// DefaultFlushInterval is the delay between two writes of the pending
	// rows.
	DefaultFlushInterval = 2 * time.Second
	// DefaultQueueSize is the length of the bus queue of the recorder.
	DefaultQueueSize = 4096
	// DefaultMaxPending is the number of rows kept in memory (waiting to
	// be written, or written and still open to coalescing) beyond which
	// the recorder writes at once and forgets the rows already written.
	DefaultMaxPending = store.MaxSecurityEventBatch
	// DefaultWriteTimeout bounds one write of the pending rows.
	DefaultWriteTimeout = 10 * time.Second
)

// detailKeys are the fields of a security log line kept in the details of
// a row, in this order. Every other field is dropped.
var detailKeys = []string{securitylog.KeyScope, securitylog.KeyPurpose, securitylog.KeyHost}

// Store writes the rows. *store.SecurityEvents implements it.
type Store interface {
	Save(ctx context.Context, batch []store.SecurityEvent) ([]store.SecurityEvent, error)
}

// Compile-time check that the repository fits.
var _ Store = (*store.SecurityEvents)(nil)

// Options configure a [Recorder]. Store is required.
type Options struct {
	// Store writes the rows.
	Store Store
	// Window is the coalescing window (DefaultWindow).
	Window time.Duration
	// FlushInterval is the delay between two writes (DefaultFlushInterval).
	FlushInterval time.Duration
	// QueueSize is the length of the bus queue (DefaultQueueSize).
	QueueSize int
	// MaxPending bounds the rows kept in memory (DefaultMaxPending, at most
	// store.MaxSecurityEventBatch).
	MaxPending int
	// WriteTimeout bounds one write (DefaultWriteTimeout).
	WriteTimeout time.Duration
	// Now is the clock (time.Now).
	Now func() time.Time
	// Logger receives the write failures (discarded when nil).
	Logger *slog.Logger
}

// key identifies the events coalesced into one row.
type key struct {
	typ, reason, ip string
	tenant          tenant.ID
}

// group is a row being coalesced.
type group struct {
	ev store.SecurityEvent
	// opened is when the row was opened, on the recorder clock: it stays
	// open to coalescing until opened + window.
	opened time.Time
	// dirty marks a row whose last state is not written yet.
	dirty bool
}

// Recorder writes the security events published on the bus to the store.
// Its methods are safe for concurrent use.
type Recorder struct {
	store         Store
	window        time.Duration
	flushInterval time.Duration
	queueSize     int
	maxPending    int
	writeTimeout  time.Duration
	now           func() time.Time
	logger        *slog.Logger

	// mu guards the rows and is held during a write, so that writes never
	// overlap and a row is never written twice.
	mu sync.Mutex
	// open holds the rows still open to coalescing, by key.
	open map[key]*group
	// closed holds the rows whose window ended before their last state
	// was written.
	closed []*group

	bus     *events.Bus
	dropped atomic.Uint64
	written atomic.Uint64

	stopOnce sync.Once
	stop     chan struct{}
	done     chan struct{}
	started  atomic.Bool
}

// New returns a recorder, not registered nor started.
func New(opts Options) (*Recorder, error) {
	if opts.Store == nil {
		return nil, errors.New("securityevents: a store is required")
	}
	r := &Recorder{
		store: opts.Store, window: opts.Window, flushInterval: opts.FlushInterval, queueSize: opts.QueueSize,
		maxPending: opts.MaxPending, writeTimeout: opts.WriteTimeout, now: opts.Now, logger: opts.Logger,
		open: map[key]*group{}, stop: make(chan struct{}), done: make(chan struct{}),
	}
	if r.window <= 0 {
		r.window = DefaultWindow
	}
	if r.flushInterval <= 0 {
		r.flushInterval = DefaultFlushInterval
	}
	if r.queueSize <= 0 {
		r.queueSize = DefaultQueueSize
	}
	if r.maxPending <= 0 || r.maxPending > store.MaxSecurityEventBatch {
		r.maxPending = DefaultMaxPending
	}
	if r.writeTimeout <= 0 {
		r.writeTimeout = DefaultWriteTimeout
	}
	if r.now == nil {
		r.now = time.Now
	}
	if r.logger == nil {
		r.logger = slog.New(slog.DiscardHandler)
	}
	return r, nil
}

// Register subscribes the recorder to the security log events of bus. It
// must be called before the bus starts; it returns the error of
// [events.Bus.Subscribe].
func (r *Recorder) Register(bus *events.Bus) error {
	if err := bus.Subscribe(SubscriberName, accepts, r.queueSize, r.handle); err != nil {
		return err
	}
	r.bus = bus
	return nil
}

// accepts keeps the security log events only.
func accepts(t events.Type) bool { return t == events.LogSecurity }

// handle receives one bus event.
func (r *Recorder) handle(ctx context.Context, ev events.Event) {
	if ev.Log != nil {
		r.Add(ctx, *ev.Log)
	}
}

// Start starts the periodic writes, until [Recorder.Close]. Starting twice
// is a no-op.
func (r *Recorder) Start() {
	if !r.started.CompareAndSwap(false, true) {
		return
	}
	go r.run()
}

// run writes the pending rows every flush interval until stop is closed.
func (r *Recorder) run() {
	defer close(r.done)
	ticker := time.NewTicker(r.flushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-r.stop:
			return
		case <-ticker.C:
			_ = r.Flush(context.Background())
		}
	}
}

// Close stops the periodic writes and writes the pending rows, within the
// deadline of ctx. The bus must be closed first, so that the events it
// still delivers are counted in. Closing twice is harmless.
func (r *Recorder) Close(ctx context.Context) error {
	r.stopOnce.Do(func() { close(r.stop) })
	if r.started.Load() {
		select {
		case <-r.done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return r.Flush(ctx)
}

// Dropped returns the number of security events left out of the database:
// dropped by the bus because the queue of the recorder was full, or by
// the recorder when its rows could not be written. The security log file
// holds them all.
func (r *Recorder) Dropped() uint64 {
	n := r.dropped.Load()
	if r.bus != nil {
		n += r.bus.Dropped(SubscriberName)
	}
	return n
}

// Written returns the number of rows inserted.
func (r *Recorder) Written() uint64 { return r.written.Load() }

// Add counts rec, a line of the security log, in the row of its key,
// opening a new row when there is none open. It may wait for a flush in
// progress (the rows are locked during a write, bounded by WriteTimeout);
// called from the bus, that wait is absorbed by the queue of the
// recorder, never by the request. It writes to the store itself only when
// MaxPending rows are waiting, which it then writes first. A record of
// another stream or with a malformed type is ignored.
func (r *Recorder) Add(ctx context.Context, rec events.LogRecord) {
	ev, ok := mapRecord(rec)
	if !ok {
		return
	}
	k := key{typ: ev.Type, reason: ev.Reason, tenant: ev.TenantID}
	if ev.IP.IsValid() {
		k.ip = ev.IP.String()
	}
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	if g := r.open[k]; g != nil {
		if now.Sub(g.opened) < r.window {
			g.ev.Occurrences++
			if ev.At.After(g.ev.LastSeenAt) {
				g.ev.LastSeenAt = ev.At
			}
			g.dirty = true
			return
		}
		delete(r.open, k)
		if g.dirty {
			r.closed = append(r.closed, g)
		}
	}
	if r.pendingLocked() >= r.maxPending {
		_ = r.flushLocked(ctx) // a failure is logged, the rows kept
		// Every row was written: forget the ones still open to coalescing
		// rather than refusing the new one (a later identical event opens
		// a new row).
		for kk, g := range r.open {
			if !g.dirty {
				delete(r.open, kk)
			}
		}
		if r.pendingLocked() >= r.maxPending {
			r.dropped.Add(1)
			return
		}
	}
	r.open[k] = &group{ev: ev, opened: now, dirty: true}
}

// pendingLocked returns the number of rows kept in memory.
func (r *Recorder) pendingLocked() int { return len(r.open) + len(r.closed) }

// Flush writes the pending rows in one transaction and forgets the rows
// whose window is over. A failed write keeps them for the next one and is
// returned; a batch the store refuses as malformed is dropped (counted).
func (r *Recorder) Flush(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.flushLocked(ctx)
}

// flushLocked implements Flush; r.mu is held.
func (r *Recorder) flushLocked(ctx context.Context) error {
	now := r.now()
	var batch []*group
	batch = append(batch, r.closed...)
	for _, g := range r.open {
		if g.dirty {
			batch = append(batch, g)
		}
	}
	err := r.write(ctx, batch)
	switch {
	case err == nil:
		r.closed = nil
	case errors.Is(err, store.ErrInvalid):
		// Never expected (the records are mapped to valid rows): drop the
		// batch rather than retry it forever.
		r.dropped.Add(uint64(len(batch)))
		for _, g := range batch {
			g.dirty = false
		}
		r.closed = nil
	default:
		r.logger.WarnContext(ctx, "securityevents: write failed, kept for the next attempt",
			slog.Int("rows", len(batch)), slog.String("error", err.Error()))
	}
	for k, g := range r.open {
		if !g.dirty && now.Sub(g.opened) >= r.window {
			delete(r.open, k)
		}
	}
	return err
}

// write saves batch and records the identifiers of the inserted rows.
func (r *Recorder) write(ctx context.Context, batch []*group) error {
	if len(batch) == 0 {
		return nil
	}
	rows := make([]store.SecurityEvent, len(batch))
	for i, g := range batch {
		rows[i] = g.ev
	}
	wctx, cancel := context.WithTimeout(ctx, r.writeTimeout)
	defer cancel()
	saved, err := r.store.Save(wctx, rows)
	if err != nil {
		return fmt.Errorf("securityevents: %w", err)
	}
	for i, g := range batch {
		if g.ev.ID == "" {
			r.written.Add(1)
		}
		g.ev.ID, g.ev.At, g.ev.LastSeenAt = saved[i].ID, saved[i].At, saved[i].LastSeenAt
		g.ev.Occurrences = saved[i].Occurrences
		g.dirty = false
	}
	return nil
}

// mapRecord returns the row of rec, false when rec is not a security log
// line with a valid type.
func mapRecord(rec events.LogRecord) (store.SecurityEvent, bool) {
	if rec.Stream != events.StreamSecurity || !store.ValidSecurityEventType(rec.Action) {
		return store.SecurityEvent{}, false
	}
	ev := store.SecurityEvent{Type: rec.Action, At: rec.Time, LastSeenAt: rec.Time, Occurrences: 1}
	if ev.At.IsZero() {
		return store.SecurityEvent{}, false
	}
	if tid := tenant.ID(rec.TenantID); tid != "" && tid.Validate() == nil {
		ev.TenantID = tid
	}
	if rec.IP.IsValid() {
		ev.IP = rec.IP.Unmap().WithZone("")
	}
	details := map[string]string{}
	for _, f := range rec.Fields {
		switch {
		case strings.ContainsAny(f.Value, `@\`):
			// Never an e-mail address (T-285), not even one spelled as a
			// JSON escape (the store refuses "\u0040" in the details).
		case f.Key == securitylog.KeyReason:
			if ev.Reason == "" && len(f.Value) <= store.MaxSecurityEventReasonLen && store.ValidSecurityEventType(f.Value) {
				ev.Reason = f.Value
			}
		case f.Key == securitylog.KeyHost && !validHost(f.Value):
			// The Host header of an unknown FQDN is attacker text: kept
			// only when it is a well-formed host name (T-285).
		default:
			for _, k := range detailKeys {
				if f.Key == k {
					if _, seen := details[k]; !seen && f.Value != "" {
						details[k] = f.Value
					}
				}
			}
		}
	}
	ev.Details = encodeDetails(details)
	return ev, true
}

// validHost reports whether h has the grammar of a tenant FQDN in the
// security log (securitylog writes a tenant only in this form): 1 to
// securitylog.MaxTenantLen bytes of [a-z0-9.-].
func validHost(h string) bool {
	if h == "" || len(h) > securitylog.MaxTenantLen {
		return false
	}
	for i := range len(h) {
		c := h[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '.' && c != '-' {
			return false
		}
	}
	return true
}

// encodeDetails returns the JSON object of details, in the order of
// detailKeys, leaving out the last fields while it exceeds
// store.MaxSecurityEventDetailsBytes; nil when empty.
func encodeDetails(details map[string]string) json.RawMessage {
	keys := make([]string, 0, len(detailKeys))
	for _, k := range detailKeys {
		if _, ok := details[k]; ok {
			keys = append(keys, k)
		}
	}
	for len(keys) > 0 {
		var b bytes.Buffer
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			b.Write(jsonString(k))
			b.WriteByte(':')
			b.Write(jsonString(details[k]))
		}
		b.WriteByte('}')
		if b.Len() <= store.MaxSecurityEventDetailsBytes {
			return b.Bytes()
		}
		keys = keys[:len(keys)-1]
	}
	return nil
}

// jsonString returns s as a JSON string, without HTML escaping.
func jsonString(s string) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s) // a string always encodes
	return bytes.TrimSuffix(b.Bytes(), []byte("\n"))
}
