package securityevents

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/events"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

const tenantA = tenant.ID("ten_01JAB00000000000000ENT1TYA")

var t0 = time.Date(2026, 11, 5, 9, 0, 0, 0, time.UTC)

// fakeStore records the batches; err, when set, fails the next saves.
type fakeStore struct {
	mu      sync.Mutex
	batches [][]store.SecurityEvent
	rows    map[string]store.SecurityEvent
	err     error
	n       int
}

func (f *fakeStore) Save(_ context.Context, batch []store.SecurityEvent) ([]store.SecurityEvent, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	if f.rows == nil {
		f.rows = map[string]store.SecurityEvent{}
	}
	out := make([]store.SecurityEvent, len(batch))
	for i, ev := range batch {
		if ev.ID == "" {
			f.n++
			ev.ID = fmt.Sprintf("sev_%026d", f.n)
		}
		f.rows[ev.ID] = ev
		out[i] = ev
	}
	f.batches = append(f.batches, out)
	return out, nil
}

// all returns the stored rows.
func (f *fakeStore) all() map[string]store.SecurityEvent {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]store.SecurityEvent{}
	for k, v := range f.rows {
		out[k] = v
	}
	return out
}

// clock is a settable clock.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func newRecorder(t *testing.T, st Store, c *clock, opts Options) *Recorder {
	t.Helper()
	opts.Store, opts.Now = st, c.Now
	r, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// rec returns a security log record of typ at at.
func rec(typ securitylog.EventType, ip string, tid tenant.ID, at time.Time, fields ...events.Field) events.LogRecord {
	r := events.LogRecord{Stream: events.StreamSecurity, Time: at, Action: string(typ), TenantID: string(tid), Fields: fields}
	if ip != "" {
		r.IP = netip.MustParseAddr(ip)
	}
	return r
}

func TestNewDefaults(t *testing.T) {
	t.Parallel()
	if _, err := New(Options{}); err == nil {
		t.Fatal("New without a store succeeded")
	}
	r, err := New(Options{Store: &fakeStore{}, MaxPending: store.MaxSecurityEventBatch + 1})
	if err != nil {
		t.Fatal(err)
	}
	if r.window != DefaultWindow || r.flushInterval != DefaultFlushInterval || r.queueSize != DefaultQueueSize ||
		r.maxPending != DefaultMaxPending || r.writeTimeout != DefaultWriteTimeout || r.now == nil || r.logger == nil {
		t.Fatalf("defaults = %+v", r)
	}
}

func TestMapRecord(t *testing.T) {
	t.Parallel()
	ip := "::ffff:203.0.113.7"
	for name, tc := range map[string]struct {
		rec     events.LogRecord
		ok      bool
		reason  string
		details string
		tid     tenant.ID
	}{
		"reason and tenant": {rec(securitylog.DepositRefused, ip, tenantA, t0, events.Field{Key: "reason", Value: "ip"}), true, "ip", "", tenantA},
		"details in order": {
			rec(securitylog.RateLimited, ip, "", t0,
				events.Field{Key: "host", Value: "h.example.net"}, events.Field{Key: "scope", Value: "code"},
				events.Field{Key: "purpose", Value: "recipient"}, events.Field{Key: "scope", Value: "second"}),
			true, "", `{"scope":"code","purpose":"recipient","host":"h.example.net"}`, "",
		},
		"html kept as is":      {rec(securitylog.RateLimited, ip, "", t0, events.Field{Key: "scope", Value: `<a>&"`}), true, "", `{"scope":"<a>&\""}`, ""},
		"host kept":            {rec(securitylog.UnknownFQDN, ip, "", t0, events.Field{Key: "host", Value: "transfer.unknown-1.example.net"}), true, "", `{"host":"transfer.unknown-1.example.net"}`, ""},
		"host free text":       {rec(securitylog.UnknownFQDN, ip, "", t0, events.Field{Key: "host", Value: `<a>&"`}), true, "", "", ""},
		"host uppercase":       {rec(securitylog.UnknownFQDN, ip, "", t0, events.Field{Key: "host", Value: "Evil.Example.NET"}), true, "", "", ""},
		"host with port":       {rec(securitylog.UnknownFQDN, ip, "", t0, events.Field{Key: "host", Value: "evil.example.net:8443"}), true, "", "", ""},
		"host with space":      {rec(securitylog.UnknownFQDN, ip, "", t0, events.Field{Key: "host", Value: "call me now"}), true, "", "", ""},
		"host too long":        {rec(securitylog.UnknownFQDN, ip, "", t0, events.Field{Key: "host", Value: strings.Repeat("a", securitylog.MaxTenantLen+1)}), true, "", "", ""},
		"host longest":         {rec(securitylog.UnknownFQDN, ip, "", t0, events.Field{Key: "host", Value: strings.Repeat("a", securitylog.MaxTenantLen)}), true, "", `{"host":"` + strings.Repeat("a", securitylog.MaxTenantLen) + `"}`, ""},
		"address dropped":      {rec(securitylog.UnknownFQDN, ip, "", t0, events.Field{Key: "host", Value: "alice@example.com"}), true, "", "", ""},
		"address reason":       {rec(securitylog.AdminLoginFailed, ip, "", t0, events.Field{Key: "reason", Value: "a@b"}), true, "", "", ""},
		"free text reason":     {rec(securitylog.AdminLoginFailed, ip, "", t0, events.Field{Key: "reason", Value: "Not A Token"}), true, "", "", ""},
		"unknown field":        {rec(securitylog.SSOFailed, ip, "", t0, events.Field{Key: "email", Value: "x"}, events.Field{Key: "reason", Value: "state_invalid"}), true, "state_invalid", "", ""},
		"empty value":          {rec(securitylog.RateLimited, ip, "", t0, events.Field{Key: "scope", Value: ""}), true, "", "", ""},
		"malformed tenant":     {rec(securitylog.RateLimited, ip, "ten_bogus", t0), true, "", "", ""},
		"no ip":                {rec(securitylog.RateLimited, "", tenantA, t0), true, "", "", tenantA},
		"audit stream ignored": {events.LogRecord{Stream: events.StreamAudit, Time: t0, Action: "rate_limited"}, false, "", "", ""},
		"bad type":             {rec("Bad Type", ip, "", t0), false, "", "", ""},
		"no time":              {rec(securitylog.RateLimited, ip, "", time.Time{}), false, "", "", ""},
	} {
		ev, ok := mapRecord(tc.rec)
		if ok != tc.ok {
			t.Errorf("%s: ok = %v", name, ok)
			continue
		}
		if !ok {
			continue
		}
		if ev.Reason != tc.reason || string(ev.Details) != tc.details || ev.TenantID != tc.tid || ev.Occurrences != 1 ||
			!ev.At.Equal(t0) || !ev.LastSeenAt.Equal(t0) {
			t.Errorf("%s: mapped %+v (details %s)", name, ev, ev.Details)
		}
		if tc.rec.IP.IsValid() && ev.IP != netip.MustParseAddr("203.0.113.7") {
			t.Errorf("%s: ip %v", name, ev.IP)
		}
	}
}

func TestEncodeDetailsBounded(t *testing.T) {
	t.Parallel()
	// Control characters are escaped six times their size: three long
	// values cannot all fit.
	long := strings.Repeat("\x01", securitylog.MaxValueLen)
	got := encodeDetails(map[string]string{"scope": long, "purpose": long, "host": long})
	if len(got) > store.MaxSecurityEventDetailsBytes || !json.Valid(got) {
		t.Fatalf("details of %d bytes: %s", len(got), got)
	}
	var m map[string]string
	_ = json.Unmarshal(got, &m)
	if _, ok := m["host"]; ok || m["scope"] != long {
		t.Fatalf("kept %v", m)
	}
	if encodeDetails(map[string]string{}) != nil {
		t.Fatal("empty details are not nil")
	}
	huge := strings.Repeat("\x01", store.MaxSecurityEventDetailsBytes)
	if got := encodeDetails(map[string]string{"scope": huge}); got != nil {
		t.Fatalf("oversized details kept: %d bytes", len(got))
	}
}

// TestNoAddressStored feeds every field a record may carry, each with an
// address, and checks that no stored value holds an "@" (T-285).
func TestNoAddressStored(t *testing.T) {
	t.Parallel()
	st := &fakeStore{}
	c := &clock{now: t0}
	r := newRecorder(t, st, c, Options{})
	ctx := context.Background()
	for i, typ := range []securitylog.EventType{
		securitylog.VerificationCodeInvalid, securitylog.TransferPasswordInvalid, securitylog.AdminLoginFailed,
		securitylog.APITokenInvalid, securitylog.UnknownFQDN, securitylog.DepositRefused, securitylog.RateLimited,
		securitylog.MetricsTokenInvalid, securitylog.AccessLinkInvalid, securitylog.ProvisioningTokenInvalid,
		securitylog.SSOFailed, securitylog.DropLinkInvalid,
	} {
		var fields []events.Field
		for _, k := range []string{"reason", "scope", "purpose", "host", "email", "sender", "to"} {
			fields = append(fields, events.Field{Key: k, Value: "alice@entity-a.example.com"})
		}
		r.Add(ctx, rec(typ, fmt.Sprintf("192.0.2.%d", i+1), tenantA, t0, fields...))
	}
	if err := r.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	rows := st.all()
	if len(rows) != 12 {
		t.Fatalf("%d rows", len(rows))
	}
	for _, ev := range rows {
		if strings.Contains(fmt.Sprintf("%v %s %s %s", ev, ev.Reason, ev.Details, ev.Type), "@") {
			t.Errorf("stored an address: %+v (details %s)", ev, ev.Details)
		}
	}
}

func TestCoalescing(t *testing.T) {
	t.Parallel()
	st := &fakeStore{}
	c := &clock{now: t0}
	r := newRecorder(t, st, c, Options{Window: time.Minute})
	ctx := context.Background()
	reason := events.Field{Key: "reason", Value: "password"}
	add := func(ip string, tid tenant.ID, at time.Time, f ...events.Field) {
		r.Add(ctx, rec(securitylog.AdminLoginFailed, ip, tid, at, f...))
	}
	// Five identical events, and four that differ by one member of the key.
	for i := range 5 {
		add("192.0.2.1", tenantA, t0.Add(time.Duration(i)*time.Second), reason)
	}
	add("192.0.2.2", tenantA, t0, reason)                                      // ip
	add("192.0.2.1", "", t0, reason)                                           // tenant
	add("192.0.2.1", tenantA, t0, events.Field{Key: "reason", Value: "totp"})  // reason
	r.Add(ctx, rec(securitylog.RateLimited, "192.0.2.1", tenantA, t0, reason)) // type
	add("192.0.2.1", tenantA, t0.Add(-time.Second), reason)                    // earlier: last kept
	if err := r.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	rows := st.all()
	if len(rows) != 5 {
		t.Fatalf("%d rows, want 5: %+v", len(rows), rows)
	}
	var main store.SecurityEvent
	for _, ev := range rows {
		if ev.Occurrences > 1 {
			main = ev
		}
	}
	if main.Occurrences != 6 || !main.At.Equal(t0) || !main.LastSeenAt.Equal(t0.Add(4*time.Second)) {
		t.Fatalf("coalesced row = %+v", main)
	}

	// Within the window, the written row is updated in place.
	c.add(30 * time.Second)
	add("192.0.2.1", tenantA, t0.Add(30*time.Second), reason)
	if err := r.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	last := st.batches[len(st.batches)-1]
	if len(last) != 1 || last[0].ID != main.ID || last[0].Occurrences != 7 || !last[0].LastSeenAt.Equal(t0.Add(30*time.Second)) {
		t.Fatalf("update batch = %+v", last)
	}
	// A flush with nothing new writes nothing.
	n := len(st.batches)
	if err := r.Flush(ctx); err != nil || len(st.batches) != n {
		t.Fatalf("idle flush wrote %d batches, %v", len(st.batches)-n, err)
	}

	// Past the window, an identical event opens a new row, and the rows
	// whose window is over are forgotten.
	c.add(31 * time.Second)
	add("192.0.2.1", tenantA, t0.Add(61*time.Second), reason)
	if err := r.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if rows := st.all(); len(rows) != 6 {
		t.Fatalf("%d rows after the window, want 6", len(rows))
	}
	r.mu.Lock()
	open := len(r.open)
	r.mu.Unlock()
	if open != 1 {
		t.Fatalf("%d rows kept in memory, want 1", open)
	}
	if r.Written() != 6 || r.Dropped() != 0 {
		t.Fatalf("written %d dropped %d", r.Written(), r.Dropped())
	}
}

// TestWindowClosedBeforeWrite checks that a row whose window ended before
// its last state was written is still written, with its final count.
func TestWindowClosedBeforeWrite(t *testing.T) {
	t.Parallel()
	st := &fakeStore{}
	c := &clock{now: t0}
	r := newRecorder(t, st, c, Options{Window: time.Minute})
	ctx := context.Background()
	r.Add(ctx, rec(securitylog.RateLimited, "192.0.2.1", tenantA, t0))
	r.Add(ctx, rec(securitylog.RateLimited, "192.0.2.1", tenantA, t0))
	c.add(2 * time.Minute)
	r.Add(ctx, rec(securitylog.RateLimited, "192.0.2.1", tenantA, t0.Add(2*time.Minute)))
	if err := r.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	rows := st.all()
	if len(rows) != 2 {
		t.Fatalf("%d rows, want 2", len(rows))
	}
	total := 0
	for _, ev := range rows {
		total += ev.Occurrences
	}
	if total != 3 {
		t.Fatalf("occurrences %d, want 3", total)
	}
}

func TestMaxPending(t *testing.T) {
	t.Parallel()
	st := &fakeStore{}
	c := &clock{now: t0}
	r := newRecorder(t, st, c, Options{MaxPending: 3})
	ctx := context.Background()
	for i := range 7 {
		r.Add(ctx, rec(securitylog.UnknownFQDN, fmt.Sprintf("192.0.2.%d", i+1), "", t0))
	}
	// The fourth and seventh events wrote the waiting rows first: nothing
	// was dropped.
	if len(st.batches) != 2 || r.Dropped() != 0 {
		t.Fatalf("%d batches, %d dropped", len(st.batches), r.Dropped())
	}
	if err := r.Flush(ctx); err != nil || len(st.all()) != 7 {
		t.Fatalf("%d rows, %v", len(st.all()), err)
	}

	// The store fails: the rows are kept, the new ones are dropped and
	// counted once the bound is reached.
	st.mu.Lock()
	st.err = errors.New("database locked")
	st.mu.Unlock()
	for i := range 5 {
		r.Add(ctx, rec(securitylog.RateLimited, fmt.Sprintf("198.51.100.%d", i+1), "", t0))
	}
	if r.Dropped() != 2 {
		t.Fatalf("dropped %d, want 2", r.Dropped())
	}
	if err := r.Flush(ctx); err == nil {
		t.Fatal("Flush on a failing store = nil")
	}
	st.mu.Lock()
	st.err = nil
	st.mu.Unlock()
	if err := r.Flush(ctx); err != nil || len(st.all()) != 10 {
		t.Fatalf("after recovery: %d rows, %v", len(st.all()), err)
	}
}

func TestMalformedBatchDropped(t *testing.T) {
	t.Parallel()
	st := &fakeStore{err: fmt.Errorf("save: %w", store.ErrInvalid)}
	r := newRecorder(t, st, &clock{now: t0}, Options{})
	ctx := context.Background()
	r.Add(ctx, rec(securitylog.RateLimited, "192.0.2.1", "", t0))
	r.Add(ctx, rec(securitylog.UnknownFQDN, "192.0.2.1", "", t0))
	if err := r.Flush(ctx); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("Flush = %v", err)
	}
	if r.Dropped() != 2 {
		t.Fatalf("dropped %d", r.Dropped())
	}
	st.mu.Lock()
	st.err = nil
	st.mu.Unlock()
	if err := r.Flush(ctx); err != nil || len(st.batches) != 0 {
		t.Fatalf("a dropped batch was retried: %d batches, %v", len(st.batches), err)
	}
}

// TestBusLifecycle runs the recorder on a real bus: the events published
// before the close are written by Close, and an event dropped by a full
// queue is counted.
func TestBusLifecycle(t *testing.T) {
	t.Parallel()
	st := &fakeStore{}
	r := newRecorder(t, st, &clock{now: t0}, Options{FlushInterval: time.Hour, QueueSize: 2})
	bus := events.New(events.Options{})
	if err := r.Register(bus); err != nil {
		t.Fatal(err)
	}
	if err := r.Register(bus); err == nil {
		t.Fatal("second Register succeeded")
	}
	// Published before the bus starts: the queue holds two events, the
	// third one is dropped.
	bus.Publish(events.Event{Type: events.LogSecurity})  // no record: ignored
	bus.Publish(events.Event{Type: events.QuotaWarning}) // not subscribed
	for i := range 2 {
		ev := rec(securitylog.RateLimited, fmt.Sprintf("192.0.2.%d", i+1), tenantA, t0)
		bus.Publish(events.Event{Type: events.LogSecurity, Log: &ev})
	}
	if err := bus.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	r.Start()
	r.Start() // no-op
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := bus.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(ctx); err != nil {
		t.Fatalf("second Close = %v", err)
	}
	if rows := st.all(); len(rows) != 1 || r.Dropped() != 1 {
		t.Fatalf("%d rows, %d dropped", len(rows), r.Dropped())
	}
}

// TestPeriodicFlush checks that the rows are written without a close.
func TestPeriodicFlush(t *testing.T) {
	t.Parallel()
	st := &fakeStore{}
	r := newRecorder(t, st, &clock{now: t0}, Options{FlushInterval: 5 * time.Millisecond})
	r.Start()
	t.Cleanup(func() { _ = r.Close(context.Background()) })
	r.Add(context.Background(), rec(securitylog.RateLimited, "192.0.2.1", "", t0))
	deadline := time.Now().Add(5 * time.Second)
	for len(st.all()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no periodic write")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestCloseDeadline checks that Close gives up at the deadline of its
// context when the periodic writer is stuck in a write.
func TestCloseDeadline(t *testing.T) {
	t.Parallel()
	st := &blockingStore{release: make(chan struct{}), entered: make(chan struct{}, 1)}
	r := newRecorder(t, st, &clock{now: t0}, Options{FlushInterval: time.Millisecond, WriteTimeout: time.Hour})
	r.Add(context.Background(), rec(securitylog.RateLimited, "192.0.2.1", "", t0))
	r.Start()
	<-st.entered
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := r.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Close = %v", err)
	}
	close(st.release)
}

// blockingStore blocks every save until release is closed.
type blockingStore struct {
	release chan struct{}
	entered chan struct{}
}

func (b *blockingStore) Save(_ context.Context, batch []store.SecurityEvent) ([]store.SecurityEvent, error) {
	select {
	case b.entered <- struct{}{}:
	default:
	}
	<-b.release
	out := make([]store.SecurityEvent, len(batch))
	for i, ev := range batch {
		ev.ID = id.New(id.SecurityEvent)
		out[i] = ev
	}
	return out, nil
}

func TestAddIgnoresOtherRecords(t *testing.T) {
	t.Parallel()
	st := &fakeStore{}
	r := newRecorder(t, st, &clock{now: t0}, Options{})
	r.Add(context.Background(), events.LogRecord{Stream: events.StreamAudit, Time: t0, Action: "admin.login"})
	if err := r.Flush(context.Background()); err != nil || len(st.batches) != 0 {
		t.Fatalf("an audit record was written: %d batches, %v", len(st.batches), err)
	}
}
