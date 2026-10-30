package avselftest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/antivirus"
	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/store"
)

// reply is one answer of the fake engine.
type reply struct {
	res antivirus.Result
	err error
}

// fakeEngine answers the scans with its current reply, records what it
// was sent, and can block until released.
type fakeEngine struct {
	mu      sync.Mutex
	reply   reply
	scans   int
	pings   int
	payload []byte
	block   chan struct{} // when non-nil, Scan waits for it (or ctx)
	started chan struct{} // signaled at every Scan start when non-nil
	// stubborn makes Scan wait for block even when ctx is done.
	stubborn bool
}

func (f *fakeEngine) set(r reply) {
	f.mu.Lock()
	f.reply = r
	f.mu.Unlock()
}

func (f *fakeEngine) Scan(ctx context.Context, r io.Reader, size int64) (antivirus.Result, error) {
	b, _ := io.ReadAll(r)
	f.mu.Lock()
	f.scans++
	f.payload = b
	block, started, rep, stubborn := f.block, f.started, f.reply, f.stubborn
	f.mu.Unlock()
	if int64(len(b)) != size {
		return antivirus.Result{}, antivirus.ErrSource
	}
	if started != nil {
		started <- struct{}{}
	}
	if block != nil && stubborn {
		<-block
	} else if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return antivirus.Result{}, fmt.Errorf("%w: %w", antivirus.ErrUnavailable, ctx.Err())
		}
	}
	return rep.res, rep.err
}

func (f *fakeEngine) Ping(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pings++
	return nil
}

func (f *fakeEngine) scanCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.scans
}

// fakeAuditor records the events.
type fakeAuditor struct {
	mu     sync.Mutex
	events []audit.Event
	err    error
}

func (a *fakeAuditor) Record(_ context.Context, ev audit.Event) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, ev)
	return a.err
}

func (a *fakeAuditor) list() []audit.Event {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]audit.Event(nil), a.events...)
}

// fakeTimers hands out channels for the retry delays and records them.
type fakeTimers struct {
	mu     sync.Mutex
	delays []time.Duration
	chans  []chan time.Time
	asked  chan time.Duration
}

func newFakeTimers() *fakeTimers { return &fakeTimers{asked: make(chan time.Duration, 64)} }

func (t *fakeTimers) after(d time.Duration) <-chan time.Time {
	c := make(chan time.Time, 1)
	t.mu.Lock()
	t.delays = append(t.delays, d)
	t.chans = append(t.chans, c)
	t.mu.Unlock()
	t.asked <- d
	return c
}

// fire fires the last timer handed out.
func (t *fakeTimers) fire() {
	t.mu.Lock()
	c := t.chans[len(t.chans)-1]
	t.mu.Unlock()
	c <- time.Time{}
}

// next waits for the next timer request.
func (t *fakeTimers) next(tb testing.TB) time.Duration {
	tb.Helper()
	select {
	case d := <-t.asked:
		return d
	case <-time.After(5 * time.Second):
		tb.Fatal("no retry timer requested")
		return 0
	}
}

var (
	detected    = reply{res: antivirus.Result{Verdict: antivirus.Infected, Signature: "Eicar-Test-Signature"}}
	clean       = reply{res: antivirus.Result{Verdict: antivirus.Clean}}
	unavailable = reply{err: fmt.Errorf("%w: dial refused", antivirus.ErrUnavailable)}
	protocol    = reply{err: fmt.Errorf("%w: garbage", antivirus.ErrProtocol)}
)

func superAdmin() adminauth.Principal {
	return adminauth.Principal{
		SessionID: "as_1", State: store.SessionAuthenticated,
		Admin: adminauth.Account{Username: "root", Role: store.RoleSuperAdmin},
	}
}

func delegated() adminauth.Principal {
	p := superAdmin()
	p.Admin.Role = store.RoleDelegatedAdmin
	p.Admin.Username = "deleg"
	return p
}

// clock is a fake clock advancing by step at every call.
func clock(step time.Duration) func() time.Time {
	var n atomic.Int64
	base := time.Date(2026, 10, 30, 8, 0, 0, 0, time.FixedZone("x", 3600))
	return func() time.Time { return base.Add(time.Duration(n.Add(1)) * step) }
}

func newTestService(eng *fakeEngine, aud *fakeAuditor, timers *fakeTimers, logs *bytes.Buffer) *Service {
	opts := Options{Engine: "clamd", Audit: aud, Now: clock(10 * time.Millisecond)}
	if timers != nil {
		opts.After = timers.after
	}
	if logs != nil {
		opts.Logger = slog.New(slog.NewTextHandler(logs, nil))
	}
	if aud == nil {
		opts.Audit = nil
	}
	return New(eng, opts)
}

func TestGateClosedUntilPass(t *testing.T) {
	eng := &fakeEngine{}
	eng.set(clean)
	s := newTestService(eng, nil, nil, nil)
	g := s.Gate()
	if g.Open() || s.Passed() {
		t.Fatal("gate open before any test")
	}
	if _, ok := s.Last(); ok {
		t.Fatal("Last before any test")
	}
	_, err := g.Scan(t.Context(), strings.NewReader("abc"), 3)
	if !errors.Is(err, antivirus.ErrUnavailable) || !errors.Is(err, ErrNotPassed) ||
		err.Error() != "antivirus: engine unavailable: EICAR self-test not passed" {
		t.Fatalf("Scan closed: %v", err)
	}
	if err := g.Ping(t.Context()); !errors.Is(err, antivirus.ErrUnavailable) {
		t.Fatalf("Ping closed: %v", err)
	}
	if eng.scanCount() != 0 || eng.pings != 0 {
		t.Fatal("closed gate reached the engine")
	}
	// A not_detected test keeps it closed.
	r, err := s.Test(t.Context(), superAdmin(), netip.Addr{})
	if err != nil || r.Outcome != OutcomeNotDetected || g.Open() {
		t.Fatalf("Test clean = %+v, %v", r, err)
	}
	eng.set(detected)
	r, err = s.Test(t.Context(), superAdmin(), netip.Addr{})
	if err != nil || !r.Passed() || !g.Open() || !s.Passed() {
		t.Fatalf("Test detected = %+v, %v", r, err)
	}
	if r.Signature != "Eicar-Test-Signature" || r.Engine != "clamd" || r.Trigger != TriggerAdmin ||
		r.Duration != 10*time.Millisecond || r.TestedAt.Location() != time.UTC {
		t.Fatalf("result = %+v", r)
	}
	if !bytes.Equal(eng.payload, antivirus.EICAR()) {
		t.Fatal("engine not sent EICAR")
	}
	eng.set(clean)
	if res, err := g.Scan(t.Context(), strings.NewReader("abc"), 3); err != nil || res.Verdict != antivirus.Clean {
		t.Fatalf("open Scan = %v, %v", res, err)
	}
	if err := g.Ping(t.Context()); err != nil || eng.pings != 1 {
		t.Fatalf("open Ping = %v", err)
	}
	if last, ok := s.Last(); !ok || last != r {
		t.Fatalf("Last = %+v", last)
	}
}

func TestOutcomes(t *testing.T) {
	tests := []struct {
		name string
		rep  reply
		want Outcome
	}{
		{"detected", detected, OutcomeDetected},
		{"clean", clean, OutcomeNotDetected},
		{"too large", reply{res: antivirus.Result{Verdict: antivirus.TooLarge}}, OutcomeNotDetected},
		{"unavailable", unavailable, OutcomeUnavailable},
		{"protocol", protocol, OutcomeError},
		{"timeout", reply{err: antivirus.ErrTimeout}, OutcomeError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eng := &fakeEngine{}
			eng.set(tt.rep)
			s := newTestService(eng, nil, nil, nil)
			r, err := s.Test(t.Context(), superAdmin(), netip.Addr{})
			if err != nil || r.Outcome != tt.want || s.Passed() != (tt.want == OutcomeDetected) {
				t.Fatalf("got %+v, %v", r, err)
			}
			if tt.want != OutcomeDetected && r.Signature != "" {
				t.Fatal("signature kept on failure")
			}
		})
	}
}

func TestTestAuthorization(t *testing.T) {
	eng := &fakeEngine{}
	eng.set(detected)
	s := newTestService(eng, nil, nil, nil)
	if _, err := s.Test(t.Context(), delegated(), netip.Addr{}); !errors.Is(err, adminauth.ErrForbidden) {
		t.Fatalf("delegated: %v", err)
	}
	if _, err := s.Test(t.Context(), adminauth.Principal{}, netip.Addr{}); !errors.Is(err, adminauth.ErrUnauthenticated) {
		t.Fatalf("anonymous: %v", err)
	}
	if eng.scanCount() != 0 {
		t.Fatal("refused test reached the engine")
	}
}

func TestDisabled(t *testing.T) {
	s := New(nil, Options{Engine: "none"})
	if !s.Disabled() || s.Gate() != nil || s.Passed() {
		t.Fatal("disabled service has a gate")
	}
	if _, err := s.Test(t.Context(), superAdmin(), netip.Addr{}); !errors.Is(err, ErrDisabled) {
		t.Fatalf("Test: %v", err)
	}
	// The role is checked first.
	if _, err := s.Test(t.Context(), delegated(), netip.Addr{}); !errors.Is(err, adminauth.ErrForbidden) {
		t.Fatalf("Test delegated: %v", err)
	}
	if _, ok := s.Last(); ok {
		t.Fatal("Last with none")
	}
	s.Run(t.Context()) // returns at once
	if err := s.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestRunRetriesWithBackoffUntilPass(t *testing.T) {
	eng := &fakeEngine{}
	eng.set(unavailable)
	aud := &fakeAuditor{}
	timers := newFakeTimers()
	var logs bytes.Buffer
	var logMu sync.Mutex
	s := New(eng, Options{
		Engine: "icap", Audit: aud, After: timers.after, Now: clock(time.Millisecond),
		Logger: slog.New(slog.NewTextHandler(&lockedWriter{w: &logs, mu: &logMu}, nil)),
	})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()

	want := []time.Duration{
		15 * time.Second, 30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute,
		8 * time.Minute, 10 * time.Minute, 10 * time.Minute,
	}
	for i, w := range want {
		if d := timers.next(t); d != w {
			t.Fatalf("delay %d = %v, want %v", i, d, w)
		}
		if i == 3 {
			eng.set(clean) // outcome change: audited
		}
		if i == len(want)-1 {
			eng.set(detected)
		}
		timers.fire()
	}
	waitFor(t, s.Passed)
	if eng.scanCount() != len(want)+1 {
		t.Fatalf("scans = %d", eng.scanCount())
	}
	last, _ := s.Last()
	if last.Trigger != TriggerStartup || last.Engine != "icap" {
		t.Fatalf("last = %+v", last)
	}
	// Audit: first (unavailable), change to not_detected, change to detected.
	evs := aud.list()
	var outcomes []string
	for _, ev := range evs {
		if ev.Action != audit.ActionAntivirusSelfTest || ev.ActorKind != store.ActorSystem ||
			ev.Actor != audit.ActorAntivirus || ev.ObjectKind != audit.ObjectSystem || ev.ObjectID != "antivirus" ||
			ev.TenantID != "" || ev.Details["engine"] != "icap" || ev.Details["trigger"] != "startup" {
			t.Fatalf("event = %+v", ev)
		}
		outcomes = append(outcomes, ev.Details["outcome"].(string))
	}
	if strings.Join(outcomes, ",") != "unavailable,not_detected,detected" {
		t.Fatalf("audited outcomes = %v", outcomes)
	}
	// No more test after a pass.
	select {
	case d := <-timers.asked:
		t.Fatalf("timer after pass: %v", d)
	case <-time.After(20 * time.Millisecond):
	}
	cancel()
	<-done
	logMu.Lock()
	out := logs.String()
	logMu.Unlock()
	if !strings.Contains(out, "level=ERROR") || !strings.Contains(out, "level=INFO") ||
		!strings.Contains(out, "engine=icap") || !strings.Contains(out, "outcome=detected") {
		t.Fatalf("logs = %s", out)
	}
}

type lockedWriter struct {
	w  io.Writer
	mu *sync.Mutex
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestOnDemandFailureClosesAndRestartsRetries(t *testing.T) {
	eng := &fakeEngine{}
	eng.set(detected)
	aud := &fakeAuditor{}
	timers := newFakeTimers()
	s := newTestService(eng, aud, timers, nil)
	if err := s.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, s.Passed)

	eng.set(clean)
	r, err := s.Test(t.Context(), superAdmin(), netip.MustParseAddr("192.0.2.7"))
	if err != nil || r.Outcome != OutcomeNotDetected || s.Passed() {
		t.Fatalf("Test = %+v, %v", r, err)
	}
	// The retries restart after RetryMin, not at once.
	if d := timers.next(t); d != RetryMin {
		t.Fatalf("delay = %v", d)
	}
	if n := eng.scanCount(); n != 2 {
		t.Fatalf("scans before the timer = %d", n)
	}
	eng.set(detected)
	timers.fire()
	waitFor(t, s.Passed)

	evs := aud.list()
	if len(evs) != 3 {
		t.Fatalf("events = %+v", evs)
	}
	adm := evs[1]
	if adm.ActorKind != store.ActorAdmin || adm.Actor != "root" || adm.IP != netip.MustParseAddr("192.0.2.7") ||
		adm.Details["trigger"] != "admin" || adm.Details["outcome"] != "not_detected" {
		t.Fatalf("admin event = %+v", adm)
	}
	if evs[2].Details["trigger"] != "startup" || evs[2].Details["outcome"] != "detected" {
		t.Fatalf("retry event = %+v", evs[2])
	}
	if err := s.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := s.Start(t.Context()); !errors.Is(err, ErrClosed) {
		t.Fatalf("Start after Close: %v", err)
	}
}

func TestOnDemandPassStopsRetries(t *testing.T) {
	eng := &fakeEngine{}
	eng.set(unavailable)
	timers := newFakeTimers()
	s := newTestService(eng, &fakeAuditor{}, timers, nil)
	if err := s.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := s.Start(t.Context()); !errors.Is(err, ErrStarted) {
		t.Fatalf("second Start: %v", err)
	}
	timers.next(t) // waiting for the first retry
	eng.set(detected)
	if r, err := s.Test(t.Context(), superAdmin(), netip.Addr{}); err != nil || !r.Passed() {
		t.Fatalf("Test = %+v, %v", r, err)
	}
	waitFor(t, s.Passed)
	// The retry loop stops without testing again, even when its timer fires.
	timers.fire()
	time.Sleep(20 * time.Millisecond)
	if n := eng.scanCount(); n != 2 {
		t.Fatalf("scans = %d", n)
	}
	// A failure on demand while idle: retries restart after RetryMin; a
	// second failure during the wait does not reset it, a pass stops it.
	eng.set(clean)
	if _, err := s.Test(t.Context(), superAdmin(), netip.Addr{}); err != nil {
		t.Fatal(err)
	}
	timers.next(t)
	if _, err := s.Test(t.Context(), superAdmin(), netip.Addr{}); err != nil {
		t.Fatal(err)
	}
	eng.set(detected)
	if _, err := s.Test(t.Context(), superAdmin(), netip.Addr{}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, s.Passed)
	if err := s.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestSingleflight(t *testing.T) {
	eng := &fakeEngine{block: make(chan struct{}), started: make(chan struct{}, 4)}
	eng.set(detected)
	s := newTestService(eng, &fakeAuditor{}, nil, nil)
	const callers = 5
	results := make(chan Result, callers)
	var wg sync.WaitGroup
	wg.Go(func() {
		r, err := s.Test(t.Context(), superAdmin(), netip.Addr{})
		if err != nil {
			t.Error(err)
		}
		results <- r
	})
	<-eng.started
	for range callers - 1 {
		wg.Go(func() {
			r, err := s.Test(t.Context(), superAdmin(), netip.Addr{})
			if err != nil {
				t.Error(err)
			}
			results <- r
		})
	}
	// Let the late callers join the call in flight.
	time.Sleep(20 * time.Millisecond)
	close(eng.block)
	wg.Wait()
	close(results)
	for r := range results {
		if !r.Passed() {
			t.Fatalf("result = %+v", r)
		}
	}
	if n := eng.scanCount(); n != 1 {
		t.Fatalf("scans = %d, want 1", n)
	}
}

func TestCallerContextDone(t *testing.T) {
	eng := &fakeEngine{block: make(chan struct{}), started: make(chan struct{}, 1)}
	eng.set(detected)
	s := newTestService(eng, &fakeAuditor{}, nil, nil)
	ctx, cancel := context.WithCancel(t.Context())
	errc := make(chan error, 1)
	go func() {
		_, err := s.Test(ctx, superAdmin(), netip.Addr{})
		errc <- err
	}()
	<-eng.started
	cancel()
	if err := <-errc; !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	// The test goes on and still updates the gate.
	close(eng.block)
	waitFor(t, s.Passed)
}

func TestCloseCancelsTestWithoutRecording(t *testing.T) {
	eng := &fakeEngine{block: make(chan struct{}), started: make(chan struct{}, 1)}
	eng.set(detected)
	aud := &fakeAuditor{}
	s := newTestService(eng, aud, nil, nil)
	if err := s.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	<-eng.started
	if err := s.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Last(); ok || len(aud.list()) != 0 {
		t.Fatal("canceled test recorded")
	}
	// A test on demand after Close is canceled too.
	close(eng.block)
	if _, err := s.Test(t.Context(), superAdmin(), netip.Addr{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Test after Close: %v", err)
	}
}

func TestCloseTimeout(t *testing.T) {
	eng := &fakeEngine{}
	eng.set(detected)
	s := newTestService(eng, nil, nil, nil)
	// Close before Start.
	if err := s.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	// A Run that never returns: Close gives up with ctx.
	s2 := newTestService(eng, nil, nil, nil)
	s2.started, s2.done = true, make(chan struct{})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := s2.Close(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Close: %v", err)
	}
}

func TestTimeoutBoundsTheTest(t *testing.T) {
	eng := &fakeEngine{block: make(chan struct{})}
	eng.set(detected)
	s := New(eng, Options{Engine: "http", Timeout: time.Nanosecond})
	if s.timeout != time.Nanosecond+timeoutMargin {
		t.Fatalf("timeout = %v", s.timeout)
	}
	s.timeout = 10 * time.Millisecond
	r, err := s.Test(t.Context(), superAdmin(), netip.Addr{})
	if err != nil || r.Outcome != OutcomeUnavailable {
		t.Fatalf("got %+v, %v", r, err)
	}
	if New(eng, Options{}).timeout != DefaultTimeout {
		t.Fatal("default timeout")
	}
}

func TestAuditFailureLogged(t *testing.T) {
	eng := &fakeEngine{}
	eng.set(detected)
	var logs bytes.Buffer
	s := newTestService(eng, &fakeAuditor{err: errors.New("db down")}, nil, &logs)
	if _, err := s.Test(t.Context(), superAdmin(), netip.Addr{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "audit write failed") {
		t.Fatalf("logs = %s", logs.String())
	}
}

func TestStartupAuditDedupAcrossAdminTests(t *testing.T) {
	eng := &fakeEngine{}
	eng.set(clean)
	aud := &fakeAuditor{}
	s := newTestService(eng, aud, nil, nil)
	ctx := t.Context()
	// Startup: first audited, same outcome not, admin always.
	_, _ = s.run(ctx, TriggerStartup, "", netip.Addr{})
	_, _ = s.run(ctx, TriggerStartup, "", netip.Addr{})
	if _, err := s.Test(ctx, superAdmin(), netip.Addr{}); err != nil {
		t.Fatal(err)
	}
	_, _ = s.run(ctx, TriggerStartup, "", netip.Addr{})
	if n := len(aud.list()); n != 2 {
		t.Fatalf("events = %d, want 2", n)
	}
}

func TestFirstDone(t *testing.T) {
	if d := New(nil, Options{}); !isClosed(d.FirstDone()) {
		t.Fatal("FirstDone open with none")
	}
	eng := &fakeEngine{}
	eng.set(unavailable)
	timers := newFakeTimers()
	s := newTestService(eng, nil, timers, nil)
	if isClosed(s.FirstDone()) {
		t.Fatal("FirstDone closed before the first test")
	}
	if err := s.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-s.FirstDone():
	case <-time.After(5 * time.Second):
		t.Fatal("FirstDone not closed after a failed first test")
	}
	if err := s.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	// Close alone closes it too.
	s2 := newTestService(eng, nil, timers, nil)
	if err := s2.Close(t.Context()); err != nil || !isClosed(s2.FirstDone()) {
		t.Fatalf("Close: %v", err)
	}
}

func isClosed(c <-chan struct{}) bool {
	select {
	case <-c:
		return true
	default:
		return false
	}
}

func TestStartupTestAndAdminTestNeverOverlap(t *testing.T) {
	// A slow failing start-up test must not overwrite the result of a test
	// on demand: the test on demand waits for it, then runs its own.
	eng := &fakeEngine{block: make(chan struct{}), started: make(chan struct{}, 4)}
	eng.set(unavailable)
	aud := &fakeAuditor{}
	timers := newFakeTimers()
	s := newTestService(eng, aud, timers, nil)
	if err := s.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	<-eng.started // the start-up test is blocked in the engine
	eng.set(detected)
	type out struct {
		r   Result
		err error
	}
	res := make(chan out, 1)
	go func() {
		r, err := s.Test(t.Context(), superAdmin(), netip.MustParseAddr("192.0.2.9"))
		res <- out{r, err}
	}()
	time.Sleep(20 * time.Millisecond)
	if n := eng.scanCount(); n != 1 {
		t.Fatalf("scans while the start-up test runs = %d, want 1", n)
	}
	close(eng.block) // the start-up test ends (unavailable), then the admin test runs
	o := <-res
	if o.err != nil || !o.r.Passed() || o.r.Trigger != TriggerAdmin {
		t.Fatalf("Test = %+v, %v", o.r, o.err)
	}
	waitFor(t, s.Passed)
	if last, _ := s.Last(); last.Trigger != TriggerAdmin || !last.Passed() {
		t.Fatalf("last = %+v", last)
	}
	evs := aud.list()
	if len(evs) != 2 || evs[0].Details["trigger"] != "startup" || evs[0].Details["outcome"] != "unavailable" ||
		evs[1].Details["trigger"] != "admin" || evs[1].Details["outcome"] != "detected" {
		t.Fatalf("events = %+v", evs)
	}
	if err := s.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestStartupRetrySharesAdminTest(t *testing.T) {
	// A start-up retry due while a test on demand runs shares it instead
	// of running a second test.
	eng := &fakeEngine{}
	eng.set(unavailable)
	aud := &fakeAuditor{}
	timers := newFakeTimers()
	s := newTestService(eng, aud, timers, nil)
	if err := s.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	timers.next(t) // the first test failed, the retry waits
	eng.mu.Lock()
	eng.block, eng.started = make(chan struct{}), make(chan struct{}, 4)
	eng.mu.Unlock()
	eng.set(detected)
	res := make(chan Result, 1)
	go func() {
		r, err := s.Test(t.Context(), superAdmin(), netip.Addr{})
		if err != nil {
			t.Error(err)
		}
		res <- r
	}()
	<-eng.started // the admin test is blocked in the engine
	timers.fire() // the retry is due: it joins the admin test
	time.Sleep(20 * time.Millisecond)
	close(eng.block)
	if r := <-res; !r.Passed() || r.Trigger != TriggerAdmin {
		t.Fatalf("Test = %+v", r)
	}
	waitFor(t, s.Passed)
	time.Sleep(20 * time.Millisecond)
	if n := eng.scanCount(); n != 2 {
		t.Fatalf("scans = %d, want 2", n)
	}
	if last, _ := s.Last(); last.Trigger != TriggerAdmin {
		t.Fatalf("last = %+v", last)
	}
	if n := len(aud.list()); n != 2 {
		t.Fatalf("events = %d, want 2", n)
	}
	if err := s.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestCloseWaitsForTestsOnDemand(t *testing.T) {
	// Close returns only once the goroutine of a test on demand ended, so
	// that nothing is audited after it.
	eng := &fakeEngine{block: make(chan struct{}), started: make(chan struct{}, 1), stubborn: true}
	eng.set(detected)
	aud := &fakeAuditor{}
	s := newTestService(eng, aud, nil, nil)
	ctx, cancel := context.WithCancel(t.Context())
	go func() { _, _ = s.Test(ctx, superAdmin(), netip.Addr{}) }()
	<-eng.started
	short, stop := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer stop()
	if err := s.Close(short); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Close with a test in progress: %v", err)
	}
	cancel()
	close(eng.block)
	if err := s.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	// The test ended after the cancellation: nothing recorded.
	if _, ok := s.Last(); ok || len(aud.list()) != 0 {
		t.Fatal("test recorded after Close")
	}
}

func TestRunReturnsWhenItsContextIsDone(t *testing.T) {
	// Run returns when its own context is done during a test; the test,
	// run within the context of the service, ends with Close.
	eng := &fakeEngine{block: make(chan struct{}), started: make(chan struct{}, 1)}
	eng.set(detected)
	s := newTestService(eng, nil, newFakeTimers(), nil)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	<-eng.started
	cancel()
	<-done
	if !isClosed(s.FirstDone()) {
		t.Fatal("FirstDone open after Run returned")
	}
	if err := s.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestRunReturnsWhenCloseCancelsItsTest(t *testing.T) {
	eng := &fakeEngine{block: make(chan struct{}), started: make(chan struct{}, 1)}
	eng.set(detected)
	s := newTestService(eng, nil, newFakeTimers(), nil)
	done := make(chan struct{})
	go func() { s.Run(t.Context()); close(done) }()
	<-eng.started
	if err := s.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	<-done // the canceled test ends Run, whose own context is still live
}
