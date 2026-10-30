// Package avselftest guards the antivirus engine with an EICAR self-test
// (CLAUDE.md section 11.1, threat model decision P44).
//
// The EICAR test string (antivirus.EICAR, harmless) is sent to the engine,
// which must report it infected. Until a self-test passes, the engine is
// treated as unavailable (fail-closed): the [Gate] placed between the
// engine and its users (antivirus worker, outage alert, health check)
// refuses every analysis and every ping with an error wrapping
// antivirus.ErrUnavailable, so that files wait, the outage alert follows
// its grace period and /healthz reports the antivirus unavailable.
//
// # Rules
//
//   - At start-up, [Service.Run] runs the self-test and retries it while
//     it fails, with a delay of RetryMin doubling up to RetryMax; after a
//     pass it never repeats it by itself.
//   - A super admin may run the self-test on demand ([Service.Test]);
//     concurrent calls share the running test. A test on demand that
//     fails closes the gate again and restarts the retries; one that
//     passes opens it.
//   - One self-test runs at a time, start-up and on demand alike, and its
//     result is applied before the next one starts, so that a slow test
//     can never overwrite the result of a later one. A start-up test due
//     while a test on demand runs shares it (recorded with the trigger
//     admin, which audits it); a test on demand asked while a start-up
//     test runs waits for its end, then runs its own test, so that every
//     test on demand is run and audited as such.
//   - Every test on demand is audited (antivirus.self_test, actor the
//     admin); the tests run by the instance only for the first one after
//     the start and when the outcome changes, so that the retries never
//     flood the audit log.
//   - Logs and audit details hold the engine name and the outcome only,
//     never an address or a secret of the engine.
package avselftest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/antivirus"
	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/store"
)

// Retry delays of the start-up self-test.
const (
	// RetryMin is the delay before the first retry of a failed start-up
	// self-test.
	RetryMin = 15 * time.Second
	// RetryMax is the longest delay between two retries.
	RetryMax = 10 * time.Minute
	// DefaultTimeout bounds a self-test when Options.Timeout is not set.
	// The engine enforces its own scan timeout first.
	DefaultTimeout = antivirus.DefaultScanTimeout + timeoutMargin
	// timeoutMargin is added to Options.Timeout, so that the engine's own
	// timeout fires first and the test reports "error" (too late) rather
	// than "unavailable".
	timeoutMargin = 30 * time.Second
)

// auditObjectID is the audit object ID (kind system) of the self-test.
const auditObjectID = "antivirus"

// Outcome is the outcome of a self-test (OpenAPI AntivirusSelfTest.outcome).
type Outcome string

// Outcomes.
const (
	// OutcomeDetected: the engine reported EICAR infected (passed).
	OutcomeDetected Outcome = "detected"
	// OutcomeNotDetected: the engine answered another verdict.
	OutcomeNotDetected Outcome = "not_detected"
	// OutcomeUnavailable: the engine could not be reached (error wrapping
	// antivirus.ErrUnavailable).
	OutcomeUnavailable Outcome = "unavailable"
	// OutcomeError: the engine answered something unexpected or too late.
	OutcomeError Outcome = "error"
)

// Trigger tells who ran a self-test (OpenAPI AntivirusSelfTest.trigger).
type Trigger string

// Triggers.
const (
	// TriggerStartup: run by the instance, at the start or a retry.
	TriggerStartup Trigger = "startup"
	// TriggerAdmin: asked by a super admin.
	TriggerAdmin Trigger = "admin"
)

// Result is the outcome of one self-test.
type Result struct {
	// Engine is the engine name (TT_ANTIVIRUS_ENGINE).
	Engine string
	// Outcome is the outcome of the test.
	Outcome Outcome
	// Signature is the signature the engine reported, with
	// OutcomeDetected only (already sanitized by the engine client).
	Signature string
	// Trigger tells who ran the test.
	Trigger Trigger
	// TestedAt is the end of the test.
	TestedAt time.Time
	// Duration is the duration of the test.
	Duration time.Duration
}

// Passed reports whether the test detected EICAR.
func (r Result) Passed() bool { return r.Outcome == OutcomeDetected }

// Errors.
var (
	// ErrDisabled reports a self-test asked while the antivirus is
	// disabled for the whole instance (engine "none").
	ErrDisabled = errors.New("avselftest: the antivirus is disabled for the whole instance")
	// ErrNotPassed is returned by the Gate while no self-test has passed.
	// It wraps antivirus.ErrUnavailable, so that the worker waits and
	// retries as for an engine outage.
	ErrNotPassed = fmt.Errorf("%w: EICAR self-test not passed", antivirus.ErrUnavailable)
	// ErrStarted is returned by [Service.Start] when already started.
	ErrStarted = errors.New("avselftest: already started")
	// ErrClosed is returned by [Service.Start] after [Service.Close].
	ErrClosed = errors.New("avselftest: closed")
)

// Engine is an antivirus engine client: *antivirus.Client (clamd),
// *antivirus.ICAPClient and *antivirus.HTTPClient implement it.
type Engine interface {
	Scan(ctx context.Context, r io.Reader, size int64) (antivirus.Result, error)
	Ping(ctx context.Context) error
}

// Gate wraps an engine and lets its analyses and pings through only once a
// self-test passed. It implements scan.Scanner and avalert.Pinger. It is
// safe for concurrent use.
type Gate struct {
	engine Engine
	open   atomic.Bool
}

// NewGate returns a closed gate over engine.
func NewGate(engine Engine) *Gate {
	return &Gate{engine: engine}
}

// Open reports whether a self-test passed and the gate lets analyses through.
func (g *Gate) Open() bool { return g.open.Load() }

// set opens or closes the gate.
func (g *Gate) set(open bool) { g.open.Store(open) }

// Scan analyzes r with the engine once the gate is open. While it is
// closed, it returns ErrNotPassed without contacting the engine.
func (g *Gate) Scan(ctx context.Context, r io.Reader, size int64) (antivirus.Result, error) {
	if !g.Open() {
		return antivirus.Result{}, ErrNotPassed
	}
	return g.engine.Scan(ctx, r, size)
}

// Ping checks the engine once the gate is open. While it is closed, it
// returns ErrNotPassed, so that the health check and the outage alert see
// the engine down.
func (g *Gate) Ping(ctx context.Context) error {
	if !g.Open() {
		return ErrNotPassed
	}
	return g.engine.Ping(ctx)
}

// Auditor records a global audit event. *audit.Writer implements it.
type Auditor interface {
	Record(ctx context.Context, ev audit.Event) error
}

// Options configure a Service.
type Options struct {
	// Engine is the engine name reported in the results, the logs and the
	// audit (TT_ANTIVIRUS_ENGINE).
	Engine string
	// Timeout is the scan timeout of the engine. A self-test is bounded by
	// Timeout plus a margin of 30 seconds, added so that the engine's own
	// timeout fires first (DefaultTimeout when zero).
	Timeout time.Duration
	// Audit records the antivirus.self_test events (nil records none).
	Audit Auditor
	// Logger receives the outcomes (discarded when nil).
	Logger *slog.Logger
	// Now is the clock (time.Now).
	Now func() time.Time
	// After waits for a retry delay (time.After); tests inject a fake.
	After func(d time.Duration) <-chan time.Time
}

// Service runs the self-tests and drives the gate. It is safe for
// concurrent use.
type Service struct {
	gate    *Gate
	engine  string
	timeout time.Duration
	auditor Auditor
	logger  *slog.Logger
	now     func() time.Time
	after   func(d time.Duration) <-chan time.Time

	// base bounds the tests, canceled by Close.
	base       context.Context
	cancelBase context.CancelFunc
	// wake is signaled after every test on demand, so that Run starts or
	// stops its retries.
	wake chan struct{}
	// firstDone is closed when the first start-up self-test ends (or is
	// canceled); firstOnce closes it once.
	firstDone chan struct{}
	firstOnce sync.Once

	mu       sync.Mutex
	last     Result
	hasLast  bool
	audited  bool // a start-up test was audited since the start
	inflight *call
	stopped  bool // set by Close: no test starts any more
	// tests tracks the goroutines running the self-tests, waited for by
	// Close. Add is only called under mu while not stopped.
	tests sync.WaitGroup

	runMu   sync.Mutex
	started bool
	closed  bool
	done    chan struct{}
}

// call is a self-test in progress, shared by concurrent callers.
type call struct {
	done    chan struct{}
	trigger Trigger
	res     Result
	err     error
}

// New returns the service guarding engine with a closed gate. A nil engine
// is the engine "none": no gate, and Test answers ErrDisabled.
func New(engine Engine, opts Options) *Service {
	s := &Service{
		engine: opts.Engine, timeout: opts.Timeout, auditor: opts.Audit, logger: opts.Logger,
		now: opts.Now, after: opts.After, wake: make(chan struct{}, 1),
		firstDone: make(chan struct{}),
	}
	if engine != nil {
		s.gate = NewGate(engine)
	} else {
		s.endFirst()
	}
	if s.timeout <= 0 {
		s.timeout = DefaultTimeout
	} else {
		s.timeout += timeoutMargin
	}
	if s.logger == nil {
		s.logger = slog.New(slog.DiscardHandler)
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.after == nil {
		s.after = time.After
	}
	s.base, s.cancelBase = context.WithCancel(context.Background())
	return s
}

// FirstDone returns a channel closed when the first start-up self-test of
// [Service.Run] ends, whatever its outcome, or is canceled; it is closed
// from the start with the engine "none". The application waits for it,
// briefly, before starting the antivirus worker, so that the files waiting
// at start-up are not taken for an engine outage.
func (s *Service) FirstDone() <-chan struct{} { return s.firstDone }

// endFirst closes firstDone once.
func (s *Service) endFirst() { s.firstOnce.Do(func() { close(s.firstDone) }) }

// Gate returns the gate over the engine, nil with the engine "none".
func (s *Service) Gate() *Gate { return s.gate }

// Disabled reports whether the antivirus is disabled (engine "none").
func (s *Service) Disabled() bool { return s.gate == nil }

// Last returns the last self-test, and false before the first one ends or
// with the engine "none".
func (s *Service) Last() (Result, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last, s.hasLast
}

// Passed reports whether the gate is open: a self-test passed, and no
// later one failed. It is false with the engine "none".
func (s *Service) Passed() bool {
	return s.gate != nil && s.gate.Open()
}

// Test runs a self-test for p, a super admin, from client ip, and returns
// its result; concurrent calls share the running test. It returns
// adminauth.ErrUnauthenticated or adminauth.ErrForbidden (checked first),
// ErrDisabled with the engine "none", and ctx.Err() when ctx is done before
// the test ends (the test goes on for the other callers).
func (s *Service) Test(ctx context.Context, p adminauth.Principal, ip netip.Addr) (Result, error) {
	if err := adminauth.RequireAuthenticated(p); err != nil {
		return Result{}, err
	}
	if err := adminauth.RequireSuperAdmin(p.Admin); err != nil {
		return Result{}, err
	}
	if s.Disabled() {
		return Result{}, ErrDisabled
	}
	for {
		c := s.flight(TriggerAdmin, p.Admin.Username, ip)
		select {
		case <-c.done:
		case <-ctx.Done():
			return Result{}, ctx.Err()
		}
		// A start-up test was running: run a test on demand after it.
		if c.trigger == TriggerAdmin || c.err != nil {
			return c.res, c.err
		}
	}
}

// flight returns the self-test in progress, whatever its trigger, or
// starts one for trigger, actor and ip when none is. The test runs within
// the context of the service and records its result before the next one
// can start. After Close, it returns an ended call failing with
// context.Canceled.
func (s *Service) flight(trigger Trigger, actor string, ip netip.Addr) *call {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.inflight != nil {
		return s.inflight
	}
	c := &call{done: make(chan struct{}), trigger: trigger}
	if s.stopped {
		c.err = context.Canceled
		close(c.done)
		return c
	}
	s.inflight = c
	s.tests.Add(1)
	go func() {
		defer s.tests.Done()
		c.res, c.err = s.run(s.base, trigger, actor, ip)
		s.mu.Lock()
		s.inflight = nil
		s.mu.Unlock()
		close(c.done)
		if trigger == TriggerAdmin {
			s.signal()
		}
	}()
	return c
}

// signal wakes Run without blocking.
func (s *Service) signal() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// run runs one self-test within ctx, records it (gate, last result, log,
// audit) and returns it. It returns ctx.Err(), recording nothing, when ctx
// is done before the test ends (shutdown).
func (s *Service) run(ctx context.Context, trigger Trigger, actor string, ip netip.Addr) (Result, error) {
	tctx, cancel := context.WithTimeout(ctx, s.timeout)
	start := s.now()
	eicar := antivirus.EICAR()
	v, err := s.gate.engine.Scan(tctx, bytes.NewReader(eicar), int64(len(eicar)))
	cancel()
	if ctx.Err() != nil {
		return Result{}, ctx.Err()
	}
	end := s.now()
	r := Result{Engine: s.engine, Trigger: trigger, TestedAt: end.UTC(), Duration: max(end.Sub(start), 0)}
	switch {
	case err == nil && v.Verdict == antivirus.Infected:
		r.Outcome, r.Signature = OutcomeDetected, v.Signature
	case err == nil:
		r.Outcome = OutcomeNotDetected
	case errors.Is(err, antivirus.ErrUnavailable):
		r.Outcome = OutcomeUnavailable
	default:
		r.Outcome = OutcomeError
	}
	s.record(ctx, r, actor, ip)
	return r, nil
}

// record applies r: the gate, the last result, the log and the audit.
func (s *Service) record(ctx context.Context, r Result, actor string, ip netip.Addr) {
	s.mu.Lock()
	changed := !s.hasLast || s.last.Outcome != r.Outcome
	doAudit := r.Trigger == TriggerAdmin || !s.audited || changed
	if r.Trigger == TriggerStartup {
		s.audited = true
	}
	s.last, s.hasLast = r, true
	s.gate.set(r.Passed())
	s.mu.Unlock()

	attrs := []any{
		slog.String("engine", r.Engine), slog.String("outcome", string(r.Outcome)),
		slog.String("trigger", string(r.Trigger)),
	}
	if r.Passed() {
		s.logger.InfoContext(ctx, "antivirus self-test passed: the engine detected the EICAR test string", attrs...)
	} else {
		s.logger.ErrorContext(ctx, "antivirus self-test failed: analyses wait until a self-test passes", attrs...)
	}
	if !doAudit || s.auditor == nil {
		return
	}
	ev := audit.Event{
		ActorKind: store.ActorSystem, Actor: audit.ActorAntivirus, Action: audit.ActionAntivirusSelfTest,
		ObjectKind: audit.ObjectSystem, ObjectID: auditObjectID,
		Details: map[string]any{"engine": r.Engine, "outcome": string(r.Outcome), "trigger": string(r.Trigger)},
	}
	if r.Trigger == TriggerAdmin {
		ev.ActorKind, ev.Actor, ev.IP = store.ActorAdmin, actor, ip
	}
	if err := s.auditor.Record(context.WithoutCancel(ctx), ev); err != nil {
		s.logger.ErrorContext(ctx, "audit write failed",
			slog.String("action", string(audit.ActionAntivirusSelfTest)), slog.Any("error", err))
	}
}

// Run runs the start-up self-test, retries it while it fails (RetryMin
// doubling up to RetryMax), and waits; a later test on demand that fails
// restarts the retries, after RetryMin. The tests run within the context of
// the service (canceled by Close), one at a time (see the package rules).
// It returns when ctx is done, at once with the engine "none".
func (s *Service) Run(ctx context.Context) {
	if s.Disabled() {
		return
	}
	first := true
	for {
		if !s.Passed() && !s.retryUntilPass(ctx, first) {
			return
		}
		first = false
		select {
		case <-ctx.Done():
			return
		case <-s.wake:
		}
	}
}

// retryUntilPass runs start-up self-tests until the gate opens, by one of
// them or by a test on demand; the first one runs at once when now is
// true, after RetryMin otherwise. It returns false when ctx is done.
func (s *Service) retryUntilPass(ctx context.Context, now bool) bool {
	delay := RetryMin
	if !now {
		if passed, ok := s.wait(ctx, delay); !ok || passed {
			return ok
		}
	}
	for {
		c := s.flight(TriggerStartup, "", netip.Addr{})
		select {
		case <-c.done:
		case <-ctx.Done():
			s.endFirst()
			return false
		}
		s.endFirst()
		if c.err != nil {
			return false
		}
		if s.Passed() {
			return true
		}
		if passed, ok := s.wait(ctx, delay); !ok || passed {
			return ok
		}
		delay = min(2*delay, RetryMax)
	}
}

// wait waits for delay, or until a test on demand opens the gate (passed
// true). ok is false when ctx is done.
func (s *Service) wait(ctx context.Context, delay time.Duration) (passed, ok bool) {
	timer := s.after(delay)
	for {
		select {
		case <-ctx.Done():
			return false, false
		case <-s.wake:
			if s.Passed() {
				return true, true
			}
		case <-timer:
			return false, true
		}
	}
}

// Start runs [Service.Run] in the background until [Service.Close]. The
// self-tests run within the context of the service, canceled by Close,
// not within ctx.
func (s *Service) Start(context.Context) error {
	s.runMu.Lock()
	defer s.runMu.Unlock()
	switch {
	case s.closed:
		return ErrClosed
	case s.started:
		return ErrStarted
	}
	s.started = true
	s.done = make(chan struct{})
	go func() {
		defer close(s.done)
		s.Run(s.base)
	}()
	return nil
}

// Close stops [Service.Run] and cancels the tests in progress, start-up
// and on demand. It waits for Run to return, when started, and for every
// test to end, so that nothing is recorded or audited after it returns; it
// waits at most until ctx is done, and returns ctx.Err() then. Calling it
// more than once is harmless.
func (s *Service) Close(ctx context.Context) error {
	s.runMu.Lock()
	s.closed = true
	started, done := s.started, s.done
	s.mu.Lock()
	s.stopped = true
	s.mu.Unlock()
	s.cancelBase()
	s.endFirst()
	s.runMu.Unlock()
	ended := make(chan struct{})
	go func() {
		if started {
			<-done
		}
		s.tests.Wait()
		close(ended)
	}()
	select {
	case <-ended:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
