// Package health implements the /healthz endpoint (cahier des charges §19).
//
// A Service runs three named checks (database, antivirus, storage)
// concurrently, each bounded by its own timeout, and Handler renders the
// result as the OpenAPI Health schema. Error details are logged, never
// returned to the client.
//
// The endpoint is public, so a Service bounds the work it triggers:
// concurrent callers share a single in-flight run, and a completed report is
// reused for CacheTTL. A storage probe that does not return (e.g. on a hung
// disk) is never started again while the previous one is still running.
package health

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultTimeout bounds a check whose Check.Timeout is not set.
const DefaultTimeout = 2 * time.Second

// CacheTTL is how long a Service reuses a completed report before running
// the checks again.
const CacheTTL = 3 * time.Second

// Names of the checks, as they appear in the Health schema.
const (
	NameDatabase  = "database"
	NameAntivirus = "antivirus"
	NameStorage   = "storage"
)

// Status is a component status of the ComponentHealth schema.
type Status string

// Component statuses.
const (
	StatusOK          Status = "ok"
	StatusUnavailable Status = "unavailable"
)

// removeFile deletes the storage probe, replaceable in tests.
var removeFile = os.Remove

// errNotConfigured is reported for a check without a Checker.
var errNotConfigured = errors.New("health: check not configured")

// errProbeRunning is reported by StorageCheck while a previous probe has not
// returned yet.
var errProbeRunning = errors.New("health: storage probe still running")

// Checker verifies the availability of one component.
type Checker interface {
	// Check returns nil when the component is available. It should honor
	// ctx; the Service gives up waiting when ctx is done anyway.
	Check(ctx context.Context) error
}

// CheckerFunc adapts an ordinary function to the Checker interface.
type CheckerFunc func(ctx context.Context) error

// Check calls f(ctx).
func (f CheckerFunc) Check(ctx context.Context) error { return f(ctx) }

// Disabled is the Checker of a component turned off by the configuration,
// which is therefore never probed and always reported available: the
// antivirus with TT_ANTIVIRUS_ENGINE=none.
var Disabled Checker = CheckerFunc(func(context.Context) error { return nil })

// Check is a Checker with its own timeout.
type Check struct {
	// Checker performs the check. A nil Checker is reported unavailable.
	Checker Checker
	// Timeout bounds the check; zero or negative means DefaultTimeout.
	Timeout time.Duration
}

// Service runs the health checks. The zero value reports every component
// unavailable. A Service must not be copied after first use.
type Service struct {
	// Database checks the database connection (e.g. a Ping).
	Database Check
	// Antivirus checks clamd (e.g. antivirus.Client.Ping).
	Antivirus Check
	// Storage checks the data directory (e.g. StorageCheck).
	Storage Check
	// Logger receives failed checks at warn level. Nil discards them.
	Logger *slog.Logger

	// now returns the current time; nil means time.Now. Set by tests.
	now func() time.Time

	mu       sync.Mutex
	inflight *run      // run in progress, nil when idle
	cached   Report    // last completed report
	cachedAt time.Time // completion time of cached, zero when none
}

// run is a set of checks in progress, shared by concurrent callers.
type run struct {
	done   chan struct{} // closed once report is set
	report Report
}

// unavailableReport is returned to a caller that gives up waiting.
var unavailableReport = Report{StatusUnavailable, StatusUnavailable, StatusUnavailable}

// Report is the outcome of a Service run.
type Report struct {
	Database  Status
	Antivirus Status
	Storage   Status
}

// Healthy reports whether every component is available.
func (r Report) Healthy() bool {
	return r.Database == StatusOK && r.Antivirus == StatusOK && r.Storage == StatusOK
}

// Run returns the health report. A report completed less than CacheTTL ago
// is reused; otherwise the checks run, and concurrent callers share that
// single run. The run is detached from ctx's cancellation (each check keeps
// its own timeout), so a caller giving up does not cancel it for the others;
// that caller gets every component reported unavailable.
func (s *Service) Run(ctx context.Context) Report {
	s.mu.Lock()
	if !s.cachedAt.IsZero() && s.clock().Sub(s.cachedAt) < CacheTTL {
		r := s.cached
		s.mu.Unlock()
		return r
	}
	c := s.inflight
	if c == nil {
		c = &run{done: make(chan struct{})}
		s.inflight = c
		go s.execute(context.WithoutCancel(ctx), c)
	}
	s.mu.Unlock()

	select {
	case <-c.done:
		return c.report
	case <-ctx.Done():
		return unavailableReport
	}
}

// execute runs the checks for c, caches the report and releases the waiters.
func (s *Service) execute(ctx context.Context, c *run) {
	c.report = s.runChecks(ctx)
	s.mu.Lock()
	s.cached, s.cachedAt, s.inflight = c.report, s.clock(), nil
	s.mu.Unlock()
	close(c.done)
}

func (s *Service) clock() time.Time {
	if s.now == nil {
		return time.Now()
	}
	return s.now()
}

// runChecks executes all checks concurrently and waits for each of them to
// finish or time out. Failures are logged with their error at warn level.
func (s *Service) runChecks(ctx context.Context) Report {
	var (
		r  Report
		wg sync.WaitGroup
	)
	targets := []struct {
		name  string
		check Check
		out   *Status
	}{
		{NameDatabase, s.Database, &r.Database},
		{NameAntivirus, s.Antivirus, &r.Antivirus},
		{NameStorage, s.Storage, &r.Storage},
	}
	for _, tg := range targets {
		wg.Go(func() {
			if err := runCheck(ctx, tg.check); err != nil {
				s.logger().WarnContext(ctx, "health check failed",
					slog.String("check", tg.name), slog.Any("error", err))
				*tg.out = StatusUnavailable
				return
			}
			*tg.out = StatusOK
		})
	}
	wg.Wait()
	return r
}

func (s *Service) logger() *slog.Logger {
	if s.Logger == nil {
		return slog.New(slog.DiscardHandler)
	}
	return s.Logger
}

// runCheck runs c with its timeout. A checker ignoring its context cannot
// delay the result beyond the timeout: it keeps running in the background
// and its result is discarded. A panic is reported as a failure.
func runCheck(ctx context.Context, c Check) error {
	if c.Checker == nil {
		return errNotConfigured
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		defer func() {
			if p := recover(); p != nil {
				done <- fmt.Errorf("health: check panicked: %v", p)
			}
		}()
		done <- c.Checker.Check(ctx)
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return fmt.Errorf("health: check abandoned: %w", context.Cause(ctx))
	}
}

// StorageCheck returns a Checker that creates then removes a probe file in
// dir. The file is created exclusively (O_EXCL) under a random name, so it
// never clobbers existing data, and it is always removed.
//
// File system calls cannot be canceled, so the probe runs in its own
// goroutine and the Checker returns as soon as ctx is done. While a probe
// has not returned (e.g. on a hung disk), no new probe is started and the
// Checker fails immediately: at most one probe goroutine exists per Checker.
func StorageCheck(dir string) Checker {
	var running atomic.Bool
	return CheckerFunc(func(ctx context.Context) error {
		if !running.CompareAndSwap(false, true) {
			return errProbeRunning
		}
		done := make(chan error, 1)
		go func() {
			defer running.Store(false)
			done <- storageProbe(dir)
		}()
		select {
		case err := <-done:
			return err
		case <-ctx.Done():
			return fmt.Errorf("health: storage probe abandoned: %w", context.Cause(ctx))
		}
	})
}

// storageProbe creates then removes a probe file in dir.
func storageProbe(dir string) error {
	f, err := os.CreateTemp(dir, ".healthcheck-*")
	if err != nil {
		return fmt.Errorf("health: storage probe: %w", err)
	}
	if err := errors.Join(f.Close(), removeFile(f.Name())); err != nil {
		return fmt.Errorf("health: storage probe cleanup: %w", err)
	}
	return nil
}
