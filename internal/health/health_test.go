package health

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var (
	ok     = CheckerFunc(func(context.Context) error { return nil })
	errBad = errors.New("secret detail 10.0.0.5:3310")
	bad    = CheckerFunc(func(context.Context) error { return errBad })
)

func TestCheckerFunc(t *testing.T) {
	if err := bad.Check(context.Background()); !errors.Is(err, errBad) {
		t.Fatalf("Check = %v", err)
	}
}

func TestReportHealthy(t *testing.T) {
	all := Report{StatusOK, StatusOK, StatusOK}
	if !all.Healthy() {
		t.Fatal("all ok not healthy")
	}
	for _, r := range []Report{
		{StatusUnavailable, StatusOK, StatusOK},
		{StatusOK, StatusUnavailable, StatusOK},
		{StatusOK, StatusOK, StatusUnavailable},
	} {
		if r.Healthy() {
			t.Fatalf("report %+v healthy", r)
		}
	}
}

func TestRunStatusesAndLogging(t *testing.T) {
	var logs bytes.Buffer
	svc := &Service{
		Database:  Check{Checker: ok},
		Antivirus: Check{Checker: bad},
		// Storage left unconfigured.
		Logger: slog.New(slog.NewTextHandler(&logs, nil)),
	}
	got := svc.Run(context.Background())
	want := Report{Database: StatusOK, Antivirus: StatusUnavailable, Storage: StatusUnavailable}
	if got != want {
		t.Fatalf("Run = %+v, want %+v", got, want)
	}
	out := logs.String()
	for _, s := range []string{"level=WARN", "check=antivirus", "secret detail", "check=storage", "not configured"} {
		if !strings.Contains(out, s) {
			t.Errorf("log %q lacks %q", out, s)
		}
	}
	if strings.Contains(out, "check=database") {
		t.Errorf("successful check logged: %q", out)
	}
}

func TestRunZeroServiceNilLogger(t *testing.T) {
	var svc Service
	if r := svc.Run(context.Background()); r.Healthy() || r.Database != StatusUnavailable {
		t.Fatalf("zero service = %+v", r)
	}
}

func TestRunConcurrentWithTimeouts(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	var running atomic.Int32
	allStarted := make(chan struct{})
	// Each checker waits until all three run at once, proving concurrency.
	barrier := CheckerFunc(func(ctx context.Context) error {
		if running.Add(1) == 3 {
			close(allStarted)
		}
		select {
		case <-allStarted:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	// A checker ignoring its context must not delay the report.
	stubborn := CheckerFunc(func(context.Context) error { <-release; return nil })

	svc := &Service{
		Database:  Check{Checker: barrier, Timeout: time.Second},
		Antivirus: Check{Checker: barrier},
		Storage:   Check{Checker: barrier},
	}
	if r := svc.Run(context.Background()); !r.Healthy() {
		t.Fatalf("concurrent checks = %+v", r)
	}

	// A fresh Service, as the first report is cached.
	svc = &Service{
		Database:  Check{Checker: ok},
		Antivirus: Check{Checker: stubborn, Timeout: 50 * time.Millisecond},
		Storage:   Check{Checker: ok},
	}
	start := time.Now()
	r := svc.Run(context.Background())
	if d := time.Since(start); d > time.Second {
		t.Fatalf("Run took %v despite a 50ms timeout", d)
	}
	if r.Antivirus != StatusUnavailable || r.Database != StatusOK || r.Storage != StatusOK {
		t.Fatalf("Run = %+v", r)
	}
}

func TestRunCheckDefaultTimeoutAndPanic(t *testing.T) {
	var deadline time.Time
	probe := CheckerFunc(func(ctx context.Context) error {
		deadline, _ = ctx.Deadline()
		return nil
	})
	if err := runCheck(context.Background(), Check{Checker: probe, Timeout: -1}); err != nil {
		t.Fatal(err)
	}
	if left := time.Until(deadline); left <= 0 || left > DefaultTimeout {
		t.Fatalf("deadline in %v, want within %v", left, DefaultTimeout)
	}
	panicky := CheckerFunc(func(context.Context) error { panic("boom") })
	if err := runCheck(context.Background(), Check{Checker: panicky}); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("panic = %v", err)
	}
}

func TestStorageCheck(t *testing.T) {
	dir := t.TempDir()
	if err := StorageCheck(dir).Check(context.Background()); err != nil {
		t.Fatalf("Check = %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("probe left files: %v, %v", entries, err)
	}
}

func TestStorageCheckFailures(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for name, d := range map[string]string{
		"nonexistent": filepath.Join(dir, "missing"),
		"not a dir":   file,
	} {
		t.Run(name, func(t *testing.T) {
			if err := StorageCheck(d).Check(context.Background()); err == nil {
				t.Fatal("Check succeeded")
			}
		})
	}
}

func TestStorageCheckReadOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory permissions are not enforced on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses permissions")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if err := StorageCheck(dir).Check(context.Background()); err == nil {
		t.Fatal("Check succeeded on a read-only directory")
	}
}

func TestStorageCheckCleanupFailure(t *testing.T) {
	errRemove := errors.New("remove failed")
	orig := removeFile
	t.Cleanup(func() { removeFile = orig })
	var probe string
	removeFile = func(name string) error {
		probe = name
		_ = orig(name)
		return errRemove
	}
	if err := StorageCheck(t.TempDir()).Check(context.Background()); !errors.Is(err, errRemove) {
		t.Fatalf("Check = %v, want %v", err, errRemove)
	}
	if !strings.HasPrefix(filepath.Base(probe), ".healthcheck-") {
		t.Fatalf("probe name = %q", probe)
	}
}

func TestDisabledChecker(t *testing.T) {
	t.Parallel()
	if err := Disabled.Check(context.Background()); err != nil {
		t.Fatalf("Disabled.Check() = %v", err)
	}
	s := &Service{
		Database:  Check{Checker: Disabled},
		Antivirus: Check{Checker: Disabled},
		Storage:   Check{Checker: Disabled},
	}
	if r := s.Run(context.Background()); !r.Healthy() || r.Antivirus != StatusOK {
		t.Fatalf("report %+v", r)
	}
}
