package admin

import (
	"context"
	"errors"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/health"
	"github.com/ed-fr/transteira/internal/maintenance"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/updatecheck"
	"github.com/ed-fr/transteira/internal/version"
)

// fakeChecks is a ComponentChecks returning a fixed report.
type fakeChecks struct {
	report health.Report
	at     time.Time
	runs   atomic.Int32
}

func (f *fakeChecks) RunAt(context.Context) (health.Report, time.Time) {
	f.runs.Add(1)
	return f.report, f.at
}

var checkedAt = time.Date(2026, 11, 18, 10, 0, 0, 0, time.FixedZone("CET", 3600))

func allOK() health.Report {
	return health.Report{Database: health.StatusOK, Antivirus: health.StatusOK, Storage: health.StatusOK}
}

// statusServer returns a server fully wired for getSystemStatus.
func statusServer(checks ComponentChecks, dbEngine, avEngine string, m *fakeMaintenance, u *fakeUpdateCheck) *Server {
	s := NewServer(WithSystemStatus(checks, dbEngine, avEngine), WithMaintenance(m), WithUpdateCheck(u))
	s.version = func() version.Info { return version.Info{Version: "2.3.0", Commit: "3f9c2ab"} }
	return s
}

func statusBody(t *testing.T, s *Server) string {
	t.Helper()
	resp, err := s.GetSystemStatus(ctxWith(store.SessionAuthenticated, superRoot), gen.GetSystemStatusRequestObject{})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	if err := resp.VisitGetSystemStatusResponse(rec); err != nil || rec.Code != 200 {
		t.Fatalf("visit = %d, %v", rec.Code, err)
	}
	return rec.Body.String()
}

func TestGetSystemStatusStates(t *testing.T) {
	t.Parallel()
	ok, bad := health.StatusOK, health.StatusUnavailable
	for name, c := range map[string]struct {
		report   health.Report
		db, av   string
		state    maintenance.State
		upd      updatecheck.Status
		wantBody string
	}{
		"all ok, never checked": {
			report: allOK(), db: "sqlite", av: "clamd", state: maintenance.State{Source: maintenance.SourceNone},
			upd: updatecheck.Status{Enabled: true},
			wantBody: `{"status":"ok","checkedAt":"2026-11-18T09:00:00Z","database":{"engine":"sqlite","status":"ok"},` +
				`"antivirus":{"engine":"clamd","status":"ok"},"storage":{"status":"ok"},` +
				`"maintenance":{"enabled":false,"source":"none"},` +
				`"version":{"version":"2.3.0","updateCheckEnabled":true,"latestVersion":null,"updateAvailable":false}}`,
		},
		"database down": {
			report: health.Report{Database: bad, Antivirus: ok, Storage: ok}, db: "postgres", av: "icap",
			state: maintenance.State{Source: maintenance.SourceNone},
			wantBody: `{"status":"degraded","checkedAt":"2026-11-18T09:00:00Z","database":{"engine":"postgres","status":"unavailable"},` +
				`"antivirus":{"engine":"icap","status":"ok"},"storage":{"status":"ok"},` +
				`"maintenance":{"enabled":false,"source":"none"},` +
				`"version":{"version":"2.3.0","updateCheckEnabled":false,"latestVersion":null,"updateAvailable":false}}`,
		},
		"antivirus down, maintenance by the super admin": {
			report: health.Report{Database: ok, Antivirus: bad, Storage: ok}, db: "sqlite", av: "http",
			state: maintenance.State{Enabled: true, Source: maintenance.SourceAdmin, AdminEnabled: true},
			upd:   updatecheck.Status{Enabled: true, LatestVersion: "2.4.0", UpdateAvailable: true},
			wantBody: `{"status":"degraded","checkedAt":"2026-11-18T09:00:00Z","database":{"engine":"sqlite","status":"ok"},` +
				`"antivirus":{"engine":"http","status":"unavailable"},"storage":{"status":"ok"},` +
				`"maintenance":{"enabled":true,"source":"admin"},` +
				`"version":{"version":"2.3.0","updateCheckEnabled":true,"latestVersion":"2.4.0","updateAvailable":true}}`,
		},
		"storage down, maintenance by the environment": {
			report: health.Report{Database: ok, Antivirus: ok, Storage: bad}, db: "sqlite", av: "clamd",
			state: maintenance.State{Enabled: true, Source: maintenance.SourceEnvironment},
			wantBody: `{"status":"degraded","checkedAt":"2026-11-18T09:00:00Z","database":{"engine":"sqlite","status":"ok"},` +
				`"antivirus":{"engine":"clamd","status":"ok"},"storage":{"status":"unavailable"},` +
				`"maintenance":{"enabled":true,"source":"environment"},` +
				`"version":{"version":"2.3.0","updateCheckEnabled":false,"latestVersion":null,"updateAvailable":false}}`,
		},
		"engine none is disabled, not a failure": {
			report: allOK(), db: "sqlite", av: "none", state: maintenance.State{Source: maintenance.SourceNone},
			wantBody: `{"status":"ok","checkedAt":"2026-11-18T09:00:00Z","database":{"engine":"sqlite","status":"ok"},` +
				`"antivirus":{"engine":"none","status":"disabled"},"storage":{"status":"ok"},` +
				`"maintenance":{"enabled":false,"source":"none"},` +
				`"version":{"version":"2.3.0","updateCheckEnabled":false,"latestVersion":null,"updateAvailable":false}}`,
		},
		"everything down": {
			report: health.Report{Database: bad, Antivirus: bad, Storage: bad}, db: "postgres", av: "clamd",
			state: maintenance.State{Source: maintenance.SourceNone},
			wantBody: `{"status":"degraded","checkedAt":"2026-11-18T09:00:00Z","database":{"engine":"postgres","status":"unavailable"},` +
				`"antivirus":{"engine":"clamd","status":"unavailable"},"storage":{"status":"unavailable"},` +
				`"maintenance":{"enabled":false,"source":"none"},` +
				`"version":{"version":"2.3.0","updateCheckEnabled":false,"latestVersion":null,"updateAvailable":false}}`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			checks := &fakeChecks{report: c.report, at: checkedAt}
			s := statusServer(checks, c.db, c.av, &fakeMaintenance{state: c.state}, &fakeUpdateCheck{status: c.upd})
			expectJSON(t, []byte(statusBody(t, s)), c.wantBody)
			if checks.runs.Load() != 1 {
				t.Errorf("the shared checks ran %d times, want 1", checks.runs.Load())
			}
		})
	}
}

// The update check is only read: the service is asked its status, never to
// check.
func TestGetSystemStatusNeverChecksUpdates(t *testing.T) {
	t.Parallel()
	u := &fakeUpdateCheck{status: updatecheck.Status{Enabled: true}}
	statusBody(t, statusServer(&fakeChecks{report: allOK(), at: checkedAt}, "sqlite", "clamd", &fakeMaintenance{}, u))
	if len(u.calls) != 1 || u.calls[0] != "status:root" {
		t.Errorf("update check calls = %v, want one status read", u.calls)
	}
}

// The status and /healthz share one run of the checks within the cache
// window.
func TestGetSystemStatusSharesChecksWithHealthz(t *testing.T) {
	t.Parallel()
	var runs atomic.Int32
	svc := &health.Service{
		Database:  health.Check{Checker: health.CheckerFunc(func(context.Context) error { runs.Add(1); return nil })},
		Antivirus: health.Check{Checker: health.Disabled},
		Storage:   health.Check{Checker: health.Disabled},
	}
	healthz := health.Handler(svc, nil)
	rec := httptest.NewRecorder()
	healthz.ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
	if rec.Code != 200 {
		t.Fatalf("/healthz = %d", rec.Code)
	}
	s := statusServer(svc, "sqlite", "none", &fakeMaintenance{}, &fakeUpdateCheck{})
	statusBody(t, s)
	if runs.Load() != 1 {
		t.Errorf("the checks ran %d times for /healthz then the status, want 1", runs.Load())
	}
}

func TestGetSystemStatusRoles(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]struct {
		ctx  context.Context
		code problem.Code
	}{
		"delegated admin":    {ctxWith(store.SessionAuthenticated, delegated), problem.CodeForbidden},
		"pending second fac": {ctxWith(store.SessionTOTPRequired, superRoot), problem.CodeUnauthenticated},
		"no session":         {context.Background(), problem.CodeUnauthenticated},
	} {
		checks, m, u := &fakeChecks{report: allOK()}, &fakeMaintenance{}, &fakeUpdateCheck{}
		_, err := statusServer(checks, "sqlite", "clamd", m, u).GetSystemStatus(c.ctx, gen.GetSystemStatusRequestObject{})
		expectProblem(t, err, c.code)
		if checks.runs.Load() != 0 || len(m.calls) != 0 || len(u.calls) != 0 {
			t.Errorf("%s: a service was reached before the role check", name)
		}
	}
}

func TestGetSystemStatusErrors(t *testing.T) {
	t.Parallel()
	ctx := ctxWith(store.SessionAuthenticated, superRoot)
	checks := &fakeChecks{report: allOK(), at: checkedAt}
	for name, s := range map[string]*Server{
		"no sources":     NewServer(WithMaintenance(&fakeMaintenance{}), WithUpdateCheck(&fakeUpdateCheck{})),
		"no checks":      NewServer(WithSystemStatus(nil, "sqlite", "clamd"), WithMaintenance(&fakeMaintenance{}), WithUpdateCheck(&fakeUpdateCheck{})),
		"no maintenance": NewServer(WithSystemStatus(checks, "sqlite", "clamd"), WithUpdateCheck(&fakeUpdateCheck{})),
		"no updates":     NewServer(WithSystemStatus(checks, "sqlite", "clamd"), WithMaintenance(&fakeMaintenance{})),
	} {
		if _, err := s.GetSystemStatus(ctx, gen.GetSystemStatusRequestObject{}); !errors.Is(err, errNoSystemStatus) {
			t.Errorf("%s = %v", name, err)
		}
	}
	boom := errors.New("database down")
	if _, err := statusServer(checks, "sqlite", "clamd", &fakeMaintenance{recorder: recorder{err: boom}}, &fakeUpdateCheck{}).
		GetSystemStatus(ctx, gen.GetSystemStatusRequestObject{}); !errors.Is(err, boom) {
		t.Errorf("maintenance failure = %v", err)
	}
	if _, err := statusServer(checks, "sqlite", "clamd", &fakeMaintenance{}, &fakeUpdateCheck{err: boom}).
		GetSystemStatus(ctx, gen.GetSystemStatusRequestObject{}); !errors.Is(err, boom) {
		t.Errorf("update check failure = %v", err)
	}
	_, err := statusServer(checks, "sqlite", "clamd", &fakeMaintenance{}, &fakeUpdateCheck{err: updatecheck.ErrDisabled}).
		GetSystemStatus(ctx, gen.GetSystemStatusRequestObject{})
	expectProblem(t, err, problem.CodeUpdateCheckDisabled)
}
