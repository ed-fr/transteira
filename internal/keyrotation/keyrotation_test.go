package keyrotation

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/events"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/masterkey"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

func TestStartRotatesAndAudits(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e, 5)
		rot, err := ev.svc.Start(ctx, superAdmin, "123456", "", clientIP)
		if err != nil {
			t.Fatalf("Start: %v", err)
		}
		if !id.Valid(id.Rotation, rot.ID) || rot.Status != store.RotationRunning || rot.FromKeyID != ev.k1.ID() ||
			rot.ToKeyID != ev.k2.ID() || rot.TotalKeys != 5 || rot.RewrappedKeys != 0 || !rot.StartedAt.Equal(testNow) {
			t.Errorf("Start = %+v", rot)
		}
		wait(t, ev.svc)
		got, err := ev.svc.Get(ctx, superAdmin, rot.ID)
		if err != nil || got.Status != store.RotationCompleted || got.RewrappedKeys != 5 || got.CompletedAt.IsZero() {
			t.Fatalf("Get = %+v, %v", got, err)
		}
		started := ev.events(t, audit.ActionMasterKeyRotationStarted)
		if len(started) != 1 || started[0].ActorKind != store.ActorAdmin || started[0].Actor != "root" ||
			started[0].IP != clientIP || started[0].TenantID != "" || started[0].ObjectID != rot.ID ||
			started[0].ObjectKind != audit.ObjectMasterKeyRotation || started[0].details["from"] != ev.k1.ID() ||
			started[0].details["to"] != ev.k2.ID() || started[0].details["total"] != float64(5) ||
			started[0].details["resumed"] != false {
			t.Errorf("started events = %+v", started)
		}
		if pub := ev.published.Events(); len(pub) != 1 || pub[0].Type != events.MasterKeyRotationCompleted ||
			pub[0].Counts["totalKeys"] != 5 || pub[0].Counts["rewrappedKeys"] != 5 {
			t.Errorf("published %+v", pub)
		}
		completed := ev.events(t, audit.ActionMasterKeyRotationCompleted)
		if len(completed) != 1 || completed[0].ActorKind != store.ActorSystem || completed[0].Actor != SystemActor ||
			completed[0].ObjectID != rot.ID || completed[0].details["rewrapped"] != float64(5) {
			t.Errorf("completed events = %+v", completed)
		}
		if !strings.Contains(ev.logs.String(), "restart with the switched configuration") {
			t.Errorf("logs lack the restart warning: %s", ev.logs)
		}
		for _, s := range ev.secrets {
			if strings.Contains(ev.logs.String(), fmt.Sprintf("%x", s)) {
				t.Fatal("the logs contain a secret")
			}
		}

		st, err := ev.svc.Status(ctx, superAdmin)
		if err != nil || st.ActiveKeyID != ev.k1.ID() || st.NewKeyID != ev.k2.ID() || !st.RestartRequired ||
			st.LatestRotation == nil || st.LatestRotation.ID != rot.ID || st.LatestRotation.Status != store.RotationCompleted {
			t.Errorf("Status = %+v, %v", st, err)
		}
		// Completed: a new start asks for the restart, before the TOTP
		// check (the recovery code is not consumed).
		_, err = ev.svc.Start(ctx, superAdmin, "", "ABCD-EFGH", clientIP)
		if !errors.Is(err, ErrRestartRequired) || !errors.Is(err, ErrConflict) {
			t.Errorf("Start after completion = %v", err)
		}
		if n := ev.confirm.count(); n != 1 {
			t.Errorf("TOTP checked %d times, want 1 (not on the refused start)", n)
		}
	})
}

func TestStartChecks(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e, 1)
		delegated := superAdmin
		delegated.Admin.Role = store.RoleDelegatedAdmin
		pending := superAdmin
		pending.State = store.SessionTOTPRequired
		for _, tt := range []struct {
			name string
			p    adminauth.Principal
			want error
		}{
			{"no session", adminauth.Principal{}, adminauth.ErrUnauthenticated},
			{"intermediate session", pending, adminauth.ErrUnauthenticated},
			{"delegated admin", delegated, adminauth.ErrForbidden},
		} {
			if _, err := ev.svc.Start(ctx, tt.p, "123456", "", clientIP); !errors.Is(err, tt.want) {
				t.Errorf("Start(%s) = %v, want %v", tt.name, err, tt.want)
			}
			if _, err := ev.svc.Get(ctx, tt.p, "rot_01JABCM8Q9R0S1T2V3V4W5X6Y7"); !errors.Is(err, tt.want) {
				t.Errorf("Get(%s) = %v, want %v", tt.name, err, tt.want)
			}
			if _, err := ev.svc.Status(ctx, tt.p); !errors.Is(err, tt.want) {
				t.Errorf("Status(%s) = %v, want %v", tt.name, err, tt.want)
			}
		}
		if n := ev.confirm.count(); n != 0 {
			t.Errorf("TOTP checked %d times before the role check", n)
		}
		if err := ev.svc.WarnInterrupted(ctx); err != nil || strings.Contains(ev.logs.String(), "is waiting") {
			t.Errorf("WarnInterrupted(no rotation) = %v, logs %s", err, ev.logs)
		}

		// Without a new key, refused before the TOTP check.
		only := New(ev.db, keyring(t, ev.k1, nil), ev.confirm, ev.audit, Options{})
		if _, err := only.Start(ctx, superAdmin, "123456", "", clientIP); !errors.Is(err, ErrNoNewKey) {
			t.Errorf("Start(no new key) = %v", err)
		}
		if n := ev.confirm.count(); n != 0 {
			t.Errorf("TOTP checked %d times without a new key", n)
		}
		st, err := only.Status(ctx, superAdmin)
		if err != nil || st.ActiveKeyID != ev.k1.ID() || st.NewKeyID != "" || st.RestartRequired || st.LatestRotation != nil {
			t.Errorf("Status(no new key) = %+v, %v", st, err)
		}

		// The TOTP errors pass through; nothing starts.
		for _, want := range []error{adminauth.ErrInvalidCredentials, &adminauth.RateLimitError{RetryAfter: time.Minute}} {
			ev.confirm.err = want
			if _, err := ev.svc.Start(ctx, superAdmin, "123456", "", clientIP); !errors.Is(err, want) {
				t.Errorf("Start(TOTP %v) = %v", want, err)
			}
		}
		ev.confirm.err = nil
		// The confirmed account lost its role meanwhile.
		ev.confirm.role = store.RoleDelegatedAdmin
		if _, err := ev.svc.Start(ctx, superAdmin, "123456", "", clientIP); !errors.Is(err, adminauth.ErrForbidden) {
			t.Errorf("Start(demoted) = %v", err)
		}
		ev.confirm.role = ""
		if _, err := ev.db.KeyRotations().Running(ctx); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("a rotation started: %v", err)
		}
		if n := len(ev.events(t, audit.ActionMasterKeyRotationStarted)); n != 0 {
			t.Errorf("started events = %d", n)
		}

		// Get: malformed and unknown identifiers.
		for _, rotID := range []string{"", "rot_x", "rot_01JABCM8Q9R0S1T2V3V4W5X6Y7"} {
			if _, err := ev.svc.Get(ctx, superAdmin, rotID); !errors.Is(err, ErrNotFound) {
				t.Errorf("Get(%q) = %v", rotID, err)
			}
		}
	})
}

// TestShutdownThenResume interrupts a rotation by Close: it is never
// recorded as failed, and the next instance resumes it with the same ID.
func TestShutdownThenResume(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e, 6)
		g := newGate()
		ev.opts.OnProgress = g.hook
		svc := ev.newService(t)
		rot, err := svc.Start(ctx, superAdmin, "123456", "", clientIP)
		if err != nil {
			t.Fatal(err)
		}
		<-g.reached
		// Running in this instance: a second start is refused before the
		// TOTP check, Done is open.
		if _, err := svc.Start(ctx, superAdmin, "", "ABCD-EFGH", clientIP); !errors.Is(err, ErrRunning) || !errors.Is(err, ErrConflict) {
			t.Errorf("second Start = %v", err)
		}
		if n := ev.confirm.count(); n != 1 {
			t.Errorf("TOTP checked %d times, want 1 (not on the refused start)", n)
		}
		select {
		case <-svc.Done():
			t.Fatal("Done closed while the worker runs")
		default:
		}
		closed := make(chan error, 1)
		go func() { closed <- svc.Close(ctx) }()
		<-svc.ctx.Done() // Close canceled the worker
		close(g.release)
		if err := <-closed; err != nil {
			t.Fatalf("Close = %v", err)
		}
		wait(t, svc)
		if _, err := svc.Start(ctx, superAdmin, "123456", "", clientIP); !errors.Is(err, ErrClosed) {
			t.Errorf("Start after Close = %v", err)
		}
		if n := ev.confirm.count(); n != 1 {
			t.Errorf("TOTP checked %d times after Close, want 1", n)
		}
		running, err := ev.db.KeyRotations().Running(ctx)
		if err != nil || running.ID != rot.ID || running.RewrappedKeys != 2 || running.Error != "" {
			t.Fatalf("Running after the shutdown = %+v, %v", running, err)
		}
		if n := len(ev.events(t, audit.ActionMasterKeyRotationFailed)); n != 0 {
			t.Errorf("failed events after an interruption = %d", n)
		}
		if !strings.Contains(ev.logs.String(), "interrupted by the shutdown") {
			t.Errorf("logs = %s", ev.logs)
		}

		// The next instance warns at start-up, then resumes on request.
		ev.opts.OnProgress = nil
		next := ev.newService(t)
		if err := next.WarnInterrupted(ctx); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(ev.logs.String(), "an interrupted master key rotation is waiting") {
			t.Errorf("no start-up warning: %s", ev.logs)
		}
		resumed, err := next.Start(ctx, superAdmin, "", "ABCD-EFGH", clientIP)
		if err != nil || resumed.ID != rot.ID || resumed.RewrappedKeys != 2 {
			t.Fatalf("Start(resume) = %+v, %v", resumed, err)
		}
		wait(t, next)
		started := ev.events(t, audit.ActionMasterKeyRotationStarted)
		resumedEvents := 0
		for _, s := range started {
			if s.ObjectID == rot.ID && s.details["resumed"] == true {
				resumedEvents++
			}
		}
		if len(started) != 2 || resumedEvents != 1 {
			t.Errorf("started events = %+v", started)
		}
		if got, err := next.Get(ctx, superAdmin, rot.ID); err != nil || got.Status != store.RotationCompleted || got.RewrappedKeys != 6 {
			t.Errorf("Get after resume = %+v, %v", got, err)
		}
	})
}

func TestMismatchAndFailure(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e, 3)
		// An interrupted rotation towards another key.
		k3 := newKey(t)
		other := store.Rotation{ID: id.New(id.Rotation), FromKeyID: ev.k1.ID(), ToKeyID: k3.ID(), StartedAt: testNow}
		if err := ev.db.KeyRotations().Start(ctx, other); err != nil {
			t.Fatal(err)
		}
		if err := ev.svc.WarnInterrupted(ctx); err != nil || strings.Contains(ev.logs.String(), "is waiting") {
			t.Errorf("WarnInterrupted(other keys) = %v, logs %s", err, ev.logs)
		}
		_, err := ev.svc.Start(ctx, superAdmin, "123456", "", clientIP)
		if !errors.Is(err, ErrRotationMismatch) || !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), other.ID) {
			t.Errorf("Start(mismatch) = %v", err)
		}
		if n := ev.confirm.count(); n != 0 {
			t.Errorf("TOTP checked %d times on a mismatch", n)
		}
		if _, err := masterkey.Abandon(ctx, ev.db, testNow); err != nil {
			t.Fatal(err)
		}

		// A corrupted row fails the rotation.
		garbage := make([]byte, 60)
		if _, err := rand.Read(garbage); err != nil {
			t.Fatal(err)
		}
		bad := store.WrappedKey{ID: id.New(id.WrappedKey), Purpose: store.KeyPurposeDEK, KeyID: ev.k1.ID(), Blob: garbage}
		if err := ev.db.WrappedKeys().Create(ctx, ev.tid, bad); err != nil {
			t.Fatal(err)
		}
		rot, err := ev.svc.Start(ctx, superAdmin, "123456", "", clientIP)
		if err != nil {
			t.Fatal(err)
		}
		wait(t, ev.svc)
		failed := ev.events(t, audit.ActionMasterKeyRotationFailed)
		if len(failed) != 1 || failed[0].ObjectID != rot.ID || failed[0].Actor != SystemActor ||
			failed[0].details["reason"] != "rewrap" || !strings.Contains(fmt.Sprint(failed[0].details["error"]), bad.ID) {
			t.Errorf("failed events = %+v", failed)
		}
		if got, err := ev.svc.Get(ctx, superAdmin, rot.ID); err != nil || got.Status != store.RotationFailed || got.Error == "" {
			t.Errorf("Get(failed) = %+v, %v", got, err)
		}
	})
}

// fakeRotate returns a rotate function returning rot and err (after run,
// when set).
func fakeRotate(rot store.Rotation, err error, run func()) func(context.Context, *store.DB, *masterkey.Keyring, *slog.Logger, masterkey.Options) (store.Rotation, error) {
	return func(context.Context, *store.DB, *masterkey.Keyring, *slog.Logger, masterkey.Options) (store.Rotation, error) {
		if run != nil {
			run()
		}
		return rot, err
	}
}

// TestWorkerOutcomes covers the outcomes the real engine rarely gives.
func TestWorkerOutcomes(t *testing.T) {
	tests := []struct {
		name string
		// rotate builds the fake engine from the started rotation.
		rotate     func(ev *env, rot store.Rotation) func(context.Context, *store.DB, *masterkey.Keyring, *slog.Logger, masterkey.Options) (store.Rotation, error)
		wantAction audit.Action
		wantReason string
		wantLog    string
	}{
		{
			name: "keys still created",
			rotate: func(_ *env, rot store.Rotation) func(context.Context, *store.DB, *masterkey.Keyring, *slog.Logger, masterkey.Options) (store.Rotation, error) {
				return fakeRotate(rot, masterkey.ErrKeysStillCreated, nil)
			},
			wantAction: audit.ActionMasterKeyRotationFailed, wantReason: "keys_still_created", wantLog: "can be resumed",
		},
		{
			name: "store error before the rotation",
			rotate: func(_ *env, _ store.Rotation) func(context.Context, *store.DB, *masterkey.Keyring, *slog.Logger, masterkey.Options) (store.Rotation, error) {
				return fakeRotate(store.Rotation{}, errFault, nil)
			},
			wantAction: audit.ActionMasterKeyRotationFailed, wantReason: "error", wantLog: "can be resumed",
		},
		{
			name: "completed by the command",
			rotate: func(ev *env, rot store.Rotation) func(context.Context, *store.DB, *masterkey.Keyring, *slog.Logger, masterkey.Options) (store.Rotation, error) {
				return fakeRotate(rot, fmt.Errorf("masterkey: rotate: %w", store.ErrRotationNotRunning), func() {
					if _, err := masterkey.Rotate(context.Background(), ev.db, ev.keys, nil, masterkey.Options{}); err != nil {
						panic(err)
					}
				})
			},
			wantLog: "status=completed",
		},
		{
			name: "finished elsewhere, unreadable",
			rotate: func(ev *env, rot store.Rotation) func(context.Context, *store.DB, *masterkey.Keyring, *slog.Logger, masterkey.Options) (store.Rotation, error) {
				return fakeRotate(rot, store.ErrRotationNotRunning, func() { _ = ev.db.Close() })
			},
			wantLog: "its state cannot be read",
		},
		{
			name: "completed before the worker",
			rotate: func(_ *env, rot store.Rotation) func(context.Context, *store.DB, *masterkey.Keyring, *slog.Logger, masterkey.Options) (store.Rotation, error) {
				ran := rot
				ran.ID = id.New(id.Rotation)
				ran.Status = store.RotationCompleted
				return fakeRotate(ran, nil, nil)
			},
			wantAction: audit.ActionMasterKeyRotationCompleted, wantLog: "before the worker started",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			ev := newEnv(t, storetest.SQLite(t), 2)
			var started store.Rotation
			ev.svc.start = func(ctx context.Context, db *store.DB, kr *masterkey.Keyring, now time.Time) (store.Rotation, error) {
				rot, err := masterkey.StartRotation(ctx, db, kr, now)
				started = rot
				return rot, err
			}
			ev.svc.rotate = func(ctx context.Context, db *store.DB, kr *masterkey.Keyring, l *slog.Logger, o masterkey.Options) (store.Rotation, error) {
				return tt.rotate(ev, started)(ctx, db, kr, l, o)
			}
			if _, err := ev.svc.Start(ctx, superAdmin, "123456", "", clientIP); err != nil {
				t.Fatal(err)
			}
			wait(t, ev.svc)
			if !strings.Contains(ev.logs.String(), tt.wantLog) {
				t.Errorf("logs lack %q: %s", tt.wantLog, ev.logs)
			}
			if tt.name == "finished elsewhere, unreadable" {
				return // the database is closed
			}
			for _, action := range []audit.Action{audit.ActionMasterKeyRotationCompleted, audit.ActionMasterKeyRotationFailed} {
				got := ev.events(t, action)
				switch {
				case action != tt.wantAction && len(got) != 0:
					t.Errorf("%s events = %+v", action, got)
				case action == tt.wantAction && len(got) != 1:
					t.Errorf("%s events = %+v", action, got)
				case action == tt.wantAction && tt.wantReason != "" && got[0].details["reason"] != tt.wantReason:
					t.Errorf("%s reason = %v", action, got[0].details["reason"])
				}
			}
			// The event published follows the audit event.
			published := ev.published.Events()
			wantType, wantSeverity := map[audit.Action]events.Type{
				audit.ActionMasterKeyRotationCompleted: events.MasterKeyRotationCompleted,
				audit.ActionMasterKeyRotationFailed:    events.MasterKeyRotationFailed,
			}[tt.wantAction], events.SeverityCritical
			if tt.wantAction == audit.ActionMasterKeyRotationCompleted {
				wantSeverity = events.SeverityInfo
			}
			switch {
			case tt.wantAction == "" && len(published) != 0:
				t.Errorf("published %+v", published)
			case tt.wantAction != "" && (len(published) != 1 || published[0].Type != wantType ||
				published[0].Severity != wantSeverity || published[0].AdminPath != events.AdminPathMasterKey ||
				!published[0].OccurredAt.Equal(testNow) || published[0].TenantID != ""):
				t.Errorf("published %+v", published)
			}
		})
	}
}

// TestStartRecheck changes the state during the TOTP re-confirmation,
// after the advisory check: the authoritative check under the lock refuses
// the start.
func TestStartRecheck(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e, 1)
		// A rotation between other keys appears meanwhile.
		other := store.Rotation{ID: id.New(id.Rotation), FromKeyID: ev.k1.ID(), ToKeyID: newKey(t).ID(), StartedAt: testNow}
		ev.confirm.during = func() {
			if err := ev.db.KeyRotations().Start(ctx, other); err != nil {
				t.Error(err)
			}
		}
		if _, err := ev.svc.Start(ctx, superAdmin, "123456", "", clientIP); !errors.Is(err, ErrRotationMismatch) {
			t.Errorf("Start(mismatch meanwhile) = %v", err)
		}
		if _, err := masterkey.Abandon(ctx, ev.db, testNow); err != nil {
			t.Fatal(err)
		}
		// The instance shuts down meanwhile.
		svc := ev.newService(t)
		ev.confirm.during = func() {
			if err := svc.Close(ctx); err != nil {
				t.Error(err)
			}
		}
		if _, err := svc.Start(ctx, superAdmin, "123456", "", clientIP); !errors.Is(err, ErrClosed) {
			t.Errorf("Start(closed meanwhile) = %v", err)
		}
		ev.confirm.during = nil
		if n := ev.confirm.count(); n != 2 {
			t.Errorf("TOTP checked %d times, want 2", n)
		}
		if n := len(ev.events(t, audit.ActionMasterKeyRotationStarted)); n != 0 {
			t.Errorf("started events = %d", n)
		}
	})
}

func TestFaults(t *testing.T) {
	t.Run("start engine", func(t *testing.T) {
		ctx := t.Context()
		ev := newEnv(t, storetest.SQLite(t), 1)
		ev.svc.start = func(context.Context, *store.DB, *masterkey.Keyring, time.Time) (store.Rotation, error) {
			return store.Rotation{}, fmt.Errorf("start: %w", store.ErrRotationRunning)
		}
		if _, err := ev.svc.Start(ctx, superAdmin, "123456", "", clientIP); !errors.Is(err, ErrRunning) {
			t.Errorf("Start(started elsewhere) = %v", err)
		}
		ev.svc.start = func(context.Context, *store.DB, *masterkey.Keyring, time.Time) (store.Rotation, error) {
			return store.Rotation{}, errFault
		}
		if _, err := ev.svc.Start(ctx, superAdmin, "123456", "", clientIP); !errors.Is(err, errFault) {
			t.Errorf("Start(start fault) = %v", err)
		}
	})

	t.Run("audit", func(t *testing.T) {
		ctx := t.Context()
		ev := newEnv(t, storetest.SQLite(t), 1)
		ev.audit.set(errFault)
		if _, err := ev.svc.Start(ctx, superAdmin, "123456", "", clientIP); !errors.Is(err, errFault) {
			t.Errorf("Start(audit fault) = %v", err)
		}
		// Not launched, but recorded: the next request resumes it.
		running, err := ev.db.KeyRotations().Running(ctx)
		if err != nil || running.RewrappedKeys != 0 {
			t.Fatalf("Running = %+v, %v", running, err)
		}
		select {
		case <-ev.svc.Done():
		default:
			t.Error("a worker runs without audit")
		}
		// The worker's own audit failure is only logged.
		g := newGate()
		ev.opts.OnProgress = g.hook
		svc := ev.newService(t)
		ev.audit.set(nil)
		if _, err := svc.Start(ctx, superAdmin, "123456", "", clientIP); err != nil {
			t.Fatal(err)
		}
		<-g.reached
		ev.audit.set(errFault)
		close(g.release)
		wait(t, svc)
		if !strings.Contains(ev.logs.String(), "audit write failed") {
			t.Errorf("logs = %s", ev.logs)
		}
	})

	t.Run("close timeout", func(t *testing.T) {
		ctx := t.Context()
		ev := newEnv(t, storetest.SQLite(t), 3)
		g := newGate()
		ev.opts.OnProgress = g.hook
		svc := ev.newService(t)
		if _, err := svc.Start(ctx, superAdmin, "123456", "", clientIP); err != nil {
			t.Fatal(err)
		}
		<-g.reached
		short, cancel := context.WithTimeout(ctx, 10*time.Millisecond)
		defer cancel()
		if err := svc.Close(short); !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("Close(short) = %v", err)
		}
		close(g.release)
		wait(t, svc)
	})

	t.Run("store", func(t *testing.T) {
		ctx := t.Context()
		ev := newEnv(t, storetest.SQLite(t), 1)
		ev.execRaw(t, `DROP TABLE master_keys`)
		if _, err := ev.svc.Start(ctx, superAdmin, "123456", "", clientIP); err == nil || errors.Is(err, ErrConflict) {
			t.Errorf("Start(active key fault) = %v", err)
		}
		if _, err := ev.svc.Status(ctx, superAdmin); err == nil {
			t.Error("Status(active key fault) succeeded")
		}

		ev = newEnv(t, storetest.SQLite(t), 1)
		ev.execRaw(t, `DROP TABLE key_rotations`)
		if _, err := ev.svc.Start(ctx, superAdmin, "123456", "", clientIP); err == nil || errors.Is(err, ErrConflict) {
			t.Errorf("Start(running fault) = %v", err)
		}
		if _, err := ev.svc.Status(ctx, superAdmin); err == nil {
			t.Error("Status(latest fault) succeeded")
		}
		if _, err := ev.svc.Get(ctx, superAdmin, "rot_01JABCM8Q9R0S1T2V3V4W5X6Y7"); err == nil || errors.Is(err, ErrNotFound) {
			t.Errorf("Get(fault) = %v", err)
		}
		if err := ev.svc.WarnInterrupted(ctx); err == nil {
			t.Error("WarnInterrupted(fault) succeeded")
		}
	})
}

// TestViewOfStoredTimes: the view of a rotation just started, whose times
// come from the clock, reads as the stored one (UTC, millisecond precision),
// and a zero completion time stays zero.
func TestViewOfStoredTimes(t *testing.T) {
	t.Parallel()
	local := time.Date(2026, 10, 23, 11, 30, 0, 123456789, time.FixedZone("CEST", 2*3600))
	v := viewOf(store.Rotation{StartedAt: local})
	want := time.Date(2026, 10, 23, 9, 30, 0, 123000000, time.UTC)
	if v.StartedAt != want || !v.CompletedAt.IsZero() {
		t.Errorf("viewOf times = %v, %v; want %v and zero", v.StartedAt, v.CompletedAt, want)
	}
	v = viewOf(store.Rotation{StartedAt: local, CompletedAt: local.Add(time.Second)})
	if v.CompletedAt != want.Add(time.Second) {
		t.Errorf("viewOf completedAt = %v", v.CompletedAt)
	}
}
