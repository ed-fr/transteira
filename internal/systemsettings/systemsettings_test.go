package systemsettings

import (
	"context"
	"errors"
	"math"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

var (
	errBoom  = errors.New("boom")
	clientIP = netip.MustParseAddr("192.0.2.10")
	_        = repo((*store.SystemSettings)(nil))
	_        = Auditor((*audit.Writer)(nil))
)

// faultRepo wraps a repo and injects failures.
type faultRepo struct {
	repo
	getErr, updateErr error
}

func (f *faultRepo) Get(ctx context.Context) (store.SystemSettingsRow, error) {
	if f.getErr != nil {
		return store.SystemSettingsRow{}, f.getErr
	}
	return f.repo.Get(ctx)
}

func (f *faultRepo) UpdateTx(ctx context.Context, fn func(*store.SystemTx, *store.SystemSettingsRow) error) (store.SystemSettingsRow, error) {
	if f.updateErr != nil {
		return store.SystemSettingsRow{}, f.updateErr
	}
	return f.repo.UpdateTx(ctx, fn)
}

// faultAuditor wraps an Auditor and may fail.
type faultAuditor struct {
	Auditor
	err error
}

func (f *faultAuditor) RecordTx(ctx context.Context, tx *store.SystemTx, ev audit.Event) error {
	if f.err != nil {
		return f.err
	}
	return f.Auditor.RecordTx(ctx, tx, ev)
}

// env is a service over a real database.
type env struct {
	t       *testing.T
	db      *store.DB
	fault   *faultRepo
	auditor *faultAuditor
	svc     *Service
	changes atomic.Int32
}

func newEnv(t *testing.T, e storetest.Engine) *env {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, e.Config())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	ev := &env{t: t, db: db, fault: &faultRepo{repo: db.SystemSettings()}, auditor: &faultAuditor{Auditor: audit.New(db)}}
	ev.svc = newService(ev.fault, ev.auditor, Options{OnChange: func() { ev.changes.Add(1) }})
	return ev
}

// events returns the config.updated events, newest first.
func (ev *env) events() []store.AuditEvent {
	ev.t.Helper()
	page, err := ev.db.AuditEvents().List(context.Background(), store.AuditFilter{Action: string(audit.ActionConfigUpdated)})
	if err != nil {
		ev.t.Fatal(err)
	}
	return page.Items
}

func principal(role store.AdminRole, lang string, tids ...tenant.ID) adminauth.Principal {
	return adminauth.Principal{
		SessionID: id.New(id.AdminSession), State: store.SessionAuthenticated,
		Admin: adminauth.Account{ID: id.New(id.Admin), Username: "root", Role: role, Language: lang, TenantIDs: tids},
	}
}

func ptr[T any](v T) *T { return &v }

func set(v string) Field[string] { return Field[string]{Set: true, Value: &v} }

func TestNew(t *testing.T) {
	db, err := store.Open(context.Background(), storetest.SQLite(t).Config())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := New(nil, audit.New(db), Options{}); !errors.Is(err, errInvalidOptions) {
		t.Fatal(err)
	}
	if _, err := New(db, nil, Options{}); !errors.Is(err, errInvalidOptions) {
		t.Fatal(err)
	}
	s, err := New(db, audit.New(db), Options{})
	if err != nil || s.onChange == nil {
		t.Fatalf("New: %v %+v", err, s)
	}
	s.onChange() // the default hook is a no-op
	if MinThreshold != 0.5 || MaxThreshold != 0.99 || DefaultThreshold != 0.85 {
		t.Fatalf("bounds %v %v %v", MinThreshold, MaxThreshold, DefaultThreshold)
	}
}

func TestRights(t *testing.T) {
	ev := newEnv(t, storetest.SQLite(t))
	ctx := context.Background()
	disabled := principal(store.RoleSuperAdmin, "en")
	disabled.Admin.Disabled = true
	bad := Patch{Threshold: ptr(math.NaN()), Email: set("not an address")}
	for name, c := range map[string]struct {
		p    adminauth.Principal
		want error
	}{
		"unauthenticated": {adminauth.Principal{}, ErrUnauthenticated},
		"pending TOTP":    {adminauth.Principal{SessionID: "as_x", State: store.SessionTOTPRequired}, ErrUnauthenticated},
		"delegated admin": {principal(store.RoleDelegatedAdmin, "en", "ten_01JAB00000000000000ENT1TYA"), ErrForbidden},
		"disabled super":  {disabled, ErrForbidden},
	} {
		if _, err := ev.svc.Get(ctx, c.p); !errors.Is(err, c.want) {
			t.Errorf("%s: Get: %v", name, err)
		}
		// The rights are checked before the patch.
		if _, err := ev.svc.Update(ctx, c.p, bad, clientIP); !errors.Is(err, c.want) {
			t.Errorf("%s: Update: %v", name, err)
		}
	}
	if got := ev.events(); len(got) != 0 || ev.changes.Load() != 0 {
		t.Fatalf("refused calls left %d events, %d changes", len(got), ev.changes.Load())
	}
}

func TestThreshold(t *testing.T) {
	ev := newEnv(t, storetest.SQLite(t))
	ctx := context.Background()
	super := principal(store.RoleSuperAdmin, "en")
	for _, v := range []float64{math.NaN(), math.Inf(1), math.Inf(-1), 0.4999, 0.9901, 0, 1, -0.85} {
		_, err := ev.svc.Update(ctx, super, Patch{Threshold: ptr(v)}, clientIP)
		var inv *InvalidError
		if !errors.As(err, &inv) || inv.Field != FieldDiskAlertThreshold || !errors.Is(err, ErrInvalidInput) {
			t.Errorf("threshold %v: %v", v, err)
		} else if !strings.Contains(err.Error(), "0.50 to 0.99") {
			t.Errorf("message %q", err)
		}
	}
	// A slice, not a map: the last value stored is checked below.
	for _, c := range []struct{ v, want float64 }{{0.5, 0.5}, {0.99, 0.99}, {0.876549, 0.8765}, {0.876551, 0.8766}, {0.85, 0.85}} {
		got, err := ev.svc.Update(ctx, super, Patch{Threshold: ptr(c.v)}, clientIP)
		if err != nil || got.DiskAlertThreshold != c.want {
			t.Errorf("threshold %v: %v %+v, want %v", c.v, err, got, c.want)
		}
	}
	row, err := ev.db.SystemSettings().Get(ctx)
	if err != nil || row.DiskAlertThresholdBP != 8500 {
		t.Fatalf("stored %v %+v", err, row)
	}
}

func TestEmail(t *testing.T) {
	ev := newEnv(t, storetest.SQLite(t))
	ctx := context.Background()
	super := principal(store.RoleSuperAdmin, "fr")
	for _, v := range []string{
		"", "Ops <ops@example.com>", "ops@example.com ", " ops@example.com", "ops@example", "@example.com",
		"ops@1.2.3.4", `"o p"@example.com`, "ops@example.com\r\nBcc: x@example.com", "(c)ops@example.com",
	} {
		_, err := ev.svc.Update(ctx, super, Patch{Email: set(v)}, clientIP)
		var inv *InvalidError
		if !errors.As(err, &inv) || inv.Field != FieldAlertEmail || !errors.Is(err, ErrInvalidInput) {
			t.Errorf("email %q: %v", v, err)
		} else if strings.Contains(err.Error(), "@") {
			t.Errorf("message quotes the value: %q", err)
		}
	}
	got, err := ev.svc.Update(ctx, super, Patch{Email: set("IT-Ops@Example.COM")}, clientIP)
	if err != nil || got.AlertEmail != "it-ops@example.com" || got.AlertEmailLanguage != "fr" {
		t.Fatalf("set: %v %+v", err, got)
	}
}

func TestMergeAndAudit(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		fr, en, de := principal(store.RoleSuperAdmin, "fr"), principal(store.RoleSuperAdmin, "en"), principal(store.RoleSuperAdmin, "de")

		got, err := ev.svc.Get(ctx, fr)
		if err != nil || got != (Settings{DiskAlertThreshold: 0.85}) {
			t.Fatalf("defaults: %v %+v", err, got)
		}

		// Both fields, by a French admin.
		got, err = ev.svc.Update(ctx, fr, Patch{Threshold: ptr(0.9), Email: set("ops@example.com")}, clientIP)
		if err != nil || got != (Settings{DiskAlertThreshold: 0.9, AlertEmail: "ops@example.com", AlertEmailLanguage: "fr"}) {
			t.Fatalf("both: %v %+v", err, got)
		}
		evs := ev.events()
		if len(evs) != 1 || ev.changes.Load() != 1 {
			t.Fatalf("%d events, %d changes", len(evs), ev.changes.Load())
		}
		a := evs[0]
		if a.TenantID != "" || a.ActorKind != store.ActorAdmin || a.Actor != "root" || a.IP != clientIP ||
			a.ObjectKind != audit.ObjectSystem || a.ObjectID != "settings" ||
			string(a.Details) != `{"fields":["diskAlertThreshold","alertEmail"]}` {
			t.Fatalf("audit event %+v details %s", a, a.Details)
		}

		// Absent members are kept; an equal threshold is no change.
		got, err = ev.svc.Update(ctx, en, Patch{Threshold: ptr(0.9)}, clientIP)
		if err != nil || got.AlertEmail != "ops@example.com" || got.AlertEmailLanguage != "fr" || got.DiskAlertThreshold != 0.9 {
			t.Fatalf("no-op: %v %+v", err, got)
		}
		if got, err = ev.svc.Update(ctx, en, Patch{}, clientIP); err != nil || got.AlertEmail != "ops@example.com" {
			t.Fatalf("empty patch: %v %+v", err, got)
		}
		if len(ev.events()) != 1 || ev.changes.Load() != 1 {
			t.Fatalf("no-op patches audited: %d events, %d changes", len(ev.events()), ev.changes.Load())
		}

		// The same address set again by an English admin moves the language.
		got, err = ev.svc.Update(ctx, en, Patch{Threshold: ptr(0.8), Email: set("OPS@example.com")}, clientIP)
		if err != nil || got.AlertEmailLanguage != "en" || got.DiskAlertThreshold != 0.8 {
			t.Fatalf("language: %v %+v", err, got)
		}
		// An unsupported admin language falls back to English: no change.
		if _, err = ev.svc.Update(ctx, de, Patch{Email: set("ops@example.com")}, clientIP); err != nil {
			t.Fatal(err)
		}
		if n := len(ev.events()); n != 2 {
			t.Fatalf("%d events", n)
		}

		// null removes the address and its language.
		got, err = ev.svc.Update(ctx, fr, Patch{Email: Field[string]{Set: true}}, clientIP)
		if err != nil || got != (Settings{DiskAlertThreshold: 0.8}) {
			t.Fatalf("remove: %v %+v", err, got)
		}
		row, err := ev.db.SystemSettings().Get(ctx)
		if err != nil || row.AlertEmail != "" || row.AlertEmailLanguage != "" {
			t.Fatalf("stored %v %+v", err, row)
		}
		// Removing it again changes nothing.
		if _, err = ev.svc.Update(ctx, fr, Patch{Email: Field[string]{Set: true}}, clientIP); err != nil {
			t.Fatal(err)
		}
		evs = ev.events()
		if len(evs) != 3 || ev.changes.Load() != 3 || string(evs[0].Details) != `{"fields":["alertEmail"]}` {
			t.Fatalf("%d events, %d changes, last %s", len(evs), ev.changes.Load(), evs[0].Details)
		}
		for _, a := range evs {
			if strings.Contains(string(a.Details), "@") {
				t.Fatalf("audit details hold an address: %s", a.Details)
			}
		}
	})
}

func TestFailures(t *testing.T) {
	ev := newEnv(t, storetest.SQLite(t))
	ctx := context.Background()
	super := principal(store.RoleSuperAdmin, "en")

	ev.fault.getErr = errBoom
	if _, err := ev.svc.Get(ctx, super); !errors.Is(err, errBoom) {
		t.Fatalf("Get: %v", err)
	}
	// A no-op patch reads the settings back.
	if _, err := ev.svc.Update(ctx, super, Patch{Threshold: ptr(0.85)}, clientIP); !errors.Is(err, errBoom) {
		t.Fatalf("no-op Update: %v", err)
	}
	ev.fault.getErr = nil

	ev.fault.updateErr = errBoom
	if _, err := ev.svc.Update(ctx, super, Patch{Threshold: ptr(0.9)}, clientIP); !errors.Is(err, errBoom) {
		t.Fatalf("UpdateTx: %v", err)
	}
	ev.fault.updateErr = nil

	// An audit failure rolls the change back.
	ev.auditor.err = errBoom
	if _, err := ev.svc.Update(ctx, super, Patch{Threshold: ptr(0.9)}, clientIP); !errors.Is(err, errBoom) {
		t.Fatalf("audit: %v", err)
	}
	row, err := ev.db.SystemSettings().Get(ctx)
	if err != nil || row.DiskAlertThresholdBP != 8500 || ev.changes.Load() != 0 {
		t.Fatalf("rolled back: %v %+v, %d changes", err, row, ev.changes.Load())
	}
}
