package audit_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

var testNow = time.Date(2026, 10, 22, 9, 0, 0, 0, time.UTC)

// openDB returns a migrated database on engine e.
func openDB(t *testing.T, e storetest.Engine) *store.DB {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, e.Config(), store.WithClock(func() time.Time { return testNow }))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return db
}

func event(action audit.Action) audit.Event {
	return audit.Event{
		ActorKind: store.ActorAdmin, Actor: "root", IP: netip.MustParseAddr("192.0.2.10"),
		Action: action, ObjectKind: audit.ObjectAdmin, ObjectID: "adm_01JABCG1H2J3K415M6N7P8Q9R0",
		Details: map[string]any{"method": "totp"},
	}
}

func TestWriter(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		db := openDB(t, e)
		w := audit.New(db)

		if err := w.Record(ctx, event(audit.ActionAdminLogin)); err != nil {
			t.Fatalf("Record = %v", err)
		}
		noDetails := event(audit.ActionSetupCompleted)
		noDetails.Details = nil
		err := db.Admins().Tx(ctx, func(tx *store.SystemTx) error { return w.RecordTx(ctx, tx, noDetails) })
		if err != nil {
			t.Fatalf("RecordTx = %v", err)
		}

		page, err := db.AuditEvents().List(ctx, store.AuditFilter{})
		if err != nil || len(page.Items) != 2 {
			t.Fatalf("List = %d items, %v", len(page.Items), err)
		}
		byAction := map[string]store.AuditEvent{}
		for _, ev := range page.Items {
			byAction[ev.Action] = ev
		}
		login := byAction["admin.login"]
		var details map[string]string
		if err := json.Unmarshal(login.Details, &details); err != nil || details["method"] != "totp" ||
			login.Actor != "root" || login.ActorKind != store.ActorAdmin || login.ObjectKind != "admin" ||
			login.IP.String() != "192.0.2.10" || login.TenantID != "" {
			t.Errorf("login event = %+v (%v)", login, err)
		}
		if setup := byAction["setup.completed"]; setup.Details != nil {
			t.Errorf("setup event details = %s, want none", setup.Details)
		}

		// A malformed event is refused by the store, in both paths.
		bad := event("Not An Action")
		if err := w.Record(ctx, bad); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("Record(bad action) = %v, want ErrInvalid", err)
		}
		err = db.Admins().Tx(ctx, func(tx *store.SystemTx) error { return w.RecordTx(ctx, tx, bad) })
		if !errors.Is(err, store.ErrInvalid) {
			t.Errorf("RecordTx(bad action) = %v, want ErrInvalid", err)
		}
	})
}

func TestWriterRefusesSecrets(t *testing.T) {
	db := openDB(t, storetest.SQLite(t))
	w := audit.New(db)
	ctx := context.Background()
	for _, key := range []string{"password", "newPassword", "Secret", "session_token", "totp_code", "recovery_code", "passphrase"} {
		ev := event(audit.ActionAdminLogin)
		ev.Details = map[string]any{key: "x"}
		if err := w.Record(ctx, ev); !errors.Is(err, audit.ErrSecretDetail) {
			t.Errorf("Record(%s) = %v, want ErrSecretDetail", key, err)
		}
		err := db.Admins().Tx(ctx, func(tx *store.SystemTx) error { return w.RecordTx(ctx, tx, ev) })
		if !errors.Is(err, audit.ErrSecretDetail) {
			t.Errorf("RecordTx(%s) = %v, want ErrSecretDetail", key, err)
		}
	}
	// A value JSON cannot encode is an error too.
	ev := event(audit.ActionAdminLogin)
	ev.Details = map[string]any{"fields": func() {}}
	if err := w.Record(ctx, ev); err == nil {
		t.Error("Record(unencodable details) = nil, want an error")
	}
	page, err := db.AuditEvents().List(ctx, store.AuditFilter{})
	if err != nil || len(page.Items) != 0 {
		t.Errorf("List = %d items, %v, want none", len(page.Items), err)
	}
}

// newTenant creates a tenant in db.
func newTenant(t *testing.T, db *store.DB, fqdn string) *tenant.Tenant {
	t.Helper()
	tn, err := db.Tenants().Create(context.Background(), &tenant.Tenant{
		Name: "Entity " + fqdn, FQDN: fqdn, DefaultLanguage: "en",
		MaxTransferBytes: 1 << 30, StorageQuotaBytes: 100 << 30,
	})
	if err != nil {
		t.Fatalf("Create(%s): %v", fqdn, err)
	}
	return tn
}

func TestRecordScoped(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		db := openDB(t, e)
		w := audit.New(db)
		ta := newTenant(t, db, "transfer.entity-a.example.com")
		tb := newTenant(t, db, "transfer.entity-b.example.com")

		ev := audit.Event{
			ActorKind: store.ActorSystem, Actor: "quota",
			Action: audit.ActionQuotaWarning, ObjectKind: audit.ObjectTenant, ObjectID: string(ta.ID),
			Details: map[string]any{"level": 80},
		}
		if err := w.RecordScoped(ctx, ta.ID, ev); err != nil {
			t.Fatalf("RecordScoped = %v", err)
		}
		explicit := ev
		explicit.TenantID = ta.ID
		explicit.Action = audit.ActionQuotaReached
		if err := w.RecordScoped(ctx, ta.ID, explicit); err != nil {
			t.Fatalf("RecordScoped(explicit tenant) = %v", err)
		}

		// Another tenant, a malformed tenant, a malformed event and
		// personal details are all refused.
		other := ev
		other.TenantID = tb.ID
		if err := w.RecordScoped(ctx, ta.ID, other); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("RecordScoped(other tenant) = %v, want ErrInvalid", err)
		}
		if err := w.RecordScoped(ctx, "bogus", ev); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("RecordScoped(bogus tenant) = %v, want ErrInvalid", err)
		}
		bad := ev
		bad.Action = "Not An Action"
		if err := w.RecordScoped(ctx, ta.ID, bad); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("RecordScoped(bad action) = %v, want ErrInvalid", err)
		}
		personal := ev
		personal.Details = map[string]any{"to": "someone@example.com"}
		if err := w.RecordScoped(ctx, ta.ID, personal); !errors.Is(err, audit.ErrPersonalDetail) {
			t.Errorf("RecordScoped(personal) = %v, want ErrPersonalDetail", err)
		}

		// RecordScopedTx writes with the transaction, applies the same
		// checks and refuses an event of another tenant.
		sa, err := db.Scoped(ta.ID)
		if err != nil {
			t.Fatal(err)
		}
		inTx := explicit
		inTx.Action = audit.ActionTransferDownloaded
		if err := sa.Tx(ctx, func(tx *store.ScopedTx) error { return w.RecordScopedTx(ctx, tx, inTx) }); err != nil {
			t.Fatalf("RecordScopedTx = %v", err)
		}
		errRollback := errors.New("rollback")
		if err := sa.Tx(ctx, func(tx *store.ScopedTx) error {
			if err := w.RecordScopedTx(ctx, tx, ev); err != nil {
				return err
			}
			return errRollback
		}); !errors.Is(err, errRollback) {
			t.Fatalf("RecordScopedTx(rolled back) = %v", err)
		}
		secret := ev
		secret.Details = map[string]any{"token": "x"}
		for name, bad := range map[string]audit.Event{"secret": secret, "personal": personal, "other tenant": other} {
			want := audit.ErrSecretDetail
			switch name {
			case "personal":
				want = audit.ErrPersonalDetail
			case "other tenant":
				want = store.ErrInvalid
			}
			if err := sa.Tx(ctx, func(tx *store.ScopedTx) error { return w.RecordScopedTx(ctx, tx, bad) }); !errors.Is(err, want) {
				t.Errorf("RecordScopedTx(%s) = %v, want %v", name, err, want)
			}
		}

		page, err := db.AuditEvents().List(ctx, store.AuditFilter{TenantID: ta.ID})
		if err != nil || len(page.Items) != 3 {
			t.Fatalf("List(a) = %d items, %v, want 3", len(page.Items), err)
		}
		for _, got := range page.Items {
			if got.TenantID != ta.ID || got.Actor != "quota" || got.ObjectKind != "tenant" {
				t.Errorf("event = %+v", got)
			}
		}
		page, err = db.AuditEvents().List(ctx, store.AuditFilter{TenantID: tb.ID})
		if err != nil || len(page.Items) != 0 {
			t.Errorf("List(b) = %d items, %v, want none", len(page.Items), err)
		}
	})
}

// typedAddress is a string type, to check that the guard sees through
// named types.
type typedAddress string

// rawDetail marshals to a JSON string escaping its at sign.
type rawDetail struct{}

func (rawDetail) MarshalJSON() ([]byte, error) {
	return []byte(strings.ReplaceAll(`"a#u0040example.com"`, "#", string(rune(0x5c)))), nil
}

func TestWriterRefusesPersonalDetails(t *testing.T) {
	db := openDB(t, storetest.SQLite(t))
	w := audit.New(db)
	ctx := context.Background()
	refused := map[string]map[string]any{
		"string":       {"from": "noreply@example.com"},
		"full-width":   {"from": "noreply" + string(rune(0xFF20)) + "example.com"},
		"small":        {"from": "noreply" + string(rune(0xFE6B)) + "example.com"},
		"typed string": {"from": typedAddress("a@example.com")},
		"string slice": {"to": []string{"ok", "a@example.com"}},
		"any slice":    {"to": []any{1, true, nil, "a@example.com"}},
		"nested map":   {"smtp": map[string]any{"fields": []any{map[string]string{"from": "a@example.com"}}}},
		"key":          {"a@example.com": 1},
		"nested key":   {"m": map[string]int{"a@example.com": 1}},
		"marshaler":    {"v": rawDetail{}},
	}
	for name, details := range refused {
		ev := event(audit.ActionAdminLogin)
		ev.Details = details
		if err := w.Record(ctx, ev); !errors.Is(err, audit.ErrPersonalDetail) {
			t.Errorf("Record(%s) = %v, want ErrPersonalDetail", name, err)
		}
		err := db.Admins().Tx(ctx, func(tx *store.SystemTx) error { return w.RecordTx(ctx, tx, ev) })
		if !errors.Is(err, audit.ErrPersonalDetail) {
			t.Errorf("RecordTx(%s) = %v, want ErrPersonalDetail", name, err)
		}
	}
	// Details without an address pass, whatever their shape.
	ok := event(audit.ActionAdminLogin)
	ok.Details = map[string]any{
		"fields": []string{"fromAddress", "host"}, "count": 3, "on": true, "none": nil,
		"nested": map[string]any{"list": []any{1.5, "x", map[string]any{"k": "v"}}},
		"reason": audit.RedactAddresses("asked by a@example.com"),
	}
	if err := w.Record(ctx, ok); err != nil {
		t.Errorf("Record(no address) = %v", err)
	}
	page, err := db.AuditEvents().List(ctx, store.AuditFilter{})
	if err != nil || len(page.Items) != 1 {
		t.Errorf("List = %d items, %v, want 1", len(page.Items), err)
	}
}

// TestSystemActions records the instance events of step 14 (settings,
// maintenance, master key rotation, disk alert) as global events, in one
// transaction with a change of the system settings.
func TestSystemActions(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		db := openDB(t, e)
		w := audit.New(db)
		events := []audit.Event{
			{
				ActorKind: store.ActorAdmin, Actor: "root", Action: audit.ActionConfigUpdated, ObjectKind: audit.ObjectSystem, ObjectID: "settings",
				Details: map[string]any{"fields": []string{"diskAlertThreshold", "alertEmail"}},
			},
			{
				ActorKind: store.ActorAdmin, Actor: "root", Action: audit.ActionMaintenanceEnabled, ObjectKind: audit.ObjectSystem, ObjectID: "maintenance",
				Details: map[string]any{"languages": []string{"en", "fr"}},
			},
			{ActorKind: store.ActorAdmin, Actor: "root", Action: audit.ActionMaintenanceDisabled, ObjectKind: audit.ObjectSystem, ObjectID: "maintenance"},
			{
				ActorKind: store.ActorAdmin, Actor: "root", Action: audit.ActionMasterKeyRotationStarted, ObjectKind: audit.ObjectMasterKeyRotation, ObjectID: "rot_01JABCM8Q9R0S1T2V3V4W5X6Y7",
				Details: map[string]any{"from": "mk_3f9a0c41d27be865", "to": "mk_b81e2d07c4a95f13", "total": 3, "resumed": false},
			},
			{ActorKind: store.ActorSystem, Actor: "master-key-rotation", Action: audit.ActionMasterKeyRotationCompleted, ObjectKind: audit.ObjectMasterKeyRotation, ObjectID: "rot_01JABCM8Q9R0S1T2V3V4W5X6Y7"},
			{ActorKind: store.ActorSystem, Actor: "master-key-rotation", Action: audit.ActionMasterKeyRotationFailed, ObjectKind: audit.ObjectMasterKeyRotation, ObjectID: "rot_01JABCM8Q9R0S1T2V3V4W5X6Y7"},
			{
				ActorKind: store.ActorSystem, Actor: "disk", Action: audit.ActionDiskAlertRaised, ObjectKind: audit.ObjectSystem, ObjectID: "disk",
				Details: map[string]any{"usedPercent": 91, "thresholdPercent": 85},
			},
			{ActorKind: store.ActorSystem, Actor: "disk", Action: audit.ActionDiskAlertCleared, ObjectKind: audit.ObjectSystem, ObjectID: "disk"},
		}
		_, err := db.SystemSettings().UpdateTx(ctx, func(tx *store.SystemTx, s *store.SystemSettingsRow) error {
			s.MaintenanceEnabled = true
			for _, ev := range events {
				if err := w.RecordTx(ctx, tx, ev); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("UpdateTx with audit = %v", err)
		}
		page, err := db.AuditEvents().List(ctx, store.AuditFilter{})
		if err != nil || len(page.Items) != len(events) {
			t.Fatalf("List = %d events, %v", len(page.Items), err)
		}
		for _, ev := range page.Items {
			if ev.TenantID != "" {
				t.Errorf("%s has tenant %q, want a global event", ev.Action, ev.TenantID)
			}
		}
	})
}
