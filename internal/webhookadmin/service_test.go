package webhookadmin

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/events"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/webhook"
)

// hexSecret is the shape of a signing secret.
var hexSecret = regexp.MustCompile(`^[0-9a-f]{64}$`)

// wantInvalid fails unless err is an *InvalidError on field with code.
func wantInvalid(t *testing.T, what string, err error, field, code string) {
	t.Helper()
	var inv *InvalidError
	if !errors.As(err, &inv) || inv.Field != field || inv.Code != code || !errors.Is(err, ErrInvalid) {
		t.Errorf("%s = %v, want invalid %s %s", what, err, field, code)
	}
}

func TestNew(t *testing.T) {
	t.Parallel()
	if _, err := New(nil, nil, Options{}); !errors.Is(err, errMissingDB) {
		t.Errorf("New without db = %v", err)
	}
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		for _, o := range []Options{{}, {Validator: fakeValidator{}}, {Tester: ev.tester}} {
			if _, err := New(ev.db, ev.vault, o); !errors.Is(err, errMissingDep) {
				t.Errorf("New(%+v) = %v", o, err)
			}
		}
		if _, err := New(ev.db, nil, Options{Validator: fakeValidator{}, Tester: ev.tester}); !errors.Is(err, errMissingDep) {
			t.Errorf("New without vault = %v", err)
		}
		s, err := New(ev.db, ev.vault, Options{Validator: fakeValidator{}, Tester: ev.tester})
		if err != nil || s.logger == nil || s.now == nil {
			t.Fatalf("New with defaults = %+v, %v", s, err)
		}
	})
}

func TestErrors(t *testing.T) {
	t.Parallel()
	if got := (&InvalidError{Field: FieldURL, Code: CodeURLNotAllowed}).Error(); got != "webhookadmin: invalid /url: url-not-allowed" {
		t.Errorf("InvalidError = %q", got)
	}
	rl := &RateLimitError{RetryAfter: time.Minute}
	if !errors.Is(rl, ErrRateLimited) || !strings.Contains(rl.Error(), "1m0s") {
		t.Errorf("RateLimitError = %v", rl)
	}
	if err := storeError("op", errBoom); !errors.Is(err, errBoom) || !strings.Contains(err.Error(), "webhookadmin: op") {
		t.Errorf("storeError = %v", err)
	}
	if err := storeError("op", fmt.Errorf("x: %w", store.ErrConflict)); !errors.Is(err, ErrConflict) {
		t.Errorf("storeError of a conflict = %v", err)
	}
	if hostOf("no-scheme.example.com") != "no-scheme.example.com" || hostOf("https://a.example.com") != "a.example.com" {
		t.Error("hostOf")
	}
	if s := newSecret(); !hexSecret.Match(s) {
		t.Errorf("newSecret = %q", s)
	}
}

func TestAccess(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		ev := newEnv(t, e)
		s := ev.svc
		anon := adminauth.Principal{}
		created, err := s.CreateTenant(ctx, ev.delegA, ev.a.ID, teamsInput(events.VirusDetected), adminIP)
		if err != nil {
			t.Fatal(err)
		}
		whk := created.Webhook.ID
		bad := CreateInput{} // never validated when the access is refused

		// Unauthenticated.
		for name, err := range map[string]error{
			"list":   func() error { _, err := s.ListTenant(ctx, anon, ev.a.ID); return err }(),
			"get":    func() error { _, err := s.GetTenant(ctx, anon, ev.a.ID, whk); return err }(),
			"create": func() error { _, err := s.CreateTenant(ctx, anon, ev.a.ID, bad, adminIP); return err }(),
			"update": func() error {
				_, err := s.UpdateTenant(ctx, anon, ev.a.ID, whk, UpdateInput{Name: new("")}, adminIP)
				return err
			}(),
			"delete":        s.DeleteTenant(ctx, anon, ev.a.ID, whk, adminIP),
			"test":          func() error { _, err := s.TestTenant(ctx, anon, ev.a.ID, whk, adminIP); return err }(),
			"system list":   func() error { _, err := s.ListSystem(ctx, anon); return err }(),
			"system create": func() error { _, err := s.CreateSystem(ctx, anon, bad, adminIP); return err }(),
		} {
			if !errors.Is(err, ErrUnauthenticated) {
				t.Errorf("%s unauthenticated = %v", name, err)
			}
		}
		// Tenant B's admin, a missing tenant, a malformed one, a tenant
		// being deleted: not found, before any validation.
		missing := tenant.ID(id.New(id.Tenant))
		for name, err := range map[string]error{
			"list B":   func() error { _, err := s.ListTenant(ctx, ev.delegB, ev.a.ID); return err }(),
			"get B":    func() error { _, err := s.GetTenant(ctx, ev.delegB, ev.a.ID, whk); return err }(),
			"create B": func() error { _, err := s.CreateTenant(ctx, ev.delegB, ev.a.ID, bad, adminIP); return err }(),
			"update B": func() error {
				_, err := s.UpdateTenant(ctx, ev.delegB, ev.a.ID, whk, UpdateInput{Name: new("")}, adminIP)
				return err
			}(),
			"delete B":       s.DeleteTenant(ctx, ev.delegB, ev.a.ID, whk, adminIP),
			"test B":         func() error { _, err := s.TestTenant(ctx, ev.delegB, ev.a.ID, whk, adminIP); return err }(),
			"get under B":    func() error { _, err := s.GetTenant(ctx, ev.delegB, ev.b.ID, whk); return err }(),
			"delete under B": s.DeleteTenant(ctx, ev.delegB, ev.b.ID, whk, adminIP),
			"missing":        func() error { _, err := s.ListTenant(ctx, ev.super, missing); return err }(),
			"malformed":      func() error { _, err := s.ListTenant(ctx, ev.super, "x"); return err }(),
			"system id":      func() error { _, err := s.GetSystem(ctx, ev.super, whk); return err }(),
		} {
			if !errors.Is(err, ErrNotFound) {
				t.Errorf("%s = %v, want not found", name, err)
			}
		}
		ev.faults.tenantStatus = tenant.StatusDeleting
		if _, err := s.ListTenant(ctx, ev.super, ev.a.ID); !errors.Is(err, ErrNotFound) {
			t.Errorf("tenant being deleted = %v", err)
		}
		ev.faults.reset()
		ev.faults.tenantErr = errBoom
		if _, err := s.ListTenant(ctx, ev.super, ev.a.ID); !errors.Is(err, errBoom) {
			t.Errorf("tenant read failure = %v", err)
		}
		ev.faults.reset()
		// The instance-wide webhooks are reserved to the super admin.
		for name, err := range map[string]error{
			"list":   func() error { _, err := s.ListSystem(ctx, ev.delegA); return err }(),
			"get":    func() error { _, err := s.GetSystem(ctx, ev.delegA, whk); return err }(),
			"create": func() error { _, err := s.CreateSystem(ctx, ev.delegA, bad, adminIP); return err }(),
			"update": func() error {
				_, err := s.UpdateSystem(ctx, ev.delegA, whk, UpdateInput{Name: new("")}, adminIP)
				return err
			}(),
			"delete": s.DeleteSystem(ctx, ev.delegA, whk, adminIP),
			"test":   func() error { _, err := s.TestSystem(ctx, ev.delegA, whk, adminIP); return err }(),
		} {
			if !errors.Is(err, ErrForbidden) {
				t.Errorf("system %s by a delegated admin = %v", name, err)
			}
		}
		// Nothing changed.
		if got, err := s.GetTenant(ctx, ev.delegA, ev.a.ID, whk); err != nil || got.Name != "Security channel" {
			t.Errorf("Get = %+v, %v", got, err)
		}
	})
}

func TestTenantLifecycle(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		ev := newEnv(t, e)
		s := ev.svc

		res, err := s.CreateTenant(ctx, ev.delegA, ev.a.ID, genericInput(), adminIP)
		if err != nil {
			t.Fatal(err)
		}
		w := res.Webhook
		if !hexSecret.MatchString(res.Secret) || w.Kind != store.WebhookGeneric || !w.Enabled || !w.HasSecret() ||
			w.URLHint != "https://siem.example.com" || w.CreatedBy != "admin.a" || !w.CreatedAt.Equal(testStart) {
			t.Fatalf("Create = %+v", res)
		}
		// The URL and the secret are sealed, the secret as its text.
		if u, err := ev.vault.Open(ctx, ev.a.ID, crypto.PurposeSecret, w.URLKeyID); err != nil || string(u) != genericInput().URL {
			t.Errorf("sealed url = %q, %v", u, err)
		}
		if sec, err := ev.vault.Open(ctx, ev.a.ID, crypto.PurposeSecret, w.SecretKeyID); err != nil || string(sec) != res.Secret {
			t.Errorf("sealed secret = %q, %v", sec, err)
		}
		row := ev.lastAudit(t, ev.a.ID)
		if row.Action != string(audit.ActionWebhookCreated) || row.ObjectKind != audit.ObjectWebhook || row.ObjectID != w.ID ||
			row.Actor != "admin.a" || row.details["kind"] != "generic" || row.details["host"] != "siem.example.com" ||
			!reflect.DeepEqual(row.details["events"], []any{"virus.detected", "quota.reached"}) {
			t.Errorf("created audit = %+v", row)
		}
		if strings.Contains(string(row.Details), "key=EXAMPLE") || strings.Contains(string(row.Details), res.Secret) {
			t.Error("the audit holds the url or the secret")
		}

		disabled := teamsInput(events.AbuseReported)
		disabled.Enabled = new(false)
		ev.clock.Advance(time.Minute)
		teams, err := s.CreateTenant(ctx, ev.delegA, ev.a.ID, disabled, adminIP)
		if err != nil || teams.Secret != "" || teams.Webhook.Enabled || teams.Webhook.HasSecret() {
			t.Fatalf("Create teams = %+v, %v", teams, err)
		}
		list, err := s.ListTenant(ctx, ev.delegA, ev.a.ID)
		if err != nil || len(list) != 2 || list[0].ID != w.ID || list[1].ID != teams.Webhook.ID {
			t.Errorf("List = %+v, %v", list, err)
		}
		if list, err := s.ListTenant(ctx, ev.delegB, ev.b.ID); err != nil || len(list) != 0 {
			t.Errorf("List B = %+v, %v", list, err)
		}

		// Update: rename, new url, new events, rotation, disable.
		oldURL, oldSecret := w.URLKeyID, w.SecretKeyID
		ev.clock.Advance(time.Minute)
		upd, err := s.UpdateTenant(ctx, ev.delegA, ev.a.ID, w.ID, UpdateInput{
			Name: new("Renamed"), URL: new("https://other.example.com/x"), Events: []events.Type{events.AbuseReported},
			Enabled: new(false), RotateSecret: true,
		}, adminIP)
		if err != nil || !hexSecret.MatchString(upd.Secret) || upd.Secret == res.Secret || upd.Webhook.Name != "Renamed" ||
			upd.Webhook.URLHint != "https://other.example.com" || upd.Webhook.Enabled {
			t.Fatalf("Update = %+v, %v", upd, err)
		}
		for _, k := range []string{oldURL, oldSecret} {
			if _, err := ev.vault.Open(ctx, ev.a.ID, crypto.PurposeSecret, k); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("old key %s after update: %v, want destroyed", k, err)
			}
		}
		if sec, err := ev.vault.Open(ctx, ev.a.ID, crypto.PurposeSecret, upd.Webhook.SecretKeyID); err != nil || string(sec) != upd.Secret {
			t.Errorf("rotated secret = %q, %v", sec, err)
		}
		row = ev.lastAudit(t, ev.a.ID)
		if row.Action != string(audit.ActionWebhookUpdated) ||
			!reflect.DeepEqual(row.details["fields"], []any{"name", "url", "events", "enabled", "rotateSecret"}) {
			t.Errorf("updated audit = %+v", row)
		}
		// An empty patch changes nothing and records no field.
		same, err := s.UpdateTenant(ctx, ev.delegA, ev.a.ID, w.ID, UpdateInput{}, adminIP)
		if err != nil || same.Secret != "" || same.Webhook.Name != "Renamed" {
			t.Errorf("empty update = %+v, %v", same, err)
		}
		if row := ev.lastAudit(t, ev.a.ID); !reflect.DeepEqual(row.details["fields"], []any{}) {
			t.Errorf("empty update audit = %+v", row.details)
		}
		// Re-enabling closes the circuit breaker.
		if err := ev.db.Webhooks().RecordDelivery(ctx, ev.a.ID, w.ID, store.WebhookDeliveryState{
			Last: store.WebhookDelivery{At: testStart}, ConsecutiveFailures: 5, CircuitOpenUntil: testStart.Add(time.Hour),
			Version: same.Webhook.UpdatedAt,
		}); err != nil {
			t.Fatal(err)
		}
		if cur, _ := ev.db.Webhooks().Get(ctx, ev.a.ID, w.ID); cur.ConsecutiveFailures != 5 {
			t.Fatalf("breaker not opened: %+v", cur)
		}
		on, err := s.UpdateTenant(ctx, ev.delegA, ev.a.ID, w.ID, UpdateInput{Enabled: new(true)}, adminIP)
		if err != nil || on.Webhook.ConsecutiveFailures != 0 || !on.Webhook.CircuitOpenUntil.IsZero() || !on.Webhook.Enabled {
			t.Errorf("re-enable = %+v, %v", on, err)
		}
		// A teams webhook has no secret to rotate.
		if _, err := s.UpdateTenant(ctx, ev.delegA, ev.a.ID, teams.Webhook.ID, UpdateInput{RotateSecret: true}, adminIP); err == nil {
			t.Error("rotation of a teams webhook accepted")
		} else {
			wantInvalid(t, "rotate teams", err, FieldRotateSecret, CodeInvalidFormat)
		}
		if _, err := s.UpdateTenant(ctx, ev.delegA, ev.a.ID, id.New(id.Webhook), UpdateInput{}, adminIP); !errors.Is(err, ErrNotFound) {
			t.Errorf("Update unknown = %v", err)
		}
		if _, err := s.UpdateTenant(ctx, ev.super, ev.b.ID, w.ID, UpdateInput{}, adminIP); !errors.Is(err, ErrNotFound) {
			t.Errorf("Update under B = %v", err)
		}

		// Delete destroys the keys.
		cur, _ := s.GetTenant(ctx, ev.delegA, ev.a.ID, w.ID)
		if err := s.DeleteTenant(ctx, ev.delegA, ev.a.ID, w.ID, adminIP); err != nil {
			t.Fatal(err)
		}
		for _, k := range []string{cur.URLKeyID, cur.SecretKeyID} {
			if _, err := ev.vault.Open(ctx, ev.a.ID, crypto.PurposeSecret, k); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("key %s after delete: %v", k, err)
			}
		}
		if row := ev.lastAudit(t, ev.a.ID); row.Action != string(audit.ActionWebhookDeleted) || row.details["kind"] != "generic" {
			t.Errorf("deleted audit = %+v", row)
		}
		if err := s.DeleteTenant(ctx, ev.delegA, ev.a.ID, w.ID, adminIP); !errors.Is(err, ErrNotFound) {
			t.Errorf("Delete twice = %v", err)
		}
		if _, err := s.GetTenant(ctx, ev.delegA, ev.a.ID, w.ID); !errors.Is(err, ErrNotFound) {
			t.Errorf("Get after delete = %v", err)
		}
	})
}

func TestValidation(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		ev := newEnv(t, e)
		s := ev.svc
		for _, c := range []struct {
			name        string
			mutate      func(*CreateInput)
			field, code string
		}{
			{"empty name", func(in *CreateInput) { in.Name = "" }, FieldName, CodeInvalidFormat},
			{"long name", func(in *CreateInput) { in.Name = strings.Repeat("n", store.MaxWebhookNameLen+1) }, FieldName, CodeInvalidFormat},
			{"control name", func(in *CreateInput) { in.Name = "a\u0007b" }, FieldName, CodeInvalidFormat},
			{"bidi name", func(in *CreateInput) { in.Name = "a\u202eb" }, FieldName, CodeInvalidFormat},
			{"bad utf-8", func(in *CreateInput) { in.Name = "\xff" }, FieldName, CodeInvalidFormat},
			{"kind", func(in *CreateInput) { in.Kind = "email" }, FieldKind, CodeInvalidFormat},
			{"no event", func(in *CreateInput) { in.Events = nil }, FieldEvents, CodeRequired},
			{"system event", func(in *CreateInput) { in.Events = []events.Type{events.VirusDetected, events.DiskAlertRaised} }, "/events/1", CodeInvalidFormat},
			{"test event", func(in *CreateInput) { in.Events = []events.Type{events.WebhookTest} }, "/events/0", CodeInvalidFormat},
			{"duplicate", func(in *CreateInput) { in.Events = []events.Type{events.QuotaReached, events.QuotaReached} }, "/events/1", CodeInvalidFormat},
			{"http url", func(in *CreateInput) { in.URL = "http://hooks.example.com/x" }, FieldURL, CodeInvalidFormat},
			{"denied url", func(in *CreateInput) { in.URL = "https://" + deniedHost + "/x" }, FieldURL, CodeURLNotAllowed},
			{"long hint", func(in *CreateInput) { in.URL = "https://" + longHost + "/x" }, FieldURL, CodeInvalidFormat},
		} {
			in := genericInput()
			c.mutate(&in)
			_, err := s.CreateTenant(ctx, ev.delegA, ev.a.ID, in, adminIP)
			wantInvalid(t, "create with "+c.name, err, c.field, c.code)
		}
		// The instance-wide webhooks refuse the tenant events.
		_, err := s.CreateSystem(ctx, ev.super, teamsInput(events.DiskAlertRaised, events.QuotaWarning), adminIP)
		wantInvalid(t, "system create with a tenant event", err, "/events/1", CodeInvalidFormat)

		w, err := s.CreateTenant(ctx, ev.delegA, ev.a.ID, genericInput(), adminIP)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range []struct {
			name        string
			in          UpdateInput
			field, code string
		}{
			{"name", UpdateInput{Name: new("")}, FieldName, CodeInvalidFormat},
			{"events", UpdateInput{Events: []events.Type{}}, FieldEvents, CodeRequired},
			{"system event", UpdateInput{Events: []events.Type{events.MaintenanceEnabled}}, "/events/0", CodeInvalidFormat},
			{"url", UpdateInput{URL: new("https://" + deniedHost)}, FieldURL, CodeURLNotAllowed},
		} {
			_, err := s.UpdateTenant(ctx, ev.delegA, ev.a.ID, w.Webhook.ID, c.in, adminIP)
			wantInvalid(t, "update with "+c.name, err, c.field, c.code)
		}
	})
}

func TestLimitAndFailures(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		ev := newEnv(t, e)
		s := ev.svc
		for range store.MaxWebhooks {
			if _, err := s.CreateTenant(ctx, ev.delegA, ev.a.ID, teamsInput(events.QuotaWarning), adminIP); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := s.CreateTenant(ctx, ev.delegA, ev.a.ID, teamsInput(events.QuotaWarning), adminIP); !errors.Is(err, ErrLimitReached) {
			t.Errorf("Create above the limit = %v", err)
		}
		ev.faults.listErr = errBoom
		if _, err := s.ListTenant(ctx, ev.delegA, ev.a.ID); !errors.Is(err, errBoom) {
			t.Errorf("List failure = %v", err)
		}
		ev.faults.reset()

		// A failed audit write is logged, the change is kept.
		ev.faults.auditErr = errBoom
		res, err := s.CreateTenant(ctx, ev.delegB, ev.b.ID, genericInput(), adminIP)
		if err != nil {
			t.Fatal(err)
		}
		ev.faults.reset()
		ev.faults.auditErr = errBoom
		if _, err := s.CreateSystem(ctx, ev.super, teamsInput(events.DiskAlertRaised), adminIP); err != nil {
			t.Fatal(err)
		}
		ev.faults.reset()
		if logs := ev.logs.String(); !strings.Contains(logs, "audit write failed") || !strings.Contains(logs, `tenant=""`) {
			t.Errorf("logs = %s", logs)
		}
		// A failed scrub is logged, the deletion is kept.
		ev.vault.scrubErr = errBoom
		if err := s.DeleteTenant(ctx, ev.delegB, ev.b.ID, res.Webhook.ID, adminIP); err != nil {
			t.Fatal(err)
		}
		ev.vault.reset()
		if !strings.Contains(ev.logs.String(), "webhook key scrub failed") {
			t.Errorf("logs = %s", ev.logs.String())
		}
	})
}

func TestCreateFailure(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		ev := newEnv(t, e)
		ev.faults.createErr = errBoom
		if _, err := ev.svc.CreateTenant(ctx, ev.delegA, ev.a.ID, genericInput(), adminIP); !errors.Is(err, errBoom) {
			t.Errorf("Create failure = %v", err)
		}
	})
}

func TestTest(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		ev := newEnv(t, e)
		s := ev.svc
		if _, err := ev.db.Tenants().Update(ctx, func() *tenant.Tenant {
			a := *ev.a
			a.WebhookIncludeAddresses = true
			return &a
		}()); err != nil {
			t.Fatal(err)
		}
		res, err := s.CreateTenant(ctx, ev.delegA, ev.a.ID, genericInput(), adminIP)
		if err != nil {
			t.Fatal(err)
		}
		// The circuit breaker is open: the test is sent anyway and changes
		// no delivery state.
		open := testStart.Add(time.Hour)
		if err := ev.db.Webhooks().RecordDelivery(ctx, ev.a.ID, res.Webhook.ID, store.WebhookDeliveryState{
			Last: store.WebhookDelivery{At: testStart}, ConsecutiveFailures: 5, CircuitOpenUntil: open,
			Version: res.Webhook.UpdatedAt,
		}); err != nil {
			t.Fatal(err)
		}
		ev.tester.result = webhook.Result{Duration: time.Second, Category: webhook.CategoryTimeout}
		got, err := s.TestTenant(ctx, ev.delegA, ev.a.ID, res.Webhook.ID, adminIP)
		if err != nil || got != ev.tester.result {
			t.Fatalf("Test = %+v, %v", got, err)
		}
		tg := ev.tester.last()
		if tg.ID != res.Webhook.ID || tg.TenantID != string(ev.a.ID) || tg.TenantName != ev.a.Name || !tg.IncludeAddresses ||
			tg.Kind != webhook.KindGeneric || tg.URL != genericInput().URL || string(tg.Secret) != res.Secret ||
			tg.ConsecutiveFailures != 5 || !tg.CircuitOpenUntil.Equal(open) {
			t.Errorf("target = %+v", tg)
		}
		if w, _ := s.GetTenant(ctx, ev.delegA, ev.a.ID, res.Webhook.ID); w.ConsecutiveFailures != 5 || w.LastDelivery.Success {
			t.Errorf("the test changed the delivery state: %+v", w)
		}
		row := ev.lastAudit(t, ev.a.ID)
		if row.Action != string(audit.ActionWebhookTested) || row.details["success"] != false || row.details["category"] != "timeout" {
			t.Errorf("tested audit = %+v", row)
		}
		if _, err := s.TestTenant(ctx, ev.delegA, ev.a.ID, id.New(id.Webhook), adminIP); !errors.Is(err, ErrNotFound) {
			t.Errorf("Test unknown = %v", err)
		}
		// Unsealing failures.
		ev.vault.reset()
		ev.vault.openAt = 1
		if _, err := s.TestTenant(ctx, ev.delegA, ev.a.ID, res.Webhook.ID, adminIP); !errors.Is(err, errBoom) {
			t.Errorf("Test with an unreadable url = %v", err)
		}
		ev.vault.reset()
		ev.vault.openAt = 2
		if _, err := s.TestTenant(ctx, ev.delegA, ev.a.ID, res.Webhook.ID, adminIP); !errors.Is(err, errBoom) {
			t.Errorf("Test with an unreadable secret = %v", err)
		}
		ev.vault.reset()
		// TestLimit per hour and per admin and tenant: 4 used above.
		for i := 0; i < TestLimit-4; i++ {
			if _, err := s.TestTenant(ctx, ev.delegA, ev.a.ID, res.Webhook.ID, adminIP); err != nil {
				t.Fatalf("test %d = %v", i, err)
			}
		}
		_, err = s.TestTenant(ctx, ev.delegA, ev.a.ID, res.Webhook.ID, adminIP)
		var rl *RateLimitError
		if !errors.As(err, &rl) || rl.RetryAfter < time.Second {
			t.Errorf("Test above the limit = %v", err)
		}
		// Another administrator is not limited.
		if _, err := s.TestTenant(ctx, ev.super, ev.a.ID, res.Webhook.ID, adminIP); err != nil {
			t.Errorf("Test by the super admin = %v", err)
		}
		ev.clock.Advance(TestWindow)
		if _, err := s.TestTenant(ctx, ev.delegA, ev.a.ID, res.Webhook.ID, adminIP); err != nil {
			t.Errorf("Test after the window = %v", err)
		}
	})
}

func TestSystemLifecycle(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		ev := newEnv(t, e)
		s := ev.svc
		in := genericInput()
		in.Events = []events.Type{events.DiskAlertRaised, events.MaintenanceEnabled}
		res, err := s.CreateSystem(ctx, ev.super, in, adminIP)
		if err != nil || !hexSecret.MatchString(res.Secret) {
			t.Fatalf("CreateSystem = %+v, %v", res, err)
		}
		w := res.Webhook
		if sec, err := ev.vault.OpenSystem(ctx, crypto.PurposeWebhook, w.SecretKeyID); err != nil || string(sec) != res.Secret {
			t.Errorf("sealed secret = %q, %v", sec, err)
		}
		row := ev.lastAudit(t, "")
		if row.TenantID != "" || row.Action != string(audit.ActionWebhookCreated) || row.ObjectID != w.ID {
			t.Errorf("system created audit = %+v", row)
		}
		// Not visible from a tenant.
		if _, err := s.GetTenant(ctx, ev.super, ev.a.ID, w.ID); !errors.Is(err, ErrNotFound) {
			t.Errorf("system webhook under a tenant = %v", err)
		}
		if list, err := s.ListSystem(ctx, ev.super); err != nil || len(list) != 1 || list[0].ID != w.ID {
			t.Errorf("ListSystem = %+v, %v", list, err)
		}
		if got, err := s.GetSystem(ctx, ev.super, w.ID); err != nil || got.ID != w.ID {
			t.Errorf("GetSystem = %+v, %v", got, err)
		}
		upd, err := s.UpdateSystem(ctx, ev.super, w.ID, UpdateInput{URL: new("https://ops.example.com/x"), RotateSecret: true}, adminIP)
		if err != nil || upd.Secret == "" || upd.Webhook.URLHint != "https://ops.example.com" {
			t.Fatalf("UpdateSystem = %+v, %v", upd, err)
		}
		for _, k := range []string{w.URLKeyID, w.SecretKeyID} {
			if _, err := ev.vault.OpenSystem(ctx, crypto.PurposeWebhook, k); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("old system secret %s: %v", k, err)
			}
		}
		slack, err := s.CreateSystem(ctx, ev.super, CreateInput{
			Name: "Ops", Kind: store.WebhookSlack, URL: "https://hooks.example.com/services/EXAMPLE",
			Events: []events.Type{events.AntivirusAlertRaised},
		}, adminIP)
		if err != nil {
			t.Fatal(err)
		}
		_, err = s.UpdateSystem(ctx, ev.super, slack.Webhook.ID, UpdateInput{RotateSecret: true}, adminIP)
		wantInvalid(t, "rotate slack", err, FieldRotateSecret, CodeInvalidFormat)
		got, err := s.TestSystem(ctx, ev.super, slack.Webhook.ID, adminIP)
		if err != nil || !got.Success {
			t.Errorf("TestSystem = %+v, %v", got, err)
		}
		if tg := ev.tester.last(); tg.TenantID != "" || tg.TenantName != "" || tg.IncludeAddresses || tg.Secret != nil {
			t.Errorf("system target = %+v", tg)
		}
		if err := s.DeleteSystem(ctx, ev.super, upd.Webhook.ID, adminIP); err != nil {
			t.Fatal(err)
		}
		for _, k := range []string{upd.Webhook.URLKeyID, upd.Webhook.SecretKeyID} {
			if _, err := ev.vault.OpenSystem(ctx, crypto.PurposeWebhook, k); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("system secret %s after delete: %v", k, err)
			}
		}
		if err := s.DeleteSystem(ctx, ev.super, upd.Webhook.ID, adminIP); !errors.Is(err, ErrNotFound) {
			t.Errorf("DeleteSystem twice = %v", err)
		}
		if _, err := s.UpdateSystem(ctx, ev.super, upd.Webhook.ID, UpdateInput{}, adminIP); !errors.Is(err, ErrNotFound) {
			t.Errorf("UpdateSystem deleted = %v", err)
		}
		// A tenant webhook is unknown under the system path.
		tw, err := s.CreateTenant(ctx, ev.super, ev.a.ID, teamsInput(events.VirusDetected), adminIP)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.DeleteSystem(ctx, ev.super, tw.Webhook.ID, adminIP); !errors.Is(err, ErrNotFound) {
			t.Errorf("DeleteSystem of a tenant webhook = %v", err)
		}
		// The system test limit is per administrator.
		for i := 1; i < TestLimit; i++ {
			if _, err := s.TestSystem(ctx, ev.super, slack.Webhook.ID, adminIP); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := s.TestSystem(ctx, ev.super, slack.Webhook.ID, adminIP); !errors.Is(err, ErrRateLimited) {
			t.Errorf("TestSystem above the limit = %v", err)
		}
	})
}

func TestSubscribers(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		ev := newEnv(t, e)
		s := ev.svc
		ga, err := s.CreateTenant(ctx, ev.delegA, ev.a.ID, genericInput(), adminIP)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.CreateTenant(ctx, ev.delegB, ev.b.ID, genericInput(), adminIP); err != nil {
			t.Fatal(err)
		}
		sys, err := s.CreateSystem(ctx, ev.super, teamsInput(events.DiskAlertRaised), adminIP)
		if err != nil {
			t.Fatal(err)
		}
		// An event of A reaches the webhook of A only.
		targets, err := s.Subscribers(ctx, string(ev.a.ID), events.VirusDetected)
		if err != nil || len(targets) != 1 || targets[0] != (webhook.Ref{ID: ga.Webhook.ID, TenantID: string(ev.a.ID)}) {
			t.Errorf("Subscribers A = %+v, %v", targets, err)
		}
		// No system webhook receives a tenant event, no tenant webhook a
		// system event.
		if targets, err := s.Subscribers(ctx, "", events.VirusDetected); err != nil || len(targets) != 0 {
			t.Errorf("system Subscribers of a tenant event = %+v, %v", targets, err)
		}
		if targets, err := s.Subscribers(ctx, string(ev.a.ID), events.DiskAlertRaised); err != nil || len(targets) != 0 {
			t.Errorf("tenant Subscribers of a system event = %+v, %v", targets, err)
		}
		targets, err = s.Subscribers(ctx, "", events.DiskAlertRaised)
		if err != nil || len(targets) != 1 || targets[0] != (webhook.Ref{ID: sys.Webhook.ID}) {
			t.Errorf("system Subscribers = %+v, %v", targets, err)
		}
		// Missing or malformed tenant, tenant being deleted, failures.
		if targets, err := s.Subscribers(ctx, id.New(id.Tenant), events.VirusDetected); err != nil || targets != nil {
			t.Errorf("Subscribers of a missing tenant = %+v, %v", targets, err)
		}
		if targets, err := s.Subscribers(ctx, "not-a-tenant", events.VirusDetected); err != nil || targets != nil {
			t.Errorf("Subscribers of a malformed tenant = %+v, %v", targets, err)
		}
		ev.faults.tenantStatus = tenant.StatusDeleting
		if targets, err := s.Subscribers(ctx, string(ev.a.ID), events.VirusDetected); err != nil || targets != nil {
			t.Errorf("Subscribers of a tenant being deleted = %+v, %v", targets, err)
		}
		ev.faults.reset()
		ev.faults.tenantErr = errBoom
		if _, err := s.Subscribers(ctx, string(ev.a.ID), events.VirusDetected); !errors.Is(err, errBoom) {
			t.Errorf("Subscribers with a tenant failure = %v", err)
		}
		ev.faults.reset()
		ev.faults.subscribedErr = errBoom
		if _, err := s.Subscribers(ctx, "", events.DiskAlertRaised); !errors.Is(err, errBoom) {
			t.Errorf("Subscribers with a list failure = %v", err)
		}
		ev.faults.reset()
		// The routing unseals nothing: an unreadable key does not hide the
		// webhook, whose attempt reads it again, and the breaker state is
		// carried.
		ev.vault.reset()
		ev.vault.openAt = 1
		if targets, err := s.Subscribers(ctx, string(ev.a.ID), events.VirusDetected); err != nil || len(targets) != 1 {
			t.Errorf("Subscribers with an unreadable key = %+v, %v", targets, err)
		}
		if n := ev.vault.openCalls; n != 0 {
			t.Errorf("Subscribers opened %d keys", n)
		}
		ev.vault.reset()
		open := webhook.Delivery{
			Version: sys.Webhook.UpdatedAt, At: testStart, Result: webhook.Result{Category: webhook.CategoryTimeout},
			ConsecutiveFailures: 5, CircuitOpenUntil: testStart.Add(webhook.BreakerCooldown),
		}
		if err := s.RecordDelivery(ctx, "", sys.Webhook.ID, open); err != nil {
			t.Fatal(err)
		}
		if targets, err := s.Subscribers(ctx, "", events.DiskAlertRaised); err != nil || len(targets) != 1 ||
			!targets[0].CircuitOpenUntil.Equal(open.CircuitOpenUntil) {
			t.Errorf("Subscribers with an open circuit = %+v, %v", targets, err)
		}

		// Deliveries are recorded per scope.
		d := webhook.Delivery{
			Version: ga.Webhook.UpdatedAt,
			At:      testStart, Result: webhook.Result{HTTPStatus: 503, Duration: time.Second, Category: webhook.CategoryHTTPStatus},
			ConsecutiveFailures: 5, CircuitOpenUntil: testStart.Add(webhook.BreakerCooldown),
		}
		if err := s.RecordDelivery(ctx, string(ev.a.ID), ga.Webhook.ID, d); err != nil {
			t.Fatal(err)
		}
		w, _ := ev.db.Webhooks().Get(ctx, ev.a.ID, ga.Webhook.ID)
		if w.ConsecutiveFailures != 5 || w.LastDelivery.HTTPStatus != 503 || w.LastDelivery.ErrorCategory != "http_status" ||
			!w.CircuitOpenUntil.Equal(d.CircuitOpenUntil) {
			t.Errorf("recorded = %+v", w)
		}
		// The webhook of A under tenant B, or under the system, is untouched.
		ok := webhook.Delivery{Version: ga.Webhook.UpdatedAt, At: testStart, Result: webhook.Result{Success: true, HTTPStatus: 200}}
		if err := s.RecordDelivery(ctx, string(ev.b.ID), ga.Webhook.ID, ok); err != nil {
			t.Errorf("RecordDelivery under B = %v", err)
		}
		if err := s.RecordDelivery(ctx, "", ga.Webhook.ID, ok); err != nil {
			t.Errorf("RecordDelivery under the system = %v", err)
		}
		if w, _ := ev.db.Webhooks().Get(ctx, ev.a.ID, ga.Webhook.ID); w.LastDelivery.Success {
			t.Error("a delivery recorded in another scope changed the webhook of A")
		}
		ok.Version = sys.Webhook.UpdatedAt
		if err := s.RecordDelivery(ctx, "", sys.Webhook.ID, ok); err != nil {
			t.Fatal(err)
		}
		if w, _ := ev.db.SystemWebhooks().Get(ctx, sys.Webhook.ID); !w.LastDelivery.Success {
			t.Errorf("system recorded = %+v", w)
		}
		if err := s.RecordDelivery(ctx, "", sys.Webhook.ID, webhook.Delivery{}); err == nil {
			t.Error("RecordDelivery of an invalid delivery accepted")
		}
	})
}

func TestTarget(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		ev := newEnv(t, e)
		s := ev.svc
		ga, err := s.CreateTenant(ctx, ev.delegA, ev.a.ID, genericInput(), adminIP)
		if err != nil {
			t.Fatal(err)
		}
		sys, err := s.CreateSystem(ctx, ev.super, teamsInput(events.DiskAlertRaised), adminIP)
		if err != nil {
			t.Fatal(err)
		}
		// The current settings of the webhook, in its owner's scope.
		tg, ok, err := s.Target(ctx, string(ev.a.ID), ga.Webhook.ID)
		if err != nil || !ok || tg.ID != ga.Webhook.ID || tg.TenantID != string(ev.a.ID) || tg.URL != genericInput().URL ||
			string(tg.Secret) != ga.Secret || !tg.Version.Equal(ga.Webhook.UpdatedAt) || !tg.Subscribed(events.VirusDetected) {
			t.Errorf("Target A = %+v, %v, %v", tg, ok, err)
		}
		if tg, ok, err := s.Target(ctx, "", sys.Webhook.ID); err != nil || !ok || tg.TenantID != "" || tg.Secret != nil {
			t.Errorf("Target system = %+v, %v, %v", tg, ok, err)
		}
		// Re-addressed and re-keyed: the new URL, secret and version.
		upd, err := s.UpdateTenant(ctx, ev.delegA, ev.a.ID, ga.Webhook.ID, UpdateInput{
			URL: new("https://moved.example.com/hook"), RotateSecret: true,
		}, adminIP)
		if err != nil {
			t.Fatal(err)
		}
		if tg, ok, err := s.Target(ctx, string(ev.a.ID), ga.Webhook.ID); err != nil || !ok || tg.URL != "https://moved.example.com/hook" ||
			string(tg.Secret) != upd.Secret || !tg.Version.After(ga.Webhook.UpdatedAt) {
			t.Errorf("Target after update = %+v, %v, %v", tg, ok, err)
		}
		// Gone for another owner, a malformed or unknown webhook, a missing,
		// malformed or deleting tenant.
		for name, c := range map[string][2]string{
			"under B":          {string(ev.b.ID), ga.Webhook.ID},
			"under the system": {"", ga.Webhook.ID},
			"system under A":   {string(ev.a.ID), sys.Webhook.ID},
			"malformed id":     {string(ev.a.ID), "whk_bad"},
			"unknown":          {string(ev.a.ID), id.New(id.Webhook)},
			"missing tenant":   {id.New(id.Tenant), ga.Webhook.ID},
			"malformed tenant": {"not-a-tenant", ga.Webhook.ID},
		} {
			if tg, ok, err := s.Target(ctx, c[0], c[1]); err != nil || ok || tg.URL != "" {
				t.Errorf("Target %s = %+v, %v, %v", name, tg, ok, err)
			}
		}
		ev.faults.tenantStatus = tenant.StatusDeleting
		if _, ok, err := s.Target(ctx, string(ev.a.ID), ga.Webhook.ID); err != nil || ok {
			t.Errorf("Target of a deleting tenant = %v, %v", ok, err)
		}
		ev.faults.reset()
		// Disabled: no target.
		if _, err := s.UpdateTenant(ctx, ev.delegA, ev.a.ID, ga.Webhook.ID, UpdateInput{Enabled: new(false)}, adminIP); err != nil {
			t.Fatal(err)
		}
		if _, ok, err := s.Target(ctx, string(ev.a.ID), ga.Webhook.ID); err != nil || ok {
			t.Errorf("Target of a disabled webhook = %v, %v", ok, err)
		}
		// Failures: tenant, webhook, unsealing (never quoting the URL).
		ev.faults.tenantErr = errBoom
		if _, _, err := s.Target(ctx, string(ev.a.ID), ga.Webhook.ID); !errors.Is(err, errBoom) {
			t.Errorf("Target with a tenant failure = %v", err)
		}
		ev.faults.reset()
		ev.faults.getErr = errBoom
		if _, _, err := s.Target(ctx, "", sys.Webhook.ID); !errors.Is(err, errBoom) {
			t.Errorf("Target with a read failure = %v", err)
		}
		ev.faults.reset()
		ev.vault.reset()
		ev.vault.openAt = 1
		if _, _, err := s.Target(ctx, "", sys.Webhook.ID); err == nil || strings.Contains(err.Error(), "example.com") {
			t.Errorf("Target with an unreadable key = %v", err)
		}
		ev.vault.reset()
		// A key destroyed by a concurrent change between the two reads is
		// read again once with the webhook; still missing, the webhook is
		// being changed or deleted: no target, no error.
		ev.vault.openMissing = 1
		if tg, ok, err := s.Target(ctx, "", sys.Webhook.ID); err != nil || !ok || tg.ID != sys.Webhook.ID || tg.URL == "" {
			t.Errorf("Target after a concurrent change = %+v, %v, %v", tg, ok, err)
		}
		ev.vault.openMissing = 2
		if tg, ok, err := s.Target(ctx, "", sys.Webhook.ID); err != nil || ok || tg.URL != "" {
			t.Errorf("Target with a key still missing = %+v, %v, %v", tg, ok, err)
		}
		ev.vault.reset()
		// Deleted: no target.
		if err := s.DeleteSystem(ctx, ev.super, sys.Webhook.ID, adminIP); err != nil {
			t.Fatal(err)
		}
		if _, ok, err := s.Target(ctx, "", sys.Webhook.ID); err != nil || ok {
			t.Errorf("Target of a deleted webhook = %v, %v", ok, err)
		}
	})
}

// TestConcurrentUpdates rotates the secret of a webhook from several
// administrators at once: each rotation applies, or is refused with
// ErrConflict when another one committed after it read the webhook
// (PostgreSQL); none fails otherwise, and the webhook stays deliverable
// with the secret of the last rotation applied.
func TestConcurrentUpdates(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		ev := newEnv(t, e)
		s := ev.svc
		ga, err := s.CreateTenant(ctx, ev.delegA, ev.a.ID, genericInput(), adminIP)
		if err != nil {
			t.Fatal(err)
		}
		const n = 8
		var (
			wg      sync.WaitGroup
			mu      sync.Mutex
			applied []Result
		)
		for range n {
			wg.Go(func() {
				res, err := s.UpdateTenant(ctx, ev.delegA, ev.a.ID, ga.Webhook.ID, UpdateInput{RotateSecret: true}, adminIP)
				switch {
				case err == nil:
					mu.Lock()
					applied = append(applied, res)
					mu.Unlock()
				case !errors.Is(err, ErrConflict):
					t.Errorf("concurrent rotation = %v", err)
				}
			})
		}
		wg.Wait()
		if len(applied) == 0 {
			t.Fatal("no rotation applied")
		}
		last := applied[0]
		for _, r := range applied {
			if r.Webhook.UpdatedAt.After(last.Webhook.UpdatedAt) {
				last = r
			}
		}
		if tg, ok, err := s.Target(ctx, string(ev.a.ID), ga.Webhook.ID); err != nil || !ok || string(tg.Secret) != last.Secret {
			t.Errorf("Target after the rotations = %v, %v", ok, err)
		}
	})
}

func TestURLChangeLimit(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		ev := newEnv(t, e)
		s := ev.svc
		w, err := s.CreateTenant(ctx, ev.delegA, ev.a.ID, teamsInput(events.VirusDetected), adminIP)
		if err != nil {
			t.Fatal(err)
		}
		// The creation counted once; the other changes of a webhook do not
		// count.
		for range 5 {
			if _, err := s.UpdateTenant(ctx, ev.delegA, ev.a.ID, w.Webhook.ID, UpdateInput{Name: new("Same")}, adminIP); err != nil {
				t.Fatal(err)
			}
		}
		// Invalid URLs count too: the limit bounds the resolutions.
		for i := 1; i < URLChangeLimit; i++ {
			if _, err := s.UpdateTenant(ctx, ev.delegA, ev.a.ID, w.Webhook.ID, UpdateInput{URL: new("https://" + deniedHost + "/")}, adminIP); !errors.Is(err, ErrInvalid) {
				t.Fatalf("change %d = %v", i, err)
			}
		}
		var limited *RateLimitError
		_, err = s.UpdateTenant(ctx, ev.delegA, ev.a.ID, w.Webhook.ID, UpdateInput{URL: new("https://hooks.example.com/")}, adminIP)
		if !errors.As(err, &limited) || !errors.Is(err, ErrRateLimited) || limited.RetryAfter < time.Second {
			t.Fatalf("over the limit = %v", err)
		}
		if _, err := s.CreateTenant(ctx, ev.delegA, ev.a.ID, teamsInput(events.VirusDetected), adminIP); !errors.Is(err, ErrRateLimited) {
			t.Errorf("creation over the limit = %v", err)
		}
		// Per administrator and tenant: the super admin on A, and the system
		// webhooks, are counted apart.
		if _, err := s.CreateTenant(ctx, ev.super, ev.a.ID, teamsInput(events.VirusDetected), adminIP); err != nil {
			t.Errorf("super admin on A = %v", err)
		}
		for range URLChangeLimit {
			if _, err := s.CreateSystem(ctx, ev.super, teamsInput(events.DiskAlertRaised), adminIP); err != nil &&
				!errors.Is(err, ErrLimitReached) {
				t.Fatalf("system creation = %v", err)
			}
		}
		if _, err := s.UpdateSystem(ctx, ev.super, id.New(id.Webhook), UpdateInput{URL: new("https://hooks.example.com/")}, adminIP); !errors.Is(err, ErrRateLimited) {
			t.Errorf("system change over the limit = %v", err)
		}
		// The window passes.
		ev.clock.Advance(URLChangeWindow)
		if _, err := s.UpdateTenant(ctx, ev.delegA, ev.a.ID, w.Webhook.ID, UpdateInput{URL: new("https://hooks.example.com/")}, adminIP); err != nil {
			t.Errorf("after the window = %v", err)
		}
	})
}

func TestOwnerFailures(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		ev := newEnv(t, e)
		s := ev.svc
		v := ev.vault
		tw, err := s.CreateTenant(ctx, ev.delegA, ev.a.ID, genericInput(), adminIP)
		if err != nil {
			t.Fatal(err)
		}
		sysIn := genericInput()
		sysIn.Events = []events.Type{events.DiskAlertRaised}
		sw, err := s.CreateSystem(ctx, ev.super, sysIn, adminIP)
		if err != nil {
			t.Fatal(err)
		}
		rotate := UpdateInput{URL: new("https://new.example.com"), RotateSecret: true}
		v.reset()
		for _, c := range []struct {
			name string
			arm  func()
			run  func() error
		}{
			{"tenant seal url", func() { v.sealAt = 1 }, func() error {
				_, err := s.CreateTenant(ctx, ev.delegA, ev.a.ID, genericInput(), adminIP)
				return err
			}},
			{"tenant seal secret", func() { v.sealAt = 2 }, func() error {
				_, err := s.CreateTenant(ctx, ev.delegA, ev.a.ID, genericInput(), adminIP)
				return err
			}},
			{"tenant update seal url", func() { v.sealAt = 1 }, func() error {
				_, err := s.UpdateTenant(ctx, ev.delegA, ev.a.ID, tw.Webhook.ID, rotate, adminIP)
				return err
			}},
			{"tenant update seal secret", func() { v.sealAt = 2 }, func() error {
				_, err := s.UpdateTenant(ctx, ev.delegA, ev.a.ID, tw.Webhook.ID, rotate, adminIP)
				return err
			}},
			{"tenant update destroy", func() { v.destroyAt = 1 }, func() error {
				_, err := s.UpdateTenant(ctx, ev.delegA, ev.a.ID, tw.Webhook.ID, rotate, adminIP)
				return err
			}},
			{"tenant delete destroy", func() { v.destroyAt = 2 }, func() error {
				return s.DeleteTenant(ctx, ev.delegA, ev.a.ID, tw.Webhook.ID, adminIP)
			}},
			{"system seal url", func() { v.wrapAt = 1 }, func() error {
				_, err := s.CreateSystem(ctx, ev.super, sysIn, adminIP)
				return err
			}},
			{"system seal secret", func() { v.wrapAt = 2 }, func() error {
				_, err := s.CreateSystem(ctx, ev.super, sysIn, adminIP)
				return err
			}},
			{"system update seal url", func() { v.wrapAt = 1 }, func() error {
				_, err := s.UpdateSystem(ctx, ev.super, sw.Webhook.ID, rotate, adminIP)
				return err
			}},
			{"system update seal secret", func() { v.wrapAt = 2 }, func() error {
				_, err := s.UpdateSystem(ctx, ev.super, sw.Webhook.ID, rotate, adminIP)
				return err
			}},
		} {
			c.arm()
			if err := c.run(); !errors.Is(err, errBoom) {
				t.Errorf("%s: %v, want the injected fault", c.name, err)
			}
			v.reset()
		}
		// Nothing changed: the keys still open.
		for _, k := range []string{tw.Webhook.URLKeyID, tw.Webhook.SecretKeyID} {
			if _, err := v.Open(ctx, ev.a.ID, crypto.PurposeSecret, k); err != nil {
				t.Errorf("key %s after the failures: %v", k, err)
			}
		}
		if list, _ := s.ListTenant(ctx, ev.delegA, ev.a.ID); len(list) != 1 {
			t.Errorf("tenant webhooks after the failures = %d", len(list))
		}

		// The transactions refuse a malformed tenant or a missing reason.
		bad := &tenantOwner{db: ev.db, vault: v, tid: "x"}
		if _, err := bad.create(ctx, store.Webhook{}, nil, nil); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("tenant owner with a malformed tenant = %v", err)
		}
		noReason := &systemOwner{db: ev.db, vault: v}
		if _, err := noReason.create(ctx, store.Webhook{}, nil, nil); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("system owner without reason = %v", err)
		}
	})
}
