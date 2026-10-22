package tenantadmin

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

func TestNewRequiresDependencies(t *testing.T) {
	if _, err := New(nil, Options{}); !errors.Is(err, errMissingDependency) {
		t.Fatalf("New: %v", err)
	}
}

func TestNewDefaults(t *testing.T) {
	ev := newEnv(t, storetest.SQLite(t), func(o *Options) {
		o.Resolver, o.Logger, o.Now = nil, nil, nil
		o.AdminHosts = []string{"Admin.Example.COM.", "bad host"}
	})
	s := ev.svc
	if s.resolver != defaultResolver || s.logger == nil || s.now == nil || s.dnsTimeout != DefaultDNSTimeout {
		t.Fatalf("defaults not applied: %+v", s)
	}
	if !slices.Contains(s.adminHosts, adminHost) || !slices.Contains(s.adminHosts, "bad host") {
		t.Fatalf("admin hosts: %v", s.adminHosts)
	}
}

func TestListTenants(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		page, err := ev.svc.ListTenants(ctx, ev.super, "", 0)
		mustNoErr(t, "super list", err)
		if len(page.Items) != 2 {
			t.Fatalf("super sees %d tenants", len(page.Items))
		}
		page, err = ev.svc.ListTenants(ctx, ev.super, "", 1)
		mustNoErr(t, "super page", err)
		if len(page.Items) != 1 || page.NextCursor == "" {
			t.Fatalf("first page: %+v", page)
		}
		_, err = ev.svc.ListTenants(ctx, ev.super, "garbage", 0)
		wantInvalid(t, "bad cursor", err, "cursor")

		// A delegated admin sees its tenants only, active ones only.
		ghost := principal(store.RoleDelegatedAdmin, "carol", ev.a.ID, "ten_01JAB00000000000000000000Z")
		page, err = ev.svc.ListTenants(ctx, ghost, "", 0)
		mustNoErr(t, "delegated list", err)
		if len(page.Items) != 1 || page.Items[0].ID != ev.a.ID {
			t.Fatalf("delegated sees %+v", page.Items)
		}
		mustNoErr(t, "deleting", ev.db.Tenants().SetStatus(ctx, ev.a.ID, tenant.StatusDeleting))
		page, err = ev.svc.ListTenants(ctx, ev.adminA, "", 0)
		mustNoErr(t, "delegated list", err)
		if len(page.Items) != 0 {
			t.Fatalf("deleting tenant listed: %+v", page.Items)
		}
		page, err = ev.svc.ListTenants(ctx, ev.super, "", 0)
		mustNoErr(t, "super list", err)
		if len(page.Items) != 2 {
			t.Fatalf("super should see the deleting tenant: %+v", page.Items)
		}

		disabled := ev.adminB
		disabled.Admin.Disabled = true
		page, err = ev.svc.ListTenants(ctx, disabled, "", 0)
		mustNoErr(t, "disabled list", err)
		if len(page.Items) != 0 {
			t.Fatalf("disabled admin sees %+v", page.Items)
		}
		_, err = ev.svc.ListTenants(ctx, adminauth.Principal{}, "", 0)
		wantErr(t, "unauthenticated", err, ErrUnauthenticated)
	})
}

func TestListTenantsFaults(t *testing.T) {
	ctx := context.Background()
	ev := newEnv(t, storetest.SQLite(t))
	ev.faults("listTenants")
	_, err := ev.svc.ListTenants(ctx, ev.super, "", 0)
	wantErr(t, "list", err, errBoom)
	ev.faults("getTenant")
	_, err = ev.svc.ListTenants(ctx, ev.adminA, "", 0)
	wantErr(t, "delegated get", err, errBoom)
	ev.faults("usedBytes")
	_, err = ev.svc.ListTenants(ctx, ev.adminA, "", 0)
	wantErr(t, "usage", err, errBoom)
}

func TestGetTenant(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		v, err := ev.svc.GetTenant(ctx, ev.adminA, ev.a.ID)
		mustNoErr(t, "get", err)
		if v.ID != ev.a.ID || v.FQDN != hostA || v.StorageUsedBytes != 0 || v.MaxTransferCeiling != 10<<30 {
			t.Fatalf("view: %+v", v)
		}
		_, err = ev.svc.GetTenant(ctx, ev.adminB, ev.a.ID)
		wantErr(t, "other tenant", err, ErrNotFound)
		_, err = ev.svc.GetTenant(ctx, ev.super, "ten_01JAB00000000000000000000Z")
		wantErr(t, "missing", err, ErrNotFound)
		mustNoErr(t, "deleting", ev.db.Tenants().SetStatus(ctx, ev.a.ID, tenant.StatusDeleting))
		_, err = ev.svc.GetTenant(ctx, ev.adminA, ev.a.ID)
		wantErr(t, "deleting for delegated", err, ErrNotFound)
		v, err = ev.svc.GetTenant(ctx, ev.super, ev.a.ID)
		mustNoErr(t, "deleting for super", err)
		if v.Status != tenant.StatusDeleting {
			t.Fatalf("status %q", v.Status)
		}
	})
}

func TestGetTenantFault(t *testing.T) {
	ev := newEnv(t, storetest.SQLite(t))
	ev.faults("getTenant")
	_, err := ev.svc.GetTenant(context.Background(), ev.super, ev.a.ID)
	wantErr(t, "get", err, errBoom)
}

func TestCreateTenant(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		in := TenantCreate{
			Name: " Entity C ", FQDN: "Transfer.Entity-C.Example.com", DefaultLanguage: "fr", StorageQuotaBytes: 1 << 40,
		}
		v, err := ev.svc.CreateTenant(ctx, ev.super, in, clientIP)
		mustNoErr(t, "create", err)
		if v.Name != "Entity C" || v.FQDN != "transfer.entity-c.example.com" ||
			v.MaxTransferBytes != tenant.MaxTransferLimit || v.MaxTransferCeiling != tenant.MaxTransferLimit {
			t.Fatalf("created: %+v", v)
		}
		if !ev.cache.sawHost(v.FQDN) {
			t.Error("the new FQDN was not invalidated")
		}
		evs := ev.auditEvents(t, v.ID, ActionTenantCreated)
		if len(evs) != 1 || evs[0].Actor != "root" || evs[0].IP != clientIP {
			t.Fatalf("audit: %+v", evs)
		}

		in.FQDN, in.MaxTransferBytes = "transfer.entity-d.example.com", 5<<30
		v, err = ev.svc.CreateTenant(ctx, ev.super, in, clientIP)
		mustNoErr(t, "create with limit", err)
		if v.MaxTransferBytes != 5<<30 || v.MaxTransferCeiling != 5<<30 {
			t.Fatalf("limits: %+v", v)
		}
		// The ceiling is set at creation, atomically with the limit.
		in.FQDN, in.MaxTransferCeiling = "transfer.entity-e.example.com", ptr(int64(10<<30))
		v, err = ev.svc.CreateTenant(ctx, ev.super, in, clientIP)
		mustNoErr(t, "create with ceiling", err)
		if v.MaxTransferBytes != 5<<30 || v.MaxTransferCeiling != 10<<30 {
			t.Fatalf("limits with ceiling: %+v", v)
		}
		// A ceiling alone gives the limit.
		in.FQDN, in.MaxTransferBytes = "transfer.entity-f.example.com", 0
		v, err = ev.svc.CreateTenant(ctx, ev.super, in, clientIP)
		mustNoErr(t, "create with ceiling only", err)
		if v.MaxTransferBytes != 10<<30 || v.MaxTransferCeiling != 10<<30 {
			t.Fatalf("limits with ceiling only: %+v", v)
		}
		in.MaxTransferCeiling = nil

		_, err = ev.svc.CreateTenant(ctx, ev.super, TenantCreate{
			Name: "Dup", FQDN: hostA, DefaultLanguage: "en", StorageQuotaBytes: 1,
		}, clientIP)
		wantErr(t, "duplicate fqdn", err, ErrAlreadyExists)

		_, err = ev.svc.CreateTenant(ctx, ev.adminA, in, clientIP)
		wantErr(t, "delegated", err, ErrForbidden)
		_, err = ev.svc.CreateTenant(ctx, adminauth.Principal{}, in, clientIP)
		wantErr(t, "unauthenticated", err, ErrUnauthenticated)
	})
}

func TestCreateTenantValidation(t *testing.T) {
	ctx := context.Background()
	ev := newEnv(t, storetest.SQLite(t))
	good := TenantCreate{Name: "X", FQDN: "x.example.com", DefaultLanguage: "en", StorageQuotaBytes: 1}
	cases := []struct {
		name  string
		edit  func(*TenantCreate)
		field string
	}{
		{"empty name", func(c *TenantCreate) { c.Name = "  " }, FieldName},
		{"long name", func(c *TenantCreate) { c.Name = string(make([]byte, 101)) }, FieldName},
		{"control name", func(c *TenantCreate) { c.Name = "a" + string(rune(0x202e)) + "b" }, FieldName},
		{"admin host", func(c *TenantCreate) { c.FQDN = "ADMIN.example.com" }, FieldFQDN},
		{"port", func(c *TenantCreate) { c.FQDN = "x.example.com:443" }, FieldFQDN},
		{"ip", func(c *TenantCreate) { c.FQDN = "192.0.2.1" }, FieldFQDN},
		{"language", func(c *TenantCreate) { c.DefaultLanguage = "de" }, FieldDefaultLanguage},
		{"quota", func(c *TenantCreate) { c.StorageQuotaBytes = 0 }, FieldStorageQuotaBytes},
		{"limit", func(c *TenantCreate) { c.MaxTransferBytes = tenant.MaxTransferLimit + 1 }, FieldMaxTransferBytes},
		{"negative limit", func(c *TenantCreate) { c.MaxTransferBytes = -1 }, FieldMaxTransferBytes},
		{"zero ceiling", func(c *TenantCreate) { c.MaxTransferCeiling = ptr(int64(0)) }, FieldMaxTransferCeiling},
		{"ceiling", func(c *TenantCreate) { c.MaxTransferCeiling = ptr(tenant.MaxTransferLimit + 1) }, FieldMaxTransferCeiling},
		{"limit above ceiling", func(c *TenantCreate) {
			c.MaxTransferBytes, c.MaxTransferCeiling = 10<<30, ptr(int64(5<<30))
		}, FieldMaxTransferBytes},
		{"limit over the maximum with a ceiling", func(c *TenantCreate) {
			c.MaxTransferBytes, c.MaxTransferCeiling = tenant.MaxTransferLimit+1, ptr(int64(5<<30))
		}, FieldMaxTransferBytes},
	}
	for _, tc := range cases {
		in := good
		tc.edit(&in)
		_, err := ev.svc.CreateTenant(ctx, ev.super, in, clientIP)
		wantInvalid(t, tc.name, err, tc.field)
	}
	ev.faults("createTenant")
	_, err := ev.svc.CreateTenant(ctx, ev.super, good, clientIP)
	wantErr(t, "store failure", err, errBoom)
}

func TestUpdateTenantSuperAdmin(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		v, err := ev.svc.UpdateTenant(ctx, ev.super, ev.a.ID, TenantUpdate{
			Name: ptr("Entity A2"), FQDN: ptr("new.entity-a.example.com"), DefaultLanguage: ptr("fr"),
			StorageQuotaBytes: ptr(int64(1 << 41)), MaxTransferBytes: ptr(int64(15 << 30)),
		}, clientIP)
		mustNoErr(t, "update", err)
		if v.Name != "Entity A2" || v.FQDN != "new.entity-a.example.com" || v.DefaultLanguage != "fr" ||
			v.StorageQuotaBytes != 1<<41 || v.MaxTransferBytes != 15<<30 || v.MaxTransferCeiling != 15<<30 {
			t.Fatalf("updated: %+v", v)
		}
		if !ev.cache.sawHost(hostA) || !ev.cache.sawHost("new.entity-a.example.com") {
			t.Fatalf("cache not invalidated: %+v", ev.cache.hosts)
		}
		evs := ev.auditEvents(t, ev.a.ID, ActionTenantUpdated)
		if len(evs) != 1 {
			t.Fatalf("audit: %+v", evs)
		}
		var details struct{ Fields []string }
		mustNoErr(t, "details", json.Unmarshal(evs[0].Details, &details))
		want := []string{"name", "fqdn", "defaultLanguage", "storageQuotaBytes", "maxTransferBytes", "maxTransferCeiling"}
		if !slices.Equal(details.Fields, want) {
			t.Fatalf("fields %v", details.Fields)
		}

		// Lowering the ceiling lowers the limit.
		v, err = ev.svc.UpdateTenant(ctx, ev.super, ev.a.ID, TenantUpdate{MaxTransferCeiling: ptr(int64(2 << 30))}, clientIP)
		mustNoErr(t, "ceiling", err)
		if v.MaxTransferCeiling != 2<<30 || v.MaxTransferBytes != 2<<30 {
			t.Fatalf("ceiling: %+v", v)
		}
		_, err = ev.svc.UpdateTenant(ctx, ev.super, ev.a.ID, TenantUpdate{
			MaxTransferCeiling: ptr(int64(3 << 30)), MaxTransferBytes: ptr(int64(4 << 30)),
		}, clientIP)
		wantInvalid(t, "limit above explicit ceiling", err, FieldMaxTransferBytes)

		// No change: no audit event.
		_, err = ev.svc.UpdateTenant(ctx, ev.super, ev.a.ID, TenantUpdate{Name: ptr("Entity A2")}, clientIP)
		mustNoErr(t, "no-op", err)
		if n := len(ev.auditEvents(t, ev.a.ID, ActionTenantUpdated)); n != 2 {
			t.Fatalf("%d update events", n)
		}

		_, err = ev.svc.UpdateTenant(ctx, ev.super, ev.a.ID, TenantUpdate{FQDN: ptr(hostB)}, clientIP)
		wantErr(t, "duplicate fqdn", err, ErrAlreadyExists)
		_, err = ev.svc.UpdateTenant(ctx, ev.super, ev.a.ID, TenantUpdate{FQDN: ptr(adminHost)}, clientIP)
		wantInvalid(t, "admin host", err, FieldFQDN)
	})
}

func TestUpdateTenantDelegated(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		v, err := ev.svc.UpdateTenant(ctx, ev.adminA, ev.a.ID, TenantUpdate{
			DefaultLanguage: ptr("fr"), MaxTransferBytes: ptr(int64(1 << 30)), Name: ptr("Entity A"),
		}, clientIP)
		mustNoErr(t, "lower", err)
		if v.DefaultLanguage != "fr" || v.MaxTransferBytes != 1<<30 || v.MaxTransferCeiling != 10<<30 {
			t.Fatalf("updated: %+v", v)
		}
		// Raising back up to the ceiling is allowed, above is not.
		_, err = ev.svc.UpdateTenant(ctx, ev.adminA, ev.a.ID, TenantUpdate{MaxTransferBytes: ptr(int64(10 << 30))}, clientIP)
		mustNoErr(t, "up to the ceiling", err)
		for name, in := range map[string]TenantUpdate{
			"above ceiling": {MaxTransferBytes: ptr(int64(11 << 30))},
			"quota":         {StorageQuotaBytes: ptr(int64(1))},
			"fqdn":          {FQDN: ptr("other.example.com")},
			"name":          {Name: ptr("Renamed")},
			"ceiling":       {MaxTransferCeiling: ptr(int64(1 << 30))},
		} {
			_, err := ev.svc.UpdateTenant(ctx, ev.adminA, ev.a.ID, in, clientIP)
			wantErr(t, name, err, ErrForbidden)
		}
		_, err = ev.svc.UpdateTenant(ctx, ev.adminB, ev.a.ID, TenantUpdate{DefaultLanguage: ptr("fr")}, clientIP)
		wantErr(t, "other tenant", err, ErrNotFound)
	})
}

func TestUpdateTenantValidation(t *testing.T) {
	ctx := context.Background()
	ev := newEnv(t, storetest.SQLite(t))
	for name, tc := range map[string]struct {
		in    TenantUpdate
		field string
	}{
		"name":     {TenantUpdate{Name: ptr("")}, FieldName},
		"fqdn":     {TenantUpdate{FQDN: ptr("bad host")}, FieldFQDN},
		"language": {TenantUpdate{DefaultLanguage: ptr("xx")}, FieldDefaultLanguage},
		"quota":    {TenantUpdate{StorageQuotaBytes: ptr(int64(-1))}, FieldStorageQuotaBytes},
		"ceiling":  {TenantUpdate{MaxTransferCeiling: ptr(int64(0))}, FieldMaxTransferCeiling},
		"limit":    {TenantUpdate{MaxTransferBytes: ptr(int64(0))}, FieldMaxTransferBytes},
	} {
		_, err := ev.svc.UpdateTenant(ctx, ev.super, ev.a.ID, tc.in, clientIP)
		wantInvalid(t, name, err, tc.field)
	}
	f := ev.faults("updateTenant")
	_, err := ev.svc.UpdateTenant(ctx, ev.super, ev.a.ID, TenantUpdate{Name: ptr("Z")}, clientIP)
	wantErr(t, "store failure", err, errBoom)
	f.errs["updateTenant"] = store.ErrNotFound
	_, err = ev.svc.UpdateTenant(ctx, ev.super, ev.a.ID, TenantUpdate{Name: ptr("Z")}, clientIP)
	wantErr(t, "gone", err, ErrNotFound)
	ev.faults("getTenant")
	_, err = ev.svc.UpdateTenant(ctx, ev.super, ev.a.ID, TenantUpdate{Name: ptr("Z")}, clientIP)
	wantErr(t, "get failure", err, errBoom)
}

func TestDeleteTenant(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		// A sealed SMTP password: a key the erasure must destroy.
		_, err := ev.svc.UpdateSMTP(ctx, ev.adminA, ev.a.ID, SMTPUpdate{
			Host: "smtp.example.com", Port: 587, Security: store.SMTPSecuritySTARTTLS, Username: "u",
			Password: ptr("pw-secret"), FromAddress: "noreply@entity-a.example.com",
		}, clientIP)
		mustNoErr(t, "smtp", err)

		err = ev.svc.DeleteTenant(ctx, ev.super, ev.a.ID, "entity a", clientIP)
		wantInvalid(t, "confirm mismatch", err, FieldConfirm)
		err = ev.svc.DeleteTenant(ctx, ev.adminA, ev.a.ID, "Entity A", clientIP)
		wantErr(t, "delegated", err, ErrForbidden)
		if ev.eraser.count() != 0 {
			t.Fatal("eraser called before confirmation")
		}

		// The start of the deletion is audited before the eraser runs.
		startedEvents := 0
		ev.eraser.started = func(tid tenant.ID) {
			startedEvents = len(ev.auditEvents(t, tid, ActionTenantDeletionStarted))
		}
		// Interrupted: the tenant stays deleting and stops resolving. The
		// request context is canceled: the eraser must not see it.
		ev.eraser.err = errBoom
		cctx, cancel := context.WithCancel(ctx)
		defer cancel()
		err = ev.svc.DeleteTenant(cctx, ev.super, ev.a.ID, "Entity A", clientIP)
		wantErr(t, "interrupted", err, errBoom)
		if startedEvents != 1 || ev.eraser.cancelable != 0 {
			t.Fatalf("started events %d, cancelable eraser calls %d", startedEvents, ev.eraser.cancelable)
		}
		got, err := ev.db.Tenants().Get(ctx, ev.a.ID)
		mustNoErr(t, "get", err)
		if got.Status != tenant.StatusDeleting {
			t.Fatalf("status %q", got.Status)
		}
		if _, err := ev.db.Tenants().TenantByFQDN(ctx, hostA); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("deleting tenant still resolves: %v", err)
		}
		_, err = ev.svc.GetSMTP(ctx, ev.adminA, ev.a.ID)
		wantErr(t, "no use while deleting", err, ErrNotFound)

		// Resume.
		mustNoErr(t, "resume", ev.svc.DeleteTenant(ctx, ev.super, ev.a.ID, "Entity A", clientIP))
		if ev.eraser.count() != 2 {
			t.Fatalf("eraser called %d times", ev.eraser.count())
		}
		if _, err := ev.db.Tenants().Get(ctx, ev.a.ID); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("tenant still there: %v", err)
		}
		evs := ev.auditEvents(t, ev.a.ID, ActionTenantDeletionStarted)
		if len(evs) != 2 || startedEvents != 2 {
			t.Fatalf("audit: %+v", evs)
		}
		var resumed []bool
		for _, x := range evs {
			var d struct {
				Name, FQDN string
				Resumed    bool
			}
			mustNoErr(t, "details", json.Unmarshal(x.Details, &d))
			if x.Actor != "root" || x.ActorKind != store.ActorAdmin || x.IP != clientIP ||
				d.Name != "Entity A" || d.FQDN != hostA {
				t.Fatalf("event: %+v %s", x, x.Details)
			}
			resumed = append(resumed, d.Resumed)
		}
		if !slices.Contains(resumed, true) || !slices.Contains(resumed, false) {
			t.Fatalf("resumed flags %v", resumed)
		}
		// The service never records tenant.deleted: the eraser does.
		if n := len(ev.auditEvents(t, ev.a.ID, "tenant.deleted")); n != 0 {
			t.Fatalf("%d tenant.deleted events from the service", n)
		}
		err = ev.svc.DeleteTenant(ctx, ev.super, ev.a.ID, "Entity A", clientIP)
		wantErr(t, "deleted", err, ErrNotFound)

		// The FQDN is free again.
		_, err = ev.svc.CreateTenant(ctx, ev.super, TenantCreate{
			Name: "Entity A again", FQDN: hostA, DefaultLanguage: "en", StorageQuotaBytes: 1,
		}, clientIP)
		mustNoErr(t, "fqdn reused", err)
	})
}

func TestDeleteTenantStatusFault(t *testing.T) {
	ev := newEnv(t, storetest.SQLite(t))
	ev.faults("setTenantStatus")
	err := ev.svc.DeleteTenant(context.Background(), ev.super, ev.a.ID, "Entity A", clientIP)
	wantErr(t, "status", err, errBoom)
}

func TestAuditFailureIsLogged(t *testing.T) {
	ev := newEnv(t, storetest.SQLite(t))
	ev.faults("audit")
	_, err := ev.svc.UpdateTenant(context.Background(), ev.super, ev.a.ID, TenantUpdate{Name: ptr("Z")}, clientIP)
	mustNoErr(t, "update", err)
	if !containsString(ev.logs.String(), "audit write failed") {
		t.Fatalf("log: %s", ev.logs.String())
	}
}

func TestNoCache(t *testing.T) {
	ev := newEnv(t, storetest.SQLite(t), func(o *Options) { o.Cache = nil })
	_, err := ev.svc.UpdateTenant(context.Background(), ev.super, ev.a.ID, TenantUpdate{Name: ptr("Z")}, clientIP)
	mustNoErr(t, "update", err)
}
