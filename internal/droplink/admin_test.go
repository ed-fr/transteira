package droplink

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

const (
	hostA     = "transfer.entity-a.example.com"
	hostB     = "transfer.entity-b.example.com"
	domainA   = "entity-a.example.com"
	missingTn = tenant.ID("ten_01JAB00000000000000000000Z")
)

var (
	testStart = time.Date(2026, time.November, 6, 9, 0, 0, 0, time.UTC)
	adminIP   = netip.MustParseAddr("192.0.2.10")
	errBoom   = errors.New("boom")
)

type syncBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// faultRepo wraps a repo and fails the operations named in errs, and
// overrides the status of the tenants read.
type faultRepo struct {
	repo
	errs         map[string]error
	tenantStatus tenant.Status
}

func (f *faultRepo) fail(op string) error { return f.errs[op] }

func (f *faultRepo) getTenant(ctx context.Context, tid tenant.ID) (*tenant.Tenant, error) {
	if err := f.fail("getTenant"); err != nil {
		return nil, err
	}
	t, err := f.repo.getTenant(ctx, tid)
	if err == nil && f.tenantStatus != "" {
		t.Status = f.tenantStatus
	}
	return t, err
}

func (f *faultRepo) networkRules(ctx context.Context, tid tenant.ID) (store.NetworkRuleSet, error) {
	if err := f.fail("networkRules"); err != nil {
		return store.NetworkRuleSet{}, err
	}
	return f.repo.networkRules(ctx, tid)
}

func (f *faultRepo) levels(ctx context.Context, tid tenant.ID) ([]store.ConfidentialityLevel, error) {
	if err := f.fail("levels"); err != nil {
		return nil, err
	}
	return f.repo.levels(ctx, tid)
}

func (f *faultRepo) list(ctx context.Context, tid tenant.ID) ([]store.DropLink, error) {
	if err := f.fail("list"); err != nil {
		return nil, err
	}
	return f.repo.list(ctx, tid)
}

func (f *faultRepo) get(ctx context.Context, tid tenant.ID, linkID string) (store.DropLink, error) {
	if err := f.fail("get"); err != nil {
		return store.DropLink{}, err
	}
	return f.repo.get(ctx, tid, linkID)
}

func (f *faultRepo) create(ctx context.Context, tid tenant.ID, l store.DropLink) (store.DropLink, error) {
	if err := f.fail("create"); err != nil {
		return store.DropLink{}, err
	}
	return f.repo.create(ctx, tid, l)
}

func (f *faultRepo) update(ctx context.Context, tid tenant.ID, linkID string, u store.DropLinkUpdate, now time.Time) (store.DropLink, bool, error) {
	if err := f.fail("update"); err != nil {
		return store.DropLink{}, false, err
	}
	return f.repo.update(ctx, tid, linkID, u, now)
}

func (f *faultRepo) rotate(ctx context.Context, tid tenant.ID, linkID string, hash []byte, now time.Time) (store.DropLink, error) {
	if err := f.fail("rotate"); err != nil {
		return store.DropLink{}, err
	}
	return f.repo.rotate(ctx, tid, linkID, hash, now)
}

func (f *faultRepo) revoke(ctx context.Context, tid tenant.ID, linkID string, now time.Time) (store.DropLink, bool, error) {
	if err := f.fail("revoke"); err != nil {
		return store.DropLink{}, false, err
	}
	return f.repo.revoke(ctx, tid, linkID, now)
}

func (f *faultRepo) audit(ctx context.Context, tid tenant.ID, ev audit.Event) error {
	if err := f.fail("audit"); err != nil {
		return err
	}
	return f.repo.audit(ctx, tid, ev)
}

// env is a service over a migrated database with tenants A and B.
type env struct {
	db   *store.DB
	logs *syncBuffer
	repo *faultRepo
	svc  *Service
	a, b *tenant.Tenant
	// super is a super admin; delegA, delegB delegated admins of A and B;
	// auditorA an auditor of A.
	super, delegA, delegB, auditorA adminauth.Principal
}

func newEnv(t *testing.T, e storetest.Engine) *env {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, e.Config(), store.WithClock(func() time.Time { return testStart }))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	ev := &env{db: db, logs: &syncBuffer{}}
	for _, h := range []string{hostA, hostB} {
		tn, err := db.Tenants().Create(ctx, &tenant.Tenant{
			SetupState: tenant.SetupStateActive,
			Name:       "Entity " + h, FQDN: h, DefaultLanguage: "fr", MaxTransferBytes: 1 << 30, StorageQuotaBytes: 1 << 40,
		})
		if err != nil {
			t.Fatal(err)
		}
		if ev.a == nil {
			ev.a = tn
		} else {
			ev.b = tn
		}
	}
	if _, err := db.NetworkRules().Replace(ctx, ev.a.ID, nil, []string{domainA}); err != nil {
		t.Fatal(err)
	}
	svc, err := New(db, Options{Now: func() time.Time { return testStart }, Logger: slog.New(slog.NewTextHandler(ev.logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	ev.repo = &faultRepo{repo: svc.repo, errs: map[string]error{}}
	svc.repo = ev.repo
	ev.svc = svc
	ev.super = principal(store.RoleSuperAdmin, "root")
	ev.delegA = principal(store.RoleDelegatedAdmin, "admin.a", ev.a.ID)
	ev.delegB = principal(store.RoleDelegatedAdmin, "admin.b", ev.b.ID)
	ev.auditorA = principal(store.RoleAuditor, "auditor.a", ev.a.ID)
	return ev
}

func principal(role store.AdminRole, username string, tids ...tenant.ID) adminauth.Principal {
	return adminauth.Principal{
		SessionID: id.New(id.AdminSession), State: store.SessionAuthenticated,
		Admin: adminauth.Account{ID: id.New(id.Admin), Username: username, Role: role, TenantIDs: tids},
	}
}

type auditRow struct {
	store.AuditEvent
	details map[string]any
}

func (ev *env) auditRows(t *testing.T, tid tenant.ID) []auditRow {
	t.Helper()
	page, err := ev.db.AuditEvents().List(context.Background(), store.AuditFilter{TenantID: tid, Limit: store.MaxPageSize})
	if err != nil {
		t.Fatal(err)
	}
	out := make([]auditRow, 0, len(page.Items))
	for i := len(page.Items) - 1; i >= 0; i-- {
		r := auditRow{AuditEvent: page.Items[i]}
		if len(r.Details) > 0 {
			if err := json.Unmarshal(r.Details, &r.details); err != nil {
				t.Fatal(err)
			}
		}
		out = append(out, r)
	}
	return out
}

func okInput() CreateInput {
	return CreateInput{Label: "Intake", Recipients: []string{"Desk@" + domainA}, ValidityDays: 7}
}

func (ev *env) create(t *testing.T) Created {
	t.Helper()
	c, err := ev.svc.Create(context.Background(), ev.delegA, ev.a.ID, okInput(), adminIP)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func wantInvalid(t *testing.T, name string, err error, field string) {
	t.Helper()
	var inv *InvalidError
	if !errors.Is(err, ErrInvalidInput) || !errors.As(err, &inv) || inv.Field != field {
		t.Errorf("%s: err = %v, want invalid %s", name, err, field)
		return
	}
	if !strings.Contains(err.Error(), field) {
		t.Errorf("%s: message %q lacks the field", name, err)
	}
}

func TestNew(t *testing.T) {
	if _, err := New(nil, Options{}); err == nil {
		t.Error("New(nil) succeeded")
	}
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		db, err := store.Open(context.Background(), e.Config())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		svc, err := New(db, Options{})
		if err != nil || svc.logger == nil || svc.now == nil || svc.newToken == nil {
			t.Errorf("New defaults = %+v, %v", svc, err)
		}
	})
}

func TestCreate(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		c, err := ev.svc.Create(ctx, ev.delegA, ev.a.ID, okInput(), adminIP)
		if err != nil {
			t.Fatal(err)
		}
		if !id.DropTokenValid(c.Token) || c.URL != "https://"+hostA+id.DropPath+c.Token {
			t.Errorf("token %q url %q", c.Token, c.URL)
		}
		l := c.Link
		if !id.Valid(id.DropLink, l.ID) || l.CreatedBy != ev.delegA.Admin.ID || !l.Enabled || l.Label != "Intake" ||
			len(l.Recipients) != 1 || l.Recipients[0] != "desk@"+domainA || l.ValidityDays != 7 || l.ConfidentialityLevel != "" {
			t.Errorf("link = %+v", l)
		}
		if !l.ExpiresAt.IsZero() || l.MaxDepositsPerHour != DefaultDepositsPerHour {
			t.Errorf("default limits = %v, %d", l.ExpiresAt, l.MaxDepositsPerHour)
		}
		got, err := ev.db.DropLinks().GetByTokenHash(ctx, ev.a.ID, id.HashToken(c.Token), testStart)
		if err != nil || got.ID != l.ID {
			t.Errorf("lookup by token = %+v, %v", got, err)
		}
		rows := ev.auditRows(t, ev.a.ID)
		if len(rows) != 1 || rows[0].Action != string(audit.ActionDropLinkCreated) || rows[0].ObjectKind != audit.ObjectDropLink ||
			rows[0].ObjectID != l.ID {
			t.Fatalf("audit = %+v", rows)
		}
		if raw := string(rows[0].Details); strings.Contains(raw, c.Token) || strings.Contains(raw, "desk@") {
			t.Errorf("audit details leak: %s", raw)
		}
		if d := rows[0].details; d["expiresAt"] != nil || d["maxDepositsPerHour"] != float64(DefaultDepositsPerHour) {
			t.Errorf("audit limits = %v", d)
		}

		// Disabled, explicit level, super admin.
		off := false
		in := okInput()
		in.Label, in.ValidityDays, in.ConfidentialityLevel, in.Enabled = "a@b", 1, "confidential", &off
		c2, err := ev.svc.Create(ctx, ev.super, ev.a.ID, in, adminIP)
		if err != nil || c2.Link.Enabled || c2.Link.ConfidentialityLevel != "confidential" {
			t.Fatalf("create disabled = %+v, %v", c2.Link, err)
		}
		if rows := ev.auditRows(t, ev.a.ID); strings.Contains(string(rows[1].Details), "a@b") {
			t.Errorf("label with at sign audited: %s", rows[1].Details)
		}

		// Expiry and hourly cap.
		end, cap5 := testStart.Add(30*24*time.Hour), 5
		in = okInput()
		in.ExpiresAt, in.MaxDepositsPerHour = &end, &cap5
		c3, err := ev.svc.Create(ctx, ev.delegA, ev.a.ID, in, adminIP)
		if err != nil || !c3.Link.ExpiresAt.Equal(end) || c3.Link.MaxDepositsPerHour != 5 {
			t.Fatalf("create with limits = %+v, %v", c3.Link, err)
		}
		if d := ev.auditRows(t, ev.a.ID)[2].details; d["expiresAt"] != end.UTC().Format(time.RFC3339) || d["maxDepositsPerHour"] != float64(5) {
			t.Errorf("audit limits = %v", d)
		}
	})
}

func TestUnused(t *testing.T) {
	t.Parallel()
	now := time.Date(2027, 3, 31, 12, 0, 0, 0, time.UTC)
	limit := now.AddDate(0, -UnusedMonths, 0) // 2026-03-31 12:00
	for name, tc := range map[string]struct {
		l    store.DropLink
		want bool
	}{
		"new":                {store.DropLink{CreatedAt: now.Add(-time.Hour)}, false},
		"created at limit":   {store.DropLink{CreatedAt: limit}, false},
		"created before":     {store.DropLink{CreatedAt: limit.Add(-time.Millisecond)}, true},
		"used recently":      {store.DropLink{CreatedAt: limit.AddDate(-1, 0, 0), LastUsedAt: limit.Add(time.Hour)}, false},
		"used long ago":      {store.DropLink{CreatedAt: limit.AddDate(-1, 0, 0), LastUsedAt: limit.Add(-time.Hour)}, true},
		"revoked":            {store.DropLink{CreatedAt: limit.AddDate(-1, 0, 0), RevokedAt: limit}, false},
		"disabled forgotten": {store.DropLink{CreatedAt: limit.AddDate(-1, 0, 0)}, true},
	} {
		if got := Unused(tc.l, now); got != tc.want {
			t.Errorf("%s: Unused = %v, want %v", name, got, tc.want)
		}
	}
}

func TestCreateValidation(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		try := func(name, field string, mut func(*CreateInput)) {
			t.Helper()
			in := okInput()
			mut(&in)
			_, err := ev.svc.Create(ctx, ev.delegA, ev.a.ID, in, adminIP)
			wantInvalid(t, name, err, field)
		}
		try("empty label", FieldLabel, func(in *CreateInput) { in.Label = "  " })
		try("long label", FieldLabel, func(in *CreateInput) { in.Label = strings.Repeat("x", MaxLabelLen+1) })
		try("control label", FieldLabel, func(in *CreateInput) { in.Label = "a\nb" })
		try("no recipient", FieldRecipients, func(in *CreateInput) { in.Recipients = nil })
		try("too many", FieldRecipients, func(in *CreateInput) {
			in.Recipients = nil
			for i := 0; i <= MaxRecipients; i++ {
				in.Recipients = append(in.Recipients, "u"+string(rune('a'+i))+"@"+domainA)
			}
		})
		try("empty address", FieldRecipients+"/0", func(in *CreateInput) { in.Recipients = []string{" "} })
		try("long address", FieldRecipients+"/0", func(in *CreateInput) {
			in.Recipients = []string{strings.Repeat("x", MaxRecipientLen) + "@" + domainA}
		})
		try("bad address", FieldRecipients+"/1", func(in *CreateInput) { in.Recipients = []string{"a@" + domainA, "nope"} })
		try("external", FieldRecipients+"/0", func(in *CreateInput) { in.Recipients = []string{"a@example.org"} })
		try("subdomain", FieldRecipients+"/0", func(in *CreateInput) { in.Recipients = []string{"a@sub." + domainA} })
		try("duplicate", FieldRecipients+"/1", func(in *CreateInput) {
			in.Recipients = []string{"a@" + domainA, "A@" + domainA}
		})
		try("validity", FieldValidity, func(in *CreateInput) { in.ValidityDays = 3 })
		try("validity zero", FieldValidity, func(in *CreateInput) { in.ValidityDays = 0 })
		try("level validity", FieldValidity, func(in *CreateInput) { in.ValidityDays = 30; in.ConfidentialityLevel = "confidential" })
		try("unknown level", FieldLevel, func(in *CreateInput) { in.ConfidentialityLevel = "nope" })
		past, zero, over := testStart, 0, MaxDepositsPerHour+1
		try("expiry now", FieldExpiresAt, func(in *CreateInput) { in.ExpiresAt = &past })
		try("cap zero", FieldMaxPerHour, func(in *CreateInput) { in.MaxDepositsPerHour = &zero })
		try("cap over", FieldMaxPerHour, func(in *CreateInput) { in.MaxDepositsPerHour = &over })
	})
}

func TestCreateFailures(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		for _, op := range []string{"getTenant", "networkRules", "levels", "create"} {
			ev.repo.errs = map[string]error{op: errBoom}
			if _, err := ev.svc.Create(ctx, ev.delegA, ev.a.ID, okInput(), adminIP); !errors.Is(err, errBoom) {
				t.Errorf("%s: err = %v", op, err)
			}
		}
		for stored, want := range map[error]error{
			store.ErrNotFound: ErrNotFound, store.ErrLimitReached: ErrLimitReached,
		} {
			ev.repo.errs = map[string]error{"create": stored}
			if _, err := ev.svc.Create(ctx, ev.delegA, ev.a.ID, okInput(), adminIP); !errors.Is(err, want) {
				t.Errorf("%v: err = %v, want %v", stored, err, want)
			}
		}
		ev.repo.errs = map[string]error{"create": store.ErrInvalid}
		_, err := ev.svc.Create(ctx, ev.delegA, ev.a.ID, okInput(), adminIP)
		wantInvalid(t, "store invalid", err, "")
		ev.repo.errs = map[string]error{}
		ev.svc.newToken = func() (string, error) { return "", errBoom }
		if _, err := ev.svc.Create(ctx, ev.delegA, ev.a.ID, okInput(), adminIP); !errors.Is(err, errBoom) {
			t.Errorf("token: err = %v", err)
		}
		if _, err := ev.svc.Rotate(ctx, ev.delegA, ev.a.ID, id.New(id.DropLink), adminIP); !errors.Is(err, errBoom) {
			t.Errorf("rotate token: err = %v", err)
		}
	})
}

func TestCreateLimit(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		for i := 0; i < store.MaxDropLinks; i++ {
			ev.create(t)
		}
		_, err := ev.svc.Create(context.Background(), ev.delegA, ev.a.ID, okInput(), adminIP)
		if !errors.Is(err, ErrLimitReached) {
			t.Errorf("err = %v, want ErrLimitReached", err)
		}
	})
}

func TestAccess(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		c := ev.create(t)
		lid := c.Link.ID
		unauth := adminauth.Principal{Admin: ev.super.Admin, State: store.SessionTOTPRequired}

		writes := map[string]func(p adminauth.Principal, tid tenant.ID) error{
			"create": func(p adminauth.Principal, tid tenant.ID) error {
				_, err := ev.svc.Create(ctx, p, tid, okInput(), adminIP)
				return err
			},
			"update": func(p adminauth.Principal, tid tenant.ID) error {
				l := "x"
				_, err := ev.svc.Update(ctx, p, tid, lid, UpdateInput{Label: &l}, adminIP)
				return err
			},
			"rotate": func(p adminauth.Principal, tid tenant.ID) error {
				_, err := ev.svc.Rotate(ctx, p, tid, lid, adminIP)
				return err
			},
			"revoke": func(p adminauth.Principal, tid tenant.ID) error { return ev.svc.Revoke(ctx, p, tid, lid, adminIP) },
		}
		reads := map[string]func(p adminauth.Principal, tid tenant.ID) error{
			"list": func(p adminauth.Principal, tid tenant.ID) error { _, err := ev.svc.List(ctx, p, tid); return err },
			"get":  func(p adminauth.Principal, tid tenant.ID) error { _, err := ev.svc.Get(ctx, p, tid, lid); return err },
		}
		for name, f := range writes {
			if err := f(unauth, ev.a.ID); !errors.Is(err, ErrUnauthenticated) {
				t.Errorf("%s unauthenticated: %v", name, err)
			}
			if err := f(ev.auditorA, ev.a.ID); !errors.Is(err, adminauth.ErrReadOnlyRole) {
				t.Errorf("%s auditor: %v", name, err)
			}
			if err := f(ev.delegB, ev.a.ID); !errors.Is(err, ErrNotFound) {
				t.Errorf("%s other tenant admin: %v", name, err)
			}
			if err := f(ev.super, missingTn); !errors.Is(err, ErrNotFound) {
				t.Errorf("%s missing tenant: %v", name, err)
			}
		}
		for name, f := range reads {
			if err := f(unauth, ev.a.ID); !errors.Is(err, ErrUnauthenticated) {
				t.Errorf("%s unauthenticated: %v", name, err)
			}
			if err := f(ev.auditorA, ev.a.ID); err != nil {
				t.Errorf("%s auditor: %v", name, err)
			}
			if err := f(ev.delegB, ev.a.ID); !errors.Is(err, ErrNotFound) {
				t.Errorf("%s other tenant admin: %v", name, err)
			}
			if err := f(ev.super, missingTn); !errors.Is(err, ErrNotFound) {
				t.Errorf("%s missing tenant: %v", name, err)
			}
		}
		// Tenant B holds nothing, and A's link is unknown from B.
		if err := reads["get"](ev.delegB, ev.b.ID); !errors.Is(err, ErrNotFound) {
			t.Errorf("get on B: %v", err)
		}
		if err := ev.svc.Revoke(ctx, ev.delegB, ev.b.ID, lid, adminIP); !errors.Is(err, ErrNotFound) {
			t.Errorf("revoke on B: %v", err)
		}
		// A tenant being deleted answers like a missing one; lookup errors pass.
		ev.repo.tenantStatus = tenant.StatusDeleting
		if err := reads["list"](ev.super, ev.a.ID); !errors.Is(err, ErrNotFound) {
			t.Errorf("deleting tenant: %v", err)
		}
		ev.repo.tenantStatus = ""
		ev.repo.errs["getTenant"] = store.ErrInvalid
		if err := reads["list"](ev.super, ev.a.ID); !errors.Is(err, ErrNotFound) {
			t.Errorf("invalid tenant: %v", err)
		}
		ev.repo.errs["getTenant"] = errBoom
		if err := reads["list"](ev.super, ev.a.ID); !errors.Is(err, errBoom) {
			t.Errorf("tenant failure: %v", err)
		}
	})
}

func TestListGet(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		c := ev.create(t)
		list, err := ev.svc.List(ctx, ev.delegA, ev.a.ID)
		if err != nil || len(list) != 1 || list[0].ID != c.Link.ID {
			t.Fatalf("List = %+v, %v", list, err)
		}
		if list, err := ev.svc.List(ctx, ev.delegB, ev.b.ID); err != nil || len(list) != 0 {
			t.Errorf("List B = %+v, %v", list, err)
		}
		if l, err := ev.svc.Get(ctx, ev.auditorA, ev.a.ID, c.Link.ID); err != nil || l.ID != c.Link.ID {
			t.Errorf("Get = %+v, %v", l, err)
		}
		if _, err := ev.svc.Get(ctx, ev.delegA, ev.a.ID, "bad"); !errors.Is(err, ErrNotFound) {
			t.Errorf("Get malformed: %v", err)
		}
		if _, err := ev.svc.Get(ctx, ev.delegA, ev.a.ID, id.New(id.DropLink)); !errors.Is(err, ErrNotFound) {
			t.Errorf("Get unknown: %v", err)
		}
		ev.repo.errs["list"] = errBoom
		if _, err := ev.svc.List(ctx, ev.delegA, ev.a.ID); !errors.Is(err, errBoom) {
			t.Errorf("List failure: %v", err)
		}
		ev.repo.errs["get"] = errBoom
		if _, err := ev.svc.Get(ctx, ev.delegA, ev.a.ID, c.Link.ID); !errors.Is(err, errBoom) {
			t.Errorf("Get failure: %v", err)
		}
	})
}

func TestUpdate(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		c := ev.create(t)
		lid := c.Link.ID
		label, days, off := "Renamed", 30, false
		l, err := ev.svc.Update(ctx, ev.delegA, ev.a.ID, lid, UpdateInput{
			Label: &label, Recipients: []string{"a@" + domainA, "b@" + domainA}, ValidityDays: &days, Enabled: &off,
		}, adminIP)
		if err != nil || l.Label != label || len(l.Recipients) != 2 || l.ValidityDays != 30 || l.Enabled {
			t.Fatalf("Update = %+v, %v", l, err)
		}
		rows := ev.auditRows(t, ev.a.ID)
		if len(rows) != 2 || rows[1].Action != string(audit.ActionDropLinkUpdated) || rows[1].details["recipientCount"] != float64(2) {
			t.Fatalf("audit = %+v", rows)
		}
		if strings.Contains(string(rows[1].Details), "@") {
			t.Errorf("recipients audited: %s", rows[1].Details)
		}
		// Only the fields that change are audited.
		cap20 := 20
		if _, err := ev.svc.Update(ctx, ev.delegA, ev.a.ID, lid, UpdateInput{
			Label: &label, Recipients: []string{"a@" + domainA, "b@" + domainA}, ValidityDays: &days, Enabled: &off,
			MaxDepositsPerHour: &cap20, ExpiresSet: true, LevelSet: true,
		}, adminIP); err != nil {
			t.Fatal(err)
		}
		if got := len(ev.auditRows(t, ev.a.ID)); got != 2 {
			t.Errorf("%d audit rows after an update to the same values, want 2", got)
		}
		// Same values again: nothing changes, nothing is audited.
		if _, err := ev.svc.Update(ctx, ev.delegA, ev.a.ID, lid, UpdateInput{Label: &label}, adminIP); err != nil {
			t.Fatal(err)
		}
		if _, err := ev.svc.Update(ctx, ev.delegA, ev.a.ID, lid, UpdateInput{}, adminIP); err != nil {
			t.Fatal(err)
		}
		if got := len(ev.auditRows(t, ev.a.ID)); got != 2 {
			t.Errorf("%d audit rows after no-op updates, want 2", got)
		}
		// Level: set (30 days not allowed there), then clear.
		_, err = ev.svc.Update(ctx, ev.delegA, ev.a.ID, lid, UpdateInput{LevelSet: true, ConfidentialityLevel: "confidential"}, adminIP)
		wantInvalid(t, "level vs validity", err, FieldValidity)
		d1 := 1
		l, err = ev.svc.Update(ctx, ev.delegA, ev.a.ID, lid, UpdateInput{LevelSet: true, ConfidentialityLevel: "confidential", ValidityDays: &d1}, adminIP)
		if err != nil || l.ConfidentialityLevel != "confidential" || l.ValidityDays != 1 {
			t.Fatalf("set level = %+v, %v", l, err)
		}
		l, err = ev.svc.Update(ctx, ev.delegA, ev.a.ID, lid, UpdateInput{LevelSet: true}, adminIP)
		if err != nil || l.ConfidentialityLevel != "" {
			t.Fatalf("clear level = %+v, %v", l, err)
		}
		// Expiry and cap: set, audited, then the expiry cleared.
		end, cap7 := testStart.Add(time.Hour), 7
		l, err = ev.svc.Update(ctx, ev.delegA, ev.a.ID, lid, UpdateInput{ExpiresSet: true, ExpiresAt: end, MaxDepositsPerHour: &cap7}, adminIP)
		if err != nil || !l.ExpiresAt.Equal(end) || l.MaxDepositsPerHour != 7 {
			t.Fatalf("set limits = %+v, %v", l, err)
		}
		rows = ev.auditRows(t, ev.a.ID)
		if d := rows[len(rows)-1].details; d["expiresAt"] != end.Format(time.RFC3339) || d["maxDepositsPerHour"] != float64(7) {
			t.Errorf("audit limits = %v", d)
		}
		l, err = ev.svc.Update(ctx, ev.delegA, ev.a.ID, lid, UpdateInput{ExpiresSet: true}, adminIP)
		if err != nil || !l.ExpiresAt.IsZero() {
			t.Fatalf("clear expiry = %+v, %v", l, err)
		}
		rows = ev.auditRows(t, ev.a.ID)
		if d := rows[len(rows)-1].details; d["expiresAt"] != nil {
			t.Errorf("audit cleared expiry = %v", d)
		}
		if _, ok := rows[len(rows)-1].details["expiresAt"]; !ok {
			t.Errorf("audit lacks the cleared expiry: %v", rows[len(rows)-1].details)
		}
		// Label with an at sign is not audited.
		at := "x@y"
		if _, err := ev.svc.Update(ctx, ev.delegA, ev.a.ID, lid, UpdateInput{Label: &at}, adminIP); err != nil {
			t.Fatal(err)
		}
		rows = ev.auditRows(t, ev.a.ID)
		if last := rows[len(rows)-1]; strings.Contains(string(last.Details), "x@y") {
			t.Errorf("label with at sign audited: %s", last.Details)
		}
		// Disabled again, at 30 days, for the re-enabling below.
		d30 := 30
		if _, err := ev.svc.Update(ctx, ev.delegA, ev.a.ID, lid, UpdateInput{Enabled: &off, ValidityDays: &d30}, adminIP); err != nil {
			t.Fatal(err)
		}
		// Re-enabling checks the validity against the current level,
		// changed meanwhile (R3).
		levels, err := ev.db.ConfidentialityLevels().List(ctx, ev.a.ID)
		if err != nil {
			t.Fatal(err)
		}
		mask, _ := store.ExpiryDaysMaskOf([]int{1, 7})
		for i := range levels {
			if levels[i].IsDefault {
				levels[i].Rules.ExpiryDaysMask = mask
			}
		}
		if _, err := ev.db.ConfidentialityLevels().Replace(ctx, ev.a.ID, levels, "adm", testStart); err != nil {
			t.Fatal(err)
		}
		on, d7 := true, 7
		_, err = ev.svc.Update(ctx, ev.delegA, ev.a.ID, lid, UpdateInput{Enabled: &on}, adminIP)
		wantInvalid(t, "re-enable with a validity the level no longer allows", err, FieldValidity)
		l, err = ev.svc.Update(ctx, ev.delegA, ev.a.ID, lid, UpdateInput{Enabled: &on, ValidityDays: &d7}, adminIP)
		if err != nil || !l.Enabled || l.ValidityDays != 7 {
			t.Fatalf("re-enable = %+v, %v", l, err)
		}
		rows = ev.auditRows(t, ev.a.ID)
		if d := rows[len(rows)-1].details; len(d) != 2 || d["enabled"] != true || d["validityDays"] != float64(7) {
			t.Errorf("audit re-enable = %v", d)
		}
	})
}

func TestUpdateValidation(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		lid := ev.create(t).Link.ID
		empty, three, nope := "", 3, "nope"
		for name, tc := range map[string]struct {
			in    UpdateInput
			field string
		}{
			"label":      {UpdateInput{Label: &empty}, FieldLabel},
			"recipients": {UpdateInput{Recipients: []string{}}, FieldRecipients},
			"external":   {UpdateInput{Recipients: []string{"a@example.org"}}, FieldRecipients + "/0"},
			"validity":   {UpdateInput{ValidityDays: &three}, FieldValidity},
			"level":      {UpdateInput{LevelSet: true, ConfidentialityLevel: nope}, FieldLevel},
			"expiry":     {UpdateInput{ExpiresSet: true, ExpiresAt: testStart.Add(-time.Second)}, FieldExpiresAt},
			"cap":        {UpdateInput{MaxDepositsPerHour: new(int)}, FieldMaxPerHour},
		} {
			_, err := ev.svc.Update(ctx, ev.delegA, ev.a.ID, lid, tc.in, adminIP)
			wantInvalid(t, name, err, tc.field)
		}
		if _, err := ev.svc.Update(ctx, ev.delegA, ev.a.ID, "bad", UpdateInput{}, adminIP); !errors.Is(err, ErrNotFound) {
			t.Errorf("malformed id: %v", err)
		}
		if _, err := ev.svc.Update(ctx, ev.delegA, ev.a.ID, id.New(id.DropLink), UpdateInput{}, adminIP); !errors.Is(err, ErrNotFound) {
			t.Errorf("unknown id: %v", err)
		}
		for _, op := range []string{"get", "update"} {
			ev.repo.errs = map[string]error{op: errBoom}
			if _, err := ev.svc.Update(ctx, ev.delegA, ev.a.ID, lid, UpdateInput{}, adminIP); !errors.Is(err, errBoom) {
				t.Errorf("%s: %v", op, err)
			}
		}
		for stored, want := range map[error]error{store.ErrNotFound: ErrNotFound, store.ErrConflict: ErrStateConflict} {
			ev.repo.errs = map[string]error{"update": stored}
			if _, err := ev.svc.Update(ctx, ev.delegA, ev.a.ID, lid, UpdateInput{}, adminIP); !errors.Is(err, want) {
				t.Errorf("%v: %v", stored, err)
			}
		}
		ev.repo.errs = map[string]error{"update": store.ErrInvalid}
		_, err := ev.svc.Update(ctx, ev.delegA, ev.a.ID, lid, UpdateInput{}, adminIP)
		wantInvalid(t, "store invalid", err, "")
	})
}

func TestRotateRevoke(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		c := ev.create(t)
		lid := c.Link.ID
		r, err := ev.svc.Rotate(ctx, ev.delegA, ev.a.ID, lid, adminIP)
		if err != nil || r.Token == c.Token || r.URL != "https://"+hostA+id.DropPath+r.Token || r.Link.ID != lid {
			t.Fatalf("Rotate = %+v, %v", r, err)
		}
		if _, err := ev.db.DropLinks().GetByTokenHash(ctx, ev.a.ID, id.HashToken(c.Token), testStart); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("old token still valid: %v", err)
		}
		if _, err := ev.db.DropLinks().GetByTokenHash(ctx, ev.a.ID, id.HashToken(r.Token), testStart); err != nil {
			t.Errorf("new token: %v", err)
		}
		if err := ev.svc.Revoke(ctx, ev.delegA, ev.a.ID, lid, adminIP); err != nil {
			t.Fatal(err)
		}
		if err := ev.svc.Revoke(ctx, ev.delegA, ev.a.ID, lid, adminIP); err != nil {
			t.Fatalf("second revoke: %v", err)
		}
		if _, err := ev.svc.Rotate(ctx, ev.delegA, ev.a.ID, lid, adminIP); !errors.Is(err, ErrStateConflict) {
			t.Errorf("rotate revoked: %v", err)
		}
		var actions []audit.Action
		for _, row := range ev.auditRows(t, ev.a.ID) {
			actions = append(actions, audit.Action(row.Action))
			if strings.Contains(string(row.Details), r.Token) || strings.Contains(string(row.Details), c.Token) {
				t.Errorf("token in audit: %s", row.Details)
			}
		}
		want := []audit.Action{audit.ActionDropLinkCreated, audit.ActionDropLinkRotated, audit.ActionDropLinkRevoked}
		if len(actions) != 3 || actions[0] != want[0] || actions[1] != want[1] || actions[2] != want[2] {
			t.Errorf("actions = %v, want %v", actions, want)
		}
		for _, bad := range []string{"bad", id.New(id.DropLink)} {
			if _, err := ev.svc.Rotate(ctx, ev.delegA, ev.a.ID, bad, adminIP); !errors.Is(err, ErrNotFound) {
				t.Errorf("rotate %q: %v", bad, err)
			}
			if err := ev.svc.Revoke(ctx, ev.delegA, ev.a.ID, bad, adminIP); !errors.Is(err, ErrNotFound) {
				t.Errorf("revoke %q: %v", bad, err)
			}
		}
		for stored, want := range map[error]error{store.ErrNotFound: ErrNotFound, store.ErrConflict: ErrStateConflict, errBoom: errBoom} {
			ev.repo.errs = map[string]error{"rotate": stored}
			if _, err := ev.svc.Rotate(ctx, ev.delegA, ev.a.ID, lid, adminIP); !errors.Is(err, want) {
				t.Errorf("rotate %v: %v", stored, err)
			}
		}
		for stored, want := range map[error]error{store.ErrNotFound: ErrNotFound, errBoom: errBoom} {
			ev.repo.errs = map[string]error{"revoke": stored}
			if err := ev.svc.Revoke(ctx, ev.delegA, ev.a.ID, lid, adminIP); !errors.Is(err, want) {
				t.Errorf("revoke %v: %v", stored, err)
			}
		}
	})
}

func TestAuditFailureIsLogged(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ev.repo.errs["audit"] = errBoom
		ctx, cancel := context.WithCancel(context.Background())
		c, err := ev.svc.Create(ctx, ev.delegA, ev.a.ID, okInput(), adminIP)
		cancel()
		if err != nil || c.Link.ID == "" {
			t.Fatalf("Create = %+v, %v", c, err)
		}
		if !strings.Contains(ev.logs.String(), "audit write failed") {
			t.Errorf("failure not logged:\n%s", ev.logs.String())
		}
	})
}
