package securityevents

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

const tenantB = tenant.ID("ten_01JAB00000000000000ENT1TYB")

// fakeLister records the filters it receives.
type fakeLister struct {
	got []store.SecurityEventFilter
	err error
}

func (f *fakeLister) List(_ context.Context, flt store.SecurityEventFilter) (store.Page[store.SecurityEvent], error) {
	f.got = append(f.got, flt)
	if f.err != nil {
		return store.Page[store.SecurityEvent]{}, f.err
	}
	return store.Page[store.SecurityEvent]{Items: []store.SecurityEvent{{ID: "sev_x", TenantID: flt.TenantID}}}, nil
}

// fakeTenants knows tenants A (active) and B (being deleted).
type fakeTenants struct{ err error }

func (f fakeTenants) Get(_ context.Context, tid tenant.ID) (*tenant.Tenant, error) {
	switch {
	case f.err != nil:
		return nil, f.err
	case tid == tenantA:
		return &tenant.Tenant{ID: tid, Status: tenant.StatusActive}, nil
	case tid == tenantB:
		return &tenant.Tenant{ID: tid, Status: tenant.StatusDeleting}, nil
	}
	return nil, store.ErrNotFound
}

func principal(role store.AdminRole, tids ...tenant.ID) adminauth.Principal {
	return adminauth.Principal{
		SessionID: "as_x", State: store.SessionAuthenticated,
		Admin: adminauth.Account{ID: "adm_x", Role: role, TenantIDs: tids},
	}
}

func TestNewService(t *testing.T) {
	t.Parallel()
	if _, err := NewService(nil, fakeTenants{}); err == nil {
		t.Error("NewService without events succeeded")
	}
	if _, err := NewService(&fakeLister{}, nil); err == nil {
		t.Error("NewService without tenants succeeded")
	}
}

// TestListTenantAccess covers every path of the tenant listing (T-283):
// the store is only reached for an authorized administrator, always with
// the tenant filter set.
func TestListTenantAccess(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for name, tc := range map[string]struct {
		p       adminauth.Principal
		tid     tenant.ID
		tenants fakeTenants
		want    error
	}{
		"super admin":         {principal(store.RoleSuperAdmin), tenantA, fakeTenants{}, nil},
		"delegated":           {principal(store.RoleDelegatedAdmin, tenantA), tenantA, fakeTenants{}, nil},
		"auditor":             {principal(store.RoleAuditor, tenantA), tenantA, fakeTenants{}, nil},
		"other tenant":        {principal(store.RoleDelegatedAdmin, tenantB), tenantA, fakeTenants{}, adminauth.ErrNotFound},
		"auditor elsewhere":   {principal(store.RoleAuditor, tenantB), tenantA, fakeTenants{}, adminauth.ErrNotFound},
		"no tenant":           {principal(store.RoleSuperAdmin), "", fakeTenants{}, adminauth.ErrNotFound},
		"unknown tenant":      {principal(store.RoleSuperAdmin), "ten_01JAB00000000000000ENT1TYC", fakeTenants{}, ErrNotFound},
		"deleting tenant":     {principal(store.RoleSuperAdmin), tenantB, fakeTenants{}, ErrNotFound},
		"malformed tenant":    {principal(store.RoleSuperAdmin), "bogus", fakeTenants{err: store.ErrInvalid}, ErrNotFound},
		"unknown role":        {principal("root", tenantA), tenantA, fakeTenants{}, adminauth.ErrNotFound},
		"pending login state": {adminauth.Principal{SessionID: "as_x", State: store.SessionTOTPRequired}, tenantA, fakeTenants{}, adminauth.ErrUnauthenticated},
	} {
		events := &fakeLister{}
		svc, _ := NewService(events, tc.tenants)
		page, err := svc.ListTenant(ctx, tc.p, tc.tid, Filter{Type: "rate_limited"})
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", name, err, tc.want)
			continue
		}
		if tc.want != nil {
			if len(events.got) != 0 {
				t.Errorf("%s: the store was read", name)
			}
			continue
		}
		if len(events.got) != 1 || events.got[0].TenantID != tc.tid || events.got[0].Type != "rate_limited" || len(page.Items) != 1 {
			t.Errorf("%s: filters %+v, page %+v", name, events.got, page)
		}
	}
	svc, _ := NewService(&fakeLister{}, fakeTenants{err: errors.New("db down")})
	if _, err := svc.ListTenant(ctx, principal(store.RoleSuperAdmin), tenantA, Filter{}); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("tenant lookup failure = %v", err)
	}
}

func TestListGlobalAccess(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for name, tc := range map[string]struct {
		p    adminauth.Principal
		tid  tenant.ID
		want error
	}{
		"whole log":   {principal(store.RoleSuperAdmin), "", nil},
		"one tenant":  {principal(store.RoleSuperAdmin), tenantB, nil},
		"delegated":   {principal(store.RoleDelegatedAdmin, tenantA), "", adminauth.ErrForbidden},
		"auditor":     {principal(store.RoleAuditor, tenantA), tenantA, adminauth.ErrForbidden},
		"unauth":      {adminauth.Principal{}, "", adminauth.ErrUnauthenticated},
		"disabled":    {adminauth.Principal{SessionID: "as_x", State: store.SessionAuthenticated, Admin: adminauth.Account{Role: store.RoleSuperAdmin, Disabled: true}}, "", adminauth.ErrForbidden},
		"bad tenant":  {principal(store.RoleSuperAdmin), "bogus", &InvalidError{}},
		"bad tenant2": {principal(store.RoleSuperAdmin), "ten_x", &InvalidError{}},
	} {
		events := &fakeLister{}
		svc, _ := NewService(events, fakeTenants{})
		_, err := svc.ListGlobal(ctx, tc.p, tc.tid, Filter{})
		var invalid *InvalidError
		switch {
		case tc.want == nil && err != nil:
			t.Errorf("%s: err = %v", name, err)
		case tc.want == nil:
			if len(events.got) != 1 || events.got[0].TenantID != tc.tid {
				t.Errorf("%s: filters %+v", name, events.got)
			}
		case errors.As(tc.want, &invalid):
			if !errors.As(err, &invalid) || invalid.Field != FieldTenantID || len(events.got) != 0 {
				t.Errorf("%s: err = %v", name, err)
			}
		case !errors.Is(err, tc.want) || len(events.got) != 0:
			t.Errorf("%s: err = %v, want %v (store read %d times)", name, err, tc.want, len(events.got))
		}
	}
}

func TestListValidation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	super := principal(store.RoleSuperAdmin)
	now := time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC)
	for name, tc := range map[string]struct {
		f     Filter
		field string
	}{
		"type":     {Filter{Type: "Bad-Type"}, FieldType},
		"period":   {Filter{From: now, To: now.Add(-time.Second)}, FieldTo},
		"negative": {Filter{Limit: -1}, FieldLimit},
		"too many": {Filter{Limit: store.MaxPageSize + 1}, FieldLimit},
	} {
		events := &fakeLister{}
		svc, _ := NewService(events, fakeTenants{})
		_, err := svc.ListGlobal(ctx, super, "", tc.f)
		var invalid *InvalidError
		if !errors.As(err, &invalid) || invalid.Field != tc.field || len(events.got) != 0 || invalid.Error() == "" {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	// The store refuses the cursor: a validation error on the cursor.
	svc, _ := NewService(&fakeLister{err: fmt.Errorf("list: %w", store.ErrInvalid)}, fakeTenants{})
	var invalid *InvalidError
	if _, err := svc.ListTenant(ctx, super, tenantA, Filter{Cursor: "x"}); !errors.As(err, &invalid) || invalid.Field != FieldCursor {
		t.Errorf("bad cursor: %v", err)
	}
	// Any other store error is a server error.
	svc, _ = NewService(&fakeLister{err: errors.New("db down")}, fakeTenants{})
	if _, err := svc.ListGlobal(ctx, super, "", Filter{}); err == nil || errors.As(err, &invalid) {
		t.Errorf("store failure = %v", err)
	}
	// A valid full filter reaches the store as is.
	events := &fakeLister{}
	svc, _ = NewService(events, fakeTenants{})
	f := Filter{Type: "unknown_fqdn", From: now, To: now.Add(time.Hour), Cursor: "c", Limit: store.MaxPageSize}
	if _, err := svc.ListGlobal(ctx, super, "", f); err != nil {
		t.Fatal(err)
	}
	want := store.SecurityEventFilter{Type: f.Type, Since: f.From, Until: f.To, Cursor: f.Cursor, Limit: f.Limit}
	if got := events.got[0]; got != want {
		t.Errorf("filter %+v, want %+v", got, want)
	}
}
