package tenantadmin

import (
	"context"
	"slices"
	"testing"

	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

func TestNetworkRules(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		r, err := ev.svc.GetNetworkRules(ctx, ev.adminA, ev.a.ID)
		mustNoErr(t, "get empty", err)
		if len(r.CIDRs) != 0 || len(r.Domains) != 0 || r.Domains == nil {
			t.Fatalf("empty rules: %+v", r)
		}
		r, err = ev.svc.UpdateNetworkRules(ctx, ev.adminA, ev.a.ID,
			[]string{" 10.10.0.0/16", "192.0.2.7", "::ffff:198.51.100.0/120", "2001:db8::/32"},
			[]string{"Entity-A.Example.com", "corp.entity-a.example.com."}, clientIP)
		mustNoErr(t, "update", err)
		wantCIDRs := []string{"10.10.0.0/16", "192.0.2.7/32", "198.51.100.0/24", "2001:db8::/32"}
		for _, c := range wantCIDRs {
			if !slices.Contains(r.CIDRs, c) {
				t.Fatalf("cidrs %v lack %s", r.CIDRs, c)
			}
		}
		if !slices.Equal(r.Domains, []string{"corp.entity-a.example.com", "entity-a.example.com"}) {
			t.Fatalf("domains %v", r.Domains)
		}
		got, err := ev.svc.GetNetworkRules(ctx, ev.adminA, ev.a.ID)
		mustNoErr(t, "get", err)
		if len(got.CIDRs) != 4 {
			t.Fatalf("stored %+v", got)
		}
		if n := len(ev.auditEvents(t, ev.a.ID, ActionTenantNetworkUpdated)); n != 1 {
			t.Fatalf("%d events", n)
		}
		_, err = ev.svc.GetNetworkRules(ctx, ev.adminB, ev.a.ID)
		wantErr(t, "other tenant get", err, ErrNotFound)
		_, err = ev.svc.UpdateNetworkRules(ctx, ev.adminB, ev.a.ID, nil, nil, clientIP)
		wantErr(t, "other tenant update", err, ErrNotFound)
	})
}

func TestNetworkRulesValidation(t *testing.T) {
	ctx := context.Background()
	ev := newEnv(t, storetest.SQLite(t))
	for name, tc := range map[string]struct {
		cidrs, domains []string
		field          string
	}{
		"host bits":    {[]string{"10.0.0.1/8"}, nil, FieldInternalCIDRs + "/0"},
		"zone":         {[]string{"10.0.0.0/8", "fe80::1%eth0"}, nil, FieldInternalCIDRs + "/1"},
		"syntax":       {[]string{"ten.zero"}, nil, FieldInternalCIDRs + "/0"},
		"bad prefix":   {[]string{"10.0.0.0/33"}, nil, FieldInternalCIDRs + "/0"},
		"domain at":    {nil, []string{"user@example.com"}, FieldInternalDomains + "/0"},
		"domain ip":    {nil, []string{"192.0.2.1"}, FieldInternalDomains + "/0"},
		"many cidrs":   {make([]string, MaxInternalCIDRs+1), nil, FieldInternalCIDRs},
		"many domains": {nil, make([]string, MaxInternalDomains+1), FieldInternalDomains},
	} {
		_, err := ev.svc.UpdateNetworkRules(ctx, ev.adminA, ev.a.ID, tc.cidrs, tc.domains, clientIP)
		wantInvalid(t, name, err, tc.field)
	}
	f := ev.faults("replaceNetworkRules", "networkRules")
	_, err := ev.svc.UpdateNetworkRules(ctx, ev.adminA, ev.a.ID, nil, nil, clientIP)
	wantErr(t, "replace", err, errBoom)
	_, err = ev.svc.GetNetworkRules(ctx, ev.adminA, ev.a.ID)
	wantErr(t, "get", err, errBoom)
	f.errs["replaceNetworkRules"] = store.ErrNotFound
	_, err = ev.svc.UpdateNetworkRules(ctx, ev.adminA, ev.a.ID, nil, nil, clientIP)
	wantErr(t, "gone", err, ErrNotFound)
}
