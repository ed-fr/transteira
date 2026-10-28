package tenantadmin

import (
	"context"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

func TestRecipientRules(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		r, err := ev.svc.GetRecipientRules(ctx, ev.adminA, ev.a.ID)
		mustNoErr(t, "get empty", err)
		if r.Allowed == nil || r.Denied == nil || len(r.Allowed)+len(r.Denied) != 0 {
			t.Fatalf("empty rules %+v", r)
		}
		has, err := ev.svc.HasRecipientRules(ctx, ev.a)
		mustNoErr(t, "has", err)
		if has {
			t.Fatal("empty rules reported as restrictions")
		}
		r, err = ev.svc.UpdateRecipientRules(ctx, ev.adminA, ev.a.ID,
			[]string{" Partner.Example.COM.", "bücher.example"}, []string{"Mail.Example.com"}, clientIP)
		mustNoErr(t, "update", err)
		if !slices.Equal(r.Allowed, []string{"partner.example.com", "xn--bcher-kva.example"}) ||
			!slices.Equal(r.Denied, []string{"mail.example.com"}) {
			t.Fatalf("rules %+v", r)
		}
		if has, _ = ev.svc.HasRecipientRules(ctx, ev.a); !has {
			t.Fatal("rules not reported")
		}
		if has, _ = ev.svc.HasRecipientRules(ctx, ev.b); has {
			t.Fatal("B reports A's rules")
		}
		events := ev.auditEvents(t, ev.a.ID, ActionTenantRecipientRulesUpdated)
		if len(events) != 1 || !strings.Contains(string(events[0].Details), "partner.example.com") ||
			!strings.Contains(string(events[0].Details), "mail.example.com") {
			t.Fatalf("audit %+v", events)
		}
		_, err = ev.svc.GetRecipientRules(ctx, ev.adminB, ev.a.ID)
		wantErr(t, "other tenant get", err, ErrNotFound)
		_, err = ev.svc.UpdateRecipientRules(ctx, ev.adminB, ev.a.ID, nil, nil, clientIP)
		wantErr(t, "other tenant update", err, ErrNotFound)
		got, _ := ev.svc.GetRecipientRules(ctx, ev.super, ev.a.ID)
		if len(got.Allowed) != 2 {
			t.Fatalf("A changed by B's admin: %+v", got)
		}
		// Emptying removes the restrictions.
		_, err = ev.svc.UpdateRecipientRules(ctx, ev.adminA, ev.a.ID, nil, nil, clientIP)
		mustNoErr(t, "empty", err)
	})
}

func TestRecipientRulesValidation(t *testing.T) {
	ctx := context.Background()
	ev := newEnv(t, storetest.SQLite(t))
	tooMany := make([]string, store.MaxRecipientRules+1)
	for i := range tooMany {
		tooMany[i] = "d" + strconv.Itoa(i) + ".example.com"
	}
	for name, tc := range map[string]struct {
		allowed, denied []string
		field           string
	}{
		"at sign":      {[]string{"user@example.com"}, nil, "/allowedDomains/0"},
		"ip":           {nil, []string{"ok.example.com", "192.0.2.1"}, "/deniedDomains/1"},
		"empty":        {[]string{""}, nil, "/allowedDomains/0"},
		"leading dot":  {[]string{".example.com"}, nil, "/allowedDomains/0"},
		"dup":          {[]string{"a.example.com", "A.Example.com."}, nil, "/allowedDomains/1"},
		"dup denied":   {nil, []string{"a.example.com", "b.example.com", "b.example.com"}, "/deniedDomains/2"},
		"many allowed": {tooMany, nil, "/allowedDomains"},
		"many denied":  {nil, tooMany, "/deniedDomains"},
	} {
		_, err := ev.svc.UpdateRecipientRules(ctx, ev.adminA, ev.a.ID, tc.allowed, tc.denied, clientIP)
		wantInvalid(t, name, err, tc.field)
	}
	f := ev.faults("replaceRecipientRules", "recipientRules")
	_, err := ev.svc.UpdateRecipientRules(ctx, ev.adminA, ev.a.ID, nil, nil, clientIP)
	wantErr(t, "replace", err, errBoom)
	_, err = ev.svc.GetRecipientRules(ctx, ev.adminA, ev.a.ID)
	wantErr(t, "get", err, errBoom)
	_, err = ev.svc.HasRecipientRules(ctx, ev.a)
	wantErr(t, "has", err, errBoom)
	f.errs["replaceRecipientRules"] = store.ErrNotFound
	_, err = ev.svc.UpdateRecipientRules(ctx, ev.adminA, ev.a.ID, nil, nil, clientIP)
	wantErr(t, "gone", err, ErrNotFound)
	f.errs["replaceRecipientRules"] = store.ErrInvalid
	_, err = ev.svc.UpdateRecipientRules(ctx, ev.adminA, ev.a.ID, nil, nil, clientIP)
	wantInvalid(t, "store invalid", err, FieldAllowedDomains)
}
