package tenantadmin

import (
	"context"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// goodLevel returns a valid level with key.
func goodLevel(key string, isDefault bool) ConfidentialityLevel {
	return ConfidentialityLevel{
		Key: key, Labels: map[string]string{"en": "Level " + key, "fr": "Niveau " + key}, IsDefault: isDefault,
		Rules: ConfidentialityRules{AllowedExpiryDays: []int{1, 7, 30}},
	}
}

func TestConfidentialityLevels(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		seeded, err := ev.svc.GetConfidentialityLevels(ctx, ev.adminA, ev.a.ID)
		mustNoErr(t, "get seeded", err)
		if len(seeded) != 3 || seeded[0].Key != "public" {
			t.Fatalf("seeded levels %+v", seeded)
		}
		cap5 := 5
		in := []ConfidentialityLevel{
			goodLevel("open", false),
			{
				Key: "secret", Labels: map[string]string{"en": "Secret", "fr": "Secret"}, IsDefault: true,
				Descriptions: map[string]string{"en": "For secrets"},
				Rules: ConfidentialityRules{
					AllowedExpiryDays: []int{7, 1}, MaxDownloads: &cap5, RequirePassword: true,
					InternalRecipientsOnly: true, ForceDeleteAfterFirstDownload: true,
				},
			},
		}
		out, err := ev.svc.UpdateConfidentialityLevels(ctx, ev.adminA, ev.a.ID, in, clientIP)
		mustNoErr(t, "update", err)
		if len(out) != 2 || out[0].Key != "open" || !out[1].IsDefault || out[1].Descriptions["en"] != "For secrets" ||
			!slices.Equal(out[1].Rules.AllowedExpiryDays, []int{1, 7}) || *out[1].Rules.MaxDownloads != 5 ||
			!out[1].Rules.RequirePassword {
			t.Fatalf("updated levels %+v", out)
		}
		got, err := ev.svc.GetConfidentialityLevels(ctx, ev.adminA, ev.a.ID)
		mustNoErr(t, "get", err)
		if len(got) != 2 || got[1].Key != "secret" {
			t.Fatalf("stored %+v", got)
		}
		events := ev.auditEvents(t, ev.a.ID, ActionTenantConfidentialityUpdated)
		if len(events) != 1 || !strings.Contains(string(events[0].Details), `"open"`) ||
			!strings.Contains(string(events[0].Details), `"secret"`) {
			t.Fatalf("audit %+v", events)
		}
		// Tenant B keeps its own levels.
		other, err := ev.svc.GetConfidentialityLevels(ctx, ev.adminB, ev.b.ID)
		mustNoErr(t, "get B", err)
		if len(other) != 3 {
			t.Fatalf("B levels %+v", other)
		}
		_, err = ev.svc.GetConfidentialityLevels(ctx, ev.adminB, ev.a.ID)
		wantErr(t, "other tenant get", err, ErrNotFound)
		_, err = ev.svc.UpdateConfidentialityLevels(ctx, ev.adminB, ev.a.ID, in, clientIP)
		wantErr(t, "other tenant update", err, ErrNotFound)
		after, _ := ev.svc.GetConfidentialityLevels(ctx, ev.super, ev.a.ID)
		if len(after) != 2 {
			t.Fatalf("A changed by B's admin: %+v", after)
		}
	})
}

func TestConfidentialityLevelsValidation(t *testing.T) {
	ctx := context.Background()
	ev := newEnv(t, storetest.SQLite(t))
	level := func(mutate func(*ConfidentialityLevel)) []ConfidentialityLevel {
		l := goodLevel("one", true)
		mutate(&l)
		return []ConfidentialityLevel{l}
	}
	zero, big := 0, 1001
	many := make([]ConfidentialityLevel, store.MaxConfidentialityLevels+1)
	for i := range many {
		many[i] = goodLevel("k"+strconv.Itoa(i), i == 0)
	}
	longLine := strings.Repeat("x", store.MaxLevelLabelRunes+1)
	for name, tc := range map[string]struct {
		levels []ConfidentialityLevel
		field  string
	}{
		"empty":         {nil, FieldLevels},
		"too many":      {many, FieldLevels},
		"no default":    {level(func(l *ConfidentialityLevel) { l.IsDefault = false }), FieldLevels},
		"two defaults":  {[]ConfidentialityLevel{goodLevel("a", true), goodLevel("b", true)}, "/items/1/isDefault"},
		"dup key":       {[]ConfidentialityLevel{goodLevel("a", true), goodLevel("a", false)}, "/items/1/key"},
		"upper key":     {level(func(l *ConfidentialityLevel) { l.Key = "Open" }), "/items/0/key"},
		"empty key":     {level(func(l *ConfidentialityLevel) { l.Key = "" }), "/items/0/key"},
		"digit key":     {level(func(l *ConfidentialityLevel) { l.Key = "1a" }), "/items/0/key"},
		"long key":      {level(func(l *ConfidentialityLevel) { l.Key = strings.Repeat("a", 33) }), "/items/0/key"},
		"key char":      {level(func(l *ConfidentialityLevel) { l.Key = "a.b" }), "/items/0/key"},
		"no fr label":   {level(func(l *ConfidentialityLevel) { l.Labels = map[string]string{"en": "x"} }), "/items/0/labels/fr"},
		"blank label":   {level(func(l *ConfidentialityLevel) { l.Labels["en"] = "  " }), "/items/0/labels/en"},
		"long label":    {level(func(l *ConfidentialityLevel) { l.Labels["fr"] = longLine }), "/items/0/labels/fr"},
		"label newline": {level(func(l *ConfidentialityLevel) { l.Labels["en"] = "a\nb" }), "/items/0/labels/en"},
		"label lang":    {level(func(l *ConfidentialityLevel) { l.Labels["de"] = "x" }), "/items/0/labels"},
		"desc lang":     {level(func(l *ConfidentialityLevel) { l.Descriptions = map[string]string{"de": "x"} }), "/items/0/descriptions"},
		"desc long": {level(func(l *ConfidentialityLevel) {
			l.Descriptions = map[string]string{"fr": strings.Repeat("x", store.MaxLevelDescriptionRunes+1)}
		}), "/items/0/descriptions/fr"},
		"no days":  {level(func(l *ConfidentialityLevel) { l.Rules.AllowedExpiryDays = nil }), "/items/0/rules/allowedExpiryDays"},
		"bad days": {level(func(l *ConfidentialityLevel) { l.Rules.AllowedExpiryDays = []int{1, 3} }), "/items/0/rules/allowedExpiryDays"},
		"cap zero": {level(func(l *ConfidentialityLevel) { l.Rules.MaxDownloads = &zero }), "/items/0/rules/maxDownloads"},
		"cap big":  {level(func(l *ConfidentialityLevel) { l.Rules.MaxDownloads = &big }), "/items/0/rules/maxDownloads"},
	} {
		_, err := ev.svc.UpdateConfidentialityLevels(ctx, ev.adminA, ev.a.ID, tc.levels, clientIP)
		wantInvalid(t, name, err, tc.field)
	}
	if n := len(ev.auditEvents(t, ev.a.ID, ActionTenantConfidentialityUpdated)); n != 0 {
		t.Fatalf("%d audit events for refused updates", n)
	}
}

func TestConfidentialityLevelsFaults(t *testing.T) {
	ctx := context.Background()
	ev := newEnv(t, storetest.SQLite(t))
	good := []ConfidentialityLevel{goodLevel("a", true)}
	f := ev.faults("replaceConfidentialityLevels", "confidentialityLevels", "audit")
	_, err := ev.svc.UpdateConfidentialityLevels(ctx, ev.adminA, ev.a.ID, good, clientIP)
	wantErr(t, "replace", err, errBoom)
	_, err = ev.svc.GetConfidentialityLevels(ctx, ev.adminA, ev.a.ID)
	wantErr(t, "get", err, errBoom)
	_, err = ev.svc.PublicConfidentialityLevels(ctx, ev.a, "en")
	wantErr(t, "public", err, errBoom)
	f.errs["replaceConfidentialityLevels"] = store.ErrNotFound
	_, err = ev.svc.UpdateConfidentialityLevels(ctx, ev.adminA, ev.a.ID, good, clientIP)
	wantErr(t, "gone", err, ErrNotFound)
	f.errs["replaceConfidentialityLevels"] = store.ErrInvalid
	_, err = ev.svc.UpdateConfidentialityLevels(ctx, ev.adminA, ev.a.ID, good, clientIP)
	wantInvalid(t, "store invalid", err, FieldLevels)
	// A failing audit write never fails the update.
	delete(f.errs, "replaceConfidentialityLevels")
	_, err = ev.svc.UpdateConfidentialityLevels(ctx, ev.adminA, ev.a.ID, good, clientIP)
	mustNoErr(t, "audit failure", err)
}

func TestPublicConfidentialityLevels(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		cap3 := 3
		l := goodLevel("only", true)
		l.Descriptions = map[string]string{"fr": "Seulement en français"}
		l.Rules.MaxDownloads = &cap3
		_, err := ev.svc.UpdateConfidentialityLevels(ctx, ev.super, ev.a.ID, []ConfidentialityLevel{l, goodLevel("two", false)}, clientIP)
		mustNoErr(t, "update", err)
		get := func(tn *tenant.Tenant, lang string) []PublicConfidentialityLevel {
			t.Helper()
			out, err := ev.svc.PublicConfidentialityLevels(ctx, tn, lang)
			mustNoErr(t, "public", err)
			return out
		}
		fr := get(ev.a, "fr")
		if len(fr) != 2 || fr[0].Label != "Niveau only" || fr[0].Description != "Seulement en français" ||
			!fr[0].IsDefault || *fr[0].Rules.MaxDownloads != 3 || fr[1].Description != "" || fr[1].IsDefault {
			t.Fatalf("fr %+v", fr)
		}
		// The default language of the tenant is English: the description
		// falls back to the only one written, the label to English.
		en := get(ev.a, "en")
		if en[0].Label != "Level only" || en[0].Description != "Seulement en français" {
			t.Fatalf("en %+v", en)
		}
		// An unsupported requested language falls back to the tenant default.
		if de := get(ev.a, "de"); de[0].Label != "Level only" {
			t.Fatalf("de %+v", de)
		}
		// Tenant B has its own seeded levels.
		if b := get(ev.b, "en"); len(b) != 3 {
			t.Fatalf("B %+v", b)
		}
	})
}
