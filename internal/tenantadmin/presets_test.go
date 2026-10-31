package tenantadmin

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/branding"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// storedPresetOf returns the background preset stored for tenant tid.
func (ev *env) storedPresetOf(t *testing.T, tid tenant.ID) string {
	t.Helper()
	tn, err := ev.db.Tenants().Get(context.Background(), tid)
	mustNoErr(t, "tenant", err)
	return tn.BackgroundPreset
}

// publicAsset returns the public asset of tenant tid, read again from the
// store like the resolver does.
func (ev *env) publicAsset(t *testing.T, tid tenant.ID, asset string) branding.Image {
	t.Helper()
	tn, err := ev.db.Tenants().Get(context.Background(), tid)
	mustNoErr(t, "tenant", err)
	img, err := ev.svc.Asset(context.Background(), tn, asset)
	mustNoErr(t, "asset "+asset, err)
	return img
}

// presetImage returns the image of preset id.
func presetImage(t *testing.T, id string) branding.Image {
	t.Helper()
	img, ok := branding.PresetBackground(id)
	if !ok {
		t.Fatalf("no preset %q", id)
	}
	return img
}

func TestSetBackgroundPreset(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)

		b, err := ev.svc.GetBranding(ctx, ev.adminA, ev.a.ID)
		mustNoErr(t, "get", err)
		if b.BackgroundPreset != branding.DefaultPresetID {
			t.Fatalf("initial preset %q", b.BackgroundPreset)
		}
		if img := ev.publicAsset(t, ev.a.ID, "background"); img.ETag != branding.DefaultBackground().ETag {
			t.Fatal("the default background is not served initially")
		}

		b, err = ev.svc.SetBackgroundPreset(ctx, ev.adminA, ev.a.ID, ptr("ocean"), clientIP)
		mustNoErr(t, "set", err)
		if b.BackgroundPreset != "ocean" || b.PrimaryColor != ev.a.PrimaryColor || len(b.Contrast) != 5 {
			t.Fatalf("branding: %+v", b)
		}
		if got := ev.storedPresetOf(t, ev.a.ID); got != "ocean" {
			t.Fatalf("stored %q", got)
		}
		if !slices.Contains(ev.cache.tenants, ev.a.ID) {
			t.Error("the resolver cache was not invalidated")
		}
		evs := ev.auditEvents(t, ev.a.ID, ActionTenantBrandingUpdated)
		if len(evs) != 1 || evs[0].Actor != "alice" || evs[0].IP != clientIP {
			t.Fatalf("audit: %+v", evs)
		}
		var details map[string]any
		mustNoErr(t, "details", json.Unmarshal(evs[0].Details, &details))
		if !reflect.DeepEqual(details, map[string]any{"backgroundPreset": "ocean"}) {
			t.Fatalf("details %v", details)
		}
		if img := ev.publicAsset(t, ev.a.ID, "background"); img.ETag != presetImage(t, "ocean").ETag ||
			img.ContentType != branding.ContentTypeJPEG {
			t.Fatal("the preset background is not served")
		}
		// Tenant B keeps the default.
		if img := ev.publicAsset(t, ev.b.ID, "background"); img.ETag != branding.DefaultBackground().ETag {
			t.Fatal("the preset of A leaked to B")
		}

		// The super admin may choose too.
		b, err = ev.svc.SetBackgroundPreset(ctx, ev.super, ev.a.ID, ptr("forest"), clientIP)
		mustNoErr(t, "super", err)
		if b.BackgroundPreset != "forest" {
			t.Fatalf("super: %+v", b)
		}

		// Unrelated updates keep the preset (read-modify-write).
		_, err = ev.svc.UpdateBranding(ctx, ev.adminA, ev.a.ID, "#112233", "#445566", clientIP)
		mustNoErr(t, "colors", err)
		_, err = ev.svc.UpdateTenant(ctx, ev.super, ev.a.ID, TenantUpdate{Name: ptr("Entity A2"), DefaultLanguage: ptr("fr")}, clientIP)
		mustNoErr(t, "update tenant", err)
		_, err = ev.svc.UpdateTenant(ctx, ev.super, ev.a.ID, TenantUpdate{AntivirusEnabled: ptr(false)}, clientIP)
		mustNoErr(t, "antivirus", err)
		if got := ev.storedPresetOf(t, ev.a.ID); got != "forest" {
			t.Fatalf("preset after unrelated updates: %q", got)
		}

		// An uploaded background takes precedence; removing it falls back
		// to the preset.
		mustNoErr(t, "upload background",
			ev.svc.UploadAsset(ctx, ev.adminA, ev.a.ID, "background", bytes.NewReader(pngImage(t, 64, 32)), clientIP))
		uploaded := ev.publicAsset(t, ev.a.ID, "background")
		if uploaded.ETag == presetImage(t, "forest").ETag {
			t.Fatal("the preset is served over the uploaded background")
		}
		b, err = ev.svc.GetBranding(ctx, ev.adminA, ev.a.ID)
		mustNoErr(t, "get", err)
		if !b.HasBackground || b.BackgroundPreset != "forest" {
			t.Fatalf("branding with upload: %+v", b)
		}
		mustNoErr(t, "delete background", ev.svc.DeleteAsset(ctx, ev.adminA, ev.a.ID, "background", clientIP))
		if img := ev.publicAsset(t, ev.a.ID, "background"); img.ETag != presetImage(t, "forest").ETag {
			t.Fatal("deleting the background does not fall back to the preset")
		}

		// null and "default" reset to the default (NULL in the database).
		for _, reset := range []*string{nil, ptr(branding.DefaultPresetID)} {
			_, err = ev.svc.SetBackgroundPreset(ctx, ev.adminA, ev.a.ID, ptr("sand"), clientIP)
			mustNoErr(t, "set", err)
			b, err = ev.svc.SetBackgroundPreset(ctx, ev.adminA, ev.a.ID, reset, clientIP)
			mustNoErr(t, "reset", err)
			if b.BackgroundPreset != branding.DefaultPresetID || ev.storedPresetOf(t, ev.a.ID) != "" {
				t.Fatalf("reset %v: %+v", reset, b)
			}
		}
		resets := 0
		for _, ev := range ev.auditEvents(t, ev.a.ID, ActionTenantBrandingUpdated) {
			var d map[string]any
			mustNoErr(t, "details", json.Unmarshal(ev.Details, &d))
			if d["backgroundPreset"] == branding.DefaultPresetID {
				resets++
			}
		}
		if resets != 2 {
			t.Fatalf("%d reset events, want 2", resets)
		}

		// Unknown presets, whatever their syntax, are refused and change
		// nothing.
		_, err = ev.svc.SetBackgroundPreset(ctx, ev.adminA, ev.a.ID, ptr("ocean"), clientIP)
		mustNoErr(t, "set", err)
		n := len(ev.auditEvents(t, ev.a.ID, ActionTenantBrandingUpdated))
		for _, bad := range []string{"", "nope", "../x", "Ocean", "ocean ", "ocean/../forest", strings.Repeat("a", 40), "default\x00"} {
			_, err = ev.svc.SetBackgroundPreset(ctx, ev.adminA, ev.a.ID, ptr(bad), clientIP)
			wantErr(t, "unknown "+bad, err, ErrUnknownBackgroundPreset)
		}
		if got := ev.storedPresetOf(t, ev.a.ID); got != "ocean" {
			t.Fatalf("stored after refusals %q", got)
		}
		if got := len(ev.auditEvents(t, ev.a.ID, ActionTenantBrandingUpdated)); got != n {
			t.Fatalf("%d audit events after refusals, want %d", got, n)
		}

		// Out of reach: not found, even for an unknown preset (access is
		// checked first); unauthenticated: 401.
		for _, preset := range []*string{ptr("forest"), ptr("../x"), nil} {
			_, err = ev.svc.SetBackgroundPreset(ctx, ev.adminB, ev.a.ID, preset, clientIP)
			wantErr(t, "other tenant", err, ErrNotFound)
		}
		_, err = ev.svc.SetBackgroundPreset(ctx, ev.super, "ten_unknown", ptr("forest"), clientIP)
		wantErr(t, "unknown tenant", err, ErrNotFound)
		_, err = ev.svc.SetBackgroundPreset(ctx, adminauth.Principal{}, ev.a.ID, ptr("forest"), clientIP)
		wantErr(t, "unauthenticated", err, ErrUnauthenticated)
		if got := ev.storedPresetOf(t, ev.a.ID); got != "ocean" {
			t.Fatalf("stored after out-of-reach attempts %q", got)
		}
		if got := len(ev.auditEvents(t, ev.b.ID, ActionTenantBrandingUpdated)); got != 0 {
			t.Fatalf("%d audit events on B", got)
		}
	})
}

// A value of valid syntax unknown to this version (a retired preset) is
// served as the default, never an error (threat model T-252).
func TestStaleBackgroundPreset(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		tn, err := ev.db.Tenants().Get(ctx, ev.a.ID)
		mustNoErr(t, "tenant", err)
		tn.BackgroundPreset = "retired-preset"
		_, err = ev.db.Tenants().Update(ctx, tn)
		mustNoErr(t, "store stale value", err)

		b, err := ev.svc.GetBranding(ctx, ev.adminA, ev.a.ID)
		mustNoErr(t, "get", err)
		if b.BackgroundPreset != branding.DefaultPresetID {
			t.Fatalf("stale preset reported as %q", b.BackgroundPreset)
		}
		if img := ev.publicAsset(t, ev.a.ID, "background"); img.ETag != branding.DefaultBackground().ETag {
			t.Fatal("a stale preset does not serve the default background")
		}
	})
}

func TestSetBackgroundPresetFaults(t *testing.T) {
	ctx := context.Background()
	ev := newEnv(t, storetest.SQLite(t))
	f := ev.faults("updateTenant")
	_, err := ev.svc.SetBackgroundPreset(ctx, ev.adminA, ev.a.ID, ptr("ocean"), clientIP)
	wantErr(t, "update", err, errBoom)
	f.errs["updateTenant"] = store.ErrNotFound
	_, err = ev.svc.SetBackgroundPreset(ctx, ev.adminA, ev.a.ID, ptr("ocean"), clientIP)
	wantErr(t, "gone", err, ErrNotFound)
	if n := len(ev.auditEvents(t, ev.a.ID, ActionTenantBrandingUpdated)); n != 0 {
		t.Fatalf("%d audit events", n)
	}
}

func TestBackgroundPresetLibrary(t *testing.T) {
	ctx := context.Background()
	ev := newEnv(t, storetest.SQLite(t))
	for _, p := range []adminauth.Principal{ev.super, ev.adminA, ev.adminB} {
		got, err := ev.svc.ListBackgroundPresets(ctx, p)
		mustNoErr(t, "list", err)
		if !reflect.DeepEqual(got, branding.Presets()) || got[0].ID != branding.DefaultPresetID {
			t.Fatalf("list: %+v", got)
		}
		img, err := ev.svc.BackgroundPreset(ctx, p, "ocean")
		mustNoErr(t, "preview", err)
		if img.ContentType != branding.ContentTypeJPEG || img.ETag != presetImage(t, "ocean").ETag || len(img.Data) == 0 {
			t.Fatalf("preview: %s %s", img.ContentType, img.ETag)
		}
	}
	img, err := ev.svc.BackgroundPreset(ctx, ev.adminA, branding.DefaultPresetID)
	mustNoErr(t, "default preview", err)
	if img.ETag != branding.DefaultBackground().ETag {
		t.Fatal("the default preset is not the default background")
	}
	for _, bad := range []string{"", "nope", "../x", "Ocean", "ocean.jpg"} {
		_, err := ev.svc.BackgroundPreset(ctx, ev.adminA, bad)
		wantErr(t, "unknown "+bad, err, ErrNotFound)
	}
	_, err = ev.svc.ListBackgroundPresets(ctx, adminauth.Principal{})
	wantErr(t, "list unauthenticated", err, ErrUnauthenticated)
	_, err = ev.svc.BackgroundPreset(ctx, adminauth.Principal{}, "ocean")
	wantErr(t, "preview unauthenticated", err, ErrUnauthenticated)
	pending := ev.adminA
	pending.State = store.SessionTOTPRequired
	_, err = ev.svc.ListBackgroundPresets(ctx, pending)
	wantErr(t, "list pending TOTP", err, ErrUnauthenticated)
}

func TestCreateTenantBackgroundPreset(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		base := TenantCreate{DefaultLanguage: "en", StorageQuotaBytes: 1 << 40}
		tests := []struct {
			fqdn   string
			preset *string
			want   string
		}{
			{"transfer.entity-c.example.com", ptr("forest"), "forest"},
			{"transfer.entity-d.example.com", ptr(branding.DefaultPresetID), ""},
			{"transfer.entity-e.example.com", nil, ""},
		}
		for _, tt := range tests {
			in := base
			in.Name, in.FQDN, in.BackgroundPreset = tt.fqdn, tt.fqdn, tt.preset
			v, err := ev.svc.CreateTenant(ctx, ev.super, in, clientIP)
			mustNoErr(t, "create "+tt.fqdn, err)
			if got := ev.storedPresetOf(t, v.ID); got != tt.want {
				t.Fatalf("%s: stored %q, want %q", tt.fqdn, got, tt.want)
			}
		}
		for _, bad := range []string{"", "nope", "../x"} {
			in := base
			in.Name, in.FQDN, in.BackgroundPreset = "Entity F", "transfer.entity-f.example.com", ptr(bad)
			_, err := ev.svc.CreateTenant(ctx, ev.super, in, clientIP)
			wantErr(t, "unknown "+bad, err, ErrUnknownBackgroundPreset)
		}
		page, err := ev.db.Tenants().List(ctx, store.TenantListOptions{Limit: 100})
		mustNoErr(t, "list", err)
		for _, tn := range page.Items {
			if tn.FQDN == "transfer.entity-f.example.com" {
				t.Fatal("a tenant was created with an unknown preset")
			}
		}
		// A delegated admin keeps its 403, whatever the preset.
		in := base
		in.Name, in.FQDN, in.BackgroundPreset = "Entity G", "transfer.entity-g.example.com", ptr("nope")
		_, err = ev.svc.CreateTenant(ctx, ev.adminA, in, clientIP)
		wantErr(t, "delegated", err, ErrForbidden)
	})
}

// A stale stored preset never blocks an update: it is cleared by the
// change and reported as the default.
func TestStalePresetDoesNotBlockUpdate(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		tn, err := ev.db.Tenants().Get(ctx, ev.a.ID)
		mustNoErr(t, "tenant", err)
		tn.BackgroundPreset = "old-preset"
		_, err = ev.db.Tenants().Update(ctx, tn)
		mustNoErr(t, "store stale value", err)

		b, err := ev.svc.UpdateBranding(ctx, ev.adminA, ev.a.ID, "#112233", "#445566", clientIP)
		mustNoErr(t, "update", err)
		if b.PrimaryColor != "#112233" || b.BackgroundPreset != branding.DefaultPresetID {
			t.Fatalf("branding: %+v", b)
		}
		if got := ev.storedPresetOf(t, ev.a.ID); got != "" {
			t.Fatalf("stored preset %q, want empty", got)
		}
	})
}
