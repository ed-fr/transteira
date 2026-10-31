package integration_test

import (
	"bytes"
	"net/http"
	"testing"

	"github.com/ed-fr/transteira/internal/branding"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// Paths of the background preset library and of the favicon (since 1.2).
const (
	pathPresets       = "/api/v1/admin/background-presets"
	pathPublicFavicon = "/api/v1/tenant/assets/"
)

// TestBackgroundPresetsAndFavicons, through the real server on every
// engine: a tenant created with a background preset serves its image,
// which any admin previews (ETag, 304); the delegated admin changes the
// preset (an unknown one, a path included, is 422 and changes nothing),
// an uploaded background takes precedence and its removal falls back to
// the preset; the favicons are the built-in ones without logo, generated
// with the logo and removed with it (threat model T-249 to T-253).
func TestBackgroundPresetsAndFavicons(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		a := startAdmin(t, e, serverOptions{}, false)
		sa := a.bootstrap(t, adminIP(1))

		// Creation: an unknown preset is refused and creates nothing.
		for _, bad := range []string{"nope", "../x"} {
			expectProblem(t, sa.call(t, http.MethodPost, pathTenants, map[string]any{
				"name": nameC, "fqdn": hostC, "defaultLanguage": "en", "storageQuotaBytes": quotaC, "backgroundPreset": bad,
			}), http.StatusUnprocessableEntity, "unknown-background-preset")
		}
		resp := mustStatus(t, "createTenant with a preset", sa.call(t, http.MethodPost, pathTenants, map[string]any{
			"name": nameC, "fqdn": hostC, "defaultLanguage": "en", "storageQuotaBytes": quotaC, "backgroundPreset": "forest",
		}), http.StatusCreated)
		var c tenantJSON
		mustJSON(t, resp.body, &c)
		dc := sa.createDelegatedOf(t, "delegate-c", c.ID, domainC, adminIP(2))

		// The library, readable by the delegated admin, default first.
		resp = mustStatus(t, "listBackgroundPresets", dc.call(t, http.MethodGet, pathPresets, nil), http.StatusOK)
		var lib struct {
			Items []struct {
				ID     string            `json:"id"`
				Labels map[string]string `json:"labels"`
			} `json:"items"`
		}
		mustJSON(t, resp.body, &lib)
		if len(lib.Items) != len(branding.Presets()) || lib.Items[0].ID != branding.DefaultPresetID ||
			lib.Items[0].Labels["fr"] == "" || lib.Items[0].Labels["en"] == "" {
			t.Fatalf("library = %s", resp.body)
		}
		preview := mustStatus(t, "getBackgroundPreset", dc.call(t, http.MethodGet, pathPresets+"/forest", nil), http.StatusOK)
		etag := preview.header.Get("ETag")
		if preview.header.Get("Content-Type") != "image/jpeg" || preview.header.Get("X-Content-Type-Options") != "nosniff" ||
			etag == "" || preview.header.Get("Cache-Control") != "private, max-age=300" {
			t.Errorf("preview headers = %v", preview.header)
		}
		nm := dc.send(t, http.MethodGet, pathPresets+"/forest", nil, http.Header{"If-None-Match": {etag}})
		if nm.status != http.StatusNotModified || len(nm.body) != 0 {
			t.Errorf("preview with If-None-Match: %d (%d bytes)", nm.status, len(nm.body))
		}
		expectProblem(t, dc.call(t, http.MethodGet, pathPresets+"/nope", nil), http.StatusNotFound, "not-found")

		// The preset chosen at creation is served.
		if bg := a.get(t, hostC, pathPublicBg); bg.status != http.StatusOK || !bytes.Equal(bg.body, preview.body) {
			t.Errorf("public background: %d, want the forest preset", bg.status)
		}
		var br struct {
			BackgroundPreset string `json:"backgroundPreset"`
		}
		resp = mustStatus(t, "getBranding", dc.call(t, http.MethodGet, tenantPath(c.ID, "/branding"), nil), http.StatusOK)
		mustJSON(t, resp.body, &br)
		if br.BackgroundPreset != "forest" {
			t.Errorf("branding preset = %q", br.BackgroundPreset)
		}

		// Change by the delegated admin; refusals change nothing.
		presetPath := tenantPath(c.ID, "/branding/background-preset")
		resp = mustStatus(t, "setBackgroundPreset", dc.call(t, http.MethodPut, presetPath, map[string]any{"preset": "ocean"}), http.StatusOK)
		mustJSON(t, resp.body, &br)
		if br.BackgroundPreset != "ocean" {
			t.Errorf("set answer = %s", resp.body)
		}
		for _, bad := range []string{"nope", "../x", "Ocean"} {
			expectProblem(t, dc.call(t, http.MethodPut, presetPath, map[string]any{"preset": bad}),
				http.StatusUnprocessableEntity, "unknown-background-preset")
		}
		ocean := mustStatus(t, "preview ocean", dc.call(t, http.MethodGet, pathPresets+"/ocean", nil), http.StatusOK)
		if bg := a.get(t, hostC, pathPublicBg); !bytes.Equal(bg.body, ocean.body) {
			t.Error("the public background is not the ocean preset")
		}

		// An uploaded background takes precedence, its removal falls back
		// to the preset.
		mustStatus(t, "upload background", dc.putBytes(t, tenantPath(c.ID, "/branding/background"), "image/jpeg",
			jpegWithExif(t, 64, 48, "b")), http.StatusNoContent)
		if bg := a.get(t, hostC, pathPublicBg); bytes.Equal(bg.body, ocean.body) {
			t.Error("the preset is served over the uploaded background")
		}
		mustStatus(t, "delete background", dc.call(t, http.MethodDelete, tenantPath(c.ID, "/branding/background"), nil), http.StatusNoContent)
		if bg := a.get(t, hostC, pathPublicBg); !bytes.Equal(bg.body, ocean.body) {
			t.Error("deleting the background does not fall back to the preset")
		}
		// null resets to the default.
		resp = mustStatus(t, "reset preset", dc.call(t, http.MethodPut, presetPath, `{"preset":null}`), http.StatusOK)
		mustJSON(t, resp.body, &br)
		if br.BackgroundPreset != branding.DefaultPresetID {
			t.Errorf("reset answer = %s", resp.body)
		}

		// Favicons: the built-in ones without logo, always 200.
		var pub struct {
			Branding struct {
				FaviconURL string `json:"faviconUrl"`
			} `json:"branding"`
		}
		mustJSON(t, a.get(t, hostC, pathPublicTenant).body, &pub)
		if pub.Branding.FaviconURL != pathPublicFavicon+"favicon" {
			t.Errorf("faviconUrl = %q", pub.Branding.FaviconURL)
		}
		builtIn := map[string][]byte{}
		for _, k := range branding.FaviconKinds() {
			r := mustStatus(t, "default "+k.String(), a.get(t, hostC, pathPublicFavicon+k.String()), http.StatusOK)
			def, _ := branding.DefaultFavicon(k)
			if !bytes.Equal(r.body, def.Data) || r.header.Get("Content-Type") != k.ContentType() ||
				r.header.Get("X-Content-Type-Options") != "nosniff" {
				t.Errorf("default %s: %v", k, r.header)
			}
			builtIn[k.String()] = r.body
		}
		// With a logo: generated icons, revalidated with their ETag.
		mustStatus(t, "upload logo", dc.putBytes(t, tenantPath(c.ID, "/branding/logo"), "image/png",
			pngWithText(t, 64, 32, "favicon-source")), http.StatusNoContent)
		for _, k := range branding.FaviconKinds() {
			path := pathPublicFavicon + k.String()
			r := mustStatus(t, k.String(), a.get(t, hostC, path), http.StatusOK)
			if bytes.Equal(r.body, builtIn[k.String()]) || r.header.Get("Content-Type") != k.ContentType() {
				t.Errorf("%s after the logo upload: still the built-in icon or %q", k, r.header.Get("Content-Type"))
			}
			nm := a.do(t, request{host: hostC, path: path, headers: http.Header{"If-None-Match": {r.header.Get("ETag")}}})
			if nm.status != http.StatusNotModified {
				t.Errorf("%s with If-None-Match: %d", k, nm.status)
			}
			// Tenant A, without logo, keeps the built-in icon.
			if ra := a.get(t, hostA, path); ra.status != http.StatusOK || !bytes.Equal(ra.body, builtIn[k.String()]) {
				t.Errorf("%s under %s: %d, want the built-in icon", k, hostA, ra.status)
			}
		}
		// The admin API never serves the favicons.
		expectProblem(t, dc.call(t, http.MethodGet, tenantPath(c.ID, "/branding/favicon"), nil), http.StatusNotFound, "not-found")
		// Deleting the logo brings the built-in icons back.
		mustStatus(t, "delete logo", dc.call(t, http.MethodDelete, tenantPath(c.ID, "/branding/logo"), nil), http.StatusNoContent)
		for _, k := range branding.FaviconKinds() {
			if r := a.get(t, hostC, pathPublicFavicon+k.String()); r.status != http.StatusOK || !bytes.Equal(r.body, builtIn[k.String()]) {
				t.Errorf("%s after the logo deletion: %d, want the built-in icon", k, r.status)
			}
		}
		a.expectTenantAudit(t, c.ID, "tenant.created", "tenant.branding_updated", "tenant.asset_uploaded", "tenant.asset_deleted")
	})
}
