package tenantadmin

import (
	"bytes"
	"context"
	"image"
	"image/color"
	"image/png"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/branding"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// pngImage returns a w x h PNG.
func pngImage(t *testing.T, w, h int) []byte {
	t.Helper()
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	for x := range w {
		img.Set(x, 0, color.NRGBA{R: 200, A: 255})
	}
	var buf bytes.Buffer
	mustNoErr(t, "encode", png.Encode(&buf, img))
	return buf.Bytes()
}

func TestBranding(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		b, err := ev.svc.GetBranding(ctx, ev.adminA, ev.a.ID)
		mustNoErr(t, "get", err)
		if b.PrimaryColor == "" || len(b.Contrast) != 5 || b.HasLogo || b.HasBackground {
			t.Fatalf("branding: %+v", b)
		}
		// A poor contrast is saved, with a failing diagnostic.
		b, err = ev.svc.UpdateBranding(ctx, ev.adminA, ev.a.ID, "#ffff00", "#00875a", clientIP)
		mustNoErr(t, "update", err)
		if b.PrimaryColor != "#FFFF00" || b.AccentColor != "#00875A" || b.Contrast[0].Level != branding.LevelFail {
			t.Fatalf("updated: %+v", b)
		}
		if n := len(ev.auditEvents(t, ev.a.ID, ActionTenantBrandingUpdated)); n != 1 {
			t.Fatalf("%d audit events", n)
		}
		_, err = ev.svc.UpdateBranding(ctx, ev.adminA, ev.a.ID, "red", "#000000", clientIP)
		wantInvalid(t, "primary", err, FieldPrimaryColor)
		_, err = ev.svc.UpdateBranding(ctx, ev.adminA, ev.a.ID, "#000000", "#00000", clientIP)
		wantInvalid(t, "accent", err, FieldAccentColor)
		_, err = ev.svc.GetBranding(ctx, ev.adminB, ev.a.ID)
		wantErr(t, "other tenant", err, ErrNotFound)
	})
}

func TestBrandingAssets(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)

		// No logo: 404; no background: the default one.
		_, err := ev.svc.Asset(ctx, ev.a, "logo")
		wantErr(t, "missing logo", err, ErrNotFound)
		img, err := ev.svc.Asset(ctx, ev.a, "background")
		mustNoErr(t, "default background", err)
		if img.ContentType != branding.ContentTypeJPEG || img.ETag == "" || len(img.Data) == 0 {
			t.Fatalf("default background: %s %s", img.ContentType, img.ETag)
		}
		_, err = ev.svc.Asset(ctx, ev.a, "favicon")
		wantErr(t, "unknown asset", err, ErrNotFound)

		mustNoErr(t, "upload logo", ev.svc.UploadAsset(ctx, ev.adminA, ev.a.ID, "logo", bytes.NewReader(pngImage(t, 64, 32)), clientIP))
		if !ev.assets.has(ev.a.ID, branding.KindLogo) {
			t.Fatal("logo not stored")
		}
		v, err := ev.svc.GetBranding(ctx, ev.adminA, ev.a.ID)
		mustNoErr(t, "get", err)
		if !v.HasLogo || v.HasBackground {
			t.Fatalf("flags: %+v", v)
		}
		tn, err := ev.db.Tenants().Get(ctx, ev.a.ID)
		mustNoErr(t, "tenant", err)
		img, err = ev.svc.Asset(ctx, tn, "logo")
		mustNoErr(t, "logo", err)
		if img.ContentType != branding.ContentTypePNG || !strings.HasPrefix(img.ETag, `"`) {
			t.Fatalf("logo: %s %s", img.ContentType, img.ETag)
		}
		if n := len(ev.auditEvents(t, ev.a.ID, ActionTenantAssetUploaded)); n != 1 {
			t.Fatalf("%d upload events", n)
		}

		// SVG, oversized and corrupt images are refused.
		svg := `<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>`
		err = ev.svc.UploadAsset(ctx, ev.adminA, ev.a.ID, "background", strings.NewReader(svg), clientIP)
		wantErr(t, "svg", err, ErrUnsupportedMediaType)
		err = ev.svc.UploadAsset(ctx, ev.adminA, ev.a.ID, "logo", bytes.NewReader(pngImage(t, 4000, 10)), clientIP)
		wantErr(t, "oversized", err, ErrPayloadTooLarge)
		corrupt := pngImage(t, 8, 8)[:40]
		err = ev.svc.UploadAsset(ctx, ev.adminA, ev.a.ID, "logo", bytes.NewReader(corrupt), clientIP)
		wantInvalid(t, "corrupt", err, FieldImage)
		err = ev.svc.UploadAsset(ctx, ev.adminA, ev.a.ID, "logo", iotest.ErrReader(errBoom), clientIP)
		wantErr(t, "read failure", err, errBoom)
		err = ev.svc.UploadAsset(ctx, ev.adminA, ev.a.ID, "icon", strings.NewReader(""), clientIP)
		wantErr(t, "unknown asset", err, ErrNotFound)
		err = ev.svc.UploadAsset(ctx, ev.adminB, ev.a.ID, "logo", bytes.NewReader(pngImage(t, 8, 8)), clientIP)
		wantErr(t, "other tenant", err, ErrNotFound)

		mustNoErr(t, "upload background",
			ev.svc.UploadAsset(ctx, ev.adminA, ev.a.ID, "background", bytes.NewReader(pngImage(t, 64, 32)), clientIP))
		tn, _ = ev.db.Tenants().Get(ctx, ev.a.ID)
		if !tn.HasBackground {
			t.Fatal("background flag not set")
		}
		// A flag whose file vanished: the default background is served.
		delete(ev.assets.data, assetKey(ev.a.ID, branding.KindBackground))
		img, err = ev.svc.Asset(ctx, tn, "background")
		mustNoErr(t, "vanished background", err)
		if img.ContentType != branding.ContentTypeJPEG {
			t.Fatalf("type %s", img.ContentType)
		}
		ev.assets.getErr = errBoom
		_, err = ev.svc.Asset(ctx, tn, "logo")
		wantErr(t, "read failure", err, errBoom)
		ev.assets.getErr = nil

		mustNoErr(t, "delete logo", ev.svc.DeleteAsset(ctx, ev.adminA, ev.a.ID, "logo", clientIP))
		tn, _ = ev.db.Tenants().Get(ctx, ev.a.ID)
		if tn.HasLogo || ev.assets.has(ev.a.ID, branding.KindLogo) {
			t.Fatal("logo not deleted")
		}
		if n := len(ev.auditEvents(t, ev.a.ID, ActionTenantAssetDeleted)); n != 1 {
			t.Fatalf("%d delete events", n)
		}
		err = ev.svc.DeleteAsset(ctx, ev.adminA, ev.a.ID, "icon", clientIP)
		wantErr(t, "unknown asset", err, ErrNotFound)
		err = ev.svc.DeleteAsset(ctx, ev.adminB, ev.a.ID, "logo", clientIP)
		wantErr(t, "other tenant", err, ErrNotFound)
	})
}

func TestBrandingFaults(t *testing.T) {
	ctx := context.Background()
	ev := newEnv(t, storetest.SQLite(t))
	logo := pngImage(t, 16, 16)

	ev.assets.putErr = errBoom
	err := ev.svc.UploadAsset(ctx, ev.adminA, ev.a.ID, "logo", bytes.NewReader(logo), clientIP)
	wantErr(t, "put", err, errBoom)
	ev.assets.putErr = nil

	ev.assets.delErr = errBoom
	err = ev.svc.DeleteAsset(ctx, ev.adminA, ev.a.ID, "logo", clientIP)
	wantErr(t, "delete", err, errBoom)
	ev.assets.delErr = nil

	f := ev.faults("updateTenant")
	err = ev.svc.UploadAsset(ctx, ev.adminA, ev.a.ID, "logo", bytes.NewReader(logo), clientIP)
	wantErr(t, "flag", err, errBoom)
	_, err = ev.svc.UpdateBranding(ctx, ev.adminA, ev.a.ID, "#000000", "#000000", clientIP)
	wantErr(t, "colors", err, errBoom)
	f.errs["updateTenant"] = store.ErrNotFound
	err = ev.svc.DeleteAsset(ctx, ev.adminA, ev.a.ID, "logo", clientIP)
	wantErr(t, "gone", err, ErrNotFound)

	ev.faults("getTenant")
	err = ev.svc.DeleteAsset(ctx, ev.adminA, ev.a.ID, "logo", clientIP)
	wantErr(t, "get", err, errBoom)
}

func TestGetAsset(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)

		// No custom image: 404 for both, never the default background.
		for _, asset := range []string{"logo", "background", "favicon"} {
			_, err := ev.svc.GetAsset(ctx, ev.adminA, ev.a.ID, asset)
			wantErr(t, "missing "+asset, err, ErrNotFound)
		}
		logo := pngImage(t, 64, 32)
		mustNoErr(t, "upload logo", ev.svc.UploadAsset(ctx, ev.adminA, ev.a.ID, "logo", bytes.NewReader(logo), clientIP))
		mustNoErr(t, "upload background",
			ev.svc.UploadAsset(ctx, ev.adminA, ev.a.ID, "background", bytes.NewReader(logo), clientIP))
		tn, err := ev.db.Tenants().Get(ctx, ev.a.ID)
		mustNoErr(t, "tenant", err)
		for _, asset := range []string{"logo", "background"} {
			for _, p := range []adminauth.Principal{ev.adminA, ev.super} {
				img, err := ev.svc.GetAsset(ctx, p, ev.a.ID, asset)
				mustNoErr(t, "get "+asset, err)
				pub, err := ev.svc.Asset(ctx, tn, asset)
				mustNoErr(t, "public "+asset, err)
				if !bytes.Equal(img.Data, pub.Data) || img.ContentType != pub.ContentType || img.ETag != pub.ETag {
					t.Fatalf("%s: admin %s %s, public %s %s", asset, img.ContentType, img.ETag, pub.ContentType, pub.ETag)
				}
			}
		}
		// Out of reach (other tenant, unknown tenant, unauthenticated): 404 or 401.
		_, err = ev.svc.GetAsset(ctx, ev.adminB, ev.a.ID, "logo")
		wantErr(t, "other tenant", err, ErrNotFound)
		_, err = ev.svc.GetAsset(ctx, ev.super, "ten_unknown", "logo")
		wantErr(t, "unknown tenant", err, ErrNotFound)
		_, err = ev.svc.GetAsset(ctx, adminauth.Principal{}, ev.a.ID, "logo")
		wantErr(t, "unauthenticated", err, ErrUnauthenticated)

		// A flag whose file vanished: 404; a read failure is reported.
		ev.assets.getErr = errBoom
		_, err = ev.svc.GetAsset(ctx, ev.adminA, ev.a.ID, "logo")
		wantErr(t, "read failure", err, errBoom)
		ev.assets.getErr = nil
		delete(ev.assets.data, assetKey(ev.a.ID, branding.KindLogo))
		_, err = ev.svc.GetAsset(ctx, ev.adminA, ev.a.ID, "logo")
		wantErr(t, "vanished logo", err, ErrNotFound)
	})
}
