package tenantadmin

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/ed-fr/transteira/internal/branding"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// logoKinds are the files written with a logo.
var logoKinds = append([]branding.Kind{branding.KindLogo}, branding.FaviconKinds()...)

// defaultFavicon returns the built-in icon of kind k.
func defaultFavicon(t *testing.T, k branding.Kind) branding.Image {
	t.Helper()
	img, ok := branding.DefaultFavicon(k)
	if !ok {
		t.Fatalf("no default %s", k)
	}
	return img
}

// snapshot returns the stored logo files of tenant tid, nil when missing.
func (ev *env) snapshot(tid tenant.ID) map[branding.Kind][]byte {
	out := map[branding.Kind][]byte{}
	for _, k := range logoKinds {
		out[k] = ev.assets.get(tid, k)
	}
	return out
}

// sameFiles fails unless the stored logo files of tid equal want.
func (ev *env) sameFiles(t *testing.T, what string, tid tenant.ID, want map[branding.Kind][]byte) {
	t.Helper()
	for k, data := range ev.snapshot(tid) {
		if !bytes.Equal(data, want[k]) {
			t.Fatalf("%s: %s changed (%d bytes, want %d)", what, k, len(data), len(want[k]))
		}
	}
}

func TestFavicons(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)

		// Without a logo: the built-in icons, 200, exact types.
		for _, k := range branding.FaviconKinds() {
			img := ev.publicAsset(t, ev.a.ID, k.String())
			def := defaultFavicon(t, k)
			if img.ETag != def.ETag || !bytes.Equal(img.Data, def.Data) || img.ContentType != k.ContentType() {
				t.Fatalf("default %s: %s %s", k, img.ContentType, img.ETag)
			}
		}
		if ct := ev.publicAsset(t, ev.a.ID, "favicon").ContentType; ct != branding.ContentTypeICO {
			t.Fatalf("favicon type %s", ct)
		}

		// A logo generates the three favicons from the re-encoded logo.
		mustNoErr(t, "upload A", ev.svc.UploadAsset(ctx, ev.adminA, ev.a.ID, "logo", bytes.NewReader(pngImage(t, 64, 32)), clientIP))
		mustNoErr(t, "upload B", ev.svc.UploadAsset(ctx, ev.adminB, ev.b.ID, "logo", bytes.NewReader(pngImage(t, 40, 40)), clientIP))
		want, err := branding.GenerateFavicons(ctx, ev.assets.get(ev.a.ID, branding.KindLogo))
		mustNoErr(t, "generate", err)
		for _, k := range branding.FaviconKinds() {
			wantImg, _ := want.Get(k)
			if !bytes.Equal(ev.assets.get(ev.a.ID, k), wantImg.Data) {
				t.Fatalf("stored %s is not generated from the stored logo", k)
			}
			a := ev.publicAsset(t, ev.a.ID, k.String())
			b := ev.publicAsset(t, ev.b.ID, k.String())
			if !bytes.Equal(a.Data, wantImg.Data) || a.ETag != wantImg.ETag || a.ContentType != k.ContentType() {
				t.Fatalf("served %s of A: %s %s", k, a.ContentType, a.ETag)
			}
			// Each tenant gets its own icons, never the other's or the
			// default ones.
			if b.ETag == a.ETag || a.ETag == defaultFavicon(t, k).ETag || b.ETag == defaultFavicon(t, k).ETag {
				t.Fatalf("%s: A %s, B %s", k, a.ETag, b.ETag)
			}
		}
		if n := len(ev.auditEvents(t, ev.a.ID, ActionTenantAssetUploaded)); n != 1 {
			t.Fatalf("%d upload events", n)
		}
		// The favicons are public only: the administration serves the
		// uploadable images.
		for _, k := range branding.FaviconKinds() {
			_, err := ev.svc.GetAsset(ctx, ev.adminA, ev.a.ID, k.String())
			wantErr(t, "admin "+k.String(), err, ErrNotFound)
		}
		// Uploading a favicon is impossible.
		err = ev.svc.UploadAsset(ctx, ev.adminA, ev.a.ID, "favicon", bytes.NewReader(pngImage(t, 16, 16)), clientIP)
		wantErr(t, "upload favicon", err, ErrNotFound)
		err = ev.svc.DeleteAsset(ctx, ev.adminA, ev.a.ID, "favicon", clientIP)
		wantErr(t, "delete favicon", err, ErrNotFound)

		// A favicon file that vanished is generated again from the logo.
		vanished := ev.assets.get(ev.a.ID, branding.KindFavicon32)
		delete(ev.assets.data, assetKey(ev.a.ID, branding.KindFavicon32))
		if img := ev.publicAsset(t, ev.a.ID, "favicon-32"); !bytes.Equal(img.Data, vanished) {
			t.Fatal("a vanished favicon is not generated again")
		}

		// A background upload leaves the favicons alone.
		before := ev.snapshot(ev.b.ID)
		mustNoErr(t, "background", ev.svc.UploadAsset(ctx, ev.adminB, ev.b.ID, "background", bytes.NewReader(pngImage(t, 64, 32)), clientIP))
		ev.sameFiles(t, "background upload", ev.b.ID, before)

		// Deleting the logo removes the favicons: the default ones again.
		mustNoErr(t, "delete logo", ev.svc.DeleteAsset(ctx, ev.adminA, ev.a.ID, "logo", clientIP))
		for _, k := range logoKinds {
			if ev.assets.has(ev.a.ID, k) {
				t.Fatalf("%s kept after the logo deletion", k)
			}
		}
		for _, k := range branding.FaviconKinds() {
			if img := ev.publicAsset(t, ev.a.ID, k.String()); img.ETag != defaultFavicon(t, k).ETag {
				t.Fatalf("%s after the logo deletion is not the default", k)
			}
		}
		// Tenant B is untouched.
		for _, k := range logoKinds {
			if !ev.assets.has(ev.b.ID, k) {
				t.Fatalf("%s of B removed", k)
			}
		}
		// Deleting a missing logo succeeds.
		mustNoErr(t, "delete again", ev.svc.DeleteAsset(ctx, ev.adminA, ev.a.ID, "logo", clientIP))
	})
}

func TestFaviconFaults(t *testing.T) {
	ctx := context.Background()
	ev := newEnv(t, storetest.SQLite(t))
	first, second := pngImage(t, 64, 32), pngImage(t, 32, 32)
	mustNoErr(t, "first logo", ev.svc.UploadAsset(ctx, ev.adminA, ev.a.ID, "logo", bytes.NewReader(first), clientIP))
	prev := ev.snapshot(ev.a.ID)
	for k, data := range prev {
		if data == nil {
			t.Fatalf("%s missing after the first upload", k)
		}
	}
	uploads := func() int { return len(ev.auditEvents(t, ev.a.ID, ActionTenantAssetUploaded)) }

	// A failed generation refuses the upload: nothing written.
	ev.svc.favicons = func(context.Context, []byte) (branding.Favicons, error) { return branding.Favicons{}, errBoom }
	err := ev.svc.UploadAsset(ctx, ev.adminA, ev.a.ID, "logo", bytes.NewReader(second), clientIP)
	wantErr(t, "generation", err, errBoom)
	ev.sameFiles(t, "generation failure", ev.a.ID, prev)
	ev.svc.favicons = branding.GenerateFavicons

	// A failed write of any file restores the previous ones.
	for _, k := range logoKinds {
		ev.assets.putErrAt = map[branding.Kind]error{k: errBoom}
		err = ev.svc.UploadAsset(ctx, ev.adminA, ev.a.ID, "logo", bytes.NewReader(second), clientIP)
		wantErr(t, "write "+k.String(), err, errBoom)
		ev.sameFiles(t, "write failure on "+k.String(), ev.a.ID, prev)
	}
	ev.assets.putErrAt = nil

	// Without a previous logo, the files written are removed again.
	ev.assets.putErrAt = map[branding.Kind]error{branding.KindLogo: errBoom}
	err = ev.svc.UploadAsset(ctx, ev.adminB, ev.b.ID, "logo", bytes.NewReader(second), clientIP)
	wantErr(t, "first write", err, errBoom)
	for _, k := range logoKinds {
		if ev.assets.has(ev.b.ID, k) {
			t.Fatalf("%s of B left after a failed first upload", k)
		}
	}
	ev.assets.putErrAt = nil

	// The previous files cannot be read: nothing is written.
	ev.assets.getErr = errBoom
	err = ev.svc.UploadAsset(ctx, ev.adminA, ev.a.ID, "logo", bytes.NewReader(second), clientIP)
	wantErr(t, "read previous", err, errBoom)
	ev.assets.getErr = nil
	ev.sameFiles(t, "read failure", ev.a.ID, prev)

	// The flag cannot be set: the previous files are restored.
	f := ev.faults("updateTenant")
	err = ev.svc.UploadAsset(ctx, ev.adminA, ev.a.ID, "logo", bytes.NewReader(second), clientIP)
	wantErr(t, "flag", err, errBoom)
	ev.sameFiles(t, "flag failure", ev.a.ID, prev)
	delete(f.errs, "updateTenant")

	// A failed restoration is logged; the error of the upload is kept.
	ev.assets.putErrAt = map[branding.Kind]error{branding.KindAppleTouchIcon: errBoom}
	ev.assets.delErrAt = map[branding.Kind]error{branding.KindLogo: errBoom}
	err = ev.svc.UploadAsset(ctx, ev.adminB, ev.b.ID, "logo", bytes.NewReader(second), clientIP)
	wantErr(t, "restore failure", err, errBoom)
	if !strings.Contains(ev.logs.String(), "branding image restore failed") {
		t.Fatalf("restore failure not logged: %s", ev.logs.String())
	}
	ev.assets.putErrAt, ev.assets.delErrAt = nil, nil

	if n := uploads(); n != 1 {
		t.Fatalf("%d upload events after failures, want 1", n)
	}
	// The logo flag stayed set and the previous logo is still served.
	if img := ev.publicAsset(t, ev.a.ID, "logo"); !bytes.Equal(img.Data, prev[branding.KindLogo]) {
		t.Fatal("the previous logo is not served")
	}

	// A failed deletion of a favicon is reported.
	ev.assets.delErrAt = map[branding.Kind]error{branding.KindFavicon32: errBoom}
	err = ev.svc.DeleteAsset(ctx, ev.adminA, ev.a.ID, "logo", clientIP)
	wantErr(t, "delete favicon", err, errBoom)
	ev.assets.delErrAt = nil
}

// legacyLogo gives tenant tid a logo as before TransTeira 1.2: the flag and
// the logo file, no favicon. It returns the stored logo.
func (ev *env) legacyLogo(t *testing.T, tid tenant.ID) []byte {
	t.Helper()
	ctx := context.Background()
	img, err := branding.ProcessContext(ctx, branding.KindLogo, bytes.NewReader(pngImage(t, 64, 32)), 0)
	mustNoErr(t, "process", err)
	mustNoErr(t, "put logo", ev.assets.Put(tid, branding.KindLogo, img.Data))
	tn, err := ev.db.Tenants().Get(ctx, tid)
	mustNoErr(t, "tenant", err)
	tn.HasLogo = true
	_, err = ev.db.Tenants().Update(ctx, tn)
	mustNoErr(t, "flag", err)
	return img.Data
}

func TestFaviconBackfill(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		logo := ev.legacyLogo(t, ev.a.ID)
		want, err := branding.GenerateFavicons(ctx, logo)
		mustNoErr(t, "generate", err)

		// First request generates and persists the three icons.
		wantImg, _ := want.Get(branding.KindFavicon32)
		got := ev.publicAsset(t, ev.a.ID, "favicon-32")
		if !bytes.Equal(got.Data, wantImg.Data) {
			t.Fatal("backfilled icon differs from the generated one")
		}
		for _, k := range branding.FaviconKinds() {
			icon, _ := want.Get(k)
			if !bytes.Equal(ev.assets.get(ev.a.ID, k), icon.Data) {
				t.Fatalf("%s not persisted", k)
			}
		}
		// Later requests read the stored files, without generating again.
		ev.svc.favicons = func(context.Context, []byte) (branding.Favicons, error) { return branding.Favicons{}, errBoom }
		for _, k := range branding.FaviconKinds() {
			icon, _ := want.Get(k)
			if img := ev.publicAsset(t, ev.a.ID, k.String()); !bytes.Equal(img.Data, icon.Data) {
				t.Fatalf("%s not read from the store", k)
			}
		}
	})
}

func TestFaviconBackfillFaults(t *testing.T) {
	ctx := context.Background()
	ev := newEnv(t, storetest.SQLite(t))
	logo := ev.legacyLogo(t, ev.a.ID)
	tn, err := ev.db.Tenants().Get(ctx, ev.a.ID)
	mustNoErr(t, "tenant", err)
	k := branding.KindFavicon32
	isDefault := func(what string, img branding.Image) {
		t.Helper()
		if img.ETag != defaultFavicon(t, k).ETag {
			t.Fatalf("%s: not the default icon", what)
		}
	}

	// File present once the lock is held: returned as it is.
	mustNoErr(t, "put", ev.assets.Put(ev.a.ID, k, []byte("icon")))
	img, ok := ev.svc.backfillFavicons(ctx, ev.a.ID, k)
	if !ok || string(img.Data) != "icon" {
		t.Fatalf("present file: %v %q", ok, img.Data)
	}
	delete(ev.assets.data, assetKey(ev.a.ID, k))

	// The logo file is missing: default icon, silently.
	delete(ev.assets.data, assetKey(ev.a.ID, branding.KindLogo))
	got, err := ev.svc.Asset(ctx, tn, k.String())
	mustNoErr(t, "no logo", err)
	isDefault("no logo file", got)
	if ev.logs.Len() != 0 {
		t.Fatalf("missing logo logged: %s", ev.logs.String())
	}
	mustNoErr(t, "restore logo", ev.assets.Put(ev.a.ID, branding.KindLogo, logo))

	// The logo cannot be read: default icon, logged.
	ev.assets.getErrAt = map[branding.Kind]error{branding.KindLogo: errBoom}
	got, err = ev.svc.Asset(ctx, tn, k.String())
	mustNoErr(t, "read error", err)
	isDefault("read error", got)
	ev.assets.getErrAt = nil
	if !strings.Contains(ev.logs.String(), "favicon backfill failed") {
		t.Fatalf("read error not logged: %s", ev.logs.String())
	}
	ev.logs.Reset()

	// The generation fails: default icon, logged, nothing stored.
	ev.svc.favicons = func(context.Context, []byte) (branding.Favicons, error) { return branding.Favicons{}, errBoom }
	got, err = ev.svc.Asset(ctx, tn, k.String())
	mustNoErr(t, "generation", err)
	isDefault("generation error", got)
	if !strings.Contains(ev.logs.String(), "favicon backfill failed") || ev.assets.has(ev.a.ID, k) {
		t.Fatalf("generation: %s", ev.logs.String())
	}
	ev.logs.Reset()
	ev.svc.favicons = branding.GenerateFavicons

	// The store fails: the generated icon is served anyway, logged.
	want, err := branding.GenerateFavicons(ctx, logo)
	mustNoErr(t, "generate", err)
	wantImg, _ := want.Get(k)
	ev.assets.putErr = errBoom
	got, err = ev.svc.Asset(ctx, tn, k.String())
	mustNoErr(t, "put error", err)
	if !bytes.Equal(got.Data, wantImg.Data) {
		t.Fatal("the generated icon is not served after a store failure")
	}
	if !strings.Contains(ev.logs.String(), "favicon backfill failed") || ev.assets.has(ev.a.ID, k) {
		t.Fatalf("put error: %s", ev.logs.String())
	}
	ev.assets.putErr = nil
}

func TestDeleteAssetAttemptsEveryFile(t *testing.T) {
	ctx := context.Background()
	ev := newEnv(t, storetest.SQLite(t))
	mustNoErr(t, "upload", ev.svc.UploadAsset(ctx, ev.adminA, ev.a.ID, "logo", bytes.NewReader(pngImage(t, 64, 32)), clientIP))
	ev.assets.delErrAt = map[branding.Kind]error{
		branding.KindLogo: errBoom, branding.KindAppleTouchIcon: errBoom,
	}
	err := ev.svc.DeleteAsset(ctx, ev.adminA, ev.a.ID, "logo", clientIP)
	wantErr(t, "partial", err, errBoom)
	if n := strings.Count(err.Error(), "tenantadmin: delete"); n != 2 {
		t.Fatalf("%d failures joined, want 2: %v", n, err)
	}
	// Every other file was still deleted.
	for _, k := range branding.FaviconKinds() {
		if k != branding.KindAppleTouchIcon && ev.assets.has(ev.a.ID, k) {
			t.Fatalf("%s not attempted", k)
		}
	}
	if n := len(ev.auditEvents(t, ev.a.ID, ActionTenantAssetDeleted)); n != 0 {
		t.Fatalf("%d delete events after a failure", n)
	}
}

// Concurrent uploads, deletions and public reads never race nor leave a
// logo without its favicons.
func TestAssetConcurrency(t *testing.T) {
	ctx := context.Background()
	ev := newEnv(t, storetest.SQLite(t))
	logo := pngImage(t, 32, 32)
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 5 {
				_ = ev.svc.UploadAsset(ctx, ev.adminA, ev.a.ID, "logo", bytes.NewReader(logo), clientIP)
				tn, err := ev.db.Tenants().Get(ctx, ev.a.ID)
				if err == nil {
					_, _ = ev.svc.Asset(ctx, tn, "favicon-32")
				}
				_ = ev.svc.DeleteAsset(ctx, ev.adminA, ev.a.ID, "logo", clientIP)
			}
		}()
	}
	wg.Wait()
}
