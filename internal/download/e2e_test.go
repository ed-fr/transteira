package download

import (
	"bytes"
	"context"
	"testing"

	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

func TestE2EView(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		p := ev.publish(ev.a, spec{contents: [][]byte{random(60), random(100)}, e2e: true, e2eMessage: "c2VhbGVk"})
		v, err := ev.svc.Resolve(context.Background(), ev.a, p.token, Cookies{})
		if err != nil {
			t.Fatal(err)
		}
		if !v.E2E || v.Locked || v.ArchiveAvailable || v.Message != "" || v.EncryptedMessage != "c2VhbGVk" || v.TotalBytes != 160 {
			t.Fatalf("view %+v", v)
		}
		if len(v.Files) != 2 {
			t.Fatalf("%d files", len(v.Files))
		}
		for i, f := range v.Files {
			src := p.files[i]
			if f.ID != src.ID || f.Name != src.Name || f.EncryptedMetadata != src.E2EMetadata || f.EncryptedMetadata == "" ||
				f.ScanStatus != store.ScanNotScannedE2E || f.MediaType != "" || f.SHA256 != src.SHA256 {
				t.Errorf("file %d: %+v, want %+v", i, f, src)
			}
		}

		// An ordinary transfer has none of the end-to-end fields.
		q := ev.publish(ev.a, spec{contents: [][]byte{random(10)}})
		v, err = ev.svc.Resolve(context.Background(), ev.a, q.token, Cookies{})
		if err != nil {
			t.Fatal(err)
		}
		if v.E2E || v.EncryptedMessage != "" || !v.ArchiveAvailable || v.Files[0].EncryptedMetadata != "" {
			t.Fatalf("ordinary view %+v", v)
		}
	})
}

func TestE2ELockedView(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		ctx := context.Background()
		p := ev.publish(ev.a, spec{contents: [][]byte{random(60)}, e2e: true, e2eMessage: "c2VhbGVk", password: true})
		v, err := ev.svc.Resolve(ctx, ev.a, p.token, Cookies{})
		if err != nil {
			t.Fatal(err)
		}
		if !v.E2E || !v.Locked || v.EncryptedMessage != "" || v.Files != nil || v.ArchiveAvailable {
			t.Fatalf("locked view %+v", v)
		}
		cookie := ev.unlock(p, "")
		if v, err = ev.svc.Resolve(ctx, ev.a, p.token, Cookies{Grant: cookie}); err != nil || v.Locked || v.EncryptedMessage != "c2VhbGVk" {
			t.Fatalf("unlocked view %+v, %v", v, err)
		}

		// A link awaiting its recipient verification.
		q := ev.publish(ev.a, spec{contents: [][]byte{random(60)}, e2e: true, perRecipient: true, verify: true})
		v, err = ev.svc.Resolve(ctx, ev.a, q.token, Cookies{})
		if err != nil {
			t.Fatal(err)
		}
		if !v.E2E || !v.Locked || v.Files != nil || v.RecipientEmailMasked == "" {
			t.Fatalf("awaiting view %+v", v)
		}
	})
}

func TestE2EArchiveUnavailable(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		ctx := context.Background()
		p := ev.publish(ev.a, spec{contents: [][]byte{random(60)}, e2e: true})
		_, err := ev.svc.PrepareArchive(ctx, ev.a, p.token, ipOne, Cookies{})
		wantErr(t, err, ErrE2EArchiveUnavailable)

		// The gates come first: a browser that has not unlocked the
		// transfer gets the lock, not the 409.
		q := ev.publish(ev.a, spec{contents: [][]byte{random(60)}, e2e: true, password: true})
		_, err = ev.svc.PrepareArchive(ctx, ev.a, q.token, ipOne, Cookies{})
		wantErr(t, err, ErrDownloadLocked)
		cookie := ev.unlock(q, "")
		_, err = ev.svc.PrepareArchive(ctx, ev.a, q.token, ipOne, Cookies{Grant: cookie})
		wantErr(t, err, ErrE2EArchiveUnavailable)

		r := ev.publish(ev.a, spec{contents: [][]byte{random(60)}, e2e: true, perRecipient: true, verify: true})
		_, err = ev.svc.PrepareArchive(ctx, ev.a, r.token, ipOne, Cookies{})
		wantErr(t, err, ErrVerificationRequired)

		// No download start was recorded by the refusals.
		if d := ev.get(p); d.DownloadCount != 0 || !d.FirstDownloadedAt.IsZero() {
			t.Fatalf("download recorded: %+v", d.Transfer)
		}
	})
}

func TestE2EFileServedUnchanged(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		ciphertext := random(9000)
		p := ev.publish(ev.a, spec{contents: [][]byte{ciphertext}, e2e: true})
		if got := ev.fetch(p, "", p.files[0].ID, 0, -1, true); !bytes.Equal(got, ciphertext) {
			t.Fatal("served content differs from the stored ciphertext")
		}
		// Ranges are served as for any file.
		if got := ev.fetch(p, "", p.files[0].ID, 100, 50, false); !bytes.Equal(got, ciphertext[100:150]) {
			t.Fatal("range differs")
		}
		if d := ev.get(p); d.FirstDownloadedAt.IsZero() {
			t.Fatal("complete download of the only file not recorded")
		}
	})
}
