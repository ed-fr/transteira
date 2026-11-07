package download

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"

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

// TestE2EMaxDownloadsOneStart: the browser builds the archive of an
// end-to-end encrypted transfer by fetching its files one after the other,
// so that the files of such a transfer are one object of the start
// deduplication: a client fetching them all counts one start, while
// another client is still refused at the limit. The audit event keeps the
// file ID.
func TestE2EMaxDownloadsOneStart(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		first, second := random(5000), random(70)
		p := ev.publish(ev.a, spec{contents: [][]byte{first, second}, e2e: true, maxDownloads: 1})
		start := ev.clock.now()
		if got := ev.fetch(p, "", p.files[0].ID, 0, -1, true); !bytes.Equal(got, first) {
			t.Fatal("first file differs")
		}
		// Due for deletion at the ceiling of the window, not after the
		// shorter grace period.
		if d := ev.get(p); !d.DeleteAfter.Equal(start.Add(startCeilingWindows * DefaultStartWindow)) {
			t.Errorf("delete after %v, want %v", d.DeleteAfter, start.Add(startCeilingWindows*DefaultStartWindow))
		}
		if got := ev.fetch(p, "", p.files[1].ID, 0, -1, true); !bytes.Equal(got, second) {
			t.Fatal("second file differs")
		}
		ev.wantLimited(p, 1)
		if evs := ev.downloadEvents(p.tn.ID); len(evs) != 1 || !strings.Contains(string(evs[0].Details), `"file":"`+p.files[0].ID+`"`) {
			t.Errorf("download events %+v, want one naming the first file", evs)
		}
		wantErr(t, ev.beginAs(p, ipTwo, p.files[1].ID, true), ErrMaxDownloads)
		ev.wantLimited(p, 1)
	})
}

// TestE2EMaxDownloadsLongFile: the window of the start of an end-to-end
// encrypted transfer moves at the end of a delivered file, so that the
// next file fetched for the browser archive after a long download is not
// counted again.
func TestE2EMaxDownloadsLongFile(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		ctx := context.Background()
		first, second := random(5000), random(70)
		p := ev.publish(ev.a, spec{contents: [][]byte{first, second}, e2e: true, maxDownloads: 1})
		f := ev.openAs(p, ipOne, p.files[0].ID)
		if err := f.Content.Begin(true); err != nil {
			t.Fatal(err)
		}
		ev.clock.advance(2 * time.Hour) // a long download, past the window
		if got, err := io.ReadAll(f.Content); err != nil || !bytes.Equal(got, first) {
			t.Fatalf("first file: %v", err)
		}
		f.Content.Delivered()
		_ = f.Content.Close(ctx)
		ev.clock.advance(time.Minute)
		if got := ev.fetch(p, "", p.files[1].ID, 0, -1, true); !bytes.Equal(got, second) {
			t.Fatal("second file differs")
		}
		ev.wantLimited(p, 1)
	})
}

// TestE2EUnlimitedAuditPerFile: without download limit, every file of an
// end-to-end encrypted transfer has its own start and audit event.
func TestE2EUnlimitedAuditPerFile(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		p := ev.publish(ev.a, spec{contents: [][]byte{random(50), random(70)}, e2e: true})
		for _, f := range p.files {
			ev.fetch(p, "", f.ID, 0, -1, true)
		}
		if evs := ev.downloadEvents(p.tn.ID); len(evs) != 2 {
			t.Errorf("%d transfer.downloaded events, want 2", len(evs))
		}
	})
}
