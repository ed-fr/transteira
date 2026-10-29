package download

import (
	"context"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

func TestResolveView(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		ctx := context.Background()
		p := ev.publish(ev.a, spec{
			contents: [][]byte{random(10), random(20), random(30), random(40), random(50)},
			statuses: []store.ScanStatus{store.ScanClean, store.ScanInfected, store.ScanNotScannedTooLarge, store.ScanError, store.ScanNotScannedEncrypted},
		})
		v, err := ev.svc.Resolve(ctx, ev.a, p.token, Cookies{})
		if err != nil {
			t.Fatal(err)
		}
		d := ev.get(p)
		if v.TransferID != p.id || v.SenderEmail != alice || v.Message != "Here are the plans" || !v.ExpiresAt.Equal(d.ExpiresAt) ||
			v.PasswordProtected || v.Locked || v.DeleteAfterFirstDownload || !v.ArchiveAvailable || v.TotalBytes != 10+30+50 {
			t.Fatalf("view %+v", v)
		}
		if len(v.Files) != 3 {
			t.Fatalf("%d files, want the 3 deliverable ones", len(v.Files))
		}
		for i, want := range []int{0, 2, 4} {
			f, src := v.Files[i], p.files[want]
			if f.ID != src.ID || f.Name != src.Name || f.Size != src.Size || f.SHA256 != src.SHA256 ||
				f.MediaType != src.MediaType || f.ScanStatus != src.ScanStatus {
				t.Errorf("file %d: %+v, want %+v", i, f, src)
			}
		}
	})
}

func TestResolveLocked(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		ctx := context.Background()
		p := ev.publish(ev.a, spec{contents: [][]byte{random(10)}, password: true, deleteAfter: true})
		v, err := ev.svc.Resolve(ctx, ev.a, p.token, Cookies{})
		if err != nil {
			t.Fatal(err)
		}
		want := View{TransferID: p.id, SenderEmail: alice, ExpiresAt: ev.get(p).ExpiresAt, PasswordProtected: true, Locked: true}
		if v.TransferID != want.TransferID || v.SenderEmail != want.SenderEmail || !v.ExpiresAt.Equal(want.ExpiresAt) ||
			!v.PasswordProtected || !v.Locked || v.Message != "" || v.TotalBytes != 0 || v.Files != nil ||
			v.ArchiveAvailable || v.DeleteAfterFirstDownload {
			t.Fatalf("locked view %+v", v)
		}
		cookie := ev.unlock(p, "")
		v, err = ev.svc.Resolve(ctx, ev.a, p.token, Cookies{Grant: cookie})
		if err != nil {
			t.Fatal(err)
		}
		if v.Locked || !v.PasswordProtected || len(v.Files) != 1 || !v.DeleteAfterFirstDownload {
			t.Fatalf("unlocked view %+v", v)
		}
		// The grant key fails: internal error.
		ev.f.set("verifyMAC", 1, nil)
		_, err = ev.svc.Resolve(ctx, ev.a, p.token, Cookies{Grant: cookie})
		wantInternal(t, err)
	})
}

func TestResolveStates(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		ctx := context.Background()
		resolve := func(p published) error {
			_, err := ev.svc.Resolve(ctx, p.tn, p.token, Cookies{})
			return err
		}
		p := ev.publish(ev.a, spec{contents: [][]byte{random(10)}})

		t.Run("malformed token", func(t *testing.T) {
			for _, tok := range []string{"", "dl_short", "xx_" + p.token[3:], p.token + "!"} {
				_, err := ev.svc.Resolve(ctx, ev.a, tok, Cookies{})
				wantErr(t, err, ErrNotFound)
			}
		})
		t.Run("unknown token", func(t *testing.T) {
			tok, _ := id.NewDownloadToken()
			_, err := ev.svc.Resolve(ctx, ev.a, tok, Cookies{})
			wantErr(t, err, ErrNotFound)
		})
		t.Run("other tenant", func(t *testing.T) {
			_, err := ev.svc.Resolve(ctx, ev.b, p.token, Cookies{})
			wantErr(t, err, ErrNotFound)
			_, err = ev.svc.OpenFile(ctx, ev.b, p.token, ipOne, Cookies{}, p.files[0].ID)
			wantErr(t, err, ErrNotFound)
			_, err = ev.svc.PrepareArchive(ctx, ev.b, p.token, ipOne, Cookies{})
			wantErr(t, err, ErrNotFound)
			_, err = ev.svc.Unlock(ctx, ev.b, p.token, ipOne, password, Cookies{})
			wantErr(t, err, ErrNotFound)
		})
		t.Run("lookup failure", func(t *testing.T) {
			ev.f.set("byToken", 1, nil)
			wantInternal(t, resolve(p))
		})
		t.Run("deleted", func(t *testing.T) {
			q := ev.publish(ev.a, spec{contents: [][]byte{random(10)}})
			ev.setStatus(q, store.TransferDeleted)
			wantErr(t, resolve(q), ErrGone)
		})
		t.Run("expired status", func(t *testing.T) {
			q := ev.publish(ev.a, spec{contents: [][]byte{random(10)}})
			ev.setStatus(q, store.TransferExpired)
			wantErr(t, resolve(q), ErrGone)
		})
		t.Run("no deliverable file", func(t *testing.T) {
			q := ev.publish(ev.a, spec{contents: [][]byte{random(10)}, statuses: []store.ScanStatus{store.ScanError}})
			wantErr(t, resolve(q), ErrGone)
		})
		t.Run("expiry", func(t *testing.T) {
			q := ev.publish(ev.a, spec{contents: [][]byte{random(10)}})
			exp := ev.get(q).ExpiresAt
			ev.clock.advance(exp.Sub(ev.clock.now()) - time.Millisecond)
			if err := resolve(q); err != nil {
				t.Fatalf("just before expiry: %v", err)
			}
			ev.clock.advance(time.Millisecond)
			wantErr(t, resolve(q), ErrGone)
			_, err := ev.svc.OpenFile(context.Background(), q.tn, q.token, ipOne, Cookies{}, q.files[0].ID)
			wantErr(t, err, ErrGone)
		})
	})
}

func TestResolveDeleteAfter(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		ctx := context.Background()
		content := random(5000)
		p := ev.publish(ev.a, spec{contents: [][]byte{content}, deleteAfter: true})
		ev.fetch(p, "", p.files[0].ID, 0, -1, true)
		d := ev.get(p)
		if d.FirstDownloadedAt.IsZero() || !d.DeleteAfter.Equal(ev.clock.now().Add(grace)) {
			t.Fatalf("first download %v, delete after %v", d.FirstDownloadedAt, d.DeleteAfter)
		}
		// Within the grace period, an interrupted range can resume.
		ev.clock.advance(grace - time.Millisecond)
		if got := ev.fetch(p, "", p.files[0].ID, 4000, -1, true); string(got) != string(content[4000:]) {
			t.Fatal("resumed range differs")
		}
		ev.clock.advance(time.Millisecond)
		_, err := ev.svc.Resolve(ctx, ev.a, p.token, Cookies{})
		wantErr(t, err, ErrGone)
		_, err = ev.svc.PrepareArchive(ctx, ev.a, p.token, ipOne, Cookies{})
		wantErr(t, err, ErrGone)
		if n := len(ev.firstDownloads()); n != 1 {
			t.Fatalf("%d first download mails, want 1", n)
		}
	})
}
