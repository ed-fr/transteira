package download

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io"
	"net/netip"
	"sync"
	"testing"

	"github.com/ed-fr/transteira/internal/filename"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/zipstream"
)

// failWriter accepts n bytes, then fails.
type failWriter struct{ n int }

func (w *failWriter) Write(p []byte) (int, error) {
	if len(p) > w.n {
		k := w.n
		w.n = 0
		return k, errFault
	}
	w.n -= len(p)
	return len(p), nil
}

func TestArchive(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		ctx := context.Background()
		contents := [][]byte{random(20_000), random(10), {}, random(3000), random(70)}
		names := []string{"report.pdf", "../../etc/passwd", "empty.txt", "REPORT.PDF", "virus.exe"}
		p := ev.publish(ev.a, spec{
			contents: contents, names: names, deleteAfter: true,
			statuses: []store.ScanStatus{store.ScanClean, store.ScanNotScannedTooLarge, store.ScanClean, store.ScanNotScannedEncrypted, store.ScanInfected},
		})
		a, err := ev.svc.PrepareArchive(ctx, ev.a, p.token, ipOne, Cookies{})
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		if err := a.Write(ctx, &buf); err != nil {
			t.Fatal(err)
		}
		if int64(buf.Len()) != a.Size() {
			t.Fatalf("wrote %d bytes, announced %d", buf.Len(), a.Size())
		}
		zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
		if err != nil {
			t.Fatal(err)
		}
		seen := map[string]int{}
		var want []string
		for _, n := range names[:4] {
			want = append(want, filename.ArchiveName(n, seen))
		}
		if len(zr.File) != 4 {
			t.Fatalf("%d entries, want the 4 deliverable files", len(zr.File))
		}
		for i, zf := range zr.File {
			if zf.Name != want[i] || zf.Method != zip.Store {
				t.Errorf("entry %d: %q (method %d), want %q", i, zf.Name, zf.Method, want[i])
			}
			rc, err := zf.Open()
			if err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(rc)
			_ = rc.Close()
			if err != nil || !bytes.Equal(got, contents[i]) {
				t.Errorf("entry %d content differs (%v)", i, err)
			}
		}
		d := ev.get(p)
		if d.FirstDownloadedAt.IsZero() || !d.DeleteAfter.Equal(ev.clock.now().Add(grace)) || len(ev.firstDownloads()) != 1 {
			t.Fatalf("archive not counted: %v, %v", d.FirstDownloadedAt, d.DeleteAfter)
		}
		// A second complete archive is no new first download.
		buf.Reset()
		if err := a.Write(ctx, &buf); err != nil {
			t.Fatal(err)
		}
		if len(ev.firstDownloads()) != 1 {
			t.Fatal("second first download mail")
		}
	})
}

func TestArchivePartial(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		ctx := context.Background()
		p := ev.publish(ev.a, spec{contents: [][]byte{random(20_000), random(500)}})
		a, err := ev.svc.PrepareArchive(ctx, ev.a, p.token, ipOne, Cookies{})
		if err != nil {
			t.Fatal(err)
		}
		if err := a.Write(ctx, &failWriter{n: int(a.Size()) - 10}); err == nil {
			t.Fatal("partial write succeeded")
		}
		if !ev.get(p).FirstDownloadedAt.IsZero() || len(ev.firstDownloads()) != 0 {
			t.Fatal("partial archive counted")
		}
		for _, fault := range []string{"open", "openRead"} {
			ev.f.set(fault, 1, nil)
			if err := a.Write(ctx, io.Discard); err == nil {
				t.Fatalf("%s fault ignored", fault)
			}
		}
		// A stored file that does not decrypt.
		if err := ev.files.Remove(ev.a.ID, p.files[1].StorageName); err != nil {
			t.Fatal(err)
		}
		w, err := ev.files.Create(ev.a.ID, p.files[1].StorageName)
		if err != nil {
			t.Fatal(err)
		}
		_ = w.Close()
		if err := a.Write(ctx, io.Discard); err == nil {
			t.Fatal("corrupt file ignored")
		}
		if !ev.get(p).FirstDownloadedAt.IsZero() {
			t.Fatal("failed archive counted")
		}
		// The size computation fails.
		saved := archiveSize
		archiveSize = func([]zipstream.Entry) (int64, error) { return 0, zipstream.ErrTooLarge }
		defer func() { archiveSize = saved }()
		_, err = ev.svc.PrepareArchive(ctx, ev.a, p.token, ipOne, Cookies{})
		wantInternal(t, err)
	})
}

func TestFirstDownloadOnce(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		ctx := context.Background()
		content := random(8000)
		p := ev.publish(ev.a, spec{contents: [][]byte{content}, deleteAfter: true})
		const n = MaxStreamsPerTransfer / 2
		var wg sync.WaitGroup
		errs := make(chan error, 2*n)
		// Distinct clients: one client may hold only
		// MaxStreamsPerTransferClient streams of the transfer.
		for i := range n {
			wg.Go(func() {
				a, err := ev.svc.PrepareArchive(ctx, ev.a, p.token, netip.AddrFrom4([4]byte{198, 51, 100, byte(100 + i)}), Cookies{})
				if err == nil {
					err = a.Write(ctx, io.Discard)
				}
				errs <- err
			})
			wg.Go(func() {
				f, err := ev.svc.OpenFile(ctx, ev.a, p.token, netip.AddrFrom4([4]byte{198, 51, 100, byte(150 + i)}), Cookies{}, p.files[0].ID)
				if err != nil {
					errs <- err
					return
				}
				_, err = io.Copy(io.Discard, f.Content)
				f.Content.Delivered()
				errs <- errors.Join(err, f.Content.Close(ctx))
			})
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
		if got := len(ev.firstDownloads()); got != 1 {
			t.Fatalf("%d first download mails, want 1", got)
		}
		if ev.state(p) != nil {
			t.Fatal("range state left")
		}
	})
}
