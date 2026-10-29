package download

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/storage"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

func TestOpenFileAccess(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		ctx := context.Background()
		p := ev.publish(ev.a, spec{
			contents: [][]byte{random(10), random(20)},
			statuses: []store.ScanStatus{store.ScanClean, store.ScanInfected},
			password: true,
		})
		q := ev.publish(ev.a, spec{contents: [][]byte{random(10)}})
		_, err := ev.svc.OpenFile(ctx, ev.a, p.token, ipOne, Cookies{}, p.files[0].ID)
		wantErr(t, err, ErrDownloadLocked)
		_, err = ev.svc.PrepareArchive(ctx, ev.a, p.token, ipOne, Cookies{})
		wantErr(t, err, ErrDownloadLocked)
		cookie := ev.unlock(p, "")
		for _, fid := range []string{p.files[1].ID, q.files[0].ID, id.New(id.File), ""} {
			_, err = ev.svc.OpenFile(ctx, ev.a, p.token, ipOne, Cookies{Grant: cookie}, fid)
			wantErr(t, err, ErrNotFound)
		}
		_, err = ev.svc.OpenFile(ctx, ev.a, "dl_x", ipOne, Cookies{Grant: cookie}, p.files[0].ID)
		wantErr(t, err, ErrNotFound)
		// The cookie of p does not unlock another protected transfer.
		r := ev.publish(ev.a, spec{contents: [][]byte{random(10)}, password: true})
		_, err = ev.svc.OpenFile(ctx, ev.a, r.token, ipOne, Cookies{Grant: cookie}, r.files[0].ID)
		wantErr(t, err, ErrDownloadLocked)
	})
}

func TestOpenFileContent(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		ctx := context.Background()
		content := random(50_000)
		p := ev.publish(ev.a, spec{contents: [][]byte{content, random(10)}})
		f, err := ev.svc.OpenFile(ctx, ev.a, p.token, ipOne, Cookies{}, p.files[0].ID)
		if err != nil {
			t.Fatal(err)
		}
		if f.ID != p.files[0].ID || f.Name != "file-0.bin" || f.Size != int64(len(content)) || f.SHA256 != p.files[0].SHA256 {
			t.Fatalf("file %+v", f)
		}
		// http.ServeContent answers a single range.
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Range", "bytes=1000-1999")
		rec := httptest.NewRecorder()
		http.ServeContent(rec, req, "", time.Time{}, f.Content)
		if rec.Code != http.StatusPartialContent || !bytes.Equal(rec.Body.Bytes(), content[1000:2000]) {
			t.Fatalf("status %d, %d bytes", rec.Code, rec.Body.Len())
		}
		f.Content.Delivered()
		if err := f.Content.Close(ctx); err != nil {
			t.Fatal(err)
		}
		if err := f.Content.Close(ctx); err != nil {
			t.Fatalf("second Close: %v", err)
		}
		if got := ev.state(p)[p.files[0].ID]; !slices.Equal(got, []span{{1000, 2000}}) {
			t.Fatalf("served %v", got)
		}
		// An unsatisfiable range gives 416 and records nothing more.
		f, err = ev.svc.OpenFile(ctx, ev.a, p.token, ipOne, Cookies{}, p.files[0].ID)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Range", "bytes=90000-")
		rec = httptest.NewRecorder()
		http.ServeContent(rec, req, "", time.Time{}, f.Content)
		if rec.Code != http.StatusRequestedRangeNotSatisfiable {
			t.Fatalf("status %d", rec.Code)
		}
		f.Content.Delivered()
		_ = f.Content.Close(ctx)
		if got := ev.state(p)[p.files[0].ID]; !slices.Equal(got, []span{{1000, 2000}}) {
			t.Fatalf("served %v", got)
		}
		// Seek errors leave the offset alone.
		f, err = ev.svc.OpenFile(ctx, ev.a, p.token, ipOne, Cookies{}, p.files[0].ID)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Content.Seek(-1, io.SeekStart); err == nil {
			t.Fatal("negative seek accepted")
		}
		all, err := io.ReadAll(f.Content)
		if err != nil || !bytes.Equal(all, content) {
			t.Fatalf("read %d bytes, %v", len(all), err)
		}
		// Closing the file twice fails; the error is reported.
		_ = f.Content.osf.Close()
		if err := f.Content.Close(ctx); err == nil {
			t.Fatal("close error lost")
		}
	})
}

func TestRangeUnion(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		a, b := random(30_000), random(7_000)
		p := ev.publish(ev.a, spec{contents: [][]byte{a, b, {}}})
		fa, fb, fe := p.files[0].ID, p.files[1].ID, p.files[2].ID
		if got := ev.fetch(p, "", fa, 0, 10_000, true); !bytes.Equal(got, a[:10_000]) {
			t.Fatal("first range differs")
		}
		if got := ev.fetch(p, "", fa, 20_000, -1, true); !bytes.Equal(got, a[20_000:]) {
			t.Fatal("second range differs")
		}
		if got := ev.state(p)[fa]; !slices.Equal(got, []span{{0, 10_000}, {20_000, 30_000}}) {
			t.Fatalf("served %v", got)
		}
		// A range served again changes nothing.
		ev.f.set("writeState", 1, nil)
		ev.fetch(p, "", fa, 2_000, 3_000, true)
		if ev.f.called("writeState") != 2 {
			t.Fatal("unchanged state written")
		}
		ev.f.set("writeState", 0, nil)
		// The whole of b and the empty file, but a still has a gap.
		ev.fetch(p, "", fb, 0, -1, true)
		ev.fetch(p, "", fe, 0, -1, true)
		if len(ev.firstDownloads()) != 0 || !ev.get(p).FirstDownloadedAt.IsZero() {
			t.Fatal("completed with a gap")
		}
		// A response not delivered does not credit its last read.
		ev.fetch(p, "", fa, 10_000, 1_000, false)
		if got := ev.state(p)[fa]; !slices.Equal(got, []span{{0, 10_000}, {20_000, 30_000}}) {
			t.Fatalf("undelivered read credited: %v", got)
		}
		// Reads followed by another read are credited.
		ev.fetch(p, "", fa, 10_000, 2_500, false)
		if got := ev.state(p)[fa]; !slices.Equal(got, []span{{0, 12_000}, {20_000, 30_000}}) {
			t.Fatalf("served %v", got)
		}
		// Opening without reading records nothing.
		f, err := ev.svc.OpenFile(context.Background(), ev.a, p.token, ipOne, Cookies{}, fa)
		if err != nil {
			t.Fatal(err)
		}
		_ = f.Content.Close(context.Background())
		ev.fetch(p, "", fa, 12_000, 8_000, true)
		d := ev.get(p)
		if d.FirstDownloadedAt.IsZero() || !d.FirstDownloadedAt.Equal(ev.clock.now()) || !d.DeleteAfter.IsZero() {
			t.Fatalf("first download %v, delete after %v", d.FirstDownloadedAt, d.DeleteAfter)
		}
		if ev.state(p) != nil {
			t.Fatal("range state kept after the first download")
		}
		jobs := ev.firstDownloads()
		if len(jobs) != 1 || jobs[0].TenantID != ev.a.ID.String() || jobs[0].Message.To[0] != alice {
			t.Fatalf("first download mails %+v", jobs)
		}
		ev.notifier.mu.Lock()
		deleteAts := slices.Clone(ev.notifier.deleteAts)
		ev.notifier.mu.Unlock()
		if len(deleteAts) != 1 || !deleteAts[0].IsZero() {
			t.Fatalf("deletion times %v", deleteAts)
		}
		// Later downloads change nothing.
		ev.fetch(p, "", fa, 0, -1, true)
		if ev.state(p) != nil || len(ev.firstDownloads()) != 1 {
			t.Fatal("a later download was tracked")
		}
	})
}

func TestContentSpanCap(t *testing.T) {
	c := &Content{}
	for i := range int64(maxContentSpans + 5) {
		c.pending = span{i * 10, i*10 + 1}
		c.credit()
	}
	if len(c.spans) != maxContentSpans {
		t.Fatalf("%d spans", len(c.spans))
	}
	c.pending = span{maxContentSpans*10 + 1000, maxContentSpans*10 + 1001}
	c.credit()
	c.pending = span{c.spans[len(c.spans)-1].end, c.spans[len(c.spans)-1].end + 5}
	c.credit()
	if len(c.spans) != maxContentSpans || c.spans[len(c.spans)-1].end-c.spans[len(c.spans)-1].start != 6 {
		t.Fatalf("adjacent read not merged: %v", c.spans[len(c.spans)-1])
	}
}

func TestOpenFileFailures(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		ctx := context.Background()
		p := ev.publish(ev.a, spec{contents: [][]byte{random(5000), random(10)}, sizes: map[int]int64{1: 11}})
		for _, fault := range []string{"open", "openRead"} {
			ev.f.set(fault, 1, nil)
			_, err := ev.svc.OpenFile(ctx, ev.a, p.token, ipOne, Cookies{}, p.files[0].ID)
			wantInternal(t, err)
		}
		// The recorded size differs from the stored file.
		_, err := ev.svc.OpenFile(ctx, ev.a, p.token, ipOne, Cookies{}, p.files[1].ID)
		wantInternal(t, err)
		// The stored file is corrupt.
		if err := ev.files.Remove(ev.a.ID, p.files[0].StorageName); err != nil {
			t.Fatal(err)
		}
		w, err := ev.files.Create(ev.a.ID, p.files[0].StorageName)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte("not an encrypted file at all"))
		_ = w.Close()
		_, err = ev.svc.OpenFile(ctx, ev.a, p.token, ipOne, Cookies{}, p.files[0].ID)
		wantInternal(t, err)
		if ev.logs.count("file not opened") != 4 {
			t.Fatalf("failures not logged:\n%s", ev.logs.all())
		}
	})
}

func TestCommitFailures(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		content := random(9000)
		p := ev.publish(ev.a, spec{contents: [][]byte{content}})
		fid := p.files[0].ID
		// Unreadable state: nothing is recorded, nothing overwritten.
		ev.f.set("readState", 1, nil)
		ev.fetch(p, "", fid, 0, 100, true)
		if ev.state(p) != nil || ev.logs.count("state unreadable") != 1 {
			t.Fatal("unreadable state not handled")
		}
		// Unwritable state.
		ev.f.set("writeState", 1, nil)
		ev.fetch(p, "", fid, 0, 100, true)
		if ev.state(p) != nil || ev.logs.count("served ranges not recorded") != 2 {
			t.Fatal("write failure not logged")
		}
		// The unwritten state stays in memory (see TestCoalescedFailures):
		// drop it to exercise the state on disk.
		ev.svc.forget(key{tid: ev.a.ID, id: p.id})
		// A corrupt state is replaced.
		if err := ev.files.WriteState(ev.a.ID, storage.StateName(p.id), []byte("junk")); err != nil {
			t.Fatal(err)
		}
		ev.fetch(p, "", fid, 0, 100, true)
		if got := ev.state(p)[fid]; !slices.Equal(got, []span{{0, 100}}) || ev.logs.count("corrupt served range state") != 1 {
			t.Fatalf("corrupt state not replaced: %v", got)
		}
		// The database fails at completion: the ranges are kept, and the
		// next request, even one that adds nothing, completes.
		ev.f.set("markFirst", 1, nil)
		ev.fetch(p, "", fid, 100, -1, true)
		if got := ev.state(p)[fid]; !slices.Equal(got, []span{{0, 9000}}) || !ev.get(p).FirstDownloadedAt.IsZero() {
			t.Fatalf("ranges lost after a database failure: %v", got)
		}
		ev.f.set("removeState", 1, nil)
		ev.fetch(p, "", fid, 0, 10, true)
		if ev.get(p).FirstDownloadedAt.IsZero() || len(ev.firstDownloads()) != 1 {
			t.Fatal("completion not retried")
		}
		if ev.logs.count("state not removed") != 1 || ev.state(p) == nil {
			t.Fatal("remove failure not logged")
		}
	})
}

func TestCompletionAfterDeletion(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		ctx := context.Background()
		content := random(3000)
		p := ev.publish(ev.a, spec{contents: [][]byte{content}})
		f, err := ev.svc.OpenFile(ctx, ev.a, p.token, ipOne, Cookies{}, p.files[0].ID)
		if err != nil {
			t.Fatal(err)
		}
		// Deleted while the response streams: it ends, nothing is recorded
		// in the database and no mail is sent.
		ev.setStatus(p, store.TransferDeleted)
		if all, err := io.ReadAll(f.Content); err != nil || !bytes.Equal(all, content) {
			t.Fatal(err)
		}
		f.Content.Delivered()
		_ = f.Content.Close(ctx)
		d := ev.get(p)
		if d.Status != store.TransferDeleted || !d.FirstDownloadedAt.IsZero() || len(ev.firstDownloads()) != 0 {
			t.Fatalf("deleted transfer recorded: %+v", d.Transfer)
		}
		if ev.logs.count("no longer available") != 1 || ev.state(p) != nil {
			t.Fatal("completion on a deleted transfer not handled")
		}
		_, err = ev.svc.OpenFile(ctx, ev.a, p.token, ipOne, Cookies{}, p.files[0].ID)
		wantErr(t, err, ErrGone)
	})
}
