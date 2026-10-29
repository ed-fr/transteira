package download

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// openAs opens the file fileID of p for the client ip, without reading it.
func (ev *env) openAs(p published, ip netip.Addr, fileID string) *File {
	ev.t.Helper()
	f, err := ev.svc.OpenFile(context.Background(), p.tn, p.token, ip, Cookies{}, fileID)
	if err != nil {
		ev.t.Fatalf("OpenFile: %v", err)
	}
	return f
}

// beginAs opens the file fileID of p for the client ip, begins a GET
// (get) or a HEAD response, closes the content and returns the decision.
func (ev *env) beginAs(p published, ip netip.Addr, fileID string, get bool) error {
	ev.t.Helper()
	f := ev.openAs(p, ip, fileID)
	defer func() { _ = f.Content.Close(context.Background()) }()
	return f.Content.Begin(get)
}

// wantLimited checks the download count of p, its audit events and the
// usage download starts of its tenant.
func (ev *env) wantLimited(p published, n int) {
	ev.t.Helper()
	if got := ev.get(p).DownloadCount; got != int64(n) {
		ev.t.Errorf("download count %d, want %d", got, n)
	}
	if got := len(ev.downloadEvents(p.tn.ID)); got != n {
		ev.t.Errorf("%d transfer.downloaded events, want %d", got, n)
	}
	if got, _ := ev.usage.counts(p.tn.ID); got != n {
		ev.t.Errorf("usage: %d starts, want %d", got, n)
	}
}

// TestMaxDownloads walks a transfer limited to one download start: the
// start reaching the limit schedules the deletion, new starts are
// refused, the counted client keeps resuming during the grace period, and
// the sweep then picks the transfer.
func TestMaxDownloads(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		ctx := context.Background()
		content := random(5000)
		p := ev.publish(ev.a, spec{contents: [][]byte{content, random(10)}, maxDownloads: 1})
		file, other := p.files[0].ID, p.files[1].ID

		v, err := ev.svc.Resolve(ctx, ev.a, p.token, Cookies{})
		if err != nil || v.DownloadsRemaining == nil || *v.DownloadsRemaining != 1 || v.Confidentiality != nil {
			t.Fatalf("page before any start: %+v, %v", v, err)
		}
		// A HEAD request is no start.
		if err := ev.beginAs(p, ipTwo, file, false); err != nil {
			t.Fatalf("HEAD: %v", err)
		}
		ev.wantLimited(p, 0)

		// The first start: counted before the first byte, deletion scheduled.
		start := ev.clock.now()
		if got := ev.fetch(p, "", file, 0, -1, true); !bytes.Equal(got, content) {
			t.Fatal("content differs")
		}
		ev.wantLimited(p, 1)
		d := ev.get(p)
		if !d.DeleteAfter.Equal(start.Add(grace)) || d.Status != store.TransferAvailable {
			t.Errorf("after the last start: delete after %v (want %v), status %s", d.DeleteAfter, start.Add(grace), d.Status)
		}
		ev.clock.advance(time.Minute)

		// The page, the unlock and the starts of other clients are refused.
		_, err = ev.svc.Resolve(ctx, ev.a, p.token, Cookies{})
		wantErr(t, err, ErrMaxDownloads)
		_, err = ev.svc.Unlock(ctx, ev.a, p.token, ipOne, password, Cookies{})
		wantErr(t, err, ErrMaxDownloads)
		wantErr(t, ev.beginAs(p, ipTwo, file, true), ErrMaxDownloads)
		wantErr(t, ev.beginAs(p, ipTwo, file, false), ErrMaxDownloads)
		// Another object is another start, even for the counted client.
		wantErr(t, ev.beginAs(p, ipOne, other, true), ErrMaxDownloads)
		// A read without Begin begins as a GET, and fails closed.
		f := ev.openAs(p, ipThree, file)
		if n, err := f.Content.Read(make([]byte, 10)); n != 0 || !errors.Is(err, ErrMaxDownloads) {
			t.Errorf("read of a refused start: %d, %v", n, err)
		}
		if n, err := f.Content.Read(make([]byte, 10)); n != 0 || !errors.Is(err, ErrMaxDownloads) {
			t.Errorf("second read of a refused start: %d, %v", n, err)
		}
		wantErr(t, f.Content.Begin(true), ErrMaxDownloads) // decided once
		_ = f.Content.Close(ctx)
		// The archive of another client: refused, nothing written.
		a, err := ev.svc.PrepareArchive(ctx, ev.a, p.token, ipTwo, Cookies{})
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		if err := a.Write(ctx, &buf); !errors.Is(err, ErrMaxDownloads) || buf.Len() != 0 {
			t.Errorf("refused archive: %v, %d bytes", err, buf.Len())
		}
		ev.wantLimited(p, 1)

		// The counted client resumes, or starts again within the window,
		// during the grace period: served, not counted.
		if got := ev.fetch(p, "", file, 1000, -1, true); !bytes.Equal(got, content[1000:]) {
			t.Error("resumed range differs")
		}
		if got := ev.fetch(p, "", file, 0, -1, true); !bytes.Equal(got, content) {
			t.Error("restart differs")
		}
		ev.wantLimited(p, 1)

		// Past the grace period: gone, and due for deletion.
		ev.clock.advance(grace)
		_, err = ev.svc.OpenFile(ctx, ev.a, p.token, ipOne, Cookies{}, file)
		wantErr(t, err, ErrGone)
		due, err := ev.db.Transfers().DueDeletions(ctx, ev.clock.now(), store.SweepPage{Limit: store.DeletionSweepLimit})
		if err != nil {
			t.Fatal(err)
		}
		if !slices.ContainsFunc(due, func(tt store.TenantTransfer) bool { return tt.TransferID == p.id && tt.TenantID == ev.a.ID }) {
			t.Errorf("transfer not due for deletion: %+v", due)
		}
		if ev.usage.invalid {
			t.Error("invalid usage count")
		}
	})
}

// TestMaxDownloadsConcurrent: concurrent starts never exceed the limit,
// through the service and straight on the store.
func TestMaxDownloadsConcurrent(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		ctx := context.Background()
		p := ev.publish(ev.a, spec{contents: [][]byte{random(100)}, maxDownloads: 2})
		ips := []netip.Addr{ipOne, ipTwo, ipThree, netip.MustParseAddr("198.51.100.99")}
		files := make([]*File, len(ips))
		for i, ip := range ips {
			files[i] = ev.openAs(p, ip, p.files[0].ID)
		}
		errs := make([]error, len(ips))
		var wg sync.WaitGroup
		for i := range files {
			wg.Go(func() { errs[i] = files[i].Content.Begin(true) })
		}
		wg.Wait()
		ok := 0
		for i, err := range errs {
			switch {
			case err == nil:
				ok++
			case !errors.Is(err, ErrMaxDownloads):
				t.Errorf("start %d: %v", i, err)
			}
			_ = files[i].Content.Close(ctx)
		}
		if ok != 2 {
			t.Errorf("%d starts allowed, want 2", ok)
		}
		ev.wantLimited(p, 2)

		// Straight on the store, without the in-process lock.
		q := ev.publish(ev.b, spec{contents: [][]byte{random(10)}, maxDownloads: 3})
		const n = 8
		var (
			mu      sync.Mutex
			claimed []int
			refused int
		)
		for i := range n {
			wg.Go(func() {
				left, err := ev.svc.repo.claim(ctx, ev.b.ID, q.id, "", "", ev.clock.now(), ev.clock.now().Add(grace), startEvent(q.id, "", archiveObject, ipOne))
				mu.Lock()
				defer mu.Unlock()
				switch {
				case err == nil:
					claimed = append(claimed, left)
				case errors.Is(err, store.ErrMaxDownloads):
					refused++
				default:
					t.Errorf("claim %d: %v", i, err)
				}
			})
		}
		wg.Wait()
		slices.Sort(claimed)
		if fmt.Sprint(claimed) != "[0 1 2]" || refused != n-3 {
			t.Errorf("claims left %v, %d refused", claimed, refused)
		}
		if got := ev.get(q).DownloadCount; got != 3 {
			t.Errorf("download count %d, want 3", got)
		}
	})
}

// TestMaxDownloadsWindow: a counted client resumes within the window,
// which an interrupted response moves; a complete response does not, so
// that the client is counted again after the window.
func TestMaxDownloadsWindow(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		content := random(5000)
		p := ev.publish(ev.a, spec{contents: [][]byte{content}, maxDownloads: 3})
		file := p.files[0].ID

		ev.fetch(p, "", file, 0, 100, false) // interrupted start
		ev.wantLimited(p, 1)
		ev.clock.advance(DefaultStartWindow - time.Minute)
		ev.fetch(p, "", file, 100, 100, false) // resumed, interrupted again: the window moves
		ev.clock.advance(DefaultStartWindow - time.Minute)
		if got := ev.fetch(p, "", file, 200, -1, true); !bytes.Equal(got, content[200:]) { // resumed to the end
			t.Error("resumed range differs")
		}
		ev.wantLimited(p, 1)
		// The complete response did not move the window: counted again
		// once it is over, even for a resumed range.
		ev.clock.advance(time.Minute)
		ev.fetch(p, "", file, 4000, -1, true)
		ev.wantLimited(p, 2)
		// A HEAD request remembers nothing: another client is counted.
		if err := ev.beginAs(p, ipTwo, file, false); err != nil {
			t.Fatal(err)
		}
		if err := ev.beginAs(p, ipTwo, file, true); err != nil {
			t.Fatal(err)
		}
		ev.wantLimited(p, 3)
		if v, err := ev.svc.Resolve(context.Background(), ev.a, p.token, Cookies{}); !errors.Is(err, ErrMaxDownloads) {
			t.Errorf("page at the limit: %+v, %v", v, err)
		}
	})
}

// TestMaxDownloadsArchive: the archive is one start of its own object,
// counted once per client within the window, decided by Begin or, without
// it, by Write; a HEAD request is never counted.
func TestMaxDownloadsArchive(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		ctx := context.Background()
		p := ev.publish(ev.a, spec{contents: [][]byte{random(300), random(200)}, maxDownloads: 2})
		archive := func(ip netip.Addr, begin, get bool) error {
			t.Helper()
			a, err := ev.svc.PrepareArchive(ctx, ev.a, p.token, ip, Cookies{})
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			if begin {
				if err := a.Begin(ctx, get); err != nil || !get {
					return err
				}
				if err := a.Begin(ctx, get); err != nil { // decided once
					t.Errorf("second Begin: %v", err)
				}
			}
			return a.Write(ctx, io.Discard)
		}
		if err := archive(ipOne, true, false); err != nil {
			t.Fatalf("HEAD: %v", err)
		}
		ev.wantLimited(p, 0)
		if err := archive(ipOne, true, true); err != nil {
			t.Fatal(err)
		}
		if err := archive(ipOne, false, true); err != nil { // Write begins, the client is remembered
			t.Fatal(err)
		}
		ev.wantLimited(p, 1)
		if err := archive(ipTwo, false, true); err != nil {
			t.Fatal(err)
		}
		ev.wantLimited(p, 2)
		wantErr(t, archive(ipThree, true, true), ErrMaxDownloads)
		wantErr(t, archive(ipThree, true, false), ErrMaxDownloads)
		// The counted clients still get it during the grace period.
		if err := archive(ipTwo, true, true); err != nil {
			t.Fatal(err)
		}
		ev.wantLimited(p, 2)
		if d := ev.get(p); d.FirstDownloadedAt.IsZero() || d.DeleteAfter.IsZero() {
			t.Errorf("after complete archives: first download %v, delete after %v", d.FirstDownloadedAt, d.DeleteAfter)
		}
		// A HEAD of a remembered client is served; Write after a HEAD
		// writes nothing.
		a, err := ev.svc.PrepareArchive(ctx, ev.a, p.token, ipOne, Cookies{})
		if err != nil {
			t.Fatal(err)
		}
		if err := a.Begin(ctx, false); err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		if err := a.Write(ctx, &buf); !errors.Is(err, errNotBegun) || buf.Len() != 0 {
			t.Errorf("Write after HEAD: %v, %d bytes", err, buf.Len())
		}
	})
}

// TestMaxDownloadsFailures: a failure of the count refuses the start
// (fail closed); a transfer deleted meanwhile is gone, one no longer
// available is at its limit. A HEAD Content is never read.
func TestMaxDownloadsFailures(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		p := ev.publish(ev.a, spec{contents: [][]byte{random(100)}, maxDownloads: 5})
		file := p.files[0].ID

		ev.f.set("claim", 1, nil)
		err := ev.beginAs(p, ipOne, file, true)
		wantInternal(t, err)
		if errors.Is(err, ErrMaxDownloads) {
			t.Errorf("internal failure maps to the limit: %v", err)
		}
		ev.wantLimited(p, 0)
		ev.f.set("claim", 1, store.ErrNotFound)
		wantErr(t, ev.beginAs(p, ipOne, file, true), ErrGone)
		ev.f.set("claim", 1, store.ErrConflict) // no longer available
		wantErr(t, ev.beginAs(p, ipOne, file, true), ErrGone)
		ev.f.set("claim", 1, store.ErrMaxDownloads)
		wantErr(t, ev.beginAs(p, ipOne, file, true), ErrMaxDownloads)
		// A failure once the client is gone is not logged as an error.
		a, err := ev.svc.PrepareArchive(context.Background(), ev.a, p.token, ipOne, Cookies{})
		if err != nil {
			t.Fatal(err)
		}
		gone, cancel := context.WithCancel(context.Background())
		cancel()
		ev.f.set("claim", 1, nil)
		wantInternal(t, a.Begin(gone, true))
		a.Close()
		if e, d := ev.logs.count("ERROR download start not counted"), ev.logs.count("DEBUG download start not counted"); e != 1 || d != 1 {
			t.Errorf("logs: %d errors, %d debug", e, d)
		}
		// The failed starts remembered nothing.
		if err := ev.beginAs(p, ipOne, file, true); err != nil {
			t.Fatal(err)
		}
		ev.wantLimited(p, 1)

		f := ev.openAs(p, ipTwo, file)
		if err := f.Content.Begin(false); err != nil {
			t.Fatal(err)
		}
		if _, err := f.Content.Read(make([]byte, 10)); !errors.Is(err, errNotBegun) {
			t.Errorf("read after HEAD: %v", err)
		}
		_ = f.Content.Close(context.Background())
		ev.wantLimited(p, 1)
		if got := ev.downloadEvents(ev.a.ID); got[0].Action != string(audit.ActionTransferDownloaded) || got[0].ObjectID != p.id {
			t.Errorf("audit event %+v", got[0])
		}
	})
}

// TestUnlimitedBegin: without download limit, Begin decides nothing and
// the start is still recorded at the first read, as in version 1.0.
func TestUnlimitedBegin(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		ctx := context.Background()
		p := ev.publish(ev.a, spec{contents: [][]byte{random(100)}})
		f := ev.open(p, p.files[0].ID)
		if err := f.Content.Begin(true); err != nil {
			t.Fatal(err)
		}
		ev.wantStarts(p, 0, 0)
		if _, err := io.Copy(io.Discard, struct{ io.Reader }{f.Content}); err != nil {
			t.Fatal(err)
		}
		f.Content.Delivered()
		_ = f.Content.Close(ctx)
		ev.wantStarts(p, 1, 100)
		a, err := ev.svc.PrepareArchive(ctx, ev.a, p.token, ipTwo, Cookies{})
		if err != nil {
			t.Fatal(err)
		}
		if err := a.Begin(ctx, true); err != nil {
			t.Fatal(err)
		}
		ev.wantStarts(p, 1, 100)
		if err := a.Write(ctx, io.Discard); err != nil {
			t.Fatal(err)
		}
		ev.wantStarts(p, 2, 200)
		v, err := ev.svc.Resolve(ctx, ev.a, p.token, Cookies{})
		if err != nil || v.DownloadsRemaining != nil {
			t.Errorf("unlimited page: %+v, %v", v, err)
		}
	})
}

// TestResolveLimitAndLevel checks the downloads left and the
// confidentiality level of the page, locked or not.
func TestResolveLimitAndLevel(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		ctx := context.Background()
		p := ev.publish(ev.a, spec{contents: [][]byte{random(10)}, maxDownloads: 3, level: true, password: true})
		v, err := ev.svc.Resolve(ctx, ev.a, p.token, Cookies{})
		if err != nil {
			t.Fatal(err)
		}
		if !v.Locked || v.DownloadsRemaining != nil || v.Confidentiality != nil {
			t.Fatalf("locked page (no level): %+v", v)
		}
		cookie := ev.unlock(p, "")
		ev.fetch(p, cookie, p.files[0].ID, 0, -1, true)
		v, err = ev.svc.Resolve(ctx, ev.a, p.token, Cookies{Grant: cookie})
		if err != nil || v.Locked || v.DownloadsRemaining == nil || *v.DownloadsRemaining != 2 || v.Confidentiality == nil ||
			v.Confidentiality.Rules == nil || !v.Confidentiality.Rules.RequirePassword {
			t.Fatalf("unlocked page: %+v, %v", v, err)
		}
	})
}

func TestConfidentialityLabel(t *testing.T) {
	t.Parallel()
	c := Confidentiality{Labels: map[string]string{"fr": "Restreint", "en": "Confidential", "de": ""}}
	for _, tt := range []struct {
		langs []string
		want  string
	}{
		{[]string{"fr"}, "Restreint"},
		{[]string{"de", "en"}, "Confidential"},
		{[]string{"it"}, "Confidential"}, // lexically first with a label
		{nil, "Confidential"},
	} {
		if got := c.Label(tt.langs...); got != tt.want {
			t.Errorf("Label(%v) = %q, want %q", tt.langs, got, tt.want)
		}
	}
	if got := (Confidentiality{}).Label("en"); got != "" {
		t.Errorf("no label: %q", got)
	}
}

// TestStartDedupClaim: a claimed start is remembered for the window,
// moved by extend; claim replaces the entry and never counts the transfer.
func TestStartDedupClaim(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 28, 9, 0, 0, 0, time.UTC)
	d := newStartDedup(time.Hour, 2, 10)
	k1 := startKey{trf: "trf_1", object: "f", client: "a"}
	k2, k3 := k1, k1
	k2.client, k3.client = "b", "c"
	seen := func(k startKey, at time.Time) bool {
		t.Helper()
		_, ok := d.seen(k, at)
		return ok
	}
	if seen(k1, now) {
		t.Fatal("seen before claimed")
	}
	d.claim(k1, now)
	d.claim(k2, now.Add(time.Minute))
	if c, ok := d.seen(k1, now.Add(59*time.Minute)); !ok || !c.Equal(now) || seen(k1, now.Add(time.Hour)) {
		t.Error("window of a claimed start")
	}
	// Extended: its window moves, and it becomes the newest.
	d.extend(k1, now, now.Add(30*time.Minute))
	if !seen(k1, now.Add(89*time.Minute)) {
		t.Error("window not moved")
	}
	d.claim(k3, now.Add(31*time.Minute)) // full: k2, the oldest, is evicted
	if d.len() != 2 || seen(k2, now.Add(32*time.Minute)) || !seen(k1, now.Add(32*time.Minute)) {
		t.Errorf("eviction: %d entries", d.len())
	}
	// claim never counts the transfer: first still records.
	if !d.first(startKey{trf: "trf_1", object: "g", client: "a"}, now.Add(32*time.Minute)) {
		t.Error("first refused after claim")
	}
	// A claim replaces the entry: its claim time is the new one.
	d.claim(k1, now.Add(40*time.Minute))
	if c, _ := d.seen(k1, now.Add(41*time.Minute)); !c.Equal(now.Add(40 * time.Minute)) {
		t.Errorf("claim time after a new claim: %v", c)
	}
}

// TestStartDedupCeiling: extending the window of a claimed start never
// keeps it past its claim time plus startCeilingWindows windows, even
// re-remembered after it expired, and the later claim time holds.
func TestStartDedupCeiling(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 28, 9, 0, 0, 0, time.UTC)
	d := newStartDedup(time.Hour, 10, 10)
	k := startKey{trf: "trf_1", object: "f", client: "a"}
	ceiling := now.Add(startCeilingWindows * time.Hour)
	d.claim(k, now)
	for i := 1; i <= 4; i++ { // an interruption every 59 minutes
		d.extend(k, now, now.Add(time.Duration(i)*59*time.Minute))
	}
	if _, ok := d.seen(k, ceiling.Add(-time.Second)); !ok {
		t.Error("forgotten before the ceiling")
	}
	if _, ok := d.seen(k, ceiling); ok {
		t.Error("remembered at the ceiling")
	}
	// Past the ceiling, extend forgets it.
	d.extend(k, now, ceiling)
	if d.len() != 0 {
		t.Errorf("%d entries past the ceiling", d.len())
	}
	// An expired or evicted start is remembered again by extend, with
	// its claim time.
	d.extend(k, now, now.Add(3*time.Hour))
	if c, ok := d.seen(k, now.Add(3*time.Hour+time.Minute)); !ok || !c.Equal(now) {
		t.Errorf("re-remembered: %v, %v", c, ok)
	}
	// A later claim remembered holds over an older one given.
	later := now.Add(3*time.Hour + 2*time.Minute)
	d.claim(k, later)
	d.extend(k, now, later.Add(time.Minute))
	if c, ok := d.seen(k, now.Add(4*time.Hour+2*time.Minute)); !ok || !c.Equal(later) {
		t.Errorf("later claim: %v, %v", c, ok)
	}
	// A remembered start past the ceiling counts as forgotten by first.
	d.claim(k, now)
	d.extend(k, now, now.Add(3*time.Hour+59*time.Minute))
	if !d.first(k, ceiling) {
		t.Error("first refused past the ceiling")
	}
}

// TestMaxDownloadsWindowCeiling: a range the client chose to end before
// the end of the file (a bytes=0-0 loop) never moves the window of its
// counted start; an interrupted response moves it, but never past the
// claim time plus startCeilingWindows windows.
func TestMaxDownloadsWindowCeiling(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		p := ev.publish(ev.a, spec{contents: [][]byte{random(5000)}, maxDownloads: 10})
		file := p.files[0].ID

		ev.fetch(p, "", file, 0, 1, true) // bytes=0-0, written to its end
		ev.wantLimited(p, 1)
		ev.clock.advance(DefaultStartWindow - time.Minute)
		ev.fetch(p, "", file, 0, 1, true) // within the window: not counted, not extended
		ev.wantLimited(p, 1)
		ev.clock.advance(time.Minute)
		ev.fetch(p, "", file, 0, 1, true) // the window of the claim is over
		ev.wantLimited(p, 2)

		// Interrupted every 59 minutes: the window moves, up to the ceiling.
		for range startCeilingWindows {
			ev.clock.advance(DefaultStartWindow - time.Minute)
			ev.fetch(p, "", file, 0, 1, false)
		}
		ev.wantLimited(p, 2)
		ev.clock.advance(startCeilingWindows * time.Minute) // the claim plus the ceiling
		ev.fetch(p, "", file, 0, 1, false)
		ev.wantLimited(p, 3)
	})
}
