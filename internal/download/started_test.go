package download

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// fakeUsage records the usage counters.
type fakeUsage struct {
	mu      sync.Mutex
	started map[tenant.ID]int
	bytes   map[tenant.ID]int64
	// invalid is set by a count at a zero time or of no byte.
	invalid bool
}

func (u *fakeUsage) DownloadStarted(tid tenant.ID, at time.Time) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.started == nil {
		u.started = map[tenant.ID]int{}
	}
	u.started[tid]++
	u.invalid = u.invalid || at.IsZero()
}

func (u *fakeUsage) BytesServed(tid tenant.ID, n int64, at time.Time) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.bytes == nil {
		u.bytes = map[tenant.ID]int64{}
	}
	u.bytes[tid] += n
	u.invalid = u.invalid || at.IsZero() || n <= 0
}

// counts returns the download starts and bytes served of tid.
func (u *fakeUsage) counts(tid tenant.ID) (int, int64) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.started[tid], u.bytes[tid]
}

// downloadEvents returns the transfer.downloaded events of tenant tid.
func (ev *env) downloadEvents(tid tenant.ID) []store.AuditEvent {
	ev.t.Helper()
	page, err := ev.db.AuditEvents().List(context.Background(), store.AuditFilter{
		TenantID: tid, Action: string(audit.ActionTransferDownloaded), Limit: store.MaxPageSize,
	})
	if err != nil {
		ev.t.Fatal(err)
	}
	return page.Items
}

// open opens the file fileID of p, without reading it.
func (ev *env) open(p published, fileID string) *File {
	ev.t.Helper()
	f, err := ev.svc.OpenFile(context.Background(), p.tn, p.token, ipOne, "", fileID)
	if err != nil {
		ev.t.Fatalf("OpenFile: %v", err)
	}
	return f
}

// wantStarts checks the download count of p, its audit events and the
// usage counters of its tenant.
func (ev *env) wantStarts(p published, n int, served int64) {
	ev.t.Helper()
	if got := ev.get(p).DownloadCount; got != int64(n) {
		ev.t.Errorf("download count %d, want %d", got, n)
	}
	if got := len(ev.downloadEvents(p.tn.ID)); got != n {
		ev.t.Errorf("%d transfer.downloaded events, want %d", got, n)
	}
	gotStarts, gotServed := ev.usage.counts(p.tn.ID)
	if gotStarts != n || gotServed != served {
		ev.t.Errorf("usage: %d starts, %d bytes; want %d, %d", gotStarts, gotServed, n, served)
	}
}

func TestDownloadStarts(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		ctx := context.Background()
		content := random(5000)
		p := ev.publish(ev.a, spec{contents: [][]byte{content, {}}})
		full, empty := p.files[0].ID, p.files[1].ID

		// A whole file from offset 0: one start.
		if got := ev.fetch(p, "", full, 0, -1, true); !bytes.Equal(got, content) {
			t.Fatal("content differs")
		}
		ev.wantStarts(p, 1, 5000)
		// A resumed range: no start, but its bytes are served.
		ev.fetch(p, "", full, 1000, -1, true)
		ev.wantStarts(p, 1, 9000)
		// A range from offset 0 within the window: no new start.
		ev.fetch(p, "", full, 0, 100, true)
		ev.wantStarts(p, 1, 9100)
		// After the window: a start.
		ev.clock.advance(DefaultStartWindow)
		ev.fetch(p, "", full, 0, 100, true)
		ev.wantStarts(p, 2, 9200)
		// A HEAD request: opened and closed, never read nor delivered.
		f := ev.open(p, full)
		if err := f.Content.Close(ctx); err != nil {
			t.Fatal(err)
		}
		ev.wantStarts(p, 2, 9200)
		// Reading from 0 again after seeking back counts once only.
		ev.clock.advance(DefaultStartWindow)
		f = ev.open(p, full)
		buf := make([]byte, 10)
		_, _ = f.Content.Read(buf)
		_, _ = f.Content.Seek(0, io.SeekStart)
		_, _ = f.Content.Read(buf)
		f.Content.Delivered()
		_ = f.Content.Close(ctx)
		ev.wantStarts(p, 3, 9210)
		// An empty file: a start once delivered, none for HEAD.
		f = ev.open(p, empty)
		_ = f.Content.Close(ctx)
		ev.wantStarts(p, 3, 9210)
		f = ev.open(p, empty)
		f.Content.Delivered()
		f.Content.Delivered()
		_ = f.Content.Close(ctx)
		ev.wantStarts(p, 4, 9210)
		// An archive prepared but not written (HEAD): no start.
		a, err := ev.svc.PrepareArchive(ctx, ev.a, p.token, ipTwo, "")
		if err != nil {
			t.Fatal(err)
		}
		a.Close()
		ev.wantStarts(p, 4, 9210)
		// An archive written: one start, the plaintext bytes served.
		a, err = ev.svc.PrepareArchive(ctx, ev.a, p.token, ipTwo, "")
		if err != nil {
			t.Fatal(err)
		}
		if err := a.Write(ctx, io.Discard); err != nil {
			t.Fatal(err)
		}
		ev.wantStarts(p, 5, 14210)

		events := ev.downloadEvents(ev.a.ID)
		var objects []string
		ips := map[netip.Addr]int{}
		for _, e := range events {
			var details map[string]string
			if err := json.Unmarshal(e.Details, &details); err != nil {
				t.Fatal(err)
			}
			objects = append(objects, details["file"])
			ips[e.IP]++
			if e.ActorKind != store.ActorRecipient || e.Actor != "link" || e.ObjectKind != audit.ObjectTransfer ||
				e.ObjectID != p.id || len(details) != 1 {
				t.Errorf("event %+v", e)
			}
		}
		want := []string{archiveObject, empty, full, full, full}
		slices.Sort(objects)
		slices.Sort(want)
		if !slices.Equal(objects, want) {
			t.Errorf("objects %v, want %v", objects, want)
		}
		if ips[ipOne] != 4 || ips[ipTwo] != 1 {
			t.Errorf("event IPs %v", ips)
		}
		// Another tenant sees nothing.
		if got := ev.downloadEvents(ev.b.ID); len(got) != 0 {
			t.Errorf("tenant B sees %d events", len(got))
		}
		if ev.usage.invalid {
			t.Error("usage counted at a zero time or with no byte")
		}
	})
}

// TestDownloadStartEventGuard checks that the audit events of the download
// starts pass the checks of the audit package (no secret, no address).
func TestDownloadStartEventGuard(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		p := ev.publish(ev.a, spec{contents: [][]byte{random(10)}})
		w := audit.New(ev.db)
		for _, object := range []string{p.files[0].ID, archiveObject} {
			if err := w.RecordScoped(context.Background(), ev.a.ID, startEvent(p.id, object, ipOne)); err != nil {
				t.Errorf("%s: %v", object, err)
			}
		}
	})
}

// TestDownloadStartNotRecorded checks that a failed recording of the start
// is logged and never stops the download, and that the recording is
// atomic.
func TestDownloadStartNotRecorded(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		ctx := context.Background()
		content := random(3000)
		p := ev.publish(ev.a, spec{contents: [][]byte{content}})
		ev.f.set("started", -1, nil)
		if got := ev.fetch(p, "", p.files[0].ID, 0, -1, true); !bytes.Equal(got, content) {
			t.Fatal("content differs")
		}
		a, err := ev.svc.PrepareArchive(ctx, ev.a, p.token, ipOne, "")
		if err != nil {
			t.Fatal(err)
		}
		if err := a.Write(ctx, io.Discard); err != nil {
			t.Fatal(err)
		}
		if n := ev.logs.count("download start not recorded"); n != 2 {
			t.Errorf("%d failure logs, want 2", n)
		}
		if got := ev.get(p).DownloadCount; got != 0 {
			t.Errorf("download count %d", got)
		}
		if got := len(ev.downloadEvents(ev.a.ID)); got != 0 {
			t.Errorf("%d events", got)
		}
		if started, served := ev.usage.counts(ev.a.ID); started != 2 || served != 6000 {
			t.Errorf("usage %d, %d", started, served)
		}
		// The count failing (unknown transfer) rolls the audit event back.
		inner := ev.svc.repo.(faultRepo).inner
		unknown := id.New(id.Transfer)
		if err := inner.started(ctx, ev.a.ID, unknown, startEvent(unknown, archiveObject, ipOne)); err == nil {
			t.Fatal("started for an unknown transfer")
		}
		if got := len(ev.downloadEvents(ev.a.ID)); got != 0 {
			t.Errorf("%d events after a failed count", got)
		}
		// An event refused by the store, or by the audit guard, records no
		// count.
		bad := startEvent(p.id, archiveObject, ipOne)
		bad.Actor = ""
		if err := inner.started(ctx, ev.a.ID, p.id, bad); err == nil {
			t.Fatal("started with an invalid event")
		}
		personal := startEvent(p.id, "someone@example.com", ipOne)
		if err := inner.started(ctx, ev.a.ID, p.id, personal); !errors.Is(err, audit.ErrPersonalDetail) {
			t.Fatalf("started with an address = %v, want ErrPersonalDetail", err)
		}
		if got := ev.get(p).DownloadCount; got != 0 {
			t.Errorf("download count %d after a refused event", got)
		}
	})
}

// TestArchiveBytesServedOnFailure checks that a broken archive counts only
// bytes written before the failure.
func TestArchiveBytesServedOnFailure(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		ctx := context.Background()
		p := ev.publish(ev.a, spec{contents: [][]byte{random(100_000), random(100_000)}})
		a, err := ev.svc.PrepareArchive(ctx, ev.a, p.token, ipOne, "")
		if err != nil {
			t.Fatal(err)
		}
		if err := a.Write(ctx, &failWriter{n: 150_000}); err == nil {
			t.Fatal("write succeeded")
		}
		started, served := ev.usage.counts(ev.a.ID)
		if started != 1 || served <= 0 || served > 150_000 {
			t.Errorf("usage %d starts, %d bytes", started, served)
		}
	})
}

// TestNoUsage checks that a service built without Usage counts nothing and
// does not fail.
func TestNoUsage(*testing.T) {
	s := New(Deps{}, Options{})
	s.usage.DownloadStarted("ten_x", time.Now())
	s.usage.BytesServed("ten_x", 1, time.Now())
	s.bytesServed("ten_x", 0)
}

// TestDownloadStartFlood checks that a client looping on a range from
// offset 0 records one start per object per window, while the bytes
// served stay exact, and that another client, another object or the end
// of the window counts again.
func TestDownloadStartFlood(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		ctx := context.Background()
		p := ev.publish(ev.a, spec{contents: [][]byte{random(1000), random(10)}})
		fetchFrom := func(ip netip.Addr, fileID string) {
			t.Helper()
			f, err := ev.svc.OpenFile(ctx, p.tn, p.token, ip, "", fileID)
			if err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 1)
			if _, err := f.Content.Read(buf); err != nil {
				t.Fatal(err)
			}
			f.Content.Delivered()
			if err := f.Content.Close(ctx); err != nil {
				t.Fatal(err)
			}
		}
		for range 50 {
			fetchFrom(ipOne, p.files[0].ID)
		}
		ev.wantStarts(p, 1, 50)
		// The same /64 is the same client.
		fetchFrom(netip.MustParseAddr("2001:db8:1:2::1"), p.files[0].ID)
		fetchFrom(netip.MustParseAddr("2001:db8:1:2::ffff"), p.files[0].ID)
		ev.wantStarts(p, 2, 52)
		// Another client, another object.
		fetchFrom(ipTwo, p.files[0].ID)
		fetchFrom(ipOne, p.files[1].ID)
		ev.wantStarts(p, 4, 54)
		// The archive is an object of its own, deduplicated as well.
		for range 3 {
			a, err := ev.svc.PrepareArchive(ctx, ev.a, p.token, ipOne, "")
			if err != nil {
				t.Fatal(err)
			}
			if err := a.Write(ctx, io.Discard); err != nil {
				t.Fatal(err)
			}
		}
		ev.wantStarts(p, 5, 54+3*1010)
		// Within the window, still once; after it, again.
		ev.clock.advance(DefaultStartWindow - time.Millisecond)
		fetchFrom(ipOne, p.files[0].ID)
		ev.wantStarts(p, 5, 55+3*1010)
		ev.clock.advance(time.Millisecond)
		fetchFrom(ipOne, p.files[0].ID)
		ev.wantStarts(p, 6, 56+3*1010)
		// Another tenant never shares the entries (the key holds the
		// tenant).
		if got := ev.downloadEvents(ev.b.ID); len(got) != 0 {
			t.Errorf("tenant B sees %d events", len(got))
		}
	})
}

// TestDownloadStartKeyCycling checks that a client cycling more /64 keys
// than the deduplication holds (an IPv6 /48) records at most
// Options.MaxStartsPerTransfer starts of a transfer per window, while the
// bytes served stay exact, and that another transfer or a new window
// counts again.
func TestDownloadStartKeyCycling(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, func(o *Options) { o.MaxStarts = 20; o.MaxStartsPerTransfer = 5 })
		ctx := context.Background()
		p := ev.publish(ev.a, spec{contents: [][]byte{random(100)}})
		q := ev.publish(ev.b, spec{contents: [][]byte{random(100)}})
		fetchFrom := func(p published, i int) {
			t.Helper()
			ip := netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 1, byte(i >> 8), byte(i), 15: 1})
			f, err := ev.svc.OpenFile(ctx, p.tn, p.token, ip, "", p.files[0].ID)
			if err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 1)
			if _, err := f.Content.Read(buf); err != nil {
				t.Fatal(err)
			}
			f.Content.Delivered()
			if err := f.Content.Close(ctx); err != nil {
				t.Fatal(err)
			}
		}
		for i := range 100 {
			fetchFrom(p, i)
		}
		ev.wantStarts(p, 5, 100)
		// Another transfer is counted apart.
		fetchFrom(q, 0)
		ev.wantStarts(q, 1, 1)
		// A new window: the cap applies again.
		ev.clock.advance(DefaultStartWindow)
		for i := range 10 {
			fetchFrom(p, i)
		}
		ev.wantStarts(p, 10, 110)
	})
}

// TestStartDedupOptions checks the defaults and the tuning of the
// deduplication.
func TestStartDedupOptions(t *testing.T) {
	s := New(Deps{}, Options{})
	if s.starts.window != DefaultStartWindow || s.starts.max != DefaultMaxStarts ||
		s.starts.perTransfer != DefaultMaxStartsPerTransfer {
		t.Errorf("defaults %v, %d, %d", s.starts.window, s.starts.max, s.starts.perTransfer)
	}
	s = New(Deps{}, Options{StartWindow: time.Minute, MaxStarts: 7, MaxStartsPerTransfer: 3})
	if s.starts.window != time.Minute || s.starts.max != 7 || s.starts.perTransfer != 3 {
		t.Errorf("tuned %v, %d, %d", s.starts.window, s.starts.max, s.starts.perTransfer)
	}
}

// TestStartDedupPerTransfer checks the per-transfer cap: cycling keys
// beyond the entries held records at most the cap per window, other
// transfers are counted apart, the counts are bounded (oldest window
// evicted first) and a clock going back opens a new window.
func TestStartDedupPerTransfer(t *testing.T) {
	t0 := time.Date(2026, 10, 22, 9, 0, 0, 0, time.UTC)
	key := func(trf string, i int) startKey {
		return newStartKey("ten_a", trf, "archive", netip.AddrFrom4([4]byte{192, 0, byte(i >> 8), byte(i)}))
	}
	d := newStartDedup(time.Hour, 10, 4)
	recorded := 0
	for i := range 1000 {
		if d.first(key("trf_x", i), t0.Add(time.Duration(i)*time.Millisecond)) {
			recorded++
		}
	}
	if recorded != 4 {
		t.Fatalf("recorded %d starts of trf_x, want 4", recorded)
	}
	if !d.first(key("trf_y", 0), t0.Add(2*time.Second)) {
		t.Fatal("trf_y not counted apart")
	}
	// After the window, the transfer counts again.
	if !d.first(key("trf_x", 999), t0.Add(time.Hour+time.Second)) {
		t.Fatal("trf_x not counted after its window")
	}
	// A clock going back opens a new window, even for a count that is not
	// the oldest.
	d = newStartDedup(time.Hour, 10, 1)
	d.first(key("trf_a", 0), t0.Add(5*time.Second))
	d.first(key("trf_b", 0), t0.Add(20*time.Second))
	if !d.first(key("trf_b", 1), t0.Add(15*time.Second)) {
		t.Fatal("trf_b not counted after the clock went back")
	}
	if d.first(key("trf_a", 1), t0.Add(15*time.Second)) {
		t.Fatal("trf_a count within its window reset")
	}

	// Bounded counts: the oldest window is evicted first.
	d = newStartDedup(time.Hour, 2, 1)
	d.first(key("trf_a", 0), t0)
	d.first(key("trf_b", 0), t0.Add(time.Second))
	if d.first(key("trf_a", 1), t0.Add(2*time.Second)) {
		t.Fatal("trf_a over its cap recorded")
	}
	d.first(key("trf_c", 0), t0.Add(3*time.Second))
	if len(d.transfers) != 2 {
		t.Fatalf("transfer counts = %d, want 2", len(d.transfers))
	}
	if !d.first(key("trf_a", 2), t0.Add(4*time.Second)) {
		t.Fatal("evicted trf_a count not reset")
	}
	if d.first(key("trf_c", 1), t0.Add(5*time.Second)) {
		t.Fatal("recent trf_c count evicted")
	}
}

// TestStartDedup checks the window, the eviction of the oldest entry when
// full and a clock going back.
func TestStartDedup(t *testing.T) {
	t0 := time.Date(2026, 10, 22, 9, 0, 0, 0, time.UTC)
	d := newStartDedup(time.Hour, 3, 100)
	key := func(i int) startKey {
		return newStartKey("ten_a", "trf_x", fmt.Sprint("fil_", i), netip.MustParseAddr("192.0.2.1"))
	}
	for i := range 3 {
		if !d.first(key(i), t0.Add(time.Duration(i)*time.Second)) {
			t.Fatalf("key %d not first", i)
		}
	}
	if d.first(key(0), t0.Add(10*time.Second)) || d.len() != 3 {
		t.Fatal("key 0 recorded twice within the window")
	}
	// Full: a new key evicts the oldest, which then counts again.
	if !d.first(key(3), t0.Add(11*time.Second)) || d.len() != 3 {
		t.Fatalf("key 3 not first, len %d", d.len())
	}
	if !d.first(key(0), t0.Add(12*time.Second)) {
		t.Fatal("evicted key 0 not first")
	}
	if d.first(key(2), t0.Add(13*time.Second)) || d.first(key(3), t0.Add(13*time.Second)) {
		t.Fatal("recent keys evicted instead of the oldest")
	}
	// After the window, every entry expires.
	if !d.first(key(4), t0.Add(2*time.Hour)) || d.len() != 1 {
		t.Fatalf("entries not expired, len %d", d.len())
	}
	// A clock going back expires the entries recorded after it, even when
	// they are not the oldest.
	d = newStartDedup(time.Hour, 10, 100)
	d.first(key(0), t0.Add(10*time.Second))
	d.first(key(1), t0.Add(5*time.Second))
	d.first(key(2), t0.Add(20*time.Second))
	if !d.first(key(2), t0.Add(15*time.Second)) {
		t.Fatal("entry recorded after now not expired")
	}
	if d.first(key(1), t0.Add(15*time.Second)) {
		t.Fatal("entry within the window expired")
	}
	// The IPv6 /64 is the client.
	a := newStartKey("ten_a", "trf_x", "archive", netip.MustParseAddr("2001:db8::1"))
	b := newStartKey("ten_a", "trf_x", "archive", netip.MustParseAddr("2001:db8::2"))
	c := newStartKey("ten_b", "trf_x", "archive", netip.MustParseAddr("2001:db8::2"))
	if a != b || a == c {
		t.Errorf("keys %v %v %v", a, b, c)
	}
}
