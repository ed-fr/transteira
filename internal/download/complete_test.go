package download

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/storage"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// complete downloads every file of p in full.
func (ev *env) complete(p published) {
	ev.t.Helper()
	for _, f := range p.files {
		if f.ScanStatus.Deliverable() {
			ev.fetch(p, "", f.ID, 0, -1, true)
		}
	}
}

func TestMailRetry(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		ev.queue.errs = []error{mail.ErrQueueFull, mail.ErrCircuitOpen, mail.ErrQueueFull, nil}
		p := ev.publish(ev.a, spec{contents: [][]byte{random(100)}})
		ev.complete(p)
		ev.waitUntil("first download mail", func() bool { return len(ev.firstDownloads()) == 1 })
		if n := ev.logs.count("will retry"); n != 3 {
			t.Fatalf("%d retries logged, want 3", n)
		}
	})
}

func TestMailRefused(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, func(o *Options) { o.MailRetryFor = time.Millisecond })
		// Past the retry deadline at once.
		ev.queue.errs = []error{mail.ErrQueueFull}
		ev.complete(ev.publish(ev.a, spec{contents: [][]byte{random(100)}}))
		if ev.logs.count("kept refusing") != 1 || len(ev.firstDownloads()) != 0 {
			t.Fatal("mail not dropped at the deadline")
		}
		// Any other refusal drops the mail.
		ev.queue.errs = []error{mail.ErrQueueClosed}
		ev.complete(ev.publish(ev.a, spec{contents: [][]byte{random(100)}}))
		if ev.logs.count("notification mail refused") != 1 {
			t.Fatal("refusal not logged")
		}
		// No SMTP settings.
		ev.complete(ev.publish(ev.c, spec{contents: [][]byte{random(100)}}))
		if ev.logs.count("no SMTP settings") != 1 {
			t.Fatal("missing SMTP not logged")
		}
		// The mail cannot be built.
		ev.f.set("firstDownload", 1, nil)
		ev.complete(ev.publish(ev.a, spec{contents: [][]byte{random(100)}}))
		if ev.logs.count("mail not built") != 1 || len(ev.firstDownloads()) != 0 {
			t.Fatal("build failure not logged")
		}
	})
}

func TestMailRetryClosed(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, func(o *Options) { o.RetryMin, o.RetryMax = time.Hour, time.Hour; o.MailRetryFor = 2 * time.Hour })
		ev.queue.errs = []error{mail.ErrQueueFull}
		ev.complete(ev.publish(ev.a, spec{contents: [][]byte{random(100)}}))
		if ev.logs.count("will retry") != 1 {
			t.Fatal("no retry scheduled")
		}
		ctx, cancel := context.WithTimeout(context.Background(), waitFor)
		defer cancel()
		if err := ev.svc.Close(ctx); err != nil {
			t.Fatal(err)
		}
		if err := ev.svc.Close(ctx); err != nil {
			t.Fatal(err)
		}
		if ev.logs.count("dropped at shutdown") != 1 {
			t.Fatal("pending retry not dropped")
		}
		// After Close, a refused mail is dropped at once; downloads work.
		ev.queue.errs = []error{mail.ErrQueueFull}
		ev.complete(ev.publish(ev.a, spec{contents: [][]byte{random(100)}}))
		if ev.logs.count("dropped at shutdown") != 2 {
			t.Fatal("refused mail not dropped after Close")
		}
	})
}

func TestNewDefaults(t *testing.T) {
	s := New(Deps{}, Options{Grace: -time.Second})
	o := s.opts
	if o.Grace != 0 || o.CommitTimeout != DefaultCommitTimeout || o.Now == nil || o.Logger == nil || s.flushBytes != flushBytes {
		t.Fatalf("options %+v", o)
	}
}

func TestDeleteAt(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, func(o *Options) { o.Grace = 0 })
		p := ev.publish(ev.a, spec{contents: [][]byte{random(100)}, deleteAfter: true})
		ev.complete(p)
		q := ev.publish(ev.a, spec{contents: [][]byte{random(100)}})
		ev.complete(q)
		now := ev.clock.now()
		if d := ev.get(p); !d.DeleteAfter.Equal(now) || len(ev.firstDownloads()) != 2 {
			t.Fatalf("delete after %v", d.DeleteAfter)
		}
		ev.notifier.mu.Lock()
		defer ev.notifier.mu.Unlock()
		if !slices.EqualFunc(ev.notifier.deleteAts, []time.Time{now, {}}, time.Time.Equal) {
			t.Fatalf("deletion times %v", ev.notifier.deleteAts)
		}
	})
}

// stateOnDisk returns the served ranges of the file fileID of p written to
// disk.
func (ev *env) stateOnDisk(p published, fileID string) []span {
	ev.t.Helper()
	return ev.state(p)[fileID]
}

func TestCoalescedWrites(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		ev.svc.flushBytes = 10_000
		a, b := random(30_000), random(4_000)
		p := ev.publish(ev.a, spec{contents: [][]byte{a, b}})
		fa, fb := p.files[0].ID, p.files[1].ID
		// Small ranges stay in memory.
		ev.fetch(p, "", fa, 0, 4_000, true)
		ev.fetch(p, "", fa, 4_000, 4_000, true)
		if ev.state(p) != nil || ev.f.called("writeState") != 0 {
			t.Fatal("small ranges written")
		}
		// Reaching the threshold writes everything kept so far.
		ev.fetch(p, "", fa, 8_000, 3_000, true)
		if got := ev.stateOnDisk(p, fa); !slices.Equal(got, []span{{0, 11_000}}) || ev.f.called("writeState") != 1 {
			t.Fatalf("on disk %v", got)
		}
		// A completed file is written at once, even when small.
		ev.fetch(p, "", fb, 0, -1, true)
		if got := ev.stateOnDisk(p, fb); !slices.Equal(got, []span{{0, 4_000}}) {
			t.Fatalf("completed file not written: %v", got)
		}
		// Close writes what is kept in memory.
		ev.fetch(p, "", fa, 20_000, 100, true)
		if got := ev.stateOnDisk(p, fa); !slices.Equal(got, []span{{0, 11_000}}) {
			t.Fatalf("on disk %v", got)
		}
		if err := ev.svc.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		if got := ev.stateOnDisk(p, fa); !slices.Equal(got, []span{{0, 11_000}, {20_000, 20_100}}) {
			t.Fatalf("not flushed at Close: %v", got)
		}
		// The transfer completes from memory and disk together.
		ev.fetch(p, "", fa, 11_000, 9_000, true)
		ev.fetch(p, "", fa, 20_100, -1, true)
		if ev.get(p).FirstDownloadedAt.IsZero() || ev.state(p) != nil || len(ev.svc.pending) != 0 {
			t.Fatal("not completed")
		}
	})
}

func TestCoalescedBounds(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		ev.svc.flushBytes = 1 << 30
		p := ev.publish(ev.a, spec{contents: [][]byte{random(maxPendingSpans*4 + 100)}})
		fid := p.files[0].ID
		// Too many spans in memory: written.
		f, err := ev.svc.OpenFile(context.Background(), ev.a, p.token, ipOne, Cookies{}, fid)
		if err != nil {
			t.Fatal(err)
		}
		_ = f.Content.Close(context.Background())
		st := served{fid: nil}
		for i := range int64(maxPendingSpans) {
			st[fid] = append(st[fid], span{i * 4, i*4 + 1})
		}
		k := key{tid: ev.a.ID, id: p.id}
		ev.svc.keep(k, st, 1)
		ev.fetch(p, "", fid, maxPendingSpans*4+2, 1, true)
		if n := len(ev.state(p)[fid]); n != maxPendingSpans+1 {
			t.Fatalf("%d spans written", n)
		}
	})
}

// fillPending keeps n states of transfers that do not exist in tenant tn,
// touched now.
func (ev *env) fillPending(tn *tenant.Tenant, n int) {
	for range n {
		ev.svc.keep(key{tid: tn.ID, id: id.New(id.Transfer)}, served{}, 1)
	}
}

func TestCoalescedEviction(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		ev.svc.flushBytes = 1 << 30
		old := ev.publish(ev.a, spec{contents: [][]byte{random(100)}})
		kOld := key{tid: ev.a.ID, id: old.id}
		// The oldest state, then enough to fill the memory.
		ev.svc.keep(kOld, served{old.files[0].ID: {{0, 5}}}, 5)
		ev.clock.advance(time.Millisecond)
		ev.fillPending(ev.a, maxPendingTransfers-1)
		ev.clock.advance(time.Millisecond)
		// A new transfer is still coalesced; the oldest state is written
		// and evicted.
		q := ev.publish(ev.a, spec{contents: [][]byte{random(1000)}})
		ev.fetch(q, "", q.files[0].ID, 0, 10, true)
		if ev.state(q) != nil || ev.svc.pending[key{tid: ev.a.ID, id: q.id}] == nil {
			t.Fatal("new transfer not coalesced with a full memory")
		}
		if got := ev.stateOnDisk(old, old.files[0].ID); !slices.Equal(got, []span{{0, 5}}) {
			t.Fatalf("oldest state not written: %v", got)
		}
		if n := len(ev.svc.pending); n != maxPendingTransfers {
			t.Fatalf("%d states kept", n)
		}
		// Once idle, every state is written; the one just kept stays.
		ev.clock.advance(idleFlush)
		r := ev.publish(ev.a, spec{contents: [][]byte{random(1000)}})
		ev.fetch(r, "", r.files[0].ID, 0, 10, true)
		if got := ev.stateOnDisk(q, q.files[0].ID); !slices.Equal(got, []span{{0, 10}}) {
			t.Fatalf("idle state not written: %v", got)
		}
		if len(ev.svc.pending) != 1 || ev.svc.pending[key{tid: ev.a.ID, id: r.id}] == nil || ev.state(r) != nil {
			t.Fatalf("%d states kept", len(ev.svc.pending))
		}
		// Idle states are looked for at most every tidyInterval.
		ev.clock.advance(idleFlush)
		ev.svc.tidied = ev.clock.now()
		ev.fetch(r, "", r.files[0].ID, 100, 10, true)
		if ev.state(r) != nil {
			t.Fatal("idle state written before tidyInterval")
		}
		// A state replaced meanwhile is not written by a stale request.
		kR := key{tid: ev.a.ID, id: r.id}
		ev.svc.flushPending(context.Background(), kR, &pendingState{}, true)
		if ev.state(r) != nil || ev.svc.pending[kR] == nil {
			t.Fatal("replaced state flushed")
		}
	})
}

func TestCoalescedFailures(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		p := ev.publish(ev.a, spec{contents: [][]byte{random(1000)}})
		fid := p.files[0].ID
		k := key{tid: ev.a.ID, id: p.id}
		// A state that cannot be written stays in memory...
		ev.f.set("writeState", 1, nil)
		ev.fetch(p, "", fid, 0, 100, true)
		if ev.state(p) != nil || ev.svc.pending[k] == nil || ev.logs.count("served ranges not recorded") != 1 {
			t.Fatal("unwritten state not kept")
		}
		// ...as does one whose transfer cannot be read...
		ev.f.set("transfer", 1, nil)
		ev.fetch(p, "", fid, 200, 100, true)
		if ev.state(p) != nil || ev.svc.pending[k] == nil || ev.logs.count("transfer unreadable") != 1 {
			t.Fatal("state of an unreadable transfer not kept")
		}
		// ...and the next write records every range.
		ev.fetch(p, "", fid, 400, 100, true)
		if got := ev.stateOnDisk(p, fid); !slices.Equal(got, []span{{0, 100}, {200, 300}, {400, 500}}) || ev.svc.pending[k] != nil {
			t.Fatalf("on disk %v", got)
		}
		// A state that cannot be encoded is dropped.
		big := served{}
		for range 3000 {
			big[id.New(id.File)] = nil
		}
		if !ev.svc.write(context.Background(), k, big, 1) || ev.svc.pending[k] != nil {
			t.Fatal("unencodable state kept")
		}

		// Over the bound, a state that cannot be written is dropped.
		ev.svc.flushBytes = 1 << 30
		ev.svc.keep(k, served{fid: {{600, 700}}}, 100)
		ev.clock.advance(time.Millisecond)
		ev.fillPending(ev.a, maxPendingTransfers-1)
		ev.clock.advance(time.Millisecond)
		ev.f.set("writeState", -1, nil)
		q := ev.publish(ev.a, spec{contents: [][]byte{random(1000)}})
		ev.fetch(q, "", q.files[0].ID, 0, 10, true)
		ev.f.set("writeState", 0, nil)
		if ev.svc.pending[k] != nil || ev.logs.count("too many states kept") != 1 || len(ev.svc.pending) != maxPendingTransfers {
			t.Fatal("unwritable state over the bound not dropped")
		}
		// An idle state that cannot be written stays for a later attempt.
		ev.svc.pending = map[key]*pendingState{}
		ev.svc.keep(k, served{fid: {{600, 700}}}, 100)
		ev.clock.advance(idleFlush)
		ev.f.set("writeState", 1, nil)
		ev.fetch(q, "", q.files[0].ID, 100, 10, true)
		if ev.svc.pending[k] == nil {
			t.Fatal("idle unwritable state dropped")
		}
	})
}

func TestFlushAllDeadline(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		ev.fillPending(ev.a, 3)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		ev.svc.flushAll(ctx)
		if ev.logs.count("WARN served ranges not written at shutdown states=3") != 1 || ev.logs.count("ERROR") != 0 {
			t.Fatalf("logs: %s", ev.logs.all())
		}
		ev.svc.pending = map[key]*pendingState{}
	})
}

func TestWriteAfterDeletion(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		ctx := context.Background()
		p := ev.publish(ev.a, spec{contents: [][]byte{random(5000)}})
		fid := p.files[0].ID
		f, err := ev.svc.OpenFile(ctx, ev.a, p.token, ipOne, Cookies{}, fid)
		if err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 1000)
		_, _ = f.Content.Read(buf)
		f.Content.Delivered()
		// Deleted by the sweeper while the response streams: the late range
		// is not written back.
		ev.setStatus(p, store.TransferDeleted)
		_ = f.Content.Close(ctx)
		if ev.state(p) != nil {
			t.Fatal("state resurrected after the deletion")
		}
		// The transfer cannot be read: nothing written, the failure logged.
		q := ev.publish(ev.a, spec{contents: [][]byte{random(5000)}})
		ev.f.set("transfer", 1, nil)
		ev.fetch(q, "", q.files[0].ID, 0, 100, true)
		if ev.state(q) != nil || ev.logs.count("transfer unreadable") != 1 {
			t.Fatal("unreadable transfer not handled")
		}
		// An unknown transfer (deleted row) is skipped silently.
		ev.svc.write(ctx, key{tid: ev.a.ID, id: "trf_01JAAAAAAAAAAAAAAAAAAAAAAA"}, served{}, 0)
		if ev.logs.count("transfer unreadable") != 1 {
			t.Fatal("unknown transfer logged")
		}
		// Already downloaded: not written.
		r := ev.publish(ev.a, spec{contents: [][]byte{random(10)}})
		ev.complete(r)
		ev.svc.write(ctx, key{tid: ev.a.ID, id: r.id}, served{r.files[0].ID: {{0, 5}}}, 5)
		if _, err := ev.files.ReadState(ev.a.ID, storage.StateName(r.id)); err == nil {
			t.Fatal("state written for a downloaded transfer")
		}
		// Close flushes nothing for a state forgotten meanwhile.
		k := key{tid: ev.a.ID, id: r.id}
		ev.svc.keep(k, served{r.files[0].ID: {{0, 5}}}, 1)
		release := ev.svc.lock(k)
		done := make(chan struct{})
		go func() {
			ev.svc.flushAll(ctx)
			close(done)
		}()
		ev.waitUntil("flush waiting for the lock", func() bool {
			ev.svc.mu.Lock()
			defer ev.svc.mu.Unlock()
			return ev.svc.locks[k].refs == 2
		})
		ev.svc.forget(k)
		release()
		<-done
	})
}
