package usage_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/usage"
)

var testNow = time.Date(2026, 10, 22, 9, 0, 0, 0, time.UTC)

// openDB returns a migrated database on engine e.
func openDB(t *testing.T, e storetest.Engine) *store.DB {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, e.Config(), store.WithClock(func() time.Time { return testNow }))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return db
}

// newTenant creates a tenant in db.
func newTenant(t *testing.T, db *store.DB, fqdn string) tenant.ID {
	t.Helper()
	tn, err := db.Tenants().Create(context.Background(), &tenant.Tenant{
		Name: "Entity " + fqdn, FQDN: fqdn, DefaultLanguage: "en",
		MaxTransferBytes: 1 << 30, StorageQuotaBytes: 100 << 30,
	})
	if err != nil {
		t.Fatalf("Create(%s): %v", fqdn, err)
	}
	return tn.ID
}

// usageOf returns the daily counters of tid by day.
func usageOf(t *testing.T, db *store.DB, tid tenant.ID) map[time.Time]store.UsageCounts {
	t.Helper()
	days, err := db.TenantUsage().Range(context.Background(), tid, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Range: %v", err)
	}
	out := map[time.Time]store.UsageCounts{}
	for _, d := range days {
		out[d.Day.UTC()] = d.UsageCounts
	}
	return out
}

func TestRecordAndFlush(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		db := openDB(t, e)
		ta := newTenant(t, db, "transfer.entity-a.example.com")
		tb := newTenant(t, db, "transfer.entity-b.example.com")
		r := usage.New(db, usage.Options{Now: func() time.Time { return testNow }})

		day1 := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
		day2 := time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC)
		// The last nanosecond of day 1 and midnight of day 2, in another
		// time zone: days are UTC.
		paris := time.FixedZone("CEST", 2*3600)
		late := day2.Add(-time.Nanosecond).In(paris)
		midnight := day2.In(paris)

		r.TransferFinalized(ta, 100, late)
		r.TransferFinalized(ta, -5, late) // a negative size counts zero bytes
		r.DownloadStarted(ta, late)
		r.BytesServed(ta, 40, late)
		r.BytesServed(ta, 0, late)  // ignored
		r.BytesServed(ta, -1, late) // ignored
		r.VirusDetected(ta, midnight)
		r.TransferFinalized(ta, 7, time.Time{}) // now: day 2
		r.DownloadStarted(tb, midnight)
		r.BytesServed(tb, 9, midnight)
		r.VirusDetected("", midnight) // no tenant: ignored
		if got := r.Pending(); got != 3 {
			t.Fatalf("Pending = %d, want 3", got)
		}
		if err := r.Flush(ctx); err != nil {
			t.Fatalf("Flush = %v", err)
		}
		if got := r.Pending(); got != 0 {
			t.Errorf("Pending after flush = %d", got)
		}

		a := usageOf(t, db, ta)
		want1 := store.UsageCounts{Transfers: 2, BytesUploaded: 100, Downloads: 1, BytesDownloaded: 40}
		want2 := store.UsageCounts{Transfers: 1, BytesUploaded: 7, VirusDetections: 1}
		if len(a) != 2 || a[day1] != want1 || a[day2] != want2 {
			t.Errorf("tenant A usage = %+v, want %v: %+v, %v: %+v", a, day1, want1, day2, want2)
		}
		if b := usageOf(t, db, tb); len(b) != 1 || b[day2] != (store.UsageCounts{Downloads: 1, BytesDownloaded: 9}) {
			t.Errorf("tenant B usage = %+v", b)
		}

		// A second flush adds to the stored counters; an empty one is a no-op.
		r.DownloadStarted(tb, midnight)
		if err := r.Flush(ctx); err != nil {
			t.Fatalf("Flush = %v", err)
		}
		if err := r.Flush(ctx); err != nil {
			t.Fatalf("empty Flush = %v", err)
		}
		if b := usageOf(t, db, tb); b[day2].Downloads != 2 {
			t.Errorf("tenant B downloads = %d, want 2", b[day2].Downloads)
		}
	})
}

func TestDeletedTenant(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		db := openDB(t, e)
		ta := newTenant(t, db, "transfer.entity-a.example.com")
		gone := newTenant(t, db, "transfer.entity-gone.example.com")
		r := usage.New(db, usage.Options{})

		r.TransferFinalized(gone, 10, testNow)
		r.TransferFinalized(ta, 20, testNow)
		if err := db.Tenants().Delete(ctx, gone); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		if err := r.Flush(ctx); err != nil {
			t.Fatalf("Flush = %v, want the deleted tenant dropped", err)
		}
		if got := r.Pending(); got != 0 {
			t.Errorf("Pending = %d, want the deleted tenant's counters dropped", got)
		}
		if a := usageOf(t, db, ta); a[store.DayOf(testNow)].BytesUploaded != 20 {
			t.Errorf("tenant A usage = %+v", a)
		}
	})
}

func TestConcurrentRecording(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		db := openDB(t, e)
		ta := newTenant(t, db, "transfer.entity-a.example.com")
		tb := newTenant(t, db, "transfer.entity-b.example.com")
		r := usage.New(db, usage.Options{})

		const workers, events = 16, 200
		var wg sync.WaitGroup
		for w := range workers {
			tid := ta
			if w%2 == 1 {
				tid = tb
			}
			wg.Go(func() {
				for range events {
					r.TransferFinalized(tid, 3, testNow)
					r.DownloadStarted(tid, testNow)
					r.BytesServed(tid, 2, testNow)
					r.VirusDetected(tid, testNow)
				}
			})
		}
		// Flushes run concurrently with the recording.
		flushErr := make(chan error, 1)
		wg.Go(func() {
			var first error
			for range 5 {
				if err := r.Flush(ctx); err != nil && first == nil {
					first = err
				}
			}
			flushErr <- first
		})
		wg.Wait()
		if err := <-flushErr; err != nil {
			t.Fatalf("concurrent Flush = %v", err)
		}
		if err := r.Flush(ctx); err != nil {
			t.Fatalf("Flush = %v", err)
		}
		n := int64(workers / 2 * events)
		want := store.UsageCounts{Transfers: n, BytesUploaded: 3 * n, Downloads: n, BytesDownloaded: 2 * n, VirusDetections: n}
		for _, tid := range []tenant.ID{ta, tb} {
			if got := usageOf(t, db, tid)[store.DayOf(testNow)]; got != want {
				t.Errorf("usage of %s = %+v, want %+v", tid, got, want)
			}
		}
	})
}

func TestStartClose(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		db := openDB(t, e)
		ta := newTenant(t, db, "transfer.entity-a.example.com")
		r := usage.New(db, usage.Options{Interval: 5 * time.Millisecond})
		if err := r.Start(ctx); err != nil {
			t.Fatalf("Start = %v", err)
		}
		if err := r.Start(ctx); !errors.Is(err, usage.ErrStarted) {
			t.Errorf("second Start = %v, want ErrStarted", err)
		}
		day := store.DayOf(testNow)

		// The periodic flush stores the counters.
		r.TransferFinalized(ta, 1, testNow)
		deadline := time.Now().Add(10 * time.Second)
		for usageOf(t, db, ta)[day].Transfers != 1 {
			if time.Now().After(deadline) {
				t.Fatal("periodic flush did not store the counters")
			}
			time.Sleep(5 * time.Millisecond)
		}

		// Close makes a final flush.
		r.DownloadStarted(ta, testNow)
		if err := r.Close(ctx); err != nil {
			t.Fatalf("Close = %v", err)
		}
		if got := usageOf(t, db, ta)[day]; got.Downloads != 1 {
			t.Errorf("usage after Close = %+v, want the final flush", got)
		}
		if err := r.Close(ctx); err != nil {
			t.Errorf("second Close = %v", err)
		}
		if err := r.Start(ctx); !errors.Is(err, usage.ErrClosed) {
			t.Errorf("Start after Close = %v, want ErrClosed", err)
		}
	})
}

func TestCloseWithoutStart(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		db := openDB(t, e)
		ta := newTenant(t, db, "transfer.entity-a.example.com")
		r := usage.New(db, usage.Options{})
		r.VirusDetected(ta, testNow)
		if err := r.Close(ctx); err != nil {
			t.Fatalf("Close = %v", err)
		}
		if got := usageOf(t, db, ta)[store.DayOf(testNow)]; got.VirusDetections != 1 {
			t.Errorf("usage after Close = %+v", got)
		}
	})
}

func TestNil(t *testing.T) {
	var r *usage.Recorder
	r.TransferFinalized("tnt_x", 1, testNow)
	r.DownloadStarted("tnt_x", testNow)
	r.BytesServed("tnt_x", 1, testNow)
	r.VirusDetected("tnt_x", testNow)
	if r.Pending() != 0 || r.Flush(context.Background()) != nil {
		t.Error("a nil recorder must hold nothing and flush without error")
	}
}
