package mytransfers

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

func TestNewRequiresDependencies(t *testing.T) {
	t.Parallel()
	ev := newEnv(t, storetest.SQLite(t))
	full := Deps{DB: ev.db, Keys: ev.keys, Notifier: ev.svc.notifier, Mail: ev.queue, SecurityLog: ev.svc.seclog, Eraser: ev.eraser}
	for name, edit := range map[string]func(*Deps){
		"db": func(d *Deps) { d.DB = nil }, "keys": func(d *Deps) { d.Keys = nil },
		"notifier": func(d *Deps) { d.Notifier = nil }, "mail": func(d *Deps) { d.Mail = nil },
		"security log": func(d *Deps) { d.SecurityLog = nil }, "eraser": func(d *Deps) { d.Eraser = nil },
	} {
		d := full
		edit(&d)
		if _, err := New(d, Options{}); !errors.Is(err, errMissingDependency) {
			t.Errorf("without %s: %v", name, err)
		}
	}
	s, err := New(full, Options{BusyRetries: -1})
	if err != nil {
		t.Fatal(err)
	}
	if s.busyRetries != 0 || s.busyDelay != DefaultBusyDelay || s.busyRetryAfter != DefaultBusyRetryAfter ||
		s.workers != DefaultWorkers || s.jobTimeout != DefaultJobTimeout || cap(s.jobs) != DefaultQueueSize || s.failures == nil {
		t.Errorf("defaults = %+v", s)
	}
	if s, _ := New(full, Options{}); s.busyRetries != DefaultBusyRetries {
		t.Errorf("busy retries = %d", s.busyRetries)
	}
	if s, _ := New(full, Options{BusyRetries: 2, BusyDelay: time.Second, BusyRetryAfter: time.Minute}); s.busyRetries != 2 ||
		s.busyDelay != time.Second || s.busyRetryAfter != time.Minute {
		t.Errorf("custom busy options = %d, %s, %s", s.busyRetries, s.busyDelay, s.busyRetryAfter)
	}
}

func TestWorkersLifecycle(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ev := newEnv(t, storetest.SQLite(t), func(o *Options) { o.Workers = 1 })
	ev.verify(ev.a, alice)
	if err := ev.svc.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := ev.svc.Start(ctx); !errors.Is(err, errStarted) {
		t.Errorf("second Start = %v", err)
	}
	if err := ev.svc.RequestLink(ctx, ev.a, clientIP, "", alice, ""); err != nil {
		t.Fatal(err)
	}
	// Close drains the queue.
	if err := ev.svc.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if ev.queue.count() != 1 {
		t.Errorf("%d mails after Close, want 1", ev.queue.count())
	}
	if err := ev.svc.Close(ctx); err != nil {
		t.Errorf("second Close = %v", err)
	}
	if err := ev.svc.Start(ctx); !errors.Is(err, errStarted) {
		t.Errorf("Start after Close = %v", err)
	}
	// A request racing with Close is dropped.
	ev.svc.submit(ctx, ev.a, linkJob{tenant: ev.a})
	wantErr(t, "after Close", ev.svc.RequestLink(ctx, ev.a, clientIP, "", alice, ""), ErrMailUnavailable)
}

func TestCloseNeverStarted(t *testing.T) {
	t.Parallel()
	ev := newEnv(t, storetest.SQLite(t))
	if err := ev.svc.Close(context.Background()); err != nil {
		t.Errorf("Close = %v", err)
	}
}

// blockingNotifier blocks every mail build until its context is done.
type blockingNotifier struct{ entered chan struct{} }

func (n blockingNotifier) MyTransfersLinkJob(ctx context.Context, _ *tenant.Tenant, _, _, _ string, _ time.Duration) (mail.Job, error) {
	close(n.entered)
	<-ctx.Done()
	return mail.Job{}, ctx.Err()
}

func TestCloseDeadline(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ev := newEnv(t, storetest.SQLite(t), func(o *Options) { o.Workers = 1 })
	ev.verify(ev.a, alice)
	n := blockingNotifier{entered: make(chan struct{})}
	ev.svc.notifier = n
	if err := ev.svc.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := ev.svc.RequestLink(ctx, ev.a, clientIP, "", alice, ""); err != nil {
		t.Fatal(err)
	}
	<-n.entered
	cctx, cancel := context.WithTimeout(ctx, 10*time.Millisecond)
	defer cancel()
	if err := ev.svc.Close(cctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Close = %v, want the deadline", err)
	}
}

func TestWorkerStopsOnCancel(t *testing.T) {
	t.Parallel()
	ev := newEnv(t, storetest.SQLite(t))
	if err := ev.svc.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	ev.svc.cancel()
	select {
	case <-ev.svc.done:
	case <-time.After(10 * time.Second):
		t.Fatal("the workers did not stop")
	}
	if err := ev.svc.Close(context.Background()); err != nil {
		t.Errorf("Close = %v", err)
	}
}
