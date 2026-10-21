package app

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/download"
	"github.com/ed-fr/transteira/internal/lifecycle"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/scan"
	"github.com/ed-fr/transteira/internal/tenant"
)

// blockingSender blocks every delivery until its context ends.
type blockingSender struct{ started chan struct{} }

func (b blockingSender) Send(ctx context.Context, _ mail.Settings, _ mail.Message) error {
	b.started <- struct{}{}
	<-ctx.Done()
	return ctx.Err()
}

func TestShutdownBudget(t *testing.T) {
	t.Parallel()
	const dockerGrace = 10 * time.Second
	if total := ShutdownTimeout + HandlerDrainTimeout + BackgroundCloseTimeout + MailDrainTimeout; total >= dockerGrace {
		t.Errorf("worst-case shutdown %v, want strictly below Docker's %v grace period", total, dockerGrace)
	}
	if ShutdownTimeout != 6*time.Second || BackgroundCloseTimeout != time.Second {
		t.Errorf("ShutdownTimeout = %v, BackgroundCloseTimeout = %v, want 6s and 1s", ShutdownTimeout, BackgroundCloseTimeout)
	}
}

func TestMailQueueOptions(t *testing.T) {
	t.Parallel()
	for size, want := range map[int]int{1000: 250, 3: 1, 1: 1} {
		o := mailQueueOptions(&config.Config{MailQueueSize: size})
		if o.TenantQueued != want || o.Workers != mail.DefaultWorkers || o.TenantConcurrency != mail.DefaultTenantConcurrency ||
			o.BreakerThreshold != mail.DefaultBreakerThreshold || o.BreakerCooldown != mail.DefaultBreakerCooldown ||
			o.RetryDelay != mail.DefaultRetryDelay {
			t.Errorf("size %d: options %+v, want defaults with TenantQueued %d", size, o, want)
		}
	}
	if newSMTPSender(&config.Config{}) == nil {
		t.Error("nil SMTP sender")
	}
}

func TestCloseMailQueue(t *testing.T) {
	t.Parallel()
	job := mail.Job{
		TenantID: "ten_a", Template: mail.TemplateVerificationCode,
		Settings: mail.Settings{Host: "relay.example.com", Port: 25, Security: mail.SecurityNone, FromAddress: "noreply@entity-a.example.com"},
		Message:  mail.Message{To: []string{"alice@entity-a.example.com"}, Subject: "Code", Text: "123456"},
	}

	t.Run("drained", func(t *testing.T) {
		t.Parallel()
		var logs bytes.Buffer
		q := mail.NewQueue(blockingSender{started: make(chan struct{}, 1)}, 1, nil, mail.QueueOptions{})
		closeMailQueue(t.Context(), q, slog.New(slog.NewTextHandler(&logs, nil)))
		if logs.Len() != 0 {
			t.Errorf("empty queue drain logged %q", logs.String())
		}
	})

	t.Run("cut short", func(t *testing.T) {
		t.Parallel()
		var logs bytes.Buffer
		sender := blockingSender{started: make(chan struct{}, 1)}
		q := mail.NewQueue(sender, 2, nil, mail.QueueOptions{})
		if err := q.Enqueue(job); err != nil {
			t.Fatal(err)
		}
		<-sender.started
		closeMailQueue(t.Context(), q, slog.New(slog.NewTextHandler(&logs, nil)))
		if !strings.Contains(logs.String(), "mail queue not drained") {
			t.Errorf("logs = %q, want the drain warning", logs.String())
		}
	})
}

func TestScanOptions(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{ScanWorkers: 3}
	if got := scanOptions(cfg, &runOptions{}, nil); got.Workers != 3 || got.RetryMin != 0 {
		t.Errorf("default scan options = %+v", got)
	}
	var o runOptions
	WithScanOptions(func(so *scan.Options) { so.RetryMin, so.RetryMax = time.Second, 2*time.Second })(&o)
	if got := scanOptions(cfg, &o, nil); got.Workers != 3 || got.RetryMin != time.Second || got.RetryMax != 2*time.Second {
		t.Errorf("edited scan options = %+v", got)
	}
}

// slowCloser never stops before its context ends.
type slowCloser struct{ closed bool }

func (c *slowCloser) Close(ctx context.Context) error {
	<-ctx.Done()
	c.closed = true
	return ctx.Err()
}

// quickCloser stops at once.
type quickCloser struct{ closed bool }

func (c *quickCloser) Close(context.Context) error { c.closed = true; return nil }

func TestCloseBackground(t *testing.T) {
	t.Parallel()
	var logs bytes.Buffer
	slow, quick := &slowCloser{}, &quickCloser{}
	start := time.Now()
	closeBackground(t.Context(), slog.New(slog.NewTextHandler(&logs, nil)), slow, quick)
	if d := time.Since(start); d < BackgroundCloseTimeout || d > 3*BackgroundCloseTimeout {
		t.Errorf("closeBackground took %s, want about %s", d, BackgroundCloseTimeout)
	}
	if !slow.closed || !quick.closed || !strings.Contains(logs.String(), "background worker still running") ||
		!strings.Contains(logs.String(), "slowCloser") || strings.Contains(logs.String(), "quickCloser") {
		t.Errorf("closed %v %v, logs %q", slow.closed, quick.closed, logs.String())
	}
}

// fakeBackend is a downloadBackend answering err, or a file and an archive.
type fakeBackend struct {
	err error
}

func (b fakeBackend) Resolve(context.Context, *tenant.Tenant, string, string) (download.View, error) {
	return download.View{TransferID: "trf_x"}, b.err
}

func (b fakeBackend) Unlock(context.Context, *tenant.Tenant, string, netip.Addr, string, string) (string, error) {
	return "dg_x", b.err
}

func (b fakeBackend) OpenFile(context.Context, *tenant.Tenant, string, netip.Addr, string, string) (*download.File, error) {
	if b.err != nil {
		return nil, b.err
	}
	return &download.File{Name: "a.txt", SHA256: "abc"}, nil
}

func (b fakeBackend) PrepareArchive(context.Context, *tenant.Tenant, string, netip.Addr, string) (*download.Archive, error) {
	if b.err != nil {
		return nil, b.err
	}
	return &download.Archive{}, nil
}

func TestDownloadAdapter(t *testing.T) {
	t.Parallel()
	ctx, tn := t.Context(), &tenant.Tenant{}
	a := downloadAdapter{svc: fakeBackend{}}
	if v, err := a.Resolve(ctx, tn, "", ""); err != nil || v.TransferID != "trf_x" {
		t.Errorf("Resolve = %+v, %v", v, err)
	}
	if c, err := a.Unlock(ctx, tn, "", netip.Addr{}, "", ""); err != nil || c != "dg_x" {
		t.Errorf("Unlock = %q, %v", c, err)
	}
	if f, err := a.OpenFile(ctx, tn, "", netip.Addr{}, "", ""); err != nil || f.Name != "a.txt" || f.SHA256 != "abc" {
		t.Errorf("OpenFile = %+v, %v", f, err)
	}
	if ar, err := a.PrepareArchive(ctx, tn, "", netip.Addr{}, ""); err != nil || ar == nil {
		t.Errorf("PrepareArchive = %v, %v", ar, err)
	}
	boom := errors.New("boom")
	a = downloadAdapter{svc: fakeBackend{err: boom}}
	if _, err := a.OpenFile(ctx, tn, "", netip.Addr{}, "", ""); !errors.Is(err, boom) {
		t.Errorf("OpenFile error = %v", err)
	}
	if ar, err := a.PrepareArchive(ctx, tn, "", netip.Addr{}, ""); !errors.Is(err, boom) || ar != nil {
		t.Errorf("PrepareArchive error = %v, %v", ar, err)
	}
}

func TestLifecycleOptions(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{
		UploadTTL: 24 * time.Hour, UploadMaxAge: 12 * time.Hour,
		BackupDir: "/backups", BackupTime: 150 * time.Minute, BackupKeep: 9,
	}
	got := lifecycleOptions(cfg, &runOptions{}, nil)
	if got.Interval != 0 || got.UploadTTL != 12*time.Hour || got.BackupDir != "/backups" ||
		got.BackupTime != 150*time.Minute || got.BackupKeep != 9 {
		t.Errorf("default lifecycle options = %+v", got)
	}
	var o runOptions
	WithLifecycleOptions(func(lo *lifecycle.Options) { lo.Interval = 50 * time.Millisecond })(&o)
	if got := lifecycleOptions(cfg, &o, nil); got.Interval != 50*time.Millisecond || got.BackupKeep != 9 {
		t.Errorf("edited lifecycle options = %+v", got)
	}
}
