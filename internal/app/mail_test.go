package app

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/scan"
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
	if total := ShutdownTimeout + HandlerDrainTimeout + ScanCloseTimeout + MailDrainTimeout; total >= dockerGrace {
		t.Errorf("worst-case shutdown %v, want strictly below Docker's %v grace period", total, dockerGrace)
	}
	if ShutdownTimeout != 6*time.Second || ScanCloseTimeout != time.Second {
		t.Errorf("ShutdownTimeout = %v, ScanCloseTimeout = %v, want 6s and 1s", ShutdownTimeout, ScanCloseTimeout)
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
