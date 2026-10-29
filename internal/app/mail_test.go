package app

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/branding"
	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/download"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/lifecycle"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/netpolicy"
	"github.com/ed-fr/transteira/internal/scan"
	"github.com/ed-fr/transteira/internal/storage"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/usage"
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
	total := ShutdownTimeout + HandlerDrainTimeout + BackgroundCloseTimeout + FinalCloseTimeout + MailDrainTimeout
	if total != 9*time.Second || total >= dockerGrace {
		t.Errorf("worst-case shutdown %v, want 9s, strictly below Docker's %v grace period", total, dockerGrace)
	}
	if ShutdownTimeout != 5*time.Second || BackgroundCloseTimeout != time.Second || FinalCloseTimeout != time.Second {
		t.Errorf("ShutdownTimeout = %v, BackgroundCloseTimeout = %v, FinalCloseTimeout = %v, want 5s, 1s and 1s",
			ShutdownTimeout, BackgroundCloseTimeout, FinalCloseTimeout)
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

// budgetCloser records whether its context still had time left when it
// was called.
type budgetCloser struct {
	err  error
	left time.Duration
}

func (c *budgetCloser) Close(ctx context.Context) error {
	c.err = ctx.Err()
	if d, ok := ctx.Deadline(); ok {
		c.left = time.Until(d)
	}
	return nil
}

func TestCloseStages(t *testing.T) {
	t.Parallel()
	var logs bytes.Buffer
	slow, quick, later := &slowCloser{}, &quickCloser{}, &budgetCloser{}
	// The second budget is long so that waiting for it by mistake is told apart
	// from a slow, loaded machine: the bound below is far under it.
	const first, second = 50 * time.Millisecond, time.Minute
	ctx, cancel := context.WithCancel(t.Context())
	cancel() // the signal context is already done at shutdown
	start := time.Now()
	closeStages(ctx, slog.New(slog.NewTextHandler(&logs, nil)),
		closeStage{timeout: first, closers: []closer{slow, quick}},
		closeStage{timeout: second, closers: []closer{later}})
	if d := time.Since(start); d < first || d > second/2 {
		t.Errorf("closeStages took %s, want about %s", d, first)
	}
	// The later stage runs once the first one is over, with its own budget:
	// the first stage exhausting its deadline does not deprive it.
	if later.err != nil || later.left < second/2 {
		t.Errorf("later stage: err %v, %s left, want its own budget", later.err, later.left)
	}
	if !slow.closed || !quick.closed || !strings.Contains(logs.String(), "background worker still running") ||
		!strings.Contains(logs.String(), "slowCloser") || strings.Contains(logs.String(), "quickCloser") {
		t.Errorf("closed %v %v, logs %q", slow.closed, quick.closed, logs.String())
	}
}

// TestCloseStagesUsageFlush checks the shutdown of the usage recorder: the
// counters recorded after the signal are flushed by the second stage even
// when the first stage exhausted its budget, before the database closes.
func TestCloseStagesUsageFlush(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		db, err := store.Open(ctx, e.Config())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = db.Close() }()
		if _, err := db.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
		tn, err := db.Tenants().Create(ctx, &tenant.Tenant{
			Name: "Entity A", FQDN: "transfer.entity-a.example.com", DefaultLanguage: "en",
			MaxTransferBytes: 1 << 30, StorageQuotaBytes: 1 << 40,
		})
		if err != nil {
			t.Fatal(err)
		}
		rec := usage.New(db, usage.Options{Interval: time.Hour})
		sig, stop := context.WithCancel(ctx)
		if err := rec.Start(sig); err != nil {
			t.Fatal(err)
		}
		stop() // SIGTERM
		now := time.Now()
		rec.BytesServed(tn.ID, 42, now) // a download finishing during the HTTP shutdown
		rec.VirusDetected(tn.ID, now)   // the antivirus worker stopping
		var logs bytes.Buffer
		closeStages(sig, slog.New(slog.NewTextHandler(&logs, nil)),
			closeStage{timeout: 20 * time.Millisecond, closers: []closer{&slowCloser{}}},
			closeStage{timeout: 5 * time.Second, closers: []closer{rec}})
		if strings.Contains(logs.String(), "Recorder") {
			t.Errorf("usage recorder cut short: %s", logs.String())
		}
		days, err := db.TenantUsage().Range(ctx, tn.ID, store.DayOf(now))
		if err != nil {
			t.Fatal(err)
		}
		if len(days) != 1 || days[0].BytesDownloaded != 42 || days[0].VirusDetections != 1 {
			t.Errorf("usage = %+v, want the counters recorded after the signal", days)
		}
	})
}

// fakeBackend is a downloadBackend answering err, or a file and an archive.
type fakeBackend struct {
	err error
}

func (b fakeBackend) Resolve(context.Context, *tenant.Tenant, string, download.Cookies) (download.View, error) {
	return download.View{TransferID: "trf_x"}, b.err
}

func (b fakeBackend) Unlock(context.Context, *tenant.Tenant, string, netip.Addr, string, download.Cookies) (string, error) {
	return "dg_x", b.err
}

func (b fakeBackend) StartVerification(context.Context, *tenant.Tenant, string, netip.Addr, bool, string, string) (*download.Challenge, error) {
	return &download.Challenge{EmailMasked: "c***@example.com"}, b.err
}

func (b fakeBackend) ConfirmVerification(context.Context, *tenant.Tenant, string, netip.Addr, string, string) (string, error) {
	return "rv_x", b.err
}

func (b fakeBackend) ReplyAccess(context.Context, *tenant.Tenant, string, string, netip.Addr) (download.ReplyTarget, error) {
	return download.ReplyTarget{TransferID: "trf_x"}, b.err
}

func (b fakeBackend) OpenFile(context.Context, *tenant.Tenant, string, netip.Addr, download.Cookies, string) (*download.File, error) {
	if b.err != nil {
		return nil, b.err
	}
	return &download.File{Name: "a.txt", SHA256: "abc"}, nil
}

func (b fakeBackend) PrepareArchive(context.Context, *tenant.Tenant, string, netip.Addr, download.Cookies) (*download.Archive, error) {
	if b.err != nil {
		return nil, b.err
	}
	return &download.Archive{}, nil
}

func TestDownloadAdapter(t *testing.T) {
	t.Parallel()
	ctx, tn := t.Context(), &tenant.Tenant{}
	a := downloadAdapter{svc: fakeBackend{}}
	if v, err := a.Resolve(ctx, tn, "", download.Cookies{}); err != nil || v.TransferID != "trf_x" {
		t.Errorf("Resolve = %+v, %v", v, err)
	}
	if c, err := a.Unlock(ctx, tn, "", netip.Addr{}, "", download.Cookies{}); err != nil || c != "dg_x" {
		t.Errorf("Unlock = %q, %v", c, err)
	}
	if ch, err := a.StartVerification(ctx, tn, "", netip.Addr{}, false, "", ""); err != nil || ch.EmailMasked != "c***@example.com" {
		t.Errorf("StartVerification = %+v, %v", ch, err)
	}
	if c, err := a.ConfirmVerification(ctx, tn, "", netip.Addr{}, "", ""); err != nil || c != "rv_x" {
		t.Errorf("ConfirmVerification = %q, %v", c, err)
	}
	if f, err := a.OpenFile(ctx, tn, "", netip.Addr{}, download.Cookies{}, ""); err != nil || f.Name != "a.txt" || f.SHA256 != "abc" {
		t.Errorf("OpenFile = %+v, %v", f, err)
	}
	if ar, err := a.PrepareArchive(ctx, tn, "", netip.Addr{}, download.Cookies{}); err != nil || ar == nil {
		t.Errorf("PrepareArchive = %v, %v", ar, err)
	}
	if err := a.ReportAbuse(ctx, tn, "", netip.Addr{}, "", "spam", ""); err != nil {
		t.Errorf("ReportAbuse = %v", err)
	}
	if target, err := a.ReplyAccess(ctx, tn, "", "", netip.Addr{}); err != nil || target.TransferID != "trf_x" {
		t.Errorf("ReplyAccess = %+v, %v", target, err)
	}
	boom := errors.New("boom")
	a = downloadAdapter{svc: fakeBackend{err: boom}}
	if err := a.ReportAbuse(ctx, tn, "", netip.Addr{}, "", "spam", ""); !errors.Is(err, boom) {
		t.Errorf("ReportAbuse error = %v", err)
	}
	if _, err := a.OpenFile(ctx, tn, "", netip.Addr{}, download.Cookies{}, ""); !errors.Is(err, boom) {
		t.Errorf("OpenFile error = %v", err)
	}
	if ar, err := a.PrepareArchive(ctx, tn, "", netip.Addr{}, download.Cookies{}); !errors.Is(err, boom) || ar != nil {
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

func TestSMTPSenderDialsThroughTheGuard(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{SMTPTimeout: 2 * time.Second, SMTPDenyNetworks: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}
	err := newSMTPSender(cfg).Send(context.Background(), mail.Settings{
		Host: "127.0.0.1", Port: 25, Security: mail.SecurityNone, FromAddress: "noreply@entity-a.example.com",
	}, mail.Message{To: []string{"bob@example.com"}, Subject: "s", Text: "t", Language: "en"})
	if !errors.Is(err, netpolicy.ErrAddressDenied) {
		t.Fatalf("err = %v, want a denied address", err)
	}
}

func TestAssetStore(t *testing.T) {
	t.Parallel()
	files, err := storage.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = files.Close() })
	a := assetStore{files: files}
	tid := tenant.ID(id.New(id.Tenant))
	for _, kind := range []branding.Kind{branding.KindLogo, branding.KindBackground} {
		if _, err := a.Get(tid, kind); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("%s missing: %v", kind, err)
		}
		if err := a.Put(tid, kind, []byte(kind.String())); err != nil {
			t.Fatal(err)
		}
		if got, err := a.Get(tid, kind); err != nil || string(got) != kind.String() {
			t.Fatalf("%s: %q %v", kind, got, err)
		}
		if err := a.Delete(tid, kind); err != nil {
			t.Fatal(err)
		}
		if _, err := a.Get(tid, kind); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("%s after delete: %v", kind, err)
		}
	}
	const unknown = branding.Kind(42)
	if err := a.Put(tid, unknown, nil); !errors.Is(err, errUnknownAsset) {
		t.Errorf("put unknown: %v", err)
	}
	if _, err := a.Get(tid, unknown); !errors.Is(err, errUnknownAsset) {
		t.Errorf("get unknown: %v", err)
	}
	if err := a.Delete(tid, unknown); !errors.Is(err, errUnknownAsset) {
		t.Errorf("delete unknown: %v", err)
	}
}

func (b fakeBackend) ReportAbuse(context.Context, *tenant.Tenant, string, netip.Addr, string, string, string) error {
	return b.err
}
