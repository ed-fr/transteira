package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/avalert"
	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/diskalert"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

func TestSystemSMTPSettings(t *testing.T) {
	t.Parallel()
	got := systemSMTPSettings(config.SystemSMTP{
		Host: "smtp.example.com", Port: 587, Security: config.SMTPSecurityStartTLS, From: "noreply@example.com",
		FromName: "TransTeira", Username: "relay", Password: config.NewSecret("s3cret"),
	})
	want := mail.Settings{
		Host: "smtp.example.com", Port: 587, Security: mail.SecurityStartTLS, Username: "relay", Password: "s3cret",
		FromAddress: "noreply@example.com", FromName: "TransTeira",
	}
	if got != want {
		t.Fatalf("settings %v, want %v", got, want)
	}
}

func TestNewSystemMail(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	off, err := newSystemMail(&config.Config{}, nil)
	if err != nil || off.queue != nil || off.mailer() != nil || off.Close(ctx) != nil {
		t.Fatalf("disabled: %v %+v", err, off)
	}
	closeMailQueues(ctx, slog.New(slog.DiscardHandler), off.queue) // nil queues are skipped

	if _, err := newSystemMail(&config.Config{SystemSMTP: config.SystemSMTP{
		Host: "smtp.example.com", Port: 25, Security: config.SMTPSecurityNone, From: "not an address",
	}}, nil); !errors.Is(err, mail.ErrInvalidSettings) {
		t.Fatalf("invalid: %v", err)
	}

	on, err := newSystemMail(&config.Config{SystemSMTP: config.SystemSMTP{
		Host: "smtp.example.com", Port: 25, Security: config.SMTPSecurityNone, From: "noreply@example.com",
	}}, nil)
	if err != nil || on.queue == nil || on.mailer() == nil || on.settings.Host != "smtp.example.com" {
		t.Fatalf("enabled: %v %+v", err, on)
	}
	if err := on.Close(ctx); err != nil {
		t.Fatal(err)
	}
	closeMailQueues(ctx, slog.New(slog.DiscardHandler), on.queue, nil)
	if err := on.queue.Enqueue(mail.Job{}); err == nil {
		t.Fatal("queue still open")
	}

	edited := diskAlertOptions(&config.Config{DataDir: "/data", AdminHosts: []string{adminHost}}, &runOptions{
		diskAlertOpts: func(o *diskalert.Options) { o.Interval = time.Second },
	}, on, nil)
	if edited.DataDir != "/data" || edited.AdminLink != "https://"+adminHost+"/admin" || edited.Interval != time.Second ||
		edited.Mailer == nil || edited.SMTP != on.settings {
		t.Fatalf("options %+v", edited)
	}

	// The antivirus alert gets the same link and system channel; without
	// system mail, no system mailer.
	cfg := &config.Config{AdminHosts: []string{adminHost}}
	av := antivirusAlertOptions(cfg, &runOptions{
		avAlertOpts: func(o *avalert.Options) { o.Grace = time.Second },
	}, on, avalert.Options{Pinger: nil})
	if av.AdminLink != "https://"+adminHost+"/admin" || av.Grace != time.Second || av.SystemMailer == nil || av.SMTP != on.settings {
		t.Fatalf("antivirus alert options %+v", av)
	}
	if av := antivirusAlertOptions(cfg, &runOptions{}, off, avalert.Options{}); av.SystemMailer != nil || av.Grace != 0 {
		t.Fatalf("antivirus alert options without system mail %+v", av)
	}
}

func TestRunRefusesInvalidSystemSMTP(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t, storetest.SQLite(t))
	cfg.SystemSMTP = config.SystemSMTP{Host: "smtp.example.com", Port: 25, Security: config.SMTPSecurityNone, From: "bad"}
	err := Run(context.Background(), cfg, WithListener(newMemListener()), WithLogOutput(io.Discard))
	if err == nil || !strings.Contains(err.Error(), "TT_SYSTEM_SMTP") {
		t.Fatalf("Run = %v", err)
	}
}

// mailpitAddr returns the Mailpit SMTP host and port and the API base URL,
// or skips the test (fails it under TT_TEST_REQUIRE_POSTGRES=1).
func mailpitAddr(t *testing.T) (string, int, string) {
	t.Helper()
	smtpAddr, api := os.Getenv("TT_TEST_MAILPIT_SMTP"), strings.TrimSuffix(os.Getenv("TT_TEST_MAILPIT_API"), "/")
	if smtpAddr == "" || api == "" {
		if os.Getenv("TT_TEST_REQUIRE_POSTGRES") == "1" {
			t.Fatal("TT_TEST_MAILPIT_SMTP and TT_TEST_MAILPIT_API are required when TT_TEST_REQUIRE_POSTGRES=1")
		}
		t.Skip("TT_TEST_MAILPIT_SMTP and TT_TEST_MAILPIT_API not set")
	}
	host, p, err := net.SplitHostPort(smtpAddr)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(p)
	if err != nil {
		t.Fatal(err)
	}
	return host, port, api
}

// mailpitFind waits for a message to rcpt and returns its subject.
func mailpitFind(ctx context.Context, t *testing.T, api, rcpt string) string {
	t.Helper()
	for {
		var list struct {
			Messages []struct {
				Subject string
				To      []struct{ Address string }
			} `json:"messages"`
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet,
			api+"/api/v1/search?query="+url.QueryEscape(`to:"`+rcpt+`"`), nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("mailpit search: %v", err)
		}
		err = json.NewDecoder(resp.Body).Decode(&list)
		_ = resp.Body.Close()
		if err != nil {
			t.Fatalf("mailpit decode: %v", err)
		}
		for _, m := range list.Messages {
			if len(m.To) == 1 && m.To[0].Address == rcpt {
				return m.Subject
			}
		}
		select {
		case <-ctx.Done():
			t.Fatalf("no mail to %s in Mailpit", rcpt)
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// TestRunDiskAlertMailpit runs the server with a nearly full fake disk and
// the system SMTP server on the loopback Mailpit (which the tenant SMTP
// guard would refuse): the alert is audited and delivered to the super
// admin, in their language.
func TestRunDiskAlertMailpit(t *testing.T) {
	t.Parallel()
	host, port, api := mailpitAddr(t)
	cfg := testConfig(t, storetest.SQLite(t))
	cfg.SMTPDenyNetworks = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}
	cfg.SystemSMTP = config.SystemSMTP{
		Host: host, Port: port, Security: config.SMTPSecurityNone, From: "transteira@example.com", FromName: "TransTeira",
	}
	prepare(t, cfg)
	var raw [8]byte
	_, _ = rand.Read(raw[:])
	rcpt := "root-" + hex.EncodeToString(raw[:]) + "@example.com"
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c := *cfg
	db, err := store.Open(ctx, &c)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Admins().Create(ctx, store.Admin{
		Username: "root", Email: rcpt, Role: store.RoleSuperAdmin, PasswordHash: "$argon2id$test", Language: "fr",
	}); err != nil {
		t.Fatal(err)
	}

	s := start(t, cfg, WithDiskAlertOptions(func(o *diskalert.Options) {
		o.Measure = func(string) (uint64, uint64, error) { return 1000, 40, nil }
	}))
	if subject := mailpitFind(ctx, t, api, rcpt); !strings.Contains(strings.ToLower(subject), "disque") {
		t.Errorf("subject %q, want the French template", subject)
	}
	if err := s.stop(t); err != nil {
		t.Fatal(err)
	}
	page, err := db.AuditEvents().List(ctx, store.AuditFilter{Action: string(audit.ActionDiskAlertRaised)})
	if err != nil || len(page.Items) != 1 || string(page.Items[0].Details) != `{"thresholdPercent":85,"usedPercent":96}` {
		t.Fatalf("audit: %v %+v", err, page.Items)
	}
	row, err := db.SystemSettings().Get(ctx)
	if err != nil || row.DiskAlertLevel != store.DiskAlertLevelRaised {
		t.Fatalf("level: %v %+v", err, row)
	}
}
