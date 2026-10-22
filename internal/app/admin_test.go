package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// setupTokenLog matches the setup token line of the application log.
var setupTokenLog = regexp.MustCompile(`No admin exists yet\. Setup token: stp_[0-9A-Za-z]{30,} \(valid until restart\)\. Open https://admin\.localhost/admin/setup`)

func TestRunServesTheAdminHost(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t, storetest.SQLite(t))
	prepare(t, cfg)
	cfg.ClamAV.Address = fakeClamd(t)
	s := start(t, cfg)

	if code, body := s.get(t, "/api/v1/admin/setup", adminHost); code != http.StatusOK || body != `{"setupRequired":true}`+"\n" {
		t.Fatalf("setup status on the admin host = %d %s", code, body)
	}
	if code, _ := s.get(t, "/api/v1/admin/setup", tenantHost); code != http.StatusNotFound {
		t.Errorf("setup status on a tenant host = %d", code)
	}
	if code, _ := s.get(t, "/api/v1/tenant", adminHost); code != http.StatusNotFound {
		t.Errorf("public tenant on the admin host = %d", code)
	}
	if code, body := s.get(t, "/api/v1/version", adminHost); code != http.StatusOK || !strings.Contains(body, `"apiVersion":"v1"`) {
		t.Errorf("version on the admin host = %d %s", code, body)
	}
	// A wrong setup token is refused (the generated one is only in the log).
	code, body := s.do(t, http.MethodPost, "/api/v1/admin/setup", adminHost, strings.NewReader(
		`{"username":"root","email":"root@example.com","password":"a-long-passphrase-2026","setupToken":"stp_wrong"}`)) // gitleaks:allow (fake test credentials)
	if code != http.StatusForbidden || !strings.Contains(body, "setup-token-invalid") {
		t.Errorf("setup with a wrong token = %d %s", code, body)
	}
	if err := s.stop(t); err != nil {
		t.Fatal(err)
	}
	logs := s.logs.String()
	if n := len(setupTokenLog.FindAllString(logs, -1)); n != 1 {
		t.Errorf("setup token logged %d times, want once: %s", n, logs)
	}
	if !strings.Contains(logs, `"level":"WARN","msg":"No admin exists yet.`) {
		t.Errorf("setup token not logged at WARN: %s", logs)
	}
}

func TestRunSetupTokenConfigured(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t, storetest.SQLite(t))
	prepare(t, cfg)
	cfg.SetupToken = config.NewSecret("stp_configured_token_value")
	s := start(t, cfg)
	if code, _ := s.get(t, "/api/v1/admin/setup", adminHost); code != http.StatusOK {
		t.Fatalf("setup status = %d", code)
	}
	if err := s.stop(t); err != nil {
		t.Fatal(err)
	}
	if logs := s.logs.String(); strings.Contains(logs, "Setup token") || strings.Contains(logs, "stp_configured_token_value") {
		t.Errorf("a configured setup token must never be logged: %s", logs)
	}
}

func TestRunRefusesAnAdminHostServingATenant(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t, storetest.SQLite(t))
	prepare(t, cfg)
	cfg.AdminHosts = []string{adminHost, strings.ToUpper(tenantHost)}
	err := Run(context.Background(), cfg, WithListener(newMemListener()), WithLogOutput(io.Discard))
	if err == nil || !strings.Contains(err.Error(), "is also the FQDN of tenant") || !strings.Contains(err.Error(), tenantHost) {
		t.Errorf("Run = %v", err)
	}
}

// lookupFunc adapts a function to tenantLookup.
type lookupFunc func(ctx context.Context, fqdn string) (*tenant.Tenant, error)

func (f lookupFunc) TenantByFQDN(ctx context.Context, fqdn string) (*tenant.Tenant, error) {
	return f(ctx, fqdn)
}

func TestCheckAdminHosts(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	unknown := lookupFunc(func(context.Context, string) (*tenant.Tenant, error) {
		return nil, fmt.Errorf("%w: %w", tenant.ErrUnknownTenant, store.ErrNotFound)
	})
	if err := checkAdminHosts(ctx, unknown, []string{adminHost, "admin2.localhost"}); err != nil {
		t.Errorf("unknown hosts: %v", err)
	}
	if err := checkAdminHosts(ctx, unknown, nil); err != nil {
		t.Errorf("no host: %v", err)
	}
	failing := lookupFunc(func(context.Context, string) (*tenant.Tenant, error) { return nil, errors.New("database down") })
	if err := checkAdminHosts(ctx, failing, []string{adminHost}); err == nil || !strings.Contains(err.Error(), "database down") {
		t.Errorf("lookup failure: %v", err)
	}
	if err := checkAdminHosts(ctx, unknown, []string{"bad host"}); err == nil || !strings.Contains(err.Error(), config.EnvAdminHosts) {
		t.Errorf("malformed host: %v", err)
	}
}

func TestNewAdminService(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cfg := testConfig(t, storetest.SQLite(t))
	prepare(t, cfg)
	c := *cfg
	db, err := store.Open(ctx, &c)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	var logs syncBuffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	if _, err := newAdminService(ctx, &config.Config{}, db, adminDeps{}, logger); err == nil || !strings.Contains(err.Error(), config.EnvAdminHosts) {
		t.Errorf("no admin host: %v", err)
	}

	// Once an administrator exists, no token is generated nor logged.
	if _, err := db.Admins().Create(ctx, store.Admin{Username: "root", Email: "root@example.com", Role: store.RoleSuperAdmin}); err != nil {
		t.Fatal(err)
	}
	svc, err := newAdminService(ctx, cfg, db, adminDeps{}, logger)
	if err != nil || svc == nil {
		t.Fatalf("newAdminService = %v, %v", svc, err)
	}
	if logs.String() != "" {
		t.Errorf("logs %q, want nothing once an admin exists", logs.String())
	}

	// A count failure refuses the start.
	_ = db.Close()
	if _, err := newAdminService(ctx, cfg, db, adminDeps{}, logger); err == nil || !strings.Contains(err.Error(), "count admins") {
		t.Errorf("closed database: %v", err)
	}
}
