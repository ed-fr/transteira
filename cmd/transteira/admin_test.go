package main

import (
	"context"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/masterkey"
	"github.com/ed-fr/transteira/internal/store"
)

// fakeHash is a syntactically valid PHC string; no password matches it.
const fakeHash = "$argon2id$v=19$m=65536,t=3,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNo" // gitleaks:allow

// seedSuperAdmin creates the super admin "root" with TOTP enabled in the
// database of dsn, and returns its ID.
func seedSuperAdmin(t *testing.T, dsn, keyFile string) string {
	t.Helper()
	ctx := context.Background()
	db, vault := keyStore(t, dsn, keyFile)
	kr, err := masterkey.Load(&config.Config{MasterKeyFile: keyFile})
	if err != nil {
		t.Fatal(err)
	}
	defer kr.Close()
	if _, err := masterkey.Check(ctx, db, kr, nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	a, err := db.Admins().Create(ctx, store.Admin{
		Username: "root", Email: "root@example.com", Role: store.RoleSuperAdmin, PasswordHash: fakeHash,
	})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := vault.WrapSystem(crypto.PurposeAdminTOTP, []byte("12345678901234567890"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Admins().SetPendingTOTP(ctx, a.ID, sealed); err != nil {
		t.Fatal(err)
	}
	if err := db.Admins().SetTOTP(ctx, a.ID, sealed.ID, 1); err != nil {
		t.Fatal(err)
	}
	return a.ID
}

func TestAdminCommands(t *testing.T) {
	dsn := setMigrateEnv(t)
	key := writeKeyFile(t)
	t.Setenv("TT_MASTER_KEY_FILE", key)
	t.Setenv("TT_LOG_LEVEL", "error")

	code, out, errOut := runCmd("admin", "list")
	if code != exitOK || !strings.Contains(out, "No administrator account") || errOut != "" {
		t.Fatalf("admin list (empty) = %d, %q, %q", code, out, errOut)
	}

	adminID := seedSuperAdmin(t, dsn, key)
	code, out, errOut = runCmd("admin", "list")
	if code != exitOK || errOut != "" {
		t.Fatalf("admin list = %d, %q, %q", code, out, errOut)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 2 || strings.Join(strings.Fields(lines[0]), " ") != "ID USERNAME ROLE ACTIVATED TOTP ENABLED DISABLED LAST LOGIN" ||
		strings.Join(strings.Fields(lines[1]), " ") != adminID+" root super_admin true true false never" {
		t.Errorf("admin list output %q", out)
	}
	if strings.Contains(out, fakeHash) || strings.Contains(out, "root@example.com") {
		t.Errorf("admin list prints more than needed: %q", out)
	}

	code, out, errOut = runCmd("admin", "reset-totp", "ROOT")
	if code != exitOK || !strings.Contains(out, `TOTP and recovery codes of "root" removed`) ||
		!strings.Contains(out, "enroll TOTP again at the next login") || errOut != "" {
		t.Fatalf("admin reset-totp = %d, %q, %q", code, out, errOut)
	}
	db, _ := keyStore(t, dsn, key)
	a, err := db.Admins().Get(context.Background(), adminID)
	if err != nil || a.TOTPEnabled || a.TOTPSecretID != "" {
		t.Errorf("after reset-totp: %+v, %v", a, err)
	}
	code, out, _ = runCmd("admin", "list")
	if code != exitOK || !strings.Contains(strings.Join(strings.Fields(out), " "), "root super_admin true false false never") {
		t.Errorf("admin list after reset = %d, %q", code, out)
	}

	code, _, errOut = runCmd("admin", "reset-totp", "ghost")
	if code != exitError || !strings.Contains(errOut, `no administrator named "ghost"`) {
		t.Errorf("reset-totp ghost = %d, %q", code, errOut)
	}
	code, _, errOut = runCmd("admin", "reset-totp", "not a name")
	if code != exitUsage || !strings.Contains(errOut, `admin reset-totp: invalid username "not a name"`) {
		t.Errorf("reset-totp invalid = %d, %q", code, errOut)
	}

	// reset-password clears everything and prints the activation link once.
	code, out, errOut = runCmd("admin", "reset-password", "Root")
	if code != exitOK || errOut != "" || !strings.Contains(out, `Password, TOTP and recovery codes of "root" removed`) {
		t.Fatalf("admin reset-password = %d, %q, %q", code, out, errOut)
	}
	link := regexp.MustCompile(`(?m)^https://admin\.localhost/admin/activate#act_[A-Za-z0-9]{43}$`).FindString(out)
	if link == "" || strings.Count(out, "act_") != 1 {
		t.Errorf("activation link not printed once: %q", out)
	}
	if a, err := db.Admins().Get(context.Background(), adminID); err != nil || a.PasswordHash != "" || a.TOTPEnabled {
		t.Errorf("after reset-password: %+v, %v", a, err)
	}
	code, out, _ = runCmd("admin", "list")
	if code != exitOK || !strings.Contains(strings.Join(strings.Fields(out), " "), "root super_admin false false false never") {
		t.Errorf("admin list after reset-password = %d, %q", code, out)
	}
	page, err := db.AuditEvents().List(context.Background(), store.AuditFilter{Action: "admin.password_reset_local"})
	if err != nil || len(page.Items) != 1 || page.Items[0].Actor != "cli" || page.Items[0].ObjectID != adminID {
		t.Errorf("audit of reset-password = %+v, %v", page.Items, err)
	}
	code, _, errOut = runCmd("admin", "reset-password", "ghost")
	if code != exitError || !strings.Contains(errOut, `no administrator named "ghost"`) {
		t.Errorf("reset-password ghost = %d, %q", code, errOut)
	}
	code, _, errOut = runCmd("admin", "reset-password", "bad name!")
	if code != exitUsage || !strings.Contains(errOut, "invalid username") {
		t.Errorf("reset-password invalid = %d, %q", code, errOut)
	}
	// A disabled account is refused.
	if _, err := db.Admins().Create(context.Background(), store.Admin{
		Username: "blocked", Email: "b@example.com", Role: store.RoleSuperAdmin, PasswordHash: fakeHash, Disabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	code, _, errOut = runCmd("admin", "reset-password", "blocked")
	if code != exitError || !strings.Contains(errOut, `the account "blocked" is disabled`) {
		t.Errorf("reset-password disabled = %d, %q", code, errOut)
	}
}

func TestAdminCommandUsage(t *testing.T) {
	for _, tc := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"admin"}, exitUsage, "Usage: transteira admin"},
		{[]string{"admin", "-h"}, exitOK, "reset-totp <username>"},
		{[]string{"admin", "help"}, exitOK, "reset-totp <username>"},
		{[]string{"admin", "nope"}, exitUsage, `unknown subcommand "nope"`},
		{[]string{"admin", "list", "extra"}, exitUsage, `unexpected argument "extra"`},
		{[]string{"admin", "list", "-h"}, exitOK, ""},
		{[]string{"admin", "reset-totp"}, exitUsage, "exactly one username"},
		{[]string{"admin", "reset-totp", "a", "b"}, exitUsage, "exactly one username"},
		{[]string{"admin", "reset-totp", "-h"}, exitOK, ""},
		{[]string{"admin", "reset-totp", "-x"}, exitUsage, "flag provided but not defined"},
		{[]string{"admin", "-h"}, exitOK, "reset-password <username>"},
		{[]string{"admin", "reset-password"}, exitUsage, "admin reset-password: exactly one username"},
		{[]string{"admin", "reset-password", "-h"}, exitOK, ""},
		{[]string{"admin", "reset-password", "a b"}, exitUsage, "invalid username"},
	} {
		code, out, errOut := runCmd(tc.args...)
		if code != tc.code || !strings.Contains(out+errOut, tc.want) {
			t.Errorf("%v = %d, %q, %q", tc.args, code, out, errOut)
		}
	}
	// The command is listed in the usage.
	if _, out, _ := runCmd("help"); !strings.Contains(out, "admin ") {
		t.Errorf("usage lacks the admin command: %q", out)
	}
}

func TestAdminCommandErrors(t *testing.T) {
	setMigrateEnv(t)
	// The master key file of setMigrateEnv does not exist.
	code, _, errOut := runCmd("admin", "list")
	if code != exitError || !strings.HasPrefix(errOut, "admin list: ") {
		t.Errorf("missing key = %d, %q", code, errOut)
	}
	// An invalid configuration.
	t.Setenv("TT_ADMIN_HOSTS", "")
	code, _, errOut = runCmd("admin", "reset-totp", "root")
	if code != exitError || !strings.Contains(errOut, "TT_ADMIN_HOSTS") {
		t.Errorf("invalid configuration = %d, %q", code, errOut)
	}
}
