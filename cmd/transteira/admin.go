package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/app"
	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/masterkey"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/store"
)

// adminUsage lists the admin subcommands.
const adminUsage = `Usage: transteira admin <subcommand>

Subcommands:
  list                       List the administrator accounts (no secret is printed)
  reset-totp <username>      Remove the TOTP enrollment and recovery codes of an account and
                             revoke its sessions: it must enroll TOTP again at its next login
  reset-password <username>  Remove the password, TOTP enrollment and recovery codes of an
                             account, revoke its sessions and print a new activation link
                             (valid 72 hours, shown once)
`

// runAdmin dispatches the admin subcommands (local recovery of the
// administrator accounts, run inside the container: CLAUDE.md section
// 6.5).
func runAdmin(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		_, _ = io.WriteString(stdout, adminUsage)
		if len(args) == 0 {
			return exitUsage
		}
		return exitOK
	}
	var run func(ctx context.Context, svc *adminauth.Service, stdout io.Writer) error
	switch name, rest := args[0], args[1:]; name {
	case "list":
		fs := newFlagSet("admin list", stderr)
		if code, ok := parseFlags(fs, rest, stderr); !ok {
			return code
		}
		run = listAdmins
	case "reset-totp", "reset-password":
		username, code, ok := parseUsername("admin "+name, rest, stderr)
		if !ok {
			return code
		}
		reset := resetTOTP
		if name == "reset-password" {
			reset = resetPassword
		}
		run = func(ctx context.Context, svc *adminauth.Service, stdout io.Writer) error {
			return reset(ctx, svc, username, stdout)
		}
	default:
		_, _ = fmt.Fprintf(stderr, "admin: unknown subcommand %q\n\n", name)
		_, _ = io.WriteString(stderr, adminUsage)
		return exitUsage
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := withAdminService(ctx, stderr, func(svc *adminauth.Service) error { return run(ctx, svc, stdout) }); err != nil {
		_, _ = fmt.Fprintf(stderr, "admin %s: %v\n", args[0], err)
		return exitError
	}
	return exitOK
}

// parseUsername parses the arguments of a subcommand taking exactly one
// username and returns it normalized. On failure it returns the exit code:
// exitOK for -h, exitUsage otherwise (a missing, extra or malformed
// username, an unknown flag).
func parseUsername(cmd string, args []string, stderr io.Writer) (string, int, bool) {
	fs := newFlagSet(cmd, stderr)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return "", exitOK, false
		}
		return "", exitUsage, false
	}
	if fs.NArg() != 1 {
		_, _ = fmt.Fprintln(stderr, cmd+": exactly one username is required")
		return "", exitUsage, false
	}
	username, err := store.NormalizeUsername(fs.Arg(0))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%s: invalid username %q\n", cmd, fs.Arg(0))
		return "", exitUsage, false
	}
	return username, exitOK, true
}

// withAdminService opens the database and the keyring like serve does
// (configuration of the environment, start-up migrations policy, master
// key check), builds the administrator service and runs fn with it. Logs
// go to stderr.
func withAdminService(ctx context.Context, stderr io.Writer, fn func(*adminauth.Service) error) error {
	cfg, err := config.FromEnvironment()
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: cfg.LogLevel}))
	keys, err := masterkey.Load(cfg)
	if err != nil {
		return err
	}
	defer keys.Close()
	db, err := app.OpenDatabase(ctx, cfg, logger)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	if _, err := masterkey.Check(ctx, db, keys, nil, time.Now()); err != nil {
		return err
	}
	// The subcommands write no security events; the setup token is unused
	// (empty: the setup is refused). The activation links point at the
	// first admin host, like those of the server.
	svc, err := adminauth.New(db, keys, masterkey.NewVault(db, keys, logger), crypto.NewPasswordHasher(1),
		securitylog.New(io.Discard), adminauth.Options{
			IdleTimeout: cfg.AdminSessionIdleTimeout, MaxAge: cfg.AdminSessionMaxAge,
			AdminBaseURL: "https://" + cfg.AdminHosts[0], Logger: logger,
		})
	if err != nil {
		return err
	}
	return fn(svc)
}

// listAdmins prints every account: identifier, username, role, activation
// and TOTP status, disabled flag and last login. No credential is printed.
func listAdmins(ctx context.Context, svc *adminauth.Service, stdout io.Writer) error {
	accounts, err := svc.ListAccounts(ctx)
	if err != nil {
		return err
	}
	if len(accounts) == 0 {
		_, err := fmt.Fprintln(stdout, "No administrator account. Run the first-run setup on the admin host.")
		return err
	}
	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "ID\tUSERNAME\tROLE\tACTIVATED\tTOTP ENABLED\tDISABLED\tLAST LOGIN")
	for _, a := range accounts {
		last := "never"
		if !a.LastLoginAt.IsZero() {
			last = a.LastLoginAt.UTC().Format(time.RFC3339)
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%t\t%t\t%t\t%s\n", a.ID, a.Username, a.Role, a.Activated, a.TOTPEnabled, a.Disabled, last)
	}
	return tw.Flush()
}

// resetTOTP removes the TOTP enrollment of username (normalized) and
// revokes its sessions, then tells the operator what happens next.
func resetTOTP(ctx context.Context, svc *adminauth.Service, username string, stdout io.Writer) error {
	err := svc.ResetTOTPLocal(ctx, username)
	if errors.Is(err, adminauth.ErrNotFound) {
		return unknownAdmin(username)
	}
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "TOTP and recovery codes of %q removed, and its sessions revoked (recorded in the audit log).\n"+
		"The administrator must sign in with their password and enroll TOTP again at the next login "+
		"(mandatory for a super admin and when TOTP is required).\n", username)
	return err
}

// resetPassword removes the password, TOTP enrollment and recovery codes
// of username (normalized), revokes its sessions and prints its new
// activation link, once: it is stored only as a hash and cannot be shown
// again.
func resetPassword(ctx context.Context, svc *adminauth.Service, username string, stdout io.Writer) error {
	link, err := svc.ResetPasswordLocal(ctx, username)
	switch {
	case errors.Is(err, adminauth.ErrNotFound):
		return unknownAdmin(username)
	case errors.Is(err, adminauth.ErrAccountDisabled):
		return fmt.Errorf("the account %q is disabled: enable it first", username)
	case err != nil:
		return err
	}
	_, err = fmt.Fprintf(stdout, "Password, TOTP and recovery codes of %q removed, and its sessions revoked (recorded in the audit log).\n"+
		"Activation link, valid until %s (shown once, transmit it to the administrator out of band):\n%s\n"+
		"The administrator opens it, chooses a new password, then enrolls TOTP again "+
		"(mandatory for a super admin and when TOTP is required).\n",
		username, link.ExpiresAt.UTC().Format(time.RFC3339), link.URL)
	return err
}

// unknownAdmin is the error of a username that names no account.
func unknownAdmin(username string) error {
	return fmt.Errorf("no administrator named %q (see \"transteira admin list\")", username)
}
