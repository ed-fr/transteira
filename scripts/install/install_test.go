// Package install_test checks the release installer (scripts/install): the pure functions of
// install.sh.in (option parsing, operating system detection, rendering of .env, of the
// Caddyfile, of the nftables ruleset, of the fail2ban jails and of the apt settings), the build
// of dist/install/install.sh by build.sh (placeholders, payload, determinism) and its --dry-run,
// which must not run any command that changes the machine.
//
// The installer itself never runs here: the functions are called from a bash that sources the
// template (its main is guarded), and the dry run gets stub commands first on its PATH that
// record any call to apt-get, docker, nft, systemctl, curl...
package install_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

const template = "install.sh.in"

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func needBash(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the installer targets Debian; its shell tests run on Linux (make check on the Linux VM)")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is not available")
	}
}

// shell sources the template in bash, then runs script; it returns stdout, stderr and the exit
// code.
func shell(t *testing.T, script string, env ...string) (stdout, stderr string, code int) {
	t.Helper()
	needBash(t)
	tpl, err := filepath.Abs(template)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "-c", `source "$TPL"`+"\n"+script)
	cmd.Env = append(os.Environ(), "TPL="+tpl, "ROOT="+repoRoot(t), "TMPDIR="+t.TempDir())
	cmd.Env = append(cmd.Env, env...)
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	err = cmd.Run()
	code = 0
	if err != nil {
		ee := &exec.ExitError{}
		if !asExitError(err, &ee) {
			t.Fatalf("bash: %v", err)
		}
		code = ee.ExitCode()
	}
	return out.String(), errOut.String(), code
}

func asExitError(err error, target **exec.ExitError) bool {
	ee, ok := err.(*exec.ExitError) //nolint:errorlint // exec.Cmd.Run returns *exec.ExitError unwrapped
	if ok {
		*target = ee
	}
	return ok
}

func mustShell(t *testing.T, script string, env ...string) string {
	t.Helper()
	out, errOut, code := shell(t, script, env...)
	if code != 0 {
		t.Fatalf("exit %d\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	return out
}

const printOpts = `
printf 'admin=%s email=%s/%s pg=%s host=%s port=%s sec=%s user=%s pwfile=%s from=%s fw=%s f2b=%s auto=%s yes=%s dry=%s up=%s\n' \
  "$OPT_ADMIN_HOST" "$OPT_ACME_EMAIL" "$OPT_ACME_EMAIL_SET" "$OPT_POSTGRES" "$OPT_SMTP_HOST" "$OPT_SMTP_PORT" \
  "$OPT_SMTP_SECURITY" "$OPT_SMTP_USER" "$OPT_SMTP_PASSWORD_FILE" "$OPT_SMTP_FROM" "$OPT_FIREWALL" "$OPT_FAIL2BAN" \
  "$OPT_AUTO_UPDATES" "$OPT_YES" "$OPT_DRY_RUN" "$OPT_UPGRADE"`

func TestParseArgs(t *testing.T) {
	cases := []struct {
		name, args, want string
	}{
		{"defaults", ``, "admin= email=/0 pg=0 host= port= sec= user= pwfile= from= fw=1 f2b=1 auto=1 yes=0 dry=0 up=0"},
		{
			"everything",
			`--admin-host Admin.Transfer.Example.COM --acme-email ops@example.com --postgres --smtp-host smtp.example.com ` +
				`--smtp-port 2525 --smtp-security tls --smtp-user bob --smtp-password-file /root/pw --smtp-from tt@example.com ` +
				`--no-firewall --no-fail2ban --no-auto-updates --yes --dry-run`,
			"admin=admin.transfer.example.com email=ops@example.com/1 pg=1 host=smtp.example.com port=2525 sec=tls user=bob " +
				"pwfile=/root/pw from=tt@example.com fw=0 f2b=0 auto=0 yes=1 dry=1 up=0",
		},
		{"equals form", `--admin-host=a.example.com --acme-email= -y`, "admin=a.example.com email=/1 pg=0 host= port= sec= user= pwfile= from= fw=1 f2b=1 auto=1 yes=1 dry=0 up=0"},
		{"upgrade", `--upgrade --yes --no-firewall`, "admin= email=/0 pg=0 host= port= sec= user= pwfile= from= fw=0 f2b=1 auto=1 yes=1 dry=0 up=1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := mustShell(t, "parse_args "+c.args+printOpts)
			if strings.TrimSpace(out) != c.want {
				t.Fatalf("got  %s\nwant %s", strings.TrimSpace(out), c.want)
			}
		})
	}
}

func TestParseArgsErrors(t *testing.T) {
	cases := []struct{ name, args, msg string }{
		{"unknown", `--frobnicate`, "unknown option '--frobnicate'"},
		{"missing value", `--admin-host`, "option --admin-host needs a value"},
		{"bare host", `--admin-host localhost`, "not a fully qualified host name"},
		{"host with path", `--admin-host a.example.com/x`, "not a fully qualified host name"},
		{"bad email", `--acme-email nope`, "is not a mail address"},
		{"bad port", `--smtp-host h --smtp-port 70000`, "is not a port"},
		{"zero port", `--smtp-host h --smtp-port 0`, "is not a port"},
		{"bad security", `--smtp-host h --smtp-security ssl`, "none, starttls or tls"},
		{"bad user", `--smtp-host h --smtp-user 'a b'`, "only letters"},
		{"bad smtp host", `--smtp-host 'h;rm'`, "not a host name"},
		{"smtp without host", `--smtp-from a@example.com`, "need --smtp-host"},
		{"upgrade with settings", `--upgrade --admin-host a.example.com`, "--upgrade keeps the settings"},
		{"upgrade with postgres", `--upgrade --postgres`, "--upgrade keeps the database engine"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, errOut, code := shell(t, "parse_args "+c.args)
			if code == 0 || !strings.Contains(errOut, c.msg) {
				t.Fatalf("exit %d, stderr %q: want a failure with %q", code, errOut, c.msg)
			}
		})
	}
}

func TestSMTPCheck(t *testing.T) {
	cases := []struct{ name, set, want string }{
		{"none", ``, "ok"},
		{"defaults", `CFG_SMTP_HOST=h CFG_SMTP_FROM=a@example.com`, "ok starttls 587"},
		{"tls port", `CFG_SMTP_HOST=h CFG_SMTP_FROM=a@example.com CFG_SMTP_SECURITY=tls`, "ok tls 465"},
		{"none port", `CFG_SMTP_HOST=h CFG_SMTP_FROM=a@example.com CFG_SMTP_SECURITY=none`, "ok none 25"},
		{"explicit port", `CFG_SMTP_HOST=h CFG_SMTP_FROM=a@example.com CFG_SMTP_PORT=2525`, "ok starttls 2525"},
		{"no from", `CFG_SMTP_HOST=h`, "fail: the system SMTP server needs a sender address (--smtp-from)"},
		{"user with none", `CFG_SMTP_HOST=h CFG_SMTP_FROM=a@example.com CFG_SMTP_SECURITY=none CFG_SMTP_USER=u CFG_SMTP_PASSWORD_SOURCE=prompt`, "fail: an SMTP user name is refused with --smtp-security none"},
		{"user without password", `CFG_SMTP_HOST=h CFG_SMTP_FROM=a@example.com CFG_SMTP_USER=u`, "fail: an SMTP user name needs a password"},
		{"password without user", `CFG_SMTP_HOST=h CFG_SMTP_FROM=a@example.com CFG_SMTP_PASSWORD_SOURCE=file:/x`, "fail: an SMTP password needs a user name"},
		{"user and password", `CFG_SMTP_HOST=h CFG_SMTP_FROM=a@example.com CFG_SMTP_USER=u CFG_SMTP_PASSWORD_SOURCE=file:/x`, "ok starttls 587"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := mustShell(t, c.set+`
if smtp_check; then echo "ok${CFG_SMTP_HOST:+ $CFG_SMTP_SECURITY $CFG_SMTP_PORT}"; else echo "fail: $REASON"; fi`)
			if !strings.HasPrefix(strings.TrimSpace(out), c.want) {
				t.Fatalf("got %q, want prefix %q", strings.TrimSpace(out), c.want)
			}
		})
	}
}

func TestDetectOS(t *testing.T) {
	cases := []struct{ name, content, want string }{
		{"debian 12", "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nID=debian\nVERSION_ID=\"12\"\nVERSION_CODENAME=bookworm\n", "ok debian 12 bookworm"},
		{"debian 13", "ID=debian\nVERSION_ID=\"13\"\nVERSION_CODENAME=trixie\n", "ok debian 13 trixie"},
		{"no codename", "ID=debian\nVERSION_ID='12'\n", "ok debian 12 bookworm"},
		{"debian 11", "ID=debian\nVERSION_ID=\"11\"\nVERSION_CODENAME=bullseye\n", "fail: unsupported Debian version '11'"},
		{"testing", "ID=debian\nVERSION_CODENAME=forky\n", "fail: unsupported Debian version 'unknown'"},
		{"ubuntu", "ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"24.04\"\n", "fail: unsupported system 'ubuntu'"},
		{"inconsistent", "ID=debian\nVERSION_ID=\"12\"\nVERSION_CODENAME=trixie\n", "fail: inconsistent os-release"},
		{"injection", "ID=debian\nVERSION_ID=\"12$(touch /tmp/x)\"\n", "fail: unsupported Debian version"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := filepath.Join(t.TempDir(), "os-release")
			if err := os.WriteFile(f, []byte(c.content), 0o600); err != nil {
				t.Fatal(err)
			}
			out := mustShell(t, `if detect_os "$F"; then echo "ok $OS_ID $OS_VERSION $OS_CODENAME"; else echo "fail: $REASON"; fi`, "F="+f)
			if !strings.HasPrefix(strings.TrimSpace(out), c.want) {
				t.Fatalf("got %q, want prefix %q", strings.TrimSpace(out), c.want)
			}
		})
	}
	out := mustShell(t, `detect_os /nonexistent/os-release || echo "fail: $REASON"`)
	if !strings.Contains(out, "not a Debian system") {
		t.Fatalf("missing file: %q", out)
	}
}

func TestMapArchAndDigests(t *testing.T) {
	out := mustShell(t, `
for a in amd64 x86_64 arm64 aarch64 armhf i386; do printf '%s=%s\n' "$a" "$(map_arch "$a" || echo none)"; done
TTI_PLATFORM_DIGESTS="linux/amd64=sha256:aa linux/arm64=sha256:bb"
platform_digest amd64; platform_digest arm64
TTI_PLATFORM_DIGESTS="linux/amd64=sha256:aa"
platform_digest arm64 || echo missing`)
	want := "amd64=amd64\nx86_64=amd64\narm64=arm64\naarch64=arm64\narmhf=none\ni386=none\nsha256:aa\nsha256:bb\nmissing\n"
	if out != want {
		t.Fatalf("got\n%s\nwant\n%s", out, want)
	}
}

func TestValidators(t *testing.T) {
	out := mustShell(t, `
for h in admin.example.com a.b.localhost xn--bcher-kva.example.org localhost -a.example.com a..example.com a.example.c0m 'a.example.com.' 'A.EXAMPLE.COM'; do
  valid_fqdn "$h" && echo "fqdn ok $h" || echo "fqdn no $h"; done
for e in a@example.com first.last+tag@sub.example.org 'a b@example.com' a@b @example.com 'a@example.com;x'; do
  valid_email "$e" && echo "email ok $e" || echo "email no $e"; done
version_lt 2.1.0 2.2.0 && echo lt1; version_lt 2.2.0 2.2.0 || echo nlt2; version_lt 2.10.0 2.9.0 || echo nlt3
version_lt 2.2.0-rc.1 2.2.0 && echo lt4`)
	for _, want := range []string{
		"fqdn ok admin.example.com", "fqdn ok a.b.localhost", "fqdn ok xn--bcher-kva.example.org",
		"fqdn no localhost", "fqdn no -a.example.com", "fqdn no a..example.com", "fqdn no a.example.com.",
		"fqdn no A.EXAMPLE.COM", "email ok a@example.com", "email ok first.last+tag@sub.example.org",
		"email no a b@example.com", "email no a@b", "email no @example.com", "email no a@example.com;x",
		"lt1", "nlt2", "nlt3", "lt4",
	} {
		if !strings.Contains(out, want+"\n") {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
}

// envKeys returns the KEY of every non-comment KEY=VALUE line, failing on a duplicate.
func envKeys(t *testing.T, env string) map[string]string {
	t.Helper()
	keys := map[string]string{}
	for _, line := range strings.Split(env, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatalf("not a KEY=VALUE line: %q", line)
		}
		if _, dup := keys[k]; dup {
			t.Fatalf("%s set twice in the rendered .env", k)
		}
		keys[k] = v
	}
	return keys
}

func TestRenderEnv(t *testing.T) {
	const img = "registry.invalid/example/transteira@sha256:0000000000000000000000000000000000000000000000000000000000000000"
	t.Run("sqlite", func(t *testing.T) {
		out := mustShell(t, `IMAGE_REF=`+img+` CFG_ADMIN_HOST=admin.transfer.example.org CFG_ENGINE=sqlite
render_env "$ROOT/deploy/.env.example"`)
		k := envKeys(t, out)
		for key, want := range map[string]string{
			"TRANSTEIRA_IMAGE": img, "PROXY_NETWORK": "proxy", "TT_ADMIN_HOSTS": "admin.transfer.example.org",
			"TT_TRUSTED_PROXIES": "172.30.0.10", "TT_TLS_ASK_ALLOWED_IPS": "172.30.0.10", "COMPOSE_FILE": "docker-compose.yml",
			"MASTER_KEY_FILE": "./secrets/master_key", "TT_SCAN_WORKERS": "1",
		} {
			if k[key] != want {
				t.Errorf("%s=%q, want %q", key, k[key], want)
			}
		}
		if _, ok := k["TT_SYSTEM_SMTP_HOST"]; ok {
			t.Error("TT_SYSTEM_SMTP_HOST set without --smtp-host")
		}
	})
	t.Run("postgres smtp", func(t *testing.T) {
		out := mustShell(t, `IMAGE_REF=`+img+` CFG_ADMIN_HOST=a.example.org CFG_ENGINE=postgres
CFG_SMTP_HOST=smtp.example.org CFG_SMTP_PORT=465 CFG_SMTP_SECURITY=tls CFG_SMTP_FROM=tt@example.org CFG_SMTP_USER=bob
render_env "$ROOT/deploy/.env.example"`)
		k := envKeys(t, out)
		for key, want := range map[string]string{
			"COMPOSE_FILE":        "docker-compose.yml:docker-compose.postgres.yml:docker-compose.installer-smtp.yml",
			"TT_SYSTEM_SMTP_HOST": "smtp.example.org", "TT_SYSTEM_SMTP_PORT": "465", "TT_SYSTEM_SMTP_SECURITY": "tls",
			"TT_SYSTEM_SMTP_FROM": "tt@example.org", "TT_SYSTEM_SMTP_USERNAME": "bob",
		} {
			if k[key] != want {
				t.Errorf("%s=%q, want %q", key, k[key], want)
			}
		}
		if strings.Contains(out, "PASSWORD=") {
			t.Error("the rendered .env must never carry a password")
		}
	})
	t.Run("example without the variable", func(t *testing.T) {
		f := filepath.Join(t.TempDir(), "env")
		if err := os.WriteFile(f, []byte("TRANSTEIRA_IMAGE=x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, errOut, code := shell(t, `IMAGE_REF=x CFG_ADMIN_HOST=a.example.org; render_env "$F"`, "F="+f)
		if code == 0 || !strings.Contains(errOut, "cannot set PROXY_NETWORK=proxy") {
			t.Fatalf("exit %d, stderr %q", code, errOut)
		}
	})
}

func TestRenderSMTPOverlay(t *testing.T) {
	sqlite := mustShell(t, `CFG_ENGINE=sqlite; render_smtp_overlay`)
	pg := mustShell(t, `CFG_ENGINE=postgres; render_smtp_overlay`)
	for _, out := range []string{sqlite, pg} {
		for _, want := range []string{
			"  transteira:\n", "TT_SYSTEM_SMTP_PASSWORD_FILE: /run/secrets/transteira_system_smtp_password",
			"file: ${SECRETS_DIR:-./secrets}/system_smtp_password",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("missing %q in\n%s", want, out)
			}
		}
	}
	if strings.Contains(sqlite, "migrate:") || !strings.Contains(pg, "  migrate:\n") {
		t.Error("the migrate service must get the secret with PostgreSQL only")
	}
}

func TestRenderCaddyfile(t *testing.T) {
	src := `"$ROOT/integrations/reverse-proxy/caddy/Caddyfile.on-demand"`
	prod := mustShell(t, `render_caddyfile `+src+` admin.transfer.example.org ops@example.org 0`)
	for _, want := range []string{"\n\temail ops@example.org\n", "\nadmin.transfer.example.org {\n", "\thttps:// {", "on_demand\n", "ask http://transteira:8080/tls/ask"} {
		if want == "\thttps:// {" {
			want = "\nhttps:// {\n"
		}
		if !strings.Contains(prod, want) {
			t.Errorf("missing %q", want)
		}
	}
	for _, bad := range []string{"acme-contact@example.com", "admin.transfer.example.com {", "local_certs"} {
		if strings.Contains(prod, bad) {
			t.Errorf("production Caddyfile contains %q", bad)
		}
	}
	test := mustShell(t, `render_caddyfile `+src+` admin.localhost "" 1`)
	if !strings.Contains(test, "{\n\t# TEST MODE") || !strings.Contains(test, "\tlocal_certs\n") ||
		!strings.Contains(test, "# No ACME contact address") || strings.Contains(test, "\temail ") {
		t.Errorf("test-mode Caddyfile:\n%s", test)
	}
	f := filepath.Join(t.TempDir(), "Caddyfile")
	if err := os.WriteFile(f, []byte("{\n}\nexample.org {\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, errOut, code := shell(t, `render_caddyfile "$F" a.example.org "" 0`, "F="+f); code == 0 || !strings.Contains(errOut, "was not found") {
		t.Fatalf("a Caddyfile without the markers must fail: exit %d, %q", code, errOut)
	}
}

func TestRenderNft(t *testing.T) {
	out := mustShell(t, `render_nft 22 2222`)
	for _, want := range []string{
		"table inet transteira_fw\ndelete table inet transteira_fw\n", "type filter hook input priority filter; policy drop;",
		`iif "lo" accept`, "ct state established,related accept", "tcp dport { 22, 2222 } accept",
		"meta nfproto ipv4 tcp dport { 80, 443 } accept", "meta nfproto ipv4 udp dport 443 accept",
		"nd-neighbor-solicit", "packet-too-big",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	// 80 and 443 are open over IPv4 only (H1: an IPv6 client relayed by docker-proxy would be seen
	// with the gateway address of the IPv4-only proxy network).
	if regexp.MustCompile(`(?m)^\s*(tcp dport \{ 80, 443 \}|udp dport 443) accept`).MatchString(out) {
		t.Error("80/443 must not be accepted for IPv6")
	}
	for _, bad := range []string{"flush ruleset", "hook forward", "DOCKER", "iptables"} {
		if strings.Contains(out, bad) {
			t.Errorf("the ruleset must not contain %q", bad)
		}
	}
	unit := mustShell(t, `render_fw_unit`)
	if !strings.Contains(unit, "ExecStart=/usr/sbin/nft -f /etc/transteira/firewall.nft") ||
		!strings.Contains(unit, "ExecStop=/usr/sbin/nft delete table inet transteira_fw") || strings.Contains(unit, "flush") {
		t.Errorf("unit:\n%s", unit)
	}
}

func TestSSHPorts(t *testing.T) {
	// Under sudo, SSH_CONNECTION is dropped: the ports come from sshd -T (port and listenaddress),
	// the sshd sockets (ss) and an active ssh.socket; other processes are ignored.
	bin := t.TempDir()
	writeStub(t, bin, "sshd", "#!/bin/sh\nprintf 'port 22\\nlistenaddress 0.0.0.0:2224\\nlistenaddress [::]:2224\\naddressfamily any\\n'\n")
	writeStub(t, bin, "ss", `#!/bin/sh
case "$1" in
-Hltnp)
	echo 'LISTEN 0 128 0.0.0.0:2222 0.0.0.0:* users:(("sshd",pid=10,fd=3))'
	echo 'LISTEN 0 128 [::]:2222 [::]:* users:(("sshd",pid=10,fd=4))'
	echo 'LISTEN 0 4096 0.0.0.0:8080 0.0.0.0:* users:(("docker-proxy",pid=11,fd=4))'
	;;
-Htnp)
	echo '0 0 192.0.2.2:2201 192.0.2.1:50000 users:(("sshd-session",pid=12,fd=4))'
	echo '0 0 192.0.2.2:443 192.0.2.9:40000 users:(("caddy",pid=13,fd=9))'
	;;
esac
`)
	writeStub(t, bin, "systemctl", `#!/bin/sh
case "$1" in
is-active) exit 0 ;;
show) echo 'Listen=[::]:2223 (Stream)' ;;
*) exit 1 ;;
esac
`)
	out := mustShell(t, `ssh_ports`, "PATH="+bin+":"+os.Getenv("PATH"), "SSH_CONNECTION=")
	if out != "22\n2201\n2222\n2223\n2224\n" {
		t.Fatalf("got %q", out)
	}
	// The session port, when its variables reach the script.
	out = mustShell(t, `ssh_ports`, "PATH="+bin+":"+os.Getenv("PATH"), "SSH_CONNECTION=192.0.2.1 50000 192.0.2.2 2200")
	if !strings.Contains(out, "\n2200\n") {
		t.Fatalf("session port missing: %q", out)
	}
	empty := t.TempDir()
	for _, c := range []string{"sshd", "ss", "systemctl"} {
		writeStub(t, empty, c, "#!/bin/sh\nexit 1\n")
	}
	out = mustShell(t, `ssh_ports`, "PATH="+empty+":"+os.Getenv("PATH"), "SSH_CONNECTION=")
	if out != "22\n" {
		t.Fatalf("fallback: got %q", out)
	}
}

func TestRenderJail(t *testing.T) {
	out := mustShell(t, `render_jail "$ROOT/integrations/fail2ban/jail.d/transteira.local" /srv/docker/volumes/transteira_logs/_data/security.log`)
	if n := strings.Count(out, "\nlogpath  = /srv/docker/volumes/transteira_logs/_data/security.log\n"); n != 2 {
		t.Errorf("logpath rendered %d times, want 2", n)
	}
	if n := strings.Count(out, "\nignoreip = 127.0.0.1/8 ::1\n"); n != 2 {
		t.Errorf("ignoreip rendered %d times, want 2", n)
	}
	for _, bad := range []string{"192.0.2.0/24", "198.51.100.10", "2001:db8"} {
		if regexp.MustCompile(`(?m)^ignoreip.*` + regexp.QuoteMeta(bad)).MatchString(out) {
			t.Errorf("documentation range %s left in ignoreip", bad)
		}
	}
	if !strings.Contains(out, "chain=DOCKER-USER") {
		t.Error("the DOCKER-USER action of the reference jail must be kept")
	}
	// HTTP/3 (443/udp, published by Caddy) is banned too, in both jails.
	for _, name := range []string{"transteira-udp", "transteira-sso-udp"} {
		if !strings.Contains(out, "iptables-multiport[name="+name+`, port="https", protocol=udp, chain=DOCKER-USER]`) {
			t.Errorf("no UDP ban action %s in the jails", name)
		}
	}
}

func TestRenderUnattended(t *testing.T) {
	out := mustShell(t, `render_unattended; render_auto_upgrades`)
	for _, want := range []string{
		"#clear Unattended-Upgrade::Origins-Pattern;",
		`"origin=Debian,codename=${distro_codename}-security,label=Debian-Security";`,
		`APT::Periodic::Unattended-Upgrade "1";`, `Unattended-Upgrade::Automatic-Reboot "false";`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(out, "label=Debian\"") || strings.Contains(out, "-updates") {
		t.Error("only the security archive may be enabled")
	}
}

func TestTestModeGuard(t *testing.T) {
	out := mustShell(t, `test_mode && echo on || echo off`)
	if strings.TrimSpace(out) != "off" {
		t.Fatalf("unset: %q", out)
	}
	out = mustShell(t, `test_mode && echo on || echo off`, "TT_INSTALL_TEST_MODE=insecure-test-only")
	if strings.TrimSpace(out) != "on" {
		t.Fatalf("exact value: %q", out)
	}
	_, errOut, code := shell(t, `test_mode && echo on`, "TT_INSTALL_TEST_MODE=1")
	if code == 0 || !strings.Contains(errOut, "unknown value") {
		t.Fatalf("TT_INSTALL_TEST_MODE=1 must be refused: exit %d, %q", code, errOut)
	}
}

func TestStateValue(t *testing.T) {
	f := filepath.Join(t.TempDir(), "install.conf")
	if err := os.WriteFile(f, []byte("# x\nTTI_STATE=installed\nTTI_ENGINE=$(touch /tmp/x)\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := mustShell(t, `state_value "$F" TTI_STATE; state_value "$F" TTI_ENGINE; state_value "$F" NOPE; echo end`, "F="+f)
	if out != "installed\n$(touch /tmp/x)\nend\n" {
		t.Fatalf("got %q", out)
	}
}

// TestCosignPins keeps the cosign release of the installer equal to the one of the Makefile.
func TestCosignPins(t *testing.T) {
	pins, err := os.ReadFile("cosign.pins")
	if err != nil {
		t.Fatal(err)
	}
	mk, err := os.ReadFile(filepath.Join(repoRoot(t), "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	pin := regexp.MustCompile(`(?m)^COSIGN_VERSION=(v[0-9.]+)$`).FindSubmatch(pins)
	mkPin := regexp.MustCompile(`cosign/v3/cmd/cosign@(v[0-9.]+)`).FindSubmatch(mk)
	if pin == nil || mkPin == nil || string(pin[1]) != string(mkPin[1]) {
		t.Fatalf("cosign.pins COSIGN_VERSION %q differs from the Makefile cosign %q", pin, mkPin)
	}
	for _, k := range []string{"COSIGN_SHA256_LINUX_AMD64", "COSIGN_SHA256_LINUX_ARM64"} {
		if !regexp.MustCompile(`(?m)^` + k + `=[0-9a-f]{64}$`).Match(pins) {
			t.Errorf("cosign.pins: %s missing or malformed", k)
		}
	}
	// The default cosign of the install-smoke harness, run on its own.
	smoke, err := os.ReadFile(filepath.Join(repoRoot(t), "scripts", "install-smoke.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(smoke), "cosign/v3/cmd/cosign@"+string(pin[1])+"}") {
		t.Errorf("scripts/install-smoke.sh: the default COSIGN is not cosign %s", pin[1])
	}
	// The cosign bootstrap of the quick install guides (verification of install.sh on a blank
	// server): same release and checksums.
	for _, doc := range []string{"docs/install/quick-install.md", "docs/install/fr/quick-install.md"} {
		b, err := os.ReadFile(filepath.Join(repoRoot(t), doc))
		if err != nil {
			t.Fatal(err)
		}
		for _, k := range []string{"COSIGN_SHA256_LINUX_AMD64", "COSIGN_SHA256_LINUX_ARM64"} {
			v := regexp.MustCompile(`(?m)^` + k + `=([0-9a-f]{64})$`).FindSubmatch(pins)
			if v == nil || !bytes.Contains(b, v[1]) {
				t.Errorf("%s: the %s of cosign.pins is missing", doc, k)
			}
		}
		if !bytes.Contains(b, []byte("releases/download/"+string(pin[1])+"/cosign-linux-amd64")) {
			t.Errorf("%s: the cosign download is not %s", doc, pin[1])
		}
	}
}

// TestTemplateHasNoImageRepository: the image repository is baked at release time only.
func TestTemplateHasNoImageRepository(t *testing.T) {
	b, err := os.ReadFile(template)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "TTI_IMAGE_REPO='@TTI_IMAGE_REPO@'") {
		t.Error("TTI_IMAGE_REPO must stay a placeholder in the template")
	}
	if regexp.MustCompile(`(docker\.io|ghcr\.io|quay\.io)/[a-z0-9]`).Match(b) {
		t.Error("the template names an image repository: it must only be baked by build.sh")
	}
}

func writeStub(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
}

// build runs build.sh with dummy release values and returns the generated script.
func build(t *testing.T, dir string) string {
	t.Helper()
	needBash(t)
	hex := func(c string) string { return strings.Repeat(c, 64) }
	img := filepath.Join(dir, "image-digest.txt")
	plat := filepath.Join(dir, "platform-digests.txt")
	if err := os.WriteFile(img, []byte("registry.invalid/example/transteira@sha256:"+hex("a")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(plat, []byte("linux/amd64 sha256:"+hex("b")+"\nlinux/arm64 sha256:"+hex("c")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "install.sh")
	cmd := exec.Command("bash", "build.sh")
	cmd.Env = append(os.Environ(), "INSTALL_VERSION=9.8.7", "RELEASE_IMAGE=registry.invalid/example/transteira",
		"INSTALL_IMAGE_DIGEST_FILE="+img, "INSTALL_PLATFORM_DIGESTS_FILE="+plat, "INSTALL_OUT="+out, "TMPDIR="+t.TempDir())
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build.sh: %v\n%s", err, b)
	}
	return out
}

func TestBuild(t *testing.T) {
	a := build(t, t.TempDir())
	b := build(t, t.TempDir())
	ab, err := os.ReadFile(a)
	if err != nil {
		t.Fatal(err)
	}
	bb, err := os.ReadFile(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ab, bb) {
		t.Fatal("two builds from the same inputs differ: the installer is not deterministic")
	}
	s := string(ab)
	if regexp.MustCompile(`@TTI_[A-Z0-9_]+@`).MatchString(s) {
		t.Error("placeholders left in the generated script")
	}
	pub, err := os.ReadFile(filepath.Join(repoRoot(t), "cosign.pub"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"TTI_VERSION='9.8.7'", "TTI_IMAGE_REPO='registry.invalid/example/transteira'",
		"TTI_INDEX_DIGEST='sha256:" + strings.Repeat("a", 64) + "'",
		"TTI_PLATFORM_DIGESTS='linux/amd64=sha256:" + strings.Repeat("b", 64) + " linux/arm64=sha256:" + strings.Repeat("c", 64) + "'",
		"TTI_COSIGN_VERSION='v3.1.4'", "TTI_COSIGN_PUB='" + strings.TrimSpace(string(pub)) + "'",
		"\n__TRANSTEIRA_INSTALL_PAYLOAD_BELOW__\n",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("generated script lacks %q", want)
		}
	}
	if out, err := exec.Command("bash", a, "--version").Output(); err != nil || string(out) != "9.8.7\n" {
		t.Errorf("--version: %q, %v", out, err)
	}
}

func TestBuildRejects(t *testing.T) {
	needBash(t)
	dir := t.TempDir()
	img := filepath.Join(dir, "img")
	plat := filepath.Join(dir, "plat")
	good := "linux/amd64 sha256:" + strings.Repeat("b", 64) + "\n"
	cases := []struct{ name, version, repo, img, plat, msg string }{
		{"bad version", "v2", "r.invalid/x", "r.invalid/x@sha256:" + strings.Repeat("a", 64), good, "not a SemVer"},
		{"tagged repo", "1.0.0", "r.invalid/x:1", "r.invalid/x:1@sha256:" + strings.Repeat("a", 64), good, "without tag or digest"},
		{"other repo", "1.0.0", "r.invalid/x", "r.invalid/y@sha256:" + strings.Repeat("a", 64), good, "not RELEASE_IMAGE"},
		{"short digest", "1.0.0", "r.invalid/x", "r.invalid/x@sha256:abc", good, "expected <repository>@sha256"},
		{"bad platform", "1.0.0", "r.invalid/x", "r.invalid/x@sha256:" + strings.Repeat("a", 64), "linux/s390x sha256:" + strings.Repeat("b", 64), "unsupported platform"},
		{"quote in digest", "1.0.0", "r.invalid/x", "r.invalid/x@sha256:" + strings.Repeat("a", 64), "linux/amd64 sha256:'$(id)'", "bad digest"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := os.WriteFile(img, []byte(c.img+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(plat, []byte(c.plat), 0o600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("bash", "build.sh")
			cmd.Env = append(os.Environ(), "INSTALL_VERSION="+c.version, "RELEASE_IMAGE="+c.repo,
				"INSTALL_IMAGE_DIGEST_FILE="+img, "INSTALL_PLATFORM_DIGESTS_FILE="+plat,
				"INSTALL_OUT="+filepath.Join(dir, "out.sh"), "TMPDIR="+t.TempDir())
			b, err := cmd.CombinedOutput()
			if err == nil || !strings.Contains(string(b), c.msg) {
				t.Fatalf("want a failure with %q, got %v\n%s", c.msg, err, b)
			}
		})
	}
	if _, err := os.Stat(filepath.Join(dir, "out.sh")); err == nil {
		t.Error("a rejected build must not leave an output file")
	}
}

// TestDryRunTouchesNothing runs the built installer with --dry-run, as a normal user, with stub
// commands first on its PATH: any call to a command that changes the machine fails the test.
func TestDryRunTouchesNothing(t *testing.T) {
	dir := t.TempDir()
	script := build(t, dir)
	bin := t.TempDir()
	marks := filepath.Join(t.TempDir(), "calls")
	for _, c := range []string{
		"apt-get", "apt", "docker", "nft", "systemctl", "curl", "wget", "fail2ban-client", "gpg", "install",
		"chown", "useradd", "iptables", "sudo",
	} {
		writeStub(t, bin, c, "#!/bin/sh\necho \""+c+" $*\" >> \""+marks+"\"\nexit 1\n")
	}
	writeStub(t, bin, "sshd", "#!/bin/sh\necho 'port 2222'\n")
	// Read-only queries of ssh_ports: allowed, they answer nothing.
	writeStub(t, bin, "systemctl", "#!/bin/sh\ncase \"$1\" in is-active|show) exit 1 ;; esac\necho \"systemctl $*\" >> \""+marks+"\"\nexit 1\n")
	writeStub(t, bin, "ss", "#!/bin/sh\nexit 0\n")
	writeStub(t, bin, "dpkg", "#!/bin/sh\n[ \"$1\" = --print-architecture ] && echo arm64\n")
	tmp := t.TempDir()
	cmd := exec.Command("bash", script, "--dry-run", "--admin-host", "admin.transfer.example.org", "--acme-email", "ops@example.org",
		"--smtp-host", "relay.internal", "--smtp-security", "none", "--smtp-from", "tt@example.org", "--no-fail2ban")
	cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "TMPDIR="+tmp, "SSH_CONNECTION=")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("dry run: %v\n%s", err, out)
	}
	if calls, err := os.ReadFile(marks); err == nil {
		t.Fatalf("the dry run called commands that change the machine:\n%s", calls)
	}
	for _, want := range []string{
		"=== DRY RUN: nothing is changed on this machine ===", "TransTeira 9.8.7",
		"linux/arm64: sha256:" + strings.Repeat("c", 64), "TT_TLS_ASK_ALLOWED_IPS=172.30.0.10",
		"TT_SYSTEM_SMTP_HOST=relay.internal", "TT_SYSTEM_SMTP_PORT=25", "\temail ops@example.org",
		"admin.transfer.example.org {", "(SSH 2222 80/tcp 443/tcp 443/udp)", "=== DRY RUN: end ===",
	} {
		if !strings.Contains(string(out), want) {
			t.Errorf("dry run output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(string(out), "fail2ban:") {
		t.Error("--no-fail2ban: the plan must not list fail2ban")
	}
	if left, _ := os.ReadDir(tmp); len(left) != 0 {
		t.Errorf("the dry run left %d entries in TMPDIR", len(left))
	}
	// A corrupted payload is refused.
	b, err := os.ReadFile(script)
	if err != nil {
		t.Fatal(err)
	}
	i := bytes.LastIndex(b, []byte("\n")) - 10
	b[i] ^= 1
	bad := filepath.Join(dir, "bad.sh")
	if err := os.WriteFile(bad, b, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd = exec.Command("bash", bad, "--dry-run", "--admin-host", "a.example.org", "--acme-email", "")
	cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "TMPDIR="+t.TempDir())
	if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "payload") {
		t.Fatalf("a corrupted payload must be refused: %v\n%s", err, out)
	}
}

func TestDryRunRefusesUnknownTestMode(t *testing.T) {
	script := build(t, t.TempDir())
	cmd := exec.Command("bash", script, "--dry-run", "--admin-host", "a.example.org", "--acme-email", "")
	cmd.Env = append(os.Environ(), "TT_INSTALL_TEST_MODE=yes", "TMPDIR="+t.TempDir())
	if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "unknown value") {
		t.Fatalf("want a refusal: %v\n%s", err, out)
	}
}

func TestRenderSSHDJournal(t *testing.T) {
	out := mustShell(t, `render_sshd_journal`)
	if !strings.Contains(out, "[sshd]\nbackend = systemd\n") {
		t.Fatalf("got\n%s", out)
	}
}
