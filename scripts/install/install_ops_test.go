package install_test

// Tests of the installer steps that touch files or call system commands: every path is a
// temporary folder set after sourcing the template, and every system command is a stub first on
// PATH, so nothing outside the test folders is read or changed.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// stubPath writes the stubs (name -> body) in a new folder and returns a PATH starting with it.
func stubPath(t *testing.T, stubs map[string]string) string {
	t.Helper()
	bin := t.TempDir()
	for name, body := range stubs {
		writeStub(t, bin, name, body)
	}
	return "PATH=" + bin + ":" + os.Getenv("PATH")
}

func TestSetEnvImage(t *testing.T) {
	f := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(f, []byte("A=1\nTRANSTEIRA_IMAGE=old@sha256:aa\n# c\nB=2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	mustShell(t, `IMAGE_REF=registry.invalid/x/y@sha256:bb; set_env_image "$F"`, "F="+f)
	b, err := os.ReadFile(f)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "A=1\nTRANSTEIRA_IMAGE=registry.invalid/x/y@sha256:bb\n# c\nB=2\n" {
		t.Fatalf("got %q", b)
	}
	if st, _ := os.Stat(f); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, want 0600", st.Mode().Perm())
	}
	g := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(g, []byte("A=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, errOut, code := shell(t, `IMAGE_REF=x; set_env_image "$F"`, "F="+g); code == 0 || !strings.Contains(errOut, "no TRANSTEIRA_IMAGE") {
		t.Fatalf("a .env without TRANSTEIRA_IMAGE must be refused: exit %d, %q", code, errOut)
	}
}

func TestCopyDeployFiles(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	for name, body := range map[string]string{
		"docker-compose.yml": "new compose", ".env": "payload env", "secrets/master_key": "payload key",
		"init-secrets.sh": "new script",
	} {
		p := filepath.Join(src, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range map[string]string{
		"docker-compose.yml": "old compose", ".env": "kept env", "secrets/master_key": "kept key",
		"docker-compose.installer-smtp.yml": "kept overlay",
	} {
		p := filepath.Join(dst, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	mustShell(t, `DEPLOY_DIR=$D; copy_deploy_files "$S"`, "D="+dst, "S="+src)
	for name, want := range map[string]string{
		"docker-compose.yml": "new compose", "init-secrets.sh": "new script", ".env": "kept env",
		"secrets/master_key": "kept key", "docker-compose.installer-smtp.yml": "kept overlay",
	} {
		b, err := os.ReadFile(filepath.Join(dst, name))
		if err != nil || string(b) != want {
			t.Errorf("%s: got %q (%v), want %q", name, b, err, want)
		}
	}
	// Explicit destination (staging folder of --upgrade).
	stage := filepath.Join(t.TempDir(), "stage")
	mustShell(t, `copy_deploy_files "$S" "$G"`, "S="+src, "G="+stage)
	if _, err := os.Stat(filepath.Join(stage, "docker-compose.yml")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(stage, ".env")); !os.IsNotExist(err) {
		t.Fatal("the payload .env must never be copied")
	}
}

func TestInstallState(t *testing.T) {
	noDocker := stubPath(t, map[string]string{"docker": "#!/bin/sh\nexit 1\n"})
	withContainer := stubPath(t, map[string]string{"docker": "#!/bin/sh\n[ \"$1 $2 $3\" = 'container inspect transteira' ]\n"})
	cases := []struct {
		name, state, path, want string
		env, caddy              bool
	}{
		{"blank", "", noDocker, "none", false, false},
		{"installing", "TTI_STATE=installing\n", noDocker, "installing", true, false},
		{"installed", "TTI_STATE=installed\n", noDocker, "installed", true, true},
		{"foreign env", "", noDocker, "foreign", true, false},
		{"foreign caddyfile", "", noDocker, "foreign", false, true},
		{"foreign container", "", withContainer, "foreign", false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.MkdirAll(filepath.Join(dir, "deploy"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(dir, "proxy"), 0o755); err != nil {
				t.Fatal(err)
			}
			if c.state != "" {
				if err := os.WriteFile(filepath.Join(dir, "install.conf"), []byte(c.state), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if c.env {
				if err := os.WriteFile(filepath.Join(dir, "deploy", ".env"), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if c.caddy {
				if err := os.WriteFile(filepath.Join(dir, "proxy", "Caddyfile"), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			out := mustShell(t, `STATE_FILE=$X/install.conf DEPLOY_DIR=$X/deploy PROXY_DIR=$X/proxy install_state`, "X="+dir, c.path)
			if strings.TrimSpace(out) != c.want {
				t.Fatalf("got %q, want %q", out, c.want)
			}
		})
	}
}

func TestRegistryHost(t *testing.T) {
	out := mustShell(t, `for r in docker.io/x/y localhost:5000/x localhost/x x/y ghcr.io/a/b 127.0.0.1:5000/a; do registry_host "$r"; done`)
	want := "docker.io\nlocalhost:5000\nlocalhost\nregistry-1.docker.io\nghcr.io\n127.0.0.1:5000\n"
	if out != want {
		t.Fatalf("got %q, want %q", out, want)
	}
}

// The log line of internal/app/app.go (JSON handler of slog), as the container prints it.
const tokenLog = `{"time":"2026-11-10T10:00:00Z","level":"WARN","msg":"No admin exists yet. Setup token: stp_AbC-12_x (valid until restart). Open https://admin.transfer.example.com/admin/setup"}`

func dockerLogsStub(t *testing.T) string {
	t.Helper()
	return stubPath(t, map[string]string{
		"docker": "#!/bin/sh\n[ \"$1\" = logs ] || exit 1\necho 'starting'\necho '" + tokenLog + "' >&2\n",
	})
}

func TestSetupToken(t *testing.T) {
	out := mustShell(t, `setup_token`, dockerLogsStub(t))
	if out != "stp_AbC-12_x\n" {
		t.Fatalf("got %q", out)
	}
	none := stubPath(t, map[string]string{"docker": "#!/bin/sh\necho 'listening'\n"})
	if out := mustShell(t, `setup_token`, none); out != "" {
		t.Fatalf("no token: got %q", out)
	}
}

// TestSummaryHidesTokenWithYes: with --yes the output goes to automation logs, so the summary
// gives the command that reads the token, not the token.
func TestSummaryHidesTokenWithYes(t *testing.T) {
	out := mustShell(t, `OPT_YES=1 CFG_ADMIN_HOST=admin.transfer.example.com summary`, dockerLogsStub(t))
	if strings.Contains(out, "stp_AbC-12_x") {
		t.Fatalf("the token is printed with --yes:\n%s", out)
	}
	for _, want := range []string{"https://admin.transfer.example.com/admin/setup", "docker logs transteira 2>&1 | grep 'Setup token'", "MASTER KEY"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
}

func TestDockerKeyOK(t *testing.T) {
	const good = "9DC858229FC7DD38854AE2D88D81803C0EBFCD88"
	key := filepath.Join(t.TempDir(), "docker.asc")
	if err := os.WriteFile(key, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, colons string
		ok           bool
	}{
		{"genuine", "pub:-:4096:1:8D81803C0EBFCD88:1487788586:::-:::scSE:::::::\nfpr:::::::::" + good + ":\nuid:-::::1487792064::X::Docker Release (CE deb) <docker@docker.com>::::::::::0:\nsub:-:4096:1:7EA0A9C3F273FCD8:1487788586::::::s::::::\nfpr:::::::::D3306A018370199E527AE7997EA0A9C3F273FCD8:\n", true},
		{"second key appended", "pub:-:4096:1:8D81803C0EBFCD88:1::::::scSE:\nfpr:::::::::" + good + ":\npub:-:4096:1:AAAAAAAAAAAAAAAA:1::::::scSE:\nfpr:::::::::AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:\n", false},
		{"other key", "pub:-:4096:1:AAAAAAAAAAAAAAAA:1::::::scSE:\nfpr:::::::::AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:\n", false},
		{"no key", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			colons := filepath.Join(t.TempDir(), "colons")
			if err := os.WriteFile(colons, []byte(c.colons), 0o600); err != nil {
				t.Fatal(err)
			}
			path := stubPath(t, map[string]string{"gpg": "#!/bin/sh\ncat '" + colons + "'\n"})
			out := mustShell(t, `docker_key_ok "$K" && echo ok || echo refused`, path, "K="+key)
			if want := map[bool]string{true: "ok\n", false: "refused\n"}[c.ok]; out != want {
				t.Fatalf("got %q, want %q", out, want)
			}
		})
	}
}

func TestDockerVersionsOK(t *testing.T) {
	stub := func(server, compose string) string {
		return stubPath(t, map[string]string{"docker": `#!/bin/sh
case "$1" in
info) exit 0 ;;
version) echo '` + server + `' ;;
compose) echo '` + compose + `' ;;
esac
`})
	}
	if out := mustShell(t, `docker_versions_ok && echo ok`, stub("28.5.1", "v2.40.3")); out != "ok\n" {
		t.Fatalf("recent Docker: %q", out)
	}
	for _, c := range []struct{ server, compose, msg string }{
		{"20.10.24+dfsg1", "2.40.0", "Docker Engine '20.10.24+dfsg1' is too old"},
		{"28.5.1", "2.20.2", "Docker Compose '2.20.2' is too old"},
		{"", "2.40.0", "Docker Engine '' is too old"},
	} {
		if _, errOut, code := shell(t, `docker_versions_ok`, stub(c.server, c.compose)); code == 0 || !strings.Contains(errOut, c.msg) {
			t.Errorf("%s/%s: exit %d, %q, want %q", c.server, c.compose, code, errOut, c.msg)
		}
	}
	down := stubPath(t, map[string]string{"docker": "#!/bin/sh\nexit 1\n"})
	if _, errOut, code := shell(t, `docker_versions_ok`, down); code == 0 || !strings.Contains(errOut, "does not answer") {
		t.Errorf("daemon down: exit %d, %q", code, errOut)
	}
}

func TestDockerDaemonConfig(t *testing.T) {
	var cfg map[string]any
	if err := json.Unmarshal([]byte(mustShell(t, `render_daemon_json`)), &cfg); err != nil {
		t.Fatal(err)
	}
	if v, ok := cfg["userland-proxy"]; !ok || v != false {
		t.Fatalf("render_daemon_json: %v", cfg)
	}
	// Docker not installed yet: the file is written, nothing is restarted.
	calls := filepath.Join(t.TempDir(), "calls")
	path := stubPath(t, map[string]string{
		"systemctl": "#!/bin/sh\necho \"systemctl $*\" >> '" + calls + "'\nexit 1\n",
		"docker":    "#!/bin/sh\necho \"docker $*\" >> '" + calls + "'\nexit 1\n",
	})
	f := filepath.Join(t.TempDir(), "docker", "daemon.json")
	mustShell(t, `DOCKER_DAEMON_JSON=$F docker_daemon_config`, path, "F="+f)
	b, err := os.ReadFile(f)
	if err != nil || !strings.Contains(string(b), `"userland-proxy": false`) {
		t.Fatalf("daemon.json: %q, %v", b, err)
	}
	if c, _ := os.ReadFile(calls); strings.Contains(string(c), "restart") {
		t.Fatalf("nothing may be restarted: %s", c)
	}
	// An existing file is never changed; a warning says it lacks the setting.
	g := filepath.Join(t.TempDir(), "daemon.json")
	if err := os.WriteFile(g, []byte(`{"log-driver": "local"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, errOut, code := shell(t, `DOCKER_DAEMON_JSON=$F docker_daemon_config`, path, "F="+g)
	if code != 0 || !strings.Contains(errOut, `does not set "userland-proxy": false`) {
		t.Fatalf("exit %d, %q", code, errOut)
	}
	if b, _ := os.ReadFile(g); string(b) != `{"log-driver": "local"}` {
		t.Fatalf("existing daemon.json changed: %q", b)
	}
}

func TestAptGetWaitsForLock(t *testing.T) {
	dir := t.TempDir()
	count := filepath.Join(dir, "count")
	path := stubPath(t, map[string]string{
		"apt-get": `#!/bin/sh
n=$(cat '` + count + `' 2>/dev/null || echo 0)
n=$((n + 1))
echo "$n" > '` + count + `'
echo "args: $*"
if [ "$n" -lt 3 ]; then echo 'E: Could not get lock /var/lib/dpkg/lock-frontend. It is held by process 42 (apt-get)' >&2; exit 100; fi
`,
		"sleep": "#!/bin/sh\nexit 0\n",
	})
	log := filepath.Join(dir, "install.log")
	out := mustShell(t, `LOG_FILE=$L; apt_get update -q && echo done`, path, "L="+log)
	if !strings.HasSuffix(out, "done\n") || !strings.Contains(out, "waiting") {
		t.Fatalf("got %q", out)
	}
	if b, _ := os.ReadFile(count); strings.TrimSpace(string(b)) != "3" {
		t.Fatalf("apt-get called %s times, want 3", b)
	}
	if b, _ := os.ReadFile(log); !strings.Contains(string(b), "args: -o DPkg::Lock::Timeout=600 update -q") {
		t.Fatalf("log: %s", b)
	}
	// Any other failure stops at once.
	fail := stubPath(t, map[string]string{"apt-get": "#!/bin/sh\necho 'E: Unable to locate package nope' >&2\nexit 100\n"})
	if _, errOut, code := shell(t, `LOG_FILE=$L; apt_get install nope`, fail, "L="+log); code == 0 || !strings.Contains(errOut, "command failed: apt-get install nope") {
		t.Fatalf("exit %d, %q", code, errOut)
	}
}

func TestResumeLoad(t *testing.T) {
	setup := func(t *testing.T, state string) string {
		dir := t.TempDir()
		for _, d := range []string{"deploy", "proxy"} {
			if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(dir, "deploy", ".env"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "install.conf"), []byte(state), 0o600); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	const paths = `STATE_FILE=$X/install.conf; DEPLOY_DIR=$X/deploy; PROXY_DIR=$X/proxy; `
	saved := "TTI_STATE=installing\nTTI_ENGINE=postgres\nTTI_ADMIN_HOST=admin.transfer.example.com\nTTI_ACME_EMAIL=ops@example.com\n" +
		"TTI_SMTP_HOST=smtp.example.com\nTTI_SMTP_PORT=587\nTTI_SMTP_SECURITY=starttls\nTTI_SMTP_FROM=tt@example.com\nTTI_SMTP_USER=bob\n"
	dir := setup(t, saved)
	out := mustShell(t, paths+`parse_args --yes --admin-host admin.transfer.example.com; resume_load; echo "$RESUMED $OPT_ADMIN_HOST $OPT_ACME_EMAIL/$OPT_ACME_EMAIL_SET $OPT_POSTGRES $OPT_SMTP_HOST $OPT_SMTP_PORT $OPT_SMTP_SECURITY $OPT_SMTP_FROM $OPT_SMTP_USER"`, "X="+dir)
	if out != "1 admin.transfer.example.com ops@example.com/1 1 smtp.example.com 587 starttls tt@example.com bob\n" {
		t.Fatalf("got %q", out)
	}
	// The saved answers pass collect_config: the SMTP secret already written is kept.
	out = mustShell(t, paths+`parse_args --yes; resume_load; collect_config; echo "$CFG_ENGINE $CFG_ADMIN_HOST $CFG_SMTP_USER $CFG_SMTP_PASSWORD_SOURCE"`, "X="+dir)
	if out != "postgres admin.transfer.example.com bob kept\n" {
		t.Fatalf("collect_config after resume_load: %q", out)
	}
	for _, c := range []struct{ name, args, msg string }{
		{"other host", `--yes --admin-host other.example.com`, "with --admin-host 'admin.transfer.example.com'"},
		{"other acme", `--yes --acme-email x@example.com`, "with --acme-email 'ops@example.com'"},
		{"other smtp", `--yes --smtp-host relay.example.com --smtp-from tt@example.com`, "with --smtp-host 'smtp.example.com'"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, errOut, code := shell(t, paths+`parse_args `+c.args+`; resume_load`, "X="+dir); code == 0 || !strings.Contains(errOut, c.msg) {
				t.Fatalf("exit %d, %q, want %q", code, errOut, c.msg)
			}
		})
	}
	sqlite := setup(t, "TTI_STATE=installing\nTTI_ENGINE=sqlite\nTTI_ADMIN_HOST=admin.transfer.example.com\nTTI_ACME_EMAIL=\n")
	if _, errOut, code := shell(t, paths+`parse_args --yes --postgres; resume_load`, "X="+sqlite); code == 0 || !strings.Contains(errOut, "rerun without --postgres") {
		t.Fatalf("--postgres on a SQLite resume: exit %d, %q", code, errOut)
	}
	if _, errOut, code := shell(t, paths+`parse_args --yes --smtp-host relay.example.com --smtp-from tt@example.com; resume_load`, "X="+sqlite); code == 0 || !strings.Contains(errOut, "without a system SMTP server") {
		t.Fatalf("SMTP added on resume: exit %d, %q", code, errOut)
	}
	// Nothing written yet: the new answers are free.
	fresh := t.TempDir()
	out = mustShell(t, paths+`parse_args --yes --admin-host new.example.com; resume_load; echo "$RESUMED $OPT_ADMIN_HOST"`, "X="+fresh)
	if out != "0 new.example.com\n" {
		t.Fatalf("no files yet: %q", out)
	}
}

func TestPreflightDNS(t *testing.T) {
	path := stubPath(t, map[string]string{
		"getent": "#!/bin/sh\necho '2001:db8::5 STREAM admin.transfer.example.com'\necho '192.0.2.5 STREAM'\n",
		"ip":     "#!/bin/sh\necho '2: eth0    inet 192.0.2.5/24 brd 192.0.2.255 scope global eth0'\n",
	})
	_, errOut, code := shell(t, `CFG_ADMIN_HOST=admin.transfer.example.com preflight_dns`, path)
	if code != 0 || !strings.Contains(errOut, "IPv6 (AAAA) record") || strings.Contains(errOut, "not an address of this server") {
		t.Fatalf("exit %d, %q", code, errOut)
	}
	only6 := stubPath(t, map[string]string{"getent": "#!/bin/sh\necho '2001:db8::5 STREAM'\n", "ip": "#!/bin/sh\n"})
	_, errOut, _ = shell(t, `CFG_ADMIN_HOST=admin.transfer.example.com preflight_dns`, only6)
	if !strings.Contains(errOut, "no IPv4 (A) record") {
		t.Fatalf("AAAA only: %q", errOut)
	}
}

func TestPreflightPortsWithoutSS(t *testing.T) {
	// A PATH without ss (the bash builtins are enough for the warning): the check is skipped
	// with a warning instead of passing silently.
	bin := t.TempDir()
	_, errOut, code := shell(t, `PATH=$B; preflight_ports`, "B="+bin)
	if code != 0 || !strings.Contains(errOut, "ss (iproute2) is missing") {
		t.Fatalf("exit %d, %q", code, errOut)
	}
}
