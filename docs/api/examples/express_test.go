package examples_test

import (
	"bytes"
	"cmp"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/tte2"
)

// The express secret examples (since 2.3, e2e-format.md section 3.3.9): express-secret.go with
// the local Go toolchain, express-secret.py in a Python image built from python/Dockerfile
// (pinned base image, packages of requirements.txt checked against their hashes) and
// express-secret.ps1 in the pinned PowerShell image. Each one reproduces the secret vectors of
// the express profile, seals a text that internal/tte2 opens, and goes through a creation, a
// status and a one-time reveal against a fake TransTeira server that checks that neither the
// text nor the key ever reaches it.

// expressText is the text of the seal and round trip tests: several scripts and planes of
// Unicode, a line break, and a marker that must never reach the server in clear.
const expressText = "Code d'accès : 4F7#kp9 marker-c0ffee-5ecret\nÉté, 日本語, 😀."

// expressMarker is the part of expressText searched for in every request.
const expressMarker = "marker-c0ffee-5ecret"

// testToken is the fake API token of the round trip (the allowed example shape of .gitleaks.toml).
const testToken = "tt_EXAMPLEexpressSecretToken0123456789abcdefghij"

// expressScript runs one of the three express secret examples.
type expressScript struct {
	name string
	// cmd returns the command running the script with args under o.
	cmd func(t *testing.T, o runOpts, args ...string) *exec.Cmd
	// vectorsArgs are the self-test arguments for the shared vectors.
	vectorsArgs func(t *testing.T) []string
	// trustCA returns the environment to trust the PEM certificate at path (round trip).
	trustCA func(path string) map[string]string
	// container is true for the scripts run in a container (Python, PowerShell): their round
	// trips need a container network that reaches the host (requireContainerNetwork).
	container bool
}

// runOpts are the options of a script run.
type runOpts struct {
	// env holds TT_* variables; the host files it names are mounted in a container.
	env map[string]string
	// net is the network through which a container reaches the fake server; nil for none.
	net *dockerNetwork
	// tty runs the script in a container (the Go one included) with a terminal as its standard
	// output and error, and no standard input.
	tty bool
}

// buildOnce is a binary of express-secret.go built once per test run.
type buildOnce struct {
	once sync.Once
	dir  string
	path string
	err  error
}

var (
	// goBinary is express-secret.go for the host; goLinuxBinary for the containers (terminal
	// tests).
	goBinary, goLinuxBinary buildOnce
	pythonImage             struct {
		once sync.Once
		tag  string
		err  error
	}
	containerNet struct {
		once sync.Once
		info string
		err  error
	}
)

// TestMain removes the binaries of express-secret.go built by the tests.
func TestMain(m *testing.M) {
	code := m.Run()
	for _, b := range []*buildOnce{&goBinary, &goLinuxBinary} {
		if b.dir != "" {
			_ = os.RemoveAll(b.dir)
		}
	}
	os.Exit(code)
}

// build builds express-secret.go once into name with the extra environment (go run would link
// it for every call).
func (b *buildOnce) build(t *testing.T, name string, env ...string) string {
	t.Helper()
	goTool := requireTool(t, "go", "version")
	b.once.Do(func() {
		b.dir, b.err = os.MkdirTemp("", "express-secret-")
		if b.err != nil {
			return
		}
		b.path = filepath.Join(b.dir, name)
		cmd := exec.Command(goTool, "build", "-o", b.path, "express-secret.go")
		cmd.Env = append(os.Environ(), env...)
		if out, err := cmd.CombinedOutput(); err != nil {
			b.err = fmt.Errorf("go build express-secret.go: %w\n%s", err, out)
		}
	})
	if b.err != nil {
		t.Fatal(b.err)
	}
	return b.path
}

// expressGoBinary builds express-secret.go for the host once.
func expressGoBinary(t *testing.T) string {
	t.Helper()
	name := "express-secret"
	if runtime.GOOS == "windows" {
		name += ".exe" // exec looks for an executable extension on Windows
	}
	return goBinary.build(t, name)
}

// expressGoLinuxBinary builds express-secret.go once for the containers: Linux, the
// architecture of the Docker server, statically linked.
func expressGoLinuxBinary(t *testing.T, docker string) string {
	t.Helper()
	out, err := exec.Command(docker, "version", "--format", "{{.Server.Arch}}").Output()
	if err != nil {
		t.Fatalf("docker version: %v", err)
	}
	return goLinuxBinary.build(t, "express-secret-linux", "GOOS=linux", "GOARCH="+strings.TrimSpace(string(out)), "CGO_ENABLED=0")
}

// expressPythonImage builds the image of python/Dockerfile once. Its tag is derived from the
// Dockerfile and requirements.txt, so a rerun finds it and needs no network.
func expressPythonImage(t *testing.T, docker string) string {
	t.Helper()
	pythonImage.once.Do(func() {
		h := sha256.New()
		for _, f := range []string{filepath.Join("python", "Dockerfile"), "requirements.txt"} {
			b, err := os.ReadFile(f)
			if err != nil {
				pythonImage.err = err
				return
			}
			h.Write(b)
		}
		tag := "transteira-examples-python:" + hex.EncodeToString(h.Sum(nil))[:16]
		if exec.Command(docker, "image", "inspect", tag).Run() != nil {
			out, err := exec.Command(docker, "build", "-q", "-t", tag, "-f", filepath.Join("python", "Dockerfile"), ".").CombinedOutput()
			if err != nil {
				pythonImage.err = fmt.Errorf("docker build python/Dockerfile: %w\n%s", err, out)
				return
			}
		}
		pythonImage.tag = tag
	})
	if pythonImage.err != nil {
		t.Fatal(pythonImage.err)
	}
	return pythonImage.tag
}

// dockerRun returns docker run arguments for a script of this folder: examples and vectors
// mounted read-only, the network of o (none without one), a terminal with o.tty (no standard
// input then), the environment of o, and the host files mounted read-only (mounts, host path to
// container path). A host file named by the environment (token, CA certificate, link) is
// mounted under /files and the variable names it there: a Windows path is no path in a Linux
// container.
func dockerRun(t *testing.T, o runOpts, mounts map[string]string) []string {
	t.Helper()
	examples, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	vectors := vectorsPath(t)
	args := []string{"run", "--rm", "-i"}
	if o.tty {
		// TERM=dumb: no terminal setup sequence of the runtime in the output.
		args = []string{"run", "--rm", "-t", "-e", "TERM=dumb"}
	}
	if o.net != nil {
		args = append(args, o.net.args...)
	} else {
		args = append(args, "--network", "none")
	}
	args = append(args, "-v", examples+":/examples:ro", "-v", filepath.Dir(vectors)+":/vectors:ro")
	for _, host := range slices.Sorted(maps.Keys(mounts)) {
		args = append(args, "-v", host+":"+mounts[host]+":ro")
	}
	for i, k := range slices.Sorted(maps.Keys(o.env)) {
		v := o.env[k]
		if filepath.IsAbs(v) && fileExists(v) {
			in := fmt.Sprintf("/files/%d-%s", i, filepath.Base(v))
			args = append(args, "-v", v+":"+in+":ro")
			v = in
		}
		args = append(args, "-e", k+"="+v)
	}
	return args
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// expressScripts returns the three examples.
func expressScripts() []expressScript {
	return []expressScript{
		{
			name: "go",
			cmd: func(t *testing.T, o runOpts, args ...string) *exec.Cmd {
				t.Helper()
				if o.tty {
					// A terminal needs a container: the binary for Linux in the Python image.
					docker := requireTool(t, "docker", "info")
					bin := map[string]string{expressGoLinuxBinary(t, docker): "/tool/express-secret"}
					a := append(dockerRun(t, o, bin), expressPythonImage(t, docker), "/tool/express-secret")
					return exec.Command(docker, append(a, args...)...)
				}
				cmd := exec.Command(expressGoBinary(t), args...)
				cmd.Env = append(os.Environ(), "TT_URL=", "TT_TOKEN_FILE=", "TT_EXPIRES=", "TT_LINK_FILE=", "TT_CA_FILE=")
				for k, v := range o.env {
					cmd.Env = append(cmd.Env, k+"="+v)
				}
				return cmd
			},
			vectorsArgs: func(t *testing.T) []string { t.Helper(); return []string{"self-test", vectorsPath(t)} },
			trustCA:     func(path string) map[string]string { return map[string]string{"TT_CA_FILE": path} },
		},
		{
			name: "python",
			cmd: func(t *testing.T, o runOpts, args ...string) *exec.Cmd {
				t.Helper()
				docker := requireTool(t, "docker", "info")
				image := expressPythonImage(t, docker)
				a := append(dockerRun(t, o, nil), image, "python", "-I", "/examples/express-secret.py")
				return exec.Command(docker, append(a, args...)...)
			},
			vectorsArgs: func(*testing.T) []string { return []string{"self-test", "/vectors/vectors.json"} },
			trustCA:     func(path string) map[string]string { return map[string]string{"TT_CA_FILE": path} },
			container:   true,
		},
		{
			name: "powershell",
			cmd: func(t *testing.T, o runOpts, args ...string) *exec.Cmd {
				t.Helper()
				docker := requireTool(t, "docker", "info")
				a := append(dockerRun(t, o, nil), powershellImage,
					"pwsh", "-NoProfile", "-NonInteractive", "-File", "/examples/express-secret.ps1")
				return exec.Command(docker, append(a, args...)...)
			},
			vectorsArgs: func(*testing.T) []string { return []string{"self-test", "-Vectors", "/vectors/vectors.json"} },
			// .NET on Linux honors SSL_CERT_FILE (here the test CA replaces the system store).
			trustCA:   func(path string) map[string]string { return map[string]string{"SSL_CERT_FILE": path} },
			container: true,
		},
	}
}

// runScript runs cmd with stdin and returns its exit code, standard output and standard error.
func runScript(t *testing.T, cmd *exec.Cmd, stdin []byte) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	cmd.Stdin, cmd.Stdout, cmd.Stderr = bytes.NewReader(stdin), &stdout, &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("%s: %v", strings.Join(cmd.Args, " "), err)
		}
		code = ee.ExitCode()
	}
	return code, stdout.String(), stderr.String()
}

// expressSelfTestLine is the line every script must print: the counts of the secret vectors
// of the express profile (no passphrase, no descriptor) and of those skipped, computed here
// independently of the scripts so that a script cannot pass by skipping vectors.
func expressSelfTestLine(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(vectorsPath(t))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Secrets        []map[string]json.RawMessage `json:"secrets"`
		SecretNegative []map[string]json.RawMessage `json:"secretNegative"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	present := func(m map[string]json.RawMessage, k string) bool {
		r, ok := m[k]
		return ok && string(r) != "null"
	}
	byName := map[string]map[string]json.RawMessage{}
	done, skipped := 0, 0
	for _, s := range v.Secrets {
		var name string
		_ = json.Unmarshal(s["name"], &name)
		byName[name] = s
		if present(s, "passphrase") || present(s, "descriptor") {
			skipped++
		} else {
			done++
		}
	}
	negDone, negSkipped := 0, 0
	for _, n := range v.SecretNegative {
		var secret string
		_ = json.Unmarshal(n["secret"], &secret)
		base := byName[secret]
		pass := base["passphrase"]
		if p, ok := n["passphrase"]; ok {
			pass = p
		}
		var passphrase string
		if pass != nil {
			_ = json.Unmarshal(pass, &passphrase)
		}
		noDescriptor := string(n["noDescriptor"]) == "true"
		descriptor := !noDescriptor && (present(n, "descriptor") || present(base, "descriptor"))
		if passphrase != "" || descriptor {
			negSkipped++
		} else {
			negDone++
		}
	}
	if done == 0 || negDone == 0 {
		t.Fatalf("no vector of the express profile: %d secrets, %d negative cases", done, negDone)
	}
	return fmt.Sprintf("self-test: ok (%d secrets, %d negative cases; skipped with a passphrase: %d secrets, %d negative cases)\n",
		done, negDone, skipped, negSkipped)
}

// TestExpressGoVet: express-secret.go, kept out of ./... by its build constraint, passes go vet.
func TestExpressGoVet(t *testing.T) {
	t.Parallel()
	goTool := requireTool(t, "go", "version")
	run(t, exec.Command(goTool, "vet", "express-secret.go"))
}

// TestExpressSelfTest: each script reproduces every secret vector of the express profile; the
// Go one is run as documented, with go run.
func TestExpressSelfTest(t *testing.T) {
	t.Parallel()
	want := expressSelfTestLine(t)
	for _, s := range expressScripts() {
		t.Run(s.name, func(t *testing.T) {
			t.Parallel()
			var cmd *exec.Cmd
			if s.name == "go" {
				cmd = exec.Command(requireTool(t, "go", "version"), append([]string{"run", "express-secret.go"}, s.vectorsArgs(t)...)...)
			} else {
				cmd = s.cmd(t, runOpts{}, s.vectorsArgs(t)...)
			}
			if out := run(t, cmd); out != want {
				t.Fatalf("output %q, want %q", out, want)
			}
		})
	}
}

// expressSealed is the output of the seal mode.
type expressSealed struct {
	FragmentKey string                     `json:"fragmentKey"`
	Body        map[string]json.RawMessage `json:"body"`
}

// openExpress checks that body is exactly a createExpressSecret body for expiresIn, that it
// opens with the fragment key in internal/tte2 and that both verifiers match, and returns the
// text.
func openExpress(t *testing.T, fragmentKey string, body map[string]json.RawMessage, expiresIn string) string {
	t.Helper()
	keys := slices.Sorted(maps.Keys(body))
	if want := []string{"encryptedText", "expiresIn", "keyVerifier", "verifier"}; !slices.Equal(keys, want) {
		t.Fatalf("body members %v, want exactly %v", keys, want)
	}
	field := func(k string) string {
		var s string
		if err := json.Unmarshal(body[k], &s); err != nil {
			t.Fatalf("%s: %v", k, err)
		}
		return s
	}
	if got := field("expiresIn"); got != expiresIn {
		t.Fatalf("expiresIn %q, want %q", got, expiresIn)
	}
	key, err := tte2.DecodeKey(fragmentKey)
	if err != nil {
		t.Fatalf("fragment key %q: %v", fragmentKey, err)
	}
	root, err := tte2.DeriveSecretKey(key, "", tte2.PassphraseDescriptor{})
	if err != nil {
		t.Fatal(err)
	}
	if err := tte2.CheckSecretFraming(field("encryptedText")); err != nil {
		t.Fatalf("framing: %v", err)
	}
	text, err := tte2.OpenSecret(root, field("encryptedText"))
	if err != nil {
		t.Fatalf("OpenSecret: %v", err)
	}
	keyProof, err := tte2.SecretKeyProof(key)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := tte2.SecretProof(root)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := field("keyVerifier"), tte2.EncodeProof(tte2.SecretVerifier(keyProof)); got != want {
		t.Errorf("keyVerifier %s, want %s", got, want)
	}
	if got, want := field("verifier"), tte2.EncodeProof(tte2.SecretVerifier(proof)); got != want {
		t.Errorf("verifier %s, want %s", got, want)
	}
	return text
}

// TestExpressSealOpensInGo: a text sealed by each script with a random key opens with
// internal/tte2, its verifiers match, and the body has exactly the four members of
// createExpressSecret; the text rules of the express profile are applied before sealing.
func TestExpressSealOpensInGo(t *testing.T) {
	t.Parallel()
	// 10 000 code points of 4 UTF-8 bytes (20 000 UTF-16 units): the largest text.
	longest := strings.Repeat("😀", 10000)
	for _, s := range expressScripts() {
		t.Run(s.name, func(t *testing.T) {
			t.Parallel()
			for _, c := range []struct {
				name, text, expires string
			}{
				{"text", expressText, "7d"},
				{"longest", longest, "1h"},
				{"bom kept", "\ufeffa", "1d"},
			} {
				code, out, errOut := runScript(t, s.cmd(t, runOpts{env: map[string]string{"TT_EXPIRES": c.expires}}, "seal"), []byte(c.text))
				if code != 0 {
					t.Fatalf("%s: exit %d\n%s", c.name, code, errOut)
				}
				var sealed expressSealed
				if err := json.Unmarshal([]byte(out), &sealed); err != nil {
					t.Fatalf("%s: %v\n%s", c.name, err, out)
				}
				if got := openExpress(t, sealed.FragmentKey, sealed.Body, c.expires); got != c.text {
					t.Fatalf("%s: opened %q, want %q", c.name, got, c.text)
				}
			}
			// Refused before anything is sealed or sent.
			for _, c := range []struct {
				name    string
				text    []byte
				expires string
			}{
				{"empty", nil, "1d"},
				{"10 001 code points", []byte(strings.Repeat("é", 10001)), "1d"},
				{"invalid UTF-8", []byte("ab\xffcd"), "1d"},
				{"encoded surrogate", []byte("ab\xed\xa0\x80cd"), "1d"},
				{"duration", []byte("a"), "2d"},
			} {
				code, out, errOut := runScript(t, s.cmd(t, runOpts{env: map[string]string{"TT_EXPIRES": c.expires}}, "seal"), c.text)
				if code != 1 || out != "" || !strings.HasPrefix(errOut, "express-secret: ") {
					t.Errorf("%s: exit %d, stdout %q, stderr %q; want exit 1 with an error only", c.name, code, out, errOut)
				}
			}
		})
	}
}

// fakeSecret is an express secret held by fakeServer.
type fakeSecret struct {
	sealed, keyVerifier, verifier string
	anonymous, read               bool
	// expiresAt replaces the expiry date of the status when set.
	expiresAt string
	// gone, when set, are the members of the 410 secret-gone answered for this secret.
	gone map[string]any
}

// fakeServer is a minimal TransTeira for the express operations (createExpressSecret,
// getSecretLink, revealSecret), recording every request.
type fakeServer struct {
	*httptest.Server
	mu       sync.Mutex
	secrets  map[string]*fakeSecret
	requests []string
	// failure, when set, answers every creation with this problem.
	failure *fakeFailure
}

type fakeFailure struct {
	status     int
	code       string
	retryAfter string
	// extra are more members of the problem.
	extra map[string]any
}

// fakeServerCert returns a self-signed certificate for 127.0.0.1, ::1 and host.docker.internal,
// the name under which the containers of Docker Desktop reach the loopback of the host.
func fakeServerCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "transteira examples fake server"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{dockerDesktopHost},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func newFakeServer(t *testing.T) *fakeServer {
	t.Helper()
	f := &fakeServer{secrets: map[string]*fakeSecret{}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/express-secrets", f.create)
	mux.HandleFunc("GET /api/v1/secret-links/{token}", f.status)
	mux.HandleFunc("POST /api/v1/secret-links/{token}/reveal", f.reveal)
	f.Server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(body))
		var dump strings.Builder
		fmt.Fprintf(&dump, "%s %s\n", r.Method, r.URL.RequestURI())
		for k, v := range r.Header {
			fmt.Fprintf(&dump, "%s: %s\n", k, strings.Join(v, ", "))
		}
		dump.Write(body)
		f.mu.Lock()
		f.requests = append(f.requests, dump.String())
		f.mu.Unlock()
		mux.ServeHTTP(w, r)
	}))
	f.Config.ErrorLog = log.New(io.Discard, "", 0)
	f.TLS = &tls.Config{Certificates: []tls.Certificate{fakeServerCert(t)}, MinVersion: tls.VersionTLS12}
	f.StartTLS()
	t.Cleanup(f.Close)
	return f
}

// put stores an express secret of text, sealed under a new key, and returns its token and the
// key of its link.
func (f *fakeServer) put(t *testing.T, text string, s fakeSecret) (token, fragmentKey string) {
	t.Helper()
	key, err := tte2.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	root, err := tte2.DeriveSecretKey(key, "", tte2.PassphraseDescriptor{})
	if err != nil {
		t.Fatal(err)
	}
	if s.sealed, err = tte2.SealSecret(root, text); err != nil {
		t.Fatal(err)
	}
	keyProof, err := tte2.SecretKeyProof(key)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := tte2.SecretProof(root)
	if err != nil {
		t.Fatal(err)
	}
	s.keyVerifier = tte2.EncodeProof(tte2.SecretVerifier(keyProof))
	s.verifier = tte2.EncodeProof(tte2.SecretVerifier(proof))
	token = newSecretToken()
	f.mu.Lock()
	f.secrets[token] = &s
	f.mu.Unlock()
	if fragmentKey, err = tte2.EncodeKey(key); err != nil {
		t.Fatal(err)
	}
	return token, fragmentKey
}

// isRead reports whether the secret of token was revealed.
func (f *fakeServer) isRead(token string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.secrets[token]
	return ok && s.read
}

func problem(w http.ResponseWriter, status int, code string, extra map[string]any) {
	p := map[string]any{"type": "about:blank", "title": code, "status": status, "code": code}
	for k, v := range extra {
		p[k] = v
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(p)
}

func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func newSecretToken() string {
	const base62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	b := []byte("tts_")
	for range 43 {
		n, err := rand.Int(rand.Reader, big.NewInt(62))
		if err != nil {
			panic(err)
		}
		b = append(b, base62[n.Int64()])
	}
	return string(b)
}

func (f *fakeServer) create(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	failure := f.failure
	f.mu.Unlock()
	if failure != nil {
		if failure.retryAfter != "" {
			w.Header().Set("Retry-After", failure.retryAfter)
		}
		problem(w, failure.status, failure.code, failure.extra)
		return
	}
	auth := r.Header.Get("Authorization")
	if auth != "" && auth != "Bearer "+testToken {
		problem(w, http.StatusUnauthorized, "invalid-credentials", nil)
		return
	}
	var body struct {
		EncryptedText string `json:"encryptedText"`
		Verifier      string `json:"verifier"`
		KeyVerifier   string `json:"keyVerifier"`
		ExpiresIn     string `json:"expiresIn"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if r.Header.Get("Content-Type") != "application/json" || dec.Decode(&body) != nil ||
		!slices.Contains([]string{"1h", "1d", "7d"}, body.ExpiresIn) ||
		tte2.CheckSecretFraming(body.EncryptedText) != nil || tte2.SecretTextIsEmpty(body.EncryptedText) {
		problem(w, http.StatusBadRequest, "validation-failed", nil)
		return
	}
	if _, err := tte2.ParseProof(body.Verifier); err != nil {
		problem(w, http.StatusBadRequest, "validation-failed", nil)
		return
	}
	if _, err := tte2.ParseProof(body.KeyVerifier); err != nil {
		problem(w, http.StatusBadRequest, "validation-failed", nil)
		return
	}
	token := newSecretToken()
	f.mu.Lock()
	f.secrets[token] = &fakeSecret{
		sealed: body.EncryptedText, keyVerifier: body.KeyVerifier, verifier: body.Verifier, anonymous: auth == "",
	}
	f.mu.Unlock()
	reply(w, http.StatusCreated, map[string]any{
		"id": "sec_01JABCS3T4V5W6X7Y8Z9A0B1C2", "token": token, "state": "active", "expiresAt": "2026-11-18T09:00:00Z",
	})
}

// secret returns a copy of the active secret of the path, or answers 404 or 410.
func (f *fakeServer) secret(w http.ResponseWriter, r *http.Request) (fakeSecret, bool) {
	f.mu.Lock()
	s, found := f.secrets[r.PathValue("token")]
	var c fakeSecret
	if found {
		c = *s
	}
	f.mu.Unlock()
	switch {
	case !found:
		problem(w, http.StatusNotFound, "not-found", nil)
	case c.gone != nil:
		problem(w, http.StatusGone, "secret-gone", c.gone)
	case c.read:
		problem(w, http.StatusGone, "secret-gone", map[string]any{"reason": "read"})
	default:
		return c, true
	}
	return c, false
}

func (f *fakeServer) status(w http.ResponseWriter, r *http.Request) {
	if s, ok := f.secret(w, r); ok {
		reply(w, http.StatusOK, map[string]any{
			"state": "active", "expiresAt": cmp.Or(s.expiresAt, "2026-11-18T09:00:00Z"), "file": nil, "express": true, "anonymous": s.anonymous,
		})
	}
}

func (f *fakeServer) reveal(w http.ResponseWriter, r *http.Request) {
	s, ok := f.secret(w, r)
	if !ok {
		return
	}
	var body struct {
		KeyProof string `json:"keyProof"`
		Proof    string `json:"proof"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if dec.Decode(&body) != nil {
		problem(w, http.StatusBadRequest, "validation-failed", nil)
		return
	}
	keyProof, err1 := tte2.ParseProof(body.KeyProof)
	proof, err2 := tte2.ParseProof(body.Proof)
	if err1 != nil || err2 != nil {
		problem(w, http.StatusBadRequest, "validation-failed", nil)
		return
	}
	if tte2.EncodeProof(tte2.SecretVerifier(keyProof)) != s.keyVerifier || tte2.EncodeProof(tte2.SecretVerifier(proof)) != s.verifier {
		problem(w, http.StatusForbidden, "secret-proof-invalid", nil)
		return
	}
	f.mu.Lock()
	f.secrets[r.PathValue("token")].read = true
	f.mu.Unlock()
	reply(w, http.StatusOK, map[string]any{"encryptedText": s.sealed})
}

// dockerDesktopHost is the name under which a container of Docker Desktop reaches the loopback
// of the host.
const dockerDesktopHost = "host.docker.internal"

// dockerNetwork is how a container reaches a fake server listening on the loopback of the host.
type dockerNetwork struct {
	// args are the docker run arguments.
	args []string
	// host replaces 127.0.0.1 in the URLs given to the container ("" keeps it).
	host string
}

// urlOf returns the URL of the server at u as the container reaches it.
func (n *dockerNetwork) urlOf(u string) string {
	if n.host == "" {
		return u
	}
	return strings.Replace(u, "127.0.0.1", n.host, 1)
}

// requireContainerNetwork returns how a container reaches the loopback of the host: the host
// network on the Linux Docker Engine; on Docker Desktop, whose host network is the one of its
// virtual machine, the default network and host.docker.internal, which Docker Desktop forwards
// to the loopback of the host. Rootless Docker reaches neither: the test is then skipped, or
// fails under TT_TEST_REQUIRE_POSTGRES=1 (make check), like a missing tool, so that make check
// never reports green without the round trips of the Python and PowerShell examples, which
// check T-397, T-399 and T-406.
func requireContainerNetwork(t *testing.T) *dockerNetwork {
	t.Helper()
	docker := requireTool(t, "docker", "info")
	containerNet.once.Do(func() {
		out, err := exec.Command(docker, "info", "--format", "{{.OperatingSystem}} {{.SecurityOptions}}").Output()
		containerNet.info, containerNet.err = strings.TrimSpace(string(out)), err
	})
	if containerNet.err != nil {
		t.Fatalf("docker info: %v", containerNet.err)
	}
	switch info := containerNet.info; {
	case strings.Contains(info, "rootless"):
		msg := "rootless Docker (" + info + ") reaches neither the host network nor its loopback: " +
			"the round trips of the examples run in a container are not checked; use a rootful Docker Engine or Docker Desktop"
		if os.Getenv("TT_TEST_REQUIRE_POSTGRES") == "1" {
			t.Fatal(msg)
		}
		t.Skip("SKIPPED: " + msg)
	case strings.Contains(info, "Docker Desktop"):
		return &dockerNetwork{args: []string{"--network", "bridge"}, host: dockerDesktopHost}
	}
	return &dockerNetwork{args: []string{"--network", "host"}}
}

// roundTrip is one script against its own fake server.
type roundTrip struct {
	t         *testing.T
	script    expressScript
	srv       *fakeServer
	caFile    string
	tokenFile string
	// net is the container network of a script run in a container, nil for the Go one.
	net *dockerNetwork
	// url is the URL of srv as the script reaches it.
	url string
	// keys of the links (encoded and in hex) never reach the server; keys and tokens never
	// reach the standard error.
	keys, tokens []string
}

func newRoundTrip(t *testing.T, s expressScript) *roundTrip {
	t.Helper()
	rt := &roundTrip{t: t, script: s, srv: newFakeServer(t)}
	rt.url = rt.srv.URL
	if s.container {
		rt.net = requireContainerNetwork(t)
		rt.url = rt.net.urlOf(rt.srv.URL)
	}
	dir := t.TempDir()
	rt.caFile = filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(rt.caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rt.srv.Certificate().Raw}), 0o644); err != nil {
		t.Fatal(err)
	}
	// Readable by the user of the container; a real token file is private to its owner.
	rt.tokenFile = filepath.Join(dir, "token")
	if err := os.WriteFile(rt.tokenFile, []byte(testToken+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return rt
}

// run runs the script in mode with stdin and the server URL, the trusted CA and extra.
func (rt *roundTrip) run(mode string, stdin []byte, extra map[string]string) (int, string, string) {
	rt.t.Helper()
	env := map[string]string{"TT_URL": rt.url}
	maps.Copy(env, rt.script.trustCA(rt.caFile))
	maps.Copy(env, extra)
	code, out, errOut := runScript(rt.t, rt.script.cmd(rt.t, runOpts{env: env, net: rt.net}, mode), stdin)
	for _, x := range append(slices.Clone(rt.keys), rt.tokens...) {
		if strings.Contains(errOut, x) {
			rt.t.Errorf("%s: the standard error holds a secret token or key:\n%s", mode, errOut)
		}
	}
	return code, out, errOut
}

// createAndRead creates an express secret (with the API token unless anonymous), checks the link
// and what the server stored, polls the status, reveals the secret once and polls again.
func (rt *roundTrip) createAndRead(anonymous bool) {
	t := rt.t
	t.Helper()
	extra := map[string]string{"TT_EXPIRES": "1h"}
	if !anonymous {
		extra["TT_TOKEN_FILE"] = rt.tokenFile
	}
	code, out, errOut := rt.run("create", []byte(expressText), extra)
	if code != 0 {
		t.Fatalf("create: exit %d\n%s", code, errOut)
	}
	prefix := rt.url + "/s/"
	token, key, ok := strings.Cut(strings.TrimPrefix(out, prefix), "#k=")
	key, eol := strings.CutSuffix(key, "\n")
	if !strings.HasPrefix(out, prefix) || !ok || !eol {
		t.Fatalf("create printed %q, want %s<token>#k=<key> and a line break", out, prefix)
	}
	keyBytes, err := tte2.DecodeKey(key)
	if err != nil {
		t.Fatalf("key of the link %q: %v", key, err)
	}
	rt.tokens = append(rt.tokens, token)
	rt.keys = append(rt.keys, key, hex.EncodeToString(keyBytes))
	rt.srv.mu.Lock()
	stored, found := rt.srv.secrets[token]
	rt.srv.mu.Unlock()
	if !found || stored.anonymous != anonymous {
		t.Fatalf("the link token is not a secret created by the server with anonymous=%v", anonymous)
	}
	body := map[string]json.RawMessage{}
	for k, v := range map[string]string{
		"encryptedText": stored.sealed, "verifier": stored.verifier, "keyVerifier": stored.keyVerifier, "expiresIn": "1h",
	} {
		body[k], _ = json.Marshal(v)
	}
	if got := openExpress(t, key, body, "1h"); got != expressText {
		t.Fatalf("the stored text opens to %q, want %q", got, expressText)
	}

	link := []byte(out)
	if code, out, errOut := rt.run("status", link, nil); code != 0 || out != "pending 2026-11-18T09:00:00Z\n" {
		t.Fatalf("status: exit %d, stdout %q, stderr %q", code, out, errOut)
	}
	code, out, errOut = rt.run("read", link, nil)
	if code != 0 || out != expressText {
		t.Fatalf("read: exit %d, stdout %q, stderr %q; want %q", code, out, errOut, expressText)
	}
	how := "with an API token of the entity"
	if anonymous {
		how = "anonymously"
	}
	if !strings.Contains(errOut, "express secret was created "+how+": its content was written by a third party") {
		t.Errorf("read: no third-party notice on the standard error: %q", errOut)
	}
	if code, out, errOut := rt.run("status", link, nil); code != 0 || out != "read\n" {
		t.Fatalf("status after the read: exit %d, stdout %q, stderr %q", code, out, errOut)
	}
	code, out, errOut = rt.run("read", link, nil)
	if code != 1 || out != "" || !strings.Contains(errOut, "getSecretLink: 410 secret-gone") || !strings.Contains(errOut, "(read)") {
		t.Fatalf("second read: exit %d, stdout %q, stderr %q", code, out, errOut)
	}
}

// checkRequests checks that no request carried the text, a key or a fragment (T-399); the
// tokens are expected in the paths.
func (rt *roundTrip) checkRequests() {
	t := rt.t
	t.Helper()
	rt.srv.mu.Lock()
	defer rt.srv.mu.Unlock()
	if len(rt.srv.requests) == 0 {
		t.Fatal("no request recorded")
	}
	for _, req := range rt.srv.requests {
		for _, k := range rt.keys {
			if strings.Contains(req, k) {
				t.Errorf("a request carries a key:\n%s", req)
			}
		}
		requestLine, _, _ := strings.Cut(req, "\n")
		if strings.Contains(req, expressMarker) || strings.Contains(requestLine, "#") {
			t.Errorf("a request carries the text or a fragment:\n%s", req)
		}
	}
}

// TestExpressRoundTrip: each script creates an express secret, anonymously and with an API
// token, prints the link composed with its own key on standard output only, polls its status,
// reveals it once and prints the exact text; no request carries the text or the key (T-399),
// and the standard error never holds a token or a key (T-406). The problems of the creation are
// explained with a hint.
func TestExpressRoundTrip(t *testing.T) {
	t.Parallel()
	for _, s := range expressScripts() {
		t.Run(s.name, func(t *testing.T) {
			t.Parallel()
			if s.container {
				requireContainerNetwork(t)
			}
			for _, flow := range []string{"anonymous", "token"} {
				t.Run(flow, func(t *testing.T) {
					t.Parallel()
					rt := newRoundTrip(t, s)
					rt.createAndRead(flow == "anonymous")
					rt.checkRequests()
				})
			}
			t.Run("problems", func(t *testing.T) {
				t.Parallel()
				rt := newRoundTrip(t, s)
				for _, c := range []struct {
					failure fakeFailure
					want    []string
				}{
					{fakeFailure{status: 403, code: "express-secrets-disabled"}, []string{"createExpressSecret: 403 express-secrets-disabled", "TT_TOKEN_FILE"}},
					{fakeFailure{status: 403, code: "express-token-not-allowed"}, []string{"createExpressSecret: 403 express-token-not-allowed", "expressAllowed"}},
					{fakeFailure{status: 429, code: "rate-limited", retryAfter: "1200"}, []string{"createExpressSecret: 429 rate-limited", "retry after 1200 seconds", "new key"}},
					{fakeFailure{status: 429, code: "express-secret-limit-reached"}, []string{"createExpressSecret: 429 express-secret-limit-reached", "too many unread express secrets"}},
					{fakeFailure{status: 400, code: "validation-failed"}, []string{"createExpressSecret: 400 validation-failed", "do not retry it unchanged"}},
				} {
					rt.srv.mu.Lock()
					rt.srv.failure = &c.failure
					rt.srv.mu.Unlock()
					code, out, errOut := rt.run("create", []byte(expressText), map[string]string{"TT_TOKEN_FILE": rt.tokenFile})
					if code != 1 || out != "" {
						t.Errorf("%s: exit %d, stdout %q; want exit 1 and no output", c.failure.code, code, out)
					}
					for _, w := range c.want {
						if !strings.Contains(errOut, w) {
							t.Errorf("%s: stderr %q lacks %q", c.failure.code, errOut, w)
						}
					}
				}
				// Unknown link: nothing to read.
				link := []byte(rt.url + "/s/" + newSecretToken() + "#k=" + strings.Repeat("A", 43))
				code, out, errOut := rt.run("read", link, nil)
				if code != 1 || out != "" || !strings.Contains(errOut, "getSecretLink: 404 not-found") || !strings.Contains(errOut, "unknown link") {
					t.Errorf("unknown link: exit %d, stdout %q, stderr %q", code, out, errOut)
				}
				rt.checkRequests()
			})
		})
	}
}

// hostile holds escape sequences (OSC 52 clipboard write, screen erase, C1 CSI), a lone carriage
// return and a bidirectional override: what a hostile server, or the author of a text, could
// send to drive or deceive the terminal of the reader.
const hostile = "\x1b]52;c;ZXZpbA==\x07\x1b[2J\rspoof\u202eevil\u202c\u009b31m"

// unsafeOnTerminal reports a character that could drive or deceive a terminal: a C0 control
// other than a line feed, DEL, a C1 control or a bidirectional formatting character.
func unsafeOnTerminal(r rune) bool {
	return (r < 0x20 && r != '\n') || (r >= 0x7f && r <= 0x9f) ||
		r == 0x061c || r == 0x200e || r == 0x200f || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069)
}

// assertPrintable fails when out holds a character of unsafeOnTerminal.
func assertPrintable(t *testing.T, what, out string) {
	t.Helper()
	if i := strings.IndexFunc(out, unsafeOnTerminal); i >= 0 {
		t.Errorf("%s: unsafe character %U at %d in %q", what, []rune(out[i:])[0], i, out)
	}
}

// TestExpressHostileServer: a link can name any server. What a hostile one answers (problem
// code, detail, reason, delay, expiry date) never reaches the terminal with control or
// bidirectional characters: the error lines replace them, and status prints only a plain-word
// reason and an RFC 3339 date (T-397, T-406).
func TestExpressHostileServer(t *testing.T) {
	t.Parallel()
	for _, s := range expressScripts() {
		t.Run(s.name, func(t *testing.T) {
			t.Parallel()
			rt := newRoundTrip(t, s)
			for _, f := range []fakeFailure{
				{status: 429, code: "rate-limited", extra: map[string]any{"detail": hostile, "retryAfterSeconds": hostile}},
				{status: 418, code: hostile, extra: map[string]any{"detail": hostile}},
			} {
				rt.srv.mu.Lock()
				rt.srv.failure = &f
				rt.srv.mu.Unlock()
				code, out, errOut := rt.run("create", []byte(expressText), nil)
				if code != 1 || out != "" || !strings.Contains(errOut, "createExpressSecret: ") {
					t.Errorf("create %d: exit %d, stdout %q, stderr %q", f.status, code, out, errOut)
				}
				assertPrintable(t, fmt.Sprintf("create %d: stderr", f.status), errOut)
			}

			// A gone secret with a hostile reason and detail.
			token, key := rt.srv.put(t, "x", fakeSecret{gone: map[string]any{"reason": hostile, "detail": hostile}})
			link := []byte(rt.url + "/s/" + token + "#k=" + key + "\n")
			code, out, errOut := rt.run("status", link, nil)
			if code != 0 || out != "gone\n" || errOut != "" {
				t.Errorf("status of a gone secret: exit %d, stdout %q, stderr %q; want gone", code, out, errOut)
			}
			code, out, errOut = rt.run("read", link, nil)
			if code != 1 || out != "" || !strings.Contains(errOut, "getSecretLink: 410 secret-gone") {
				t.Errorf("read of a gone secret: exit %d, stdout %q, stderr %q", code, out, errOut)
			}
			assertPrintable(t, "read of a gone secret: stderr", errOut)

			// A live secret with a hostile expiry date: refused, nothing printed on stdout.
			token, key = rt.srv.put(t, "x", fakeSecret{expiresAt: "2026-11-18T09:00:00Z" + hostile})
			code, out, errOut = rt.run("status", []byte(rt.url+"/s/"+token+"#k="+key), nil)
			if code != 1 || out != "" || !strings.Contains(errOut, "getSecretLink: unexpected answer") {
				t.Errorf("status with a hostile date: exit %d, stdout %q, stderr %q", code, out, errOut)
			}
			assertPrintable(t, "status with a hostile date: stderr", errOut)
		})
	}
}

// TestExpressTerminal: read on a terminal replaces the characters of the text that could drive
// or deceive it, a lone carriage return included (it would let the rest of a line overwrite
// what was shown), keeps the tabs, line feeds and CR LF, and says so on the standard error; the
// secret is consumed (T-397). Every script runs in a container with a terminal, the Go one built
// for Linux.
func TestExpressTerminal(t *testing.T) {
	t.Parallel()
	text := "first line\r\nhidden part\rSHOWN\t" + hostile + " end"
	for _, s := range expressScripts() {
		t.Run(s.name, func(t *testing.T) {
			t.Parallel()
			s.container = true // the terminal is the one of a container
			rt := newRoundTrip(t, s)
			token, key := rt.srv.put(t, text, fakeSecret{anonymous: true})
			linkFile := filepath.Join(t.TempDir(), "link")
			if err := os.WriteFile(linkFile, []byte(rt.url+"/s/"+token+"#k="+key+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			env := map[string]string{"TT_URL": rt.url, "TT_LINK_FILE": linkFile}
			maps.Copy(env, s.trustCA(rt.caFile))
			code, out, _ := runScript(t, s.cmd(t, runOpts{env: env, net: rt.net, tty: true}, "read"), nil)
			if code != 0 || !rt.srv.isRead(token) {
				t.Fatalf("read: exit %d, read by the server: %v\n%q", code, rt.srv.isRead(token), out)
			}
			// The terminal turns each line feed into CR LF (and the CR LF of the text into
			// CR CR LF): undo it, then every CR must still end a line.
			shown := strings.ReplaceAll(out, "\r\n", "\n")
			for i := strings.IndexByte(shown, '\r'); i >= 0; i = strings.IndexByte(shown, '\r') {
				if !strings.HasPrefix(shown[i+1:], "\n") {
					t.Fatalf("a lone carriage return reached the terminal: %q", out)
				}
				shown = shown[i+1:]
			}
			for _, x := range []string{"\x1b]52", "\x1b[2J", "\x07", "\u202e", "\u009b"} {
				if strings.Contains(out, x) {
					t.Errorf("%q reached the terminal: %q", x, out)
				}
			}
			for _, w := range []string{"first line", "hidden part�SHOWN\t", "spoof", "end", "replaced with U+FFFD"} {
				if !strings.Contains(out, w) {
					t.Errorf("the terminal lacks %q: %q", w, out)
				}
			}
		})
	}
}
