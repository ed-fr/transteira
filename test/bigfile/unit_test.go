package bigfile

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/config"
)

// Unit tests of the parts of the large-file test that need no stack. They
// run with the ordinary test suite (no build tag).

// envOf returns a getenv function reading m.
func envOf(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

// minimalEnv is the smallest valid environment.
func minimalEnv() map[string]string {
	return map[string]string{
		EnvBaseURL:    "https://transfer.bigfile.localhost:8443",
		EnvAdminURL:   "https://admin.bigfile.localhost:8443/",
		EnvSetupToken: "setup-token",
	}
}

func TestLoadConfigDefaults(t *testing.T) {
	t.Parallel()
	c, err := LoadConfig(envOf(minimalEnv()))
	if err != nil {
		t.Fatal(err)
	}
	if c.Bytes != 20<<30 || c.Chunk != 1<<30 || c.CutAt != 0.43 || c.DownloadCutAt != 0.3 || c.Seed != 20 ||
		c.ClamAVMaxScanBytes != 2<<30 || c.ScanTimeout != 30*time.Minute || c.Report != "" || c.CAFile != "" || len(c.Resolve) != 0 {
		t.Fatalf("defaults = %+v", c)
	}
	if c.TenantHost() != "transfer.bigfile.localhost" || c.AdminHost() != "admin.bigfile.localhost" || c.AdminURL.Path != "" {
		t.Fatalf("hosts %q %q, admin path %q", c.TenantHost(), c.AdminHost(), c.AdminURL.Path)
	}
	if c.ExpectedScanStatus() != "not_scanned_too_large" {
		t.Fatalf("20 GiB scan status %q", c.ExpectedScanStatus())
	}
}

// TestDefaultsMatchTheServer keeps the copy of a server default that cannot
// be referenced as a typed constant equal to it (config holds it as the
// string default of TT_CLAMAV_MAX_SCAN_BYTES).
func TestDefaultsMatchTheServer(t *testing.T) {
	t.Parallel()
	server, err := strconv.ParseInt(config.DefaultClamAVMaxScanBytes, 10, 64)
	if err != nil {
		t.Fatalf("config.DefaultClamAVMaxScanBytes %q: %v", config.DefaultClamAVMaxScanBytes, err)
	}
	if DefaultClamAVMaxScanBytes != server {
		t.Fatalf("DefaultClamAVMaxScanBytes = %d, the server default is %d", DefaultClamAVMaxScanBytes, server)
	}
}

func TestLoadConfigOverrides(t *testing.T) {
	t.Parallel()
	env := minimalEnv()
	for k, v := range map[string]string{
		EnvCAFile: "/tmp/root.crt", EnvResolve: "transfer.bigfile.localhost=127.0.0.1",
		EnvBytes: "2147483648", EnvChunk: "268435456", EnvCutAt: "0.5", EnvDownloadCutAt: "0.25",
		EnvSeed: "7", EnvReport: "out/report.json", EnvEngine: "postgres",
		EnvClamAVMaxScanBytes: "2147483648", EnvScanTimeout: "5m",
	} {
		env[k] = v
	}
	c, err := LoadConfig(envOf(env))
	if err != nil {
		t.Fatal(err)
	}
	want := Config{
		BaseURL: c.BaseURL, AdminURL: c.AdminURL, CAFile: "/tmp/root.crt",
		Resolve:    map[string]string{"transfer.bigfile.localhost": "127.0.0.1"},
		SetupToken: "setup-token", Bytes: 2 << 30, Chunk: 256 << 20, CutAt: 0.5, DownloadCutAt: 0.25,
		Seed: 7, Report: "out/report.json", Engine: "postgres", ClamAVMaxScanBytes: 2 << 30, ScanTimeout: 5 * time.Minute,
	}
	if !reflect.DeepEqual(c, want) {
		t.Fatalf("config = %+v\nwant     %+v", c, want)
	}
	if c.ExpectedScanStatus() != "clean" {
		t.Fatalf("2 GiB (at the limit) scan status %q, want clean", c.ExpectedScanStatus())
	}
}

func TestLoadConfigErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		set  map[string]string
		want string
	}{
		{"base missing", map[string]string{EnvBaseURL: ""}, EnvBaseURL + ": not set"},
		{"admin missing", map[string]string{EnvAdminURL: ""}, EnvAdminURL + ": not set"},
		{"token missing", map[string]string{EnvSetupToken: ""}, EnvSetupToken + ": not set"},
		{"http base", map[string]string{EnvBaseURL: "http://transfer.example.com"}, "not an https origin"},
		{"base with path", map[string]string{EnvBaseURL: "https://transfer.example.com/x"}, "not an https origin"},
		{"base with query", map[string]string{EnvBaseURL: "https://transfer.example.com?a=1"}, "not an https origin"},
		{"base with user", map[string]string{EnvBaseURL: "https://u@transfer.example.com"}, "not an https origin"},
		{"base without host", map[string]string{EnvBaseURL: "https://"}, "not an https origin"},
		{"base unparsable", map[string]string{EnvBaseURL: "https://[::1"}, "not an https origin"},
		{"bad resolve", map[string]string{EnvResolve: "nohost"}, EnvResolve},
		{"bytes not a number", map[string]string{EnvBytes: "big"}, EnvBytes},
		{"bytes too small", map[string]string{EnvBytes: "1000"}, EnvBytes},
		{"bytes above 20 GiB", map[string]string{EnvBytes: "21474836481"}, EnvBytes},
		{"chunk too small", map[string]string{EnvChunk: "1"}, EnvChunk},
		{"cut zero", map[string]string{EnvCutAt: "0"}, EnvCutAt},
		{"cut one", map[string]string{EnvCutAt: "1"}, EnvCutAt},
		{"cut NaN", map[string]string{EnvCutAt: "NaN"}, EnvCutAt},
		{"download cut text", map[string]string{EnvDownloadCutAt: "half"}, EnvDownloadCutAt},
		{"seed negative", map[string]string{EnvSeed: "-1"}, EnvSeed},
		{"scan timeout", map[string]string{EnvScanTimeout: "soon"}, EnvScanTimeout},
		{"scan timeout negative", map[string]string{EnvScanTimeout: "-1m"}, EnvScanTimeout},
		{"clamav max", map[string]string{EnvClamAVMaxScanBytes: "0"}, EnvClamAVMaxScanBytes},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			env := minimalEnv()
			for k, v := range tc.set {
				env[k] = v
			}
			_, err := LoadConfig(envOf(env))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want one mentioning %q", err, tc.want)
			}
		})
	}
	// Every error is reported at once.
	_, err := LoadConfig(envOf(map[string]string{EnvBytes: "x"}))
	for _, name := range []string{EnvBaseURL, EnvAdminURL, EnvSetupToken, EnvBytes} {
		if err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("joined error %v does not mention %s", err, name)
		}
	}
}

func TestParseResolve(t *testing.T) {
	t.Parallel()
	got, err := ParseResolve(" Transfer.Bigfile.Localhost=127.0.0.1 , admin.bigfile.localhost=127.0.0.1:9443,v6.bigfile.localhost=[::1]:443,,other.localhost=::1")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"transfer.bigfile.localhost": "127.0.0.1", "admin.bigfile.localhost": "127.0.0.1:9443",
		"v6.bigfile.localhost": "[::1]:443", "other.localhost": "::1",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseResolve = %v, want %v", got, want)
	}
	if m, err := ParseResolve(""); err != nil || len(m) != 0 {
		t.Fatalf("empty = %v, %v", m, err)
	}
	for _, bad := range []string{"host", "=127.0.0.1", "host=", "host=localhost", "host=127.0.0.1:", "a=127.0.0.1,A=127.0.0.2", "host=example.com:443"} {
		if _, err := ParseResolve(bad); err == nil {
			t.Errorf("ParseResolve(%q) accepted", bad)
		}
	}
}

func TestDialerTarget(t *testing.T) {
	t.Parallel()
	d := &Dialer{Resolve: map[string]string{"transfer.bigfile.localhost": "127.0.0.1", "admin.bigfile.localhost": "127.0.0.2:9443"}}
	for in, want := range map[string]string{
		"transfer.bigfile.localhost:8443": "127.0.0.1:8443",
		"TRANSFER.bigfile.localhost:443":  "127.0.0.1:443",
		"admin.bigfile.localhost:8443":    "127.0.0.2:9443",
		"example.com:443":                 "example.com:443",
		"no-port":                         "no-port",
	} {
		if got := d.Target(in); got != want {
			t.Errorf("Target(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDialerDialContext(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	accepted := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			accepted <- err.Error()
			return
		}
		b, _ := io.ReadAll(c)
		_ = c.Close()
		accepted <- string(b)
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	d := &Dialer{Resolve: map[string]string{"transfer.bigfile.localhost": "127.0.0.1"}}
	c, err := d.DialContext(context.Background(), "tcp", net.JoinHostPort("transfer.bigfile.localhost", port))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(c, "hello")
	_ = c.Close()
	if got := <-accepted; got != "hello" {
		t.Fatalf("the listener received %q, want hello", got)
	}
}

func TestTOTPCode(t *testing.T) {
	t.Parallel()
	// RFC 6238 appendix B, SHA-1 secret "12345678901234567890", truncated
	// to 6 digits.
	const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" // gitleaks:allow (RFC 6238 test vector)
	for unix, want := range map[int64]string{59: "287082", 1111111109: "081804", 1111111111: "050471", 1234567890: "005924", 2000000000: "279037", 20000000000: "353130"} {
		step := TOTPStep(time.Unix(unix, 0))
		if step != unix/30 {
			t.Fatalf("TOTPStep(%d) = %d", unix, step)
		}
		got, err := TOTPCode(secret, step)
		if err != nil || got != want {
			t.Errorf("TOTPCode at %d = %q, %v; want %q", unix, got, err, want)
		}
	}
	// Case, spaces and padding are ignored.
	if got, err := TOTPCode("gezd gnbv gy3t qojq gezd gnbv gy3t qojq====", 1); err != nil || got != "287082" {
		t.Errorf("normalised secret = %q, %v", got, err)
	}
	if _, err := TOTPCode("not base32!", 1); err == nil {
		t.Error("invalid secret accepted")
	}
	if _, err := TOTPCode(secret, -1); err == nil {
		t.Error("negative step accepted")
	}
}

func TestPlanCut(t *testing.T) {
	t.Parallel()
	const gib = 1 << 30
	tests := []struct {
		name        string
		size, chunk int64
		frac        float64
		want        CutPlan
	}{
		// 0.4 of 20 GiB is exactly 8 GiB, a chunk boundary: the PATCH starts
		// one chunk earlier.
		{"20 GiB", 20 * gib, gib, 0.4, CutPlan{Start: 7 * gib, At: 8 * gib, Checkpoint: true}},
		{"20 GiB at the default fraction", 20 * gib, gib, DefaultCutAt, CutPlan{Start: 8 * gib, At: 9234179686, Checkpoint: true}},
		{"2 GiB", 2 * gib, gib, 0.4, CutPlan{Start: 0, At: 858993459, Checkpoint: true}},
		{"small chunks", 2 * gib, 64 << 20, 0.5, CutPlan{Start: gib - 128<<20, At: gib, Checkpoint: true}},
		{"just enough", 2 * minCutSpan, gib, 0.5, CutPlan{Start: 0, At: minCutSpan, Checkpoint: true}},
		{"too small for a checkpoint", 64 << 20, gib, 0.4, CutPlan{Start: 0, At: 26843545}},
		{"clamped low", 1 << 20, gib, 1e-9, CutPlan{Start: 0, At: 1}},
		{"clamped high", 1 << 20, gib, 0.9999999999, CutPlan{Start: 0, At: 1<<20 - 1}},
	}
	for _, tc := range tests {
		got := PlanCut(tc.size, tc.chunk, tc.frac)
		if got != tc.want {
			t.Errorf("%s: PlanCut = %+v, want %+v", tc.name, got, tc.want)
		}
		if got.Checkpoint && got.At-got.Start < minCutSpan {
			t.Errorf("%s: the interrupted PATCH sends %d bytes, fewer than %d", tc.name, got.At-got.Start, minCutSpan)
		}
		if got.Start%tc.chunk != 0 || got.At <= got.Start || got.At >= tc.size {
			t.Errorf("%s: incoherent plan %+v", tc.name, got)
		}
	}
}

func TestChunks(t *testing.T) {
	t.Parallel()
	if got, want := Chunks(10, 35, 10), [][2]int64{{10, 20}, {20, 30}, {30, 35}}; !reflect.DeepEqual(got, want) {
		t.Errorf("Chunks = %v, want %v", got, want)
	}
	if got := Chunks(5, 5, 10); len(got) != 0 {
		t.Errorf("empty range gives %v", got)
	}
	if got, want := Chunks(0, 20, 10), [][2]int64{{0, 10}, {10, 20}}; !reflect.DeepEqual(got, want) {
		t.Errorf("exact multiple gives %v, want %v", got, want)
	}
}

func TestReport(t *testing.T) {
	t.Parallel()
	var r Report
	start := time.Date(2026, 10, 25, 12, 0, 0, 0, time.FixedZone("CET", 3600))
	p := r.AddPhase("upload", start, start.Add(2*time.Second), 200<<20)
	if p.MiBPerSecond != 100 || p.Seconds != 2 || p.Start.Location() != time.UTC {
		t.Fatalf("phase = %+v", p)
	}
	if s := p.String(); s != "upload: 200.0 MiB in 2s (100.0 MiB/s)" {
		t.Errorf("String = %q", s)
	}
	q := r.AddPhase("setup", start, start.Add(1500*time.Millisecond), 0)
	if q.MiBPerSecond != 0 || q.String() != "setup: 1.5s" {
		t.Errorf("phase without bytes = %+v, %q", q, q.String())
	}
	if z := r.AddPhase("instant", start, start, 10); z.MiBPerSecond != 0 {
		t.Errorf("zero-length phase throughput %v", z.MiBPerSecond)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "out", "report.json")
	r.Passed, r.Bytes, r.SHA256.Expected = true, 200<<20, "abc"
	if err := r.Write(path); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back["passed"] != true || back["sha256"].(map[string]any)["expected"] != "abc" || len(back["phases"].([]any)) != 3 {
		t.Fatalf("report JSON = %s", b)
	}
	// A directory in the way of the file, then a file in the way of the
	// directory.
	if err := r.Write(dir); err == nil {
		t.Error("writing over a directory succeeded")
	}
	if err := r.Write(filepath.Join(path, "sub", "report.json")); err == nil {
		t.Error("creating a directory under a file succeeded")
	}
}

func TestBodyForLog(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("x", 700)
	tests := []struct {
		name, what, body, want string
	}{
		{name: "ordinary body", what: "GET /api/v1/transfers/x", body: `{"status":"uploading"}`, want: `{"status":"uploading"}`},
		{name: "ordinary body truncated", what: "GET /healthz", body: long, want: long[:600]},
		{name: "setup secret hidden", what: "POST /admin/setup", body: `{"secret":"JBSWY3DPEHPK3PXP"}`, want: "[body of 29 bytes not shown: secret path]"},
		{name: "token secret hidden", what: "POST /admin/tenants/t1/api-tokens", body: `{"token":"tt_abc"}`, want: "[body of 18 bytes not shown: secret path]"},
		{name: "not JSON on a secret path", what: "POST /admin/setup", body: "token tt_abc", want: "[body of 12 bytes not shown: secret path]"},
		{
			name: "problem on a secret path", what: "POST /admin/setup",
			body: `{"code":"setup-token-invalid","title":"Invalid setup token","detail":"tt_abc"}`,
			want: `problem "setup-token-invalid": "Invalid setup token" [rest of the body not shown: secret path]`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := BodyForLog(tt.what, []byte(tt.body))
			if got != tt.want {
				t.Fatalf("BodyForLog(%q, %q) = %q, want %q", tt.what, tt.body, got, tt.want)
			}
			if strings.Contains(tt.what, "/admin/setup") || strings.Contains(tt.what, "/api-tokens") {
				if strings.Contains(got, "JBSWY3DPEHPK3PXP") || strings.Contains(got, "tt_abc") {
					t.Fatalf("BodyForLog leaked a secret: %q", got)
				}
			}
		})
	}
}
