package securitylog

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

var fixedTime = time.Date(2026, 10, 20, 9, 41, 0, 123456789, time.FixedZone("CEST", 2*3600))

func fixedClock() time.Time { return fixedTime }

const tenantA = "transfer.entity-a.example.com"

// allEvents lists every event type of section 16.3. The fail2ban and
// CrowdSec tests check that the integrations cover exactly these.
var allEvents = []EventType{
	VerificationCodeInvalid, TransferPasswordInvalid, AdminLoginFailed,
	APITokenInvalid, UnknownFQDN, DepositRefused, RateLimited, MetricsTokenInvalid,
}

type goldenCase struct {
	name  string
	ev    Event
	line  string // expected line, without the trailing newline
	banIP string // IP the ban filters must extract, "" when the line must not match
}

// goldenCases are the reference lines of the stable format. Changing one of
// them is a breaking change for the fail2ban and CrowdSec integrations.
var goldenCases = []goldenCase{
	{
		name: "verification code invalid",
		ev: Event{
			Type: VerificationCodeInvalid, IP: netip.MustParseAddr("203.0.113.7"), Tenant: tenantA,
			Fields: []Field{{"email", "alice@entity-a.example.com"}},
		},
		line:  `2026-10-20T07:41:00.123Z ip=203.0.113.7 tenant=transfer.entity-a.example.com event=verification_code_invalid email="alice@entity-a.example.com"`,
		banIP: "203.0.113.7",
	},
	{
		// Since 1.1 (decision P38): a wrong recipient code, as the download
		// service writes it; same event, so the 1.0 filters ban it.
		name: "verification code invalid recipient",
		ev: Event{
			Type: VerificationCodeInvalid, IP: netip.MustParseAddr("203.0.113.8"), Tenant: tenantA,
			Fields: []Field{{"transfer", "trf_01JABCD9F1"}, {KeyPurpose, PurposeRecipient}},
		},
		line:  `2026-10-20T07:41:00.123Z ip=203.0.113.8 tenant=transfer.entity-a.example.com event=verification_code_invalid transfer="trf_01JABCD9F1" purpose="recipient"`,
		banIP: "203.0.113.8",
	},
	{
		name:  "transfer password invalid",
		ev:    Event{Type: TransferPasswordInvalid, IP: netip.MustParseAddr("198.51.100.23"), Tenant: tenantA, Fields: []Field{{"transfer", "tr_01jab"}}},
		line:  `2026-10-20T07:41:00.123Z ip=198.51.100.23 tenant=transfer.entity-a.example.com event=transfer_password_invalid transfer="tr_01jab"`,
		banIP: "198.51.100.23",
	},
	{
		name:  "admin login failed password",
		ev:    Event{Type: AdminLoginFailed, IP: netip.MustParseAddr("2001:db8::1"), Tenant: tenantA, Fields: []Field{{KeyReason, ReasonPassword}, {"user", "admin"}}},
		line:  `2026-10-20T07:41:00.123Z ip=2001:db8::1 tenant=transfer.entity-a.example.com event=admin_login_failed reason="password" user="admin"`,
		banIP: "2001:db8::1",
	},
	{
		name:  "admin login failed totp",
		ev:    Event{Type: AdminLoginFailed, IP: netip.MustParseAddr("192.0.2.10"), Fields: []Field{{KeyReason, ReasonTOTP}}},
		line:  `2026-10-20T07:41:00.123Z ip=192.0.2.10 tenant=- event=admin_login_failed reason="totp"`,
		banIP: "192.0.2.10",
	},
	{
		name:  "admin login failed recovery code",
		ev:    Event{Type: AdminLoginFailed, IP: netip.MustParseAddr("192.0.2.11"), Fields: []Field{{KeyReason, ReasonRecoveryCode}}},
		line:  `2026-10-20T07:41:00.123Z ip=192.0.2.11 tenant=- event=admin_login_failed reason="recovery_code"`,
		banIP: "192.0.2.11",
	},
	{
		name:  "api token invalid",
		ev:    Event{Type: APITokenInvalid, IP: netip.MustParseAddr("192.0.2.12"), Tenant: tenantA},
		line:  `2026-10-20T07:41:00.123Z ip=192.0.2.12 tenant=transfer.entity-a.example.com event=api_token_invalid`,
		banIP: "192.0.2.12",
	},
	{
		name:  "metrics token invalid",
		ev:    Event{Type: MetricsTokenInvalid, IP: netip.MustParseAddr("192.0.2.13")},
		line:  `2026-10-20T07:41:00.123Z ip=192.0.2.13 tenant=- event=metrics_token_invalid`,
		banIP: "192.0.2.13",
	},
	{
		name:  "unknown fqdn",
		ev:    Event{Type: UnknownFQDN, IP: netip.MustParseAddr("203.0.113.7"), Tenant: tenantA, Fields: []Field{{KeyHost, "evil.example.net"}}},
		line:  `2026-10-20T07:41:00.123Z ip=203.0.113.7 tenant=transfer.entity-a.example.com event=unknown_fqdn host="evil.example.net"`,
		banIP: "203.0.113.7",
	},
	{
		name:  "unknown fqdn without tenant",
		ev:    Event{Type: UnknownFQDN, IP: netip.MustParseAddr("203.0.113.8"), Fields: []Field{{KeyHost, "198.51.100.1:443"}}},
		line:  `2026-10-20T07:41:00.123Z ip=203.0.113.8 tenant=- event=unknown_fqdn host="198.51.100.1:443"`,
		banIP: "203.0.113.8",
	},
	{
		name:  "deposit refused ip",
		ev:    Event{Type: DepositRefused, IP: netip.MustParseAddr("192.0.2.13"), Tenant: tenantA, Fields: []Field{{KeyReason, ReasonIP}}},
		line:  `2026-10-20T07:41:00.123Z ip=192.0.2.13 tenant=transfer.entity-a.example.com event=deposit_refused reason="ip"`,
		banIP: "192.0.2.13",
	},
	{
		name:  "deposit refused domain",
		ev:    Event{Type: DepositRefused, IP: netip.MustParseAddr("192.0.2.14"), Tenant: tenantA, Fields: []Field{{KeyReason, ReasonDomain}}},
		line:  `2026-10-20T07:41:00.123Z ip=192.0.2.14 tenant=transfer.entity-a.example.com event=deposit_refused reason="domain"`,
		banIP: "192.0.2.14",
	},
	{
		name:  "deposit refused blocklist",
		ev:    Event{Type: DepositRefused, IP: netip.MustParseAddr("192.0.2.15"), Tenant: tenantA, Fields: []Field{{KeyReason, ReasonBlocklist}}},
		line:  `2026-10-20T07:41:00.123Z ip=192.0.2.15 tenant=transfer.entity-a.example.com event=deposit_refused reason="blocklist"`,
		banIP: "192.0.2.15",
	},
	{
		name:  "deposit refused invitation",
		ev:    Event{Type: DepositRefused, IP: netip.MustParseAddr("192.0.2.16"), Tenant: tenantA, Fields: []Field{{KeyReason, ReasonInvitation}}},
		line:  `2026-10-20T07:41:00.123Z ip=192.0.2.16 tenant=transfer.entity-a.example.com event=deposit_refused reason="invitation"`,
		banIP: "192.0.2.16",
	},
	{
		name:  "rate limited",
		ev:    Event{Type: RateLimited, IP: netip.MustParseAddr("192.0.2.17"), Tenant: tenantA, Fields: []Field{{KeyScope, "verification_code"}}},
		line:  `2026-10-20T07:41:00.123Z ip=192.0.2.17 tenant=transfer.entity-a.example.com event=rate_limited scope="verification_code"`,
		banIP: "192.0.2.17",
	},
	{
		name: "rate limited transfer password",
		ev: Event{
			Type: RateLimited, IP: netip.MustParseAddr("198.51.100.7"), Tenant: tenantA,
			Fields: []Field{{"transfer", "trf_01JABCD8E3"}, {KeyScope, "transfer_password"}},
		},
		line:  `2026-10-20T07:41:00.123Z ip=198.51.100.7 tenant=transfer.entity-a.example.com event=rate_limited transfer="trf_01JABCD8E3" scope="transfer_password"`,
		banIP: "198.51.100.7",
	},
	{
		// Download stream limits never feed bans (shared NAT, download
		// managers): the integrations ignore this exact line.
		name: "rate limited download streams",
		ev: Event{
			Type: RateLimited, IP: netip.MustParseAddr("198.51.100.8"), Tenant: tenantA,
			Fields: []Field{{"transfer", "trf_01JABCD8E3"}, {KeyScope, "download_streams"}},
		},
		line:  `2026-10-20T07:41:00.123Z ip=198.51.100.8 tenant=transfer.entity-a.example.com event=rate_limited transfer="trf_01JABCD8E3" scope="download_streams"`,
		banIP: "",
	},
	{
		name:  "ipv4-mapped ipv6 is unmapped",
		ev:    Event{Type: RateLimited, IP: netip.MustParseAddr("::ffff:192.0.2.18"), Fields: []Field{{KeyScope, "global"}}},
		line:  `2026-10-20T07:41:00.123Z ip=192.0.2.18 tenant=- event=rate_limited scope="global"`,
		banIP: "192.0.2.18",
	},
	{
		name:  "ipv6 zone is dropped",
		ev:    Event{Type: RateLimited, IP: netip.MustParseAddr("fe80::1").WithZone(" ip=192.0.2.66 x"), Fields: []Field{{KeyScope, "global"}}},
		line:  `2026-10-20T07:41:00.123Z ip=fe80::1 tenant=- event=rate_limited scope="global"`,
		banIP: "fe80::1",
	},
	{
		name:  "no client ip",
		ev:    Event{Type: RateLimited, Fields: []Field{{KeyScope, "global"}}},
		line:  `2026-10-20T07:41:00.123Z ip=- tenant=- event=rate_limited scope="global"`,
		banIP: "",
	},
	{
		name:  "event not used for banning",
		ev:    Event{Type: "transfer_downloaded", IP: netip.MustParseAddr("192.0.2.19"), Tenant: tenantA},
		line:  `2026-10-20T07:41:00.123Z ip=192.0.2.19 tenant=transfer.entity-a.example.com event=transfer_downloaded`,
		banIP: "",
	},
	{
		name: "invalid tenant is replaced",
		ev: Event{
			Type: UnknownFQDN, IP: netip.MustParseAddr("192.0.2.20"), Tenant: "Evil ip=192.0.2.66",
			Fields: []Field{{KeyHost, "x"}},
		},
		line:  `2026-10-20T07:41:00.123Z ip=192.0.2.20 tenant=- event=unknown_fqdn host="x"`,
		banIP: "192.0.2.20",
	},
}

// forgedValues are attacker-controlled values trying to inject a line or a
// fake ip= token.
var forgedValues = []string{
	"x\n2026-10-20T07:41:00.000Z ip=192.0.2.66 tenant=- event=admin_login_failed reason=\"password\"",
	"x\r\n2026-10-20T07:41:00.000Z ip=192.0.2.66 tenant=- event=api_token_invalid",
	"\" ip=192.0.2.66 tenant=- event=api_token_invalid",
	"x\\\" ip=192.0.2.66 \\",
	"x" + lineSep + " ip=192.0.2.66 event=api_token_invalid",
	"x\x00\x1b[31m ip=192.0.2.66",
	"x\x85 ip=192.0.2.66\xff\xfe",
	strings.Repeat("A", 300) + "\n ip=192.0.2.66",
}

func render(t *testing.T, ev Event) string {
	t.Helper()
	var buf bytes.Buffer
	if err := New(&buf, WithClock(fixedClock)).Log(ev); err != nil {
		t.Fatalf("Log: %v", err)
	}
	return buf.String()
}

func TestGoldenLines(t *testing.T) {
	t.Parallel()
	for _, tc := range goldenCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := render(t, tc.ev); got != tc.line+"\n" {
				t.Errorf("line mismatch\n got: %q\nwant: %q", got, tc.line+"\n")
			}
		})
	}
}

func TestGoldenCoversAllEvents(t *testing.T) {
	t.Parallel()
	seen := map[EventType]bool{}
	for _, tc := range goldenCases {
		seen[tc.ev.Type] = true
	}
	for _, e := range allEvents {
		if !seen[e] {
			t.Errorf("no golden line for %s", e)
		}
	}
}

func TestForgedValuesStayOnOneLine(t *testing.T) {
	t.Parallel()
	for _, v := range forgedValues {
		ev := Event{
			Type: UnknownFQDN, IP: netip.MustParseAddr("198.51.100.9"), Tenant: tenantA,
			Fields: []Field{{KeyHost, v}, {"email", v}},
		}
		line := render(t, ev)
		if strings.Count(line, "\n") != 1 || !strings.HasSuffix(line, "\n") || strings.ContainsRune(line, '\r') {
			t.Errorf("value %q broke the line: %q", v, line)
		}
		if !utf8.ValidString(line) {
			t.Errorf("value %q produced invalid UTF-8: %q", v, line)
		}
		p, err := parseLine(line)
		if err != nil {
			t.Fatalf("value %q: %v (line %q)", v, err, line)
		}
		if p.ip != "198.51.100.9" || len(p.fields) != 2 {
			t.Errorf("value %q: parsed %+v", v, p)
		}
		for _, f := range p.fields {
			if want := truncate(v, MaxValueLen); f.Value != want {
				t.Errorf("round trip of %q: got %q want %q", v, f.Value, want)
			}
		}
	}
}

func TestEscaping(t *testing.T) {
	t.Parallel()
	const bs = `\`
	cases := map[string]string{
		"plain text":                   `plain text`,
		`a"b\c`:                        `a\"b\\c`,
		"\n\r\t":                       `\n\r\t`,
		"\x00\x1f\x7f":                 `\x00\x1f\x7f`,
		"\xff\xc3":                     `\xff\xc3`,
		"\xc2\x85\xe2\x80\xa8":         bs + "u0085" + bs + "u2028",
		"\xe2\x80\xae\xf3\xa0\x80\x81": bs + "u202e" + bs + "U000e0001",
		"\xc2\xa0":                     bs + "u00a0",
		"\xc3\xa9\xe6\xbc\xa2 ok":      "\xc3\xa9\xe6\xbc\xa2 ok",
	}
	for in, want := range cases {
		var b bytes.Buffer
		appendEscaped(&b, in)
		if b.String() != want {
			t.Errorf("escape(%q) = %q, want %q", in, b.String(), want)
		}
	}
}

func TestTruncate(t *testing.T) {
	t.Parallel()
	ascii := strings.Repeat("a", 300)
	if got := truncate(ascii, MaxValueLen); len(got) != MaxValueLen {
		t.Errorf("ascii: len %d", len(got))
	}
	// 255 ASCII bytes then a 3-byte rune straddling the limit: cut before it.
	s := strings.Repeat("a", 255) + "€" + "b"
	if got := truncate(s, MaxValueLen); got != strings.Repeat("a", 255) {
		t.Errorf("rune boundary: got len %d", len(got))
	}
	// Only continuation bytes: no rune start nearby, plain byte cut.
	cont := strings.Repeat("\x80", 300)
	if got := truncate(cont, MaxValueLen); len(got) != MaxValueLen {
		t.Errorf("invalid utf-8: len %d", len(got))
	}
	if got := truncate("short", MaxValueLen); got != "short" {
		t.Errorf("short: %q", got)
	}
	// Cut reaching the start of the string.
	if got := truncate("\x80\x80€", 1); got != "\x80" {
		t.Errorf("near start: %q", got)
	}
	if got := truncate("€x", 1); got != "" {
		t.Errorf("rune at start: %q", got)
	}
}

func TestInvalidEventsAreRejected(t *testing.T) {
	t.Parallel()
	ip := netip.MustParseAddr("192.0.2.1")
	long := EventType(strings.Repeat("a", MaxEventLen+1))
	for _, e := range []EventType{"", "Upper", "1abc", "a b", "a\nb", "a-b", "é", long} {
		var buf bytes.Buffer
		err := New(&buf).Log(Event{Type: e, IP: ip})
		if !errors.Is(err, ErrInvalidEvent) || buf.Len() != 0 {
			t.Errorf("event %q: err %v, wrote %q", e, err, buf.String())
		}
	}
	longKey := strings.Repeat("k", MaxKeyLen+1)
	for _, k := range []string{"", "ip", "tenant", "event", "Key", "k1", "a b", "a=b", "a\"", longKey} {
		var buf bytes.Buffer
		err := New(&buf).Log(Event{Type: RateLimited, IP: ip, Fields: []Field{{"scope", "ok"}, {k, "v"}}})
		if !errors.Is(err, ErrInvalidKey) || buf.Len() != 0 {
			t.Errorf("key %q: err %v, wrote %q", k, err, buf.String())
		}
	}
	// Longest valid event and key are accepted.
	var buf bytes.Buffer
	ok := Event{Type: EventType(strings.Repeat("a", MaxEventLen)), IP: ip, Fields: []Field{{strings.Repeat("k", MaxKeyLen), "v"}}}
	if err := New(&buf).Log(ok); err != nil {
		t.Errorf("max lengths: %v", err)
	}
}

func TestTenantValidation(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"":                          "-",
		tenantA:                     tenantA,
		"transfer.localhost":        "transfer.localhost",
		"UPPER.example.com":         "-",
		"a_b.example.com":           "-",
		"a b":                       "-",
		"a\n":                       "-",
		strings.Repeat("a", 253):    strings.Repeat("a", 253),
		strings.Repeat("a", 254):    "-",
		"xn--bcher-kva.example.com": "xn--bcher-kva.example.com",
		"transfer.example.com:8443": "-",
	}
	for in, want := range cases {
		if got := formatTenant(in); got != want {
			t.Errorf("formatTenant(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFormatIP(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   netip.Addr
		want string
	}{
		{netip.Addr{}, "-"},
		{netip.MustParseAddr("192.0.2.1"), "192.0.2.1"},
		{netip.MustParseAddr("::ffff:192.0.2.1"), "192.0.2.1"},
		{netip.MustParseAddr("2001:db8::1"), "2001:db8::1"},
		{netip.MustParseAddr("fe80::1%eth0"), "fe80::1"},
		{netip.IPv6Unspecified(), "::"},
	}
	for _, tc := range cases {
		if got := FormatIP(tc.in); got != tc.want {
			t.Errorf("FormatIP(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestClockIsConvertedToUTC(t *testing.T) {
	t.Parallel()
	line := render(t, Event{Type: RateLimited})
	if !strings.HasPrefix(line, "2026-10-20T07:41:00.123Z ") {
		t.Errorf("timestamp: %q", line)
	}
	// Default clock: a parseable recent UTC timestamp.
	var buf bytes.Buffer
	if err := New(&buf).Log(Event{Type: RateLimited}); err != nil {
		t.Fatal(err)
	}
	ts, err := time.Parse(TimeLayout, strings.Fields(buf.String())[0])
	if err != nil || time.Since(ts) > time.Minute {
		t.Errorf("default clock: %v %v", ts, err)
	}
}

func TestConcurrentLinesDoNotInterleave(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	l := New(&buf, WithClock(fixedClock))
	const goroutines, perG = 16, 200
	var wg sync.WaitGroup
	for g := range goroutines {
		wg.Go(func() {
			for range perG {
				ev := Event{
					Type: RateLimited, IP: netip.AddrFrom4([4]byte{192, 0, 2, byte(g)}),
					Fields: []Field{{KeyScope, strings.Repeat("x", g*10)}},
				}
				if err := l.Log(ev); err != nil {
					t.Error(err)
				}
			}
		})
	}
	wg.Wait()
	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	if len(lines) != goroutines*perG {
		t.Fatalf("got %d lines", len(lines))
	}
	for _, line := range lines {
		if _, err := parseLine(line + "\n"); err != nil {
			t.Fatalf("corrupted line %q: %v", line, err)
		}
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestWriteError(t *testing.T) {
	t.Parallel()
	err := New(failWriter{}).Log(Event{Type: RateLimited})
	if err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Errorf("err = %v", err)
	}
}

func TestNewLoggerLifecycle(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	l := New(&buf)
	if err := l.Reopen(); err != nil {
		t.Errorf("Reopen on New logger: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
	if err := l.Log(Event{Type: RateLimited}); !errors.Is(err, ErrClosed) {
		t.Errorf("Log after Close: %v", err)
	}
	if err := l.Reopen(); !errors.Is(err, ErrClosed) {
		t.Errorf("Reopen after Close: %v", err)
	}
	stop := l.HandleSIGHUP(t.Context()) // must not panic on any platform
	stop()
	stop() // idempotent
}

func TestOpenAppendsAndReopens(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "security.log")
	if err := os.WriteFile(path, []byte("existing\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := Open(path, WithClock(fixedClock))
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Log(goldenCases[0].ev); err != nil {
		t.Fatal(err)
	}
	if err := l.Reopen(); err != nil {
		t.Fatal(err)
	}
	if err := l.Log(goldenCases[1].ev); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := "existing\n" + goldenCases[0].line + "\n" + goldenCases[1].line + "\n"
	if string(got) != want {
		t.Errorf("file content\n got: %q\nwant: %q", got, want)
	}
}

func TestOpenCreatesFile(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "security.log")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	if _, err := os.Stat(path); err != nil {
		t.Errorf("file not created: %v", err)
	}
}

func TestOpenError(t *testing.T) {
	t.Parallel()
	_, err := Open(filepath.Join(t.TempDir(), "missing-dir", "security.log"))
	if err == nil {
		t.Fatal("expected an error for a missing directory")
	}
}

// fakeFile is an io.WriteCloser whose Close can fail.
type fakeFile struct {
	bytes.Buffer
	closeErr error
	closed   bool
}

func (f *fakeFile) Close() error {
	f.closed = true
	return f.closeErr
}

// withOpenFile replaces openFile for the duration of a (non-parallel) test.
func withOpenFile(t *testing.T, fn func(string) (io.WriteCloser, error)) {
	t.Helper()
	orig := openFile
	openFile = fn
	t.Cleanup(func() { openFile = orig })
}

func TestReopenErrors(t *testing.T) { //nolint:paralleltest // replaces the package-level openFile
	first := &fakeFile{closeErr: errors.New("close failed")}
	second := &fakeFile{}
	calls := 0
	withOpenFile(t, func(string) (io.WriteCloser, error) {
		calls++
		switch calls {
		case 1:
			return first, nil
		case 2:
			return nil, errors.New("permission denied")
		default:
			return second, nil
		}
	})
	l, err := Open("security.log")
	if err != nil {
		t.Fatal(err)
	}
	// Failed open: the old file stays in use.
	if err := l.Reopen(); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("Reopen with open failure: %v", err)
	}
	if err := l.Log(Event{Type: RateLimited}); err != nil || first.Len() == 0 {
		t.Errorf("old file not kept: %v", err)
	}
	// Successful open, failing close of the old file: the new file is used.
	if err := l.Reopen(); err == nil || !strings.Contains(err.Error(), "close failed") {
		t.Errorf("Reopen with close failure: %v", err)
	}
	if err := l.Log(Event{Type: RateLimited}); err != nil || second.Len() == 0 || !first.closed {
		t.Errorf("new file not used: %v", err)
	}
	second.closeErr = errors.New("final close failed")
	if err := l.Close(); err == nil || !strings.Contains(err.Error(), "final close failed") {
		t.Errorf("Close error: %v", err)
	}
}

func TestReopenOnSignal(t *testing.T) { //nolint:paralleltest // replaces the package-level openFile
	files := []*fakeFile{{}, {}, {}, {}}
	calls := 0
	withOpenFile(t, func(string) (io.WriteCloser, error) {
		calls++
		if calls == 2 {
			return nil, errors.New("reopen failed")
		}
		return files[calls-1], nil
	})
	errs := make(chan error, 4)
	l, err := Open("security.log", WithErrorHandler(func(err error) { errs <- err }))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	sig := make(chan os.Signal)
	done := make(chan struct{})
	go func() {
		l.reopenOn(ctx, sig)
		close(done)
	}()
	sig <- os.Interrupt // first reopen fails: reported to the handler
	if err := <-errs; err == nil || !strings.Contains(err.Error(), "reopen failed") {
		t.Errorf("handler got %v", err)
	}
	sig <- os.Interrupt // second reopen succeeds
	sig <- os.Interrupt // synchronizes: the previous signal was processed
	cancel()
	<-done
	if calls != 4 || !files[0].closed || !files[2].closed {
		t.Errorf("calls = %d, closed = %v %v", calls, files[0].closed, files[2].closed)
	}
	select {
	case err := <-errs:
		t.Errorf("unexpected error: %v", err)
	default:
	}
}

func TestReopenOnSignalAfterClose(t *testing.T) {
	t.Parallel()
	errs := make(chan error, 1)
	l := New(io.Discard, WithErrorHandler(func(err error) { errs <- err }))
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	sig := make(chan os.Signal)
	done := make(chan struct{})
	go func() {
		l.reopenOn(ctx, sig)
		close(done)
	}()
	sig <- os.Interrupt // Reopen returns ErrClosed: not reported
	sig <- os.Interrupt // synchronizes: the previous signal was processed
	cancel()
	<-done
	select {
	case err := <-errs:
		t.Errorf("ErrClosed reported to the handler: %v", err)
	default:
	}
}

// fakeModeFile records the Chmod calls of tightenMode.
type fakeModeFile struct {
	mode     os.FileMode
	statErr  error
	chmodded []os.FileMode
}

func (f *fakeModeFile) Stat() (os.FileInfo, error) {
	if f.statErr != nil {
		return nil, f.statErr
	}
	return fakeInfo{mode: f.mode}, nil
}

func (f *fakeModeFile) Chmod(mode os.FileMode) error {
	f.chmodded = append(f.chmodded, mode)
	return errors.New("chmod not permitted") // best effort: ignored
}

type fakeInfo struct {
	os.FileInfo
	mode os.FileMode
}

func (i fakeInfo) Mode() os.FileMode { return i.mode }

func TestTightenMode(t *testing.T) { //nolint:paralleltest // replaces the package-level tightenModeEnabled
	prev := tightenModeEnabled
	t.Cleanup(func() { tightenModeEnabled = prev })

	tightenModeEnabled = false
	f := &fakeModeFile{mode: 0o666}
	tightenMode(f)
	if f.chmodded != nil {
		t.Errorf("disabled: chmod %v", f.chmodded)
	}

	tightenModeEnabled = true
	for _, tc := range []struct {
		mode os.FileMode
		want []os.FileMode
	}{
		{0o666, []os.FileMode{0o640}},
		{0o644, []os.FileMode{0o640}},
		{0o604, []os.FileMode{0o600}},
		{0o755, []os.FileMode{0o640}},
		{0o640, nil},
		{0o600, nil},
		{0o400, nil},
	} {
		f := &fakeModeFile{mode: tc.mode}
		tightenMode(f)
		if len(f.chmodded) != len(tc.want) || (tc.want != nil && f.chmodded[0] != tc.want[0]) {
			t.Errorf("mode %o: chmod %v, want %v", tc.mode, f.chmodded, tc.want)
		}
	}
	f = &fakeModeFile{statErr: errors.New("stat failed")}
	tightenMode(f)
	if f.chmodded != nil {
		t.Errorf("stat error: chmod %v", f.chmodded)
	}
}

// lineSep is U+2028 LINE SEPARATOR and nonPrintable mixes control, invalid
// and non-printable bytes, written as byte escapes on purpose.
const (
	lineSep      = "\xe2\x80\xa8"
	nonPrintable = "\x00\xff" + lineSep
	eAcute       = "\xc3\xa9"
)
