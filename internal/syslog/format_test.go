package syslog

import (
	"bytes"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ed-fr/transteira/internal/events"
)

var testFormatter = formatter{facility: 16, hostname: "host.example.com", procID: "42"}

var testTime = time.Date(2026, 10, 27, 8, 9, 10, 123456789, time.UTC)

func TestFormatAuditGolden(t *testing.T) {
	rec := &events.LogRecord{
		Stream: events.StreamAudit, Time: testTime.In(time.FixedZone("x", 3600)), Tenant: "ten_01",
		Action: "admin.login", ActorKind: "admin", Actor: "adm_01",
		IP:         netip.MustParseAddr("::ffff:203.0.113.7"),
		ObjectKind: "admin", ObjectID: "adm_01", AuditID: "aud_01",
		Details: []byte(`{"secret":"never exported"}`),
	}
	got := string(testFormatter.format(rec, time.Time{}))
	want := `<133>1 2026-10-27T08:09:10.123456Z host.example.com transteira 42 admin.login ` +
		`[transteira@32473 stream="audit" tenant="ten_01" action="admin.login" actor_kind="admin" actor="adm_01" ` +
		`ip="203.0.113.7" object_kind="admin" object_id="adm_01" audit_id="aud_01"] admin.login admin adm_01`
	if got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
}

func TestFormatSecurityGolden(t *testing.T) {
	line := `2026-10-27T08:09:10.123Z ip=203.0.113.7 tenant=transfer.entity-a.example.com event=unknown_fqdn host="evil\"]\nx.example.net"`
	rec := &events.LogRecord{
		Stream: events.StreamSecurity, Tenant: "transfer.entity-a.example.com", Action: "unknown_fqdn",
		IP: netip.MustParseAddr("fe80::1%eth0"),
		Fields: []events.Field{
			{Key: "host", Value: "evil\"]\nx\\.example.net"},
			{Key: "tenant", Value: "forged"},
			{Key: "bad key=\"]", Value: "v"},
			{Key: "=\"]", Value: "dropped"},
		},
		Line: line,
	}
	got := string(testFormatter.format(rec, testTime))
	want := `<132>1 2026-10-27T08:09:10.123456Z host.example.com transteira 42 unknown_fqdn ` +
		`[transteira@32473 stream="security" tenant="transfer.entity-a.example.com" action="unknown_fqdn" ip="fe80::1" ` +
		`host="evil\"\]\nx\\.example.net" badkey="v"] ` + line
	if got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
}

func TestFormatMinimal(t *testing.T) {
	f := formatter{facility: 0, hostname: "-", procID: "1"}
	got := string(f.format(&events.LogRecord{}, testTime))
	if want := `<5>1 2026-10-27T08:09:10.123456Z - transteira 1 - [transteira@32473]`; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	got = string(f.format(&events.LogRecord{Stream: events.StreamAudit, ObjectID: "x"}, testTime))
	if want := `<5>1 2026-10-27T08:09:10.123456Z - transteira 1 audit [transteira@32473 stream="audit" object_id="x"] x`; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestMsgID(t *testing.T) {
	cases := map[string]string{
		"admin.login":           "admin.login",
		"a b\x00é":              "a_b___",
		strings.Repeat("x", 40): strings.Repeat("x", 32),
		"":                      "audit",
	}
	for in, want := range cases {
		if got := msgID(&events.LogRecord{Stream: events.StreamAudit, Action: in}); got != want {
			t.Errorf("msgID(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSDName(t *testing.T) {
	cases := map[string]string{
		"reason":                "reason",
		"a b=c]d\"e\x01é":       "abcde",
		strings.Repeat("k", 40): strings.Repeat("k", 32),
		"= ]\"":                 "",
	}
	for in, want := range cases {
		if got := sdName(in); got != want {
			t.Errorf("sdName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAppendEscaped(t *testing.T) {
	cases := []struct {
		in   string
		mode int
		want string
	}{
		{"plain é", escapeSD, "plain é"},
		{`a"b\c]d`, escapeSD, `a\"b\\c\]d`},
		{`a"b\c]d`, escapeQuote, `a\"b\\c]d`},
		{`a"b\c]d`, 0, `a"b\c]d`},
		{"l1\nl2\rl3\tl4", 0, `l1\nl2\rl3\tl4`},
		{"\x00\x1b\x7f", 0, `\x00\x1b\x7f`},
		{"\xff\xfe", 0, `\xff\xfe`},
		{string([]rune{0x85, 0x2028, 0x2029, 0x202e, 0xe0001}), 0, strings.ReplaceAll("|u0085|u2028|u2029|u202e|U000e0001", "|", `\`)},
	}
	for _, c := range cases {
		var b bytes.Buffer
		appendEscaped(&b, c.in, c.mode)
		if b.String() != c.want {
			t.Errorf("appendEscaped(%q, %d) = %q, want %q", c.in, c.mode, b.String(), c.want)
		}
	}
}

func TestAppendParamTruncates(t *testing.T) {
	var b bytes.Buffer
	appendParam(&b, "k", strings.Repeat("a", MaxValueLen+10))
	if want := ` k="` + strings.Repeat("a", MaxValueLen) + `"`; b.String() != want {
		t.Fatalf("got %q", b.String())
	}
	b.Reset()
	appendParam(&b, "k", "")
	if b.Len() != 0 {
		t.Fatalf("empty value written: %q", b.String())
	}
}

func TestTruncate(t *testing.T) {
	cases := []struct {
		in   string
		n    int
		want string
	}{
		{"abc", 5, "abc"},
		{"abcdef", 3, "abc"},
		{"aé", 2, "a"},          // é is 2 bytes: never cut inside
		{"a€b", 3, "a"},         // € is 3 bytes
		{"a\U0001F600", 4, "a"}, // 4-byte rune
		{"a\x80\x80\x80\x80\x80", 5, "a\x80\x80\x80\x80"}, // invalid UTF-8: byte cut
	}
	for _, c := range cases {
		if got := string(truncate([]byte(c.in), c.n)); got != c.want {
			t.Errorf("truncate(%q, %d) = %q, want %q", c.in, c.n, got, c.want)
		}
	}
	if got := truncateString("aé", 2); got != "a" {
		t.Errorf("truncateString = %q", got)
	}
}

func TestFormatAuditMessageEscapes(t *testing.T) {
	// The audit values escape the backslash (and the quote) in the MSG too:
	// a literal backslash followed by n stays apart from an escaped line
	// feed.
	rec := &events.LogRecord{Stream: events.StreamAudit, Action: `a"b\c]`, ObjectKind: `k\n`, ObjectID: "x\ny"}
	got := string(testFormatter.format(rec, testTime))
	if want := `action="a\"b\\c\]" object_kind="k\\n" object_id="x\ny"] a\"b\\c] k\\n x\ny`; !strings.HasSuffix(got, want) {
		t.Fatalf("got %q, want suffix %q", got, want)
	}
	// The security line, already escaped when written locally, is kept as
	// is but for its control characters.
	rec = &events.LogRecord{Stream: events.StreamSecurity, Line: `ts=x type="a\"b" field="k\n"` + "\x01"}
	got = string(testFormatter.format(rec, testTime))
	if want := `] ts=x type="a\"b" field="k\n"\x01`; !strings.HasSuffix(got, want) {
		t.Fatalf("got %q, want suffix %q", got, want)
	}
}

func TestAppendEscapedMax(t *testing.T) {
	cases := []struct {
		in       string
		n        int
		want     string
		complete bool
	}{
		{"a\x01b", 100, `a\x01b`, true},
		{"a\x01b", 6, `a\x01b`, true},
		{"a\x01b", 5, `a\x01`, false},
		{"a\x01b", 4, "a", false}, // never inside an escape sequence
		{"aé", 2, "a", false},     // never inside a rune
		{"", 0, "", true},
	}
	for _, c := range cases {
		var b bytes.Buffer
		n, complete := appendEscapedMax(&b, c.in, 0, c.n)
		if b.String() != c.want || n != b.Len() || complete != c.complete {
			t.Errorf("appendEscapedMax(%q, %d) = %q, %d, %v", c.in, c.n, b.String(), n, complete)
		}
	}
}

func TestAppendMessageLimit(t *testing.T) {
	audit := &events.LogRecord{Action: "act", ObjectKind: "kind", ObjectID: "id"}
	sec := &events.LogRecord{Line: "\x01\x01"}
	cases := []struct {
		rec   *events.LogRecord
		limit int
		want  string
	}{
		{audit, 100, " act kind id"},
		{audit, 12, " act kind id"},
		{audit, 11, " act kind i"},
		{audit, 9, " act kind"},
		{audit, 5, " act"}, // no room for a space and one byte of the next part
		{audit, 4, " act"},
		{audit, 3, " ac"},
		{audit, 1, ""},
		{sec, 9, ` \x01\x01`},
		{sec, 8, ` \x01`},
		{sec, 4, ""}, // the first escape does not fit: no lone space
		{&events.LogRecord{Action: `a\b`}, 100, ` a\\b`},
		{&events.LogRecord{Action: `a\b`}, 3, " a"}, // never inside the escaped backslash
		{&events.LogRecord{Line: `a\b`}, 100, ` a\b`},
		{&events.LogRecord{}, 100, ""},
	}
	for _, c := range cases {
		var b bytes.Buffer
		appendMessage(&b, c.rec, c.limit)
		if b.String() != c.want || b.Len() > c.limit {
			t.Errorf("appendMessage(%+v, %d) = %q, want %q", c.rec, c.limit, b.String(), c.want)
		}
	}
}

// inflated returns n bytes of control characters, each escaped as 4 bytes.
func inflated(n int) string { return strings.Repeat("\x01", n) }

func TestFormatFitsDatagram(t *testing.T) {
	udp := formatter{facility: 16, hostname: "host.example.com", procID: "42", maxLen: MaxDatagram}
	ip := netip.MustParseAddr("203.0.113.7")
	check := func(name string, rec *events.LogRecord, f formatter, wantParams string) parsedMessage {
		t.Helper()
		out := f.format(rec, testTime)
		if len(out) > MaxDatagram || !utf8.Valid(out) {
			t.Fatalf("%s: %d bytes", name, len(out))
		}
		p, ok := parseMessage(string(out))
		if !ok {
			t.Fatalf("%s: malformed message %q", name, out)
		}
		if got := strings.Join(p.params, ","); got != wantParams {
			t.Fatalf("%s: params %s, want %s", name, got, wantParams)
		}
		return p
	}

	// The structured data fits: only the MSG part is cut, between escapes.
	line := inflated(3000)
	rec := &events.LogRecord{Stream: events.StreamSecurity, Tenant: "ten_01", Action: "unknown_fqdn", IP: ip, Line: line}
	p := check("long line", rec, udp, "stream,tenant,action,ip")
	var full bytes.Buffer
	appendEscaped(&full, line, 0)
	if p.msg == "" || len(p.msg)%4 != 0 || !strings.HasPrefix(full.String(), p.msg) {
		t.Fatalf("long line: msg cut inside an escape: %d bytes", len(p.msg))
	}
	if got := len(udp.format(rec, testTime)); got < MaxDatagram-3 {
		t.Fatalf("long line: %d bytes, the room is not used", got)
	}

	// Inflated values: whole parameters are removed from the end, the kept
	// ones (stream, tenant, action, ip) staying.
	rec = &events.LogRecord{
		Stream: events.StreamAudit, Tenant: "ten_01", Action: "transfer.created", IP: ip,
		ActorKind: inflated(MaxValueLen), Actor: inflated(MaxValueLen), ObjectKind: inflated(MaxValueLen),
		ObjectID: inflated(MaxValueLen), AuditID: inflated(MaxValueLen),
		Fields: []events.Field{{Key: "f1", Value: inflated(MaxValueLen)}, {Key: "f2", Value: inflated(MaxValueLen)}},
		Line:   inflated(1000),
	}
	p = check("inflated fields", rec, udp, "stream,tenant,action,actor_kind,ip")
	if p.values[3] != strings.Repeat(`\x01`, MaxValueLen) {
		t.Fatal("inflated fields: value altered")
	}

	// Even the kept parameters go, from the end, when they cannot all fit.
	long := formatter{facility: 16, hostname: strings.Repeat("h", MaxHostnameLen), procID: "42", maxLen: MaxDatagram}
	rec = &events.LogRecord{
		Stream: events.StreamSecurity, Tenant: inflated(MaxValueLen), Action: inflated(MaxValueLen), IP: ip,
		Actor: inflated(MaxValueLen),
	}
	check("inflated kept", rec, long, "stream,tenant")

	// Without a limit nothing is removed.
	out := testFormatter.format(rec, testTime)
	if p, ok := parseMessage(string(out)); !ok || len(p.params) != 5 || len(out) <= MaxDatagram {
		t.Fatalf("unlimited: %d bytes", len(out))
	}
}

func TestFitParams(t *testing.T) {
	ps := []sdParam{{text: []byte("aa"), keep: true}, {text: []byte("bbb")}, {text: []byte("c"), keep: true}, {text: []byte("dddd")}}
	got, total := fitParams(append([]sdParam(nil), ps...), 20, 17)
	if len(got) != 3 || string(got[2].text) != "c" || total != 16 {
		t.Fatalf("got %d params, total %d", len(got), total)
	}
	got, total = fitParams(append([]sdParam(nil), ps...), 20, 12)
	if len(got) != 1 || string(got[0].text) != "aa" || total != 12 {
		t.Fatalf("got %d params, total %d", len(got), total)
	}
	got, total = fitParams(append([]sdParam(nil), ps...), 20, 0)
	if len(got) != 0 || total != 10 {
		t.Fatalf("got %d params, total %d", len(got), total)
	}
}

func TestFormatIP(t *testing.T) {
	if got := formatIP(netip.Addr{}); got != "" {
		t.Errorf("invalid addr = %q", got)
	}
	if got := formatIP(netip.MustParseAddr("2001:db8::1")); got != "2001:db8::1" {
		t.Errorf("ipv6 = %q", got)
	}
}

// parsedMessage is an RFC 5424 message split by a strict test parser.
type parsedMessage struct {
	header []string
	params []string // parameter names, in order
	values []string // unescaped parameter values
	msg    string
}

// parseMessage parses msg strictly; ok is false when it is not one well
// formed RFC 5424 message with one transteira structured data element.
func parseMessage(msg string) (p parsedMessage, ok bool) {
	for range 6 {
		i := strings.IndexByte(msg, ' ')
		if i <= 0 {
			return p, false
		}
		p.header = append(p.header, msg[:i])
		msg = msg[i+1:]
	}
	if !strings.HasPrefix(msg, "["+SDID) {
		return p, false
	}
	msg = msg[len(SDID)+1:]
	for {
		switch {
		case strings.HasPrefix(msg, "]"):
			msg = msg[1:]
			if msg != "" {
				if msg[0] != ' ' {
					return p, false
				}
				p.msg = msg[1:]
			}
			return p, true
		case strings.HasPrefix(msg, " "):
			msg = msg[1:]
		default:
			return p, false
		}
		eq := strings.Index(msg, `="`)
		if eq <= 0 || strings.ContainsAny(msg[:eq], " ]\"=") {
			return p, false
		}
		p.params = append(p.params, msg[:eq])
		msg = msg[eq+2:]
		var v strings.Builder
		for {
			if msg == "" {
				return p, false
			}
			c := msg[0]
			if c == '"' {
				msg = msg[1:]
				break
			}
			if c == ']' {
				return p, false // must be escaped
			}
			if c == '\\' && len(msg) > 1 && strings.IndexByte(`"\]`, msg[1]) >= 0 {
				v.WriteByte(msg[1])
				msg = msg[2:]
				continue
			}
			v.WriteByte(c)
			msg = msg[1:]
		}
		p.values = append(p.values, v.String())
	}
}

func FuzzFormat(f *testing.F) {
	f.Add("admin.login", "adm\"]\n<13>1 fake", "host", "evil\r\n] \"x\\", "line\nsecond"+string(rune(0x2028)))
	f.Add("", "", "", "", "")
	f.Add("a\x00b", "\xff\xfe", "k=\"]", "\u0085", "\x1b[31m")
	f.Fuzz(func(t *testing.T, action, actor, key, value, line string) {
		rec := &events.LogRecord{
			Stream: events.StreamSecurity, Action: action, Actor: actor, Tenant: "t",
			Fields: []events.Field{{Key: key, Value: value}}, Line: line,
		}
		out := testFormatter.format(rec, testTime)
		if !utf8.Valid(out) {
			t.Fatalf("invalid UTF-8: %q", out)
		}
		for _, r := range string(out) {
			if r != ' ' && !unicode.IsPrint(r) {
				t.Fatalf("non-printable rune %U in %q", r, out)
			}
		}
		p, ok := parseMessage(string(out))
		if !ok {
			t.Fatalf("malformed message %q", out)
		}
		want := []string{"stream", "tenant"}
		wantValues := []string{"security", "t"}
		if action != "" {
			want, wantValues = append(want, "action"), append(wantValues, "")
		}
		if actor != "" {
			want, wantValues = append(want, "actor"), append(wantValues, "")
		}
		if name := sdName(key); name != "" && !fixedParams[name] && value != "" {
			want, wantValues = append(want, name), append(wantValues, "")
		}
		if strings.Join(p.params, ",") != strings.Join(want, ",") {
			t.Fatalf("params %v, want %v in %q", p.params, want, out)
		}
		if p.values[0] != wantValues[0] || p.values[1] != wantValues[1] {
			t.Fatalf("values %v", p.values)
		}
		if len(p.header) != 6 || p.header[0] != "<132>1" {
			t.Fatalf("header %v", p.header)
		}
		// Over UDP, the message stays well formed and within MaxDatagram,
		// even with inflated values.
		udp := testFormatter
		udp.maxLen = MaxDatagram
		big := &events.LogRecord{
			Stream: events.StreamSecurity, Action: action, Actor: strings.Repeat(actor, 64), Tenant: "t",
			Fields: []events.Field{
				{Key: key, Value: strings.Repeat(value, 64)},
				{Key: key + "2", Value: strings.Repeat(value, 64)},
				{Key: key + "3", Value: strings.Repeat(value, 64)},
			},
			Line: strings.Repeat(line, 64),
		}
		uout := udp.format(big, testTime)
		up, ok := parseMessage(string(uout))
		if !ok || len(uout) > MaxDatagram || !utf8.Valid(uout) {
			t.Fatalf("bad datagram (%d bytes) %q", len(uout), uout)
		}
		if len(up.params) < 2 || up.params[0] != "stream" || up.params[1] != "tenant" {
			t.Fatalf("datagram params %v", up.params)
		}
		// Octet-counting framing gives back exactly the message.
		e := &Exporter{network: "tcp"}
		framed := string(e.frame(out))
		sp := strings.IndexByte(framed, ' ')
		n, err := strconv.Atoi(framed[:sp])
		if err != nil || n != len(out) || framed[sp+1:] != string(out) {
			t.Fatalf("bad frame %q", framed)
		}
	})
}
