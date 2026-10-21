package securitylog

import (
	"bufio"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
)

const fail2banFilter = "../../integrations/fail2ban/filter.d/transteira.conf"

// goAddr is a Go (RE2) stand-in for fail2ban's <ADDR>/<HOST>: an IPv4 or
// IPv6 literal, never "-". The captured text is checked with netip.
const goAddr = `(?P<host>(?:\d{1,3}\.){3}\d{1,3}|[0-9A-Fa-f]{0,4}:[0-9A-Fa-f:.]*)`

// fail2banSim reproduces how fail2ban applies a filter to a line: find the
// date with datepattern, remove it, then search each failregex in what
// remains (fail2ban keeps the text around the date, leading space
// included); a line matched by a failregex is dropped when an ignoreregex
// also matches it.
type fail2banSim struct {
	date    *regexp.Regexp
	fails   []*regexp.Regexp
	ignores []*regexp.Regexp
	event   []string // events of the _events alternation
}

// match returns the address banned for line, or "" when no failregex matches.
func (s *fail2banSim) match(line string) string {
	line = strings.TrimRight(line, "\n")
	loc := s.date.FindStringIndex(line)
	if loc == nil {
		return ""
	}
	rest := line[:loc[0]] + line[loc[1]:]
	for _, re := range s.fails {
		if m := re.FindStringSubmatch(rest); m != nil {
			for _, ig := range s.ignores {
				if ig.MatchString(rest) {
					return ""
				}
			}
			return m[re.SubexpIndex("host")]
		}
	}
	return ""
}

var (
	f2bOnce sync.Once
	f2bSim  *fail2banSim
	f2bErr  string
)

// loadFail2ban parses the [Definition] section of the filter (keys, indented
// continuation lines, %(name)s interpolation, %% escapes) and converts it to
// Go regular expressions.
func loadFail2ban(t testing.TB) *fail2banSim {
	t.Helper()
	f2bOnce.Do(func() { f2bSim, f2bErr = buildFail2ban() })
	if f2bErr != "" {
		t.Fatal(f2bErr)
	}
	return f2bSim
}

func buildFail2ban() (*fail2banSim, string) {
	f, err := os.Open(fail2banFilter)
	if err != nil {
		return nil, err.Error()
	}
	defer func() { _ = f.Close() }()
	defs := map[string]string{}
	section, last := "", ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		raw := sc.Text()
		trimmed := strings.TrimSpace(raw)
		switch {
		case trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";"):
			continue
		case strings.HasPrefix(trimmed, "["):
			section = trimmed
		case section != "[Definition]":
		case raw[0] == ' ' || raw[0] == '\t':
			defs[last] += "\n" + trimmed
		default:
			k, v, ok := strings.Cut(raw, "=")
			if !ok {
				return nil, "malformed line: " + raw
			}
			last = strings.TrimSpace(k)
			defs[last] = strings.TrimSpace(v)
		}
	}
	interp := regexp.MustCompile(`%\((\w+)\)s`)
	expand := func(v string) string {
		for range 5 {
			v = interp.ReplaceAllStringFunc(v, func(m string) string { return defs[interp.FindStringSubmatch(m)[1]] })
		}
		return strings.ReplaceAll(v, "%%", "%")
	}
	sim := &fail2banSim{event: strings.Split(defs["_events"], "|")}

	dp := expand(defs["datepattern"])
	dp = strings.ReplaceAll(dp, "{^LN-BEG}", "^")
	dp = strings.NewReplacer("%Y", `\d{4}`, "%m", `\d{2}`, "%d", `\d{2}`, "%H", `\d{2}`,
		"%M", `\d{2}`, "%S", `\d{2}`, "%f", `\d+`).Replace(dp)
	if sim.date, err = regexp.Compile(dp); err != nil {
		return nil, "datepattern: " + err.Error()
	}
	for fr := range strings.SplitSeq(expand(defs["failregex"]), "\n") {
		fr = strings.NewReplacer("<ADDR>", goAddr, "<HOST>", goAddr).Replace(fr)
		re, err := regexp.Compile(fr)
		if err != nil {
			return nil, "failregex: " + err.Error()
		}
		sim.fails = append(sim.fails, re)
	}
	if ir := expand(defs["ignoreregex"]); ir != "" {
		for ig := range strings.SplitSeq(ir, "\n") {
			ig = strings.NewReplacer("<ADDR>", goAddr, "<HOST>", goAddr).Replace(ig)
			re, err := regexp.Compile(ig)
			if err != nil {
				return nil, "ignoreregex: " + err.Error()
			}
			sim.ignores = append(sim.ignores, re)
		}
	}
	if len(sim.fails) == 0 || defs["failregex"] == "" {
		return nil, "no failregex"
	}
	return sim, ""
}

func TestFail2banEventsMatchCatalogue(t *testing.T) {
	t.Parallel()
	sim := loadFail2ban(t)
	got := slices.Clone(sim.event)
	want := make([]string, 0, len(allEvents))
	for _, e := range allEvents {
		want = append(want, string(e))
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("_events = %v, want %v", got, want)
	}
}

func TestFail2banGoldenLines(t *testing.T) {
	t.Parallel()
	sim := loadFail2ban(t)
	for _, tc := range goldenCases {
		if got := sim.match(tc.line + "\n"); got != tc.banIP {
			t.Errorf("%s: banned %q, want %q", tc.name, got, tc.banIP)
		}
		if tc.banIP != "" {
			if _, err := netip.ParseAddr(tc.banIP); err != nil {
				t.Errorf("%s: %v", tc.name, err)
			}
		}
	}
}

func TestFail2banForgedLines(t *testing.T) {
	t.Parallel()
	sim := loadFail2ban(t)
	for _, v := range forgedValues {
		for _, ev := range []Event{
			{Type: UnknownFQDN, IP: netip.MustParseAddr("198.51.100.9"), Fields: []Field{{KeyHost, v}}},
			{Type: "transfer_downloaded", IP: netip.MustParseAddr("198.51.100.9"), Fields: []Field{{"name", v}}},
			{Type: UnknownFQDN, Fields: []Field{{KeyHost, v}}},
		} {
			line := render(t, ev)
			want := ""
			if ev.Type == UnknownFQDN && ev.IP.IsValid() {
				want = "198.51.100.9"
			}
			if got := sim.match(line); got != want {
				t.Errorf("value %q: banned %q, want %q (line %q)", v, got, want, line)
			}
		}
	}
	// Hand-forged lines that TransTeira never writes must not match either.
	for _, line := range []string{
		`x 2026-10-20T07:41:00.123Z ip=192.0.2.66 tenant=- event=api_token_invalid`,
		`2026-10-20T07:41:00.123Z tenant=- ip=192.0.2.66 event=api_token_invalid`,
		`2026-10-20T07:41:00.123Z ip=- tenant=- event=api_token_invalid ip=192.0.2.66`,
		`2026-10-20T07:41:00.123Z ip=- tenant=- event=api_token_invalid x=" ip=192.0.2.66 "`,
		`2026-10-20T07:41:00.123Z ip=192.0.2.66 tenant=- event=api_token_invalid_suffix`,
		`2026-10-20T07:41:00.123Z ip=evil.example.net tenant=- event=api_token_invalid`,
	} {
		if got := sim.match(line); got != "" {
			t.Errorf("forged line %q banned %q", line, got)
		}
	}
}

// downloadStreamsLines are rate_limited lines checked against the
// exclusion of the download_streams scope by both integrations: banned
// tells whether the line must still count as a failure.
var downloadStreamsLines = []struct {
	name   string
	ev     Event
	banned bool
}{
	{"download_streams", Event{
		Type: RateLimited, IP: netip.MustParseAddr("198.51.100.30"), Tenant: "transfer.entity-a.example.com",
		Fields: []Field{{"transfer", "trf_01JABCD8E3"}, {KeyScope, "download_streams"}},
	}, false},
	{"transfer_password", Event{
		Type: RateLimited, IP: netip.MustParseAddr("198.51.100.31"), Tenant: "transfer.entity-a.example.com",
		Fields: []Field{{"transfer", "trf_01JABCD8E3"}, {KeyScope, "transfer_password"}},
	}, true},
	{"scope smuggled in the transfer", Event{
		Type: RateLimited, IP: netip.MustParseAddr("198.51.100.32"),
		Fields: []Field{{"transfer", `trf_01JABCD8E3" scope="download_streams`}, {KeyScope, "global"}},
	}, true},
	{"scope smuggled in the scope", Event{
		Type: RateLimited, IP: netip.MustParseAddr("198.51.100.33"),
		Fields: []Field{{"transfer", "trf_01JABCD8E3"}, {KeyScope, `x" scope="download_streams`}},
	}, true},
	{"scope smuggled before the scope", Event{
		Type: RateLimited, IP: netip.MustParseAddr("198.51.100.34"),
		Fields: []Field{{"transfer", `trf_01JABCD8E3" scope="download_streams"`}, {KeyScope, "download_streams"}},
	}, true},
	{"extra field after the scope", Event{
		Type: RateLimited, IP: netip.MustParseAddr("198.51.100.35"),
		Fields: []Field{{"transfer", "trf_01JABCD8E3"}, {KeyScope, "download_streams"}, {"x", "y"}},
	}, true},
	{"scope first", Event{
		Type: RateLimited, IP: netip.MustParseAddr("198.51.100.36"),
		Fields: []Field{{KeyScope, "download_streams"}, {"x", `" scope="download_streams`}},
	}, true},
	{"another event", Event{
		Type: TransferPasswordInvalid, IP: netip.MustParseAddr("198.51.100.37"),
		Fields: []Field{{"transfer", "trf_01JABCD8E3"}, {KeyScope, "download_streams"}},
	}, true},
}

func TestFail2banDownloadStreamsIgnored(t *testing.T) {
	t.Parallel()
	sim := loadFail2ban(t)
	for _, tc := range downloadStreamsLines {
		line := render(t, tc.ev)
		want := ""
		if tc.banned {
			want = tc.ev.IP.String()
		}
		if got := sim.match(line); got != want {
			t.Errorf("%s: banned %q, want %q (line %q)", tc.name, got, want, line)
		}
	}
}
