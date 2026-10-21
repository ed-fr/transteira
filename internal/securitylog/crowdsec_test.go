package securitylog

import (
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

const (
	crowdsecParser   = "../../integrations/crowdsec/parsers/s01-parse/transteira-logs.yaml"
	crowdsecBF       = "../../integrations/crowdsec/scenarios/transteira-bf.yaml"
	crowdsecFQDNScan = "../../integrations/crowdsec/scenarios/transteira-fqdn-scan.yaml"
)

// grokPatterns are RE2 equivalents of the grok macros used by the parser.
var grokPatterns = map[string]string{
	"TIMESTAMP_ISO8601": `\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?`,
	"IP":                `(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f]{0,4}:[0-9A-Fa-f:.]*)`,
	"NOTSPACE":          `\S+`,
	"WORD":              `\b\w+\b`,
	"GREEDYDATA":        `.*`,
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// loadCrowdsecPattern extracts the single-quoted grok pattern of the parser
// and converts it to a Go regular expression.
func loadCrowdsecPattern(t *testing.T) *regexp.Regexp {
	t.Helper()
	m := regexp.MustCompile(`(?m)^\s*pattern:\s*'(.*)'\s*$`).FindStringSubmatch(readFile(t, crowdsecParser))
	if m == nil {
		t.Fatal("grok pattern not found")
	}
	macro := regexp.MustCompile(`%\{(\w+)(?::(\w+))?\}`)
	var unknown []string
	expr := macro.ReplaceAllStringFunc(m[1], func(s string) string {
		sub := macro.FindStringSubmatch(s)
		p, ok := grokPatterns[sub[1]]
		if !ok {
			unknown = append(unknown, sub[1])
		}
		if sub[2] != "" {
			return "(?P<" + sub[2] + ">" + p + ")"
		}
		return p
	})
	if len(unknown) > 0 {
		t.Fatalf("grok macros without a Go equivalent: %v", unknown)
	}
	return regexp.MustCompile(expr)
}

// crowdsecIP returns the source_ip extracted from line, or "" if it does
// not parse.
func crowdsecIP(re *regexp.Regexp, line string) (ip, event string) {
	m := re.FindStringSubmatch(strings.TrimRight(line, "\n"))
	if m == nil {
		return "", ""
	}
	return m[re.SubexpIndex("source_ip")], m[re.SubexpIndex("event")]
}

func TestCrowdsecGoldenLines(t *testing.T) {
	t.Parallel()
	re := loadCrowdsecPattern(t)
	for _, tc := range goldenCases {
		ip, event := crowdsecIP(re, tc.line)
		want := tc.ev.Type
		if !tc.ev.IP.IsValid() {
			want = ""
		}
		if ip != FormatIP(tc.ev.IP) && (tc.ev.IP.IsValid() || ip != "") {
			t.Errorf("%s: source_ip %q, want %q", tc.name, ip, FormatIP(tc.ev.IP))
		}
		if event != string(want) {
			t.Errorf("%s: event %q, want %q", tc.name, event, want)
		}
	}
}

func TestCrowdsecForgedLines(t *testing.T) {
	t.Parallel()
	re := loadCrowdsecPattern(t)
	for _, v := range forgedValues {
		line := render(t, Event{Type: UnknownFQDN, IP: netip.MustParseAddr("198.51.100.9"), Fields: []Field{{KeyHost, v}}})
		if ip, event := crowdsecIP(re, line); ip != "198.51.100.9" || event != string(UnknownFQDN) {
			t.Errorf("value %q: parsed ip %q event %q", v, ip, event)
		}
		line = render(t, Event{Type: UnknownFQDN, Fields: []Field{{KeyHost, v}}})
		if ip, _ := crowdsecIP(re, line); ip != "" {
			t.Errorf("value %q: line without ip parsed %q", v, ip)
		}
	}
	for _, line := range []string{
		`x 2026-10-20T07:41:00.123Z ip=192.0.2.66 tenant=- event=api_token_invalid`,
		`2026-10-20T07:41:00.123Z ip=- tenant=- event=api_token_invalid ip=192.0.2.66`,
		`2026-10-20T07:41:00.123Z tenant=- ip=192.0.2.66 event=api_token_invalid`,
	} {
		if ip, _ := crowdsecIP(re, line); ip != "" {
			t.Errorf("forged line %q parsed ip %q", line, ip)
		}
	}
}

// scenarioFilter returns the filter of a scenario, YAML escapes of double
// quotes removed.
func scenarioFilter(t *testing.T, path string) string {
	t.Helper()
	m := regexp.MustCompile(`(?m)^filter:\s*"(.*)"\s*$`).FindStringSubmatch(readFile(t, path))
	if m == nil {
		t.Fatalf("%s: no filter", path)
	}
	return strings.ReplaceAll(m[1], `\"`, `"`)
}

// scenarioEvents returns the distinct event names quoted in the filter of
// a scenario.
func scenarioEvents(t *testing.T, path string) []string {
	t.Helper()
	filter := scenarioFilter(t, path)
	var out []string
	for _, q := range regexp.MustCompile(`'([a-z_]+)'`).FindAllStringSubmatch(filter, -1) {
		if q[1] != "transteira_security" {
			out = append(out, q[1])
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func TestCrowdsecScenariosCoverCatalogue(t *testing.T) {
	t.Parallel()
	var bf []string
	for _, e := range allEvents {
		if e != UnknownFQDN {
			bf = append(bf, string(e))
		}
	}
	slices.Sort(bf)
	if got := scenarioEvents(t, crowdsecBF); !slices.Equal(got, bf) {
		t.Errorf("brute force scenario events = %v, want %v", got, bf)
	}
	if got := scenarioEvents(t, crowdsecFQDNScan); !slices.Equal(got, []string{string(UnknownFQDN)}) {
		t.Errorf("scan scenario events = %v", got)
	}
}

func TestCrowdsecDownloadStreamsExcluded(t *testing.T) {
	t.Parallel()
	re := loadCrowdsecPattern(t)
	filter := scenarioFilter(t, crowdsecBF)
	m := regexp.MustCompile(`!\(evt\.Meta\.transteira_event == 'rate_limited' && evt\.Parsed\.fields matches '([^']*)'\)`).FindStringSubmatch(filter)
	if m == nil {
		t.Fatalf("no download_streams exclusion in %q", filter)
	}
	excluded := regexp.MustCompile(m[1])
	events := scenarioEvents(t, crowdsecBF)
	for _, tc := range downloadStreamsLines {
		line := strings.TrimRight(render(t, tc.ev), "\n")
		sub := re.FindStringSubmatch(line)
		if sub == nil {
			t.Fatalf("%s: line %q not parsed", tc.name, line)
		}
		event, fields := sub[re.SubexpIndex("event")], sub[re.SubexpIndex("fields")]
		counted := slices.Contains(events, event) && (event != string(RateLimited) || !excluded.MatchString(fields))
		if counted != tc.banned {
			t.Errorf("%s: counted %v, want %v (line %q)", tc.name, counted, tc.banned, line)
		}
	}
}
