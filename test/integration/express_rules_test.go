package integration_test

import (
	"bufio"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The shipped fail2ban filter and CrowdSec brute force scenario, applied
// to the security log lines a real server wrote (since 2.3, threat model
// T-405, P87): internal/securitylog checks them against golden lines,
// these tests against the lines of the express flows. The conversion to
// Go regular expressions follows internal/securitylog/fail2ban_test.go and
// crowdsec_test.go.

const (
	// fail2banFilterPath, crowdsecParserPath and crowdsecBFPath are the
	// shipped rules, relative to this package.
	fail2banFilterPath = "../../integrations/fail2ban/filter.d/transteira.conf"
	crowdsecParserPath = "../../integrations/crowdsec/parsers/s01-parse/transteira-logs.yaml"
	crowdsecBFPath     = "../../integrations/crowdsec/scenarios/transteira-bf.yaml"
	// banAddr stands for fail2ban's <ADDR> and <HOST>: an IPv4 or IPv6
	// literal, never "-".
	banAddr = `(?P<host>(?:\d{1,3}\.){3}\d{1,3}|[0-9A-Fa-f]{0,4}:[0-9A-Fa-f:.]*)`
)

// grokMacros are RE2 equivalents of the grok macros of the CrowdSec
// parser.
var grokMacros = map[string]string{
	"TIMESTAMP_ISO8601": `\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?`,
	"IP":                `(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f]{0,4}:[0-9A-Fa-f:.]*)`,
	"NOTSPACE":          `\S+`,
	"WORD":              `\b\w+\b`,
	"GREEDYDATA":        `.*`,
}

// banRules are the shipped rules as Go regular expressions.
type banRules struct {
	// f2bDate, f2bFail and f2bIgnore are the datepattern, failregex and
	// ignoreregex of the fail2ban filter.
	f2bDate            *regexp.Regexp
	f2bFail, f2bIgnore []*regexp.Regexp
	// csLine is the grok pattern of the CrowdSec parser, csEvents the
	// events of the brute force scenario and csExcluded its exclusion of
	// rate_limited lines.
	csLine     *regexp.Regexp
	csEvents   []string
	csExcluded *regexp.Regexp
}

// loadBanRules reads the shipped rules.
func loadBanRules(t *testing.T) *banRules {
	t.Helper()
	r := &banRules{}
	r.loadFail2ban(t)
	r.loadCrowdsec(t)
	return r
}

// loadFail2ban parses the [Definition] section of the fail2ban filter
// (keys, indented continuation lines, %(name)s interpolation, %% escapes).
func (r *banRules) loadFail2ban(t *testing.T) {
	t.Helper()
	f, err := os.Open(fail2banFilterPath)
	if err != nil {
		t.Fatal(err)
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
		case strings.HasPrefix(trimmed, "["):
			section = trimmed
		case section != "[Definition]":
		case raw[0] == ' ' || raw[0] == '\t':
			defs[last] += "\n" + trimmed
		default:
			k, v, ok := strings.Cut(raw, "=")
			if !ok {
				t.Fatalf("%s: malformed line %q", fail2banFilterPath, raw)
			}
			last = strings.TrimSpace(k)
			defs[last] = strings.TrimSpace(v)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	interp := regexp.MustCompile(`%\((\w+)\)s`)
	expand := func(v string) string {
		for range 5 {
			v = interp.ReplaceAllStringFunc(v, func(m string) string { return defs[interp.FindStringSubmatch(m)[1]] })
		}
		return strings.ReplaceAll(v, "%%", "%")
	}
	date := strings.ReplaceAll(expand(defs["datepattern"]), "{^LN-BEG}", "^")
	date = strings.NewReplacer("%Y", `\d{4}`, "%m", `\d{2}`, "%d", `\d{2}`, "%H", `\d{2}`, "%M", `\d{2}`, "%S", `\d{2}`,
		"%f", `\d+`).Replace(date)
	r.f2bDate = regexp.MustCompile(date)
	addr := strings.NewReplacer("<ADDR>", banAddr, "<HOST>", banAddr)
	for key, out := range map[string]*[]*regexp.Regexp{"failregex": &r.f2bFail, "ignoreregex": &r.f2bIgnore} {
		for re := range strings.SplitSeq(expand(defs[key]), "\n") {
			if re != "" {
				*out = append(*out, regexp.MustCompile(addr.Replace(re)))
			}
		}
	}
	if len(r.f2bFail) == 0 {
		t.Fatalf("%s: no failregex", fail2banFilterPath)
	}
}

// loadCrowdsec reads the grok pattern of the parser and the filter of the
// brute force scenario.
func (r *banRules) loadCrowdsec(t *testing.T) {
	t.Helper()
	read := func(path string) string {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	m := regexp.MustCompile(`(?m)^\s*pattern:\s*'(.*)'\s*$`).FindStringSubmatch(read(crowdsecParserPath))
	if m == nil {
		t.Fatalf("%s: no grok pattern", crowdsecParserPath)
	}
	macro := regexp.MustCompile(`%\{(\w+)(?::(\w+))?\}`)
	r.csLine = regexp.MustCompile(macro.ReplaceAllStringFunc(m[1], func(s string) string {
		sub := macro.FindStringSubmatch(s)
		p, ok := grokMacros[sub[1]]
		if !ok {
			t.Fatalf("grok macro %s has no Go equivalent", sub[1])
		}
		if sub[2] != "" {
			return "(?P<" + sub[2] + ">" + p + ")"
		}
		return p
	}))
	f := regexp.MustCompile(`(?m)^filter:\s*"(.*)"\s*$`).FindStringSubmatch(read(crowdsecBFPath))
	if f == nil {
		t.Fatalf("%s: no filter", crowdsecBFPath)
	}
	filter := strings.ReplaceAll(f[1], `\"`, `"`)
	list := regexp.MustCompile(`evt\.Meta\.transteira_event in \[([^\]]*)\]`).FindStringSubmatch(filter)
	excl := regexp.MustCompile(`!\(evt\.Meta\.transteira_event == 'rate_limited' && evt\.Parsed\.fields matches '([^']*)'\)`).
		FindStringSubmatch(filter)
	if list == nil || excl == nil {
		t.Fatalf("%s: unexpected filter %q", crowdsecBFPath, filter)
	}
	for _, q := range regexp.MustCompile(`'([a-z_]+)'`).FindAllStringSubmatch(list[1], -1) {
		r.csEvents = append(r.csEvents, q[1])
	}
	r.csExcluded = regexp.MustCompile(excl[1])
}

// fail2ban returns the address the fail2ban filter counts a failure for
// on line, "" when it ignores the line.
func (r *banRules) fail2ban(line string) string {
	loc := r.f2bDate.FindStringIndex(line)
	if loc == nil {
		return ""
	}
	rest := line[:loc[0]] + line[loc[1]:]
	for _, re := range r.f2bFail {
		m := re.FindStringSubmatch(rest)
		if m == nil {
			continue
		}
		if slices.ContainsFunc(r.f2bIgnore, func(ig *regexp.Regexp) bool { return ig.MatchString(rest) }) {
			return ""
		}
		return m[re.SubexpIndex("host")]
	}
	return ""
}

// crowdsec returns the source IP the CrowdSec brute force scenario counts
// an event for on line, "" when it ignores the line.
func (r *banRules) crowdsec(line string) string {
	m := r.csLine.FindStringSubmatch(line)
	if m == nil {
		return ""
	}
	event, fields := m[r.csLine.SubexpIndex("event")], m[r.csLine.SubexpIndex("fields")]
	if !slices.Contains(r.csEvents, event) || (event == "rate_limited" && r.csExcluded.MatchString(fields)) {
		return ""
	}
	return m[r.csLine.SubexpIndex("source_ip")]
}
