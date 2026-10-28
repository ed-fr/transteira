package metrics

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

// parsedSample is one sample line of the text format.
type parsedSample struct {
	name   string
	labels map[string]string
	order  []string
	value  float64
}

var (
	reHelp = regexp.MustCompile(`^# HELP ([a-zA-Z_:][a-zA-Z0-9_:]*) (.*)$`)
	reType = regexp.MustCompile(`^# TYPE ([a-zA-Z_:][a-zA-Z0-9_:]*) (counter|gauge)$`)
	reName = regexp.MustCompile(`^[a-zA-Z_:][a-zA-Z0-9_:]*`)
	reKey  = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*`)
)

// parseSampleLine parses a sample line (name, optional labels, value),
// unescaping the label values.
func parseSampleLine(line string) (parsedSample, error) {
	s := parsedSample{labels: map[string]string{}}
	s.name = reName.FindString(line)
	if s.name == "" {
		return s, errors.New("no metric name")
	}
	rest := line[len(s.name):]
	if strings.HasPrefix(rest, "{") {
		rest = rest[1:]
		for {
			key := reKey.FindString(rest)
			if key == "" || !strings.HasPrefix(rest[len(key):], `="`) {
				return s, fmt.Errorf("bad label in %q", line)
			}
			rest = rest[len(key)+2:]
			var val strings.Builder
			closed := false
			for i := 0; i < len(rest); i++ {
				c := rest[i]
				switch {
				case c == '\\' && i+1 < len(rest):
					i++
					switch rest[i] {
					case '\\':
						val.WriteByte('\\')
					case '"':
						val.WriteByte('"')
					case 'n':
						val.WriteByte('\n')
					default:
						return s, fmt.Errorf("bad escape in %q", line)
					}
				case c == '"':
					rest = rest[i+1:]
					closed = true
				case c == '\n':
					return s, errors.New("raw line feed")
				default:
					val.WriteByte(c)
				}
				if closed {
					break
				}
			}
			if !closed {
				return s, fmt.Errorf("unterminated label value in %q", line)
			}
			if _, dup := s.labels[key]; dup {
				return s, fmt.Errorf("duplicate label %q", key)
			}
			s.labels[key] = val.String()
			s.order = append(s.order, key)
			if strings.HasPrefix(rest, ",") {
				rest = rest[1:]
				continue
			}
			if !strings.HasPrefix(rest, "}") {
				return s, fmt.Errorf("unterminated label set in %q", line)
			}
			rest = rest[1:]
			break
		}
	}
	if !strings.HasPrefix(rest, " ") {
		return s, fmt.Errorf("no value separator in %q", line)
	}
	v, err := strconv.ParseFloat(rest[1:], 64)
	if err != nil {
		return s, fmt.Errorf("bad value in %q: %w", line, err)
	}
	s.value = v
	return s, nil
}

// parseExposition checks the whole text format: every family starts with
// HELP then TYPE, its samples follow, every line is valid, names come from
// the catalog in catalog order, and each family appears once.
func parseExposition(t *testing.T, text string) map[string][]parsedSample {
	t.Helper()
	if !strings.HasSuffix(text, "\n") {
		t.Fatalf("output does not end with a line feed: %q", text)
	}
	index := map[string]int{}
	for i, d := range catalog {
		index[d.Name] = i
	}
	out := map[string][]parsedSample{}
	current, last := "", -1
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		if m := reHelp.FindStringSubmatch(line); m != nil {
			pos, ok := index[m[1]]
			if !ok {
				t.Fatalf("unknown family %q", m[1])
			}
			if pos <= last {
				t.Fatalf("family %q out of catalog order", m[1])
			}
			last = pos
			if i+1 >= len(lines) {
				t.Fatalf("HELP without TYPE for %q", m[1])
			}
			tm := reType.FindStringSubmatch(lines[i+1])
			if tm == nil || tm[1] != m[1] || tm[2] != string(catalog[pos].Type) {
				t.Fatalf("bad TYPE line after HELP %q: %q", m[1], lines[i+1])
			}
			current = m[1]
			i++
			continue
		}
		s, err := parseSampleLine(line)
		if err != nil {
			t.Fatal(err)
		}
		if s.name != current {
			t.Fatalf("sample %q outside its family %q", s.name, current)
		}
		if want := catalog[index[current]].Labels; !slices.Equal(s.order, want) {
			t.Fatalf("labels %v of %q, want %v", s.order, s.name, want)
		}
		out[current] = append(out[current], s)
	}
	return out
}

func TestCatalog(t *testing.T) {
	t.Parallel()
	got := Catalog()
	if len(got) != 26 {
		t.Fatalf("catalog has %d families, want 26", len(got))
	}
	seen := map[string]bool{}
	for _, d := range got {
		if !strings.HasPrefix(d.Name, "transteira_") || seen[d.Name] || d.Help == "" {
			t.Errorf("bad family %+v", d)
		}
		seen[d.Name] = true
		if strings.HasSuffix(d.Name, "_total") != (d.Type == Counter) {
			t.Errorf("%s: type %s does not match the _total suffix", d.Name, d.Type)
		}
	}
	// The result is a copy.
	got[0].Name = "changed"
	got[0].Labels[0] = "changed"
	again := Catalog()
	if again[0].Name != nameBuildInfo || again[0].Labels[0] != labelVersion {
		t.Fatal("Catalog returned the internal slice")
	}
}

func TestFormatFloat(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		in   float64
		want string
	}{
		{0, "0"},
		{1, "1"},
		{-3, "-3"},
		{1932735283200, "1932735283200"},
		{0.3, "0.3"},
		{1761555570.5, "1761555570.5"},
		{1e-7, "1e-07"},
		{1e22, "1e+22"},
		{math.MaxFloat64, "1.7976931348623157e+308"},
		{math.NaN(), "NaN"},
		{math.Inf(1), "+Inf"},
		{math.Inf(-1), "-Inf"},
	} {
		if got := formatFloat(tc.in); got != tc.want {
			t.Errorf("formatFloat(%v) = %q, want %q", tc.in, got, tc.want)
		}
		if got, err := strconv.ParseFloat(formatFloat(tc.in), 64); err != nil || (got != tc.in && !math.IsNaN(tc.in)) {
			t.Errorf("formatFloat(%v) does not parse back: %v, %v", tc.in, got, err)
		}
	}
	if formatInt(-5) != "-5" || formatUint(math.MaxUint64) != "18446744073709551615" || formatBool(true) != "1" || formatBool(false) != "0" {
		t.Fatal("bad integer formatting")
	}
}

func TestEscaping(t *testing.T) {
	t.Parallel()
	if got := escapeLabel("a\\b\"c\nd"); got != `a\\b\"c\nd` {
		t.Fatalf("escapeLabel = %q", got)
	}
	if got := escapeHelp("a\\b\"c\nd"); got != `a\\b"c\nd` {
		t.Fatalf("escapeHelp = %q", got)
	}
	if got := escapeLabel("x\xffy"); got != "x�y" {
		t.Fatalf("escapeLabel(invalid UTF-8) = %q", got)
	}
}

func TestExpositionSortsAndSkips(t *testing.T) {
	t.Parallel()
	e := newExposition()
	e.add(nameHTTPRequests, "2", "5xx")
	e.add(nameHTTPRequests, "1", "2xx")
	e.add("transteira_unknown", "1")
	e.add(nameBuildInfo, "1", "1.0.0") // missing commit label value
	e.add(nameUptime, "7")
	var b bytes.Buffer
	e.writeTo(&b)
	want := `# HELP transteira_build_info Version of the running instance.
# TYPE transteira_build_info gauge
transteira_build_info{version="1.0.0",commit=""} 1
# HELP transteira_uptime_seconds Seconds since the start of the process.
# TYPE transteira_uptime_seconds gauge
transteira_uptime_seconds 7
# HELP transteira_http_requests_total HTTP requests, per status class.
# TYPE transteira_http_requests_total counter
transteira_http_requests_total{class="2xx"} 1
transteira_http_requests_total{class="5xx"} 2
`
	if b.String() != want {
		t.Fatalf("got:\n%s\nwant:\n%s", b.String(), want)
	}
	parseExposition(t, b.String())
}

func TestParseSampleLineErrors(t *testing.T) {
	t.Parallel()
	for _, line := range []string{
		"",
		"x{",
		`x{a=1} 1`,
		`x{a="1\q"} 1`,
		`x{a="1`,
		`x{a="1",a="2"} 1`,
		`x{a="1"`,
		`x{a="1"}1`,
		`x{a="1"} y`,
		"x{a=\"\n\"} 1",
	} {
		if _, err := parseSampleLine(line); err == nil {
			t.Errorf("parseSampleLine(%q) accepted", line)
		}
	}
}

// FuzzLabelEscaping checks that any tenant label value yields exactly one
// sample line that parses back to the value (invalid UTF-8 replaced).
func FuzzLabelEscaping(f *testing.F) {
	for _, seed := range []string{"", "ten_01JAB00000000000000ENT1TYA", `a"b`, `a\b`, "a\nb", `\n`, `\"`, "\xff", "é}{,=\"", "\r\t"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, v string) {
		e := newExposition()
		e.add(nameTransfers, "1", v)
		var b bytes.Buffer
		e.writeTo(&b)
		lines := strings.Split(strings.TrimSuffix(b.String(), "\n"), "\n")
		if len(lines) != 3 {
			t.Fatalf("%d lines for %q: %q", len(lines), v, b.String())
		}
		s, err := parseSampleLine(lines[2])
		if err != nil {
			t.Fatal(err)
		}
		want := v
		if !utf8.ValidString(v) {
			want = strings.ToValidUTF8(v, "�")
		}
		if s.labels[labelTenant] != want || s.value != 1 {
			t.Fatalf("parsed %q = %v, want %q", s.labels[labelTenant], s.value, want)
		}
		parseExposition(t, b.String())
	})
}
