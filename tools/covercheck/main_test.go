package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
)

const testModule = "github.com/ed-fr/transteira"

func TestRun(t *testing.T) {
	cfg := filepath.Join("testdata", "config.json")
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantOut    []string
		wantErrOut string
	}{
		{
			name:     "pass with missing critical package",
			args:     []string{"-profile", filepath.Join("testdata", "pass.out"), "-config", cfg, "-root", "testdata"},
			wantCode: exitPass,
			wantOut: []string{
				"internal/crypto", "100.0%", "ok",
				"internal/tenant", "MISSING (not yet implemented)",
				"internal/example", "90.9%",
				"TOTAL", "94.1%",
				"coverage gate: PASS",
			},
		},
		{
			name:     "critical package below threshold",
			args:     []string{"-profile", filepath.Join("testdata", "fail_critical.out"), "-config", cfg, "-root", "testdata"},
			wantCode: exitFail,
			wantOut:  []string{"FAIL", "coverage gate: FAIL (internal/crypto at 90.0% below required 100.0%)"},
		},
		{
			name:     "global below threshold",
			args:     []string{"-profile", filepath.Join("testdata", "fail_global.out"), "-config", cfg, "-root", "testdata"},
			wantCode: exitFail,
			wantOut:  []string{"coverage gate: FAIL (global coverage 66.6% below required 85.0%)"},
		},
		{
			name:       "malformed profile",
			args:       []string{"-profile", filepath.Join("testdata", "malformed.out"), "-config", cfg, "-root", "testdata"},
			wantCode:   exitUsage,
			wantErrOut: "profile line 2",
		},
		{
			name:       "empty profile",
			args:       []string{"-profile", filepath.Join("testdata", "empty.out"), "-config", cfg, "-root", "testdata"},
			wantCode:   exitUsage,
			wantErrOut: "no statements to measure",
		},
		{
			name:       "everything excluded",
			args:       []string{"-profile", filepath.Join("testdata", "excluded_only.out"), "-config", cfg, "-root", "testdata"},
			wantCode:   exitUsage,
			wantErrOut: "no statements to measure",
		},
		{
			name:     "critical sub-packages checked individually",
			args:     []string{"-profile", filepath.Join("testdata", "subpackages.out"), "-config", "thresholds.json", "-root", "testdata"},
			wantCode: exitFail,
			wantOut: []string{
				"internal/store/sqlite", "internal/store/postgres",
				"coverage gate: FAIL (internal/store/postgres at 50.0% below required 100.0%)",
			},
		},
		{
			name:     "critical package on disk but absent from profile",
			args:     []string{"-profile", filepath.Join("testdata", "pass.out"), "-config", cfg, "-root", filepath.Join("testdata", "disk")},
			wantCode: exitFail,
			wantOut: []string{
				"FAIL (on disk, absent from profile)",
				"internal/tenant: critical package present on disk but absent from the coverage profile",
			},
		},
		{
			name:       "missing profile",
			args:       []string{"-profile", filepath.Join("testdata", "nope.out"), "-config", cfg, "-root", "testdata"},
			wantCode:   exitUsage,
			wantErrOut: "reading profile",
		},
		{
			name:       "missing config",
			args:       []string{"-profile", filepath.Join("testdata", "pass.out"), "-config", filepath.Join("testdata", "nope.json")},
			wantCode:   exitUsage,
			wantErrOut: "reading config",
		},
		{
			name:       "invalid config",
			args:       []string{"-profile", filepath.Join("testdata", "pass.out"), "-config", filepath.Join("testdata", "config_invalid.json")},
			wantCode:   exitUsage,
			wantErrOut: "module must not be empty",
		},
		{
			name:       "unknown flag",
			args:       []string{"-bogus"},
			wantCode:   exitUsage,
			wantErrOut: "flag provided but not defined",
		},
		{
			name:       "extra argument",
			args:       []string{"-config", cfg, "extra"},
			wantCode:   exitUsage,
			wantErrOut: "unexpected arguments",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			code := run(tt.args, &out, &errOut)
			if code != tt.wantCode {
				t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, tt.wantCode, out.String(), errOut.String())
			}
			for _, w := range tt.wantOut {
				if !strings.Contains(out.String(), w) {
					t.Errorf("stdout does not contain %q:\n%s", w, out.String())
				}
			}
			if tt.wantErrOut != "" && !strings.Contains(errOut.String(), tt.wantErrOut) {
				t.Errorf("stderr does not contain %q:\n%s", tt.wantErrOut, errOut.String())
			}
		})
	}
}

func TestRunWriteError(t *testing.T) {
	var errOut bytes.Buffer
	args := []string{"-profile", filepath.Join("testdata", "pass.out"), "-config", filepath.Join("testdata", "config.json")}
	if code := run(args, failWriter{}, &errOut); code != exitUsage {
		t.Fatalf("exit code = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(errOut.String(), "writing report") {
		t.Errorf("stderr = %q", errOut.String())
	}
}

func TestRunRealThresholds(t *testing.T) {
	var out, errOut bytes.Buffer
	args := []string{"-profile", filepath.Join("testdata", "pass.out"), "-config", "thresholds.json", "-root", "testdata"}
	if code := run(args, &out, &errOut); code != exitPass {
		t.Fatalf("exit code = %d, stderr = %s", code, errOut.String())
	}
	for _, pkg := range []string{
		"internal/adminauth", "internal/apitoken", "internal/audit",
		"internal/httpserver/middleware", "internal/store", "internal/tenant",
	} {
		if !strings.Contains(out.String(), pkg) {
			t.Errorf("report does not list critical package %s", pkg)
		}
	}
}

func TestParseConfig(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr string
	}{
		{name: "valid", input: `{"global": 85, "module": "m", "critical": {"a": 100}}`},
		{name: "not json", input: `{`, wantErr: "parsing config"},
		{name: "unknown field", input: `{"module": "m", "globl": 85}`, wantErr: "unknown field"},
		{name: "empty module", input: `{"global": 85}`, wantErr: "module must not be empty"},
		{name: "global too high", input: `{"global": 101, "module": "m"}`, wantErr: "global threshold"},
		{name: "global negative", input: `{"global": -1, "module": "m"}`, wantErr: "global threshold"},
		{name: "critical out of range", input: `{"global": 85, "module": "m", "critical": {"a": 150}}`, wantErr: `for "a"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseConfig(strings.NewReader(tt.input))
			checkErr(t, err, tt.wantErr)
		})
	}
}

func TestParseLine(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		want    Block
		wantErr string
	}{
		{
			name: "valid",
			line: "github.com/ed-fr/transteira/internal/crypto/aead.go:10.2,12.3 4 1",
			want: Block{File: "github.com/ed-fr/transteira/internal/crypto/aead.go", Pos: "10.2,12.3", Stmts: 4, Count: 1},
		},
		{
			name: "windows path with drive letter",
			line: "C:/src/x/main.go:1.1,2.2 1 0",
			want: Block{File: "C:/src/x/main.go", Pos: "1.1,2.2", Stmts: 1},
		},
		{name: "too few fields", line: "a.go:1.1,2.2 1", wantErr: "expected 3 fields"},
		{name: "too many fields", line: "a.go:1.1,2.2 1 1 1", wantErr: "expected 3 fields"},
		{name: "no colon", line: "a.go 1 1", wantErr: "missing file name"},
		{name: "empty file name", line: ":1.1,2.2 1 1", wantErr: "missing file name"},
		{name: "no comma", line: "a.go:1.1 1 1", wantErr: "invalid position"},
		{name: "no dot", line: "a.go:1,2.2 1 1", wantErr: "invalid position"},
		{name: "empty number", line: "a.go:1.,2.2 1 1", wantErr: "invalid position"},
		{name: "non digit", line: "a.go:1.1,2.x 1 1", wantErr: "invalid position"},
		{name: "bad statements", line: "a.go:1.1,2.2 x 1", wantErr: "invalid statement count"},
		{name: "negative statements", line: "a.go:1.1,2.2 -1 1", wantErr: "invalid statement count"},
		{name: "bad count", line: "a.go:1.1,2.2 1 x", wantErr: "invalid execution count"},
		{name: "negative count", line: "a.go:1.1,2.2 1 -3", wantErr: "invalid execution count"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseLine(tt.line)
			checkErr(t, err, tt.wantErr)
			if tt.wantErr == "" && got != tt.want {
				t.Errorf("ParseLine() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestParseProfile(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantBlocks int
		wantErr    string
	}{
		{name: "set", input: "mode: set\na.go:1.1,2.2 1 1\n", wantBlocks: 1},
		{name: "count with blank lines", input: "\nmode: count\n\na.go:1.1,2.2 1 4\nb.go:1.1,2.2 1 0\n", wantBlocks: 2},
		{name: "concatenated profiles", input: "mode: atomic\na.go:1.1,2.2 1 1\nmode: atomic\na.go:1.1,2.2 1 0\n", wantBlocks: 2},
		{name: "mode only", input: "mode: set\n", wantBlocks: 0},
		{name: "empty", input: "", wantErr: "missing mode line"},
		{name: "no mode", input: "a.go:1.1,2.2 1 1\n", wantErr: "line 1: missing mode line"},
		{name: "unknown mode", input: "mode: weird\n", wantErr: "unknown mode"},
		{name: "bad line", input: "mode: set\nnonsense\n", wantErr: "line 2"},
		{name: "line too long", input: "mode: set\n" + strings.Repeat("a", 2*1024*1024), wantErr: "reading profile"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseProfile(strings.NewReader(tt.input))
			checkErr(t, err, tt.wantErr)
			if tt.wantErr == "" && len(got) != tt.wantBlocks {
				t.Errorf("got %d blocks, want %d", len(got), tt.wantBlocks)
			}
		})
	}
}

func TestPackageOf(t *testing.T) {
	tests := []struct {
		file, want string
	}{
		{testModule + "/internal/crypto/aead.go", "internal/crypto"},
		{testModule + "/main.go", "."},
		{testModule + "x/foo/a.go", testModule + "x/foo"},
		{"example.com/other/pkg/a.go", "example.com/other/pkg"},
	}
	for _, tt := range tests {
		if got := packageOf(testModule, tt.file); got != tt.want {
			t.Errorf("packageOf(%q) = %q, want %q", tt.file, got, tt.want)
		}
	}
}

func TestHasPathPrefix(t *testing.T) {
	tests := []struct {
		pkg, prefix string
		want        bool
	}{
		{"internal/api/gen", "internal/api/gen", true},
		{"internal/api/gen/sub", "internal/api/gen", true},
		{"internal/api/gen/sub", "internal/api/gen/", true},
		{"internal/api/generic", "internal/api/gen", false},
		{"internal/api", "internal/api/gen", false},
	}
	for _, tt := range tests {
		if got := hasPathPrefix(tt.pkg, tt.prefix); got != tt.want {
			t.Errorf("hasPathPrefix(%q, %q) = %v, want %v", tt.pkg, tt.prefix, got, tt.want)
		}
	}
}

func TestAggregate(t *testing.T) {
	cfg := Config{Module: testModule, Exclude: []string{"internal/testutil"}}
	f := testModule + "/internal/store/store.go"
	blocks := []Block{
		{File: f, Pos: "1.1,2.2", Stmts: 3, Count: 0},
		{File: f, Pos: "1.1,2.2", Stmts: 3, Count: 2}, // duplicate, covered
		{File: f, Pos: "4.1,5.2", Stmts: 2, Count: 0},
		{File: f, Pos: "4.1,5.2", Stmts: 2, Count: 0}, // duplicate, uncovered
		{File: testModule + "/internal/testutil/smtp.go", Pos: "1.1,2.2", Stmts: 50, Count: 0},
	}
	stats := Aggregate(cfg, blocks)
	if len(stats) != 1 {
		t.Fatalf("got %d packages, want 1: %v", len(stats), stats)
	}
	got := *stats["internal/store"]
	want := PackageStat{Name: "internal/store", Statements: 5, Covered: 3}
	if got != want {
		t.Errorf("stat = %+v, want %+v", got, want)
	}
}

func TestEvaluate(t *testing.T) {
	cfg := Config{Global: 85, Module: testModule, Critical: map[string]float64{"a": 100, "b": 90, "missing": 100}}
	tests := []struct {
		name        string
		stats       map[string]*PackageStat
		wantReasons int
	}{
		{
			name: "all pass",
			stats: map[string]*PackageStat{
				"a": {Name: "a", Statements: 10, Covered: 10},
				"b": {Name: "b", Statements: 10, Covered: 9},
				"c": {Name: "c", Statements: 10, Covered: 8},
			},
		},
		{
			name: "two critical failures and global",
			stats: map[string]*PackageStat{
				"a": {Name: "a", Statements: 10000, Covered: 9999},
				"b": {Name: "b", Statements: 10, Covered: 8},
				"c": {Name: "c", Statements: 10000, Covered: 0},
			},
			wantReasons: 3,
		},
		{name: "empty profile", stats: map[string]*PackageStat{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rep := Evaluate(cfg, tt.stats, fstest.MapFS{})
			if len(rep.Reasons) != tt.wantReasons {
				t.Errorf("reasons = %v, want %d", rep.Reasons, tt.wantReasons)
			}
			if rep.Passed() != (tt.wantReasons == 0) {
				t.Errorf("Passed() = %v", rep.Passed())
			}
			for i := 1; i < len(rep.Rows); i++ {
				if rep.Rows[i-1].Stat.Name >= rep.Rows[i].Stat.Name {
					t.Errorf("rows not sorted: %q before %q", rep.Rows[i-1].Stat.Name, rep.Rows[i].Stat.Name)
				}
			}
			last := rep.Rows[len(rep.Rows)-1]
			if last.Stat.Name != "missing" || last.Present || !last.OK {
				t.Errorf("missing critical package row = %+v", last)
			}
		})
	}
}

func TestCriticalThreshold(t *testing.T) {
	cfg := Config{Critical: map[string]float64{"internal/store": 100, "internal/store/legacy": 70, "internal/storage": 50}}
	tests := []struct {
		pkg       string
		want      float64
		wantFound bool
	}{
		{"internal/store", 100, true},
		{"internal/store/sqlite", 100, true},
		{"internal/store/legacy", 70, true},
		{"internal/store/legacy/v1", 70, true},
		{"internal/storage", 50, true},
		{"internal/storex", 0, false},
		{"internal", 0, false},
	}
	for _, tt := range tests {
		got, found := criticalThreshold(cfg, tt.pkg)
		if got != tt.want || found != tt.wantFound {
			t.Errorf("criticalThreshold(%q) = %v, %v; want %v, %v", tt.pkg, got, found, tt.want, tt.wantFound)
		}
	}
}

func TestEvaluateSubPackages(t *testing.T) {
	cfg := Config{Global: 0, Critical: map[string]float64{"store": 100, "tenant": 100}}
	stats := map[string]*PackageStat{
		"store/sqlite":   {Name: "store/sqlite", Statements: 4, Covered: 4},
		"store/postgres": {Name: "store/postgres", Statements: 4, Covered: 3},
	}
	rep := Evaluate(cfg, stats, fstest.MapFS{})
	if len(rep.Reasons) != 1 || !strings.Contains(rep.Reasons[0], "store/postgres") {
		t.Fatalf("reasons = %v", rep.Reasons)
	}
	names := make([]string, 0, len(rep.Rows))
	for _, r := range rep.Rows {
		names = append(names, r.Stat.Name)
	}
	// "store" itself must not be reported missing since sub-packages exist.
	if got := strings.Join(names, ","); got != "store/postgres,store/sqlite,tenant" {
		t.Errorf("rows = %s", got)
	}
}

func TestHasGoSources(t *testing.T) {
	src := &fstest.MapFile{Data: []byte("package x\n")}
	fsys := fstest.MapFS{
		"internal/crypto/aead.go":             src,
		"internal/store/sqlite/db.go":         src,
		"internal/onlytests/x_test.go":        src,
		"internal/onlytestdata/testdata/a.go": src,
		"internal/hidden/.cache/a.go":         src,
		"internal/under/_old/a.go":            src,
		"internal/excl/storetest/suite.go":    src,
		"internal/notgo/README.md":            src,
	}
	cfg := Config{Exclude: []string{"internal/excl/storetest"}}
	tests := []struct {
		dir  string
		want bool
	}{
		{"internal/crypto", true},
		{"internal/store", true}, // sources only in a sub-package
		{"internal/onlytests", false},
		{"internal/onlytestdata", false},
		{"internal/hidden", false},
		{"internal/under", false},
		{"internal/excl", false},
		{"internal/notgo", false},
		{"internal/adminauht", false}, // does not exist
	}
	for _, tt := range tests {
		if got := hasGoSources(cfg, fsys, tt.dir); got != tt.want {
			t.Errorf("hasGoSources(%q) = %v, want %v", tt.dir, got, tt.want)
		}
	}
}

func TestEvaluateCriticalOnDisk(t *testing.T) {
	cfg := Config{Critical: map[string]float64{"internal/adminauth": 100, "internal/adminauht": 100}}
	fsys := fstest.MapFS{"internal/adminauth/auth.go": &fstest.MapFile{Data: []byte("package adminauth\n")}}
	stats := map[string]*PackageStat{"other": {Name: "other", Statements: 1, Covered: 1}}
	rep := Evaluate(cfg, stats, fsys)
	if len(rep.Reasons) != 1 || !strings.HasPrefix(rep.Reasons[0], "internal/adminauth: critical package present on disk") {
		t.Fatalf("reasons = %v", rep.Reasons)
	}
	for _, r := range rep.Rows {
		switch r.Stat.Name {
		case "internal/adminauth":
			if !r.OnDisk || r.OK {
				t.Errorf("adminauth row = %+v", r)
			}
		case "internal/adminauht":
			if r.OnDisk || !r.OK || r.Present {
				t.Errorf("typo row = %+v", r)
			}
		}
	}
}

func TestFindModuleRoot(t *testing.T) {
	root, err := findModuleRoot(".")
	if err != nil {
		t.Fatalf("findModuleRoot: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Errorf("no go.mod in %s", root)
	}

	if _, err := findModuleRoot(t.TempDir()); err == nil {
		// A temp dir may only have a go.mod above it on unusual systems.
		t.Log("go.mod found above temp dir; skipping negative check")
	} else if !strings.Contains(err.Error(), "no go.mod found") {
		t.Errorf("error = %v", err)
	}
}

func TestRunNoModuleRoot(t *testing.T) {
	dir := t.TempDir()
	if _, err := findModuleRoot(dir); err == nil {
		t.Skip("a go.mod exists above the temp dir")
	}
	profile, _ := filepath.Abs(filepath.Join("testdata", "pass.out"))
	cfg, _ := filepath.Abs(filepath.Join("testdata", "config.json"))
	t.Chdir(dir)
	var out, errOut bytes.Buffer
	if code := run([]string{"-profile", profile, "-config", cfg}, &out, &errOut); code != exitUsage {
		t.Fatalf("exit code = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(errOut.String(), "locating module root") {
		t.Errorf("stderr = %q", errOut.String())
	}
}

func TestHasStatements(t *testing.T) {
	if hasStatements(map[string]*PackageStat{"a": {Name: "a"}}) {
		t.Error("package without statements reported as measurable")
	}
	if !hasStatements(map[string]*PackageStat{"a": {Name: "a", Statements: 1}}) {
		t.Error("package with statements reported as empty")
	}
}

func TestFormatPercent(t *testing.T) {
	tests := []struct {
		in   float64
		want string
	}{
		{100, "100.0"},
		{99.99, "99.9"},
		{85, "85.0"},
		{0, "0.0"},
	}
	for _, tt := range tests {
		if got := formatPercent(tt.in); got != tt.want {
			t.Errorf("formatPercent(%v) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestPercentNoStatements(t *testing.T) {
	if p := (PackageStat{}).Percent(); p != 100 {
		t.Errorf("Percent() = %v, want 100", p)
	}
}

func TestWriteReportErrors(t *testing.T) {
	pass := Report{Global: PackageStat{Name: "TOTAL"}}
	fail := Report{Global: PackageStat{Name: "TOTAL"}, Reasons: []string{"x"}}
	tests := []struct {
		name    string
		w       *limitWriter
		rep     Report
		wantErr string
	}{
		{name: "table write fails", w: &limitWriter{n: 0}, rep: pass, wantErr: "writing report"},
		{name: "pass verdict write fails", w: &limitWriter{n: 1 << 20, failOn: "coverage gate"}, rep: pass, wantErr: "writing verdict"},
		{name: "fail verdict write fails", w: &limitWriter{n: 1 << 20, failOn: "coverage gate"}, rep: fail, wantErr: "writing verdict"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checkErr(t, WriteReport(tt.w, tt.rep), tt.wantErr)
		})
	}
}

func FuzzParseLine(f *testing.F) {
	for _, s := range []string{
		"github.com/ed-fr/transteira/internal/crypto/aead.go:10.2,12.3 4 1",
		"C:/x/a.go:1.1,2.2 0 0",
		"a.go:1.1,2.2 1",
		":::: 1 1",
		"a.go:1.1,2.2 99999999999999999999 1",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, line string) {
		b, err := ParseLine(line)
		if err != nil {
			return
		}
		if b.File == "" || b.Stmts < 0 || b.Count < 0 {
			t.Fatalf("invalid block accepted: %+v from %q", b, line)
		}
		if checkPos(b.Pos) != nil {
			t.Fatalf("invalid position accepted: %q", b.Pos)
		}
		// Round trip: re-parsing the canonical form yields the same block.
		canon := b.File + ":" + b.Pos + " " + itoa(b.Stmts) + " " + itoa64(b.Count)
		b2, err := ParseLine(canon)
		if err != nil || b2 != b {
			t.Fatalf("round trip of %q failed: %+v, %v", canon, b2, err)
		}
	})
}

// checkErr fails the test when err does not match the expected substring
// (an empty want means no error is expected).
func checkErr(t *testing.T, err error, want string) {
	t.Helper()
	switch {
	case want == "" && err != nil:
		t.Fatalf("unexpected error: %v", err)
	case want != "" && err == nil:
		t.Fatalf("expected error containing %q, got nil", want)
	case want != "" && !strings.Contains(err.Error(), want):
		t.Fatalf("error %q does not contain %q", err, want)
	}
}

var errWrite = errors.New("write failed")

// failWriter rejects every write.
type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errWrite }

// limitWriter accepts n writes, then fails; it also fails on any write
// containing failOn when that is set.
type limitWriter struct {
	n      int
	failOn string
}

func (w *limitWriter) Write(p []byte) (int, error) {
	if w.n <= 0 || (w.failOn != "" && bytes.Contains(p, []byte(w.failOn))) {
		return 0, errWrite
	}
	w.n--
	return len(p), nil
}

func itoa(n int) string { return strconv.Itoa(n) }

func itoa64(n int64) string { return strconv.FormatInt(n, 10) }
