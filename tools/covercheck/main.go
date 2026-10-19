// Command covercheck is the coverage-threshold gate run by "make check".
//
// It reads a Go coverage profile (as produced by "go test -coverprofile"),
// computes statement coverage globally and per package, and compares the
// results with the thresholds declared in a JSON configuration file
// (section 24.3 of the specification: 85 % globally, 100 % on critical
// packages).
//
// Usage:
//
//	covercheck [-profile coverage.out] [-config tools/covercheck/thresholds.json]
//
// Exit status: 0 when every threshold is met, 1 when at least one threshold
// is missed, 2 on usage, configuration or profile parse errors, or when the
// profile contains no statement to measure after exclusions.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
)

// Exit codes returned by run.
const (
	exitPass  = 0
	exitFail  = 1
	exitUsage = 2
)

// Config is the content of the thresholds file.
type Config struct {
	// Global is the minimum statement coverage, in percent, over all
	// non-excluded packages.
	Global float64 `json:"global"`
	// Module is the Go module path, stripped from profile file names so
	// that packages are reported relative to the repository root.
	Module string `json:"module"`
	// Exclude lists package path prefixes (relative to the module) that are
	// ignored entirely, such as generated code or test helpers.
	Exclude []string `json:"exclude"`
	// Critical maps a package path (relative to the module) to its
	// required coverage percentage. An entry applies to the package and to
	// each of its sub-packages individually; the most specific entry wins.
	Critical map[string]float64 `json:"critical"`
}

// Block is one coverage block of a profile line.
type Block struct {
	// File is the file name as written in the profile (import path form).
	File string
	// Pos is the "startLine.startCol,endLine.endCol" position, kept as text
	// because it is only used as a deduplication key.
	Pos string
	// Stmts is the number of statements in the block.
	Stmts int
	// Count is the execution count (0 or 1 in "set" mode).
	Count int64
}

// PackageStat holds the statement coverage of one package.
type PackageStat struct {
	// Name is the package path relative to the module.
	Name string
	// Statements is the total number of statements.
	Statements int
	// Covered is the number of covered statements.
	Covered int
}

// Percent returns the coverage percentage. A package without statements is
// considered fully covered.
func (p PackageStat) Percent() float64 {
	if p.Statements == 0 {
		return 100
	}
	return float64(p.Covered) * 100 / float64(p.Statements)
}

// Row is one line of the report table.
type Row struct {
	// Stat is the coverage of the package.
	Stat PackageStat
	// Threshold is the required percentage, 0 when the package has no
	// specific threshold.
	Threshold float64
	// Present is false for critical packages absent from the profile.
	Present bool
	// OnDisk is true for a critical package absent from the profile whose
	// directory nevertheless holds Go source files.
	OnDisk bool
	// OK is false when the package misses its threshold.
	OK bool
}

// Report is the result of evaluating a profile against a configuration.
type Report struct {
	// Rows are sorted by package name.
	Rows []Row
	// Global aggregates every non-excluded package.
	Global PackageStat
	// Reasons lists failure reasons; it is empty when the gate passes.
	Reasons []string
}

// Passed reports whether every threshold is met.
func (r Report) Passed() bool { return len(r.Reasons) == 0 }

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run executes the command with the given arguments and returns its exit
// status.
func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("covercheck", flag.ContinueOnError)
	flags.SetOutput(stderr)
	profilePath := flags.String("profile", "coverage.out", "Go coverage profile to check")
	configPath := flags.String("config", "tools/covercheck/thresholds.json", "JSON thresholds file")
	rootPath := flags.String("root", "", "module root directory (default: nearest parent directory containing go.mod)")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if flags.NArg() != 0 {
		_, _ = fmt.Fprintf(stderr, "covercheck: unexpected arguments: %v\n", flags.Args())
		flags.Usage()
		return exitUsage
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "covercheck: %v\n", err)
		return exitUsage
	}
	blocks, err := loadProfile(*profilePath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "covercheck: %v\n", err)
		return exitUsage
	}

	stats := Aggregate(cfg, blocks)
	if !hasStatements(stats) {
		_, _ = fmt.Fprintln(stderr, "covercheck: no statements to measure (empty profile or everything excluded)")
		return exitUsage
	}
	root := *rootPath
	if root == "" {
		if root, err = findModuleRoot("."); err != nil {
			_, _ = fmt.Fprintf(stderr, "covercheck: %v\n", err)
			return exitUsage
		}
	}
	report := Evaluate(cfg, stats, os.DirFS(root))
	if err := WriteReport(stdout, report); err != nil {
		_, _ = fmt.Fprintf(stderr, "covercheck: %v\n", err)
		return exitUsage
	}
	if !report.Passed() {
		return exitFail
	}
	return exitPass
}

// findModuleRoot walks up from start to the nearest directory containing a
// go.mod file.
func findModuleRoot(start string) (string, error) {
	dir, err := filepath.Abs(start)
	if err != nil {
		return "", fmt.Errorf("locating module root: %w", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("locating module root: no go.mod found above %s", start)
		}
		dir = parent
	}
}

// hasGoSources reports whether dir (slash-separated, relative to fsys) or
// one of its non-excluded sub-directories contains a non-test .go file.
// Directories named testdata, or starting with "." or "_", are skipped as
// the go tool does. A missing directory has no sources.
func hasGoSources(cfg Config, fsys fs.FS, dir string) bool {
	found := false
	_ = fs.WalkDir(fsys, dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return fs.SkipDir
		}
		name := d.Name()
		if d.IsDir() {
			if p != dir && (name == "testdata" || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_")) {
				return fs.SkipDir
			}
			if excluded(cfg, p) {
				return fs.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go") {
			found = true
			return fs.SkipAll
		}
		return nil
	})
	return found
}

// loadConfig reads and validates the thresholds file at name.
func loadConfig(name string) (Config, error) {
	f, err := os.Open(name) //nolint:gosec // G304: the path is an operator-supplied flag.
	if err != nil {
		return Config{}, fmt.Errorf("reading config: %w", err)
	}
	defer func() { _ = f.Close() }()
	return ParseConfig(f)
}

// ParseConfig decodes and validates a thresholds configuration.
func ParseConfig(r io.Reader) (Config, error) {
	var cfg Config
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("parsing config: %w", err)
	}
	if cfg.Module == "" {
		return Config{}, errors.New("config: module must not be empty")
	}
	if !validPercent(cfg.Global) {
		return Config{}, fmt.Errorf("config: global threshold %v out of range [0,100]", cfg.Global)
	}
	for pkg, t := range cfg.Critical {
		if !validPercent(t) {
			return Config{}, fmt.Errorf("config: threshold %v for %q out of range [0,100]", t, pkg)
		}
	}
	return cfg, nil
}

func validPercent(v float64) bool { return v >= 0 && v <= 100 }

// loadProfile reads the coverage profile at name.
func loadProfile(name string) ([]Block, error) {
	f, err := os.Open(name) //nolint:gosec // G304: the path is an operator-supplied flag.
	if err != nil {
		return nil, fmt.Errorf("reading profile: %w", err)
	}
	defer func() { _ = f.Close() }()
	return ParseProfile(f)
}

// ParseProfile parses a Go coverage profile in text format. The first
// non-empty line must be a "mode:" line (set, count or atomic); further
// "mode:" lines, as found in concatenated profiles, are accepted.
func ParseProfile(r io.Reader) ([]Block, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var blocks []Block
	seenMode := false
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if mode, ok := strings.CutPrefix(line, "mode:"); ok {
			mode = strings.TrimSpace(mode)
			switch mode {
			case "set", "count", "atomic":
			default:
				return nil, fmt.Errorf("profile line %d: unknown mode %q", lineNo, mode)
			}
			seenMode = true
			continue
		}
		if !seenMode {
			return nil, fmt.Errorf("profile line %d: missing mode line", lineNo)
		}
		b, err := ParseLine(line)
		if err != nil {
			return nil, fmt.Errorf("profile line %d: %w", lineNo, err)
		}
		blocks = append(blocks, b)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading profile: %w", err)
	}
	if !seenMode {
		return nil, errors.New("profile: empty or missing mode line")
	}
	return blocks, nil
}

// ParseLine parses one block line of a coverage profile:
//
//	file:startLine.startCol,endLine.endCol numStmts count
func ParseLine(line string) (Block, error) {
	fields := strings.Fields(line)
	if len(fields) != 3 {
		return Block{}, fmt.Errorf("expected 3 fields, got %d", len(fields))
	}
	loc := fields[0]
	colon := strings.LastIndexByte(loc, ':')
	if colon <= 0 {
		return Block{}, fmt.Errorf("missing file name in %q", loc)
	}
	file, pos := loc[:colon], loc[colon+1:]
	if err := checkPos(pos); err != nil {
		return Block{}, err
	}
	stmts, err := strconv.Atoi(fields[1])
	if err != nil || stmts < 0 {
		return Block{}, fmt.Errorf("invalid statement count %q", fields[1])
	}
	count, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil || count < 0 {
		return Block{}, fmt.Errorf("invalid execution count %q", fields[2])
	}
	return Block{File: file, Pos: pos, Stmts: stmts, Count: count}, nil
}

// checkPos validates a "startLine.startCol,endLine.endCol" position.
func checkPos(pos string) error {
	start, end, ok := strings.Cut(pos, ",")
	if !ok {
		return fmt.Errorf("invalid position %q", pos)
	}
	for _, p := range [2]string{start, end} {
		l, c, ok := strings.Cut(p, ".")
		if !ok || !isUint(l) || !isUint(c) {
			return fmt.Errorf("invalid position %q", pos)
		}
	}
	return nil
}

// isUint reports whether s is a non-empty string of ASCII digits.
func isUint(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// packageOf returns the package path of a profile file name, relative to
// module when the file belongs to it ("." for the module root).
func packageOf(module, file string) string {
	dir := path.Dir(file)
	if dir == module {
		return "."
	}
	if rel, ok := strings.CutPrefix(dir, module+"/"); ok {
		return rel
	}
	return dir
}

// hasPathPrefix reports whether pkg equals prefix or is below it, on path
// element boundaries ("a/b" matches "a/b/c" but not "a/bc").
func hasPathPrefix(pkg, prefix string) bool {
	prefix = strings.TrimSuffix(prefix, "/")
	return pkg == prefix || strings.HasPrefix(pkg, prefix+"/")
}

// excluded reports whether pkg matches one of the configured exclusions.
func excluded(cfg Config, pkg string) bool {
	for _, p := range cfg.Exclude {
		if hasPathPrefix(pkg, p) {
			return true
		}
	}
	return false
}

// Aggregate computes per-package statement coverage from profile blocks,
// skipping excluded packages. A block listed several times (as happens with
// -coverpkg) is counted once and is covered if any occurrence has a
// non-zero count.
func Aggregate(cfg Config, blocks []Block) map[string]*PackageStat {
	type key struct{ file, pos string }
	type state struct {
		stmts   int
		covered bool
	}
	seen := make(map[key]*state, len(blocks))
	order := make([]key, 0, len(blocks))
	for _, b := range blocks {
		k := key{b.File, b.Pos}
		s, ok := seen[k]
		if !ok {
			s = &state{}
			seen[k] = s
			order = append(order, k)
		}
		s.stmts = max(s.stmts, b.Stmts)
		s.covered = s.covered || b.Count > 0
	}

	stats := make(map[string]*PackageStat)
	for _, k := range order {
		pkg := packageOf(cfg.Module, k.file)
		if excluded(cfg, pkg) {
			continue
		}
		st, ok := stats[pkg]
		if !ok {
			st = &PackageStat{Name: pkg}
			stats[pkg] = st
		}
		s := seen[k]
		st.Statements += s.stmts
		if s.covered {
			st.Covered += s.stmts
		}
	}
	return stats
}

// criticalThreshold returns the threshold of the most specific critical
// entry matching pkg (the entry itself or one of its parent packages).
func criticalThreshold(cfg Config, pkg string) (float64, bool) {
	best, threshold, found := "", 0.0, false
	for prefix, t := range cfg.Critical {
		if hasPathPrefix(pkg, prefix) && (!found || len(prefix) > len(best)) {
			best, threshold, found = prefix, t, true
		}
	}
	return threshold, found
}

// anyUnder reports whether stats holds prefix or one of its sub-packages.
func anyUnder(stats map[string]*PackageStat, prefix string) bool {
	for name := range stats {
		if hasPathPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// hasStatements reports whether at least one statement is measured.
func hasStatements(stats map[string]*PackageStat) bool {
	for _, st := range stats {
		if st.Statements > 0 {
			return true
		}
	}
	return false
}

// Evaluate compares package statistics with the configured thresholds.
// A critical entry for which neither the package nor any sub-package is
// present in stats is reported as missing and does not fail the gate, unless
// its directory in fsys (the module root) holds Go source files: a profile
// that skips an existing critical package, or a typo in the entry name that
// matches nothing measured, must not silently disable the gate.
func Evaluate(cfg Config, stats map[string]*PackageStat, fsys fs.FS) Report {
	var rep Report
	rep.Global.Name = "TOTAL"
	var reasons []string
	for _, st := range stats {
		rep.Global.Statements += st.Statements
		rep.Global.Covered += st.Covered
		t, critical := criticalThreshold(cfg, st.Name)
		row := Row{Stat: *st, Threshold: t, Present: true, OK: true}
		if critical && !meets(*st, t) {
			row.OK = false
			reasons = append(reasons, fmt.Sprintf("%s at %s%% below required %s%%",
				st.Name, formatPercent(st.Percent()), formatPercent(t)))
		}
		rep.Rows = append(rep.Rows, row)
	}
	for pkg, t := range cfg.Critical {
		if anyUnder(stats, pkg) {
			continue
		}
		row := Row{Stat: PackageStat{Name: pkg}, Threshold: t, OK: true}
		if hasGoSources(cfg, fsys, pkg) {
			row.OnDisk, row.OK = true, false
			reasons = append(reasons, pkg+": critical package present on disk but absent from the coverage profile")
		}
		rep.Rows = append(rep.Rows, row)
	}
	sort.Slice(rep.Rows, func(i, j int) bool { return rep.Rows[i].Stat.Name < rep.Rows[j].Stat.Name })
	sort.Strings(reasons)
	if !meets(rep.Global, cfg.Global) {
		reasons = append(reasons, fmt.Sprintf("global coverage %s%% below required %s%%",
			formatPercent(rep.Global.Percent()), formatPercent(cfg.Global)))
	}
	rep.Reasons = reasons
	return rep
}

// meets reports whether st reaches threshold. A 100 % threshold requires
// every statement to be covered, independently of floating-point rounding.
func meets(st PackageStat, threshold float64) bool {
	if threshold >= 100 {
		return st.Covered == st.Statements
	}
	return st.Percent() >= threshold
}

// formatPercent formats p with one decimal, truncated rather than rounded so
// that a failing 99.96 % is never displayed as 100.0 %.
func formatPercent(p float64) string {
	return strconv.FormatFloat(math.Floor(p*10)/10, 'f', 1, 64)
}

// WriteReport writes the human-readable report table and the final verdict.
func WriteReport(w io.Writer, rep Report) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "PACKAGE\tSTATEMENTS\tCOVERED\tTHRESHOLD\tSTATUS")
	for _, r := range rep.Rows {
		threshold := "-"
		if r.Threshold > 0 || !r.Present {
			threshold = formatPercent(r.Threshold) + "%"
		}
		if !r.Present {
			status := "MISSING (not yet implemented)"
			if r.OnDisk {
				status = "FAIL (on disk, absent from profile)"
			}
			_, _ = fmt.Fprintf(tw, "%s\t-\t-\t%s\t%s\n", r.Stat.Name, threshold, status)
			continue
		}
		status := "ok"
		if !r.OK {
			status = "FAIL"
		}
		_, _ = fmt.Fprintf(tw, "%s\t%d\t%s%%\t%s\t%s\n", r.Stat.Name, r.Stat.Statements,
			formatPercent(r.Stat.Percent()), threshold, status)
	}
	_, _ = fmt.Fprintf(tw, "%s\t%d\t%s%%\n", rep.Global.Name, rep.Global.Statements,
		formatPercent(rep.Global.Percent()))
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("writing report: %w", err)
	}
	var err error
	if rep.Passed() {
		_, err = fmt.Fprintln(w, "coverage gate: PASS")
	} else {
		_, err = fmt.Fprintf(w, "coverage gate: FAIL (%s)\n", strings.Join(rep.Reasons, "; "))
	}
	if err != nil {
		return fmt.Errorf("writing verdict: %w", err)
	}
	return nil
}
