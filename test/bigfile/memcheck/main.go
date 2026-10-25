// Command memcheck checks the memory samples recorded by scripts/bigfile.sh during the 20 GB test
// (CLAUDE.md section 24.2: "the memory consumption stays stable") and prints the summary of the
// client report (test/bigfile, BIGFILE_REPORT).
//
// The sampler writes one CSV line per container and sample, without header:
//
//	<unix time in ms>,<container name>,<anon bytes>[,<total bytes>[,<file>,<kernel>,<sock>[,<swap bytes>]]]
//
// scripts/bigfile.sh writes "ms,container,anon,current,file,kernel,sock,swap" from the cgroup of
// each container: the checked metric is "anon" of memory.stat (the anonymous memory of the
// processes: Go heap, stacks, buffers), which is what a leak grows, plus the swap of the cgroup
// (the eighth column, when present: anonymous memory pushed to swap still belongs to the server,
// and a leak swapped out must not hide). memory.current (the total, which is also what
// `docker stats` starts from) is only reported: it includes the page cache of the file being
// written to and read from the data volume, which the kernel fills up to the memory limit and
// reclaims on demand, and which is not memory held by the server. The file, kernel and sock
// columns are kept in the CSV for diagnosis only.
//
// For the server container (-server), two criteria, both required:
//   - peak: the largest sample of the whole run is at most -max-mem;
//   - no upward trend, checked over each transfer window: the samples of the window sorted by
//     time, the mean of its last quarter is at most (mean of its first quarter) x -trend-ratio,
//     plus -trend-slack. The ratio absorbs the working set that settles once a transfer runs
//     (buffers, connections, the scan queue), the absolute slack the noise of a server that idles
//     at a few tens of MiB. A leak proportional to the bytes transferred (a buffer kept per chunk,
//     say) breaks it on a 20 GB run.
//
// With -report (the JSON report of the client), the windows are the "upload-total" phase and the
// span from "download-full" to the last download phase, and the sampling must cover each of them:
// a window with fewer than -min-trend samples, or with a gap longer than -max-gap between two
// consecutive samples (the bounds of the window count as samples, so that a sampler that started
// late or died early is caught), FAILS. A passed report without both windows fails too. The
// report summary (result, resume offsets, durations and throughputs of the phases) is printed
// first. Without -report, or when a failed report lacks those phases, the whole run is one
// window, and with fewer than -min-trend samples its trend is reported as not checked.
//
// The phases of the report are timed with the clock of the client (the host), the samples with
// the clock of the Docker host (a VM with Docker Desktop, whose clock may differ).
// -clock-offsets-ms gives the offsets measured by scripts/bigfile.sh (sample clock minus client
// clock, in ms, at the start and at the end of the client): the windows are shifted by their
// mean, and an offset larger than -max-clock-offset in absolute value fails (clocks that far
// apart, or drifting, make the windows unreliable).
//
// The peak of each other container (-also, e.g. Caddy) is reported, never checked; so are the
// peaks of the total and of the swap of the server, when the CSV has them.
//
// Usage:
//
//	memcheck -csv mem-sqlite.csv -server transteira-bigfile-sqlite-transteira \
//	    -also transteira-bigfile-sqlite-proxy-caddy-1 -max-mem 256MiB [-report report-sqlite.json] \
//	    [-clock-offsets-ms 120,-80] [-label sqlite]
//
// Exit status: 0 when every criterion holds, 1 when one fails, 2 on a usage or input error.
package main

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// sample is one memory measure of one container.
type sample struct {
	atMs int64
	// bytes is the checked metric: anon, plus swap when the CSV has it.
	bytes int64
	// total is the optional fourth column (memory.current), -1 when absent.
	total int64
	// swap is the optional eighth column, -1 when absent.
	swap int64
}

// limits are the criteria applied to the server container.
type limits struct {
	maxPeak         int64
	trendRatio      float64
	trendSlack      int64
	minTrendSamples int
	// coverage requires every window to be covered by the samples (at least
	// minTrendSamples, no gap above maxGapMs): set for the windows of a
	// client report.
	coverage bool
	maxGapMs int64
}

// window is a time span of the run over which the trend is checked (unix ms, inclusive).
type window struct {
	name     string
	from, to int64
}

// trend is the trend criterion over one window.
type trend struct {
	window    window
	n         int
	checked   bool
	firstMean float64
	lastMean  float64
	limit     float64
	// maxGapMs is the largest time between consecutive samples of the
	// window, its bounds included.
	maxGapMs int64
}

// result is the analysis of the samples of the server container.
type result struct {
	n          int
	durationMs int64
	peak       int64
	trends     []trend
	violations []string
}

// clientReport is the part of the report of test/bigfile read here.
type clientReport struct {
	Engine     string `json:"engine"`
	Passed     bool   `json:"passed"`
	Error      string `json:"error"`
	Bytes      int64  `json:"bytes"`
	ScanStatus string `json:"scanStatus"`
	Upload     struct {
		CutStart     int64 `json:"cutStart"`
		CutAt        int64 `json:"cutAt"`
		ResumeOffset int64 `json:"resumeOffset"`
		LostBytes    int64 `json:"lostBytes"`
		Patches      int   `json:"patches"`
	} `json:"upload"`
	Download struct {
		CutAt int64 `json:"cutAt"`
	} `json:"download"`
	SHA256 struct {
		Expected string `json:"expected"`
	} `json:"sha256"`
	Phases []phase `json:"phases"`
}

// phase is one timed step of the client report.
type phase struct {
	Name         string    `json:"name"`
	Start        time.Time `json:"start"`
	End          time.Time `json:"end"`
	Seconds      float64   `json:"seconds"`
	Bytes        int64     `json:"bytes"`
	MiBPerSecond float64   `json:"mibPerSecond"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is main without the process: it parses args, analyzes the CSV and writes the summary.
func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("memcheck", flag.ContinueOnError)
	fs.SetOutput(stderr)
	csvPath := fs.String("csv", "", "CSV file written by the sampler (required)")
	server := fs.String("server", "", "server container name (required)")
	also := fs.String("also", "", "comma-separated containers whose peak is reported only")
	reportPath := fs.String("report", "", "JSON report of the client: summary and transfer windows")
	maxMem := fs.String("max-mem", "256MiB", "largest allowed server sample (bytes, or with a B, KiB, MiB, GiB, kB, MB or GB unit)")
	ratio := fs.Float64("trend-ratio", 1.25, "allowed ratio between the last and the first quarter means")
	slack := fs.String("trend-slack", "64MiB", "absolute slack added to the trend limit")
	minTrend := fs.Int("min-trend", 8, "fewest server samples in a window (trend criterion; with -report, coverage)")
	maxGap := fs.Duration("max-gap", 5*time.Second, "with -report, longest allowed gap between two samples inside a window")
	offsets := fs.String("clock-offsets-ms", "", "comma-separated offsets of the sample clock minus the client clock, in ms")
	maxOffset := fs.Duration("max-clock-offset", 2*time.Second, "largest allowed absolute clock offset")
	label := fs.String("label", "", "label of the run in the summary (e.g. the database engine)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *csvPath == "" || *server == "" {
		_, _ = fmt.Fprintln(stderr, "memcheck: -csv and -server are required")
		return 2
	}
	peak, err := parseSize(*maxMem)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "memcheck: -max-mem: %v\n", err)
		return 2
	}
	sl, err := parseSize(*slack)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "memcheck: -trend-slack: %v\n", err)
		return 2
	}
	if *ratio < 1 || *minTrend < 4 || *maxGap <= 0 || *maxOffset <= 0 {
		_, _ = fmt.Fprintln(stderr, "memcheck: -trend-ratio must be >= 1, -min-trend >= 4, -max-gap and -max-clock-offset > 0")
		return 2
	}
	offs, err := parseOffsets(*offsets)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "memcheck: -clock-offsets-ms: %v\n", err)
		return 2
	}
	byName, err := readSamplesFile(*csvPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "memcheck: %v\n", err)
		return 2
	}
	prefix := "memcheck:"
	if *label != "" {
		prefix = "memcheck (" + *label + "):"
	}
	lim := limits{maxPeak: peak, trendRatio: *ratio, trendSlack: sl, minTrendSamples: *minTrend, maxGapMs: maxGap.Milliseconds()}
	var windows []window
	var extra []string
	if *reportPath != "" {
		rep, err := readReport(*reportPath)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "memcheck: %v\n", err)
			return 2
		}
		printReport(stdout, prefix, rep)
		windows = transferWindows(rep)
		lim.coverage = len(windows) > 0
		if rep.Passed && len(windows) != 2 {
			extra = append(extra, fmt.Sprintf("the passed client report has %d transfer windows, want the upload and the download", len(windows)))
		}
	}
	if len(offs) > 0 {
		shift, viol := clockShift(offs, maxOffset.Milliseconds())
		_, _ = fmt.Fprintf(stdout, "%s clock offsets of the samples vs the client %v ms: windows shifted by %d ms (limit +/-%s)\n",
			prefix, offs, shift, *maxOffset)
		extra = append(extra, viol...)
		for i := range windows {
			windows[i].from += shift
			windows[i].to += shift
		}
	}
	return report(stdout, prefix, *server, splitList(*also), byName, windows, lim, extra)
}

// parseOffsets parses comma-separated clock offsets in ms (none for an empty string).
func parseOffsets(s string) ([]int64, error) {
	var out []int64
	for _, p := range splitList(s) {
		v, err := strconv.ParseInt(p, 10, 64)
		if err != nil || v < -(1<<40) || v > 1<<40 {
			return nil, fmt.Errorf("bad offset %q", p)
		}
		out = append(out, v)
	}
	return out, nil
}

// clockShift returns the shift to apply to the windows, the mean of offs (not empty), and a
// violation per offset larger than maxMs in absolute value.
func clockShift(offs []int64, maxMs int64) (int64, []string) {
	var sum int64
	var viol []string
	for _, o := range offs {
		sum += o
		if o > maxMs || o < -maxMs {
			viol = append(viol, fmt.Sprintf("clock offset of %d ms between the samples and the client, above +/-%d ms "+
				"(resynchronize the clock of the Docker VM, e.g. restart Docker Desktop, or raise BIGFILE_MAX_CLOCK_OFFSET)", o, maxMs))
		}
	}
	return sum / int64(len(offs)), viol
}

func readSamplesFile(path string) (map[string][]sample, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the path is an operator-supplied flag.
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	m, err := readSamples(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return m, nil
}

func readReport(path string) (clientReport, error) {
	var r clientReport
	b, err := os.ReadFile(path) //nolint:gosec // G304: the path is an operator-supplied flag.
	if err != nil {
		return r, err
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return r, fmt.Errorf("%s: %w", path, err)
	}
	return r, nil
}

// printReport writes the summary of the client report.
func printReport(w io.Writer, prefix string, r clientReport) {
	status := "PASSED"
	if !r.Passed {
		status = "FAILED: " + r.Error
	}
	_, _ = fmt.Fprintf(w, "%s client %s, %s, scan status %q, SHA-256 %s\n", prefix, status, mib(float64(r.Bytes)), r.ScanStatus, r.SHA256.Expected)
	_, _ = fmt.Fprintf(w, "%s upload cut at %d (PATCH from %d), resumed at %d (%s sent again), %d PATCH requests; download cut at %d, resumed with Range\n",
		prefix, r.Upload.CutAt, r.Upload.CutStart, r.Upload.ResumeOffset, mib(float64(r.Upload.LostBytes)), r.Upload.Patches, r.Download.CutAt)
	for _, p := range r.Phases {
		if p.Bytes > 0 {
			_, _ = fmt.Fprintf(w, "%s phase %-22s %8.1f s  %10.1f MiB  %7.1f MiB/s\n", prefix, p.Name, p.Seconds, float64(p.Bytes)/(1<<20), p.MiBPerSecond)
		} else {
			_, _ = fmt.Fprintf(w, "%s phase %-22s %8.1f s\n", prefix, p.Name, p.Seconds)
		}
	}
}

// transferWindows returns the upload and download windows of the report (each only when its
// phases are present).
func transferWindows(r clientReport) []window {
	var ws []window
	var dl *window
	for _, p := range r.Phases {
		from, to := p.Start.UnixMilli(), p.End.UnixMilli()
		switch {
		case p.Name == "upload-total":
			ws = append(ws, window{name: "upload", from: from, to: to})
		case p.Name == "download-full":
			dl = &window{name: "download", from: from, to: to}
		case strings.HasPrefix(p.Name, "download-") && dl != nil:
			dl.to = max(dl.to, to)
		}
	}
	if dl != nil {
		ws = append(ws, *dl)
	}
	return ws
}

// report writes the memory summary and returns the exit status. extra are the violations found
// before the analysis (clock offsets, missing windows).
func report(w io.Writer, prefix, server string, also []string, byName map[string][]sample, windows []window, lim limits, extra []string) int {
	srv := byName[server]
	if len(srv) == 0 {
		_, _ = fmt.Fprintf(w, "%s FAIL: no sample of the server container %s\n", prefix, server)
		return 1
	}
	r := analyze(srv, windows, lim)
	violations := append(append([]string(nil), extra...), r.violations...)
	_, _ = fmt.Fprintf(w, "%s %s: %d samples over %.0f s, peak %s (limit %s)\n",
		prefix, server, r.n, float64(r.durationMs)/1000, mib(float64(r.peak)), mib(float64(lim.maxPeak)))
	if t := peakOfField(srv, func(x sample) int64 { return x.total }); t >= 0 {
		_, _ = fmt.Fprintf(w, "%s %s: peak of the total %s (page cache included, reported only)\n", prefix, server, mib(float64(t)))
	}
	if sw := peakOfField(srv, func(x sample) int64 { return x.swap }); sw >= 0 {
		_, _ = fmt.Fprintf(w, "%s %s: peak of the swap %s (counted in the checked anon + swap)\n", prefix, server, mib(float64(sw)))
	}
	for _, t := range r.trends {
		switch {
		case t.checked:
			_, _ = fmt.Fprintf(w, "%s %s: %s trend over %d samples (largest gap %.1f s): first quarter mean %s, last quarter mean %s (limit %s = first x %.2f + %s)\n",
				prefix, server, t.window.name, t.n, float64(t.maxGapMs)/1000, mib(t.firstMean), mib(t.lastMean), mib(t.limit), lim.trendRatio, mib(float64(lim.trendSlack)))
		case lim.coverage:
			_, _ = fmt.Fprintf(w, "%s %s: %s trend NOT COVERED (%d samples, fewer than %d)\n", prefix, server, t.window.name, t.n, lim.minTrendSamples)
		default:
			_, _ = fmt.Fprintf(w, "%s %s: %s trend NOT CHECKED (%d samples, fewer than %d)\n", prefix, server, t.window.name, t.n, lim.minTrendSamples)
		}
	}
	for _, name := range also {
		s := byName[name]
		if len(s) == 0 {
			_, _ = fmt.Fprintf(w, "%s %s: no sample\n", prefix, name)
			continue
		}
		_, _ = fmt.Fprintf(w, "%s %s: %d samples, peak %s (reported only)\n", prefix, name, len(s), mib(float64(peakOf(s))))
	}
	if len(violations) > 0 {
		for _, v := range violations {
			_, _ = fmt.Fprintf(w, "%s FAIL: %s: %s\n", prefix, server, v)
		}
		return 1
	}
	_, _ = fmt.Fprintf(w, "%s OK\n", prefix)
	return 0
}

// analyze applies the criteria of lim to the samples of the server container (not empty). The
// trend is checked over each window, or over the whole run when there is none.
func analyze(samples []sample, windows []window, lim limits) result {
	s := append([]sample(nil), samples...)
	sort.SliceStable(s, func(i, j int) bool { return s[i].atMs < s[j].atMs })
	r := result{n: len(s), durationMs: s[len(s)-1].atMs - s[0].atMs, peak: peakOf(s)}
	if r.peak > lim.maxPeak {
		r.violations = append(r.violations, fmt.Sprintf("peak %s above the limit %s", mib(float64(r.peak)), mib(float64(lim.maxPeak))))
	}
	if len(windows) == 0 {
		windows = []window{{name: "whole run", from: s[0].atMs, to: s[len(s)-1].atMs}}
	}
	for _, win := range windows {
		var in []sample
		for _, x := range s {
			if x.atMs >= win.from && x.atMs <= win.to {
				in = append(in, x)
			}
		}
		t := trend{window: win, n: len(in), maxGapMs: largestGap(win, in)}
		if lim.coverage {
			if len(in) < lim.minTrendSamples {
				r.violations = append(r.violations, fmt.Sprintf("the sampling does not cover the %s: %d samples in the window, fewer than %d",
					win.name, len(in), lim.minTrendSamples))
			}
			if t.maxGapMs > lim.maxGapMs {
				r.violations = append(r.violations, fmt.Sprintf("the sampling does not cover the %s: a gap of %.1f s without sample, above %.1f s",
					win.name, float64(t.maxGapMs)/1000, float64(lim.maxGapMs)/1000))
			}
		}
		if len(in) >= lim.minTrendSamples {
			q := len(in) / 4
			t.checked = true
			t.firstMean = mean(in[:q])
			t.lastMean = mean(in[len(in)-q:])
			t.limit = t.firstMean*lim.trendRatio + float64(lim.trendSlack)
			if t.lastMean > t.limit {
				r.violations = append(r.violations, fmt.Sprintf("upward trend during the %s: mean of the last quarter %s above %s (first quarter %s)",
					win.name, mib(t.lastMean), mib(t.limit), mib(t.firstMean)))
			}
		}
		r.trends = append(r.trends, t)
	}
	return r
}

// largestGap returns the largest time between consecutive samples of in (sorted by time, inside
// win), the bounds of win counting as samples: the whole window when in is empty.
func largestGap(win window, in []sample) int64 {
	prev, gap := win.from, int64(0)
	for _, x := range in {
		gap = max(gap, x.atMs-prev)
		prev = x.atMs
	}
	return max(gap, win.to-prev)
}

func peakOf(s []sample) int64 {
	var p int64
	for _, x := range s {
		p = max(p, x.bytes)
	}
	return p
}

// peakOfField returns the largest field(x) of s, -1 when no sample has the field (all -1).
func peakOfField(s []sample, field func(sample) int64) int64 {
	p := int64(-1)
	for _, x := range s {
		p = max(p, field(x))
	}
	return p
}

func mean(s []sample) float64 {
	var sum float64
	for _, x := range s {
		sum += float64(x.bytes)
	}
	return sum / float64(len(s))
}

// readSamples parses the sampler CSV into the samples of each container. Blank lines are
// skipped; any malformed line is an error (a broken sampler must not pass silently).
func readSamples(r io.Reader) (map[string][]sample, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	cr.ReuseRecord = true
	out := map[string][]sample{}
	for {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		line, _ := cr.FieldPos(0)
		if len(rec) < 3 {
			return nil, fmt.Errorf("line %d: %d fields, want at least 3", line, len(rec))
		}
		at, err := strconv.ParseInt(rec[0], 10, 64)
		if err != nil || at < 0 {
			return nil, fmt.Errorf("line %d: bad timestamp %q", line, rec[0])
		}
		name := strings.TrimSpace(rec[1])
		if name == "" {
			return nil, fmt.Errorf("line %d: empty container name", line)
		}
		b, err := strconv.ParseInt(rec[2], 10, 64)
		if err != nil || b < 0 {
			return nil, fmt.Errorf("line %d: bad byte count %q", line, rec[2])
		}
		total, swap := int64(-1), int64(-1)
		if len(rec) >= 4 {
			if total, err = strconv.ParseInt(rec[3], 10, 64); err != nil || total < 0 {
				return nil, fmt.Errorf("line %d: bad total %q", line, rec[3])
			}
		}
		if len(rec) >= 8 {
			if swap, err = strconv.ParseInt(rec[7], 10, 64); err != nil || swap < 0 || swap > math.MaxInt64-b {
				return nil, fmt.Errorf("line %d: bad swap %q", line, rec[7])
			}
			b += swap
		}
		out[name] = append(out[name], sample{atMs: at, bytes: b, total: total, swap: swap})
	}
}

// units maps the size suffixes accepted by parseSize (those of `docker stats` and of the
// BIGFILE_* variables) to their multiplier.
var units = map[string]float64{
	"": 1, "B": 1,
	"KiB": 1 << 10, "MiB": 1 << 20, "GiB": 1 << 30, "TiB": 1 << 40,
	"kB": 1e3, "KB": 1e3, "MB": 1e6, "GB": 1e9, "TB": 1e12,
}

// parseSize parses a non-negative size such as "384MiB", "1.5GiB", "12.39MiB" or "1048576".
func parseSize(s string) (int64, error) {
	t := strings.TrimSpace(s)
	i := strings.IndexFunc(t, func(r rune) bool { return (r < '0' || r > '9') && r != '.' })
	num, unit := t, ""
	if i >= 0 {
		num, unit = t[:i], strings.TrimSpace(t[i:])
	}
	mult, ok := units[unit]
	if !ok {
		return 0, fmt.Errorf("unknown unit in size %q", s)
	}
	v, err := strconv.ParseFloat(num, 64)
	if err != nil || num == "" || strings.HasPrefix(num, ".") || strings.HasSuffix(num, ".") {
		return 0, fmt.Errorf("bad number in size %q", s)
	}
	b := v * mult
	if b >= math.MaxInt64/2 {
		return 0, fmt.Errorf("size %q too large", s)
	}
	return int64(math.Round(b)), nil
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func mib(b float64) string { return fmt.Sprintf("%.1f MiB", b/(1<<20)) }
