package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

const mi = 1 << 20

func TestParseSize(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in      string
		want    int64
		wantErr bool
	}{
		{in: "1048576", want: 1 << 20},
		{in: "0", want: 0},
		{in: "384MiB", want: 384 * mi},
		{in: " 12.5MiB ", want: 12*mi + mi/2},
		{in: "1.5GiB", want: 3 << 29},
		{in: "2KiB", want: 2048},
		{in: "1TiB", want: 1 << 40},
		{in: "10B", want: 10},
		{in: "3kB", want: 3000},
		{in: "3KB", want: 3000},
		{in: "2MB", want: 2e6},
		{in: "1GB", want: 1e9},
		{in: "1TB", want: 1e12},
		{in: "1 MiB", want: mi},
		{in: "", wantErr: true},
		{in: "MiB", wantErr: true},
		{in: "1XB", wantErr: true},
		{in: "-1MiB", wantErr: true},
		{in: "1e9", wantErr: true},
		{in: ".5MiB", wantErr: true},
		{in: "5.MiB", wantErr: true},
		{in: "1.2.3MiB", wantErr: true},
		{in: "NaN", wantErr: true},
		{in: "99999999999TiB", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()
			got, err := parseSize(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseSize(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Fatalf("parseSize(%q) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}

func FuzzParseSize(f *testing.F) {
	for _, s := range []string{"384MiB", "1.5GiB", "12345", "", "1e9", "-1", "9999999999999TB"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		b, err := parseSize(s)
		if err == nil && b < 0 {
			t.Fatalf("parseSize(%q) = %d, negative without error", s, b)
		}
	})
}

func TestReadSamples(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		in      string
		want    map[string]int // samples per container
		wantErr string
	}{
		{name: "empty", in: "", want: map[string]int{}},
		{
			name: "two containers",
			in:   "1000,app,100\n1500,proxy,7\n2000,app,200\n\n",
			want: map[string]int{"app": 2, "proxy": 1},
		},
		{name: "bad timestamp", in: "x,app,1\n", wantErr: "bad timestamp"},
		{name: "negative timestamp", in: "-1,app,1\n", wantErr: "bad timestamp"},
		{name: "empty name", in: "1, ,1\n", wantErr: "empty container name"},
		{name: "bad bytes", in: "1,app,1.5\n", wantErr: "bad byte count"},
		{name: "negative bytes", in: "1,app,-5\n", wantErr: "bad byte count"},
		{name: "too few fields", in: "1,app\n", wantErr: "2 fields, want at least 3"},
		{name: "total and extra columns", in: "1,app,10,20,5,1,0\n2,app,11,21\n", want: map[string]int{"app": 2}},
		{name: "bad total", in: "1,app,10,x\n", wantErr: "bad total"},
		{name: "negative total", in: "1,app,10,-2\n", wantErr: "bad total"},
		{name: "quoting error", in: "1,\"app,10\n", wantErr: "extraneous"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := readSamples(strings.NewReader(tt.in))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("readSamples error = %v, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("readSamples: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("readSamples = %d containers, want %d", len(got), len(tt.want))
			}
			for name, n := range tt.want {
				if len(got[name]) != n {
					t.Fatalf("container %s: %d samples, want %d", name, len(got[name]), n)
				}
			}
		})
	}
}

// series builds samples one second apart from a list of MiB values.
func series(mibs ...int64) []sample {
	s := make([]sample, len(mibs))
	for i, m := range mibs {
		s[i] = sample{atMs: int64(i) * 1000, bytes: m * mi}
	}
	return s
}

func TestAnalyze(t *testing.T) {
	t.Parallel()
	lim := limits{maxPeak: 384 * mi, trendRatio: 1.25, trendSlack: 64 * mi, minTrendSamples: 8}
	tests := []struct {
		name         string
		samples      []sample
		wantViol     int
		wantTrend    bool
		wantPeak     int64
		wantContains string
	}{
		{name: "flat", samples: series(50, 60, 60, 61, 59, 60, 62, 60), wantTrend: true, wantPeak: 62 * mi},
		{name: "steady growth within tolerance", samples: series(40, 40, 60, 80, 90, 95, 100, 104), wantTrend: true, wantPeak: 104 * mi},
		{name: "leak", samples: series(40, 40, 80, 120, 160, 200, 240, 280), wantViol: 1, wantTrend: true, wantPeak: 280 * mi, wantContains: "upward trend"},
		{name: "peak above limit", samples: series(50, 50, 400, 50, 50, 50, 50, 50), wantViol: 1, wantTrend: true, wantPeak: 400 * mi, wantContains: "peak"},
		{name: "both", samples: series(10, 10, 10, 10, 10, 10, 500, 500), wantViol: 2, wantTrend: true, wantPeak: 500 * mi},
		{name: "too few samples", samples: series(10, 300, 300), wantTrend: false, wantPeak: 300 * mi},
		{
			name:      "unsorted input is sorted by time",
			samples:   []sample{{atMs: 7000, bytes: 60 * mi}, {atMs: 0, bytes: 50 * mi}, {atMs: 6000, bytes: 60 * mi}, {atMs: 1000, bytes: 50 * mi}, {atMs: 5000, bytes: 60 * mi}, {atMs: 2000, bytes: 55 * mi}, {atMs: 4000, bytes: 60 * mi}, {atMs: 3000, bytes: 55 * mi}},
			wantTrend: true, wantPeak: 60 * mi,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := analyze(tt.samples, nil, lim)
			if len(r.violations) != tt.wantViol {
				t.Fatalf("violations = %q, want %d", r.violations, tt.wantViol)
			}
			if len(r.trends) != 1 || r.trends[0].window.name != "whole run" {
				t.Fatalf("trends = %+v, want one whole run window", r.trends)
			}
			if r.trends[0].checked != tt.wantTrend {
				t.Fatalf("trend checked = %v, want %v", r.trends[0].checked, tt.wantTrend)
			}
			if r.peak != tt.wantPeak {
				t.Fatalf("peak = %d, want %d", r.peak, tt.wantPeak)
			}
			if tt.wantContains != "" && !strings.Contains(strings.Join(r.violations, "\n"), tt.wantContains) {
				t.Fatalf("violations %q do not mention %q", r.violations, tt.wantContains)
			}
		})
	}
}

func TestAnalyzeWindows(t *testing.T) {
	t.Parallel()
	lim := limits{maxPeak: 1 << 30, trendRatio: 1.25, trendSlack: 64 * mi, minTrendSamples: 8}
	// 0-9 s idle at 20 MiB, 10-29 s upload flat at 100 MiB, 30-49 s download leaking.
	var s []sample
	for i := range 50 {
		m := int64(20)
		switch {
		case i >= 30:
			m = 100 + int64(i-30)*20
		case i >= 10:
			m = 100
		}
		s = append(s, sample{atMs: int64(i) * 1000, bytes: m * mi})
	}
	tests := []struct {
		name     string
		windows  []window
		wantViol []string
		checked  []bool
	}{
		{name: "upload only", windows: []window{{"upload", 10000, 29000}}, checked: []bool{true}},
		{name: "upload and download", windows: []window{{"upload", 10000, 29000}, {"download", 30000, 49000}}, checked: []bool{true, true}, wantViol: []string{"during the download"}},
		{name: "window without samples", windows: []window{{"upload", 100000, 200000}}, checked: []bool{false}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := analyze(s, tt.windows, lim)
			if len(r.violations) != len(tt.wantViol) {
				t.Fatalf("violations = %q, want %q", r.violations, tt.wantViol)
			}
			for i, v := range tt.wantViol {
				if !strings.Contains(r.violations[i], v) {
					t.Fatalf("violation %q does not mention %q", r.violations[i], v)
				}
			}
			for i, c := range tt.checked {
				if r.trends[i].checked != c {
					t.Fatalf("window %s checked = %v, want %v", r.trends[i].window.name, r.trends[i].checked, c)
				}
			}
		})
	}
}

func TestTransferWindows(t *testing.T) {
	t.Parallel()
	at := func(sec int) time.Time { return time.Unix(1_800_000_000+int64(sec), 0).UTC() }
	ph := func(name string, from, to int) phase { return phase{Name: name, Start: at(from), End: at(to)} }
	ms := func(sec int) int64 { return at(sec).UnixMilli() }
	tests := []struct {
		name   string
		phases []phase
		want   []window
	}{
		{name: "none", want: nil},
		{
			name: "full run",
			phases: []phase{
				ph("expected-sha256", 0, 5), ph("setup", 5, 6), ph("upload-interrupted", 6, 10), ph("upload-total", 6, 20),
				ph("finalize-to-available", 20, 21), ph("download-full", 21, 30), ph("download-before-cut", 30, 33), ph("download-resume", 33, 40),
			},
			want: []window{{"upload", ms(6), ms(20)}, {"download", ms(21), ms(40)}},
		},
		{name: "download phase before download-full is ignored", phases: []phase{ph("download-before-cut", 1, 2)}, want: nil},
		{name: "failed during the upload", phases: []phase{ph("setup", 0, 1), ph("upload-1", 1, 2)}, want: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := transferWindows(clientReport{Phases: tt.phases})
			if len(got) != len(tt.want) {
				t.Fatalf("windows = %+v, want %+v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("window %d = %+v, want %+v", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestAnalyzeCoverage(t *testing.T) {
	t.Parallel()
	lim := limits{maxPeak: 1 << 30, trendRatio: 1.25, trendSlack: 64 * mi, minTrendSamples: 8, coverage: true, maxGapMs: 5000}
	// One sample a second from 0 to 29 s, except a hole from 11 to 17 s.
	var s []sample
	for i := range 30 {
		if i > 10 && i < 18 {
			continue
		}
		s = append(s, sample{atMs: int64(i) * 1000, bytes: 50 * mi})
	}
	tests := []struct {
		name     string
		win      window
		wantViol []string
		wantGap  int64
	}{
		{name: "covered", win: window{"upload", 0, 10000}, wantGap: 1000},
		{name: "hole inside", win: window{"upload", 0, 29000}, wantGap: 8000, wantViol: []string{"a gap of 8.0 s without sample, above 5.0 s"}},
		{name: "sampler started late", win: window{"download", -7000, 7000}, wantGap: 7000, wantViol: []string{"a gap of 7.0 s"}},
		{name: "sampler died early", win: window{"download", 20000, 36000}, wantGap: 7000, wantViol: []string{"a gap of 7.0 s"}},
		{
			name: "too few samples", win: window{"upload", 9000, 19000}, wantGap: 8000,
			wantViol: []string{"4 samples in the window, fewer than 8", "a gap of 8.0 s"},
		},
		{
			name: "no sample at all", win: window{"download", 100000, 101000}, wantGap: 1000,
			wantViol: []string{"0 samples in the window, fewer than 8"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := analyze(s, []window{tt.win}, lim)
			if len(r.violations) != len(tt.wantViol) {
				t.Fatalf("violations = %q, want %q", r.violations, tt.wantViol)
			}
			for i, v := range tt.wantViol {
				if !strings.Contains(r.violations[i], v) || !strings.Contains(r.violations[i], "does not cover the "+tt.win.name) {
					t.Fatalf("violation %q does not mention %q", r.violations[i], v)
				}
			}
			if r.trends[0].maxGapMs != tt.wantGap {
				t.Fatalf("largest gap = %d ms, want %d", r.trends[0].maxGapMs, tt.wantGap)
			}
		})
	}
}

func TestClockShift(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		offs      []int64
		wantShift int64
		wantViol  int
	}{
		{name: "one", offs: []int64{150}, wantShift: 150},
		{name: "mean", offs: []int64{100, -50}, wantShift: 25},
		{name: "at the limit", offs: []int64{2000, -2000}, wantShift: 0},
		{name: "too far ahead", offs: []int64{2001, 1999}, wantShift: 2000, wantViol: 1},
		{name: "both too far", offs: []int64{-3000, -2500}, wantShift: -2750, wantViol: 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			shift, viol := clockShift(tt.offs, 2000)
			if shift != tt.wantShift || len(viol) != tt.wantViol {
				t.Fatalf("clockShift(%v) = %d, %q; want %d and %d violations", tt.offs, shift, viol, tt.wantShift, tt.wantViol)
			}
			for _, v := range viol {
				if !strings.Contains(v, "BIGFILE_MAX_CLOCK_OFFSET") {
					t.Fatalf("violation %q does not tell how to fix it", v)
				}
			}
		})
	}
}

func TestParseOffsets(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in      string
		want    []int64
		wantErr bool
	}{
		{in: "", want: nil},
		{in: "12", want: []int64{12}},
		{in: " -40 , 7 ", want: []int64{-40, 7}},
		{in: "1.5", wantErr: true},
		{in: "x", wantErr: true},
		{in: "1099511627777", wantErr: true},
		{in: "-1099511627777", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()
			got, err := parseOffsets(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseOffsets(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			}
			if !tt.wantErr && !slices.Equal(got, tt.want) {
				t.Fatalf("parseOffsets(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestReadSamplesSwap(t *testing.T) {
	t.Parallel()
	got, err := readSamples(strings.NewReader("1,app,100,900,5,1,0,40\n2,app,100,900,5,1,0,0\n3,app,7,8\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := []sample{{atMs: 1, bytes: 140, total: 900, swap: 40}, {atMs: 2, bytes: 100, total: 900, swap: 0}, {atMs: 3, bytes: 7, total: 8, swap: -1}}
	if !slices.Equal(got["app"], want) {
		t.Fatalf("samples = %+v, want %+v (the checked bytes are anon + swap)", got["app"], want)
	}
	for _, in := range []string{"1,app,1,2,3,4,5,x\n", "1,app,1,2,3,4,5,-1\n", "1,app,10,2,3,4,5,9223372036854775800\n"} {
		if _, err := readSamples(strings.NewReader(in)); err == nil || !strings.Contains(err.Error(), "bad swap") {
			t.Fatalf("readSamples(%q) error = %v, want bad swap", in, err)
		}
	}
}

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// csvOf returns the CSV lines of the samples of one container, one a second from fromSec, with
// the values of mibs (anon, in MiB) and the extra columns cols appended to each line.
func csvOf(name string, fromSec int64, mibs []int64, cols ...string) string {
	var b strings.Builder
	for i, m := range mibs {
		b.WriteString(strings.Join(append([]string{itoa((fromSec + int64(i)) * 1000), name, itoa(m * mi)}, cols...), ",") + "\n")
	}
	return b.String()
}

// repeat returns n times v.
func repeat(v int64, n int) []int64 {
	out := make([]int64, n)
	for i := range out {
		out[i] = v
	}
	return out
}

// phasesJSON is a report with the given phases and passed flag.
func phasesJSON(passed bool, phases string) string {
	return fmt.Sprintf(`{"engine":"sqlite","passed":%t,"bytes":1073741824,"scanStatus":"clean",
		"upload":{"cutStart":0,"cutAt":429496729,"resumeOffset":268435456,"lostBytes":161061273,"patches":3},
		"download":{"cutAt":322122547},"sha256":{"expected":"ab12"},"phases":[%s]}`, passed, phases)
}

// at returns the RFC 3339 time sec seconds after the epoch.
func at(sec int) string { return time.Unix(int64(sec), 0).UTC().Format(time.RFC3339) }

// ph returns the JSON of a phase from fromSec to toSec.
func ph(name string, fromSec, toSec int, extra string) string {
	return fmt.Sprintf(`{"name":%q,"start":%q,"end":%q,"seconds":%d%s}`, name, at(fromSec), at(toSec), toSec-fromSec, extra)
}

func TestRun(t *testing.T) {
	t.Parallel()
	// 24 samples, 0 to 23 s: the upload is 0-11 s, the download 12-23 s.
	flatCSV := writeFile(t, "flat.csv", csvOf("app", 0, repeat(60, 24), itoa(900*mi), "1", "0", "0", itoa(2*mi))+csvOf("proxy", 0, repeat(20, 24)))
	var leak []int64
	for i := range 12 {
		leak = append(leak, int64(40+40*i))
	}
	leakCSV := writeFile(t, "leak.csv", csvOf("app", 0, leak))
	shortCSV := writeFile(t, "short.csv", "0,app,1\n1000,app,2\n")
	badCSV := writeFile(t, "bad.csv", "zz,app,1\n")
	// The same samples, with a hole from 4 to 10 s inside the upload.
	holeCSV := writeFile(t, "hole.csv", csvOf("app", 0, repeat(60, 4))+csvOf("app", 11, repeat(60, 13)))
	// The same samples on a clock 60 s ahead of the client.
	aheadCSV := writeFile(t, "ahead.csv", csvOf("app", 60, repeat(60, 24)))

	upload := ph("upload-total", 0, 11, `,"bytes":1073741824,"mibPerSecond":93.1`)
	download := ph("download-full", 12, 18, `,"bytes":1073741824,"mibPerSecond":92.0`) + "," + ph("download-resume", 18, 23, "")
	okReport := writeFile(t, "ok.json", phasesJSON(true, ph("setup", 0, 1, "")+","+upload+","+download))
	uploadOnlyReport := writeFile(t, "upload-only.json", phasesJSON(true, upload))
	failedReport := writeFile(t, "failed.json", `{"passed":false,"error":"sha256 mismatch","phases":[]}`)
	failedUploadReport := writeFile(t, "failed-upload.json", phasesJSON(false, upload))
	badReport := writeFile(t, "bad.json", `{"passed":`)
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout []string
		wantStderr string
	}{
		{
			name: "ok with reported container",
			args: []string{"-csv", flatCSV, "-server", "app", "-also", "proxy, missing", "-label", "sqlite"},
			wantStdout: []string{
				"memcheck (sqlite): app: 24 samples over 23 s, peak 62.0 MiB (limit 256.0 MiB)",
				"app: peak of the total 900.0 MiB (page cache included, reported only)",
				"app: peak of the swap 2.0 MiB (counted in the checked anon + swap)",
				"proxy: 24 samples, peak 20.0 MiB (reported only)", "missing: no sample", "OK",
			},
		},
		{
			name:       "leak fails",
			args:       []string{"-csv", leakCSV, "-server", "app", "-max-mem", "1GiB"},
			wantCode:   1,
			wantStdout: []string{"memcheck: FAIL: app: upward trend"},
		},
		{
			name:       "peak fails",
			args:       []string{"-csv", flatCSV, "-server", "app", "-max-mem", "32MiB"},
			wantCode:   1,
			wantStdout: []string{"FAIL: app: peak 62.0 MiB above the limit 32.0 MiB"},
		},
		{
			name:       "trend not checked without a report",
			args:       []string{"-csv", shortCSV, "-server", "app"},
			wantStdout: []string{"whole run trend NOT CHECKED (2 samples, fewer than 8)", "OK"},
		},
		{
			name: "report summary and windows",
			args: []string{"-csv", flatCSV, "-server", "app", "-report", okReport},
			wantStdout: []string{
				"memcheck: client PASSED, 1024.0 MiB, scan status \"clean\", SHA-256 ab12",
				"upload cut at 429496729 (PATCH from 0), resumed at 268435456 (153.6 MiB sent again), 3 PATCH requests; download cut at 322122547",
				"phase setup                       1.0 s",
				"phase upload-total               11.0 s      1024.0 MiB     93.1 MiB/s",
				"app: upload trend over 12 samples (largest gap 1.0 s)",
				"app: download trend over 12 samples (largest gap 1.0 s)",
				"OK",
			},
		},
		{
			name:       "too few samples in a report window fails",
			args:       []string{"-csv", shortCSV, "-server", "app", "-report", okReport},
			wantCode:   1,
			wantStdout: []string{"upload trend NOT COVERED (2 samples, fewer than 8)", "FAIL: app: the sampling does not cover the upload: 2 samples", "FAIL: app: the sampling does not cover the download: 0 samples"},
		},
		{
			name:       "gap in a report window fails",
			args:       []string{"-csv", holeCSV, "-server", "app", "-report", okReport},
			wantCode:   1,
			wantStdout: []string{"FAIL: app: the sampling does not cover the upload: a gap of 8.0 s without sample, above 5.0 s"},
		},
		{
			name:     "gap within a larger max-gap",
			args:     []string{"-csv", holeCSV, "-server", "app", "-report", okReport, "-max-gap", "10s", "-min-trend", "4"},
			wantCode: 0, wantStdout: []string{"upload trend over 5 samples (largest gap 8.0 s)", "OK"},
		},
		{
			name:       "passed report without the download window fails",
			args:       []string{"-csv", flatCSV, "-server", "app", "-report", uploadOnlyReport},
			wantCode:   1,
			wantStdout: []string{"FAIL: app: the passed client report has 1 transfer windows, want the upload and the download"},
		},
		{
			name:       "failed client report without phases",
			args:       []string{"-csv", flatCSV, "-server", "app", "-report", failedReport},
			wantStdout: []string{"client FAILED: sha256 mismatch", "whole run trend over 24 samples", "OK"},
		},
		{
			name:       "failed client report with the upload window only",
			args:       []string{"-csv", flatCSV, "-server", "app", "-report", failedUploadReport},
			wantStdout: []string{"client FAILED", "upload trend over 12 samples", "OK"},
		},
		{
			name:       "clock offset corrected",
			args:       []string{"-csv", aheadCSV, "-server", "app", "-report", okReport, "-clock-offsets-ms", "59900,60100", "-max-clock-offset", "2m"},
			wantStdout: []string{"clock offsets of the samples vs the client [59900 60100] ms: windows shifted by 60000 ms (limit +/-2m0s)", "upload trend over 12 samples", "download trend over 12 samples", "OK"},
		},
		{
			name:       "clock offset not corrected",
			args:       []string{"-csv", aheadCSV, "-server", "app", "-report", okReport},
			wantCode:   1,
			wantStdout: []string{"does not cover the upload: 0 samples"},
		},
		{
			name:       "clock offset above the limit",
			args:       []string{"-csv", flatCSV, "-server", "app", "-report", okReport, "-clock-offsets-ms", "300,2500"},
			wantCode:   1,
			wantStdout: []string{"windows shifted by 1400 ms (limit +/-2s)", "FAIL: app: clock offset of 2500 ms between the samples and the client, above +/-2000 ms"},
		},
		{name: "malformed report", args: []string{"-csv", flatCSV, "-server", "app", "-report", badReport}, wantCode: 2, wantStderr: "bad.json"},
		{name: "missing report", args: []string{"-csv", flatCSV, "-server", "app", "-report", filepath.Join(t.TempDir(), "none.json")}, wantCode: 2, wantStderr: "memcheck:"},
		{name: "no server sample", args: []string{"-csv", flatCSV, "-server", "other"}, wantCode: 1, wantStdout: []string{"FAIL: no sample of the server container other"}},
		{name: "missing flags", args: []string{"-csv", flatCSV}, wantCode: 2, wantStderr: "required"},
		{name: "unknown flag", args: []string{"-nope"}, wantCode: 2, wantStderr: "flag provided but not defined"},
		{name: "bad max-mem", args: []string{"-csv", flatCSV, "-server", "app", "-max-mem", "lots"}, wantCode: 2, wantStderr: "-max-mem"},
		{name: "bad slack", args: []string{"-csv", flatCSV, "-server", "app", "-trend-slack", "x1"}, wantCode: 2, wantStderr: "-trend-slack"},
		{name: "bad ratio", args: []string{"-csv", flatCSV, "-server", "app", "-trend-ratio", "0.5"}, wantCode: 2, wantStderr: "-trend-ratio"},
		{name: "bad min-trend", args: []string{"-csv", flatCSV, "-server", "app", "-min-trend", "2"}, wantCode: 2, wantStderr: "-min-trend"},
		{name: "bad max-gap", args: []string{"-csv", flatCSV, "-server", "app", "-max-gap", "0s"}, wantCode: 2, wantStderr: "-max-gap"},
		{name: "bad max-clock-offset", args: []string{"-csv", flatCSV, "-server", "app", "-max-clock-offset", "-1s"}, wantCode: 2, wantStderr: "-max-clock-offset"},
		{name: "bad clock offsets", args: []string{"-csv", flatCSV, "-server", "app", "-clock-offsets-ms", "1,x"}, wantCode: 2, wantStderr: "-clock-offsets-ms: bad offset \"x\""},
		{name: "missing file", args: []string{"-csv", filepath.Join(t.TempDir(), "none.csv"), "-server", "app"}, wantCode: 2, wantStderr: "memcheck:"},
		{name: "malformed csv", args: []string{"-csv", badCSV, "-server", "app"}, wantCode: 2, wantStderr: "bad timestamp"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var out, errOut bytes.Buffer
			code := run(tt.args, &out, &errOut)
			if code != tt.wantCode {
				t.Fatalf("run = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, tt.wantCode, out.String(), errOut.String())
			}
			for _, w := range tt.wantStdout {
				if !strings.Contains(out.String(), w) {
					t.Fatalf("stdout does not contain %q:\n%s", w, out.String())
				}
			}
			if tt.wantStderr != "" && !strings.Contains(errOut.String(), tt.wantStderr) {
				t.Fatalf("stderr does not contain %q:\n%s", tt.wantStderr, errOut.String())
			}
		})
	}
}

func itoa(v int64) string { return strconv.FormatInt(v, 10) }
