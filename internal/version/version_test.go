package version

import (
	"encoding/json"
	"errors"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
)

func buildInfo(mainVersion, goVersion string, settings map[string]string) func() (*debug.BuildInfo, bool) {
	return func() (*debug.BuildInfo, bool) {
		bi := &debug.BuildInfo{GoVersion: goVersion, Main: debug.Module{Version: mainVersion}}
		for k, v := range settings {
			bi.Settings = append(bi.Settings, debug.BuildSetting{Key: k, Value: v})
		}
		return bi, true
	}
}

func TestResolve(t *testing.T) {
	const rev = "3f9c2ab0123456789abcdef0123456789abcdef0"
	vcs := map[string]string{"vcs.revision": rev, "vcs.time": "2026-10-19T16:00:00Z", "vcs.modified": "false"}
	dirty := map[string]string{"vcs.revision": rev, "vcs.modified": "true", "other": "x"}

	tests := []struct {
		name                string
		version, commit, dt string
		read                func() (*debug.BuildInfo, bool)
		want                Info
	}{
		{
			name:    "no build info",
			version: defaultVersion, commit: unknown, dt: unknown,
			read: func() (*debug.BuildInfo, bool) { return nil, false },
			want: Info{Version: defaultVersion, Commit: unknown, Date: unknown, GoVersion: runtime.Version()},
		},
		{
			name:    "ok but nil build info",
			version: "1.0.0", commit: "abc", dt: "d",
			read: func() (*debug.BuildInfo, bool) { return nil, true },
			want: Info{Version: "1.0.0", Commit: "abc", Date: "d", GoVersion: runtime.Version()},
		},
		{
			name:    "fallback to vcs and module version",
			version: defaultVersion, commit: unknown, dt: unknown,
			read: buildInfo("v1.4.0", "go1.27.2", vcs),
			want: Info{Version: "1.4.0", Commit: rev, Date: "2026-10-19T16:00:00Z", GoVersion: "go1.27.2"},
		},
		{
			name:    "dirty tree, devel module version, empty go version",
			version: defaultVersion, commit: unknown, dt: unknown,
			read: buildInfo("(devel)", "", dirty),
			want: Info{Version: defaultVersion, Commit: rev + "-dirty", Date: unknown, GoVersion: runtime.Version()},
		},
		{
			name:    "injected values win",
			version: "2.0.0-rc.1", commit: "deadbee", dt: "2026-01-01T00:00:00Z",
			read: buildInfo("v1.4.0", "go1.27.2", vcs),
			want: Info{Version: "2.0.0-rc.1", Commit: "deadbee", Date: "2026-01-01T00:00:00Z", GoVersion: "go1.27.2"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolve(tt.version, tt.commit, tt.dt, tt.read); got != tt.want {
				t.Errorf("resolve() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestGet(t *testing.T) {
	origRead, origV, origC, origD := readBuildInfo, Version, Commit, Date
	t.Cleanup(func() { readBuildInfo, Version, Commit, Date = origRead, origV, origC, origD })

	Version, Commit, Date = "1.2.3", "3f9c2ab", "2026-10-19T16:00:00Z"
	readBuildInfo = buildInfo("", "go1.27.2", nil)
	want := Info{Version: "1.2.3", Commit: "3f9c2ab", Date: "2026-10-19T16:00:00Z", GoVersion: "go1.27.2"}
	if got := Get(); got != want {
		t.Errorf("Get() = %+v, want %+v", got, want)
	}
}

func TestGetRealBuildInfo(t *testing.T) {
	if got := Get(); got.Version == "" || got.GoVersion == "" {
		t.Errorf("Get() returned empty fields: %+v", got)
	}
}

func TestInfoString(t *testing.T) {
	tests := []struct {
		name string
		info Info
		want string
	}{
		{
			name: "short commit",
			info: Info{Version: "1.2.3", Commit: "3f9c2ab", Date: "2026-10-19T16:00:00Z", GoVersion: "go1.27.2"},
			want: "transteira 1.2.3 (commit 3f9c2ab, built 2026-10-19T16:00:00Z, go1.27.2)",
		},
		{
			name: "full dirty commit is abbreviated",
			info: Info{Version: "1.2.3", Commit: "3f9c2ab0123456789-dirty", Date: "d", GoVersion: "go1.27.2"},
			want: "transteira 1.2.3 (commit 3f9c2ab-dirty, built d, go1.27.2)",
		},
		{
			name: "unknown kept intact",
			info: Info{Version: defaultVersion, Commit: unknown, Date: unknown, GoVersion: "go1.27.2"},
			want: "transteira 0.0.0-dev (commit unknown, built unknown, go1.27.2)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.info.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestInfoJSON(t *testing.T) {
	b, err := json.Marshal(Info{Version: "1.2.3", Commit: "abc", Date: "d", GoVersion: "go1.27.2"})
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"version":"1.2.3","commit":"abc","date":"d","goVersion":"go1.27.2"}`
	if string(b) != want {
		t.Errorf("JSON = %s, want %s", b, want)
	}
}

func TestParseSemver(t *testing.T) {
	tests := []struct {
		in                  string
		major, minor, patch int
		pre                 string
		wantErr             bool
	}{
		{in: "0.0.0-dev", pre: "dev"},
		{in: "1.2.3", major: 1, minor: 2, patch: 3},
		{in: "10.20.30-rc.1+build.5", major: 10, minor: 20, patch: 30, pre: "rc.1"},
		{in: "1.0.0+meta", major: 1},
		{in: "1.0.0-alpha.0valid", major: 1, pre: "alpha.0valid"},
		{in: "", wantErr: true},
		{in: "v1.2.3", wantErr: true},
		{in: "1.2", wantErr: true},
		{in: "01.2.3", wantErr: true},
		{in: "1.2.3-01", wantErr: true},
		{in: "1.2.3-", wantErr: true},
		{in: "1.2.3+", wantErr: true},
		{in: "1.2.3 ", wantErr: true},
		{in: "99999999999999999999.0.0", wantErr: true},
		{in: "0.99999999999999999999.0", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			major, minor, patch, pre, err := ParseSemver(tt.in)
			if tt.wantErr {
				if !errors.Is(err, ErrInvalidSemver) {
					t.Fatalf("ParseSemver(%q) error = %v, want ErrInvalidSemver", tt.in, err)
				}
				if IsValid(tt.in) {
					t.Errorf("IsValid(%q) = true, want false", tt.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseSemver(%q) unexpected error: %v", tt.in, err)
			}
			if major != tt.major || minor != tt.minor || patch != tt.patch || pre != tt.pre {
				t.Errorf("ParseSemver(%q) = %d.%d.%d-%q, want %d.%d.%d-%q",
					tt.in, major, minor, patch, pre, tt.major, tt.minor, tt.patch, tt.pre)
			}
			if !IsValid(tt.in) {
				t.Errorf("IsValid(%q) = false, want true", tt.in)
			}
		})
	}
}

func TestValid(t *testing.T) {
	orig := Version
	t.Cleanup(func() { Version = orig })
	tests := []struct {
		version string
		want    bool
	}{
		{defaultVersion, true},
		{"1.2.3", true},
		{"latest", false},
	}
	for _, tt := range tests {
		Version = tt.version
		if got := Valid(); got != tt.want {
			t.Errorf("Valid() with %q = %v, want %v", tt.version, got, tt.want)
		}
	}
}

func FuzzSemver(f *testing.F) {
	for _, s := range []string{"0.0.0-dev", "1.2.3", "1.2.3-rc.1+build", "v1", "01.0.0", "1.2.3-"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		major, minor, patch, pre, err := ParseSemver(s)
		if err != nil {
			if !errors.Is(err, ErrInvalidSemver) {
				t.Fatalf("unexpected error type: %v", err)
			}
			return
		}
		if major < 0 || minor < 0 || patch < 0 {
			t.Fatalf("negative component in %q", s)
		}
		if pre != "" && !strings.Contains(s, "-"+pre) {
			t.Fatalf("pre-release %q not found in %q", pre, s)
		}
	})
}
