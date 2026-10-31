package updatecheck

import (
	"strings"
	"testing"
)

func TestParseRelease(t *testing.T) {
	t.Parallel()
	const page = "https://github.com/ed-fr/transteira/releases/tag/v1.2.1"
	tests := []struct {
		name    string
		body    string
		want    Release
		wantErr bool
	}{
		{
			"stable with v", `{"tag_name":"v1.2.1","html_url":"` + page + `","draft":false,"prerelease":false}`,
			Release{Version: "1.2.1", URL: page},
			false,
		},
		{"stable without v", `{"tag_name":"1.2.1"}`, Release{Version: "1.2.1"}, false},
		{"build metadata", `{"tag_name":"v1.2.1+build.7"}`, Release{Version: "1.2.1+build.7"}, false},
		{
			"other members ignored", `{"name":"<script>x</script>","body":"**notes**","assets":[{"a":1}],"tag_name":"v2.0.0"}`,
			Release{Version: "2.0.0"},
			false,
		},
		{
			"bad url dropped, version kept", `{"tag_name":"v1.2.1","html_url":"https://evil.example.com/x"}`,
			Release{Version: "1.2.1"},
			false,
		},
		{"draft ignored", `{"tag_name":"v9.0.0","draft":true}`, Release{}, false},
		{"prerelease flag ignored", `{"tag_name":"v9.0.0","prerelease":true}`, Release{}, false},
		{"prerelease suffix ignored", `{"tag_name":"v9.0.0-rc.1"}`, Release{}, false},
		{"not semver", `{"tag_name":"latest"}`, Release{}, true},
		{"two v", `{"tag_name":"vv1.2.1"}`, Release{}, true},
		{"leading zero", `{"tag_name":"v01.2.1"}`, Release{}, true},
		{"too long", `{"tag_name":"v1.2.3-` + strings.Repeat("a", 60) + `"}`, Release{}, true},
		{"missing tag", `{"html_url":"` + page + `"}`, Release{}, true},
		{"tag not a string", `{"tag_name":1}`, Release{}, true},
		{"draft not a bool", `{"tag_name":"v1.0.0","draft":"no"}`, Release{}, true},
		{"url not a string", `{"tag_name":"v1.0.0","html_url":7}`, Release{}, true},
		{"null", `null`, Release{}, true},
		{"array", `[{"tag_name":"v1.0.0"}]`, Release{}, true},
		{"trailing data", `{"tag_name":"v1.0.0"} {}`, Release{}, true},
		{"truncated", `{"tag_name":"v1.0.0"`, Release{}, true},
		{"empty", ``, Release{}, true},
	}
	for _, tt := range tests {
		got, err := ParseRelease([]byte(tt.body))
		if (err != nil) != tt.wantErr || got != tt.want {
			t.Errorf("%s: ParseRelease = %+v, %v; want %+v, error %v", tt.name, got, err, tt.want, tt.wantErr)
		}
	}
}

func TestFilterReleaseURL(t *testing.T) {
	t.Parallel()
	good := []string{
		"https://github.com/ed-fr/transteira/releases/tag/v1.2.1",
		"https://github.com/ed-fr/transteira/releases/tag/1.2.1+build.7",
		"https://github.com/ed-fr/transteira/releases/latest",
	}
	for _, u := range good {
		if got := FilterReleaseURL(u); got != u {
			t.Errorf("FilterReleaseURL(%q) = %q, want it kept", u, got)
		}
	}
	bad := []string{
		"",
		"http://github.com/ed-fr/transteira/releases/tag/v1.2.1",
		"HTTPS://github.com/ed-fr/transteira/releases/tag/v1.2.1",
		"https://GitHub.com/ed-fr/transteira/releases/tag/v1.2.1",
		"https://github.com.evil.example/ed-fr/transteira/releases/tag/v1.2.1",
		"https://evil.example.com/ed-fr/transteira/releases/tag/v1.2.1",
		"https://github.com:443/ed-fr/transteira/releases/tag/v1.2.1",
		"https://github.com:/ed-fr/transteira/releases/tag/v1.2.1",
		"https://user:pass@github.com/ed-fr/transteira/releases/tag/v1.2.1",
		"https://user@github.com/ed-fr/transteira/releases/tag/v1.2.1",
		"https://github.com/ed-fr/transteira/releases/",
		"https://github.com/ed-fr/transteira/releases",
		"https://github.com/ed-fr/transteira/releases/../../../evil/repo",
		"https://github.com/ed-fr/transteira/releases/tag/../../../../evil",
		"https://github.com/ed-fr/transteira/releases/./tag",
		"https://github.com/ed-fr/transteira/releases//tag",
		"https://github.com/ed-fr/transteira/releases/tag/v1.2.1/",
		"https://github.com/ed-fr/transteira/releases/%2e%2e/x",
		"https://github.com/ed-fr/transteira/releases/tag%2Fx",
		"https://github.com/ed-fr/transteira/releases/tag\\..\\x",
		"https://github.com/ed-fr/transteira/releases/tag/v1?x=1",
		"https://github.com/ed-fr/transteira/releases/tag/v1#x",
		"https://github.com/ed-fr/transteira/releases/tag/v 1",
		"https://github.com/ed-fr/transteira/releases/tag/v1\n",
		"https://github.com/ed-fr/transteira/releases/tag/v1 ",
		"https://github.com/ed-fr/other/releases/tag/v1.2.1",
		"https://github.com/ed-fr/transteira/archive/v1.2.1.zip",
		"javascript:alert(1)//https://github.com/ed-fr/transteira/releases/x",
		"https://github.com/ed-fr/transteira/releases/" + strings.Repeat("a", MaxReleaseURLLength),
	}
	for _, u := range bad {
		if got := FilterReleaseURL(u); got != "" {
			t.Errorf("FilterReleaseURL(%q) = %q, want it refused", u, got)
		}
	}
}

func TestCompare(t *testing.T) {
	t.Parallel()
	tests := []struct {
		a, b string
		want int
		ok   bool
	}{
		{"1.2.0", "1.2.0", 0, true},
		{"1.2.1", "1.2.0", 1, true},
		{"1.2.0", "1.10.0", -1, true},
		{"2.0.0", "1.99.99", 1, true},
		{"1.0.0", "1.0.1", -1, true},
		{"1.0.0+a", "1.0.0+b", 0, true},
		{"1.0.0", "1.0.0-rc.1", 1, true},
		{"1.0.0-rc.1", "1.0.0", -1, true},
		{"1.0.0-alpha", "1.0.0-alpha.1", -1, true},
		{"1.0.0-alpha.1", "1.0.0-alpha.beta", -1, true},
		{"1.0.0-alpha.beta", "1.0.0-beta", -1, true},
		{"1.0.0-beta.2", "1.0.0-beta.11", -1, true},
		{"1.0.0-beta.11", "1.0.0-rc.1", -1, true},
		{"1.0.0-rc.1", "1.0.0-rc.1", 0, true},
		{"1.0.0-1", "1.0.0-a", -1, true},
		{"1.0.0-a", "1.0.0-1", 1, true},
		{"1.0.0-99999999999999999999999", "1.0.0-100", 1, true},
		{"0.0.0-dev", "1.2.0", -1, true},
		{"v1.2.0", "1.2.0", 0, false},
		{"1.2", "1.2.0", 0, false},
		{"1.2.0", "x", 0, false},
		{"99999999999999999999.0.0", "1.0.0", 0, false},
		{"1.0.0-" + strings.Repeat("a", 60), "1.0.0", 0, false},
	}
	for _, tt := range tests {
		got, ok := Compare(tt.a, tt.b)
		if got != tt.want || ok != tt.ok {
			t.Errorf("Compare(%q, %q) = %d, %v; want %d, %v", tt.a, tt.b, got, ok, tt.want, tt.ok)
		}
	}
}

func TestNewerAndStable(t *testing.T) {
	t.Parallel()
	tests := []struct {
		latest, current string
		want            bool
	}{
		{"1.2.1", "1.2.0", true},
		{"1.2.0", "1.2.0", false},
		{"1.1.9", "1.2.0", false},
		{"1.2.0", "1.2.0-rc.1", true},
		{"1.2.0", "0.0.0-dev", true},
		{"1.3.0-rc.1", "1.2.0", false}, // a pre-release is never announced
		{"1.2.1", "not-a-version", false},
		{"garbage", "1.2.0", false},
	}
	for _, tt := range tests {
		if got := Newer(tt.latest, tt.current); got != tt.want {
			t.Errorf("Newer(%q, %q) = %v, want %v", tt.latest, tt.current, got, tt.want)
		}
	}
	for s, want := range map[string]bool{"1.2.0": true, "1.2.0+b": true, "1.2.0-rc.1": false, "v1.2.0": false, "": false} {
		if got := StableVersion(s); got != want {
			t.Errorf("StableVersion(%q) = %v, want %v", s, got, want)
		}
	}
}

func FuzzParseRelease(f *testing.F) {
	for _, s := range []string{
		`{"tag_name":"v1.2.1","html_url":"https://github.com/ed-fr/transteira/releases/tag/v1.2.1"}`,
		`{"tag_name":"v1.2.1-rc.1","prerelease":true}`, `{"tag_name":1}`, `null`, `[]`, `{"tag_name":"v1"}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		r, err := ParseRelease(body)
		if err != nil {
			if r != (Release{}) {
				t.Fatalf("ParseRelease failed but returned %+v", r)
			}
			return
		}
		if r.Version != "" && !StableVersion(r.Version) {
			t.Fatalf("ParseRelease kept the unstable or invalid version %q", r.Version)
		}
		if r.URL != "" && (r.Version == "" || FilterReleaseURL(r.URL) != r.URL) {
			t.Fatalf("ParseRelease kept the URL %q (version %q)", r.URL, r.Version)
		}
	})
}

func FuzzCompare(f *testing.F) {
	for _, s := range [][2]string{
		{"1.2.0", "1.2.1"}, {"1.0.0-rc.1", "1.0.0"}, {"1.0.0-alpha.1", "1.0.0-alpha.beta"}, {"1.0.0+x", "1.0.0"}, {"x", "1.0.0"},
	} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, a, b string) {
		ab, okAB := Compare(a, b)
		ba, okBA := Compare(b, a)
		if okAB != okBA || ab != -ba {
			t.Fatalf("Compare(%q, %q) = %d, %v but Compare(%q, %q) = %d, %v", a, b, ab, okAB, b, a, ba, okBA)
		}
		if aa, ok := Compare(a, a); ok && aa != 0 {
			t.Fatalf("Compare(%q, %q) = %d, want 0", a, a, aa)
		}
		if okAB && ab > 0 && StableVersion(a) != Newer(a, b) {
			t.Fatalf("Newer(%q, %q) disagrees with Compare", a, b)
		}
		if !okAB && Newer(a, b) {
			t.Fatalf("Newer(%q, %q) is true for an invalid version", a, b)
		}
	})
}

func FuzzFilterReleaseURL(f *testing.F) {
	for _, s := range []string{
		"https://github.com/ed-fr/transteira/releases/tag/v1.2.1", "https://github.com/ed-fr/transteira/releases/../x",
		"https://github.com:443/ed-fr/transteira/releases/x", "https://u@github.com/ed-fr/transteira/releases/x",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		got := FilterReleaseURL(raw)
		if got == "" {
			return
		}
		if got != raw || !strings.HasPrefix(got, ReleasePagePrefix) || len(got) > MaxReleaseURLLength {
			t.Fatalf("FilterReleaseURL(%q) = %q", raw, got)
		}
		rest := strings.TrimPrefix(got, ReleasePagePrefix)
		for _, seg := range strings.Split(rest, "/") {
			if seg == "" || seg == "." || seg == ".." {
				t.Fatalf("FilterReleaseURL kept %q with the segment %q", raw, seg)
			}
		}
		if strings.ContainsAny(rest, "?#@%\\") {
			t.Fatalf("FilterReleaseURL kept %q with a forbidden character", raw)
		}
	})
}

func FuzzDecodeState(f *testing.F) {
	for _, s := range []string{
		`{"latestVersion":"1.2.1","releaseUrl":"https://github.com/ed-fr/transteira/releases/tag/v1.2.1","checkedAt":"2026-10-30T06:00:00Z","lastError":"none"}`,
		`{"lastError":"network"}`, `{"latestVersion":"9.0.0-rc.1","lastError":"none"}`, `null`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		st, ok := decodeState(raw)
		if !ok {
			return
		}
		if !st.LastError.valid() || st.LatestVersion != nil && !StableVersion(*st.LatestVersion) ||
			st.ReleaseURL != nil && (st.LatestVersion == nil || FilterReleaseURL(*st.ReleaseURL) != *st.ReleaseURL) {
			t.Fatalf("decodeState(%q) accepted %+v", raw, st)
		}
	})
}
