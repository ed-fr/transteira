package branding

import (
	"errors"
	"math"
	"testing"
)

// mustColor parses a color or fails the test.
func mustColor(t *testing.T, s string) Color {
	t.Helper()
	c, err := ParseHexColor(s)
	if err != nil {
		t.Fatalf("ParseHexColor(%q): %v", s, err)
	}
	return c
}

func TestParseHexColor(t *testing.T) {
	valid := map[string]Color{
		"#000000": {},
		"#FFFFFF": {R: 0xFF, G: 0xFF, B: 0xFF},
		"#1a2B3c": {R: 0x1A, G: 0x2B, B: 0x3C},
	}
	for s, want := range valid {
		if got := mustColor(t, s); got != want {
			t.Errorf("ParseHexColor(%q) = %v, want %v", s, got, want)
		}
	}
	for _, s := range []string{"", "#FFF", "FFFFFFF", "#FFFFFFF", "#GGGGGG", "#12345", " #123456", "rgb(0,0,0)"} {
		if _, err := ParseHexColor(s); !errors.Is(err, ErrInvalidColor) {
			t.Errorf("ParseHexColor(%q): err = %v", s, err)
		}
	}
}

func TestHex(t *testing.T) {
	if got := mustColor(t, "#1a2b3c").Hex(); got != "#1A2B3C" {
		t.Errorf("Hex = %s", got)
	}
}

func TestRelativeLuminance(t *testing.T) {
	cases := map[string]float64{
		"#000000": 0,
		"#FFFFFF": 1,
		"#FF0000": 0.2126,
		"#00FF00": 0.7152,
		"#0000FF": 0.0722,
		"#0A0A0A": 0.0030352698,  // linear segment (below 0.04045)
		"#777777": 0.18447565544, // gamma segment
	}
	for s, want := range cases {
		if got := RelativeLuminance(mustColor(t, s)); math.Abs(got-want) > 1e-6 {
			t.Errorf("RelativeLuminance(%s) = %v, want %v", s, got, want)
		}
	}
}

func TestContrastRatio(t *testing.T) {
	cases := []struct {
		a, b string
		want float64
	}{
		{"#000000", "#FFFFFF", 21},
		{"#FFFFFF", "#000000", 21},
		{"#777777", "#FFFFFF", 4.478},
		{"#767676", "#FFFFFF", 4.542},
		{"#595959", "#FFFFFF", 7.0},
		{"#123456", "#123456", 1},
	}
	for _, tc := range cases {
		if got := ContrastRatio(mustColor(t, tc.a), mustColor(t, tc.b)); math.Abs(got-tc.want) > 0.005 {
			t.Errorf("ContrastRatio(%s, %s) = %v, want about %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestLevelFor(t *testing.T) {
	cases := map[float64]Level{21: LevelAAA, 7: LevelAAA, 6.99: LevelAA, 4.5: LevelAA, 4.49: LevelFail, 1: LevelFail}
	for ratio, want := range cases {
		if got := LevelFor(ratio); got != want {
			t.Errorf("LevelFor(%v) = %s, want %s", ratio, got, want)
		}
	}
}

func TestCheck(t *testing.T) {
	got := Check(mustColor(t, "#000000"), mustColor(t, "#777777"))
	want := []ContrastResult{
		{Pair: PairPrimaryOnLight, Ratio: 21, Level: LevelAAA},
		{Pair: PairAccentOnLight, Ratio: 4.47, Level: LevelFail}, // truncated, never rounded up to AA
		{Pair: PairTextOnPrimary, Ratio: 21, Level: LevelAAA},
	}
	if len(got) != len(want) {
		t.Fatalf("Check = %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Check[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
	// A mid-tone primary: white text on it is AA, the primary on white is AA.
	mid := Check(mustColor(t, "#767676"), mustColor(t, "#FFFFFF"))
	if mid[0].Level != LevelAA || mid[1].Level != LevelFail || mid[1].Ratio != 1 || mid[2].Level != LevelAA {
		t.Errorf("Check(#767676, #FFFFFF) = %+v", mid)
	}
}
