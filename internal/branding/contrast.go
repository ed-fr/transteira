package branding

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strings"
)

// ErrInvalidColor means a color is not in the #RRGGBB form.
var ErrInvalidColor = errors.New("branding: color must be #RRGGBB")

// Color is an sRGB color with 8 bits per channel.
type Color struct {
	R, G, B uint8
}

// LightBackground is the page background of the light theme, against which
// the tenant colors are checked.
var LightBackground = Color{R: 0xFF, G: 0xFF, B: 0xFF}

// DarkBackground is the surface color (#111827) of the dark theme, against
// which the tenant colors are also checked.
var DarkBackground = Color{R: 0x11, G: 0x18, B: 0x27}

// TextOnPrimary is the color of text written on the primary color (buttons).
var TextOnPrimary = Color{R: 0xFF, G: 0xFF, B: 0xFF}

// ParseHexColor parses a color in the #RRGGBB form (either case), matching
// the HexColor schema of the API.
func ParseHexColor(s string) (Color, error) {
	if len(s) != 7 || s[0] != '#' {
		return Color{}, fmt.Errorf("%w: %q", ErrInvalidColor, s)
	}
	b, err := hex.DecodeString(s[1:])
	if err != nil {
		return Color{}, fmt.Errorf("%w: %q", ErrInvalidColor, s)
	}
	return Color{R: b[0], G: b[1], B: b[2]}, nil
}

// Hex returns the color in the #RRGGBB form, uppercase.
func (c Color) Hex() string {
	return "#" + strings.ToUpper(hex.EncodeToString([]byte{c.R, c.G, c.B}))
}

// RelativeLuminance returns the WCAG 2.x relative luminance of c, between 0
// (black) and 1 (white).
func RelativeLuminance(c Color) float64 {
	return 0.2126*linear(c.R) + 0.7152*linear(c.G) + 0.0722*linear(c.B)
}

// linear converts an 8-bit sRGB channel to linear light.
func linear(v uint8) float64 {
	s := float64(v) / 255
	if s <= 0.04045 {
		return s / 12.92
	}
	return math.Pow((s+0.055)/1.055, 2.4)
}

// ContrastRatio returns the WCAG 2.x contrast ratio of a and b, between 1
// and 21, whatever their order.
func ContrastRatio(a, b Color) float64 {
	la, lb := RelativeLuminance(a), RelativeLuminance(b)
	if la < lb {
		la, lb = lb, la
	}
	return (la + 0.05) / (lb + 0.05)
}

// Level is a WCAG conformance level for normal text.
type Level string

// Contrast levels, matching the ContrastResult schema of the API.
const (
	LevelAAA  Level = "AAA"
	LevelAA   Level = "AA"
	LevelFail Level = "fail"
)

// Minimum contrast ratios of the levels for normal text.
const (
	MinRatioAAA = 7.0
	MinRatioAA  = 4.5
)

// LevelFor returns the level reached by a contrast ratio.
func LevelFor(ratio float64) Level {
	switch {
	case ratio >= MinRatioAAA:
		return LevelAAA
	case ratio >= MinRatioAA:
		return LevelAA
	default:
		return LevelFail
	}
}

// Pair names a checked foreground / background combination.
type Pair string

// Checked pairs, matching the ContrastResult schema of the API.
const (
	PairPrimaryOnLight Pair = "primary-on-light"
	PairAccentOnLight  Pair = "accent-on-light"
	PairTextOnPrimary  Pair = "text-on-primary"
	PairPrimaryOnDark  Pair = "primary-on-dark"
	PairAccentOnDark   Pair = "accent-on-dark"
)

// ContrastResult is the contrast check of one pair.
type ContrastResult struct {
	// Pair is the checked combination.
	Pair Pair `json:"pair"`
	// Ratio is the contrast ratio, truncated (never rounded up) to two
	// decimals.
	Ratio float64 `json:"ratio"`
	// Level is the level reached by Ratio.
	Level Level `json:"level"`
}

// Check returns the contrast of the tenant colors for each pair of the API:
// primary and accent on the light background, text on the primary color, then
// primary and accent on the dark background. A failing light pair is a
// warning to show the admin, not a refusal. A failing *-on-dark pair is only
// informative: the dark theme then keeps its own accessible link and focus
// colors, and uses the accent for decoration only.
func Check(primary, accent Color) []ContrastResult {
	return []ContrastResult{
		result(PairPrimaryOnLight, primary, LightBackground),
		result(PairAccentOnLight, accent, LightBackground),
		result(PairTextOnPrimary, TextOnPrimary, primary),
		result(PairPrimaryOnDark, primary, DarkBackground),
		result(PairAccentOnDark, accent, DarkBackground),
	}
}

// result computes the contrast result of one pair.
func result(pair Pair, fg, bg Color) ContrastResult {
	// The epsilon absorbs floating point noise (21 may come out as 20.999...).
	ratio := math.Floor(ContrastRatio(fg, bg)*100+1e-9) / 100
	return ContrastResult{Pair: pair, Ratio: ratio, Level: LevelFor(ratio)}
}
