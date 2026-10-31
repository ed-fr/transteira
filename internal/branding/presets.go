package branding

import (
	"bytes"
	"image/color"
	"sync"
)

// DefaultPresetID is the identifier of the built-in default background, the
// one served to tenants that have not chosen another preset.
const DefaultPresetID = "default"

// Preset is an entry of the library of generated backgrounds offered when an
// entity is created.
type Preset struct {
	// ID is the stable identifier stored in the database and published in
	// the API (matches ^[a-z][a-z0-9-]{0,31}$).
	ID string
	// Labels are the display names, keyed by language ("en" and "fr").
	Labels map[string]string
}

// presetDef is the compiled definition of a preset: its labels and the
// recipe of its image.
type presetDef struct {
	id     string
	en, fr string
	spec   backgroundSpec
	image  func() Image
}

// rgb builds an opaque color from a 0xRRGGBB value.
func rgb(v uint32) color.RGBA {
	return color.RGBA{R: uint8(v >> 16), G: uint8(v >> 8), B: uint8(v), A: 0xFF} //nolint:gosec // G115: byte extraction
}

// presetDefs is the library, in display order. Every background is calm and
// light to mid-tone, since a semi-transparent veil and a card are drawn over
// it. They all are variants of the generator of the default background:
// other directions, a third color stop, soft glows and their own grain seed.
var presetDefs = buildPresetDefs()

func buildPresetDefs() []*presetDef {
	specs := []struct {
		id, en, fr string
		spec       backgroundSpec
	}{
		{DefaultPresetID, "Default", "Par défaut", defaultSpec},
		{"aurora", "Aurora", "Aurore", backgroundSpec{
			stops: []color.RGBA{rgb(0xC9E8E0), rgb(0xCFCBEE), rgb(0xB5D2F0)},
			ax:    1, ay: 2, seed: 0xA5C3E1B7,
			glows: []glow{{cx: 800, cy: 250, radius: 450, color: rgb(0xE6F7DE), strength: 200}},
		}},
		{"ocean", "Ocean", "Océan", backgroundSpec{
			stops: []color.RGBA{rgb(0xD3E6F4), rgb(0x9DC3DE), rgb(0x6F9FC3)},
			ax:    0, ay: 1, seed: 0x1B873593,
			glows: []glow{{cx: 200, cy: 100, radius: 500, color: rgb(0xEAF4FB), strength: 180}},
		}},
		{"forest", "Forest", "Forêt", backgroundSpec{
			stops: []color.RGBA{rgb(0xDCE8D5), rgb(0xA9C6A1), rgb(0x729C7C)},
			ax:    2, ay: 1, seed: 0x7F4A7C15,
			glows: []glow{{cx: 150, cy: 900, radius: 420, color: rgb(0xEEF5D8), strength: 170}},
		}},
		{"sunset", "Sunset", "Coucher de soleil", backgroundSpec{
			stops: []color.RGBA{rgb(0xF7E1CF), rgb(0xEFBCA3), rgb(0xCB9DBA)},
			ax:    1, ay: 1, seed: 0x2545F491,
			glows: []glow{{cx: 850, cy: 850, radius: 480, color: rgb(0xFBE8B8), strength: 190}},
		}},
		{"dusk", "Dusk", "Crépuscule", backgroundSpec{
			stops: []color.RGBA{rgb(0xDBD6ED), rgb(0xABA2D1), rgb(0x7C7AAE)},
			ax:    1, ay: 3, seed: 0x5BD1E995,
			glows: []glow{
				{cx: 250, cy: 200, radius: 400, color: rgb(0xEFE9F7), strength: 170},
				{cx: 900, cy: 800, radius: 350, color: rgb(0xC9B8DE), strength: 120},
			},
		}},
		{"sand", "Sand", "Sable", backgroundSpec{
			stops: []color.RGBA{rgb(0xF4ECDF), rgb(0xE3D3B9), rgb(0xCDB993)},
			ax:    3, ay: 1, seed: 0x6C078965,
			glows: []glow{{cx: 500, cy: 0, radius: 600, color: rgb(0xFBF6EA), strength: 160}},
		}},
		{"slate", "Slate", "Ardoise", backgroundSpec{
			stops: []color.RGBA{rgb(0xE2E6EB), rgb(0xB4BDC9), rgb(0x8794A4)},
			ax:    1, ay: 1, seed: 0x3C6EF372,
			glows: []glow{{cx: 900, cy: 100, radius: 450, color: rgb(0xF2F4F7), strength: 170}},
		}},
	}
	defs := make([]*presetDef, len(specs))
	for i, s := range specs {
		d := &presetDef{id: s.id, en: s.en, fr: s.fr, spec: s.spec}
		if s.id == DefaultPresetID {
			// Exactly the bytes of DefaultBackground, generated only once.
			d.image = defaultBackground
		} else {
			d.image = sync.OnceValue(d.spec.render)
		}
		defs[i] = d
	}
	return defs
}

// Presets returns the library of background presets in display order,
// [DefaultPresetID] first. The result is a deep copy the caller may modify.
func Presets() []Preset {
	out := make([]Preset, len(presetDefs))
	for i, d := range presetDefs {
		out[i] = Preset{ID: d.id, Labels: map[string]string{"en": d.en, "fr": d.fr}}
	}
	return out
}

// lookupPreset returns the definition of the preset id, or nil.
func lookupPreset(id string) *presetDef {
	for _, d := range presetDefs {
		if d.id == id {
			return d
		}
	}
	return nil
}

// ValidPreset reports whether id is one of [Presets] (an exact match against
// the compiled list, so a value can never be turned into a path or a query).
func ValidPreset(id string) bool { return lookupPreset(id) != nil }

// PresetBackground returns the JPEG background of the preset id, or false for
// an unknown id. It is generated deterministically on first use and kept in
// memory; the returned Data is a copy the caller may keep or modify. The
// default preset is exactly [DefaultBackground].
func PresetBackground(id string) (Image, bool) {
	d := lookupPreset(id)
	if d == nil {
		return Image{}, false
	}
	img := d.image()
	img.Data = bytes.Clone(img.Data)
	return img, true
}

// BackgroundFor returns the background served for a stored preset value:
// the image of the preset id, or [DefaultBackground] when id is empty or
// unknown (a stale database value is never an error).
func BackgroundFor(id string) Image {
	if img, ok := PresetBackground(id); ok {
		return img
	}
	return DefaultBackground()
}
