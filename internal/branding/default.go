package branding

import (
	"bytes"
	"image"
	"image/color"
	"sync"
)

// Dimensions of the generated default background.
const (
	defaultBackgroundWidth  = 1920
	defaultBackgroundHeight = 1080
)

// defaultBackground generates the default background once, on first use.
var defaultBackground = sync.OnceValue(generateDefaultBackground)

// DefaultBackground returns the background served to tenants that have not
// uploaded one: a neutral, generic diagonal gradient with a subtle grain,
// generated deterministically (no external file, no brand). The returned
// Data is a copy the caller may keep or modify.
func DefaultBackground() Image {
	img := defaultBackground()
	img.Data = bytes.Clone(img.Data)
	return img
}

// generateDefaultBackground renders and encodes the default background.
func generateDefaultBackground() Image {
	from := color.RGBA{R: 0xD5, G: 0xDD, B: 0xE6, A: 0xFF} // soft blue gray, top left
	to := color.RGBA{R: 0xF1, G: 0xED, B: 0xE7, A: 0xFF}   // warm light gray, bottom right
	w, h := defaultBackgroundWidth, defaultBackgroundHeight
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	span := w + h - 2
	state := uint32(0x9E3779B9) // fixed seed: the output is reproducible
	for y := range h {
		for x := range w {
			// xorshift32: a tiny deterministic generator for the grain.
			state ^= state << 13
			state ^= state >> 17
			state ^= state << 5
			grain := int(state%5) - 2
			t := x + y
			img.SetRGBA(x, y, color.RGBA{
				R: mix(from.R, to.R, t, span, grain),
				G: mix(from.G, to.G, t, span, grain),
				B: mix(from.B, to.B, t, span, grain),
				A: 0xFF,
			})
		}
	}
	var buf bytes.Buffer
	encodeJPEG(&buf, img)
	return newImage(buf.Bytes(), ContentTypeJPEG, w, h)
}

// mix interpolates between a and b at position t of span, adds grain and
// clamps the result to a byte.
func mix(a, b uint8, t, span, grain int) uint8 {
	v := int(a) + (int(b)-int(a))*t/span + grain
	return uint8(min(max(v, 0), 0xFF))
}
