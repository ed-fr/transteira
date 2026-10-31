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
func generateDefaultBackground() Image { return defaultSpec.render() }

// defaultSpec is the recipe of the default background: a soft blue gray at
// the top left fading to a warm light gray at the bottom right.
var defaultSpec = backgroundSpec{
	stops: []color.RGBA{
		{R: 0xD5, G: 0xDD, B: 0xE6, A: 0xFF},
		{R: 0xF1, G: 0xED, B: 0xE7, A: 0xFF},
	},
	ax: 1, ay: 1,
	seed: 0x9E3779B9,
}

// glow is a soft radial light (or shade) added over the gradient.
type glow struct {
	// cx, cy and radius are in thousandths of the image width (cx and
	// radius) and height (cy), so that a recipe does not depend on the size.
	cx, cy, radius int
	color          color.RGBA
	// strength is the opacity at the center, from 0 to 256.
	strength int
}

// backgroundSpec is the recipe of a generated background: a gradient of two
// or three evenly spaced color stops along the direction (ax, ay), soft
// radial glows and a grain from a fixed seed, so that the output is
// reproducible byte for byte.
type backgroundSpec struct {
	stops  []color.RGBA
	ax, ay int
	glows  []glow
	seed   uint32
}

// render draws the recipe at the size of the default background and encodes
// it. Everything is integer arithmetic on the pixel buffer (no math.Pow, no
// At/Set calls), which keeps a generation well under a second.
func (b backgroundSpec) render() Image {
	w, h := defaultBackgroundWidth, defaultBackgroundHeight
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	span := (w-1)*b.ax + (h-1)*b.ay
	state := b.seed
	type px struct{ cx, cy, r2 int }
	glows := make([]px, len(b.glows))
	for i, g := range b.glows {
		r := g.radius * w / 1000
		glows[i] = px{g.cx * w / 1000, g.cy * h / 1000, r * r}
	}
	for y := range h {
		row := img.Pix[y*img.Stride:]
		for x := range w {
			// xorshift32: a tiny deterministic generator for the grain.
			state ^= state << 13
			state ^= state >> 17
			state ^= state << 5
			grain := int(state%5) - 2
			c := b.gradient(x*b.ax+y*b.ay, span)
			r, g, bl := int(c[0]), int(c[1]), int(c[2])
			for i, gl := range glows {
				dx, dy := x-gl.cx, y-gl.cy
				d2 := dx*dx + dy*dy
				if d2 >= gl.r2 {
					continue
				}
				// Quadratic falloff from the center to the radius.
				k := (gl.r2 - d2) * 256 / gl.r2
				k = k * k * b.glows[i].strength >> 16
				lc := b.glows[i].color
				r += (int(lc.R) - r) * k >> 8
				g += (int(lc.G) - g) * k >> 8
				bl += (int(lc.B) - bl) * k >> 8
			}
			o := x * 4
			row[o] = clamp(r + grain)
			row[o+1] = clamp(g + grain)
			row[o+2] = clamp(bl + grain)
			row[o+3] = 0xFF
		}
	}
	var buf bytes.Buffer
	encodeJPEG(&buf, img)
	return newImage(buf.Bytes(), ContentTypeJPEG, w, h)
}

// gradient returns the color at position t of span along the stops.
func (b backgroundSpec) gradient(t, span int) [3]uint8 {
	segments := len(b.stops) - 1
	seg := min(t*segments/span, segments-1)
	// The segment seg covers [seg*span/segments, (seg+1)*span/segments].
	lo := seg * span / segments
	hi := (seg + 1) * span / segments
	a, c := b.stops[seg], b.stops[seg+1]
	return [3]uint8{
		mix(a.R, c.R, t-lo, hi-lo),
		mix(a.G, c.G, t-lo, hi-lo),
		mix(a.B, c.B, t-lo, hi-lo),
	}
}

// clamp restricts v to a byte.
func clamp(v int) uint8 { return uint8(min(max(v, 0), 0xFF)) }

// mix interpolates between a and b at position t of span.
func mix(a, b uint8, t, span int) uint8 {
	return clamp(int(a) + (int(b)-int(a))*t/span)
}
