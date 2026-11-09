package branding

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"sync"

	"golang.org/x/image/draw"
)

// Sizes of the generated icons, in pixels.
const (
	icoSize16 = 16
	icoSize32 = 32
	icoSize48 = 48
	// appleTouchSide is the side of the apple-touch-icon.
	appleTouchSide = 180
)

// FaviconKinds returns the generated icon kinds: [KindFavicon],
// [KindFavicon32] and [KindAppleTouchIcon], in that order.
func FaviconKinds() []Kind {
	return []Kind{KindFavicon, KindFavicon32, KindAppleTouchIcon}
}

// Favicons are the icons generated from a tenant logo.
type Favicons struct {
	// ICO is the multi-size container (PNG images of 16, 32 and 48 px).
	ICO Image
	// PNG32 is the 32x32 PNG icon.
	PNG32 Image
	// PNG180 is the 180x180 PNG icon (apple-touch-icon).
	PNG180 Image
}

// Get returns the image of kind k (one of [FaviconKinds]), or false for
// another kind.
func (f Favicons) Get(k Kind) (Image, bool) {
	switch k {
	case KindFavicon:
		return f.ICO, true
	case KindFavicon32:
		return f.PNG32, true
	case KindAppleTouchIcon:
		return f.PNG180, true
	default:
		return Image{}, false
	}
}

// GenerateFavicons builds the favicons from a logo already re-encoded by
// [Process], that is a PNG: anything else is refused with [ErrInvalid], and
// dimensions above [MaxLogoSide] with [ErrTooLarge] (checked on the header,
// before decoding). The decoding and scaling hold a decoding slot of the
// process like [Process] does, so that icon generation cannot add to the
// memory of concurrent image processing; ctx cancels the wait for it.
//
// The logo is centered on a transparent square, whatever its aspect ratio,
// and scaled with Catmull-Rom for each size.
func GenerateFavicons(ctx context.Context, logoPNG []byte) (Favicons, error) {
	cfg, err := png.DecodeConfig(bytes.NewReader(logoPNG))
	if err != nil {
		return Favicons{}, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if cfg.Width > MaxLogoSide || cfg.Height > MaxLogoSide {
		return Favicons{}, fmt.Errorf("%w: logo %dx%d exceeds %d px", ErrTooLarge, cfg.Width, cfg.Height, MaxLogoSide)
	}
	release, err := acquireSlot(ctx, decodeSlots)
	if err != nil {
		return Favicons{}, fmt.Errorf("branding: wait for a decoding slot: %w", err)
	}
	defer release()
	src, err := png.Decode(bytes.NewReader(logoPNG))
	if err != nil {
		return Favicons{}, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	return iconsFrom(func(side int) *image.NRGBA { return squareIcon(src, side) }), nil
}

// iconsFrom encodes the icons, each size being drawn by drawSide.
func iconsFrom(drawSide func(side int) *image.NRGBA) Favicons {
	p16 := encodePNGBytes(drawSide(icoSize16))
	p32 := encodePNGBytes(drawSide(icoSize32))
	p48 := encodePNGBytes(drawSide(icoSize48))
	p180 := encodePNGBytes(drawSide(appleTouchSide))
	ico := buildICO([]icoImage{{icoSize16, p16}, {icoSize32, p32}, {icoSize48, p48}})
	return Favicons{
		ICO:    newImage(ico, ContentTypeICO, icoSize48, icoSize48),
		PNG32:  newImage(p32, ContentTypePNG, icoSize32, icoSize32),
		PNG180: newImage(p180, ContentTypePNG, appleTouchSide, appleTouchSide),
	}
}

// squareIcon scales src to fill a side x side transparent square, centered,
// keeping its aspect ratio (at least 1 pixel on each side). Small logos are
// enlarged too: an icon is displayed at a fixed size.
func squareIcon(src image.Image, side int) *image.NRGBA {
	dst := image.NewNRGBA(image.Rect(0, 0, side, side))
	b := src.Bounds()
	w, h := side, max(1, (b.Dy()*side+b.Dx()/2)/b.Dx())
	if b.Dy() > b.Dx() {
		w, h = max(1, (b.Dx()*side+b.Dy()/2)/b.Dy()), side
	}
	x, y := (side-w)/2, (side-h)/2
	draw.CatmullRom.Scale(dst, image.Rect(x, y, x+w, y+h), toFastSource(src), b, draw.Src, nil)
	return dst
}

// encodePNGBytes encodes img. Encoding into a bytes.Buffer cannot fail for
// bounded dimensions.
func encodePNGBytes(img image.Image) []byte {
	var buf bytes.Buffer
	_ = (&png.Encoder{CompressionLevel: png.BestCompression}).Encode(&buf, img)
	return buf.Bytes()
}

// icoImage is one PNG image of an ICO container.
type icoImage struct {
	side int
	data []byte
}

// buildICO writes an ICO container: an ICONDIR (reserved 0, type 1, count),
// one 16-byte ICONDIRENTRY per image (width, height, no palette, 1 plane,
// 32 bits per pixel, payload length and offset), then the PNG payloads.
// Sides must be below 256 (a byte of 0 would mean 256).
func buildICO(images []icoImage) []byte {
	offset := 6 + 16*len(images)
	var buf bytes.Buffer
	le := binary.LittleEndian
	_ = binary.Write(&buf, le, [3]uint16{0, 1, uint16(len(images))}) //nolint:gosec // G115: three fixed images
	for _, im := range images {
		buf.Write([]byte{byte(im.side), byte(im.side), 0, 0}) //nolint:gosec // G115: sides are 16, 32 and 48
		_ = binary.Write(&buf, le, [2]uint16{1, 32})
		_ = binary.Write(&buf, le, [2]uint32{uint32(len(im.data)), uint32(offset)}) //nolint:gosec // G115: payloads of a few KiB
		offset += len(im.data)
	}
	for _, im := range images {
		buf.Write(im.data)
	}
	return buf.Bytes()
}

// defaultFavicons generates the built-in icons once, on first use.
var defaultFavicons = sync.OnceValue(func() Favicons { return iconsFrom(renderDefaultIcon) })

// DefaultFavicon returns the built-in icon of kind k (one of [FaviconKinds])
// served to tenants without a logo, or false for another kind. The icon is
// generated deterministically by code (no external file): a neutral blue
// rounded square with a white "T", deliberately not the TransTeira symbol of
// the administration (web/static/favicon.svg), so that the public pages of a
// tenant stay unbranded. The returned Data is a copy the caller may keep or
// modify.
func DefaultFavicon(k Kind) (Image, bool) {
	img, ok := defaultFavicons().Get(k)
	if !ok {
		return Image{}, false
	}
	img.Data = bytes.Clone(img.Data)
	return img, true
}

// iconSamples is the supersampling of the built-in icon: samples per pixel
// side.
const iconSamples = 4

// renderDefaultIcon draws the built-in icon on a side x side square. The
// shapes are drawn on a 32-unit grid: a #1d4ed8 square of
// radius 6 and a white "T" made of a bar (9,11)-(23,11) and a stem
// (16,11)-(16,23), 3 units thick with round caps. Coverage is estimated by
// supersampling, which gives smooth edges at every size.
func renderDefaultIcon(side int) *image.NRGBA {
	dst := image.NewNRGBA(image.Rect(0, 0, side, side))
	blue := [3]int{0x1D, 0x4E, 0xD8}
	unit := 32 / float64(side*iconSamples)
	for py := range side {
		for px := range side {
			var inside, ink int
			for sy := range iconSamples {
				for sx := range iconSamples {
					x := (float64(px*iconSamples+sx) + 0.5) * unit
					y := (float64(py*iconSamples+sy) + 0.5) * unit
					if !inRoundedSquare(x, y) {
						continue
					}
					inside++
					if nearSegment(x, y, 9, 11, 23, 11) || nearSegment(x, y, 16, 11, 16, 23) {
						ink++
					}
				}
			}
			if inside == 0 {
				continue
			}
			// White over blue by the share of ink among the covered samples.
			mixc := func(c int) uint8 { return uint8((c*(inside-ink) + 255*ink + inside/2) / inside) } //nolint:gosec // G115: a weighted mean of bytes
			const total = iconSamples * iconSamples
			dst.SetNRGBA(px, py, color.NRGBA{
				R: mixc(blue[0]), G: mixc(blue[1]), B: mixc(blue[2]),
				A: uint8((inside*255 + total/2) / total), //nolint:gosec // G115: inside <= total
			})
		}
	}
	return dst
}

// inRoundedSquare reports whether (x, y) is inside the 32-unit square with
// corners of radius 6.
func inRoundedSquare(x, y float64) bool {
	const side, r = 32.0, 6.0
	cx := min(max(x, r), side-r)
	cy := min(max(y, r), side-r)
	dx, dy := x-cx, y-cy
	return dx*dx+dy*dy <= r*r
}

// nearSegment reports whether (x, y) is within half the stroke width (1.5)
// of the segment (x1, y1)-(x2, y2): a thick line with round caps.
func nearSegment(x, y, x1, y1, x2, y2 float64) bool {
	const half = 1.5
	dx, dy := x2-x1, y2-y1
	t := min(max(((x-x1)*dx+(y-y1)*dy)/(dx*dx+dy*dy), 0), 1)
	ex, ey := x-(x1+t*dx), y-(y1+t*dy)
	return ex*ex+ey*ey <= half*half
}
