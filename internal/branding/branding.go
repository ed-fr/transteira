// Package branding validates and normalizes the visual identity of a tenant:
// logo and background images, and the WCAG contrast of its colors (§13).
//
// Uploaded images are never stored or served as received. [Process] detects
// the format from the content (PNG, JPEG or WebP only), bounds the declared
// dimensions before decoding anything (decompression bombs), decodes the
// image, downscales it when needed and re-encodes it: PNG for a logo, JPEG
// for a background. Before decoding, the memory that decoding, scaling and
// re-encoding may allocate is estimated from the declared dimensions, for the
// worst case of the format, declared color model and layout (every
// allocation counted, short-lived ones included, as the tests measure), and
// bounded by [MaxDecodeBytes]; at most [MaxConcurrentReads] upload bodies are
// held and [MaxConcurrentDecodes] images decoded at once in the process, so
// that a burst of uploads cannot exhaust memory. Metadata (EXIF,
// ICC profiles, text chunks), trailing data and any active content are
// dropped by construction, since only pixels survive the round trip.
package branding

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"golang.org/x/image/draw"
)

// Kind identifies a branding image.
type Kind int

// Branding image kinds.
const (
	// KindLogo is the tenant logo, re-encoded as PNG to keep transparency.
	KindLogo Kind = iota + 1
	// KindBackground is the full-screen background image, re-encoded as JPEG.
	KindBackground
)

// Upload size limits, as published in the OpenAPI specification.
const (
	// MaxLogoBytes is the largest accepted logo upload (5 MiB).
	MaxLogoBytes int64 = 5 << 20
	// MaxBackgroundBytes is the largest accepted background upload (10 MiB).
	MaxBackgroundBytes int64 = 10 << 20
)

// Dimension limits, checked on the image header before decoding.
const (
	// MaxLogoSide is the largest accepted logo width or height, in pixels.
	MaxLogoSide = 2048
	// MaxBackgroundSide is the largest accepted background width or height.
	MaxBackgroundSide = 8192
	// MaxBackgroundPixels caps the background area (35 Mpx): a
	// non-interlaced 8-bit PNG background of that size, plus its scaling and
	// encoding buffers, fits within [MaxDecodeBytes]. Formats whose worst
	// case needs more memory per pixel are further limited by that budget:
	// about 26 to 33 Mpx for a 16-bit or interlaced 8-bit PNG, 12.1 to 13.7
	// Mpx for a three-component JPEG (a 4000 x 3000 photo fits), 10.2 for a
	// CMYK JPEG and 5.9 for a WebP, whose lossless Huffman trees alone may
	// take 203 MiB.
	MaxBackgroundPixels = 35_000_000
	// LogoTargetSide is the longest side of a stored logo; larger logos are
	// downscaled, keeping their aspect ratio.
	LogoTargetSide = 512
	// BackgroundTargetSide is the longest side of a stored background.
	BackgroundTargetSide = 3840
	// BackgroundJPEGQuality is the JPEG quality of a stored background.
	BackgroundJPEGQuality = 85
)

// Decoding limits, shared by every request of the process.
const (
	// MaxDecodeBytes bounds the memory one image may need to be decoded,
	// scaled and re-encoded (320 MiB), estimated before decoding from its
	// declared dimensions for the worst case of its format, color model and
	// layout; a larger image is refused with [ErrTooLarge], like an image of
	// oversized dimensions. Reading the body comes on top: about twice the
	// upload size.
	MaxDecodeBytes int64 = 320 << 20
	// MaxConcurrentDecodes is the number of images decoded at the same time
	// in the process, so that processing never needs more than
	// MaxConcurrentDecodes x [MaxDecodeBytes]; further uploads wait for a
	// slot or for the cancellation of their context.
	MaxConcurrentDecodes = 1
	// MaxConcurrentReads is the number of upload bodies read and held in
	// memory at the same time in the process, each up to the byte limit of
	// its kind, from reading until the image is processed or refused;
	// further uploads wait, before reading their body, for a slot or for
	// the cancellation of their context.
	MaxConcurrentReads = 4
)

// Content types of the re-encoded images.
const (
	ContentTypePNG  = "image/png"
	ContentTypeJPEG = "image/jpeg"
)

// Errors returned by [Process] and [ParseKind].
var (
	// ErrUnsupportedFormat means the content is not a PNG, JPEG or WebP
	// image (HTTP 415).
	ErrUnsupportedFormat = errors.New("branding: unsupported image format (PNG, JPEG or WebP only)")
	// ErrTooLarge means the upload exceeds the byte limit, its declared
	// dimensions exceed the limits of its kind, or processing it would need
	// more than [MaxDecodeBytes] (HTTP 413).
	ErrTooLarge = errors.New("branding: image too large")
	// ErrInvalid means the image is corrupt, truncated or has impossible
	// dimensions (HTTP 400).
	ErrInvalid = errors.New("branding: invalid image")
	// ErrUnknownKind means the kind is neither logo nor background.
	ErrUnknownKind = errors.New("branding: unknown image kind")
)

// Image is a re-encoded branding image, safe to store and serve as is.
type Image struct {
	// Data is the encoded image (PNG or JPEG).
	Data []byte
	// ContentType is the exact media type of Data.
	ContentType string
	// Width and Height are the dimensions of the stored image.
	Width, Height int
	// ETag is the quoted hexadecimal SHA-256 of Data, usable as an HTTP
	// entity tag.
	ETag string
}

// kindSpec holds the limits and output format of a kind.
type kindSpec struct {
	name        string
	maxBytes    int64
	maxSide     int
	maxPixels   int64
	targetSide  int
	contentType string
	// scaler downscales the decoded image to targetSide. A [draw.Kernel]
	// allocates a temporary buffer, counted by [kindSpec.memoryNeed].
	scaler draw.Scaler
}

// spec returns the limits of k, or false for an unknown kind.
func (k Kind) spec() (kindSpec, bool) {
	switch k {
	case KindLogo:
		return kindSpec{
			name: "logo", maxBytes: MaxLogoBytes, maxSide: MaxLogoSide,
			maxPixels: MaxLogoSide * MaxLogoSide, targetSide: LogoTargetSide,
			contentType: ContentTypePNG,
			// Up to 4x smaller: Catmull-Rom keeps small logos sharp.
			scaler: draw.CatmullRom,
		}, true
	case KindBackground:
		return kindSpec{
			name: "background", maxBytes: MaxBackgroundBytes, maxSide: MaxBackgroundSide,
			maxPixels: MaxBackgroundPixels, targetSide: BackgroundTargetSide,
			contentType: ContentTypeJPEG,
			// At most 8192 to 3840, about 2x smaller: the approximate
			// bilinear scaler is good enough there and, unlike a kernel,
			// allocates nothing proportional to the source.
			scaler: draw.ApproxBiLinear,
		}, true
	default:
		return kindSpec{}, false
	}
}

// String returns "logo" or "background" (the {asset} path value of the
// API), or "" for an unknown kind.
func (k Kind) String() string {
	s, _ := k.spec()
	return s.name
}

// MaxBytes returns the upload size limit of k, or 0 for an unknown kind.
func (k Kind) MaxBytes() int64 {
	s, _ := k.spec()
	return s.maxBytes
}

// ContentType returns the media type of the images stored for k, or "" for
// an unknown kind.
func (k Kind) ContentType() string {
	s, _ := k.spec()
	return s.contentType
}

// ParseKind parses an {asset} path value: "logo" or "background".
func ParseKind(s string) (Kind, error) {
	for _, k := range []Kind{KindLogo, KindBackground} {
		if s == k.String() {
			return k, nil
		}
	}
	return 0, ErrUnknownKind
}

// newImage wraps encoded data with its metadata and entity tag.
func newImage(data []byte, contentType string, width, height int) Image {
	sum := sha256.Sum256(data)
	return Image{
		Data:        data,
		ContentType: contentType,
		Width:       width,
		Height:      height,
		ETag:        `"` + hex.EncodeToString(sum[:]) + `"`,
	}
}
