package branding

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash/crc32"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"

	"golang.org/x/image/draw"
)

// gradient returns a w x h test image with an opaque gradient.
func gradient(w, h int) *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	for y := range h {
		for x := range w {
			img.SetNRGBA(x, y, color.NRGBA{R: uint8(x), G: uint8(y), B: 0x80, A: 0xFF})
		}
	}
	return img
}

// encodePNG encodes img as PNG.
func encodePNG(t testing.TB, img image.Image) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// encodeJPEGT encodes img as JPEG.
func encodeJPEGT(t testing.TB, img image.Image) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, nil); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// readFixture reads a file of testdata.
func readFixture(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// pngChunk builds a PNG chunk with a valid CRC.
func pngChunk(typ string, data []byte) []byte {
	var b []byte
	b = binary.BigEndian.AppendUint32(b, uint32(len(data)))
	b = append(b, typ...)
	b = append(b, data...)
	return binary.BigEndian.AppendUint32(b, crc32.ChecksumIEEE(append([]byte(typ), data...)))
}

// pngHeader returns a PNG made of only a signature and an IHDR chunk
// declaring the given dimensions (8-bit RGBA). It cannot be decoded.
func pngHeader(w, h uint32) []byte {
	return pngHeaderDepth(w, h, 8, 6)
}

// pngHeaderDepth is pngHeader with the given bit depth and color type.
func pngHeaderDepth(w, h uint32, depth, colorType byte) []byte {
	ihdr := binary.BigEndian.AppendUint32(nil, w)
	ihdr = binary.BigEndian.AppendUint32(ihdr, h)
	ihdr = append(ihdr, depth, colorType, 0, 0, 0)
	return append(append([]byte{}, pngMagic...), pngChunk("IHDR", ihdr)...)
}

// jpegHeader returns a JPEG made of only SOI, a baseline SOF0 segment
// declaring the given dimensions (one gray component) and a start of scan
// header (where the decoder stops reading the configuration). It cannot be
// decoded.
func jpegHeader(w, h uint16) []byte {
	return jpegHeaderSOF(w, h, 0xC0, 1)
}

// jpegHeaderSOF is jpegHeader with the given start of frame marker (0xC2
// for a progressive JPEG) and number of components (1, 3 or 4).
func jpegHeaderSOF(w, h uint16, sof byte, comps int) []byte {
	ids := []byte{1, 2, 3, 4}[:comps]
	return append([]byte{0xFF, 0xD8}, append(jpegSOF(w, h, sof, ids), jpegSOS...)...)
}

// jpegSOF returns a start of frame segment declaring the given dimensions
// and one component (sampling 1x1, table 0) per identifier of ids.
func jpegSOF(w, h uint16, sof byte, ids []byte) []byte {
	b := []byte{0xFF, sof}
	b = binary.BigEndian.AppendUint16(b, uint16(8+3*len(ids)))
	b = append(b, 0x08)
	b = binary.BigEndian.AppendUint16(b, h)
	b = binary.BigEndian.AppendUint16(b, w)
	b = append(b, byte(len(ids)))
	for _, id := range ids {
		b = append(b, id, 0x11, 0x00)
	}
	return b
}

// jpegSOS is a start of scan header for one component.
var jpegSOS = []byte{0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00}

// webpHeader returns an extended WebP made of only a VP8X chunk declaring
// the given canvas dimensions. It cannot be decoded.
func webpHeader(w, h uint32) []byte {
	vp8x := []byte{0, 0, 0, 0}
	for _, v := range []uint32{w - 1, h - 1} {
		vp8x = append(vp8x, byte(v), byte(v>>8), byte(v>>16))
	}
	body := append([]byte("WEBPVP8X"), binary.LittleEndian.AppendUint32(nil, uint32(len(vp8x)))...)
	body = append(body, vp8x...)
	return append(append([]byte("RIFF"), binary.LittleEndian.AppendUint32(nil, uint32(len(body)))...), body...)
}

// checkOutput decodes img.Data with the decoder of its content type and
// checks its dimensions and entity tag.
func checkOutput(t testing.TB, img Image) image.Image {
	t.Helper()
	var (
		dec image.Image
		err error
	)
	switch img.ContentType {
	case ContentTypePNG:
		dec, err = png.Decode(bytes.NewReader(img.Data))
	case ContentTypeJPEG:
		dec, err = jpeg.Decode(bytes.NewReader(img.Data))
	default:
		t.Fatalf("content type %q", img.ContentType)
	}
	if err != nil {
		t.Fatalf("output does not decode: %v", err)
	}
	if b := dec.Bounds(); b.Dx() != img.Width || b.Dy() != img.Height {
		t.Fatalf("output %dx%d, Image says %dx%d", b.Dx(), b.Dy(), img.Width, img.Height)
	}
	sum := sha256.Sum256(img.Data)
	if want := `"` + hex.EncodeToString(sum[:]) + `"`; img.ETag != want {
		t.Fatalf("ETag = %s, want %s", img.ETag, want)
	}
	return dec
}

func TestProcessFormats(t *testing.T) {
	cases := []struct {
		name       string
		kind       Kind
		data       []byte
		wantType   string
		wantW      int
		wantH      int
		wantPixels func(t *testing.T, img image.Image)
	}{
		{name: "png logo", kind: KindLogo, data: encodePNG(t, gradient(100, 50)), wantType: ContentTypePNG, wantW: 100, wantH: 50},
		{name: "jpeg logo", kind: KindLogo, data: encodeJPEGT(t, gradient(64, 64)), wantType: ContentTypePNG, wantW: 64, wantH: 64},
		{name: "webp lossy logo", kind: KindLogo, data: readFixture(t, "lossy-64x48.webp"), wantType: ContentTypePNG, wantW: 64, wantH: 48},
		{
			name: "webp lossless logo keeps transparency", kind: KindLogo,
			data: readFixture(t, "lossless-alpha-40x30.webp"), wantType: ContentTypePNG, wantW: 40, wantH: 30,
			wantPixels: func(t *testing.T, img image.Image) {
				t.Helper()
				if _, _, _, a := img.At(30, 10).RGBA(); a != 0 {
					t.Errorf("alpha at transparent pixel = %d", a)
				}
				if _, _, _, a := img.At(5, 10).RGBA(); a != 0xFFFF {
					t.Errorf("alpha at opaque pixel = %d", a)
				}
			},
		},
		{name: "png background", kind: KindBackground, data: encodePNG(t, gradient(200, 100)), wantType: ContentTypeJPEG, wantW: 200, wantH: 100},
		{name: "jpeg background", kind: KindBackground, data: encodeJPEGT(t, gradient(80, 60)), wantType: ContentTypeJPEG, wantW: 80, wantH: 60},
		{name: "webp background", kind: KindBackground, data: readFixture(t, "lossy-64x48.webp"), wantType: ContentTypeJPEG, wantW: 64, wantH: 48},
		{
			name: "transparent background flattened on white", kind: KindBackground,
			data: encodePNG(t, image.NewNRGBA(image.Rect(0, 0, 16, 16))), wantType: ContentTypeJPEG, wantW: 16, wantH: 16,
			wantPixels: func(t *testing.T, img image.Image) {
				t.Helper()
				if r, g, b, _ := img.At(8, 8).RGBA(); r < 0xF000 || g < 0xF000 || b < 0xF000 {
					t.Errorf("pixel = %x %x %x, want white", r, g, b)
				}
			},
		},
		{name: "logo downscaled landscape", kind: KindLogo, data: encodePNG(t, gradient(1024, 512)), wantType: ContentTypePNG, wantW: 512, wantH: 256},
		{name: "logo downscaled portrait", kind: KindLogo, data: encodePNG(t, gradient(300, 900)), wantType: ContentTypePNG, wantW: 171, wantH: 512},
		{name: "logo at the target size is kept", kind: KindLogo, data: encodePNG(t, gradient(512, 512)), wantType: ContentTypePNG, wantW: 512, wantH: 512},
		{name: "background downscaled", kind: KindBackground, data: encodeJPEGT(t, gradient(4000, 1000)), wantType: ContentTypeJPEG, wantW: 3840, wantH: 960},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			img, err := Process(tc.kind, bytes.NewReader(tc.data), 0)
			if err != nil {
				t.Fatalf("Process: %v", err)
			}
			if img.ContentType != tc.wantType || img.Width != tc.wantW || img.Height != tc.wantH {
				t.Fatalf("got %s %dx%d, want %s %dx%d", img.ContentType, img.Width, img.Height, tc.wantType, tc.wantW, tc.wantH)
			}
			if img.ContentType != tc.kind.ContentType() {
				t.Errorf("content type %s, kind says %s", img.ContentType, tc.kind.ContentType())
			}
			dec := checkOutput(t, img)
			if tc.wantPixels != nil {
				tc.wantPixels(t, dec)
			}
		})
	}
}

func TestProcessStripsMetadata(t *testing.T) {
	const secret = "GPS 48.8566N 2.3522E camera-serial-123456"
	t.Run("jpeg exif", func(t *testing.T) {
		src := encodeJPEGT(t, gradient(32, 32))
		payload := append([]byte("Exif\x00\x00"), secret...)
		app1 := []byte{0xFF, 0xE1}
		app1 = binary.BigEndian.AppendUint16(app1, uint16(len(payload)+2))
		app1 = append(app1, payload...)
		in := append(append(append([]byte{}, src[:2]...), app1...), src[2:]...)
		for _, kind := range []Kind{KindLogo, KindBackground} {
			img, err := Process(kind, bytes.NewReader(in), 0)
			if err != nil {
				t.Fatalf("%s: %v", kind, err)
			}
			checkOutput(t, img)
			if bytes.Contains(img.Data, []byte("Exif")) || bytes.Contains(img.Data, []byte(secret)) {
				t.Errorf("%s: EXIF kept", kind)
			}
			if kind == KindBackground {
				assertNoAPPSegments(t, img.Data)
			}
		}
	})
	t.Run("png text chunk", func(t *testing.T) {
		src := encodePNG(t, gradient(32, 32))
		text := pngChunk("tEXt", append([]byte("Comment\x00"), secret...))
		in := append(append(append([]byte{}, src[:33]...), text...), src[33:]...) // after IHDR
		img, err := Process(KindLogo, bytes.NewReader(in), 0)
		if err != nil {
			t.Fatal(err)
		}
		checkOutput(t, img)
		if bytes.Contains(img.Data, []byte("tEXt")) || bytes.Contains(img.Data, []byte(secret)) {
			t.Error("text chunk kept")
		}
	})
}

// assertNoAPPSegments fails if the JPEG data holds an APPn or COM segment
// before the start of scan.
func assertNoAPPSegments(t *testing.T, data []byte) {
	t.Helper()
	i := 2
	for i+4 <= len(data) {
		marker := data[i+1]
		if marker == 0xDA { // start of scan
			return
		}
		if marker >= 0xE0 && marker <= 0xEF || marker == 0xFE {
			t.Fatalf("segment FF%02X present", marker)
		}
		i += 2 + int(binary.BigEndian.Uint16(data[i+2:]))
	}
	t.Fatal("no start of scan")
}

func TestProcessPolyglot(t *testing.T) {
	trailer := []byte("<html><script>alert(document.cookie)</script></html>")
	src := encodePNG(t, gradient(20, 20))
	in := append(append([]byte{}, src...), trailer...)
	for _, kind := range []Kind{KindLogo, KindBackground} {
		img, err := Process(kind, bytes.NewReader(in), 0)
		if err != nil {
			t.Fatalf("%s: a PNG with trailing HTML that decodes must be accepted: %v", kind, err)
		}
		checkOutput(t, img)
		if bytes.Contains(img.Data, []byte("<script")) || bytes.Contains(img.Data, []byte("html")) {
			t.Errorf("%s: trailer kept in output", kind)
		}
	}
	// HTML first, then a PNG: not an image.
	if _, err := Process(KindLogo, bytes.NewReader(append(append([]byte{}, trailer...), src...)), 0); !errors.Is(err, ErrUnsupportedFormat) {
		t.Errorf("HTML then PNG: err = %v", err)
	}
}

func TestProcessUnsupportedFormats(t *testing.T) {
	cases := map[string][]byte{
		"empty":             nil,
		"svg":               []byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`),
		"svg with bom":      []byte("\xEF\xBB\xBF<?xml version=\"1.0\"?><svg/>"),
		"gif":               []byte("GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"),
		"bmp":               append([]byte("BM"), make([]byte, 60)...),
		"tiff le":           append([]byte("II*\x00"), make([]byte, 60)...),
		"tiff be":           append([]byte("MM\x00*"), make([]byte, 60)...),
		"heic":              append([]byte("\x00\x00\x00\x18ftypheic"), make([]byte, 60)...),
		"riff not webp":     append([]byte("RIFF\x10\x00\x00\x00WAVEfmt "), make([]byte, 16)...),
		"short riff":        []byte("RIFF\x00\x00"),
		"html":              []byte("<!doctype html><p>hi</p>"),
		"pdf":               []byte("%PDF-1.7\n"),
		"partial png magic": pngMagic[:4],
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Process(KindLogo, bytes.NewReader(data), 0); !errors.Is(err, ErrUnsupportedFormat) {
				t.Errorf("err = %v, want ErrUnsupportedFormat", err)
			}
		})
	}
}

func TestProcessDimensionsCheckedBeforeDecode(t *testing.T) {
	// Every input below is a bare header: decoding it fully would fail with
	// ErrInvalid, so ErrTooLarge proves the dimensions were checked first.
	cases := []struct {
		name string
		kind Kind
		data []byte
		want error
	}{
		{"png bomb", KindBackground, pngHeader(100_000, 100_000), ErrTooLarge},
		{"png logo too wide", KindLogo, pngHeader(MaxLogoSide+1, 1), ErrTooLarge},
		{"png logo too high", KindLogo, pngHeader(1, MaxLogoSide+1), ErrTooLarge},
		{"png background too wide", KindBackground, pngHeader(MaxBackgroundSide+1, 10), ErrTooLarge},
		{"png background pixel cap", KindBackground, pngHeader(8000, 6000), ErrTooLarge},
		{"jpeg bomb", KindBackground, jpegHeader(65_000, 65_000), ErrTooLarge},
		{"jpeg logo too wide", KindLogo, jpegHeader(MaxLogoSide+1, 10), ErrTooLarge},
		{"webp bomb", KindBackground, webpHeader(30_000, 30_000), ErrTooLarge},
		{"webp logo too high", KindLogo, webpHeader(10, MaxLogoSide+1), ErrTooLarge},
		// Within limits: the header passes and the missing pixel data fails.
		{"png header within limits", KindLogo, pngHeader(MaxLogoSide, MaxLogoSide), ErrInvalid},
		{"png background at the pixel cap", KindBackground, pngHeader(7000, 5000), ErrInvalid},
		{"png background just over the pixel cap", KindBackground, pngHeader(7000, 5001), ErrTooLarge},
		{"jpeg header within limits", KindLogo, jpegHeader(100, 100), ErrInvalid},
		{"webp header within limits", KindLogo, webpHeader(100, 100), ErrInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Process(tc.kind, bytes.NewReader(tc.data), 0); !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestCheckDimensions(t *testing.T) {
	s, _ := KindLogo.spec()
	for _, d := range [][2]int{{0, 1}, {1, 0}, {-1, 5}} {
		if err := s.checkDimensions(d[0], d[1]); !errors.Is(err, ErrInvalid) {
			t.Errorf("%v: err = %v", d, err)
		}
	}
	if err := s.checkDimensions(MaxLogoSide, MaxLogoSide); err != nil {
		t.Errorf("max logo: %v", err)
	}
}

func TestProcessByteLimits(t *testing.T) {
	small := encodePNG(t, gradient(16, 16))
	t.Run("caller limit", func(t *testing.T) {
		if _, err := Process(KindLogo, bytes.NewReader(small), int64(len(small))-1); !errors.Is(err, ErrTooLarge) {
			t.Errorf("err = %v", err)
		}
		if _, err := Process(KindLogo, bytes.NewReader(small), int64(len(small))); err != nil {
			t.Errorf("exact limit: %v", err)
		}
	})
	for _, kind := range []Kind{KindLogo, KindBackground} {
		t.Run(kind.String()+" kind limit", func(t *testing.T) {
			over := append(append([]byte{}, small...), make([]byte, int(kind.MaxBytes())-len(small)+1)...)
			// A caller limit above the kind limit does not raise it.
			if _, err := Process(kind, bytes.NewReader(over), 1<<40); !errors.Is(err, ErrTooLarge) {
				t.Errorf("err = %v", err)
			}
			// Exactly at the limit: the trailing zeros are ignored by the decoder.
			if _, err := Process(kind, bytes.NewReader(over[:kind.MaxBytes()]), 0); err != nil {
				t.Errorf("at limit: %v", err)
			}
		})
	}
}

func TestProcessTruncated(t *testing.T) {
	inputs := map[string][]byte{
		"png":           encodePNG(t, gradient(64, 64)),
		"jpeg":          encodeJPEGT(t, gradient(64, 64)),
		"webp lossy":    readFixture(t, "lossy-64x48.webp"),
		"webp lossless": readFixture(t, "lossless-alpha-40x30.webp"),
	}
	for name, data := range inputs {
		for _, cut := range []int{len(data) / 2, len(data) - 10} {
			t.Run(name, func(t *testing.T) {
				if _, err := Process(KindLogo, bytes.NewReader(data[:cut]), 0); !errors.Is(err, ErrInvalid) {
					t.Errorf("cut at %d: err = %v, want ErrInvalid", cut, err)
				}
			})
		}
	}
	// Magic number only: the header cannot be read.
	if _, err := Process(KindLogo, bytes.NewReader(pngMagic), 0); !errors.Is(err, ErrInvalid) {
		t.Errorf("magic only: err = %v", err)
	}
}

func TestProcessErrors(t *testing.T) {
	if _, err := Process(Kind(0), strings.NewReader(""), 0); !errors.Is(err, ErrUnknownKind) {
		t.Errorf("unknown kind: err = %v", err)
	}
	readErr := errors.New("connection reset")
	_, err := Process(KindLogo, iotest.ErrReader(readErr), 0)
	if !errors.Is(err, readErr) {
		t.Errorf("read error: err = %v", err)
	}
	for _, sentinel := range []error{ErrTooLarge, ErrUnsupportedFormat, ErrInvalid, ErrUnknownKind} {
		if errors.Is(err, sentinel) {
			t.Errorf("read error matches %v", sentinel)
		}
	}
}

func TestKind(t *testing.T) {
	cases := []struct {
		kind     Kind
		name     string
		maxBytes int64
		ctype    string
	}{
		{KindLogo, "logo", 5 << 20, "image/png"},
		{KindBackground, "background", 10 << 20, "image/jpeg"},
		{Kind(99), "", 0, ""},
	}
	for _, tc := range cases {
		if tc.kind.String() != tc.name || tc.kind.MaxBytes() != tc.maxBytes || tc.kind.ContentType() != tc.ctype {
			t.Errorf("%d: %q %d %q", tc.kind, tc.kind.String(), tc.kind.MaxBytes(), tc.kind.ContentType())
		}
		if tc.name == "" {
			continue
		}
		if k, err := ParseKind(tc.name); err != nil || k != tc.kind {
			t.Errorf("ParseKind(%q) = %v, %v", tc.name, k, err)
		}
	}
	for _, s := range []string{"", "Logo", "favicon", "background "} {
		if _, err := ParseKind(s); !errors.Is(err, ErrUnknownKind) {
			t.Errorf("ParseKind(%q): err = %v", s, err)
		}
	}
}

func TestFit(t *testing.T) {
	cases := []struct{ w, h, target, wantW, wantH int }{
		{100, 50, 512, 100, 50},
		{512, 512, 512, 512, 512},
		{1024, 1024, 512, 512, 512},
		{1024, 512, 512, 512, 256},
		{300, 900, 512, 171, 512},
		{2048, 1, 512, 512, 1},
		{1, 2048, 512, 1, 512},
	}
	for _, tc := range cases {
		if w, h := fit(tc.w, tc.h, tc.target); w != tc.wantW || h != tc.wantH {
			t.Errorf("fit(%d, %d, %d) = %d, %d, want %d, %d", tc.w, tc.h, tc.target, w, h, tc.wantW, tc.wantH)
		}
	}
}

func TestDefaultBackground(t *testing.T) {
	a := DefaultBackground()
	if a.ContentType != ContentTypeJPEG || a.Width != 1920 || a.Height != 1080 {
		t.Fatalf("got %s %dx%d", a.ContentType, a.Width, a.Height)
	}
	checkOutput(t, a)
	// The caller owns its copy.
	a.Data[len(a.Data)-3] ^= 0xFF
	if b := DefaultBackground(); b.ETag != a.ETag || bytes.Equal(a.Data, b.Data) {
		t.Error("DefaultBackground shares its data")
	}
	// Deterministic: a fresh rendering gives the same bytes.
	if c := generateDefaultBackground(); c.ETag != a.ETag {
		t.Error("default background is not deterministic")
	}
}

// FuzzProcess checks that arbitrary input never panics and that any
// accepted image comes out as a valid PNG or JPEG within the limits.
func FuzzProcess(f *testing.F) {
	small := encodePNG(f, gradient(24, 16))
	f.Add(small)
	f.Add(encodeJPEGT(f, gradient(16, 24)))
	f.Add(readFixture(f, "lossy-64x48.webp"))
	f.Add(readFixture(f, "lossless-alpha-40x30.webp"))
	f.Add(append(append([]byte{}, small...), "<html><script>x</script>"...))
	f.Add(pngHeader(100_000, 100_000))
	f.Add(jpegHeader(300, 200))
	f.Add(webpHeader(300, 200))
	f.Add([]byte("<svg/>"))
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, kind := range []Kind{KindLogo, KindBackground} {
			img, err := Process(kind, bytes.NewReader(data), 0)
			if err != nil {
				if !errors.Is(err, ErrInvalid) && !errors.Is(err, ErrTooLarge) && !errors.Is(err, ErrUnsupportedFormat) {
					t.Fatalf("%s: unexpected error %v", kind, err)
				}
				continue
			}
			if img.ContentType != kind.ContentType() {
				t.Fatalf("%s: content type %s", kind, img.ContentType)
			}
			s, _ := kind.spec()
			if img.Width > s.targetSide || img.Height > s.targetSide {
				t.Fatalf("%s: %dx%d exceeds target", kind, img.Width, img.Height)
			}
			checkOutput(t, img)
		}
	})
}

func TestProcessMemoryBudget(t *testing.T) {
	// Every input is a bare header within the dimension limits: ErrTooLarge
	// comes from the memory estimate, ErrInvalid from the decoder.
	rgb := append([]byte{0xFF, 0xD8}, append(jpegSOF(BackgroundTargetSide, 2160, 0xC0, []byte("RGB")), jpegSOS...)...)
	cases := []struct {
		name string
		kind Kind
		data []byte
		want error
	}{
		{"png 8-bit rgba at the pixel cap", KindBackground, pngHeaderDepth(7000, 5000, 8, 6), ErrInvalid},
		{"png 8-bit gray at the pixel cap", KindBackground, pngHeaderDepth(7000, 5000, 8, 0), ErrInvalid},
		{"png 16-bit rgba over budget", KindBackground, pngHeaderDepth(5916, 5916, 16, 6), ErrTooLarge},
		{"png 16-bit rgba small enough", KindBackground, pngHeaderDepth(4000, 4000, 16, 6), ErrInvalid},
		// A tRNS chunk, unseen in the header, turns 16-bit gray into NRGBA64.
		{"png 16-bit gray counted as nrgba64", KindBackground, pngHeaderDepth(7000, 5000, 16, 0), ErrTooLarge},
		{"png 16-bit logo within budget", KindLogo, pngHeaderDepth(MaxLogoSide, MaxLogoSide, 16, 6), ErrInvalid},
		// Interlacing doubles the decoding memory.
		{"png interlaced over budget", KindBackground, pngHeaderInterlaced(7000, 5000, 8, 6), ErrTooLarge},
		{"png interlaced within budget", KindBackground, pngHeaderInterlaced(4000, 3000, 8, 6), ErrInvalid},
		{"png 16-bit interlaced logo within budget", KindLogo, pngHeaderInterlaced(MaxLogoSide, MaxLogoSide, 16, 6), ErrInvalid},
		{"jpeg gray within budget", KindBackground, jpegHeaderSOF(7000, 5000, 0xC0, 1), ErrInvalid},
		{"jpeg gray progressive within budget", KindBackground, jpegHeaderSOF(7000, 5000, 0xC2, 1), ErrInvalid},
		{"jpeg color at the stored size", KindBackground, jpegHeaderSOF(BackgroundTargetSide, 2160, 0xC0, 3), ErrInvalid},
		{"jpeg rgb at the stored size", KindBackground, rgb, ErrInvalid},
		// A baseline frame is budgeted like a progressive one.
		{"jpeg 12 Mpx photo within budget", KindBackground, jpegHeaderSOF(4000, 3000, 0xC2, 3), ErrInvalid},
		{"jpeg color baseline over budget", KindBackground, jpegHeaderSOF(5000, 3750, 0xC0, 3), ErrTooLarge},
		{"jpeg color progressive over budget", KindBackground, jpegHeaderSOF(5000, 3750, 0xC2, 3), ErrTooLarge},
		{"jpeg cmyk within budget", KindBackground, jpegHeaderSOF(3000, 3000, 0xC0, 4), ErrInvalid},
		{"jpeg cmyk over budget", KindBackground, jpegHeaderSOF(4000, 3200, 0xC0, 4), ErrTooLarge},
		{"jpeg cmyk logo within budget", KindLogo, jpegHeaderSOF(MaxLogoSide, MaxLogoSide, 0xC2, 4), ErrInvalid},
		{"webp within budget", KindBackground, webpHeader(2560, 1440), ErrInvalid},
		{"webp 4K over budget", KindBackground, webpHeader(BackgroundTargetSide, 2160), ErrTooLarge},
		{"webp over budget", KindBackground, webpHeader(5916, 5916), ErrTooLarge},
		{"webp logo within budget", KindLogo, webpHeader(MaxLogoSide, MaxLogoSide), ErrInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Process(tc.kind, bytes.NewReader(tc.data), 0); !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestProcessMarkerConfusion is the regression test of a JPEG whose markers
// a side parser walked differently from image/jpeg: the decoder skips FF00
// as filler, then the stray bytes up to the real progressive frame header,
// while a parser reading FF00 as a segment with a length landed on a fake
// baseline header hidden in a comment. Whatever the layout, the budget
// assumes a progressive frame.
func TestProcessMarkerConfusion(t *testing.T) {
	data := []byte{0xFF, 0xD8, 0xFF, 0x00, 0x00, 0x20}
	data = append(data, jpegSOF(6000, 5800, 0xC2, []byte{1, 2, 3})...)
	// The fake SOF0 sits where a parser jumping 0x20 bytes past FF00 lands.
	const fakeAt = 2 + 2 + 0x20
	payload := append(make([]byte, fakeAt-len(data)-4), jpegSOF(16, 16, 0xC0, []byte{1})...)
	data = append(data, 0xFF, 0xFE)
	data = binary.BigEndian.AppendUint16(data, uint16(len(payload)+2))
	data = append(data, payload...)
	data = append(data, jpegSOS...)
	if !bytes.Equal(data[fakeAt:fakeAt+2], []byte{0xFF, 0xC0}) {
		t.Fatalf("fake frame header misplaced: % x", data)
	}

	cfg, err := jpeg.DecodeConfig(bytes.NewReader(data))
	if err != nil || cfg.Width != 6000 || cfg.Height != 5800 || cfg.ColorModel != color.YCbCrModel {
		t.Fatalf("image/jpeg reads %dx%d %T, %v; want the real 6000x5800 frame", cfg.Width, cfg.Height, cfg.ColorModel, err)
	}
	// Refused before any decoding slot is taken: every slot is busy, so
	// waiting for one would fail with the deadline of ctx.
	fillDecodeSlots(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := ProcessContext(ctx, KindBackground, bytes.NewReader(data), 0); !errors.Is(err, ErrTooLarge) {
		t.Errorf("err = %v, want ErrTooLarge", err)
	}
}

func TestProcessStoredSizeJPEG(t *testing.T) {
	img, err := Process(KindBackground, bytes.NewReader(encodeJPEGT(t, gradient(BackgroundTargetSide, 2160))), 0)
	if err != nil {
		t.Fatalf("3840x2160 baseline JPEG: %v", err)
	}
	if img.Width != BackgroundTargetSide || img.Height != 2160 {
		t.Errorf("got %dx%d", img.Width, img.Height)
	}
}

func TestCheckMemory(t *testing.T) {
	s, _ := KindBackground.spec()
	cfg := func(m color.Model, w, h int) image.Config { return image.Config{ColorModel: m, Width: w, Height: h} }
	pngCheck := func(m color.Model, w, h int) error {
		return s.checkMemory(cfg(m, w, h), int64(w)*int64(h)*pngPerPixel(m))
	}
	jpg := func(m color.Model, w, h int) error {
		return s.checkMemory(cfg(m, w, h), jpegDecodeBytes(cfg(m, w, h), nil))
	}
	// 35 Mpx of 8-bit PNG plus the scaling and encoding buffers fit the
	// budget: the pixel cap never refuses what the budget would accept.
	for _, d := range [][2]int{{5916, 5916}, {MaxBackgroundSide, 4272}} {
		if err := pngCheck(color.RGBAModel, d[0], d[1]); err != nil {
			t.Errorf("%v 8-bit: %v", d, err)
		}
	}
	if err := pngCheck(color.NRGBA64Model, 5916, 5916); !errors.Is(err, ErrTooLarge) {
		t.Errorf("16-bit: err = %v", err)
	}
	// A 12 Mpx photo and the stored background size fit as color JPEGs,
	// whatever their frame.
	for _, d := range [][2]int{{4000, 3000}, {BackgroundTargetSide, 2160}} {
		if err := jpg(color.YCbCrModel, d[0], d[1]); err != nil {
			t.Errorf("%v JPEG: %v", d, err)
		}
	}
	if err := jpg(color.CMYKModel, 4000, 3200); !errors.Is(err, ErrTooLarge) {
		t.Errorf("CMYK: err = %v", err)
	}
	// Every logo fits, whatever its format, color model and layout.
	l, _ := KindLogo.spec()
	logo := cfg(color.NRGBA64Model, MaxLogoSide, MaxLogoSide)
	interlaced := pngHeaderInterlaced(MaxLogoSide, MaxLogoSide, 16, 6)
	for name, n := range map[string]int64{
		"png":  pngDecodeBytes(logo, interlaced),
		"jpeg": jpegDecodeBytes(cfg(color.CMYKModel, MaxLogoSide, MaxLogoSide), nil),
		"webp": webpDecodeBytes(logo, make([]byte, MaxLogoBytes)),
	} {
		if err := l.checkMemory(logo, n); err != nil {
			t.Errorf("logo %s: %v", name, err)
		}
	}
}

func TestMemoryNeed(t *testing.T) {
	l, _ := KindLogo.spec()
	b, _ := KindBackground.spec()
	cfg := func(w, h int) image.Config { return image.Config{Width: w, Height: h} }
	cases := []struct {
		name string
		spec kindSpec
		cfg  image.Config
		want int64
	}{
		// Kernel scaler resizing: its dstWidth x srcHeight buffer counts.
		{"logo resized", l, cfg(2048, 1024), 100 + 512*256*8 + 512*1024*32 + renderOverhead},
		{"logo kept", l, cfg(512, 300), 100 + 512*300*8 + renderOverhead},
		// The approximate bilinear scaler allocates no buffer.
		{"background resized", b, cfg(7680, 4320), 100 + 3840*2160*8 + renderOverhead},
	}
	for _, tc := range cases {
		if got := tc.spec.memoryNeed(tc.cfg, 100); got != tc.want {
			t.Errorf("%s: %d, want %d", tc.name, got, tc.want)
		}
	}
	// Changing the scaler of a kind changes its estimate accordingly.
	b.scaler = draw.CatmullRom
	if got, want := b.memoryNeed(cfg(7680, 4320), 0), int64(3840*2160*8+3840*4320*32)+renderOverhead; got != want {
		t.Errorf("background with a kernel: %d, want %d", got, want)
	}
}

func TestDecodeBytes(t *testing.T) {
	cfg := func(m color.Model, w, h int) image.Config { return image.Config{ColorModel: m, Width: w, Height: h} }
	gray := cfg(color.GrayModel, 100, 50)
	progressive := pngHeaderInterlaced(100, 50, 8, 0)
	cases := []struct {
		name string
		got  int64
		want int64
	}{
		{"png", pngDecodeBytes(gray, pngHeaderDepth(100, 50, 8, 0)), 100 * 50 * 4},
		{"png interlaced", pngDecodeBytes(gray, progressive), 2 * 100 * 50 * 4},
		{"jpeg rounded to whole MCUs", jpegDecodeBytes(cfg(color.CMYKModel, 100, 50), nil), 131 * 81 * 24},
		{"webp", webpDecodeBytes(gray, make([]byte, 1000)), 115*65*11 + webpReserve + 1000},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s: %d, want %d", tc.name, tc.got, tc.want)
		}
	}
}

// pngHeaderInterlaced is pngHeaderDepth declaring Adam7 interlacing.
func pngHeaderInterlaced(w, h uint32, depth, colorType byte) []byte {
	ihdr := binary.BigEndian.AppendUint32(nil, w)
	ihdr = binary.BigEndian.AppendUint32(ihdr, h)
	ihdr = append(ihdr, depth, colorType, 0, 0, 1)
	return append(append([]byte{}, pngMagic...), pngChunk("IHDR", ihdr)...)
}

func TestPNGInterlaced(t *testing.T) {
	plain := pngHeaderDepth(10, 10, 8, 0)
	adam7 := pngHeaderInterlaced(10, 10, 8, 0)
	// An unknown chunk before IHDR, which image/png skips.
	skipped := append(append(append([]byte{}, pngMagic...), pngChunk("zzZz", []byte("x"))...), plain[len(pngMagic):]...)
	badLength := append([]byte{}, plain...)
	binary.BigEndian.PutUint32(badLength[len(pngMagic):], 12)
	hugeChunk := append(append([]byte{}, pngMagic...), 0xFF, 0xFF, 0xFF, 0xF0, 'z', 'z', 'z', 'z')
	cases := []struct {
		name string
		data []byte
		want bool
	}{
		{"not interlaced", plain, false},
		{"interlaced", adam7, true},
		{"after an unknown chunk", skipped, false},
		{"truncated IHDR", plain[:len(plain)-6], true},
		{"bad IHDR length", badLength, true},
		{"no IHDR", pngMagic, true},
		{"chunk longer than the data", hugeChunk, true},
	}
	for _, tc := range cases {
		if got := pngInterlaced(tc.data); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
	// image/png reads the same IHDR after the unknown chunk.
	if _, err := png.DecodeConfig(bytes.NewReader(skipped)); err != nil {
		t.Errorf("image/png refuses the skipped chunk: %v", err)
	}
}

func TestPerPixel(t *testing.T) {
	cases := []struct {
		name     string
		perPixel func(color.Model) int64
		model    color.Model
		want     int64
	}{
		{"png palette", pngPerPixel, color.Palette{color.Black, color.White}, 1},
		// Gray may come with tRNS, decoded as NRGBA or NRGBA64.
		{"png gray", pngPerPixel, color.GrayModel, 4},
		{"png gray16", pngPerPixel, color.Gray16Model, 8},
		{"png rgba", pngPerPixel, color.RGBAModel, 4},
		{"png nrgba", pngPerPixel, color.NRGBAModel, 4},
		{"png rgba64", pngPerPixel, color.RGBA64Model, 8},
		{"png nrgba64", pngPerPixel, color.NRGBA64Model, 8},
		// Never declared by image/png: the largest pixel.
		{"png alpha", pngPerPixel, color.AlphaModel, 8},
		{"jpeg gray", jpegPerPixel, color.GrayModel, 5},
		{"jpeg ycbcr", jpegPerPixel, color.YCbCrModel, 19},
		{"jpeg rgb transform", jpegPerPixel, color.RGBAModel, 19},
		{"jpeg cmyk", jpegPerPixel, color.CMYKModel, 24},
	}
	for _, tc := range cases {
		if got := tc.perPixel(tc.model); got != tc.want {
			t.Errorf("%s: %d bytes per pixel, want %d", tc.name, got, tc.want)
		}
	}
}

// fillDecodeSlots takes every decoding slot and returns the function that
// frees them (also called at the end of the test).
func fillDecodeSlots(t *testing.T) func() {
	t.Helper()
	return fillSlots(t, decodeSlots, MaxConcurrentDecodes)
}

// fillSlots takes n tokens of slots and returns the function that frees
// them (also called at the end of the test).
func fillSlots(t *testing.T, slots chan struct{}, n int) func() {
	t.Helper()
	for range n {
		slots <- struct{}{}
	}
	var once sync.Once
	free := func() {
		once.Do(func() {
			for range n {
				<-slots
			}
		})
	}
	t.Cleanup(free)
	return free
}

func TestProcessContextWaitsForASlot(t *testing.T) {
	small := encodePNG(t, gradient(16, 16))
	free := fillDecodeSlots(t)

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ProcessContext(canceled, KindLogo, bytes.NewReader(small), 0); !errors.Is(err, context.Canceled) {
		t.Errorf("canceled: err = %v", err)
	}
	short, cancelShort := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancelShort()
	if _, err := ProcessContext(short, KindLogo, bytes.NewReader(small), 0); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("busy slots: err = %v", err)
	}
	// An image refused before decoding never waits for a decoding slot.
	long, cancelLong := context.WithTimeout(context.Background(), time.Second)
	defer cancelLong()
	if _, err := ProcessContext(long, KindBackground, bytes.NewReader(pngHeader(100_000, 100_000)), 0); !errors.Is(err, ErrTooLarge) {
		t.Errorf("oversized: err = %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := Process(KindLogo, bytes.NewReader(small), 0)
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("Process returned while every slot was taken: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	// The waiting upload holds its reading slot.
	if n := len(readSlots); n != 1 {
		t.Errorf("%d reading slots taken while waiting to decode, want 1", n)
	}
	free()
	if err := <-done; err != nil {
		t.Fatalf("after freeing the slots: %v", err)
	}
	if n := len(decodeSlots) + len(readSlots); n != 0 {
		t.Errorf("%d slots still taken", n)
	}
}

// countingReader counts the calls to Read of the wrapped reader.
type countingReader struct {
	r     io.Reader
	reads *atomic.Int32
}

func (c countingReader) Read(p []byte) (int, error) {
	c.reads.Add(1)
	return c.r.Read(p)
}

func TestProcessContextWaitsForAReadingSlot(t *testing.T) {
	small := encodePNG(t, gradient(16, 16))
	var reads atomic.Int32
	body := func() io.Reader { return countingReader{bytes.NewReader(small), &reads} }

	free := fillSlots(t, readSlots, MaxConcurrentReads)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ProcessContext(canceled, KindLogo, body(), 0); !errors.Is(err, context.Canceled) {
		t.Errorf("canceled: err = %v", err)
	}
	short, cancelShort := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancelShort()
	if _, err := ProcessContext(short, KindLogo, body(), 0); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("busy slots: err = %v", err)
	}
	if n := reads.Load(); n != 0 {
		t.Errorf("body read %d times without a reading slot", n)
	}
	free()

	// With every decoding slot taken, MaxConcurrentReads uploads read their
	// body and wait to decode; one more does not even read its body.
	freeDecode := fillSlots(t, decodeSlots, MaxConcurrentDecodes)
	var wg sync.WaitGroup
	errs := make(chan error, MaxConcurrentReads+1)
	readers := make([]atomic.Int32, MaxConcurrentReads+1)
	for i := range readers {
		wg.Go(func() {
			_, err := Process(KindLogo, countingReader{bytes.NewReader(small), &readers[i]}, 0)
			errs <- err
		})
	}
	started := func() int {
		n := 0
		for i := range readers {
			if readers[i].Load() > 0 {
				n++
			}
		}
		return n
	}
	for deadline := time.Now().Add(5 * time.Second); started() < MaxConcurrentReads && time.Now().Before(deadline); {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	if started := started(); started != MaxConcurrentReads {
		t.Errorf("%d bodies read while decoding is blocked, want %d", started, MaxConcurrentReads)
	}
	freeDecode()
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
	if n := len(decodeSlots) + len(readSlots); n != 0 {
		t.Errorf("%d slots still taken", n)
	}
}

func TestProcessConcurrentUploads(t *testing.T) {
	small := encodePNG(t, gradient(64, 64))
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Go(func() {
			_, err := Process(KindLogo, bytes.NewReader(small), 0)
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
	if n := len(decodeSlots) + len(readSlots); n != 0 {
		t.Errorf("%d slots still taken", n)
	}
}
