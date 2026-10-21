package notify

import (
	"bytes"
	"errors"
	"image"
	"image/color"
	"image/png"
	"strings"
	"testing"

	"github.com/makiuchi-d/gozxing"
	gozxingqr "github.com/makiuchi-d/gozxing/qrcode"
	"rsc.io/qr"
)

const testLink = "https://transfer.entity-a.example.com/d/dl_01HZY3K5V7W9XBCDFGHJKMNPQR"

// decodeQR decodes the QR code of a PNG with a test-only decoder.
func decodeQR(t *testing.T, img image.Image) string {
	t.Helper()
	bmp, err := gozxing.NewBinaryBitmapFromImage(img)
	if err != nil {
		t.Fatal(err)
	}
	res, err := gozxingqr.NewQRCodeReader().Decode(bmp, nil)
	if err != nil {
		t.Fatalf("decode QR: %v", err)
	}
	return res.GetText()
}

func TestQRPNG(t *testing.T) {
	for _, link := range []string{testLink, "http://a.localhost/d/x", testLink + "?" + strings.Repeat("q", 300)} {
		data, err := QRPNG(link)
		if err != nil {
			t.Fatal(err)
		}
		if len(data) > 16<<10 {
			t.Errorf("PNG of %d bytes", len(data))
		}
		cfg, err := png.DecodeConfig(bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		img, err := png.Decode(bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		code, err := qr.Encode(link, qr.M)
		if err != nil {
			t.Fatal(err)
		}
		side := (code.Size + 2*QRQuietZone) * QRModulePixels
		if cfg.Width != side || cfg.Height != side {
			t.Errorf("image %dx%d, want %dx%d", cfg.Width, cfg.Height, side, side)
		}
		// Every pixel matches its module, and the quiet zone is white.
		for y := range side {
			for x := range side {
				mx, my := x/QRModulePixels-QRQuietZone, y/QRModulePixels-QRQuietZone
				want := code.Black(mx, my) // false outside the code: quiet zone
				r, _, _, _ := img.At(x, y).RGBA()
				if got := r == 0; got != want {
					t.Fatalf("pixel (%d,%d) black=%v, want %v", x, y, got, want)
				}
			}
		}
		if got := decodeQR(t, img); got != link {
			t.Errorf("decoded %q, want %q", got, link)
		}
	}
}

func TestQRPNGSmallAndOneBit(t *testing.T) {
	data, err := QRPNG(testLink)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) > 2<<10 {
		t.Errorf("PNG of %d bytes, want under 2 KiB", len(data))
	}
	img, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	p, ok := img.(*image.Paletted)
	if !ok || len(p.Palette) != 2 {
		t.Fatalf("not a 2-color image: %T", img)
	}
	white, _, _, _ := p.Palette[0].RGBA()
	black, _, _, _ := p.Palette[1].RGBA()
	if white != 0xffff || black != 0 || color.GrayModel.Convert(p.Palette[0]) != (color.Gray{Y: 0xff}) {
		t.Errorf("palette %v", p.Palette)
	}
	if bytes.Contains(data, []byte("tEXt")) || bytes.Contains(data, []byte("http")) {
		t.Error("PNG carries metadata")
	}
}

func TestQRPNGErrors(t *testing.T) {
	for _, s := range []string{"", strings.Repeat("a", maxQRText+1)} {
		if _, err := QRPNG(s); !errors.Is(err, ErrQRText) {
			t.Errorf("len %d: %v", len(s), err)
		}
	}
	boom := errors.New("boom")

	origQR := qrEncode
	qrEncode = func(string, qr.Level) (*qr.Code, error) { return nil, boom }
	_, err := QRPNG(testLink)
	qrEncode = origQR
	if !errors.Is(err, boom) {
		t.Errorf("encode error: %v", err)
	}

	origPNG := pngEncode
	pngEncode = func(*bytes.Buffer, image.Image) error { return boom }
	_, err = QRPNG(testLink)
	pngEncode = origPNG
	if !errors.Is(err, boom) {
		t.Errorf("png error: %v", err)
	}
}
