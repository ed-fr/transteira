package notify

import (
	"bytes"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/png"

	"rsc.io/qr"
)

// QR code rendering parameters.
const (
	// QRModulePixels is the side of one QR module, in pixels.
	QRModulePixels = 4
	// QRQuietZone is the width of the white border, in modules: 4, the
	// minimum of ISO/IEC 18004.
	QRQuietZone = 4
	// maxQRText bounds the encoded text. A download link is far shorter;
	// the bound keeps the image small (a version 15 code at most, 77
	// modules: 340 x 340 pixels with the quiet zone, a few kilobytes).
	maxQRText = 400
)

// ErrQRText is returned by [QRPNG] for an empty text or one above the size limit.
var ErrQRText = errors.New("notify: QR code text empty or too long")

// qrPalette is the 1-bit palette of the QR image: index 0 white, 1 black.
var qrPalette = color.Palette{color.Gray{Y: 0xff}, color.Gray{Y: 0x00}}

// Encoders, replaced by the tests to reach their error paths, which real
// inputs cannot trigger (the text is bounded, the PNG goes to memory).
var (
	qrEncode  = qr.Encode
	pngEncode = func(buf *bytes.Buffer, img image.Image) error {
		enc := png.Encoder{CompressionLevel: png.BestCompression}
		return enc.Encode(buf, img)
	}
)

// QRPNG returns the QR code of url as a PNG image, generated locally (the
// mail embeds it as an inline part, never as a remote image: threat T-87).
//
// The code uses error correction level M (about 15 % of the modules can be
// damaged), modules of [QRModulePixels] pixels and a quiet zone of
// [QRQuietZone] modules. The image is a 1-bit paletted PNG, black on white,
// without any metadata; for a link of the usual length it weighs well under
// 2 KiB, far below the 1 MiB limit of inline parts.
func QRPNG(url string) ([]byte, error) {
	if url == "" || len(url) > maxQRText {
		return nil, ErrQRText
	}
	code, err := qrEncode(url, qr.M)
	if err != nil {
		return nil, fmt.Errorf("notify: qr encode: %w", err)
	}
	side := (code.Size + 2*QRQuietZone) * QRModulePixels
	img := image.NewPaletted(image.Rect(0, 0, side, side), qrPalette)
	for y := range code.Size {
		for x := range code.Size {
			if !code.Black(x, y) {
				continue
			}
			x0, y0 := (x+QRQuietZone)*QRModulePixels, (y+QRQuietZone)*QRModulePixels
			for dy := range QRModulePixels {
				row := img.Pix[(y0+dy)*img.Stride:]
				for dx := range QRModulePixels {
					row[x0+dx] = 1
				}
			}
		}
	}
	var buf bytes.Buffer
	if err := pngEncode(&buf, img); err != nil {
		return nil, fmt.Errorf("notify: qr png: %w", err)
	}
	return buf.Bytes(), nil
}
