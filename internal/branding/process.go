package branding

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"io"

	"golang.org/x/image/draw"
	"golang.org/x/image/webp"
)

// codec decodes one accepted input format. The decoders are called directly,
// never through the image package registry, so that no other registered
// format (GIF, for instance) can slip through.
type codec struct {
	decodeConfig func(io.Reader) (image.Config, error)
	decode       func(io.Reader) (image.Image, error)
	// decodeBytes returns the worst-case memory that decoding data, whose
	// header declares cfg, may allocate (see [pngDecodeBytes],
	// [jpegDecodeBytes] and [webpDecodeBytes]).
	decodeBytes func(cfg image.Config, data []byte) int64
}

// Magic numbers of the accepted formats.
var (
	pngMagic  = []byte("\x89PNG\r\n\x1a\n")
	jpegMagic = []byte{0xFF, 0xD8, 0xFF}
)

// detect identifies the format from the first bytes of data, ignoring any
// declared content type or file name.
func detect(data []byte) (codec, bool) {
	switch {
	case bytes.HasPrefix(data, pngMagic):
		return codec{png.DecodeConfig, png.Decode, pngDecodeBytes}, true
	case bytes.HasPrefix(data, jpegMagic):
		return codec{jpeg.DecodeConfig, jpeg.Decode, jpegDecodeBytes}, true
	case len(data) >= 12 && string(data[0:4]) == "RIFF" && string(data[8:12]) == "WEBP":
		return codec{webp.DecodeConfig, webp.Decode, webpDecodeBytes}, true
	default:
		return codec{}, false
	}
}

// Process is [ProcessContext] without cancellation: it waits for a reading
// and a decoding slot as long as needed.
func Process(kind Kind, r io.Reader, maxBytes int64) (Image, error) {
	return ProcessContext(context.Background(), kind, r, maxBytes)
}

// ProcessContext validates an uploaded branding image of the given kind and
// returns it re-encoded (see the package documentation).
//
// At most maxBytes bytes are accepted; a value of 0 or above the limit of the
// kind ([MaxLogoBytes], [MaxBackgroundBytes]) is replaced by that limit. The
// body is read only once one of the [MaxConcurrentReads] process-wide
// reading slots is free, and that slot is held until the image is processed
// or refused. The declared dimensions are checked before the image is
// decoded: a logo may not exceed [MaxLogoSide] on either side, a background
// [MaxBackgroundSide] or [MaxBackgroundPixels]; and the memory needed to
// decode, scale and re-encode it, estimated from those dimensions for the
// worst case of the format and declared color model, may not exceed
// [MaxDecodeBytes]. Decoding then waits for one of the
// [MaxConcurrentDecodes] process-wide slots. Waiting for either slot gives
// up with the error of ctx when it is done first. The result is downscaled
// to [LogoTargetSide] or [BackgroundTargetSide] on its longest side when
// larger. A transparent background is flattened on white.
//
// Errors wrap [ErrUnsupportedFormat], [ErrTooLarge], [ErrInvalid],
// [ErrUnknownKind] or the error of ctx; any other error comes from reading r.
func ProcessContext(ctx context.Context, kind Kind, r io.Reader, maxBytes int64) (Image, error) {
	spec, ok := kind.spec()
	if !ok {
		return Image{}, ErrUnknownKind
	}
	limit := spec.maxBytes
	if maxBytes > 0 && maxBytes < limit {
		limit = maxBytes
	}
	releaseRead, err := acquireSlot(ctx, readSlots)
	if err != nil {
		return Image{}, fmt.Errorf("branding: wait for a reading slot: %w", err)
	}
	defer releaseRead()
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return Image{}, fmt.Errorf("branding: read %s: %w", spec.name, err)
	}
	if int64(len(data)) > limit {
		return Image{}, fmt.Errorf("%w: %s exceeds %d bytes", ErrTooLarge, spec.name, limit)
	}
	return spec.process(ctx, data)
}

// process validates, decodes and re-encodes the complete upload data.
func (s kindSpec) process(ctx context.Context, data []byte) (Image, error) {
	c, ok := detect(data)
	if !ok {
		return Image{}, ErrUnsupportedFormat
	}
	cfg, err := c.decodeConfig(bytes.NewReader(data))
	if err != nil {
		return Image{}, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if err := s.checkDimensions(cfg.Width, cfg.Height); err != nil {
		return Image{}, err
	}
	if err := s.checkMemory(cfg, c.decodeBytes(cfg, data)); err != nil {
		return Image{}, err
	}
	release, err := acquireSlot(ctx, decodeSlots)
	if err != nil {
		return Image{}, fmt.Errorf("branding: wait for a decoding slot: %w", err)
	}
	defer release()
	src, err := c.decode(bytes.NewReader(data))
	if err != nil {
		return Image{}, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	return s.render(src), nil
}

// readSlots holds one token per upload body being read or processed in the
// process, so that at most [MaxConcurrentReads] bodies are buffered at once.
var readSlots = make(chan struct{}, MaxConcurrentReads)

// decodeSlots holds one token per image being decoded in the process.
var decodeSlots = make(chan struct{}, MaxConcurrentDecodes)

// acquireSlot waits for a free token of slots and returns the function that
// frees it, or the error of ctx if it is done first (checked before
// waiting, so that a canceled request never takes a slot).
func acquireSlot(ctx context.Context, slots chan struct{}) (release func(), err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case slots <- struct{}{}:
		return func() { <-slots }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// checkDimensions enforces the limits of the kind on declared dimensions.
func (s kindSpec) checkDimensions(width, height int) error {
	if width < 1 || height < 1 {
		return fmt.Errorf("%w: dimensions %dx%d", ErrInvalid, width, height)
	}
	if width > s.maxSide || height > s.maxSide || int64(width)*int64(height) > s.maxPixels {
		return fmt.Errorf("%w: %s of %dx%d pixels exceeds %dx%d or %d pixels",
			ErrTooLarge, s.name, width, height, s.maxSide, s.maxSide, s.maxPixels)
	}
	return nil
}

// Fixed parts of the memory estimate of [kindSpec.memoryNeed].
const (
	// renderOverhead covers the allocations that do not grow with the
	// image: decoder state and tables (inflate window, Huffman tables), the
	// kernel weights of the scaler and the state of the encoders (the
	// deflate compressor of the PNG encoder alone takes about 1.2 MB).
	renderOverhead int64 = 4 << 20
	// encodedPerPixel bounds the bytes allocated per output pixel for the
	// re-encoded image, including the growth of its buffer: random noise,
	// the least compressible content, measures about 2 for a JPEG
	// background at quality 85 and 1.2 for a 512 x 512 PNG logo beyond
	// the compressor itself.
	encodedPerPixel int64 = 4
	// kernelTmpPerPixel is the size of one entry of the temporary buffer
	// that a [draw.Kernel] scaler allocates, a [4]float64 per pixel of a
	// dstWidth x srcHeight image.
	kernelTmpPerPixel int64 = 32
)

// checkMemory refuses an image whose processing would need more than
// [MaxDecodeBytes] (see [kindSpec.memoryNeed]). It is called after
// checkDimensions, so the products cannot overflow.
func (s kindSpec) checkMemory(cfg image.Config, decodeBytes int64) error {
	if need := s.memoryNeed(cfg, decodeBytes); need > MaxDecodeBytes {
		return fmt.Errorf("%w: %s of %dx%d pixels needs %d bytes to process, above %d",
			ErrTooLarge, s.name, cfg.Width, cfg.Height, need, MaxDecodeBytes)
	}
	return nil
}

// memoryNeed returns the worst-case memory that processing an image of
// configuration cfg allocates: decodeBytes for the decoding, the 4-byte
// per pixel image it is scaled into, the temporary buffer of the scaler
// when it is a [draw.Kernel] and the image is resized, the re-encoded
// output ([encodedPerPixel]) and [renderOverhead].
func (s kindSpec) memoryNeed(cfg image.Config, decodeBytes int64) int64 {
	w, h := fit(cfg.Width, cfg.Height, s.targetSide)
	out := int64(w) * int64(h)
	need := decodeBytes + out*4 + out*encodedPerPixel + renderOverhead
	if _, ok := s.scaler.(*draw.Kernel); ok && (w != cfg.Width || h != cfg.Height) {
		need += int64(w) * int64(cfg.Height) * kernelTmpPerPixel
	}
	return need
}

// pngDecodeBytes returns the worst-case memory of decoding a PNG: the
// decoded image, the only allocation proportional to it (see
// [pngPerPixel]), counted twice when the image is interlaced, since the
// decoder then allocates the full image plus one image per Adam7 pass,
// whose sizes add up to the full one.
func pngDecodeBytes(cfg image.Config, data []byte) int64 {
	n := int64(cfg.Width) * int64(cfg.Height) * pngPerPixel(cfg.ColorModel)
	if pngInterlaced(data) {
		n *= 2
	}
	return n
}

// pngPerPixel returns the size of one pixel of the image the PNG decoder
// returns for a header declaring model m. The header is read without the
// tRNS chunk, which turns a gray image (declared Gray or Gray16) into an
// NRGBA or NRGBA64 one; a paletted image stays paletted. Any model the
// decoder never declares counts as the largest pixel, 8 bytes.
func pngPerPixel(m color.Model) int64 {
	if _, ok := m.(color.Palette); ok {
		return 1
	}
	switch m {
	case color.GrayModel, color.RGBAModel, color.NRGBAModel:
		return 4
	default: // Gray16, RGBA64, NRGBA64
		return 8
	}
}

// pngInterlaced reports whether the IHDR chunk of a PNG declares Adam7
// interlacing. It walks the chunks from the signature like image/png, which
// skips unknown chunks found before IHDR, and answers true, the worst case,
// for data whose IHDR cannot be found or is malformed (impossible once
// png.DecodeConfig has accepted data).
func pngInterlaced(data []byte) bool {
	off := len(pngMagic)
	for off+8 <= len(data) {
		length := int(binary.BigEndian.Uint32(data[off:]))
		if string(data[off+4:off+8]) == "IHDR" {
			return length != 13 || len(data) < off+8+13 || data[off+8+12] != 0
		}
		if length < 0 || length > len(data) {
			break
		}
		off += 12 + length
	}
	return true
}

// jpegDecodeBytes returns the worst-case memory of decoding a JPEG: its
// buffers are sized on dimensions rounded up to whole MCUs (up to 32
// pixels, 31 more than declared, on each side), at [jpegPerPixel] bytes
// per pixel.
func jpegDecodeBytes(cfg image.Config, _ []byte) int64 {
	return int64(cfg.Width+31) * int64(cfg.Height+31) * jpegPerPixel(cfg.ColorModel)
}

// jpegPerPixel returns the worst-case memory per pixel of decoding a JPEG
// declared in model m. Whether the frame is progressive is not trusted from
// the bytes (the markers can be laid out so that a side parser and the
// decoder disagree), so the coefficient buffers of a progressive JPEG, one
// 64 x int32 block per 8x8 block of each component (4 bytes per pixel per
// component), are always counted. On top of them comes the decoded image:
// 1 byte for gray; 7 for three components (planes without chroma
// subsampling, plus the RGBA image of the RGB-transform path); 8 for CMYK
// (the YCbCr planes, the black plane and the CMYK output).
func jpegPerPixel(m color.Model) int64 {
	switch m {
	case color.GrayModel:
		return 1 + 4*1
	case color.CMYKModel:
		return 8 + 4*4
	default: // YCbCr, or RGBA for an RGB-transform JPEG
		return 7 + 4*3
	}
}

// webpDecodeBytes returns the worst-case memory of decoding a WebP,
// whatever its declared model (the VP8X header may announce a lossy YCbCr
// image while the payload is lossless): [webpPerPixel] bytes per pixel, on
// dimensions rounded up to whole 16-pixel macroblocks; [webpReserve] for
// the Huffman trees of a lossless bit stream; and the size of data, which
// the lossy decoder copies.
func webpDecodeBytes(cfg image.Config, data []byte) int64 {
	return int64(cfg.Width+15)*int64(cfg.Height+15)*webpPerPixel + webpReserve + int64(len(data))
}

// Worst case of the WebP decoder (golang.org/x/image/vp8 and vp8l).
const (
	// webpPerPixel is the worst-case memory per pixel of decoding a WebP:
	// a lossy image with a lossless alpha plane allocates its 4:2:0 YCbCr
	// planes (1.5 bytes), the alpha plane decoded as an NRGBA image
	// (4 bytes) then expanded by a color-indexing transform into another
	// one (4 bytes), the predictor and cross-color sub-images (0.25 byte
	// each at most) and the extracted alpha plane (1 byte). A lossless
	// image needs at most 8.5 bytes.
	webpPerPixel int64 = 11
	// webpReserve bounds the Huffman trees of one lossless bit stream, which
	// do not grow with the image: up to 2600 groups of 5 trees (the decoder
	// refuses more), each group allocating up to 82 KB with an 11-bit color
	// cache (tree nodes, plus code lengths and codes discarded once the tree
	// is built), 203 MiB in all.
	webpReserve int64 = 208 << 20
)

// render downscales src if needed and encodes it in the output format.
func (s kindSpec) render(src image.Image) Image {
	b := src.Bounds()
	w, h := fit(b.Dx(), b.Dy(), s.targetSide)
	rect := image.Rect(0, 0, w, h)
	var buf bytes.Buffer
	if s.contentType == ContentTypePNG {
		dst := image.NewNRGBA(rect)
		scale(s.scaler, dst, src, draw.Src)
		// Encoding into a bytes.Buffer cannot fail for bounded dimensions.
		_ = (&png.Encoder{CompressionLevel: png.BestCompression}).Encode(&buf, dst)
	} else {
		dst := image.NewRGBA(rect)
		draw.Draw(dst, rect, image.White, image.Point{}, draw.Src)
		scale(s.scaler, dst, src, draw.Over)
		encodeJPEG(&buf, dst)
	}
	return newImage(buf.Bytes(), s.contentType, w, h)
}

// encodeJPEG encodes img at [BackgroundJPEGQuality]. Encoding into a
// bytes.Buffer cannot fail for bounded dimensions.
func encodeJPEG(buf *bytes.Buffer, img image.Image) {
	_ = jpeg.Encode(buf, img, &jpeg.Options{Quality: BackgroundJPEGQuality})
}

// scale draws src onto the whole of dst, resampling with scaler when the
// sizes differ.
func scale(scaler draw.Scaler, dst draw.Image, src image.Image, op draw.Op) {
	if dst.Bounds().Size() == src.Bounds().Size() {
		draw.Draw(dst, dst.Bounds(), src, src.Bounds().Min, op)
		return
	}
	scaler.Scale(dst, dst.Bounds(), toFastSource(src), src.Bounds(), op, nil)
}

// rgba64Source hides the concrete type of an image from the scalers, so
// that they read it through RGBA64At.
type rgba64Source struct{ image.RGBA64Image }

// toFastSource returns src, or src wrapped in an [rgba64Source] when it is
// a YCbCr image with a chroma subsampling the scalers have no fast path for
// (4:1:1, 4:1:0 from a JPEG): they would otherwise read it through At,
// which allocates for every pixel read.
func toFastSource(src image.Image) image.Image {
	if y, ok := src.(*image.YCbCr); ok {
		switch y.SubsampleRatio {
		case image.YCbCrSubsampleRatio444, image.YCbCrSubsampleRatio422,
			image.YCbCrSubsampleRatio420, image.YCbCrSubsampleRatio440:
		default:
			return rgba64Source{y}
		}
	}
	return src
}

// fit returns the dimensions of a width x height image whose longest side is
// at most target, keeping the aspect ratio (rounded, at least 1 pixel).
func fit(width, height, target int) (w, h int) {
	switch {
	case width <= target && height <= target:
		return width, height
	case width >= height:
		return target, max(1, (height*target+width/2)/width)
	default:
		return max(1, (width*target+height/2)/height), target
	}
}
