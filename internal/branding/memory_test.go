package branding

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/binary"
	"image"
	"image/color"
	"image/jpeg"
	"runtime"
	"testing"
)

// The tests of this file make the memory bound of checkMemory real: they
// build worst-case images that the estimate accepts close to the budget,
// process them, and compare the bytes actually allocated
// (runtime.MemStats.TotalAlloc, every allocation counted, even short-lived
// ones) with the estimate and with MaxDecodeBytes. They run serially (no
// test of the package is parallel), so that no other goroutine allocates
// during a measurement.

// allocated returns the bytes f allocates, after a garbage collection.
func allocated(f func()) uint64 {
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// worstCase is an input built to allocate as much as its format allows for
// its dimensions.
type worstCase struct {
	name string
	kind Kind
	data func(t testing.TB) []byte
	// heavy inputs are skipped under -short (they still run in make check).
	heavy bool
}

func TestProcessMemoryMeasured(t *testing.T) {
	cases := []worstCase{
		{
			// 8-bit gray declared, decoded as NRGBA because of tRNS; at the
			// pixel cap with the widest background.
			name: "png gray tRNS background 8192 wide", kind: KindBackground, heavy: true,
			data: func(t testing.TB) []byte {
				w := MaxBackgroundSide
				h := maxAcceptedHeight(t, KindBackground, w, func(h int) int64 {
					return int64(w) * int64(h) * 4
				})
				return pngFile(t, w, h, 8, 0, false, []byte{0, 0})
			},
		},
		{
			name: "png gray16 tRNS interlaced background 8192 wide", kind: KindBackground, heavy: true,
			data: func(t testing.TB) []byte {
				w := MaxBackgroundSide
				h := maxAcceptedHeight(t, KindBackground, w, func(h int) int64 {
					return int64(w) * int64(h) * 8 * 2
				})
				return pngFile(t, w, h, 16, 0, true, []byte{0, 0})
			},
		},
		{
			name: "png gray16 tRNS interlaced logo", kind: KindLogo,
			data: func(t testing.TB) []byte {
				return pngFile(t, MaxLogoSide, MaxLogoSide, 16, 0, true, []byte{0, 0})
			},
		},
		{
			name: "jpeg color baseline background 4:3", kind: KindBackground, heavy: true,
			data: func(t testing.TB) []byte {
				w, h := maxAcceptedJPEG(t, 3)
				return jpegBaseline(t, w, h)
			},
		},
		{
			name: "jpeg color progressive background 4:3", kind: KindBackground, heavy: true,
			data: func(t testing.TB) []byte {
				w, h := maxAcceptedJPEG(t, 3)
				return jpegProgressive(t, w, h, "\x01\x02\x03")
			},
		},
		{
			// Components named R, G and B: decoded into an extra RGBA image.
			name: "jpeg rgb progressive background 4:3", kind: KindBackground, heavy: true,
			data: func(t testing.TB) []byte {
				w, h := maxAcceptedJPEG(t, 3)
				return jpegProgressive(t, w, h, "RGB")
			},
		},
		{
			name: "jpeg cmyk progressive background 4:3", kind: KindBackground, heavy: true,
			data: func(t testing.TB) []byte {
				w, h := maxAcceptedJPEG(t, 4)
				return jpegProgressive(t, w, h, "\x01\x02\x03\x04")
			},
		},
		{
			// 4:1:1 chroma subsampling, which the scalers read through
			// RGBA64At (see toFastSource) instead of the allocating At.
			name: "jpeg 4:1:1 background 3840 wide", kind: KindBackground, heavy: true,
			data: func(t testing.TB) []byte { return jpeg411(t, 3840, 2160) },
		},
		{
			name: "jpeg 4:1:1 logo", kind: KindLogo,
			data: func(t testing.TB) []byte { return jpeg411(t, MaxLogoSide, MaxLogoSide) },
		},
		{
			name: "jpeg cmyk progressive logo", kind: KindLogo,
			data: func(t testing.TB) []byte { return jpegProgressive(t, MaxLogoSide, MaxLogoSide, "\x01\x02\x03\x04") },
		},
		{
			name: "webp lossless background 4:3", kind: KindBackground, heavy: true,
			data: func(t testing.TB) []byte {
				w, h := maxAcceptedWebP(t)
				return webpLossless(w, h)
			},
		},
		{
			name: "webp lossy with lossless alpha background 4:3", kind: KindBackground, heavy: true,
			data: func(t testing.TB) []byte {
				w, h := maxAcceptedWebP(t)
				return webpLossyAlpha(w, h)
			},
		},
		{
			// Small enough for the Huffman trees to be nearly all of the
			// memory: checks webpReserve on its own.
			name: "webp lossless small logo", kind: KindLogo,
			data: func(testing.TB) []byte { return webpLossless(256, 256) },
		},
		{
			name: "webp lossy with lossless alpha small logo", kind: KindLogo,
			data: func(testing.TB) []byte { return webpLossyAlpha(256, 256) },
		},
		{
			name: "webp lossless logo", kind: KindLogo,
			data: func(testing.TB) []byte { return webpLossless(MaxLogoSide, MaxLogoSide) },
		},
		{
			name: "webp lossy with lossless alpha logo", kind: KindLogo,
			data: func(testing.TB) []byte { return webpLossyAlpha(MaxLogoSide, MaxLogoSide) },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.heavy && testing.Short() {
				t.Skip("heavy memory measurement skipped under -short")
			}
			measureWorstCase(t, tc.kind, tc.data(t))
		})
	}
}

// measureWorstCase processes data, which the estimate must accept, and
// checks that the bytes allocated stay within the estimate (validation,
// decoding, scaling and encoding) and within MaxDecodeBytes plus the
// reading of the body (io.ReadAll allocates its intermediate chunks and the
// final copy, about twice the body size).
func measureWorstCase(t *testing.T, kind Kind, data []byte) {
	t.Helper()
	s, _ := kind.spec()
	c, ok := detect(data)
	if !ok {
		t.Fatal("format not detected")
	}
	cfg, err := c.decodeConfig(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	estimate := s.memoryNeed(cfg, c.decodeBytes(cfg, data))
	if estimate > MaxDecodeBytes {
		t.Fatalf("%dx%d: estimate %d above the budget, the input must be accepted", cfg.Width, cfg.Height, estimate)
	}

	var perr error
	phase := allocated(func() { _, perr = s.process(context.Background(), data) })
	if perr != nil {
		t.Fatalf("process: %v", perr)
	}
	total := allocated(func() { _, perr = ProcessContext(context.Background(), kind, bytes.NewReader(data), 0) })
	if perr != nil {
		t.Fatalf("ProcessContext: %v", perr)
	}
	t.Logf("%dx%d, %d input bytes: estimate %.1f MiB, allocated %.1f MiB (%.0f%% of the estimate), with reading %.1f MiB",
		cfg.Width, cfg.Height, len(data), mib(estimate), mib(int64(phase)),
		100*float64(phase)/float64(estimate), mib(int64(total)))
	if int64(phase) > estimate {
		t.Errorf("allocated %d bytes, above the estimate %d", phase, estimate)
	}
	if limit := MaxDecodeBytes + 3*int64(len(data)); int64(total) > limit {
		t.Errorf("ProcessContext allocated %d bytes, above MaxDecodeBytes plus reading (%d)", total, limit)
	}
}

func mib(n int64) float64 { return float64(n) / (1 << 20) }

// maxAcceptedHeight returns the largest height accepted for a kind image of
// the given width whose decoding needs decodeBytes(height).
func maxAcceptedHeight(t testing.TB, kind Kind, width int, decodeBytes func(h int) int64) int {
	t.Helper()
	s, _ := kind.spec()
	accepted := func(h int) bool {
		cfg := image.Config{Width: width, Height: h}
		return s.checkDimensions(width, h) == nil && s.checkMemory(cfg, decodeBytes(h)) == nil
	}
	lo, hi := 0, s.maxSide+1 // accepted(lo) or lo == 0; !accepted(hi)
	for hi-lo > 1 {
		if mid := (lo + hi) / 2; accepted(mid) {
			lo = mid
		} else {
			hi = mid
		}
	}
	if lo == 0 {
		t.Fatalf("no %s %d pixels wide is accepted", s.name, width)
	}
	return lo
}

// maxAcceptedJPEG returns the largest 4:3 background accepted for a JPEG
// with comps components (3: YCbCr, 4: CMYK), its width a multiple of 32.
func maxAcceptedJPEG(t testing.TB, comps int) (w, h int) {
	t.Helper()
	m := jpegConfigModel(comps)
	return maxAccepted43(t, func(w, h int) int64 {
		return jpegDecodeBytes(image.Config{ColorModel: m, Width: w, Height: h}, nil)
	})
}

// maxAcceptedWebP returns the largest 4:3 WebP background accepted, for an
// input of up to 2 MiB (the generated ones are smaller).
func maxAcceptedWebP(t testing.TB) (w, h int) {
	t.Helper()
	return maxAccepted43(t, func(w, h int) int64 {
		return webpDecodeBytes(image.Config{Width: w, Height: h}, make([]byte, 2<<20))
	})
}

// maxAccepted43 returns the largest 4:3 background, its width a multiple of
// 32, whose decoding needing decodeBytes(w, h) is accepted.
func maxAccepted43(t testing.TB, decodeBytes func(w, h int) int64) (w, h int) {
	t.Helper()
	s, _ := KindBackground.spec()
	for w = MaxBackgroundSide &^ 31; w >= 32; w -= 32 {
		h = w * 3 / 4
		cfg := image.Config{Width: w, Height: h}
		if s.checkDimensions(w, h) == nil && s.checkMemory(cfg, decodeBytes(w, h)) == nil {
			return w, h
		}
	}
	t.Fatal("no 4:3 background accepted")
	return 0, 0
}

// pngFile builds a zero-filled (black, or transparent with trns) PNG of the
// given bit depth and color type, Adam7-interlaced if asked, with a tRNS
// chunk holding trns if not nil.
func pngFile(t testing.TB, w, h int, depth, colorType byte, interlaced bool, trns []byte) []byte {
	t.Helper()
	channels := map[byte]int{0: 1, 2: 3, 3: 1, 4: 2, 6: 4}[colorType]
	bitsPerPixel := channels * int(depth)
	rowBytes := func(width int) int { return 1 + (width*bitsPerPixel+7)/8 }
	size := h * rowBytes(w)
	if interlaced {
		size = 0
		for _, p := range [7][4]int{{0, 0, 8, 8}, {4, 0, 8, 8}, {0, 4, 4, 8}, {2, 0, 4, 4}, {0, 2, 2, 4}, {1, 0, 2, 2}, {0, 1, 1, 2}} {
			pw, ph := (w-p[0]+p[2]-1)/p[2], (h-p[1]+p[3]-1)/p[3]
			if pw > 0 && ph > 0 {
				size += ph * rowBytes(pw)
			}
		}
	}
	var idat bytes.Buffer
	zw, err := zlib.NewWriterLevel(&idat, zlib.BestSpeed)
	if err != nil {
		t.Fatal(err)
	}
	zero := make([]byte, 1<<20)
	for size > 0 {
		n := min(size, len(zero))
		if _, err := zw.Write(zero[:n]); err != nil {
			t.Fatal(err)
		}
		size -= n
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	interlace := byte(0)
	if interlaced {
		interlace = 1
	}
	ihdr := binary.BigEndian.AppendUint32(nil, uint32(w))
	ihdr = binary.BigEndian.AppendUint32(ihdr, uint32(h))
	ihdr = append(ihdr, depth, colorType, 0, 0, interlace)
	out := append(append([]byte{}, pngMagic...), pngChunk("IHDR", ihdr)...)
	if trns != nil {
		out = append(out, pngChunk("tRNS", trns)...)
	}
	out = append(out, pngChunk("IDAT", idat.Bytes())...)
	return append(out, pngChunk("IEND", nil)...)
}

// jpegBaseline encodes a uniform 4:2:0 color image with image/jpeg.
func jpegBaseline(t testing.TB, w, h int) []byte {
	t.Helper()
	var buf bytes.Buffer
	img := image.NewYCbCr(image.Rect(0, 0, w, h), image.YCbCrSubsampleRatio420)
	if err := jpeg.Encode(&buf, img, nil); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// jpeg411 returns a uniform color JPEG with 4:1:1 chroma subsampling: a
// 4:2:0 one from image/jpeg whose luma sampling factors are rewritten from
// 2x2 to 4x1. A uniform image codes every MCU alike, and both layouts have
// four luma blocks per MCU and as many MCUs when w is a multiple of 32 and
// h of 16, so the scan stays valid.
func jpeg411(t testing.TB, w, h int) []byte {
	t.Helper()
	data := jpegBaseline(t, w, h)
	i := bytes.Index(data, []byte{0xFF, 0xC0})
	// SOF0: marker, length, precision, height, width, count, then the
	// first component: identifier, sampling factors, table.
	if i < 0 || data[i+11] != 0x22 {
		t.Fatal("unexpected SOF0 layout")
	}
	data[i+11] = 0x41
	return data
}

// jpegConfigModel is the model image/jpeg declares for comps components.
func jpegConfigModel(comps int) color.Model {
	cfg, err := jpeg.DecodeConfig(bytes.NewReader(jpegProgressiveHeader(16, 16, "\x01\x02\x03\x04"[:comps])))
	if err != nil {
		panic(err)
	}
	return cfg.ColorModel
}

// jpegProgressiveHeader returns the segments of jpegProgressive up to its
// start of scan header included.
func jpegProgressiveHeader(w, h int, ids string) []byte {
	comps := len(ids)
	b := []byte{0xFF, 0xD8}
	if comps == 4 {
		// Adobe APP14 with transform 0: CMYK.
		b = append(b, 0xFF, 0xEE, 0x00, 0x0E)
		b = append(b, "Adobe\x00\x64\x00\x00\x00\x00\x00"...)
	}
	b = append(b, 0xFF, 0xDB, 0x00, 0x43, 0x00)
	b = append(b, bytes.Repeat([]byte{1}, 64)...)
	b = append(b, jpegSOF(uint16(w), uint16(h), 0xC2, []byte(ids))...)
	// DC table 0 with the single symbol 0 (difference 0), code "0".
	b = append(b, 0xFF, 0xC4, 0x00, 0x14, 0x00, 1)
	b = append(b, make([]byte, 15)...)
	b = append(b, 0x00)
	// Interleaved DC first scan of every component.
	b = append(b, 0xFF, 0xDA)
	b = binary.BigEndian.AppendUint16(b, uint16(6+2*comps))
	b = append(b, byte(comps))
	for _, id := range []byte(ids) {
		b = append(b, id, 0x00)
	}
	return append(b, 0x00, 0x00, 0x00)
}

// jpegProgressive returns a uniform progressive JPEG with one component
// per identifier of ids (1 gray, 3 YCbCr, or RGB when named "RGB", 4 CMYK),
// all sampled 1x1: one DC scan whose every difference is 0, which makes the
// decoder allocate the coefficient buffers of every component.
func jpegProgressive(t testing.TB, w, h int, ids string) []byte {
	t.Helper()
	b := jpegProgressiveHeader(w, h, ids)
	blocks := len(ids) * ((w + 7) / 8) * ((h + 7) / 8)
	b = append(b, make([]byte, blocks/8)...)
	if blocks%8 != 0 {
		b = append(b, byte(0xFF>>(blocks%8))) // the remaining codes, then 1-bit padding
	}
	return append(b, 0xFF, 0xD9)
}

// vp8lWriter writes a VP8L bit stream, least significant bit first.
type vp8lWriter struct {
	buf  []byte
	acc  uint64
	nacc uint
}

// bits writes the n low bits of v.
func (w *vp8lWriter) bits(v uint32, n uint) {
	w.acc |= uint64(v) << w.nacc
	w.nacc += n
	for w.nacc >= 8 {
		w.buf = append(w.buf, byte(w.acc))
		w.acc >>= 8
		w.nacc -= 8
	}
}

// code writes the Huffman code c of length n, most significant bit first.
func (w *vp8lWriter) code(c uint32, n uint) {
	for i := n; i > 0; i-- {
		w.bits(c>>(i-1)&1, 1)
	}
}

// bytes flushes the pending bits and returns the stream.
func (w *vp8lWriter) bytes() []byte {
	if w.nacc > 0 {
		w.buf = append(w.buf, byte(w.acc))
		w.acc, w.nacc = 0, 0
	}
	return w.buf
}

// simpleTree writes a simple Huffman tree holding only symbol s (< 256),
// which decodes with no bits.
func (w *vp8lWriter) simpleTree(s uint32) {
	w.bits(1, 1) // simple
	w.bits(0, 1) // one symbol
	if s < 2 {
		w.bits(0, 1)
		w.bits(s, 1)
		return
	}
	w.bits(1, 1)
	w.bits(s, 8)
}

// codeLengthOrder is the order of the code length code lengths.
var codeLengthOrder = [19]int{17, 18, 0, 1, 2, 3, 4, 5, 16, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}

// normalTree writes a normal Huffman tree for an alphabet of alphabetSize
// symbols, where the symbols below len(lengths) have the given code lengths
// (one or two distinct values, a complete code) and the others none.
func (w *vp8lWriter) normalTree(lengths []uint32, alphabetSize int) {
	lo, hi := lengths[0], lengths[0]
	for _, l := range lengths {
		lo, hi = min(lo, l), max(hi, l)
	}
	w.bits(0, 1) // normal
	last := 0
	for i, sym := range codeLengthOrder {
		if uint32(sym) == lo || uint32(sym) == hi {
			last = i
		}
	}
	nCodes := max(last+1, 4)
	w.bits(uint32(nCodes-4), 4)
	for i := range nCodes {
		if sym := uint32(codeLengthOrder[i]); sym == lo || sym == hi {
			w.bits(1, 3) // one-bit codes: lo is "0", hi is "1"
		} else {
			w.bits(0, 3)
		}
	}
	if len(lengths) == alphabetSize {
		w.bits(0, 1)
	} else {
		w.bits(1, 1)
		ms := uint32(len(lengths) - 2)
		k := uint(0)
		for ms>>(2+2*k) != 0 {
			k++
		}
		w.bits(uint32(k), 3)
		w.bits(ms, 2+2*k)
	}
	if lo == hi {
		return // a single code length symbol takes no bits
	}
	for _, l := range lengths {
		if l == hi {
			w.code(1, 1)
		} else {
			w.code(0, 1)
		}
	}
}

// codeLengths returns n1 lengths l1 followed by n2 lengths l2.
func codeLengths(n1 int, l1 uint32, n2 int, l2 uint32) []uint32 {
	out := make([]uint32, 0, n1+n2)
	for range n1 {
		out = append(out, l1)
	}
	for range n2 {
		out = append(out, l2)
	}
	return out
}

// lz77Length returns the prefix symbol and extra bits coding an LZ77
// length (1 to 4096) in VP8L.
func lz77Length(l int) (sym, extra uint32, n uint) {
	if l <= 4 {
		return uint32(l - 1), 0, 0
	}
	v := uint32(l - 1)
	for s := uint32(4); ; s++ {
		e := (s - 2) >> 1
		if off := (2 + s&1) << e; v < off+1<<e {
			return s, v - off, uint(e)
		}
	}
}

// Worst-case VP8L parameters.
const (
	vp8lGroups  = 2600 // the most Huffman groups the decoder accepts
	vp8lCCBits  = 11   // the largest color cache
	vp8lGreen   = 256 + 24 + 1<<vp8lCCBits
	vp8lMaxCopy = 4096 // the longest LZ77 copy
)

// vp8lImage writes the transforms and pixels of a w x h VP8L image (the bit
// stream after its 5-byte header) built to allocate the most memory: all
// four transforms (a 256-color index, so that the packed image is as large
// as the output, plus predictor and cross-color sub-images with the
// smallest tiles), an 11-bit color cache and 2600 Huffman groups, all
// referenced, each with complete trees over the whole alphabets. The
// pixels are one literal then the longest LZ77 copies.
func vp8lImage(wr *vp8lWriter, w, h int) {
	tiles := func(size, bits int) int { return (size + 1<<bits - 1) >> bits }
	// Predictor then cross-color transforms with 4x4 tiles, then subtract
	// green, then a 256-color indexing transform.
	for _, typ := range []uint32{0, 1} {
		wr.bits(1, 1)
		wr.bits(typ, 2)
		wr.bits(0, 3) // tile bits 2
		wr.bits(0, 1) // sub-image: no color cache
		for range 5 {
			wr.simpleTree(0)
		}
	}
	wr.bits(1, 1)
	wr.bits(2, 2)
	wr.bits(1, 1)
	wr.bits(3, 2)
	wr.bits(255, 8) // 256 colors
	wr.bits(0, 1)
	for range 5 {
		wr.simpleTree(0)
	}
	wr.bits(0, 1) // no more transforms

	// Main image: color cache and meta Huffman codes, with the largest
	// tiles that still give every group its own tile.
	wr.bits(1, 1)
	wr.bits(vp8lCCBits, 4)
	wr.bits(1, 1)
	hBits := 9
	for hBits > 2 && tiles(w, hBits)*tiles(h, hBits) < vp8lGroups {
		hBits--
	}
	wr.bits(uint32(hBits-2), 3)
	// Entropy image: group index i = red<<8 | green, coded on 8 + 4 bits.
	wr.bits(0, 1)
	wr.normalTree(codeLengths(256, 8, 0, 0), 256+24)
	wr.normalTree(codeLengths(16, 4, 0, 0), 256)
	for range 3 {
		wr.simpleTree(0)
	}
	nTiles := tiles(w, hBits) * tiles(h, hBits)
	for i := range nTiles {
		g := i % vp8lGroups
		wr.code(uint32(g&0xFF), 8)
		wr.code(uint32(g>>8), 4)
	}
	// The groups, all alike: green over its 2328 symbols (1768 of length 11,
	// 560 of length 12), red, blue and alpha over 256 (length 8), distance
	// over 40 (24 of length 5, 16 of length 6).
	for range vp8lGroups {
		wr.normalTree(codeLengths(1768, 11, vp8lGreen-1768, 12), vp8lGreen)
		for range 3 {
			wr.normalTree(codeLengths(256, 8, 0, 0), 256)
		}
		wr.normalTree(codeLengths(24, 5, 16, 6), 40)
	}
	// One literal pixel (index 0), then copies of the previous pixel
	// (distance code 2, symbol 1).
	wr.code(0, 11)
	for range 3 {
		wr.code(0, 8)
	}
	for left := w*h - 1; left > 0; {
		n := min(left, vp8lMaxCopy)
		sym, extra, nExtra := lz77Length(n)
		wr.code(256+sym, 11)
		wr.bits(extra, nExtra)
		wr.code(1, 5)
		left -= n
	}
}

// vp8lStream returns a complete worst-case VP8L bit stream of w x h pixels.
func vp8lStream(w, h int) []byte {
	var wr vp8lWriter
	wr.bits(0x2F, 8)
	wr.bits(uint32(w-1), 14)
	wr.bits(uint32(h-1), 14)
	wr.bits(1, 1) // alpha used
	wr.bits(0, 3) // version
	vp8lImage(&wr, w, h)
	return wr.bytes()
}

// riffChunk returns a RIFF chunk, padded to an even size.
func riffChunk(id string, data []byte) []byte {
	b := append([]byte(id), binary.LittleEndian.AppendUint32(nil, uint32(len(data)))...)
	b = append(b, data...)
	if len(data)%2 == 1 {
		b = append(b, 0)
	}
	return b
}

// webpFile wraps chunks in a RIFF WEBP container.
func webpFile(chunks ...[]byte) []byte {
	body := []byte("WEBP")
	for _, c := range chunks {
		body = append(body, c...)
	}
	return append(append([]byte("RIFF"), binary.LittleEndian.AppendUint32(nil, uint32(len(body)))...), body...)
}

// webpLossless returns a worst-case lossless WebP (see vp8lImage).
func webpLossless(w, h int) []byte {
	return webpFile(riffChunk("VP8L", vp8lStream(w, h)))
}

// webpLossyAlpha returns a lossy WebP whose alpha plane is a worst-case
// lossless bit stream (see vp8lImage). The VP8 key frame is all zeros after
// its header, which decodes as macroblocks without coefficients.
func webpLossyAlpha(w, h int) []byte {
	vp8x := []byte{0x10, 0, 0, 0} // alpha
	for _, v := range []int{w - 1, h - 1} {
		vp8x = append(vp8x, byte(v), byte(v>>8), byte(v>>16))
	}
	// The alpha bit stream without its 5-byte header, which the decoder
	// synthesizes; flags: lossless compression, no filter.
	alph := append([]byte{0x01}, vp8lStream(w, h)[5:]...)

	mbs := ((w + 15) / 16) * ((h + 15) / 16)
	first := min(mbs*8+64, 1<<19-1) // first partition: modes
	tag := uint32(first)<<5 | 0x10  // key frame, version 0, shown
	frame := []byte{byte(tag), byte(tag >> 8), byte(tag >> 16), 0x9D, 0x01, 0x2A}
	frame = binary.LittleEndian.AppendUint16(frame, uint16(w))
	frame = binary.LittleEndian.AppendUint16(frame, uint16(h))
	frame = append(frame, make([]byte, first+mbs*4+64)...)
	return webpFile(riffChunk("VP8X", vp8x), riffChunk("ALPH", alph), riffChunk("VP8 ", frame))
}
