package tte2

import (
	"bytes"
	"errors"
	"io"
	"math"
	"testing"
)

// failReader fails every read.
type failReader struct{}

// Read implements io.Reader.
func (failReader) Read([]byte) (int, error) { return 0, errors.New("no entropy") }

// sealAll encrypts plain chunk by chunk with c and returns the stream.
func sealAll(t *testing.T, c *ChunkCipher, plain []byte) []byte {
	t.Helper()
	head := c.Header().Bytes()
	out := bytes.Clone(head[:])
	size := c.ChunkSize()
	count := ChunkCount(int64(len(plain)), size)
	for n := range count {
		lo := int(n) * size
		hi := min(lo+size, len(plain))
		var err error
		out, err = c.Seal(out, uint64(n), plain[lo:hi], n == count-1)
		if err != nil {
			t.Fatal(err)
		}
	}
	return out
}

func TestNewHeader(t *testing.T) {
	h, err := NewHeader(testChunk)
	if err != nil || h.ChunkSize != testChunk || h.Salt == ([SaltSize]byte{}) {
		t.Fatalf("NewHeader = %+v, %v", h, err)
	}
	if _, err := NewHeader(testChunk + 1); !errors.Is(err, ErrInvalidChunkSize) {
		t.Fatal(err)
	}
	withRand(t, failReader{})
	if _, err := NewHeader(testChunk); err == nil {
		t.Fatal("random failure ignored")
	}
}

func TestNewChunkCipherErrors(t *testing.T) {
	h := Header{ChunkSize: testChunk}
	if _, err := NewChunkCipher(make([]byte, 31), 0, h); !errors.Is(err, ErrInvalidKey) {
		t.Fatal(err)
	}
	if _, err := NewChunkCipher(testKey(1), -1, h); !errors.Is(err, ErrInvalidIndex) {
		t.Fatal(err)
	}
	if _, err := NewChunkCipher(testKey(1), 0, Header{ChunkSize: 1000}); !errors.Is(err, ErrInvalidChunkSize) {
		t.Fatal(err)
	}
	c, err := NewChunkCipher(testKey(1), 0, h)
	if err != nil || c.Header() != h || c.ChunkSize() != testChunk {
		t.Fatal(c, err)
	}
}

// TestChunkCipherMatchesWriter checks that chunk-by-chunk sealing reproduces
// the Writer byte for byte, and that Open decrypts the Writer output.
func TestChunkCipherMatchesWriter(t *testing.T) {
	key := testKey(3)
	c := testChunk
	for _, size := range []int{0, 1, c - 1, c, c + 1, 2 * c, 3*c + 17} {
		plain := pattern(size)
		h, err := NewHeader(c)
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		w, err := NewWriter(&buf, key, 2, WithChunkSize(2*c), WithHeader(h))
		if err != nil {
			t.Fatal(err)
		}
		if w.Header() != h {
			t.Fatal("WithHeader ignored")
		}
		if _, err := w.Write(plain); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		cc, err := NewChunkCipher(key, 2, h)
		if err != nil {
			t.Fatal(err)
		}
		ct := sealAll(t, cc, plain)
		if !bytes.Equal(ct, buf.Bytes()) {
			t.Fatalf("size %d: chunk sealing differs from Writer", size)
		}
		if int64(len(ct)) != CiphertextSize(int64(size), c) {
			t.Fatalf("size %d: wrong stream size", size)
		}

		// Open every chunk of the Writer output, as a resumed download
		// would: header re-read, then chunks located by ChunkOffset.
		rh, err := ParseHeader(ct[:HeaderSize])
		if err != nil {
			t.Fatal(err)
		}
		oc, err := NewChunkCipher(key, 2, rh)
		if err != nil {
			t.Fatal(err)
		}
		total, _ := PlaintextSize(int64(len(ct)), c)
		count := ChunkCount(total, c)
		var got []byte
		for n := range count {
			lo := ChunkOffset(n, c)
			hi := min(ChunkOffset(n+1, c), int64(len(ct)))
			got, err = oc.Open(got, uint64(n), ct[lo:hi], n == count-1)
			if err != nil {
				t.Fatalf("size %d chunk %d: %v", size, n, err)
			}
		}
		if !bytes.Equal(got, plain) {
			t.Fatalf("size %d: Open differs", size)
		}
	}
}

// TestWriterWithHeaderDeterministic checks that two Writers sharing a header
// produce the same stream, and that the default stays a fresh salt.
func TestWriterWithHeaderDeterministic(t *testing.T) {
	key := testKey(4)
	plain := pattern(testChunk + 5)
	h, err := NewHeader(testChunk)
	if err != nil {
		t.Fatal(err)
	}
	run := func(opts ...Option) []byte {
		var buf bytes.Buffer
		w, err := NewWriter(&buf, key, 0, opts...)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write(plain)
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	a, b := run(WithHeader(h)), run(WithHeader(h))
	if !bytes.Equal(a, b) {
		t.Fatal("WithHeader is not deterministic")
	}
	x, y := run(WithChunkSize(testChunk)), run(WithChunkSize(testChunk))
	if bytes.Equal(x[:HeaderSize], y[:HeaderSize]) {
		t.Fatal("default salt reused")
	}
	if _, err := NewWriter(io.Discard, key, 0, WithHeader(Header{ChunkSize: 3})); !errors.Is(err, ErrInvalidChunkSize) {
		t.Fatal(err)
	}
	withRand(t, failReader{})
	if _, err := NewWriter(io.Discard, key, 0); err == nil {
		t.Fatal("random failure ignored")
	}
}

func TestChunkCipherOpenErrors(t *testing.T) {
	c := testChunk
	key := testKey(7)
	h, err := NewHeader(c)
	if err != nil {
		t.Fatal(err)
	}
	cc, _ := NewChunkCipher(key, 1, h)
	middle, _ := cc.Seal(nil, 0, pattern(c), false)
	final, _ := cc.Seal(nil, 1, pattern(10), true)
	empty, _ := cc.Seal(nil, 0, nil, true)
	fullFinal, _ := cc.Seal(nil, 1, pattern(c), true)

	if p, err := cc.Open(nil, 0, middle, false); err != nil || !bytes.Equal(p, pattern(c)) {
		t.Fatal(err)
	}
	if p, err := cc.Open(nil, 0, empty, true); err != nil || len(p) != 0 {
		t.Fatal(err)
	}
	other, _ := NewChunkCipher(key, 2, h)
	otherSalt := h
	otherSalt.Salt[0] ^= 1
	saltCipher, _ := NewChunkCipher(key, 1, otherSalt)
	wrongKey, _ := NewChunkCipher(testKey(8), 1, h)
	flipped := bytes.Clone(final)
	flipped[3] ^= 0x80
	tag := bytes.Clone(final)
	tag[len(tag)-1] ^= 1

	cases := []struct {
		name   string
		c      *ChunkCipher
		n      uint64
		sealed []byte
		last   bool
		want   error
	}{
		{"tampered data", cc, 1, flipped, true, ErrAuth},
		{"tampered tag", cc, 1, tag, true, ErrAuth},
		{"wrong n", cc, 2, final, true, ErrAuth},
		{"middle wrong n", cc, 1, middle, false, ErrAuth},
		{"wrong last flag on final", cc, 1, fullFinal, false, ErrAuth},
		{"wrong last flag on middle", cc, 0, middle, true, ErrAuth},
		{"wrong index", other, 1, final, true, ErrAuth},
		{"wrong salt", saltCipher, 1, final, true, ErrAuth},
		{"wrong key", wrongKey, 1, final, true, ErrAuth},
		{"shorter than tag", cc, 1, final[:TagSize-1], true, ErrFormat},
		{"short middle", cc, 0, middle[:len(middle)-1], false, ErrFormat},
		{"oversized middle", cc, 0, append(bytes.Clone(middle), 0), false, ErrFormat},
		{"oversized final", cc, 1, append(bytes.Clone(middle), 0), true, ErrFormat},
		{"empty final after data", cc, 1, empty, true, ErrFormat},
		{"counter beyond 32 bits", cc, MaxChunks, final, true, ErrCounterOverflow},
		{"middle at last counter", cc, math.MaxUint32, middle, false, ErrCounterOverflow},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := tc.c.Open(make([]byte, 0, 8), tc.n, tc.sealed, tc.last)
			if !errors.Is(err, tc.want) || p != nil {
				t.Fatalf("Open = %d bytes, %v; want %v", len(p), err, tc.want)
			}
		})
	}

	// A final chunk at the last counter value is allowed.
	last, err := cc.Seal(nil, math.MaxUint32, pattern(1), true)
	if err != nil {
		t.Fatal(err)
	}
	if p, err := cc.Open(nil, math.MaxUint32, last, true); err != nil || !bytes.Equal(p, pattern(1)) {
		t.Fatal(err)
	}
}

func TestChunkCipherSealErrors(t *testing.T) {
	c := testChunk
	cc, _ := NewChunkCipher(testKey(9), 0, Header{ChunkSize: c})
	dst := []byte("prefix")
	cases := []struct {
		name  string
		n     uint64
		plain []byte
		last  bool
		want  error
	}{
		{"short middle", 0, pattern(c - 1), false, ErrFormat},
		{"oversized middle", 0, pattern(c + 1), false, ErrFormat},
		{"oversized final", 3, pattern(c + 1), true, ErrFormat},
		{"oversized final 0", 0, pattern(c + 1), true, ErrFormat},
		{"empty final after data", 1, nil, true, ErrFormat},
		{"empty middle", 0, nil, false, ErrFormat},
		{"counter beyond 32 bits", MaxChunks, pattern(1), true, ErrCounterOverflow},
		{"middle at last counter", math.MaxUint32, pattern(c), false, ErrCounterOverflow},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := cc.Seal(dst, tc.n, tc.plain, tc.last)
			if !errors.Is(err, tc.want) || !bytes.Equal(out, dst) {
				t.Fatalf("Seal = %q, %v; want %v", out, err, tc.want)
			}
		})
	}
	// Valid edge lengths append to dst.
	for _, tc := range []struct {
		n    uint64
		size int
		last bool
	}{{0, 0, true}, {0, c, true}, {5, 1, true}, {5, c, true}, {7, c, false}} {
		out, err := cc.Seal(bytes.Clone(dst), tc.n, pattern(tc.size), tc.last)
		if err != nil || len(out) != len(dst)+tc.size+TagSize || !bytes.HasPrefix(out, dst) {
			t.Fatalf("%+v: %d bytes, %v", tc, len(out), err)
		}
	}
}

func TestChunkCipherInPlace(t *testing.T) {
	c := testChunk
	cc, _ := NewChunkCipher(testKey(10), 0, Header{ChunkSize: c})
	buf := make([]byte, c, c+TagSize)
	copy(buf, pattern(c))
	sealed, err := cc.Seal(buf[:0], 0, buf, false)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := cc.Open(sealed[:0], 0, sealed, false)
	if err != nil || !bytes.Equal(plain, pattern(c)) {
		t.Fatal("in-place round trip failed", err)
	}
}

func TestChunkCount(t *testing.T) {
	c := testChunk
	cases := []struct {
		plain int64
		chunk int
		want  int64
	}{
		{0, c, 1},
		{1, c, 1},
		{int64(c), c, 1},
		{int64(c) + 1, c, 2},
		{MaxChunks * int64(c), c, MaxChunks},
		{MaxChunks*int64(c) + 1, c, -1},
		{-1, c, -1},
		{10, c + 1, -1},
	}
	for _, tc := range cases {
		if got := ChunkCount(tc.plain, tc.chunk); got != tc.want {
			t.Errorf("ChunkCount(%d, %d) = %d, want %d", tc.plain, tc.chunk, got, tc.want)
		}
		if tc.want > 0 {
			// The size formula: CiphertextSize counts TagSize per chunk.
			if CiphertextSize(tc.plain, tc.chunk) != HeaderSize+tc.plain+TagSize*tc.want {
				t.Errorf("ChunkCount(%d, %d) disagrees with CiphertextSize", tc.plain, tc.chunk)
			}
		}
	}
}

func TestChunkOffsetAndAt(t *testing.T) {
	c := testChunk
	block := int64(c + TagSize)
	cases := []struct {
		n     int64
		chunk int
		want  int64
	}{
		{0, c, HeaderSize},
		{1, c, HeaderSize + block},
		{MaxChunks - 1, c, HeaderSize + (MaxChunks-1)*block},
		{MaxChunks, c, -1},
		{-1, c, -1},
		{0, 100, -1},
	}
	for _, tc := range cases {
		if got := ChunkOffset(tc.n, tc.chunk); got != tc.want {
			t.Errorf("ChunkOffset(%d, %d) = %d, want %d", tc.n, tc.chunk, got, tc.want)
		}
	}

	at := []struct {
		off     int64
		chunk   int
		n, skip int64
	}{
		{HeaderSize, c, 0, 0},
		{HeaderSize + 5, c, 0, 5},
		{HeaderSize + block - 1, c, 0, block - 1},
		{HeaderSize + block, c, 1, 0},
		{HeaderSize + 3*block + 7, c, 3, 7},
		{HeaderSize + MaxChunks*block - 1, c, MaxChunks - 1, block - 1},
		{HeaderSize + MaxChunks*block, c, -1, -1},
		{HeaderSize - 1, c, -1, -1},
		{0, c, -1, -1},
		{-1, c, -1, -1},
		{HeaderSize, 100, -1, -1},
	}
	for _, tc := range at {
		n, skip := ChunkAt(tc.off, tc.chunk)
		if n != tc.n || skip != tc.skip {
			t.Errorf("ChunkAt(%d, %d) = (%d, %d), want (%d, %d)", tc.off, tc.chunk, n, skip, tc.n, tc.skip)
		}
		if n >= 0 && ChunkOffset(n, tc.chunk)+skip != tc.off {
			t.Errorf("ChunkAt(%d) does not invert ChunkOffset", tc.off)
		}
	}
}

// TestChunkResumeUpload simulates an upload interrupted at every offset of a
// small stream: resealing from ChunkAt must yield the original tail.
func TestChunkResumeUpload(t *testing.T) {
	c := testChunk
	key := testKey(11)
	plain := pattern(2*c + 300)
	h, _ := NewHeader(c)
	cc, _ := NewChunkCipher(key, 0, h)
	ct := sealAll(t, cc, plain)
	count := ChunkCount(int64(len(plain)), c)
	for _, off := range []int64{HeaderSize, HeaderSize + 1, ChunkOffset(1, c) - 1, ChunkOffset(1, c), ChunkOffset(2, c) + 3, int64(len(ct)) - 1} {
		n, skip := ChunkAt(off, c)
		var tail []byte
		for j := n; j < count; j++ {
			lo := int(j) * c
			hi := min(lo+c, len(plain))
			var err error
			tail, err = cc.Seal(tail, uint64(j), plain[lo:hi], j == count-1)
			if err != nil {
				t.Fatal(err)
			}
		}
		if !bytes.Equal(tail[skip:], ct[off:]) {
			t.Fatalf("resume at %d differs", off)
		}
	}
}
