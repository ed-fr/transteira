package seeded

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"math/rand/v2"
	"testing"
	"testing/iotest"
)

// reference is the stream of seed concatenated block by block, built
// independently of reader: the specification of the package.
func reference(seed uint64, size int64) []byte {
	out := make([]byte, 0, size)
	for i := int64(0); int64(len(out)) < size; i++ {
		b := make([]byte, BlockSize)
		_, _ = rand.NewChaCha8(blockKey(seed, i)).Read(b)
		out = append(out, b[:min(BlockSize, size-int64(len(out)))]...)
	}
	return out
}

func TestStreamMatchesReference(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		seed uint64
		size int64
	}{
		{"empty", 1, 0},
		{"one byte", 1, 1},
		{"less than a block", 2, BlockSize - 1},
		{"exactly a block", 3, BlockSize},
		{"a block and a byte", 4, BlockSize + 1},
		{"several blocks", 5, 3*BlockSize + 12345},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := io.ReadAll(Stream(tc.seed, tc.size))
			if err != nil {
				t.Fatal(err)
			}
			if want := reference(tc.seed, tc.size); !bytes.Equal(got, want) {
				t.Fatalf("Stream(%d, %d) differs from the block reference (%d bytes, want %d)", tc.seed, tc.size, len(got), len(want))
			}
			if err := iotest.TestReader(Stream(tc.seed, tc.size), reference(tc.seed, tc.size)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRangeIsASliceOfStream(t *testing.T) {
	t.Parallel()
	const seed, size = 7, 4*BlockSize + 777
	full := reference(seed, size)
	cases := [][2]int64{
		{0, 0},
		{0, 1},
		{0, size},
		{size, 0},
		{size - 1, 1},
		{BlockSize - 1, 2},
		{BlockSize, 1},
		{BlockSize, BlockSize},
		{BlockSize + 1, BlockSize - 2},
		{2*BlockSize - 1, 1},
		{3 * BlockSize, BlockSize + 777},
		{12345, 3 * BlockSize},
	}
	// Random offsets and lengths, deterministic (fixed PCG seed).
	r := rand.New(rand.NewPCG(1, 2))
	for range 40 {
		off := r.Int64N(size + 1)
		cases = append(cases, [2]int64{off, r.Int64N(size - off + 1)})
	}
	for _, c := range cases {
		got, err := io.ReadAll(Range(seed, c[0], c[1]))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, full[c[0]:c[0]+c[1]]) {
			t.Fatalf("Range(%d, %d, %d) is not the matching slice of the stream", seed, c[0], c[1])
		}
	}
}

func TestRangeOddReads(t *testing.T) {
	t.Parallel()
	const seed, off, n = 9, BlockSize - 100, 2*BlockSize + 50
	want := reference(seed, off+n)[off:]
	// One-byte reads, and an empty read in the middle, cross block
	// boundaries one byte at a time.
	r := Range(seed, off, n)
	if k, err := r.Read(nil); k != 0 || err != nil {
		t.Fatalf("empty read = %d, %v", k, err)
	}
	got, err := io.ReadAll(iotest.OneByteReader(r))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("one-byte reads differ from the stream")
	}
	if k, err := r.Read(make([]byte, 8)); k != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("read after the end = %d, %v; want 0, EOF", k, err)
	}
}

func TestSeedsDiffer(t *testing.T) {
	t.Parallel()
	if bytes.Equal(Bytes(1, 64), Bytes(2, 64)) {
		t.Fatal("seeds 1 and 2 give the same stream")
	}
	if !bytes.Equal(Bytes(3, 1000), Bytes(3, 1000)) {
		t.Fatal("the same seed gives two different streams")
	}
	if b := Bytes(3, 0); len(b) != 0 {
		t.Fatalf("Bytes(3, 0) has %d bytes", len(b))
	}
}

func TestRangeInvalid(t *testing.T) {
	t.Parallel()
	for _, c := range [][2]int64{{-1, 1}, {0, -1}, {math.MaxInt64, 1}, {1, math.MaxInt64}, {1 << 62, 1 << 62}, {math.MinInt64, 0}} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("Range(_, %d, %d) did not panic", c[0], c[1])
				}
			}()
			Range(1, c[0], c[1])
		}()
	}
}

// TestRangeAtTheLimits checks that the largest representable ranges are
// accepted: off+n == math.MaxInt64 does not overflow.
func TestRangeAtTheLimits(t *testing.T) {
	t.Parallel()
	for _, c := range [][2]int64{{math.MaxInt64, 0}, {0, math.MaxInt64}, {math.MaxInt64 - 5, 5}} {
		r := Range(1, c[0], c[1])
		if c[1] == 0 {
			if n, err := r.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
				t.Errorf("Range(_, %d, 0).Read = %d, %v; want 0, io.EOF", c[0], n, err)
			}
			continue
		}
		if n, err := r.Read(make([]byte, 3)); n != 3 || err != nil {
			t.Errorf("Range(_, %d, %d).Read = %d, %v; want 3, nil", c[0], c[1], n, err)
		}
	}
}

func TestSum(t *testing.T) {
	t.Parallel()
	for _, size := range []int64{0, 1, BlockSize, 2*BlockSize + 3} {
		want := sha256.Sum256(reference(11, size))
		if got := Sum(11, size); got != want {
			t.Errorf("Sum(11, %d) = %x, want %x", size, got, want)
		}
		if got := SumHex(11, size); got != hex.EncodeToString(want[:]) {
			t.Errorf("SumHex(11, %d) = %s", size, got)
		}
	}
}

func TestHashingReader(t *testing.T) {
	t.Parallel()
	data := []byte("hello, hashing reader")
	h := NewHashingReader(bytes.NewReader(data))
	if _, err := io.Copy(io.Discard, h); err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(data)
	if h.N() != int64(len(data)) || h.Sum() != want || h.Hex() != hex.EncodeToString(want[:]) {
		t.Fatalf("N %d, Sum %x, Hex %s; want %d, %x", h.N(), h.Sum(), h.Hex(), len(data), want)
	}
	// Errors of the underlying reader are passed through with the bytes.
	e := NewHashingReader(iotest.ErrReader(io.ErrUnexpectedEOF))
	if n, err := e.Read(make([]byte, 4)); n != 0 || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("Read = %d, %v; want 0, ErrUnexpectedEOF", n, err)
	}
}

func BenchmarkStream(b *testing.B) {
	buf := make([]byte, 256<<10)
	b.SetBytes(64 << 20)
	for b.Loop() {
		if _, err := io.CopyBuffer(io.Discard, Stream(1, 64<<20), buf); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSum(b *testing.B) {
	b.SetBytes(64 << 20)
	for b.Loop() {
		Sum(1, 64<<20)
	}
}
