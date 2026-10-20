package crypto

import (
	"bytes"
	"errors"
	"io"
	"math"
	"math/rand/v2"
	"sync"
	"testing"
	"testing/iotest"
)

// newRA opens ct with NewReaderAt for tenantA/fileA.
func newRA(dek, ct []byte) (*ReaderAt, error) {
	return NewReaderAt(bytes.NewReader(ct), int64(len(ct)), dek, tenantA, fileA)
}

// readAllAt reads the whole plaintext of r through a SectionReader.
func readAllAt(r *ReaderAt) ([]byte, error) {
	return io.ReadAll(io.NewSectionReader(r, 0, r.Size()))
}

func TestReaderAtRoundTrip(t *testing.T) {
	dek := testDEK(50)
	rng := rand.New(rand.NewPCG(3, 4))
	for _, n := range []int{0, 1, cs - 1, cs, cs + 1, 2 * cs, 5*cs + 123} {
		data := pattern(n)
		ct := encrypt(t, dek, tenantA, fileA, data, cs, nil)
		r, err := newRA(dek, ct)
		if err != nil {
			t.Fatalf("n=%d: %v", n, err)
		}
		if r.Size() != int64(n) || PlaintextSize(int64(len(ct)), cs) != int64(n) {
			t.Fatalf("n=%d: Size %d", n, r.Size())
		}
		if len(r.buf) > cs+tagSize {
			t.Fatalf("buffer of %d bytes", len(r.buf))
		}
		got, err := readAllAt(r)
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("n=%d: read all: %v", n, err)
		}
		if err := iotest.TestReader(io.NewSectionReader(r, 0, r.Size()), data); err != nil {
			t.Fatalf("n=%d: %v", n, err)
		}
		// Random ranges, including ones crossing chunk boundaries and the end.
		for range 200 {
			off := rng.Int64N(int64(n) + 10)
			p := make([]byte, rng.IntN(3*cs))
			m, err := r.ReadAt(p, off)
			end := min(off+int64(len(p)), int64(n))
			want := []byte{}
			if off < int64(n) {
				want = data[off:end]
			}
			if !bytes.Equal(p[:m], want) {
				t.Fatalf("n=%d off=%d len=%d: wrong bytes", n, off, len(p))
			}
			switch {
			case off+int64(len(p)) > int64(n) && len(p) > 0:
				if !errors.Is(err, io.EOF) {
					t.Fatalf("n=%d off=%d len=%d: %v, want EOF", n, off, len(p), err)
				}
			case err != nil:
				t.Fatalf("n=%d off=%d len=%d: %v", n, off, len(p), err)
			}
		}
		if _, err := r.ReadAt(make([]byte, 1), -1); !errors.Is(err, ErrNegativeOffset) {
			t.Fatalf("negative offset: %v", err)
		}
	}
}

func TestReaderAtConcurrent(t *testing.T) {
	dek := testDEK(51)
	data := pattern(7*cs + 5)
	r, err := newRA(dek, encrypt(t, dek, tenantA, fileA, data, cs, nil))
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for g := range 8 {
		wg.Go(func() {
			rng := rand.New(rand.NewPCG(uint64(g), 9))
			for range 300 {
				off := rng.Int64N(int64(len(data)))
				p := make([]byte, min(rng.IntN(2*cs)+1, len(data)-int(off)))
				if _, err := r.ReadAt(p, off); err != nil || !bytes.Equal(p, data[off:off+int64(len(p))]) {
					errs <- errors.New("concurrent ReadAt returned wrong data")
					return
				}
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

func TestNewReaderAtErrors(t *testing.T) {
	dek := testDEK(52)
	data := pattern(3*cs + 100)
	ct := encrypt(t, dek, tenantA, fileA, data, cs, nil)
	bounds := chunkBounds(ct, cs)

	if _, err := NewReaderAt(bytes.NewReader(ct), int64(len(ct)), dek[:3], tenantA, fileA); !errors.Is(err, ErrKeySize) {
		t.Fatalf("dek: %v", err)
	}
	if _, err := NewReaderAt(bytes.NewReader(ct), int64(len(ct)), dek, "", fileA); !errors.Is(err, ErrInvalidBinding) {
		t.Fatalf("binding: %v", err)
	}
	for _, size := range []int64{-1, 0, HeaderSize - 1} {
		if _, err := NewReaderAt(bytes.NewReader(ct), size, dek, tenantA, fileA); !errors.Is(err, ErrTruncated) {
			t.Fatalf("size %d: %v", size, err)
		}
	}
	// The source is shorter than the announced size.
	if _, err := NewReaderAt(bytes.NewReader(ct[:10]), int64(len(ct)), dek, tenantA, fileA); !errors.Is(err, ErrTruncated) {
		t.Fatalf("short header: %v", err)
	}
	if _, err := NewReaderAt(bytes.NewReader(ct[:len(ct)-1]), int64(len(ct)), dek, tenantA, fileA); !errors.Is(err, ErrTruncated) {
		t.Fatalf("short final chunk: %v", err)
	}
	if _, err := NewReaderAt(failReaderAt{}, int64(len(ct)), dek, tenantA, fileA); !errors.Is(err, errBoom) {
		t.Fatalf("read error: %v", err)
	}
	bad := append([]byte(nil), ct...)
	bad[4] = 9
	if _, err := newRA(dek, bad); !errors.Is(err, ErrBadHeader) {
		t.Fatalf("bad header: %v", err)
	}
	// Truncation: at a chunk boundary, or leaving less than a tag.
	for _, cut := range []int{HeaderSize, bounds[1][0], bounds[2][0], bounds[1][0] + tagSize - 1, len(ct) - (cs/2 + 100)} {
		if PlaintextSize(int64(cut), cs) >= 0 {
			continue
		}
		if _, err := newRA(dek, ct[:cut]); !errors.Is(err, ErrTruncated) {
			t.Fatalf("cut %d: %v", cut, err)
		}
	}
	// Plausible sizes: the final chunk does not authenticate.
	for name, mod := range map[string][]byte{
		"cut inside final":  ct[:len(ct)-1],
		"cut inside chunk":  ct[:bounds[1][0]+100],
		"appended byte":     append(append([]byte(nil), ct...), 0),
		"appended chunk":    append(append([]byte(nil), ct...), ct[bounds[0][0]:bounds[0][1]]...),
		"appended file":     append(append([]byte(nil), ct...), ct...),
		"final chunk moved": append(append([]byte(nil), ct[:bounds[2][0]]...), ct[bounds[3][0]:]...),
	} {
		if _, err := newRA(dek, mod); !errors.Is(err, ErrAuth) && !errors.Is(err, ErrTruncated) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	for name, c := range map[string][2]string{"tenant": {"ten_B", fileA}, "file": {tenantA, "fil_B"}} {
		if _, err := NewReaderAt(bytes.NewReader(ct), int64(len(ct)), dek, c[0], c[1]); !errors.Is(err, ErrAuth) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if _, err := NewReaderAt(bytes.NewReader(ct), int64(len(ct)), testDEK(53), tenantA, fileA); !errors.Is(err, ErrAuth) {
		t.Fatalf("wrong dek: %v", err)
	}

	// More than 2^32 chunks.
	huge := int64(HeaderSize) + (int64(math.MaxUint32)+1)*int64(cs+tagSize) + tagSize
	if _, err := NewReaderAt(bytes.NewReader(ct[:HeaderSize]), huge, dek, tenantA, fileA); !errors.Is(err, ErrCounterOverflow) {
		t.Fatalf("overflow: %v", err)
	}
}

// failReaderAt always fails.
type failReaderAt struct{}

func (failReaderAt) ReadAt([]byte, int64) (int, error) { return 0, errBoom }

// limitedReaderAt serves src but fails (or reports EOF) from offset limit.
type limitedReaderAt struct {
	src   []byte
	limit int64
	err   error
}

func (l *limitedReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off+int64(len(p)) > l.limit {
		return 0, l.err
	}
	return copy(p, l.src[off:]), nil
}

func TestReaderAtChunkErrors(t *testing.T) {
	dek := testDEK(54)
	data := pattern(3*cs + 100)
	ct := encrypt(t, dek, tenantA, fileA, data, cs, nil)
	bounds := chunkBounds(ct, cs)

	// A tampered middle chunk: the chunks around it stay readable.
	mod := append([]byte(nil), ct...)
	mod[bounds[1][0]+5] ^= 1
	r, err := newRA(dek, mod)
	if err != nil {
		t.Fatal(err)
	}
	p := make([]byte, 2*cs)
	n, err := r.ReadAt(p, 10)
	if !errors.Is(err, ErrAuth) || n != cs-10 || !bytes.Equal(p[:n], data[10:cs]) {
		t.Fatalf("tampered chunk: n=%d %v", n, err)
	}
	if n, err := r.ReadAt(p[:cs], 0); err != nil || n != cs || !bytes.Equal(p[:cs], data[:cs]) {
		t.Fatalf("chunk 0 after failure: %v", err)
	}
	if n, err := r.ReadAt(p[:50], 2*cs); err != nil || !bytes.Equal(p[:n], data[2*cs:2*cs+50]) {
		t.Fatalf("chunk 2: %v", err)
	}
	if _, err := r.ReadAt(p[:1], cs+1); !errors.Is(err, ErrAuth) {
		t.Fatalf("tampered chunk again: %v", err)
	}

	// The source fails, or shrinks, after NewReaderAt.
	for _, e := range []error{errBoom, io.EOF} {
		src := &limitedReaderAt{src: ct, limit: int64(len(ct)), err: e}
		r, err := NewReaderAt(src, int64(len(ct)), dek, tenantA, fileA)
		if err != nil {
			t.Fatal(err)
		}
		src.limit = int64(bounds[1][0])
		if _, err := r.ReadAt(p[:1], 0); err != nil {
			t.Fatal(err)
		}
		_, err = r.ReadAt(p[:1], cs)
		want := errBoom
		if errors.Is(e, io.EOF) {
			want = ErrTruncated
		}
		if !errors.Is(err, want) {
			t.Fatalf("source %v: %v", e, err)
		}
	}
}

func TestReaderAtTamperEveryByte(t *testing.T) {
	dek := testDEK(55)
	data := pattern(2*cs + cs/2)
	ct := encrypt(t, dek, tenantA, fileA, data, cs, nil)
	for i := range ct {
		mod := append([]byte(nil), ct...)
		mod[i] ^= 0x01
		r, err := newRA(dek, mod)
		if err != nil {
			continue
		}
		got, err := readAllAt(r)
		if err == nil {
			t.Fatalf("byte %d: tampered file fully read", i)
		}
		if len(got)%cs != 0 || !bytes.Equal(got, data[:len(got)]) {
			t.Fatalf("byte %d: unauthenticated bytes returned", i)
		}
	}
}

func TestPlaintextSize(t *testing.T) {
	for _, chunk := range []int{MinChunkSize, 4000, DefaultChunkSize, MaxChunkSize} {
		for _, n := range []int64{0, 1, int64(chunk) - 1, int64(chunk), int64(chunk) + 1, 10*int64(chunk) + 7, 1 << 40} {
			if got := PlaintextSize(EncryptedSize(n, chunk), chunk); got != n {
				t.Fatalf("chunk %d n %d: %d", chunk, n, got)
			}
		}
	}
	block := int64(cs + tagSize)
	for _, c := range []struct {
		size  int64
		chunk int
	}{
		{HeaderSize + tagSize, MinChunkSize - 1},
		{HeaderSize + tagSize, MaxChunkSize + 1},
		{HeaderSize + tagSize - 1, cs},
		{-1, cs},
		{HeaderSize + block, cs},
		{HeaderSize + block + tagSize - 1, cs},
	} {
		if got := PlaintextSize(c.size, c.chunk); got != -1 {
			t.Fatalf("PlaintextSize(%d, %d) = %d", c.size, c.chunk, got)
		}
	}
}

// scriptedReader returns data, then the scripted results in order, then
// (0, io.EOF).
type scriptedReader struct {
	data   []byte
	script []scripted
}

type scripted struct {
	n   int
	err error
}

func (s *scriptedReader) Read(p []byte) (int, error) {
	if len(s.data) > 0 {
		n := copy(p, s.data)
		s.data = s.data[n:]
		return n, nil
	}
	if len(s.script) == 0 {
		return 0, io.EOF
	}
	r := s.script[0]
	s.script = s.script[1:]
	for i := range min(r.n, len(p)) {
		p[i] = 'x'
	}
	return min(r.n, len(p)), r.err
}

func TestReaderEndOfStream(t *testing.T) {
	dek := testDEK(56)
	data := pattern(cs + 10)
	ct := encrypt(t, dek, tenantA, fileA, data, cs, nil)
	zeros := func(k int) []scripted { return make([]scripted, k) }
	eof := scripted{err: io.EOF}
	cases := map[string]struct {
		script []scripted
		want   error
	}{
		"empty reads then EOF":  {append(append([]scripted{eof}, zeros(5)...), eof), nil},
		"empty reads then data": {append(append([]scripted{eof}, zeros(5)...), scripted{n: 1}), ErrTrailingData},
		"error after the end":   {[]scripted{eof, {err: errBoom}}, errBoom},
		"no progress after end": {append([]scripted{eof}, zeros(maxEmptyReads)...), io.ErrNoProgress},
	}
	for name, c := range cases {
		r, err := NewReader(&scriptedReader{data: ct, script: c.script}, dek, tenantA, fileA)
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(r)
		if c.want == nil {
			if err != nil || !bytes.Equal(got, data) {
				t.Fatalf("%s: %v", name, err)
			}
			continue
		}
		if !errors.Is(err, c.want) || !bytes.Equal(got, data[:len(got)]) || len(got)%cs != 0 {
			t.Fatalf("%s: %d bytes, %v", name, len(got), err)
		}
	}
	// A source that stops making progress in the middle of a chunk.
	r, err := NewReader(&scriptedReader{data: ct[:HeaderSize+10], script: zeros(maxEmptyReads + 1)}, dek, tenantA, fileA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(r); !errors.Is(err, io.ErrNoProgress) {
		t.Fatalf("no progress: %v", err)
	}
}

func FuzzReaderAt(f *testing.F) {
	dek := testDEK(57)
	setRand(f, &detReader{seed: "fuzz-readerat"})
	ct := encrypt(f, dek, tenantA, fileA, fuzzPlain, cs, nil)
	f.Add(ct, int64(0), uint16(100))
	f.Add(ct[:len(ct)-1], int64(cs-5), uint16(cs))
	f.Add(append(append([]byte(nil), ct...), 1), int64(0), uint16(10))
	f.Add(encrypt(f, dek, tenantA, fileA, nil, cs, nil), int64(0), uint16(1))
	f.Add([]byte("TTEF"), int64(0), uint16(1))
	f.Fuzz(func(t *testing.T, data []byte, off int64, n uint16) {
		r, err := newRA(dek, data)
		if err != nil {
			if !errors.Is(err, ErrBadHeader) && !errors.Is(err, ErrTruncated) &&
				!errors.Is(err, ErrAuth) && !errors.Is(err, ErrCounterOverflow) {
				t.Fatalf("unexpected NewReaderAt error: %v", err)
			}
			return
		}
		if r.Size() != int64(len(fuzzPlain)) && r.Size() != 0 {
			t.Fatalf("accepted a file of %d bytes", r.Size())
		}
		p := make([]byte, n)
		m, err := r.ReadAt(p, off)
		if off < 0 {
			if !errors.Is(err, ErrNegativeOffset) {
				t.Fatalf("negative offset: %v", err)
			}
			return
		}
		if m > 0 && !bytes.Equal(p[:m], fuzzPlain[off:off+int64(m)]) {
			t.Fatal("returned unauthenticated bytes")
		}
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, ErrAuth) {
			t.Fatalf("unexpected ReadAt error: %v", err)
		}
	})
}
