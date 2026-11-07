package tte2

import (
	"bytes"
	"errors"
	"io"
	"math"
	"testing"
	"testing/iotest"
)

func TestRoundTrip(t *testing.T) {
	c := testChunk
	key := testKey(1)
	for _, n := range []int{0, 1, 100, c - 1, c, c + 1, 2 * c, 2*c + 1, 3*c + 5} {
		plain := pattern(n)
		ct := encrypt(t, key, 3, c, plain)
		if got := CiphertextSize(int64(n), c); got != int64(len(ct)) {
			t.Fatalf("n=%d: CiphertextSize %d, stream %d", n, got, len(ct))
		}
		if p, ok := PlaintextSize(int64(len(ct)), c); !ok || p != int64(n) {
			t.Fatalf("n=%d: PlaintextSize %d %v", n, p, ok)
		}
		readers := map[string]func([]byte) io.Reader{
			"whole":   func(b []byte) io.Reader { return bytes.NewReader(b) },
			"onebyte": func(b []byte) io.Reader { return iotest.OneByteReader(bytes.NewReader(b)) },
			"half":    func(b []byte) io.Reader { return iotest.HalfReader(bytes.NewReader(b)) },
			"dataerr": func(b []byte) io.Reader { return iotest.DataErrReader(bytes.NewReader(b)) },
		}
		for name, mk := range readers {
			r, err := NewReader(mk(ct), key, 3)
			if err != nil {
				t.Fatalf("n=%d %s: %v", n, name, err)
			}
			if r.ChunkSize() != c {
				t.Fatalf("ChunkSize %d", r.ChunkSize())
			}
			got, err := io.ReadAll(r)
			if err != nil || !bytes.Equal(got, plain) {
				t.Fatalf("n=%d %s: err %v, equal %v", n, name, err, bytes.Equal(got, plain))
			}
			if m, err := r.Read(make([]byte, 1)); m != 0 || !errors.Is(err, io.EOF) {
				t.Fatalf("after EOF: %d %v", m, err)
			}
		}
	}
}

func TestWriterSplitWrites(t *testing.T) {
	c := testChunk
	key := testKey(2)
	plain := pattern(2*c + 77)
	var buf bytes.Buffer
	w, err := NewWriter(&buf, key, 0, WithChunkSize(c))
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range []int{1, c - 1, 1, 13, c, 63} {
		if _, err := w.Write(plain[:step]); err != nil {
			t.Fatal(err)
		}
		plain = plain[step:]
	}
	if len(plain) != 0 {
		t.Fatalf("test bug: %d left", len(plain))
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := decrypt(key, 0, buf.Bytes())
	if err != nil || !bytes.Equal(got, pattern(2*c+77)) {
		t.Fatalf("err %v", err)
	}
}

func TestDefaultChunkSize(t *testing.T) {
	key := testKey(3)
	var buf bytes.Buffer
	w, err := NewWriter(&buf, key, 0)
	if err != nil {
		t.Fatal(err)
	}
	plain := pattern(DefaultChunkSize + 1)
	if _, err := w.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if int64(buf.Len()) != CiphertextSize(int64(len(plain)), DefaultChunkSize) {
		t.Fatalf("size %d", buf.Len())
	}
	got, err := decrypt(key, 0, buf.Bytes())
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatal(err)
	}
}

func TestWriterErrors(t *testing.T) {
	key := testKey(4)
	for _, c := range []int{0, MinChunkSize / 2, MinChunkSize + 1, 3 << 16, MaxChunkSize * 2} {
		if _, err := NewWriter(io.Discard, key, 0, WithChunkSize(c)); !errors.Is(err, ErrInvalidChunkSize) {
			t.Fatalf("chunk %d: %v", c, err)
		}
	}
	if _, err := NewWriter(io.Discard, key[:31], 0); !errors.Is(err, ErrInvalidKey) {
		t.Fatal(err)
	}
	for _, idx := range []int{-1, MaxIndex + 1} {
		if _, err := NewWriter(io.Discard, key, idx); !errors.Is(err, ErrInvalidIndex) {
			t.Fatalf("index %d: %v", idx, err)
		}
	}
	t.Run("rand", func(t *testing.T) {
		withRand(t, iotest.ErrReader(errWrite))
		if _, err := NewWriter(io.Discard, key, 0); !errors.Is(err, errWrite) {
			t.Fatal(err)
		}
	})
	if _, err := NewWriter(&limitWriter{limit: 10}, key, 0); !errors.Is(err, errWrite) {
		t.Fatal(err)
	}
	if _, err := NewWriter(&limitWriter{limit: 10, short: true}, key, 0); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal(err)
	}

	// A failing chunk write is sticky.
	w, err := NewWriter(&limitWriter{limit: HeaderSize}, key, 0, WithChunkSize(testChunk))
	if err != nil {
		t.Fatal(err)
	}
	n, err := w.Write(pattern(testChunk + 1))
	if !errors.Is(err, errWrite) || n != testChunk {
		t.Fatalf("write: %d %v", n, err)
	}
	if _, err := w.Write([]byte{1}); !errors.Is(err, errWrite) {
		t.Fatal(err)
	}
	if err := w.Close(); !errors.Is(err, errWrite) {
		t.Fatal(err)
	}

	// Closed writer.
	w, err = NewWriter(io.Discard, key, 0, WithChunkSize(testChunk))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte{1}); !errors.Is(err, ErrWriterClosed) {
		t.Fatal(err)
	}
	if err := w.Close(); !errors.Is(err, ErrWriterClosed) {
		t.Fatal(err)
	}

	// Counter overflow: a middle chunk at the last counter value.
	w, err = NewWriter(io.Discard, key, 0, WithChunkSize(testChunk))
	if err != nil {
		t.Fatal(err)
	}
	w.counter = math.MaxUint32
	if _, err := w.Write(pattern(testChunk + 1)); !errors.Is(err, ErrCounterOverflow) {
		t.Fatal(err)
	}
}

func TestReaderErrors(t *testing.T) {
	c := testChunk
	key := testKey(5)
	three := encrypt(t, key, 1, c, pattern(2*c+100)) // two middle chunks, short final
	two := encrypt(t, key, 1, c, pattern(2*c))       // one middle chunk, full final
	one := encrypt(t, key, 1, c, pattern(10))
	empty := encrypt(t, key, 1, c, nil)
	head := three[:HeaderSize]
	a0, b0 := chunkAt(c, 0)
	a1, b1 := chunkAt(c, 1)
	c0, c1, rest := three[a0:b0], three[a1:b1], three[b1:]

	flip := func(b []byte, i int) []byte {
		out := bytes.Clone(b)
		out[i] ^= 0x01
		return out
	}
	withHeaderByte := func(b []byte, i int, v byte) []byte {
		out := bytes.Clone(b)
		out[i] = v
		return out
	}

	// Forged stream: a middle chunk then an empty final chunk, sealed with
	// the right key.
	h, _ := ParseHeader(head)
	aead := fileAEAD(key, 1, &h)
	n0 := chunkNonce(0, false)
	n1 := chunkNonce(1, true)
	forged := cat(head, aead.Seal(nil, n0[:], pattern(c), head), aead.Seal(nil, n1[:], nil, head))

	cases := []struct {
		name  string
		ct    []byte
		key   []byte
		index int
		want  error
	}{
		{"reordered", cat(head, c1, c0, rest), key, 1, ErrAuth},
		{"duplicated", cat(head, c0, c0, c1, rest), key, 1, ErrAuth},
		{"missing final", cat(head, c0, c1), key, 1, ErrTruncated},
		{"missing middle", cat(head, c0, rest), key, 1, ErrAuth},
		{"trailing after full final", cat(two, []byte{0}), key, 1, ErrTrailingData},
		{"trailing after short final", cat(three, []byte{0}), key, 1, ErrAuth},
		{"truncated in final", three[:len(three)-1], key, 1, ErrAuth},
		{"truncated in middle", three[:b0-1], key, 1, ErrAuth},
		{"short final", cat(head, c0, c1, rest[:TagSize-1]), key, 1, ErrTruncated},
		{"header only", head, key, 1, ErrTruncated},
		{"short header", head[:10], key, 1, ErrTruncated},
		{"no data", nil, key, 1, ErrTruncated},
		{"wrong index", three, key, 2, ErrAuth},
		{"wrong key", three, testKey(6), 1, ErrAuth},
		{"wrong key empty", empty, testKey(6), 1, ErrAuth},
		{"wrong key one", one, testKey(6), 1, ErrAuth},
		{"flipped chunk bit", flip(three, a1+5), key, 1, ErrAuth},
		{"flipped tag bit", flip(three, len(three)-1), key, 1, ErrAuth},
		{"flipped salt bit", flip(three, 20), key, 1, ErrAuth},
		{"chunk size changed", withHeaderByte(three, 9, 0x02), key, 1, ErrAuth},
		{"bad magic", withHeaderByte(three, 0, 'X'), key, 1, ErrBadHeader},
		{"bad version", withHeaderByte(three, 4, 2), key, 1, ErrBadHeader},
		{"bad kind", withHeaderByte(three, 5, 2), key, 1, ErrBadHeader},
		{"reserved 6", withHeaderByte(three, 6, 1), key, 1, ErrBadHeader},
		{"reserved 7", withHeaderByte(three, 7, 1), key, 1, ErrBadHeader},
		{"reserved 31", withHeaderByte(three, 31, 1), key, 1, ErrBadHeader},
		{"chunk not power of two", withHeaderByte(three, 11, 1), key, 1, ErrBadHeader},
		{"chunk too large", withHeaderByte(three, 8, 1), key, 1, ErrBadHeader},
		{"empty final after data", forged, key, 1, ErrFormat},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decrypt(tc.key, tc.index, tc.ct)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			if len(tc.ct) > HeaderSize && len(got) > len(tc.ct) {
				t.Fatal("more plaintext than ciphertext")
			}
		})
	}
}

func TestReaderNeverReturnsUnauthenticatedFinal(t *testing.T) {
	c := testChunk
	key := testKey(7)
	ct := encrypt(t, key, 0, c, pattern(c+10))
	ct[len(ct)-1] ^= 1
	r, err := NewReader(bytes.NewReader(ct), key, 0)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(r)
	if !errors.Is(err, ErrAuth) || len(got) != c {
		t.Fatalf("got %d bytes, %v", len(got), err)
	}
	if _, err2 := r.Read(make([]byte, 1)); !errors.Is(err2, ErrAuth) {
		t.Fatal("error not sticky")
	}
}

func TestReaderSourceErrors(t *testing.T) {
	c := testChunk
	key := testKey(8)
	ct := encrypt(t, key, 0, c, pattern(2*c))
	if _, err := NewReader(nil, key[:1], 0); !errors.Is(err, ErrInvalidKey) {
		t.Fatal(err)
	}
	if _, err := NewReader(nil, key, -1); !errors.Is(err, ErrInvalidIndex) {
		t.Fatal(err)
	}
	if _, err := NewReader(iotest.ErrReader(errWrite), key, 0); !errors.Is(err, errWrite) {
		t.Fatal(err)
	}
	r, err := NewReader(&errReader{data: ct[:HeaderSize+100], err: errWrite}, key, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(r); !errors.Is(err, errWrite) {
		t.Fatal(err)
	}
	r, err = NewReader(&stallReader{data: ct[:HeaderSize+100]}, key, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(r); !errors.Is(err, io.ErrNoProgress) {
		t.Fatal(err)
	}
	if n, err := r.Read(nil); n != 0 || err != nil {
		t.Fatal("empty read")
	}
}

func TestReaderCounterOverflow(t *testing.T) {
	c := testChunk
	key := testKey(9)
	ct := encrypt(t, key, 0, c, pattern(2*c))
	r, err := NewReader(bytes.NewReader(ct), key, 0)
	if err != nil {
		t.Fatal(err)
	}
	r.counter = math.MaxUint32
	if _, err := io.ReadAll(r); !errors.Is(err, ErrCounterOverflow) {
		t.Fatal(err)
	}
}
