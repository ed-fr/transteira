package crypto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"math/rand/v2"
	"runtime"
	"testing"
	"testing/iotest"
)

const (
	tenantA = "ten_A"
	fileA   = "fil_A"
	cs      = MinChunkSize // small chunk size used by most tests
)

func TestStreamRoundTrip(t *testing.T) {
	dek := testDEK(1)
	rng := rand.New(rand.NewPCG(1, 2))
	sizes := []int{0, 1, 15, 16, 17, cs - 1, cs, cs + 1, 2*cs - 1, 2 * cs, 2*cs + 1, 5*cs + 123, 8 * cs}
	patterns := map[string][]int{
		"single":   nil,
		"bytes":    {1},
		"chunk":    {cs},
		"odd":      {7, 1000, 1, 3000},
		"chunk+1":  {cs + 1},
		"chunk-1":  {cs - 1},
		"variable": {rng.IntN(3 * cs), rng.IntN(cs), rng.IntN(100), rng.IntN(5 * cs)},
	}
	for _, n := range sizes {
		data := pattern(n)
		for name, pieces := range patterns {
			ct := encrypt(t, dek, tenantA, fileA, data, cs, pieces)
			if int64(len(ct)) != EncryptedSize(int64(n), cs) {
				t.Fatalf("size %d %s: ciphertext %d bytes, EncryptedSize %d", n, name, len(ct), EncryptedSize(int64(n), cs))
			}
			got, err := decrypt(dek, tenantA, fileA, ct)
			if err != nil || !bytes.Equal(got, data) {
				t.Fatalf("size %d %s: decrypt err=%v equal=%v", n, name, err, bytes.Equal(got, data))
			}
			// Small reads and short source reads.
			r, err := NewReader(iotest.HalfReader(bytes.NewReader(ct)), dek, tenantA, fileA)
			if err != nil {
				t.Fatal(err)
			}
			got, err = io.ReadAll(iotest.OneByteReader(r))
			if err != nil || !bytes.Equal(got, data) {
				t.Fatalf("size %d %s: byte reads err=%v", n, name, err)
			}
			// A source returning its last bytes together with io.EOF.
			got, err = decryptFrom(iotest.DataErrReader(iotest.HalfReader(bytes.NewReader(ct))), dek)
			if err != nil || !bytes.Equal(got, data) {
				t.Fatalf("size %d %s: data+EOF reads err=%v", n, name, err)
			}
		}
	}
}

// decryptFrom decrypts the file of tenantA/fileA read from src.
func decryptFrom(src io.Reader, dek []byte) ([]byte, error) {
	r, err := NewReader(src, dek, tenantA, fileA)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

func TestStreamDefaultChunkSize(t *testing.T) {
	dek := testDEK(2)
	data := pattern(DefaultChunkSize*2 + 10)
	var out bytes.Buffer
	w, err := NewWriter(&out, dek, tenantA, fileA)
	if err != nil {
		t.Fatal(err)
	}
	writePieces(t, w, data, nil)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint32(out.Bytes()[5:9]) != DefaultChunkSize {
		t.Fatal("default chunk size not recorded")
	}
	if int64(out.Len()) != EncryptedSize(int64(len(data)), DefaultChunkSize) {
		t.Fatal("EncryptedSize mismatch")
	}
	got, err := decrypt(dek, tenantA, fileA, out.Bytes())
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("decrypt: %v", err)
	}
	// Maximal chunk size round trip.
	ct := encrypt(t, dek, tenantA, fileA, pattern(MaxChunkSize+1), MaxChunkSize, nil)
	if got, err := decrypt(dek, tenantA, fileA, ct); err != nil || len(got) != MaxChunkSize+1 {
		t.Fatalf("max chunk size: %v", err)
	}
}

func TestStreamLayout(t *testing.T) {
	dek := testDEK(3)
	ct := encrypt(t, dek, tenantA, fileA, pattern(2*cs+cs/2), cs, nil)
	if string(ct[:4]) != "TTEF" || ct[4] != 1 || binary.BigEndian.Uint32(ct[5:9]) != cs {
		t.Fatalf("header: %x", ct[:HeaderSize])
	}
	if len(ct) != HeaderSize+2*(cs+tagSize)+cs/2+tagSize {
		t.Fatalf("length %d", len(ct))
	}
	// Empty plaintext: header and an empty final chunk (tag only).
	empty := encrypt(t, dek, tenantA, fileA, nil, cs, nil)
	if len(empty) != HeaderSize+tagSize {
		t.Fatalf("empty file length %d", len(empty))
	}
	// Multiple of the chunk size: a trailing empty final chunk.
	exact := encrypt(t, dek, tenantA, fileA, pattern(2*cs), cs, nil)
	if len(exact) != HeaderSize+2*(cs+tagSize)+tagSize {
		t.Fatalf("exact multiple length %d", len(exact))
	}
}

func TestEncryptedSizeInvalid(t *testing.T) {
	for _, c := range []struct {
		n  int64
		cs int
	}{{-1, cs}, {0, MinChunkSize - 1}, {0, MaxChunkSize + 1}, {0, 0}} {
		if got := EncryptedSize(c.n, c.cs); got != -1 {
			t.Fatalf("EncryptedSize(%d, %d) = %d", c.n, c.cs, got)
		}
	}
	if EncryptedSize(0, cs) != HeaderSize+tagSize {
		t.Fatal("empty size")
	}
}

// chunkBounds returns the [start, end) offsets of every chunk of ct.
func chunkBounds(ct []byte, chunkSize int) [][2]int {
	var b [][2]int
	for off := HeaderSize; off < len(ct); off += chunkSize + tagSize {
		b = append(b, [2]int{off, min(off+chunkSize+tagSize, len(ct))})
	}
	return b
}

// assertAuthenticatedPrefix reads ct and checks that the read fails with an
// error and that everything returned before is a chunk-aligned prefix of data.
func assertAuthenticatedPrefix(t *testing.T, dek []byte, ct, data []byte, chunkSize int) error {
	t.Helper()
	r, err := NewReader(bytes.NewReader(ct), dek, tenantA, fileA)
	if err != nil {
		return err
	}
	got, err := io.ReadAll(r)
	if err == nil {
		t.Fatal("altered ciphertext accepted")
	}
	if len(got)%chunkSize != 0 || !bytes.Equal(got, data[:len(got)]) {
		t.Fatalf("returned %d unauthenticated bytes", len(got))
	}
	return err
}

func TestStreamTamperEveryByte(t *testing.T) {
	dek := testDEK(4)
	data := pattern(2*cs + cs/2)
	ct := encrypt(t, dek, tenantA, fileA, data, cs, nil)
	for i := range ct {
		mod := append([]byte(nil), ct...)
		mod[i] ^= 0x01
		err := assertAuthenticatedPrefix(t, dek, mod, data, cs)
		switch {
		case i < 5: // magic and version
			if !errors.Is(err, ErrBadHeader) {
				t.Fatalf("byte %d: %v, want ErrBadHeader", i, err)
			}
		case i < 9: // chunk size: either out of range or misaligned chunks
			if !errors.Is(err, ErrBadHeader) && !errors.Is(err, ErrAuth) && !errors.Is(err, ErrTruncated) {
				t.Fatalf("byte %d: %v", i, err)
			}
		default: // nonce prefix, chunk bodies and tags
			if !errors.Is(err, ErrAuth) {
				t.Fatalf("byte %d: %v, want ErrAuth", i, err)
			}
		}
	}
}

func TestStreamBadHeader(t *testing.T) {
	dek := testDEK(5)
	ct := encrypt(t, dek, tenantA, fileA, pattern(10), cs, nil)
	for name, mutate := range map[string]func([]byte){
		"magic":       func(b []byte) { copy(b, "TTEX") },
		"version 0":   func(b []byte) { b[4] = 0 },
		"version 2":   func(b []byte) { b[4] = 2 },
		"chunk small": func(b []byte) { binary.BigEndian.PutUint32(b[5:9], MinChunkSize-1) },
		"chunk large": func(b []byte) { binary.BigEndian.PutUint32(b[5:9], MaxChunkSize+1) },
		"chunk zero":  func(b []byte) { binary.BigEndian.PutUint32(b[5:9], 0) },
		"chunk max":   func(b []byte) { binary.BigEndian.PutUint32(b[5:9], math.MaxUint32) },
	} {
		mod := append([]byte(nil), ct...)
		mutate(mod)
		if _, err := NewReader(bytes.NewReader(mod), dek, tenantA, fileA); !errors.Is(err, ErrBadHeader) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestStreamTruncation(t *testing.T) {
	dek := testDEK(6)
	for _, n := range []int{0, cs / 2, cs, 3*cs + 100, 3 * cs} {
		data := pattern(n)
		ct := encrypt(t, dek, tenantA, fileA, data, cs, nil)
		// Inside the header.
		for i := range HeaderSize {
			if _, err := decrypt(dek, tenantA, fileA, ct[:i]); !errors.Is(err, ErrTruncated) {
				t.Fatalf("n=%d header cut %d: %v", n, i, err)
			}
		}
		// At every chunk boundary before the final chunk.
		bounds := chunkBounds(ct, cs)
		for _, b := range bounds[:len(bounds)-1] {
			for _, cut := range []int{b[0], b[1]} {
				err := assertAuthenticatedPrefix(t, dek, ct[:cut], data, cs)
				if !errors.Is(err, ErrTruncated) {
					t.Fatalf("n=%d boundary cut %d: %v", n, cut, err)
				}
			}
		}
		// Header only.
		if _, err := decrypt(dek, tenantA, fileA, ct[:HeaderSize]); !errors.Is(err, ErrTruncated) {
			t.Fatalf("n=%d header only: %v", n, err)
		}
		// Inside every chunk.
		for _, b := range bounds {
			for _, cut := range []int{b[0] + 1, b[0] + tagSize - 1, b[0] + tagSize, b[1] - 1} {
				if cut <= b[0] || cut >= b[1] {
					continue
				}
				err := assertAuthenticatedPrefix(t, dek, ct[:cut], data, cs)
				if !errors.Is(err, ErrAuth) && !errors.Is(err, ErrTruncated) {
					t.Fatalf("n=%d inner cut %d: %v", n, cut, err)
				}
			}
		}
	}
}

func TestStreamReorderDuplicateDrop(t *testing.T) {
	dek := testDEK(7)
	data := pattern(4*cs + 10)
	ct := encrypt(t, dek, tenantA, fileA, data, cs, nil)
	b := chunkBounds(ct, cs)
	chunk := func(i int) []byte { return ct[b[i][0]:b[i][1]] }
	build := func(order ...int) []byte {
		out := append([]byte(nil), ct[:HeaderSize]...)
		for _, i := range order {
			out = append(out, chunk(i)...)
		}
		return out
	}
	for name, order := range map[string][]int{
		"swap 0 1":         {1, 0, 2, 3, 4},
		"swap 2 3":         {0, 1, 3, 2, 4},
		"duplicate 0":      {0, 0, 1, 2, 3, 4},
		"duplicate 2":      {0, 1, 2, 2, 3, 4},
		"drop 1":           {0, 2, 3, 4},
		"final early":      {0, 1, 4},
		"final duplicated": {0, 1, 2, 3, 4, 4},
		"final moved":      {4, 0, 1, 2, 3},
	} {
		err := assertAuthenticatedPrefix(t, dek, build(order...), data, cs)
		if !errors.Is(err, ErrAuth) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	// Chunks spliced from another file encrypted with the same DEK.
	other := encrypt(t, dek, tenantA, fileA, data, cs, nil)
	spliced := append(append([]byte(nil), ct[:b[1][0]]...), other[b[1][0]:]...)
	if err := assertAuthenticatedPrefix(t, dek, spliced, data, cs); !errors.Is(err, ErrAuth) {
		t.Fatalf("spliced: %v", err)
	}
}

func TestStreamTrailingData(t *testing.T) {
	dek := testDEK(8)
	for _, n := range []int{0, 10, cs, 2*cs + 5} {
		data := pattern(n)
		ct := encrypt(t, dek, tenantA, fileA, data, cs, nil)
		// Appended bytes change the final chunk: authentication fails.
		for _, extra := range [][]byte{{0}, bytes.Repeat([]byte{1}, 40), bytes.Repeat([]byte{2}, cs+tagSize)} {
			mod := append(append([]byte(nil), ct...), extra...)
			if err := assertAuthenticatedPrefix(t, dek, mod, data, cs); !errors.Is(err, ErrAuth) {
				t.Fatalf("n=%d +%d bytes: %v", n, len(extra), err)
			}
		}
		// A whole valid file appended after the final chunk.
		mod := append(append([]byte(nil), ct...), ct...)
		if err := assertAuthenticatedPrefix(t, dek, mod, data, cs); !errors.Is(err, ErrAuth) {
			t.Fatalf("n=%d doubled: %v", n, err)
		}
		// Data showing up after the authenticated final chunk.
		r, err := NewReader(&eofThenMore{data: ct, extra: []byte("x")}, dek, tenantA, fileA)
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(r)
		if !errors.Is(err, ErrTrailingData) || len(got)%cs != 0 || !bytes.Equal(got, data[:len(got)]) {
			t.Fatalf("n=%d trailing: %d bytes, %v", n, len(got), err)
		}
		// The same source without extra data is fine.
		r, err = NewReader(&eofThenMore{data: ct}, dek, tenantA, fileA)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := io.ReadAll(r); err != nil || !bytes.Equal(got, data) {
			t.Fatalf("n=%d no trailing: %v", n, err)
		}
	}
}

func TestStreamWrongBinding(t *testing.T) {
	dek := testDEK(9)
	data := pattern(cs + 1)
	ct := encrypt(t, dek, tenantA, fileA, data, cs, nil)
	for name, c := range map[string]struct {
		dek            []byte
		tenant, fileID string
	}{
		"dek":     {testDEK(10), tenantA, fileA},
		"tenant":  {dek, "ten_B", fileA},
		"file":    {dek, tenantA, "fil_B"},
		"swapped": {dek, fileA, tenantA},
		"shifted": {dek, tenantA + "f", "il_A"},
	} {
		got, err := decrypt(c.dek, c.tenant, c.fileID, ct)
		if !errors.Is(err, ErrAuth) || len(got) != 0 {
			t.Fatalf("%s: %d bytes, %v", name, len(got), err)
		}
	}
}

func TestNewWriterErrors(t *testing.T) {
	dek := testDEK(11)
	var out bytes.Buffer
	if _, err := NewWriter(&out, dek[:31], tenantA, fileA); !errors.Is(err, ErrKeySize) {
		t.Fatalf("short dek: %v", err)
	}
	if _, err := NewWriter(&out, append(dek, 0), tenantA, fileA); !errors.Is(err, ErrKeySize) {
		t.Fatalf("long dek: %v", err)
	}
	if _, err := NewWriter(&out, dek, "", fileA); !errors.Is(err, ErrInvalidBinding) {
		t.Fatalf("empty tenant: %v", err)
	}
	if _, err := NewWriter(&out, dek, tenantA, ""); !errors.Is(err, ErrInvalidBinding) {
		t.Fatalf("empty file: %v", err)
	}
	for _, n := range []int{0, MinChunkSize - 1, MaxChunkSize + 1, -1} {
		if _, err := NewWriter(&out, dek, tenantA, fileA, WithChunkSize(n)); !errors.Is(err, ErrInvalidChunkSize) {
			t.Fatalf("chunk size %d: %v", n, err)
		}
	}
	if out.Len() != 0 {
		t.Fatal("failed NewWriter wrote data")
	}
	if _, err := NewWriter(&failWriter{limit: 0}, dek, tenantA, fileA); !errors.Is(err, errBoom) {
		t.Fatalf("header write: %v", err)
	}
	if _, err := NewWriter(shortWriter{}, dek, tenantA, fileA); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short header write: %v", err)
	}
	setRand(t, errReader{})
	if _, err := NewWriter(&out, dek, tenantA, fileA); !errors.Is(err, errBoom) {
		t.Fatalf("rand failure: %v", err)
	}
}

func TestWriterStickyError(t *testing.T) {
	dek := testDEK(12)
	fw := &failWriter{limit: HeaderSize + cs + tagSize}
	w, err := NewWriter(fw, dek, tenantA, fileA, WithChunkSize(cs))
	if err != nil {
		t.Fatal(err)
	}
	if n, err := w.Write(pattern(cs + 10)); err != nil || n != cs+10 {
		t.Fatalf("first chunk: %d, %v", n, err)
	}
	n, err := w.Write(pattern(2 * cs))
	if !errors.Is(err, errBoom) || n != cs-10 {
		t.Fatalf("second chunk: %d, %v", n, err)
	}
	if _, err := w.Write([]byte{1}); !errors.Is(err, errBoom) {
		t.Fatalf("write after error: %v", err)
	}
	if _, err := w.Checkpoint(nil); !errors.Is(err, errBoom) {
		t.Fatalf("checkpoint after error: %v", err)
	}
	if err := w.Close(); !errors.Is(err, errBoom) {
		t.Fatalf("close after error: %v", err)
	}

	// Failure of the final chunk.
	fw = &failWriter{limit: HeaderSize}
	w, err = NewWriter(fw, dek, tenantA, fileA, WithChunkSize(cs))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); !errors.Is(err, errBoom) {
		t.Fatalf("final chunk: %v", err)
	}
	if err := w.Close(); !errors.Is(err, errBoom) {
		t.Fatalf("second close: %v", err)
	}
}

func TestWriterClosed(t *testing.T) {
	var out bytes.Buffer
	w, err := NewWriter(&out, testDEK(13), tenantA, fileA)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	size := out.Len()
	if err := w.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := w.Write([]byte{1}); !errors.Is(err, ErrWriterClosed) {
		t.Fatalf("Write after Close: %v", err)
	}
	if _, err := w.Checkpoint(nil); !errors.Is(err, ErrWriterClosed) {
		t.Fatalf("Checkpoint after Close: %v", err)
	}
	if out.Len() != size {
		t.Fatal("closed writer wrote data")
	}
	if n, err := w.Write(nil); n != 0 || !errors.Is(err, ErrWriterClosed) {
		t.Fatalf("empty Write after Close: %d, %v", n, err)
	}
}

func TestWriterCounterOverflow(t *testing.T) {
	dek := testDEK(14)
	data := pattern(cs)

	// The last two counter values: one full chunk then the final chunk.
	var out bytes.Buffer
	w, err := NewWriter(&out, dek, tenantA, fileA, WithChunkSize(cs))
	if err != nil {
		t.Fatal(err)
	}
	w.counter = math.MaxUint32 - 1
	writePieces(t, w, data, nil)
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	ct := out.Bytes()

	r, err := NewReader(bytes.NewReader(ct), dek, tenantA, fileA)
	if err != nil {
		t.Fatal(err)
	}
	r.counter = math.MaxUint32 - 1
	if got, err := io.ReadAll(r); err != nil || !bytes.Equal(got, data) {
		t.Fatalf("read near overflow: %v", err)
	}
	r, err = NewReader(bytes.NewReader(ct), dek, tenantA, fileA)
	if err != nil {
		t.Fatal(err)
	}
	r.counter = math.MaxUint32
	if _, err := io.ReadAll(r); !errors.Is(err, ErrCounterOverflow) {
		t.Fatalf("reader overflow: %v", err)
	}

	// A full chunk may not take the last counter value.
	w, err = NewWriter(io.Discard, dek, tenantA, fileA, WithChunkSize(cs))
	if err != nil {
		t.Fatal(err)
	}
	w.counter = math.MaxUint32 - 1
	if _, err := w.Write(pattern(2 * cs)); !errors.Is(err, ErrCounterOverflow) {
		t.Fatalf("writer overflow: %v", err)
	}
	if err := w.Close(); !errors.Is(err, ErrCounterOverflow) {
		t.Fatalf("close after overflow: %v", err)
	}

	// The final chunk alone may take it.
	w, err = NewWriter(io.Discard, dek, tenantA, fileA, WithChunkSize(cs))
	if err != nil {
		t.Fatal(err)
	}
	w.counter = math.MaxUint32
	writePieces(t, w, pattern(cs-1), nil)
	if err := w.Close(); err != nil {
		t.Fatalf("final chunk at max counter: %v", err)
	}
}

func TestNewReaderErrors(t *testing.T) {
	dek := testDEK(15)
	ct := encrypt(t, dek, tenantA, fileA, pattern(10), cs, nil)
	if _, err := NewReader(bytes.NewReader(ct), dek[:16], tenantA, fileA); !errors.Is(err, ErrKeySize) {
		t.Fatalf("dek: %v", err)
	}
	if _, err := NewReader(bytes.NewReader(ct), dek, tenantA, ""); !errors.Is(err, ErrInvalidBinding) {
		t.Fatalf("binding: %v", err)
	}
	if _, err := NewReader(errReader{}, dek, tenantA, fileA); !errors.Is(err, errBoom) {
		t.Fatalf("read error: %v", err)
	}
	if _, err := NewReader(bytes.NewReader(nil), dek, tenantA, fileA); !errors.Is(err, ErrTruncated) {
		t.Fatalf("empty: %v", err)
	}
}

func TestReaderErrors(t *testing.T) {
	dek := testDEK(16)
	data := pattern(3 * cs)
	ct := encrypt(t, dek, tenantA, fileA, data, cs, nil)

	// Source failure after the first chunk, sticky.
	r, err := NewReader(&failAfterReader{data: ct[:HeaderSize+cs+tagSize]}, dek, tenantA, fileA)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(r)
	if !errors.Is(err, errBoom) || !bytes.Equal(got, data[:cs]) {
		t.Fatalf("source failure: %d bytes, %v", len(got), err)
	}
	if _, err := r.Read(make([]byte, 1)); !errors.Is(err, errBoom) {
		t.Fatalf("sticky error: %v", err)
	}

	// Empty reads, EOF repeated.
	r, err = NewReader(bytes.NewReader(ct), dek, tenantA, fileA)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := r.Read(nil); n != 0 || err != nil {
		t.Fatalf("empty read: %d, %v", n, err)
	}
	if _, err := io.ReadAll(r); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if n, err := r.Read(make([]byte, 8)); n != 0 || !errors.Is(err, io.EOF) {
			t.Fatalf("after EOF: %d, %v", n, err)
		}
	}
	// iotest checks the io.Reader contract.
	r, err = NewReader(bytes.NewReader(ct), dek, tenantA, fileA)
	if err != nil {
		t.Fatal(err)
	}
	if err := iotest.TestReader(r, data); err != nil {
		t.Fatal(err)
	}
}

func TestNoPlaintextInCiphertext(t *testing.T) {
	marker := []byte("TRANSTEIRA-PLAINTEXT-MARKER-")
	data := bytes.Repeat(marker, (5*cs)/len(marker)+3)
	dek := testDEK(17)
	var out bytes.Buffer
	w, err := NewWriter(&out, dek, tenantA, fileA, WithChunkSize(cs))
	if err != nil {
		t.Fatal(err)
	}
	writePieces(t, w, data[:len(data)/2], []int{100})
	st, err := w.Checkpoint(bytes.Repeat(marker, 30))
	if err != nil {
		t.Fatal(err)
	}
	sb, err := st.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	writePieces(t, w, data[len(data)/2:], []int{333})
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	for _, blob := range [][]byte{out.Bytes(), sb} {
		for i := 0; i+12 <= len(marker); i++ {
			if bytes.Contains(blob, marker[i:i+12]) {
				t.Fatal("plaintext visible in output")
			}
		}
	}
}

func TestNonceUniqueness(t *testing.T) {
	dek := testDEK(18)
	seen := make(map[[nonceSize]byte]string)
	add := func(n [nonceSize]byte, what string) {
		if prev, dup := seen[n]; dup {
			t.Fatalf("nonce reused: %s and %s", prev, what)
		}
		seen[n] = what
	}
	for f := range 200 {
		var out bytes.Buffer
		w, err := NewWriter(&out, dek, tenantA, fileA, WithChunkSize(cs))
		if err != nil {
			t.Fatal(err)
		}
		data := pattern(3*cs + f)
		for i, piece := range [][]byte{data[:cs/2], data[cs/2 : 2*cs+7], data[2*cs+7:]} {
			writePieces(t, w, piece, nil)
			st, err := w.Checkpoint(nil)
			if err != nil {
				t.Fatal(err)
			}
			for range 2 { // repeated checkpoints get fresh nonces
				var n [nonceSize]byte
				copy(n[:], st.tail[1:1+nonceSize])
				add(n, "tail")
				st, err = w.Checkpoint(nil)
				if err != nil {
					t.Fatal(err)
				}
			}
			if i == 1 {
				// Resume from this checkpoint into a throwaway destination:
				// the chunk counters continue, never restart.
				rw, _, err := ResumeWriter(io.Discard, dek, tenantA, fileA, st, st.CiphertextSize())
				if err != nil {
					t.Fatal(err)
				}
				if rw.counter != w.counter {
					t.Fatal("resumed counter differs")
				}
			}
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		var h header
		copy(h[:], out.Bytes())
		chunks := len(chunkBounds(out.Bytes(), cs))
		for c := range chunks {
			add(h.nonce(uint32(c), c == chunks-1), "chunk")
		}
	}
	if len(seen) < 200*(4+6) {
		t.Fatalf("only %d nonces collected", len(seen))
	}
}

func TestReaderBoundedAllocation(t *testing.T) {
	dek := testDEK(19)
	// A forged header announcing the largest chunk size, followed by a few
	// bytes: the reader must not allocate a full chunk up front.
	ct := encrypt(t, dek, tenantA, fileA, pattern(10), cs, nil)
	binary.BigEndian.PutUint32(ct[5:9], MaxChunkSize)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for range 10 {
		if _, err := decrypt(dek, tenantA, fileA, ct); !errors.Is(err, ErrAuth) {
			t.Fatalf("forged header: %v", err)
		}
	}
	runtime.ReadMemStats(&after)
	if delta := after.TotalAlloc - before.TotalAlloc; delta > 4<<20 {
		t.Fatalf("10 short reads allocated %d bytes", delta)
	}
}
