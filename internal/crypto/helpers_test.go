package crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

// testKeyB64 is the fixed master key of the tests: bytes 0x00..0x1f, public
// by design (not a secret).
const testKeyB64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=" // gitleaks:allow

// errBoom is returned by the failing test doubles.
var errBoom = errors.New("boom")

// detReader is a deterministic byte source: SHA-256(seed | counter) blocks.
type detReader struct {
	seed    string
	counter uint64
	buf     []byte
}

func (d *detReader) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		if len(d.buf) == 0 {
			h := sha256.New()
			h.Write([]byte(d.seed))
			_ = binary.Write(h, binary.BigEndian, d.counter)
			d.counter++
			d.buf = h.Sum(nil)
		}
		c := copy(p[n:], d.buf)
		d.buf = d.buf[c:]
		n += c
	}
	return n, nil
}

// errReader always fails.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errBoom }

// setRand replaces randReader for the duration of the test.
func setRand(t testing.TB, r io.Reader) {
	t.Helper()
	old := randReader
	randReader = r
	t.Cleanup(func() { randReader = old })
}

// testKey parses the fixed test master key.
func testKey(t testing.TB) *MasterKey {
	t.Helper()
	k, err := ParseMasterKey([]byte(testKeyB64))
	if err != nil {
		t.Fatalf("ParseMasterKey: %v", err)
	}
	return k
}

// otherKey returns a master key different from testKey.
func otherKey(t testing.TB) *MasterKey {
	t.Helper()
	raw := bytes.Repeat([]byte{0xA5, 0x5A}, MasterKeySize/2)
	k, err := ParseMasterKey([]byte(base64.StdEncoding.EncodeToString(raw)))
	if err != nil {
		t.Fatalf("ParseMasterKey: %v", err)
	}
	return k
}

// testDEK returns a fixed data encryption key derived from seed.
func testDEK(seed byte) []byte {
	dek := make([]byte, DEKSize)
	for i := range dek {
		dek[i] = seed + byte(i)
	}
	return dek
}

// pattern returns n deterministic plaintext bytes.
func pattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte((i*7 + i/251) % 251)
	}
	return b
}

// failWriter accepts limit bytes, then fails.
type failWriter struct {
	limit int
	buf   bytes.Buffer
}

func (f *failWriter) Write(p []byte) (int, error) {
	if f.buf.Len()+len(p) > f.limit {
		return 0, errBoom
	}
	return f.buf.Write(p)
}

// shortWriter reports writing one byte less than asked, without error.
type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }

// failAfterReader returns data, then errBoom.
type failAfterReader struct {
	data []byte
}

func (f *failAfterReader) Read(p []byte) (int, error) {
	if len(f.data) == 0 {
		return 0, errBoom
	}
	n := copy(p, f.data)
	f.data = f.data[n:]
	return n, nil
}

// eofThenMore returns data, then io.EOF once, then extra: a source that grows
// after the reader saw its end.
type eofThenMore struct {
	data    []byte
	sentEOF bool
	extra   []byte
}

func (e *eofThenMore) Read(p []byte) (int, error) {
	if len(e.data) > 0 {
		n := copy(p, e.data)
		e.data = e.data[n:]
		return n, nil
	}
	if !e.sentEOF {
		e.sentEOF = true
		return 0, io.EOF
	}
	if len(e.extra) == 0 {
		return 0, io.EOF
	}
	n := copy(p, e.extra)
	e.extra = e.extra[n:]
	return n, nil
}

// encrypt encrypts data with chunk size cs, writing it in pieces of the given
// sizes (cycled; nil means one write).
func encrypt(t testing.TB, dek []byte, tenantID, fileID string, data []byte, cs int, pieces []int) []byte {
	t.Helper()
	var out bytes.Buffer
	w, err := NewWriter(&out, dek, tenantID, fileID, WithChunkSize(cs))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	writePieces(t, w, data, pieces)
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return out.Bytes()
}

// writePieces writes data to w in pieces of the given sizes (cycled).
func writePieces(t testing.TB, w io.Writer, data []byte, pieces []int) {
	t.Helper()
	if len(pieces) == 0 {
		pieces = []int{len(data)}
	}
	for i := 0; len(data) > 0; i++ {
		n := min(max(pieces[i%len(pieces)], 1), len(data))
		m, err := w.Write(data[:n])
		if err != nil || m != n {
			t.Fatalf("Write: n=%d m=%d err=%v", n, m, err)
		}
		data = data[n:]
	}
}

// decrypt decrypts ct entirely.
func decrypt(dek []byte, tenantID, fileID string, ct []byte) ([]byte, error) {
	r, err := NewReader(bytes.NewReader(ct), dek, tenantID, fileID)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}
