package tte2

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// testChunk is the chunk size used by most tests (the smallest one).
const testChunk = MinChunkSize

// testKey returns a fixed transfer key derived from seed.
func testKey(seed byte) []byte {
	k := make([]byte, KeySize)
	for i := range k {
		k[i] = seed + byte(i)
	}
	return k
}

// pattern returns n plaintext bytes where byte i is i mod 251, the plaintext
// of every file vector.
func pattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i % 251)
	}
	return b
}

// withRand replaces the package randomness with r for the duration of the
// test.
func withRand(t *testing.T, r io.Reader) {
	t.Helper()
	old := randReader
	randReader = r
	t.Cleanup(func() { randReader = old })
}

// encrypt encrypts plain with a single Write and returns the stream.
func encrypt(t *testing.T, key []byte, index, chunk int, plain []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := NewWriter(&buf, key, index, WithChunkSize(chunk))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// decrypt reads a whole stream.
func decrypt(key []byte, index int, ct []byte) ([]byte, error) {
	r, err := NewReader(bytes.NewReader(ct), key, index)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

// errorNames maps the sentinel errors to the names used by the vectors, in
// matching order (a Validator header error wraps both ErrFormat and
// ErrBadHeader and is named ErrFormat).
var errorNames = []struct {
	err  error
	name string
}{
	{ErrFormat, "ErrFormat"},
	{ErrBadHeader, "ErrBadHeader"},
	{ErrAuth, "ErrAuth"},
	{ErrTruncated, "ErrTruncated"},
	{ErrTrailingData, "ErrTrailingData"},
	{ErrCounterOverflow, "ErrCounterOverflow"},
	{ErrEncoding, "ErrEncoding"},
	{ErrInvalidMetadata, "ErrInvalidMetadata"},
	{ErrInvalidMessage, "ErrInvalidMessage"},
	{ErrInvalidSecret, "ErrInvalidSecret"},
	{ErrInvalidPassphrase, "ErrInvalidPassphrase"},
	{ErrInvalidState, "ErrInvalidState"},
	{ErrInvalidKey, "ErrInvalidKey"},
	{ErrInvalidIndex, "ErrInvalidIndex"},
}

// errorName returns the vector name of err, "" for nil and "other" for an
// unknown error.
func errorName(err error) string {
	if err == nil {
		return ""
	}
	for _, e := range errorNames {
		if errors.Is(err, e.err) {
			return e.name
		}
	}
	return "other"
}

// chunkAt returns the bounds of encrypted chunk j of a stream with chunk size
// c (middle chunks only).
func chunkAt(c, j int) (int, int) {
	start := HeaderSize + j*(c+TagSize)
	return start, start + c + TagSize
}

// cat concatenates byte slices into a new slice.
func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// errReader returns its error after data.
type errReader struct {
	data []byte
	err  error
}

// Read implements io.Reader.
func (e *errReader) Read(p []byte) (int, error) {
	if len(e.data) == 0 {
		return 0, e.err
	}
	n := copy(p, e.data)
	e.data = e.data[n:]
	return n, nil
}

// stallReader returns its data, then (0, nil) forever.
type stallReader struct{ data []byte }

// Read implements io.Reader.
func (s *stallReader) Read(p []byte) (int, error) {
	n := copy(p, s.data)
	s.data = s.data[n:]
	return n, nil
}

// limitWriter accepts limit bytes, then fails (or writes short).
type limitWriter struct {
	limit int
	short bool
}

// errWrite is the error returned by limitWriter.
var errWrite = errors.New("write failed")

// Write implements io.Writer.
func (l *limitWriter) Write(p []byte) (int, error) {
	if len(p) <= l.limit {
		l.limit -= len(p)
		return len(p), nil
	}
	if l.short {
		n := l.limit
		l.limit = 0
		return n, nil
	}
	return 0, errWrite
}
