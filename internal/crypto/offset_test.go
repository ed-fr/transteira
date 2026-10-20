package crypto

import (
	"bytes"
	"testing"
)

// TestWriterOffset checks that Offset counts the plaintext accepted, matches
// the PlaintextSize of a checkpoint, survives a resumption and stops at
// Close.
func TestWriterOffset(t *testing.T) {
	dek := testDEK(7)
	var dst bytes.Buffer
	w, err := NewWriter(&dst, dek, "ten_a", "fil_x", WithChunkSize(MinChunkSize))
	if err != nil {
		t.Fatal(err)
	}
	if w.Offset() != 0 {
		t.Fatalf("Offset of a new writer = %d", w.Offset())
	}
	data := bytes.Repeat([]byte("offset "), MinChunkSize) // several chunks
	cut := 2*MinChunkSize + 123
	if _, err := w.Write(data[:cut]); err != nil {
		t.Fatal(err)
	}
	st, err := w.Checkpoint([]byte("extra"))
	if err != nil {
		t.Fatal(err)
	}
	if w.Offset() != int64(cut) || st.PlaintextSize() != w.Offset() {
		t.Fatalf("Offset = %d, PlaintextSize = %d, want %d", w.Offset(), st.PlaintextSize(), cut)
	}

	resumedDst := bytes.NewBuffer(bytes.Clone(dst.Bytes()))
	r, _, err := ResumeWriter(resumedDst, dek, "ten_a", "fil_x", st, int64(dst.Len()))
	if err != nil {
		t.Fatal(err)
	}
	if r.Offset() != int64(cut) {
		t.Fatalf("Offset after ResumeWriter = %d, want %d", r.Offset(), cut)
	}
	if _, err := r.Write(data[cut:]); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if r.Offset() != int64(len(data)) {
		t.Errorf("Offset after Close = %d, want %d", r.Offset(), len(data))
	}
}
