package upload

import (
	"bytes"
	"crypto/sha256"
	"encoding"
	"io"
	"testing"

	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/storage"
)

// TestWorstCaseCheckpointFits checks that the largest checkpoint the engine
// can write (a pending chunk of chunkSize-1 bytes, the chunk size the
// engine passes to crypto.NewWriter, and the hash state as
// extra data) stays within storage.MaxCheckpointSize.
func TestWorstCaseCheckpointFits(t *testing.T) {
	dek := bytes.Repeat([]byte{7}, crypto.DEKSize)
	w, err := crypto.NewWriter(io.Discard, dek, "ten_01JAAAAAAAAAAAAAAAAAAAAAAA", "fil_01JAAAAAAAAAAAAAAAAAAAAAAA",
		crypto.WithChunkSize(chunkSize))
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.New()
	pending := make([]byte, chunkSize-1)
	h.Write(pending)
	if _, err := w.Write(pending); err != nil {
		t.Fatal(err)
	}
	extra, err := h.(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	st, err := w.Checkpoint(extra)
	if err != nil {
		t.Fatal(err)
	}
	data, err := st.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if len(data) > storage.MaxCheckpointSize {
		t.Fatalf("worst-case checkpoint = %d bytes, above storage.MaxCheckpointSize = %d", len(data), storage.MaxCheckpointSize)
	}
	// The bound must also hold with the largest extra data crypto accepts.
	if limit := len(data) - len(extra) + crypto.MaxCheckpointExtra; limit > storage.MaxCheckpointSize {
		t.Fatalf("checkpoint with maximal extra = %d bytes, above %d", limit, storage.MaxCheckpointSize)
	}
}
