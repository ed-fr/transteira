package crypto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

// roundTripState serializes and parses st.
func roundTripState(t *testing.T, st *State) *State {
	t.Helper()
	b, err := st.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnmarshalState(b)
	if err != nil {
		t.Fatalf("UnmarshalState: %v", err)
	}
	b2, err := got.MarshalBinary()
	if err != nil || !bytes.Equal(b, b2) {
		t.Fatal("state does not round trip")
	}
	return got
}

func TestCheckpointResumeEveryOffset(t *testing.T) {
	dek := testDEK(20)
	data := pattern(3*cs + 100)
	for off := 0; off <= 2*cs+20; off++ {
		var out bytes.Buffer
		w, err := NewWriter(&out, dek, tenantA, fileA, WithChunkSize(cs))
		if err != nil {
			t.Fatal(err)
		}
		writePieces(t, w, data[:off], []int{off/3 + 1})
		st, err := w.Checkpoint(nil)
		if err != nil {
			t.Fatal(err)
		}
		st = roundTripState(t, st)
		if st.PlaintextSize() != int64(off) {
			t.Fatalf("off %d: PlaintextSize %d", off, st.PlaintextSize())
		}
		if st.CiphertextSize() != int64(out.Len()) {
			t.Fatalf("off %d: CiphertextSize %d, written %d", off, st.CiphertextSize(), out.Len())
		}
		if st.ChunkSize() != cs {
			t.Fatalf("ChunkSize %d", st.ChunkSize())
		}
		prefix := append([]byte(nil), out.Bytes()...)

		// Reference: the original writer continues.
		writePieces(t, w, data[off:], nil)
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		want := out.Bytes()

		// Resumed writer, appending to the kept prefix.
		dst := bytes.NewBuffer(prefix)
		rw, _, err := ResumeWriter(dst, dek, tenantA, fileA, st, int64(dst.Len()))
		if err != nil {
			t.Fatalf("off %d: ResumeWriter: %v", off, err)
		}
		writePieces(t, rw, data[off:], []int{cs/2 + 3})
		if err := rw.Close(); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(dst.Bytes(), want) {
			t.Fatalf("off %d: resumed ciphertext differs from the uninterrupted one", off)
		}
		got, err := decrypt(dek, tenantA, fileA, dst.Bytes())
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("off %d: decrypt: %v", off, err)
		}
	}
}

func TestCheckpointChain(t *testing.T) {
	dek := testDEK(21)
	data := pattern(6*cs + 77)
	var disk []byte
	var st *State
	pieces := []int{10, cs + 5, 3, 2 * cs, cs - 1, 0}
	off := 0
	for i, n := range pieces {
		var w *Writer
		var err error
		dst := bytes.NewBuffer(append([]byte(nil), disk...))
		if i == 0 {
			w, err = NewWriter(dst, dek, tenantA, fileA, WithChunkSize(cs))
		} else {
			w, _, err = ResumeWriter(dst, dek, tenantA, fileA, st, int64(dst.Len()))
		}
		if err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
		writePieces(t, w, data[off:off+n], nil)
		off += n
		if st, err = w.Checkpoint(nil); err != nil {
			t.Fatal(err)
		}
		st = roundTripState(t, st)
		disk = dst.Bytes()
		if int64(len(disk)) != st.CiphertextSize() {
			t.Fatalf("step %d: disk %d bytes, checkpoint %d", i, len(disk), st.CiphertextSize())
		}
	}
	dst := bytes.NewBuffer(append([]byte(nil), disk...))
	w, _, err := ResumeWriter(dst, dek, tenantA, fileA, st, int64(dst.Len()))
	if err != nil {
		t.Fatal(err)
	}
	writePieces(t, w, data[off:], nil)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := decrypt(dek, tenantA, fileA, dst.Bytes())
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("decrypt: %v", err)
	}
}

func TestResumeStaleCheckpoint(t *testing.T) {
	dek := testDEK(27)
	data := pattern(4*cs + 10)
	for _, off := range []int{0, 10, cs, cs + 10} {
		var out bytes.Buffer
		w, err := NewWriter(&out, dek, tenantA, fileA, WithChunkSize(cs))
		if err != nil {
			t.Fatal(err)
		}
		writePieces(t, w, data[:off], nil)
		st, err := w.Checkpoint(nil)
		if err != nil {
			t.Fatal(err)
		}
		size := st.CiphertextSize()
		// A crash after a full chunk was written but before the next
		// checkpoint was persisted: the file is longer than the checkpoint.
		writePieces(t, w, data[off:off+2*cs], nil)
		longer := int64(out.Len())
		if longer <= size {
			t.Fatal("test setup: no chunk written after the checkpoint")
		}
		for name, existing := range map[string]int64{
			"chunk after checkpoint": longer,
			"partial write":          size + 1,
			"one byte missing":       size - 1,
			"one chunk missing":      size - cs - tagSize,
			"empty file":             0,
		} {
			if _, _, err := ResumeWriter(io.Discard, dek, tenantA, fileA, st, existing); !errors.Is(err, ErrStaleCheckpoint) {
				t.Fatalf("off %d, %s: %v", off, name, err)
			}
		}
		// The exact size resumes.
		if _, _, err := ResumeWriter(io.Discard, dek, tenantA, fileA, st, size); err != nil {
			t.Fatalf("off %d, exact size: %v", off, err)
		}
	}
}

func TestCheckpointRepeatedFreshNonce(t *testing.T) {
	dek := testDEK(22)
	var out bytes.Buffer
	w, err := NewWriter(&out, dek, tenantA, fileA, WithChunkSize(cs))
	if err != nil {
		t.Fatal(err)
	}
	writePieces(t, w, pattern(cs+50), nil)
	a, err := w.Checkpoint(nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := w.Checkpoint(nil)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a.tail, b.tail) || bytes.Equal(a.tail[1:13], b.tail[1:13]) {
		t.Fatal("repeated checkpoints share a nonce")
	}
	for _, st := range []*State{a, b} {
		if _, _, err := ResumeWriter(io.Discard, dek, tenantA, fileA, st, st.CiphertextSize()); err != nil {
			t.Fatal(err)
		}
	}
	setRand(t, errReader{})
	if _, err := w.Checkpoint(nil); !errors.Is(err, errBoom) {
		t.Fatalf("rand failure: %v", err)
	}
	// The writer remains usable after a failed checkpoint.
	if _, err := w.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestResumeRefusesForeignOrTamperedState(t *testing.T) {
	dek := testDEK(23)
	newState := func(fileID string, n int) *State {
		w, err := NewWriter(io.Discard, dek, tenantA, fileID, WithChunkSize(cs))
		if err != nil {
			t.Fatal(err)
		}
		writePieces(t, w, pattern(n), nil)
		st, err := w.Checkpoint(nil)
		if err != nil {
			t.Fatal(err)
		}
		return st
	}
	st := newState(fileA, cs+100)
	for name, c := range map[string]struct {
		dek            []byte
		tenant, fileID string
	}{
		"dek":    {testDEK(24), tenantA, fileA},
		"tenant": {dek, "ten_B", fileA},
		"file":   {dek, tenantA, "fil_B"},
	} {
		if _, _, err := ResumeWriter(io.Discard, c.dek, c.tenant, c.fileID, st, st.CiphertextSize()); !errors.Is(err, ErrAuth) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	// A state of another file with the same DEK.
	foreign := newState("fil_B", cs+100)
	if _, _, err := ResumeWriter(io.Discard, dek, tenantA, fileA, foreign, foreign.CiphertextSize()); !errors.Is(err, ErrAuth) {
		t.Fatalf("foreign state: %v", err)
	}

	// Every byte of the serialized state matters.
	b, err := st.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	for i := range b {
		mod := append([]byte(nil), b...)
		mod[i] ^= 0x01
		parsed, err := UnmarshalState(mod)
		if err != nil {
			if !errors.Is(err, ErrBadState) {
				t.Fatalf("byte %d: %v", i, err)
			}
			continue
		}
		if _, _, err := ResumeWriter(io.Discard, dek, tenantA, fileA, parsed, parsed.CiphertextSize()); !errors.Is(err, ErrAuth) {
			t.Fatalf("byte %d: tampered state resumed: %v", i, err)
		}
	}
	// Chunk count changed, framing intact.
	mod := append([]byte(nil), b...)
	binary.BigEndian.PutUint32(mod[21:25], 7)
	parsed, err := UnmarshalState(mod)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ResumeWriter(io.Discard, dek, tenantA, fileA, parsed, parsed.CiphertextSize()); !errors.Is(err, ErrAuth) {
		t.Fatalf("chunk count: %v", err)
	}

	// Invalid arguments.
	if _, _, err := ResumeWriter(io.Discard, dek, tenantA, fileA, nil, 0); !errors.Is(err, ErrBadState) {
		t.Fatalf("nil state: %v", err)
	}
	if _, _, err := ResumeWriter(io.Discard, dek, tenantA, fileA, &State{}, 0); !errors.Is(err, ErrBadState) {
		t.Fatalf("zero state: %v", err)
	}
	if _, _, err := ResumeWriter(io.Discard, dek[:5], tenantA, fileA, st, st.CiphertextSize()); !errors.Is(err, ErrKeySize) {
		t.Fatalf("short dek: %v", err)
	}
	if _, _, err := ResumeWriter(io.Discard, dek, "", fileA, st, st.CiphertextSize()); !errors.Is(err, ErrInvalidBinding) {
		t.Fatalf("empty tenant: %v", err)
	}
}

func TestUnmarshalStateStrict(t *testing.T) {
	w, err := NewWriter(io.Discard, testDEK(25), tenantA, fileA, WithChunkSize(cs))
	if err != nil {
		t.Fatal(err)
	}
	writePieces(t, w, pattern(cs+10), nil)
	st, err := w.Checkpoint(nil)
	if err != nil {
		t.Fatal(err)
	}
	good, err := st.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if len(good) != stateFixedSize+envelopeOverhead+10 {
		t.Fatalf("state length %d", len(good))
	}
	withTail := func(tail []byte) []byte {
		b := append([]byte(nil), good[:stateFixedSize]...)
		binary.BigEndian.PutUint32(b[29:33], uint32(len(tail)))
		return append(b, tail...)
	}
	cases := map[string][]byte{
		"empty":           nil,
		"short":           good[:stateFixedSize-1],
		"fixed part only": good[:stateFixedSize],
		"magic":           append([]byte("XXCK"), good[4:]...),
		"version":         append(append([]byte("TTCK"), 2), good[5:]...),
		"extra byte":      append(append([]byte(nil), good...), 0),
		"missing byte":    good[:len(good)-1],
		"bad header":      append(append(append([]byte(nil), good[:5]...), 'X'), good[6:]...),
		"tail too short":  withTail(make([]byte, envelopeOverhead-1)),
		"tail too long":   withTail(append([]byte{tailVersion}, make([]byte, envelopeOverhead+cs-1)...)),
		"tail version":    withTail(append([]byte{2}, make([]byte, envelopeOverhead-1)...)),
	}
	for name, b := range cases {
		if _, err := UnmarshalState(b); !errors.Is(err, ErrBadState) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	// Largest valid tail: chunk size - 1 bytes of plaintext.
	if _, err := UnmarshalState(withTail(append([]byte{tailVersion}, make([]byte, envelopeOverhead+cs-2)...))); err != nil {
		t.Fatalf("largest tail: %v", err)
	}
	// UnmarshalBinary leaves the receiver unchanged on error, and copies.
	var s State
	if err := s.UnmarshalBinary(cases["extra byte"]); !errors.Is(err, ErrBadState) || s.tail != nil {
		t.Fatalf("UnmarshalBinary on error: %v", err)
	}
	buf := append([]byte(nil), good...)
	if err := s.UnmarshalBinary(buf); err != nil {
		t.Fatal(err)
	}
	clear(buf)
	if b, _ := s.MarshalBinary(); !bytes.Equal(b, good) {
		t.Fatal("state aliases its input")
	}
}

func TestStateInvalidAccessors(t *testing.T) {
	var nilState *State
	for _, s := range []*State{nilState, {}} {
		if s.ChunkSize() != 0 || s.CiphertextSize() != -1 || s.PlaintextSize() != -1 {
			t.Fatal("invalid state accessors")
		}
	}
	if _, err := nilState.MarshalBinary(); !errors.Is(err, ErrBadState) {
		t.Fatalf("nil MarshalBinary: %v", err)
	}
}

func TestCheckpointAtChunkBoundary(t *testing.T) {
	dek := testDEK(26)
	var out bytes.Buffer
	w, err := NewWriter(&out, dek, tenantA, fileA, WithChunkSize(cs))
	if err != nil {
		t.Fatal(err)
	}
	writePieces(t, w, pattern(2*cs), nil)
	st, err := w.Checkpoint(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.tail) != envelopeOverhead || st.CiphertextSize() != int64(out.Len()) || st.PlaintextSize() != 2*cs {
		t.Fatal("boundary checkpoint sizes")
	}
	// Resume and close immediately: an empty final chunk.
	dst := bytes.NewBuffer(append([]byte(nil), out.Bytes()...))
	rw, _, err := ResumeWriter(dst, dek, tenantA, fileA, st, int64(dst.Len()))
	if err != nil {
		t.Fatal(err)
	}
	if err := rw.Close(); err != nil {
		t.Fatal(err)
	}
	if got, err := decrypt(dek, tenantA, fileA, dst.Bytes()); err != nil || !bytes.Equal(got, pattern(2*cs)) {
		t.Fatalf("decrypt: %v", err)
	}
}

func TestCheckpointExtra(t *testing.T) {
	dek := testDEK(28)
	data := pattern(3*cs + 50)
	for _, extra := range [][]byte{nil, {}, {0}, []byte("sha256 state"), bytes.Repeat([]byte{7}, MaxCheckpointExtra)} {
		var out bytes.Buffer
		w, err := NewWriter(&out, dek, tenantA, fileA, WithChunkSize(cs))
		if err != nil {
			t.Fatal(err)
		}
		writePieces(t, w, data[:cs+77], nil)
		st, err := w.Checkpoint(extra)
		if err != nil {
			t.Fatal(err)
		}
		st = roundTripState(t, st)
		if st.PlaintextSize() != cs+77 || st.CiphertextSize() != int64(out.Len()) {
			t.Fatal("sizes with extra")
		}
		dst := bytes.NewBuffer(append([]byte(nil), out.Bytes()...))
		rw, got, err := ResumeWriter(dst, dek, tenantA, fileA, st, int64(dst.Len()))
		if err != nil || !bytes.Equal(got, extra) || (len(extra) == 0) != (got == nil) {
			t.Fatalf("extra %d bytes: got %d, %v", len(extra), len(got), err)
		}
		writePieces(t, rw, data[cs+77:], nil)
		if err := rw.Close(); err != nil {
			t.Fatal(err)
		}
		if plain, err := decrypt(dek, tenantA, fileA, dst.Bytes()); err != nil || !bytes.Equal(plain, data) {
			t.Fatalf("decrypt: %v", err)
		}
	}

	w, err := NewWriter(io.Discard, dek, tenantA, fileA, WithChunkSize(cs))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Checkpoint(make([]byte, MaxCheckpointExtra+1)); !errors.Is(err, ErrExtraTooLarge) {
		t.Fatalf("too large: %v", err)
	}
	// The extra length is authenticated: moving the boundary between extra
	// and pending plaintext is detected.
	writePieces(t, w, data[:20], nil)
	st, err := w.Checkpoint([]byte("0123456789"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := st.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range []uint32{0, 9, 11, 30} {
		mod := append([]byte(nil), b...)
		binary.BigEndian.PutUint32(mod[25:29], l)
		parsed, err := UnmarshalState(mod)
		if err != nil {
			t.Fatalf("extra length %d: %v", l, err)
		}
		if _, _, err := ResumeWriter(io.Discard, dek, tenantA, fileA, parsed, parsed.CiphertextSize()); !errors.Is(err, ErrAuth) {
			t.Fatalf("extra length %d: %v", l, err)
		}
	}
}

func TestUnmarshalStateExtraBounds(t *testing.T) {
	w, err := NewWriter(io.Discard, testDEK(29), tenantA, fileA, WithChunkSize(cs))
	if err != nil {
		t.Fatal(err)
	}
	st, err := w.Checkpoint([]byte("abc"))
	if err != nil {
		t.Fatal(err)
	}
	good, err := st.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	build := func(extraLen uint32, tail []byte) []byte {
		b := append([]byte(nil), good[:stateFixedSize]...)
		binary.BigEndian.PutUint32(b[25:29], extraLen)
		binary.BigEndian.PutUint32(b[29:33], uint32(len(tail)))
		return append(b, tail...)
	}
	tail := func(n int) []byte { return append([]byte{tailVersion}, make([]byte, n-1)...) }
	for name, b := range map[string][]byte{
		"extra over max":       build(MaxCheckpointExtra+1, tail(envelopeOverhead+MaxCheckpointExtra+1)),
		"tail shorter":         build(10, tail(envelopeOverhead+9)),
		"pending a full chunk": build(10, tail(envelopeOverhead+10+cs)),
		"empty tail":           build(0, nil),
	} {
		if _, err := UnmarshalState(b); !errors.Is(err, ErrBadState) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	for name, b := range map[string][]byte{
		"max extra, max pending": build(MaxCheckpointExtra, tail(envelopeOverhead+MaxCheckpointExtra+cs-1)),
		"extra only":             build(10, tail(envelopeOverhead+10)),
	} {
		if _, err := UnmarshalState(b); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
}
