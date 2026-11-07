package tte2

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"unicode/utf8"
)

// fuzzKey is the transfer key of the fuzz targets.
var fuzzKey = testKey(0x60)

// smallStreams returns the small vector streams, as seeds.
func smallStreams(f *testing.F) [][]byte {
	f.Helper()
	var out [][]byte
	for _, n := range []int{0, 1, 300} {
		var buf bytes.Buffer
		w, err := NewWriter(&buf, fuzzKey, 0, WithChunkSize(MinChunkSize))
		if err != nil {
			f.Fatal(err)
		}
		_, _ = w.Write(pattern(n))
		_ = w.Close()
		out = append(out, buf.Bytes())
	}
	return out
}

// FuzzReader decrypts arbitrary input: it must fail with a known error, and
// an accepted stream must be exactly what the Writer produces for its
// plaintext and salt.
func FuzzReader(f *testing.F) {
	for _, s := range smallStreams(f) {
		f.Add(s, 0)
		f.Add(s[:len(s)-1], 0)
		f.Add(append(bytes.Clone(s), 0), 1)
	}
	f.Fuzz(func(t *testing.T, data []byte, index int) {
		index &= 0xff
		plain, err := decrypt(fuzzKey, index, data)
		if err != nil {
			if errorName(err) == "other" {
				t.Fatalf("unclassified error %v", err)
			}
			return
		}
		h, _ := ParseHeader(data[:HeaderSize])
		defer withFixedRand(h.Salt[:])()
		var buf bytes.Buffer
		w, err := NewWriter(&buf, fuzzKey, index, WithChunkSize(h.ChunkSize))
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write(plain)
		_ = w.Close()
		if !bytes.Equal(buf.Bytes(), data) {
			t.Fatal("accepted a non-canonical stream")
		}
	})
}

// FuzzReaderTamper alters one byte of a valid stream: decryption must fail.
func FuzzReaderTamper(f *testing.F) {
	f.Add(uint32(0), uint32(0), byte(1))
	f.Add(uint32(70000), uint32(40), byte(0x80))
	f.Add(uint32(MinChunkSize), uint32(MinChunkSize+HeaderSize+TagSize-1), byte(1))
	f.Fuzz(func(t *testing.T, n, pos uint32, x byte) {
		if x == 0 {
			return
		}
		size := int(n % (3*MinChunkSize + 1))
		ct := encrypt(t, fuzzKey, 0, MinChunkSize, pattern(size))
		i := int(pos) % len(ct)
		ct[i] ^= x
		if _, err := decrypt(fuzzKey, 0, ct); err == nil || errorName(err) == "other" {
			t.Fatalf("tampered byte %d of %d: %v", i, len(ct), err)
		}
	})
}

// FuzzValidator checks that validating in pieces, with a checkpoint
// (MarshalBinary, UnmarshalBinary) at every split point, gives the same
// outcome as validating in one go.
func FuzzValidator(f *testing.F) {
	for _, s := range smallStreams(f) {
		f.Add(int64(len(s)), s, []byte{1, 5, 12, 31})
		f.Add(int64(len(s)+1), s[:40], []byte{11})
	}
	f.Add(int64(MinFileSize), []byte("TTE2\x01\x01\x00\x00\x00\x01\x00\x00"), []byte{3})
	f.Fuzz(func(t *testing.T, declared int64, data, splits []byte) {
		whole, err := NewValidator(declared)
		if err != nil {
			if !errors.Is(err, ErrFormat) {
				t.Fatal(err)
			}
			return
		}
		errWhole := whole.Check(data)
		if errWhole != nil && (!errors.Is(errWhole, ErrFormat) || whole.Offset() != 0) {
			t.Fatalf("one go: %v at %d", errWhole, whole.Offset())
		}

		v, _ := NewValidator(declared)
		rest := data
		var errPieces error
		for _, s := range splits {
			n := min(int(s), len(rest))
			if errPieces = v.Check(rest[:n]); errPieces != nil {
				break
			}
			rest = rest[n:]
			state, err := v.MarshalBinary()
			if err != nil || len(state) > MaxValidatorStateSize {
				t.Fatalf("marshal: %v, %d bytes", err, len(state))
			}
			var next Validator
			if err := next.UnmarshalBinary(state); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if next != *v {
				t.Fatal("state round trip differs")
			}
			v = &next
		}
		if errPieces == nil {
			errPieces = v.Check(rest)
		}
		if (errWhole == nil) != (errPieces == nil) {
			t.Fatalf("one go %v, pieces %v", errWhole, errPieces)
		}
		if errWhole == nil && (v.Offset() != whole.Offset() || v.Complete() != whole.Complete()) {
			t.Fatal("final state differs")
		}
	})
}

// FuzzValidatorState decodes arbitrary checkpoint states.
func FuzzValidatorState(f *testing.F) {
	v, _ := NewValidator(100)
	_ = v.Check([]byte("TTE2\x01"))
	good, _ := v.MarshalBinary()
	f.Add(good)
	f.Fuzz(func(t *testing.T, b []byte) {
		var v Validator
		if err := v.UnmarshalBinary(b); err != nil {
			if !errors.Is(err, ErrInvalidState) {
				t.Fatal(err)
			}
			return
		}
		again, _ := v.MarshalBinary()
		if !bytes.Equal(again, b) {
			t.Fatal("accepted a non-canonical state")
		}
	})
}

// vectorSeeds returns the sealed strings of the vectors file.
func vectorSeeds(f *testing.F) []string {
	f.Helper()
	data, err := os.ReadFile(vectorsFile)
	if err != nil {
		f.Fatal(err)
	}
	var vs vectorSet
	if err := json.Unmarshal(data, &vs); err != nil {
		f.Fatal(err)
	}
	var out []string
	for _, m := range vs.Metadata {
		out = append(out, m.Sealed)
	}
	for _, m := range vs.MetadataNegative {
		out = append(out, m.Sealed)
	}
	for _, m := range vs.Messages {
		out = append(out, m.Sealed)
	}
	return out
}

// FuzzOpenSealed opens arbitrary strings as metadata and messages: they must
// fail with a known error.
func FuzzOpenSealed(f *testing.F) {
	for _, s := range vectorSeeds(f) {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		key := vectorKey()
		if _, err := OpenMetadata(key, 1, s); err != nil && errorName(err) == "other" {
			t.Fatal(err)
		}
		if _, err := OpenMessage(key, s); err != nil && errorName(err) == "other" {
			t.Fatal(err)
		}
	})
}

// FuzzOpenMetadata seals arbitrary JSON and opens it: accepted metadata must
// satisfy every rule and survive a SealMetadata round trip.
func FuzzOpenMetadata(f *testing.F) {
	f.Add([]byte(`{"v":1,"index":0,"count":1,"name":"a","type":"","size":0,"sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}`))
	f.Add([]byte(`{"v":1,"index":0,"count":2,"name":"a","path":"b","type":"x","size":1,"sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","name":"c"}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, plain []byte) {
		s, err := sealMetadataRaw(fuzzKey, 0, plain)
		if err != nil {
			return // too large
		}
		m, err := OpenMetadata(fuzzKey, 0, s)
		if err != nil {
			if !errors.Is(err, ErrInvalidMetadata) {
				t.Fatal(err)
			}
			return
		}
		if m.Index != 0 || m.Count < 1 || m.Name == "" || m.Size < 0 || !isLowerHex64(m.SHA256) {
			t.Fatalf("accepted %+v", m)
		}
		again, err := SealMetadata(fuzzKey, 0, m)
		if err != nil {
			return // re-encoding can grow past MaxMetadataSize (escapes)
		}
		back, err := OpenMetadata(fuzzKey, 0, again)
		if err != nil || back != m {
			t.Fatalf("round trip: %v", err)
		}
	})
}

// FuzzOpenMessage seals arbitrary bytes as a message: they open if and only
// if they are valid UTF-8 of at most MaxMessageRunes characters.
func FuzzOpenMessage(f *testing.F) {
	f.Add([]byte("hello"))
	f.Add([]byte("caf\xe9"))
	f.Fuzz(func(t *testing.T, plain []byte) {
		s, err := sealMessageRaw(fuzzKey, plain)
		if err != nil {
			t.Fatal(err)
		}
		text, err := OpenMessage(fuzzKey, s)
		valid := utf8.Valid(plain) && utf8.RuneCount(plain) <= MaxMessageRunes && len(s) <= MaxMessageEncodedSize
		if valid != (err == nil) || (err == nil && text != string(plain)) {
			t.Fatalf("valid %v, err %v", valid, err)
		}
	})
}

// FuzzOpenChunk opens arbitrary bytes as a chunk: it must fail with a known
// error and no plaintext, and an accepted chunk must reseal to the same bytes.
func FuzzOpenChunk(f *testing.F) {
	h := Header{ChunkSize: MinChunkSize}
	copy(h.Salt[:], "fuzz-chunk-salt!")
	c, err := NewChunkCipher(fuzzKey, 0, h)
	if err != nil {
		f.Fatal(err)
	}
	middle, _ := c.Seal(nil, 0, pattern(MinChunkSize), false)
	final, _ := c.Seal(nil, 1, pattern(300), true)
	empty, _ := c.Seal(nil, 0, nil, true)
	f.Add(middle, uint64(0), false)
	f.Add(final, uint64(1), true)
	f.Add(empty, uint64(0), true)
	f.Add(final[:TagSize-1], uint64(1), true)
	f.Add(final, uint64(MaxChunks), true)
	f.Fuzz(func(t *testing.T, sealed []byte, n uint64, last bool) {
		plain, err := c.Open(nil, n, sealed, last)
		if err != nil {
			if plain != nil {
				t.Fatal("plaintext returned on error")
			}
			if errorName(err) == "other" {
				t.Fatalf("unclassified error %v", err)
			}
			return
		}
		again, err := c.Seal(nil, n, plain, last)
		if err != nil || !bytes.Equal(again, sealed) {
			t.Fatal("accepted a chunk that does not reseal identically")
		}
	})
}
