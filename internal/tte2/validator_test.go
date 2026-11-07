package tte2

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"testing"
)

func TestValidatorAccepts(t *testing.T) {
	c := testChunk
	ct := encrypt(t, testKey(10), 0, c, pattern(c+5))
	v, err := NewValidator(int64(len(ct)))
	if err != nil {
		t.Fatal(err)
	}
	if v.DeclaredSize() != int64(len(ct)) || v.ChunkSize() != 0 || v.Complete() {
		t.Fatal("initial state")
	}
	for i := range 12 {
		if err := v.Check(ct[i : i+1]); err != nil {
			t.Fatal(err)
		}
	}
	if v.ChunkSize() != c {
		t.Fatalf("ChunkSize %d", v.ChunkSize())
	}
	if err := v.Check(nil); err != nil {
		t.Fatal(err)
	}
	if err := v.Check(ct[12:]); err != nil {
		t.Fatal(err)
	}
	if !v.Complete() || v.Offset() != int64(len(ct)) {
		t.Fatal("not complete")
	}
	if err := v.Check([]byte{0}); !errors.Is(err, ErrFormat) {
		t.Fatalf("beyond declared size: %v", err)
	}
}

func TestValidatorRejects(t *testing.T) {
	c := testChunk
	ct := encrypt(t, testKey(11), 0, c, pattern(100))
	if _, err := NewValidator(MinFileSize - 1); !errors.Is(err, ErrFormat) {
		t.Fatal(err)
	}
	var zero Validator
	if err := zero.Check([]byte{1}); !errors.Is(err, ErrFormat) {
		t.Fatal(err)
	}
	if zero.Complete() {
		t.Fatal("zero complete")
	}
	// A declared size that does not match the chunk layout.
	v, _ := NewValidator(HeaderSize + int64(c+TagSize) + TagSize)
	if err := v.Check(ct[:9]); err != nil {
		t.Fatal(err)
	}
	// Byte 9 fixes the chunk size: the size mismatch is known at once.
	if err := v.Check(ct[9:40]); !errors.Is(err, ErrFormat) {
		t.Fatal(err)
	}
	if v.Offset() != 9 {
		t.Fatal("rejected slice advanced the offset")
	}
	// A bad header byte, alone or inside a larger slice.
	for _, i := range []int{0, 4, 5, 6, 30} {
		bad := bytes.Clone(ct)
		bad[i] ^= 0x40
		v, _ := NewValidator(int64(len(ct)))
		err := v.Check(bad)
		if !errors.Is(err, ErrFormat) || !errors.Is(err, ErrBadHeader) || v.Offset() != 0 {
			t.Fatalf("byte %d: %v", i, err)
		}
	}
	// Too much data in one slice.
	v, _ = NewValidator(int64(len(ct)))
	if err := v.Check(append(bytes.Clone(ct), 0)); !errors.Is(err, ErrFormat) {
		t.Fatal(err)
	}
}

func TestValidatorState(t *testing.T) {
	c := testChunk
	ct := encrypt(t, testKey(12), 0, c, pattern(2*c))
	for _, at := range []int{0, 5, 12, 31, 32, 100, len(ct)} {
		v, _ := NewValidator(int64(len(ct)))
		if err := v.Check(ct[:at]); err != nil {
			t.Fatal(err)
		}
		state, err := v.MarshalBinary()
		if err != nil || len(state) > MaxValidatorStateSize {
			t.Fatalf("at %d: %v, %d bytes", at, err, len(state))
		}
		var w Validator
		if err := w.UnmarshalBinary(state); err != nil {
			t.Fatalf("at %d: %v", at, err)
		}
		if w != *v {
			t.Fatalf("at %d: state differs", at)
		}
		if err := w.Check(ct[at:]); err != nil || !w.Complete() {
			t.Fatalf("at %d: resume %v", at, err)
		}
	}

	v, _ := NewValidator(int64(len(ct)))
	_ = v.Check(ct[:20])
	good, _ := v.MarshalBinary()
	mutate := func(f func([]byte) []byte) []byte { return f(bytes.Clone(good)) }
	bad := map[string][]byte{
		"empty":         nil,
		"short":         good[:validatorFixedSize-1],
		"version":       mutate(func(b []byte) []byte { b[0] = 2; return b }),
		"declared low":  mutate(func(b []byte) []byte { binary.BigEndian.PutUint64(b[1:9], MinFileSize-1); return b }),
		"declared huge": mutate(func(b []byte) []byte { binary.BigEndian.PutUint64(b[1:9], math.MaxInt64+1); return b }),
		"offset high":   mutate(func(b []byte) []byte { binary.BigEndian.PutUint64(b[9:17], uint64(len(ct))+1); return b }),
		"prefix long":   append(bytes.Clone(good), 0),
		"prefix short":  good[:len(good)-1],
		"prefix bad":    mutate(func(b []byte) []byte { b[validatorFixedSize] = 'X'; return b }),
		"size mismatch": mutate(func(b []byte) []byte { binary.BigEndian.PutUint64(b[1:9], uint64(len(ct))+1); return b }),
	}
	for name, b := range bad {
		w := *v
		if err := w.UnmarshalBinary(b); !errors.Is(err, ErrInvalidState) {
			t.Fatalf("%s: %v", name, err)
		}
		if w != *v {
			t.Fatalf("%s: validator changed", name)
		}
	}
}
