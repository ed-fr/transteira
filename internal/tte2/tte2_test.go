package tte2

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"testing/iotest"
)

func TestKeys(t *testing.T) {
	k, err := NewKey()
	if err != nil || len(k) != KeySize {
		t.Fatal(err)
	}
	s, err := EncodeKey(k)
	if err != nil || len(s) != EncodedKeySize {
		t.Fatal(err)
	}
	back, err := DecodeKey(s)
	if err != nil || !bytes.Equal(back, k) {
		t.Fatal(err)
	}
	if _, err := EncodeKey(k[:5]); !errors.Is(err, ErrInvalidKey) {
		t.Fatal(err)
	}
	bad := []string{
		"",
		s[:42],
		s + "A",
		"+" + s[1:],
		"\n" + s[1:],
		s[:42] + "B", // non-zero trailing bits: not canonical
	}
	for _, b := range bad {
		if _, err := DecodeKey(b); !errors.Is(err, ErrInvalidKey) {
			t.Fatalf("%q: %v", b, err)
		}
	}
	// The canonical encoding of a zero key ends with 'A'.
	if _, err := DecodeKey(strings.Repeat("A", 43)); err != nil {
		t.Fatal(err)
	}
	withRand(t, iotest.ErrReader(errWrite))
	if _, err := NewKey(); !errors.Is(err, errWrite) {
		t.Fatal(err)
	}
}

func TestValidChunkSize(t *testing.T) {
	for c, want := range map[int]bool{
		0: false, -MinChunkSize: false, MinChunkSize / 2: false, MinChunkSize: true,
		MinChunkSize + 1: false, 1 << 17: true, DefaultChunkSize: true, 3 << 20: false,
		MaxChunkSize: true, MaxChunkSize * 2: false,
	} {
		if ValidChunkSize(c) != want {
			t.Fatalf("%d: want %v", c, want)
		}
	}
}

func TestHeader(t *testing.T) {
	h := Header{ChunkSize: DefaultChunkSize}
	for i := range h.Salt {
		h.Salt[i] = byte(i + 1)
	}
	b := h.Bytes()
	if string(b[:4]) != Magic || b[4] != Version || b[5] != KindFile {
		t.Fatalf("% x", b)
	}
	got, err := ParseHeader(b[:])
	if err != nil || got != h {
		t.Fatalf("%v %+v", err, got)
	}
	if _, err := ParseHeader(b[:31]); !errors.Is(err, ErrBadHeader) {
		t.Fatal(err)
	}
	for i := range HeaderSize {
		if i >= 12 && i < 28 {
			continue // salt: any value
		}
		bad := b
		bad[i] ^= 0x80
		if _, err := ParseHeader(bad[:]); !errors.Is(err, ErrBadHeader) {
			t.Fatalf("byte %d accepted", i)
		}
	}
}
