package vcode

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

// seq returns a reader yielding the big-endian 32-bit values vals, then
// failing.
func seq(vals ...uint32) io.Reader {
	var b []byte
	for _, v := range vals {
		b = binary.BigEndian.AppendUint32(b, v)
	}
	return bytes.NewReader(b)
}

func TestNew(t *testing.T) {
	t.Parallel()
	if RejectAtOrAbove%Space != 0 || RejectAtOrAbove > 1<<32 || (1<<32)-RejectAtOrAbove >= Space {
		t.Fatalf("rejection bound %d is not the largest multiple of %d", int64(RejectAtOrAbove), Space)
	}
	if code, err := New(seq(0xFFFFFFFF, RejectAtOrAbove, RejectAtOrAbove-1)); err != nil || code != "999999" {
		t.Errorf("after rejections: %q, %v", code, err)
	}
	if code, err := New(seq(7)); err != nil || code != "000007" {
		t.Errorf("zero padding: %q, %v", code, err)
	}
	if _, err := New(seq()); !errors.Is(err, io.EOF) {
		t.Errorf("failing source: %v", err)
	}
	for range 100 {
		code, err := New(rand.Reader)
		if err != nil || !Valid(code) {
			t.Fatalf("New = %q, %v", code, err)
		}
	}
}

func TestValid(t *testing.T) {
	t.Parallel()
	for code, want := range map[string]bool{
		"000000": true, "123456": true, "12345": false, "1234567": false, "12345a": false, "": false,
		"	12345": false, "١٢٣٤٥٦": false,
	} {
		if got := Valid(code); got != want {
			t.Errorf("Valid(%q) = %v", code, got)
		}
	}
}

// FuzzValid checks that Valid accepts exactly the strings of Digits ASCII
// digits.
func FuzzValid(f *testing.F) {
	for _, seed := range []string{"123456", "12345", "abcdef", "١٢٣٤٥٦", ""} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, code string) {
		want := len(code) == Digits
		for i := range len(code) {
			want = want && code[i] >= '0' && code[i] <= '9'
		}
		if Valid(code) != want {
			t.Fatalf("Valid(%q) = %v", code, !want)
		}
	})
}
