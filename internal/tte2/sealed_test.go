package tte2

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"testing/iotest"
)

// testMetadata returns valid metadata for file index of count.
func testMetadata(index, count int) Metadata {
	return Metadata{
		Index: index, Count: count, Name: "rapport <final> & été.pdf", Path: "docs/2026",
		Type: "application/pdf", Size: 1234, SHA256: strings.Repeat("ab", 32),
	}
}

// reseal decodes a sealed blob, lets f change the decoded bytes and encodes it
// again.
func reseal(t *testing.T, s string, f func([]byte) []byte) string {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(f(b))
}

func TestMetadataRoundTrip(t *testing.T) {
	key := testKey(20)
	for _, m := range []Metadata{testMetadata(2, 3), {Index: 0, Count: 1, Name: "a", SHA256: strings.Repeat("0", 64)}} {
		s, err := SealMetadata(key, m.Index, m)
		if err != nil {
			t.Fatal(err)
		}
		got, err := OpenMetadata(key, m.Index, s)
		if err != nil || got != m {
			t.Fatalf("%v %+v", err, got)
		}
	}
}

func TestSealMetadataErrors(t *testing.T) {
	key := testKey(21)
	good := testMetadata(0, 1)
	if _, err := SealMetadata(key[:3], 0, good); !errors.Is(err, ErrInvalidKey) {
		t.Fatal(err)
	}
	if _, err := SealMetadata(key, -1, good); !errors.Is(err, ErrInvalidIndex) {
		t.Fatal(err)
	}
	if _, err := sealMetadataRaw(key, -1, nil); !errors.Is(err, ErrInvalidIndex) {
		t.Fatal(err)
	}
	bad := map[string]func(*Metadata){
		"index":     func(m *Metadata) { m.Index = 1 },
		"count 0":   func(m *Metadata) { m.Count = 0 },
		"name":      func(m *Metadata) { m.Name = "" },
		"size":      func(m *Metadata) { m.Size = -1 },
		"sha upper": func(m *Metadata) { m.SHA256 = strings.Repeat("AB", 32) },
		"sha short": func(m *Metadata) { m.SHA256 = "ab" },
		"too large": func(m *Metadata) { m.Name = strings.Repeat("n", MaxMetadataSize) },
	}
	for name, f := range bad {
		m := good
		f(&m)
		if _, err := SealMetadata(key, 0, m); !errors.Is(err, ErrInvalidMetadata) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	m := good
	m.Index, m.Count = 1, 1
	if _, err := SealMetadata(key, 1, m); !errors.Is(err, ErrInvalidMetadata) {
		t.Fatal("index >= count accepted")
	}
	withRand(t, iotest.ErrReader(errWrite))
	if _, err := SealMetadata(key, 0, good); !errors.Is(err, errWrite) {
		t.Fatal(err)
	}
}

func TestOpenMetadataErrors(t *testing.T) {
	key := testKey(22)
	s, err := SealMetadata(key, 1, testMetadata(1, 2))
	if err != nil {
		t.Fatal(err)
	}
	raw := func(json string) string {
		t.Helper()
		out, err := sealMetadataRaw(key, 1, []byte(json))
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	const sha = `"` + "0000000000000000000000000000000000000000000000000000000000000000" + `"`
	cases := []struct {
		name  string
		key   []byte
		index int
		s     string
		want  error
	}{
		{"bad key", key[:1], 1, s, ErrInvalidKey},
		{"bad index", key, -1, s, ErrInvalidIndex},
		{"wrong key", testKey(23), 1, s, ErrAuth},
		{"wrong index", key, 0, s, ErrAuth},
		{"flipped", key, 1, reseal(t, s, func(b []byte) []byte { b[20] ^= 1; return b }), ErrAuth},
		{"version", key, 1, reseal(t, s, func(b []byte) []byte { b[0] = 2; return b }), ErrEncoding},
		{"too short", key, 1, reseal(t, s, func(b []byte) []byte { return b[:sealedOverhead-1] }), ErrEncoding},
		{"padding", key, 1, s + "=", ErrEncoding},
		{"newline", key, 1, s[:10] + "\n" + s[10:], ErrEncoding},
		{"std alphabet", key, 1, "+" + s[1:], ErrEncoding},
		{"bad length", key, 1, strings.Repeat("A", 29), ErrEncoding},
		{"too long", key, 1, strings.Repeat("A", base64.RawURLEncoding.EncodedLen(MaxMetadataSize)+1), ErrEncoding},
		{"array", key, 1, raw(`[]`), ErrInvalidMetadata},
		{"null", key, 1, raw(`null`), ErrInvalidMetadata},
		{"trailing", key, 1, raw(`{}x`), ErrInvalidMetadata},
		{"unknown field", key, 1, raw(`{"v":1,"index":1,"count":2,"name":"a","type":"","size":0,"sha256":` + sha + `,"x":1}`), ErrInvalidMetadata},
		{"case", key, 1, raw(`{"v":1,"index":1,"count":2,"Name":"a","type":"","size":0,"sha256":` + sha + `}`), ErrInvalidMetadata},
		{"null field", key, 1, raw(`{"v":1,"index":1,"count":2,"name":"a","path":null,"type":"","size":0,"sha256":` + sha + `}`), ErrInvalidMetadata},
		{"missing", key, 1, raw(`{"v":1,"index":1,"count":2,"name":"a","size":0,"sha256":` + sha + `}`), ErrInvalidMetadata},
		{"wrong type", key, 1, raw(`{"v":1,"index":"1","count":2,"name":"a","type":"","size":0,"sha256":` + sha + `}`), ErrInvalidMetadata},
		{"float", key, 1, raw(`{"v":1.0,"index":1,"count":2,"name":"a","type":"","size":0,"sha256":` + sha + `}`), ErrInvalidMetadata},
		{"version 2", key, 1, raw(`{"v":2,"index":1,"count":2,"name":"a","type":"","size":0,"sha256":` + sha + `}`), ErrInvalidMetadata},
		{"index mismatch", key, 1, raw(`{"v":1,"index":0,"count":2,"name":"a","type":"","size":0,"sha256":` + sha + `}`), ErrInvalidMetadata},
		{"count", key, 1, raw(`{"v":1,"index":1,"count":1,"name":"a","type":"","size":0,"sha256":` + sha + `}`), ErrInvalidMetadata},
	}
	for _, tc := range cases {
		if _, err := OpenMetadata(tc.key, tc.index, tc.s); !errors.Is(err, tc.want) {
			t.Fatalf("%s: got %v, want %v", tc.name, err, tc.want)
		}
	}
	ok := raw(`{"sha256":` + sha + `,"size":0,"type":"","name":"a","count":2,"index":1,"v":1}`)
	if _, err := OpenMetadata(key, 1, ok); err != nil {
		t.Fatalf("field order: %v", err)
	}
}

func TestMessage(t *testing.T) {
	key := testKey(30)
	for _, text := range []string{"", "Bonjour, voici les fichiers.", strings.Repeat("é", MaxMessageRunes), strings.Repeat("😀", MaxMessageRunes)} {
		s, err := SealMessage(key, text)
		if err != nil || len(s) > MaxMessageEncodedSize {
			t.Fatalf("%v %d", err, len(s))
		}
		got, err := OpenMessage(key, s)
		if err != nil || got != text {
			t.Fatal(err)
		}
	}
	if _, err := SealMessage(key, strings.Repeat("a", MaxMessageRunes+1)); !errors.Is(err, ErrInvalidMessage) {
		t.Fatal(err)
	}
	if _, err := SealMessage(key, "\xff"); !errors.Is(err, ErrInvalidMessage) {
		t.Fatal(err)
	}
	if _, err := SealMessage(key[:1], "a"); !errors.Is(err, ErrInvalidKey) {
		t.Fatal(err)
	}
	s, _ := SealMessage(key, "hello")
	if _, err := OpenMessage(key[:1], s); !errors.Is(err, ErrInvalidKey) {
		t.Fatal(err)
	}
	if _, err := OpenMessage(testKey(31), s); !errors.Is(err, ErrAuth) {
		t.Fatal(err)
	}
	if _, err := OpenMessage(key, strings.Repeat("A", MaxMessageEncodedSize+1)); !errors.Is(err, ErrEncoding) {
		t.Fatal(err)
	}
	// A metadata blob does not open as a message (different key and AAD).
	m, _ := SealMetadata(key, 0, testMetadata(0, 1))
	if _, err := OpenMessage(key, m); !errors.Is(err, ErrAuth) {
		t.Fatal(err)
	}
	for _, plain := range []string{"\xff", strings.Repeat("a", MaxMessageRunes+1)} {
		raw, err := sealMessageRaw(key, []byte(plain))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := OpenMessage(key, raw); !errors.Is(err, ErrInvalidMessage) {
			t.Fatal(err)
		}
	}
}

func TestCheckFraming(t *testing.T) {
	key := testKey(7)
	m, err := SealMetadata(key, 0, Metadata{Index: 0, Count: 1, Name: "a", Size: 0, SHA256: strings.Repeat("0", 64)})
	if err != nil {
		t.Fatal(err)
	}
	msg, err := SealMessage(key, "hello")
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckMetadataFraming(m); err != nil {
		t.Fatal(err)
	}
	if err := CheckMessageFraming(msg); err != nil {
		t.Fatal(err)
	}
	short := base64.RawURLEncoding.EncodeToString([]byte{1, 2, 3})
	version0 := base64.RawURLEncoding.EncodeToString(make([]byte, 40))
	tooLong := strings.Repeat("A", MaxMessageEncodedSize+1)
	for _, s := range []string{"", "AA", short, version0, m + "=", tooLong} {
		if err := CheckMetadataFraming(s); !errors.Is(err, ErrEncoding) {
			t.Errorf("metadata %.16q: %v", s, err)
		}
		if err := CheckMessageFraming(s); !errors.Is(err, ErrEncoding) {
			t.Errorf("message %.16q: %v", s, err)
		}
	}
}
