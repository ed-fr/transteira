package tte2

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"strings"
	"testing"
)

// update regenerates the reference vectors: go test ./internal/tte2 -run TestVectors -update
var update = flag.Bool("update", false, "regenerate testdata/vectors.json")

// vectorsFile holds the reference vectors shared with the TypeScript port.
const vectorsFile = "testdata/vectors.json"

// vectorDoc documents the vectors file inside the file itself.
const vectorDoc = "TTE2 reference vectors (docs/architecture/e2e-format.md). " +
	"Fields ending in Hex are lowercase hexadecimal, ciphertextBase64 is standard base64 with padding, " +
	"sealed values are base64url without padding as on the wire. " +
	"The plaintext of every file vector is plaintextLength bytes where byte i is i mod 251. " +
	"Salts and nonces are fixed: sealing again with them must reproduce the ciphertext exactly. " +
	"A negative or validator input is the concatenation of its parts: {base, from, to} is ciphertext[from:to] " +
	"of the file vector named base, {hex} is literal bytes. keyHex, when present, replaces the transfer key; " +
	"index replaces the file index. expectedError names the sentinel error (Go names), empty for success."

// vectorSet is the JSON layout of testdata/vectors.json.
type vectorSet struct {
	Description      string            `json:"description"`
	KeyHex           string            `json:"keyHex"`
	KeyFragment      string            `json:"keyFragment"`
	Files            []fileVector      `json:"files"`
	FileNegative     []streamCase      `json:"fileNegative"`
	Sizes            []sizeVector      `json:"sizes"`
	Validator        []validatorVector `json:"validator"`
	Metadata         []metadataVector  `json:"metadata"`
	MetadataNegative []sealedNegative  `json:"metadataNegative"`
	Messages         []messageVector   `json:"messages"`
	MessageNegative  []sealedNegative  `json:"messageNegative"`
	// Since 2.1 (vectors_secret_test.go).
	SecretsDescription string           `json:"secretsDescription"`
	Secrets            []secretVector   `json:"secrets"`
	SecretNegative     []secretNegative `json:"secretNegative"`
}

// fileVector is a valid file stream.
type fileVector struct {
	Name                string `json:"name"`
	Index               int    `json:"index"`
	ChunkSize           int    `json:"chunkSize"`
	SaltHex             string `json:"saltHex"`
	PlaintextLength     int    `json:"plaintextLength"`
	PlaintextSHA256Hex  string `json:"plaintextSha256Hex"`
	CiphertextLength    int    `json:"ciphertextLength"`
	CiphertextSHA256Hex string `json:"ciphertextSha256Hex"`
	CiphertextBase64    string `json:"ciphertextBase64"`
}

// part is a piece of a constructed input.
type part struct {
	Base string `json:"base,omitempty"`
	From int    `json:"from,omitempty"`
	To   int    `json:"to,omitempty"`
	Hex  string `json:"hex,omitempty"`
}

// streamCase is an altered file stream and the expected Reader error.
type streamCase struct {
	Name          string `json:"name"`
	KeyHex        string `json:"keyHex,omitempty"`
	Index         int    `json:"index"`
	Parts         []part `json:"parts"`
	ExpectedError string `json:"expectedError"`
}

// sizeVector is a ValidSize / PlaintextSize case.
type sizeVector struct {
	Total     int64 `json:"total"`
	ChunkSize int   `json:"chunkSize"`
	Valid     bool  `json:"valid"`
	Plaintext int64 `json:"plaintext"`
}

// validatorVector is a Validator case: the input is checked in one go and
// byte by byte, with the same outcome.
type validatorVector struct {
	Name          string `json:"name"`
	DeclaredSize  int64  `json:"declaredSize"`
	Parts         []part `json:"parts"`
	ExpectedError string `json:"expectedError"`
	Complete      bool   `json:"complete"`
}

// metadataVector is a sealed metadata blob.
type metadataVector struct {
	Name      string          `json:"name"`
	Index     int             `json:"index"`
	NonceHex  string          `json:"nonceHex"`
	Plaintext string          `json:"plaintext"`
	Metadata  json.RawMessage `json:"metadata"`
	Sealed    string          `json:"sealed"`
}

// messageVector is a sealed message.
type messageVector struct {
	Name     string `json:"name"`
	NonceHex string `json:"nonceHex"`
	Text     string `json:"text"`
	Sealed   string `json:"sealed"`
}

// sealedNegative is a sealed blob that must not open.
type sealedNegative struct {
	Name          string `json:"name"`
	KeyHex        string `json:"keyHex,omitempty"`
	Index         int    `json:"index"`
	Sealed        string `json:"sealed"`
	ExpectedError string `json:"expectedError"`
}

// vectorKey is the transfer key of the vectors.
func vectorKey() []byte { return testKey(0x40) }

// fixed returns n bytes derived from label, for salts and nonces.
func fixed(label string, n int) []byte {
	sum := sha256.Sum256([]byte("tte2 vector " + label))
	return sum[:n]
}

// withFixedRand makes the next random draw return b.
func withFixedRand(b []byte) func() {
	old := randReader
	randReader = bytes.NewReader(b)
	return func() { randReader = old }
}

// encryptFixed encrypts the pattern plaintext with a fixed salt.
func encryptFixed(t *testing.T, key []byte, index, chunk, n int, salt []byte) []byte {
	t.Helper()
	defer withFixedRand(salt)()
	return encrypt(t, key, index, chunk, pattern(n))
}

func hexSum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func TestVectors(t *testing.T) {
	if *update {
		data, err := json.MarshalIndent(generateVectors(t), "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(vectorsFile, append(data, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(vectorsFile)
	if err != nil {
		t.Fatal(err)
	}
	var vs vectorSet
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&vs); err != nil {
		t.Fatal(err)
	}
	verifyVectors(t, &vs)
}

// generateVectors builds the vector set from the implementation.
func generateVectors(t *testing.T) *vectorSet {
	t.Helper()
	key := vectorKey()
	frag, _ := EncodeKey(key)
	c := MinChunkSize
	vs := &vectorSet{Description: vectorDoc, KeyHex: hex.EncodeToString(key), KeyFragment: frag}
	streams := map[string][]byte{}
	for _, f := range []struct {
		name     string
		index, n int
	}{
		{"empty", 0, 0},
		{"one-byte", 1, 1},
		{"exactly-one-chunk", 2, c},
		{"one-chunk-plus-one", 3, c + 1},
		{"multi-chunk", 4, 2*c + 100},
	} {
		salt := fixed("salt "+f.name, SaltSize)
		ct := encryptFixed(t, key, f.index, c, f.n, salt)
		streams[f.name] = ct
		vs.Files = append(vs.Files, fileVector{
			Name: f.name, Index: f.index, ChunkSize: c, SaltHex: hex.EncodeToString(salt),
			PlaintextLength: f.n, PlaintextSHA256Hex: hexSum(pattern(f.n)),
			CiphertextLength: len(ct), CiphertextSHA256Hex: hexSum(ct),
			CiphertextBase64: base64.StdEncoding.EncodeToString(ct),
		})
	}

	multi := streams["multi-chunk"]
	full := streams["exactly-one-chunk"]
	m := len(multi)
	block := c + TagSize
	h0, c0, c1 := HeaderSize, HeaderSize+block, HeaderSize+2*block
	b := func(base string, from, to int) part { return part{Base: base, From: from, To: to} }
	mb := func(from, to int) part { return b("multi-chunk", from, to) }
	lit := func(bs ...byte) part { return part{Hex: hex.EncodeToString(bs)} }
	// setByte replaces byte i of multi-chunk with v.
	setByte := func(i int, v byte) []part { return []part{mb(0, i), lit(v), mb(i+1, m)} }
	flipBit := func(i int) []part { return setByte(i, multi[i]^0x01) }
	// The empty final chunk after chunk 0, sealed with the right key.
	hdr, _ := ParseHeader(multi[:HeaderSize])
	nonce := chunkNonce(1, true)
	emptyFinal := fileAEAD(key, 4, &hdr).Seal(nil, nonce[:], nil, multi[:HeaderSize])

	neg := func(name string, index int, want string, parts ...part) {
		vs.FileNegative = append(vs.FileNegative, streamCase{Name: name, Index: index, Parts: parts, ExpectedError: want})
	}
	neg("reordered-chunks", 4, "ErrAuth", mb(0, h0), mb(c0, c1), mb(h0, c0), mb(c1, m))
	neg("duplicated-chunk", 4, "ErrAuth", mb(0, c0), mb(h0, m))
	neg("missing-final-chunk", 4, "ErrTruncated", mb(0, c1))
	neg("missing-middle-chunk", 4, "ErrAuth", mb(0, c0), mb(c1, m))
	neg("trailing-after-full-final", 2, "ErrTrailingData", b("exactly-one-chunk", 0, len(full)), lit(0))
	neg("trailing-after-short-final", 4, "ErrAuth", mb(0, m), lit(0))
	neg("truncated-in-final", 4, "ErrAuth", mb(0, m-1))
	neg("truncated-in-middle", 4, "ErrAuth", mb(0, c0-1))
	neg("final-shorter-than-tag", 4, "ErrTruncated", mb(0, c1+TagSize-1))
	neg("header-only", 4, "ErrTruncated", mb(0, h0))
	neg("short-header", 4, "ErrTruncated", mb(0, 10))
	neg("no-data", 4, "ErrTruncated")
	neg("wrong-index", 3, "ErrAuth", mb(0, m))
	neg("flipped-chunk-bit", 4, "ErrAuth", flipBit(c0+5)...)
	neg("flipped-tag-bit", 4, "ErrAuth", flipBit(m-1)...)
	neg("flipped-salt-bit", 4, "ErrAuth", flipBit(20)...)
	neg("chunk-size-changed", 4, "ErrAuth", setByte(9, 0x02)...)
	neg("bad-magic", 4, "ErrBadHeader", setByte(0, 'X')...)
	neg("bad-version", 4, "ErrBadHeader", setByte(4, 2)...)
	neg("bad-kind", 4, "ErrBadHeader", setByte(5, 2)...)
	neg("reserved-byte-6", 4, "ErrBadHeader", setByte(6, 1)...)
	neg("reserved-byte-31", 4, "ErrBadHeader", setByte(31, 1)...)
	neg("chunk-size-not-power-of-two", 4, "ErrBadHeader", setByte(11, 1)...)
	neg("chunk-size-too-small", 4, "ErrBadHeader", append([]part{mb(0, 8), lit(0, 0, 0x80, 0)}, mb(12, m))...)
	neg("chunk-size-too-large", 4, "ErrBadHeader", append([]part{mb(0, 8), lit(0x01, 0, 0, 0)}, mb(12, m))...)
	neg("empty-final-after-data", 4, "ErrFormat", mb(0, c0), part{Hex: hex.EncodeToString(emptyFinal)})
	vs.FileNegative = append(vs.FileNegative, streamCase{
		Name: "wrong-key", KeyHex: hex.EncodeToString(testKey(0x41)), Index: 4, Parts: []part{mb(0, m)}, ExpectedError: "ErrAuth",
	})

	for _, s := range []struct {
		total int64
		chunk int
	}{
		{0, c},
		{47, c},
		{48, c},
		{49, c},
		{int64(HeaderSize + block), c},
		{int64(HeaderSize + block + 1), c},
		{int64(HeaderSize + block + 15), c},
		{int64(HeaderSize + block + 16), c},
		{int64(HeaderSize + block + 17), c},
		{int64(HeaderSize + 2*block), c},
		{48, c + 1},
		{48, MaxChunkSize * 2},
		{HeaderSize + MaxChunks*int64(block), c},
		{HeaderSize + MaxChunks*int64(block) + 17, c},
		{CiphertextSize(10<<30, DefaultChunkSize), DefaultChunkSize},
		{CiphertextSize(10<<30, DefaultChunkSize) + 1, DefaultChunkSize},
	} {
		p, ok := PlaintextSize(s.total, s.chunk)
		vs.Sizes = append(vs.Sizes, sizeVector{Total: s.total, ChunkSize: s.chunk, Valid: ok, Plaintext: p})
	}

	fb := func(from, to int) part { return b("exactly-one-chunk", from, to) }
	fl := len(full)
	val := func(name string, declared int64, want string, complete bool, parts ...part) {
		vs.Validator = append(vs.Validator, validatorVector{Name: name, DeclaredSize: declared, Parts: parts, ExpectedError: want, Complete: complete})
	}
	val("complete-stream", int64(fl), "", true, fb(0, fl))
	val("partial-stream", int64(fl), "", false, fb(0, 40))
	val("declared-size-not-a-stream-size", int64(fl)+1, "ErrFormat", false, fb(0, 40))
	val("empty-final-after-data-size", int64(fl)+TagSize, "ErrFormat", false, fb(0, 12))
	val("data-beyond-declared-size", int64(fl)-1, "ErrFormat", false, fb(0, fl))
	val("declared-size-below-minimum", MinFileSize-1, "ErrFormat", false)
	val("bad-magic", int64(fl), "ErrFormat", false, lit('T', 'T', 'E', '1'))
	val("bad-version", int64(fl), "ErrFormat", false, fb(0, 4), lit(2))
	val("bad-kind", int64(fl), "ErrFormat", false, fb(0, 5), lit(2))
	val("reserved-byte-7", int64(fl), "ErrFormat", false, fb(0, 7), lit(1))
	val("chunk-size-too-small", int64(fl), "ErrFormat", false, fb(0, 8), lit(0, 0, 0x80, 0))
	val("reserved-byte-28", int64(fl), "ErrFormat", false, fb(0, 28), lit(1))

	vs.Metadata, vs.MetadataNegative = generateMetadata(t, key)
	vs.Messages, vs.MessageNegative = generateMessages(t, key)
	vs.SecretsDescription = secretVectorDoc
	vs.Secrets, vs.SecretNegative = generateSecrets(t)
	return vs
}

// sealFixed runs f with a fixed nonce.
func sealFixed(t *testing.T, nonce []byte, f func() (string, error)) string {
	t.Helper()
	defer withFixedRand(nonce)()
	s, err := f()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// generateMetadata builds the metadata vectors.
func generateMetadata(t *testing.T, key []byte) ([]metadataVector, []sealedNegative) {
	t.Helper()
	var pos []metadataVector
	ms := map[string]Metadata{
		"with-path":    {Index: 1, Count: 3, Name: "Rapport <final> & été.pdf", Path: "projets/2026/Q4", Type: "application/pdf", Size: 1234567, SHA256: hexSum([]byte("a"))},
		"without-path": {Index: 0, Count: 1, Name: "notes.txt", Type: "", Size: 0, SHA256: hexSum(nil)},
	}
	for _, name := range []string{"with-path", "without-path"} {
		m := ms[name]
		nonce := fixed("nonce metadata "+name, NonceSize)
		s := sealFixed(t, nonce, func() (string, error) { return SealMetadata(key, m.Index, m) })
		b, _ := base64.RawURLEncoding.DecodeString(s)
		plain, err := metadataAEADOpen(key, m.Index, b)
		if err != nil {
			t.Fatal(err)
		}
		pos = append(pos, metadataVector{Name: name, Index: m.Index, NonceHex: hex.EncodeToString(nonce), Plaintext: string(plain), Metadata: plain, Sealed: s})
	}
	good := pos[0].Sealed
	sha := `"` + hexSum(nil) + `"`
	raw := func(name, json string) sealedNegative {
		s := sealFixed(t, fixed("nonce metadata "+name, NonceSize), func() (string, error) { return sealMetadataRaw(key, 1, []byte(json)) })
		return sealedNegative{Name: name, Index: 1, Sealed: s, ExpectedError: "ErrInvalidMetadata"}
	}
	obj := func(fields string) string {
		return `{"v":1,"index":1,"count":2,` + fields + `}`
	}
	mod := func(f func([]byte) []byte) string {
		b, _ := base64.RawURLEncoding.DecodeString(good)
		return base64.RawURLEncoding.EncodeToString(f(b))
	}
	neg := []sealedNegative{
		{Name: "wrong-key", KeyHex: hex.EncodeToString(testKey(0x41)), Index: 1, Sealed: good, ExpectedError: "ErrAuth"},
		{Name: "wrong-index", Index: 2, Sealed: good, ExpectedError: "ErrAuth"},
		{Name: "flipped-bit", Index: 1, Sealed: mod(func(b []byte) []byte { b[len(b)-1] ^= 1; return b }), ExpectedError: "ErrAuth"},
		{Name: "flipped-nonce-bit", Index: 1, Sealed: mod(func(b []byte) []byte { b[1] ^= 1; return b }), ExpectedError: "ErrAuth"},
		{Name: "bad-version-byte", Index: 1, Sealed: mod(func(b []byte) []byte { b[0] = 2; return b }), ExpectedError: "ErrEncoding"},
		{Name: "shorter-than-overhead", Index: 1, Sealed: mod(func(b []byte) []byte { return b[:sealedOverhead-1] }), ExpectedError: "ErrEncoding"},
		{Name: "padding", Index: 1, Sealed: good + "=", ExpectedError: "ErrEncoding"},
		{Name: "line-break", Index: 1, Sealed: good[:8] + "\n" + good[8:], ExpectedError: "ErrEncoding"},
		{Name: "standard-alphabet", Index: 1, Sealed: "+" + good[1:], ExpectedError: "ErrEncoding"},
		{Name: "too-long", Index: 1, Sealed: strings.Repeat("A", base64.RawURLEncoding.EncodedLen(MaxMetadataSize)+1), ExpectedError: "ErrEncoding"},
		raw("not-an-object", `[]`),
		raw("json-null", `null`),
		raw("trailing-data", obj(`"name":"a","type":"","size":0,"sha256":`+sha)+`x`),
		raw("unknown-field", obj(`"name":"a","type":"","size":0,"sha256":`+sha+`,"extra":1`)),
		raw("field-name-case", obj(`"Name":"a","type":"","size":0,"sha256":`+sha)),
		raw("null-field", obj(`"name":"a","path":null,"type":"","size":0,"sha256":`+sha)),
		raw("missing-field", obj(`"name":"a","size":0,"sha256":`+sha)),
		raw("wrong-type", obj(`"name":"a","type":"","size":"0","sha256":`+sha)),
		raw("version-2", `{"v":2,"index":1,"count":2,"name":"a","type":"","size":0,"sha256":`+sha+`}`),
		raw("index-mismatch", `{"v":1,"index":0,"count":2,"name":"a","type":"","size":0,"sha256":`+sha+`}`),
		raw("index-not-below-count", `{"v":1,"index":1,"count":1,"name":"a","type":"","size":0,"sha256":`+sha+`}`),
		raw("empty-name", obj(`"name":"","type":"","size":0,"sha256":`+sha)),
		raw("negative-size", obj(`"name":"a","type":"","size":-1,"sha256":`+sha)),
		raw("uppercase-sha256", obj(`"name":"a","type":"","size":0,"sha256":"`+strings.ToUpper(hexSum(nil))+`"`)),
		raw("invalid-utf8-name", obj(`"name":"a`+"\xff"+`","type":"","size":0,"sha256":`+sha)),
	}
	return pos, neg
}

// metadataAEADOpen decrypts a decoded metadata blob without checks.
func metadataAEADOpen(key []byte, index int, b []byte) ([]byte, error) {
	aead, aad := metadataAEAD(key, index)
	return aead.Open(nil, b[1:1+NonceSize], b[1+NonceSize:], aad)
}

// generateMessages builds the message vectors.
func generateMessages(t *testing.T, key []byte) ([]messageVector, []sealedNegative) {
	t.Helper()
	var pos []messageVector
	texts := []struct{ name, text string }{
		{"empty", ""},
		{"ascii", "Hello, here are the files."},
		{"unicode", "Bonjour, voici les fichiers : été, 日本語, 😀.\nÀ bientôt."},
	}
	for _, m := range texts {
		nonce := fixed("nonce message "+m.name, NonceSize)
		s := sealFixed(t, nonce, func() (string, error) { return SealMessage(key, m.text) })
		pos = append(pos, messageVector{Name: m.name, NonceHex: hex.EncodeToString(nonce), Text: m.text, Sealed: s})
	}
	good := pos[1].Sealed
	b, _ := base64.RawURLEncoding.DecodeString(good)
	b[len(b)-1] ^= 1
	rawMsg := func(name, plain string) sealedNegative {
		s := sealFixed(t, fixed("nonce message "+name, NonceSize), func() (string, error) { return sealMessageRaw(key, []byte(plain)) })
		return sealedNegative{Name: name, Sealed: s, ExpectedError: "ErrInvalidMessage"}
	}
	meta := sealFixed(t, fixed("nonce message metadata", NonceSize), func() (string, error) {
		return SealMetadata(key, 0, Metadata{Index: 0, Count: 1, Name: "a", SHA256: hexSum(nil)})
	})
	neg := []sealedNegative{
		{Name: "wrong-key", KeyHex: hex.EncodeToString(testKey(0x41)), Sealed: good, ExpectedError: "ErrAuth"},
		{Name: "flipped-bit", Sealed: base64.RawURLEncoding.EncodeToString(b), ExpectedError: "ErrAuth"},
		{Name: "metadata-blob", Sealed: meta, ExpectedError: "ErrAuth"},
		{Name: "too-long-encoding", Sealed: strings.Repeat("A", MaxMessageEncodedSize+1), ExpectedError: "ErrEncoding"},
		rawMsg("invalid-utf8", "caf\xe9"),
		rawMsg("too-many-characters", strings.Repeat("a", MaxMessageRunes+1)),
	}
	return pos, neg
}

// build concatenates the parts of a constructed input.
func build(t *testing.T, streams map[string][]byte, parts []part) []byte {
	t.Helper()
	var out []byte
	for _, p := range parts {
		if p.Base != "" {
			out = append(out, streams[p.Base][p.From:p.To]...)
			continue
		}
		b, err := hex.DecodeString(p.Hex)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, b...)
	}
	return out
}

// keyFor returns the override key of a case or the vector key.
func keyFor(t *testing.T, key []byte, override string) []byte {
	t.Helper()
	if override == "" {
		return key
	}
	k, err := hex.DecodeString(override)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// verifyVectors checks every vector against the implementation.
func verifyVectors(t *testing.T, vs *vectorSet) {
	t.Helper()
	key, err := hex.DecodeString(vs.KeyHex)
	if err != nil {
		t.Fatal(err)
	}
	if k, err := DecodeKey(vs.KeyFragment); err != nil || !bytes.Equal(k, key) {
		t.Fatalf("key fragment: %v", err)
	}
	streams := map[string][]byte{}
	for _, f := range vs.Files {
		ct, err := base64.StdEncoding.DecodeString(f.CiphertextBase64)
		if err != nil || len(ct) != f.CiphertextLength || hexSum(ct) != f.CiphertextSHA256Hex {
			t.Fatalf("%s: ciphertext encoding", f.Name)
		}
		salt, _ := hex.DecodeString(f.SaltHex)
		if again := encryptFixed(t, key, f.Index, f.ChunkSize, f.PlaintextLength, salt); !bytes.Equal(again, ct) {
			t.Fatalf("%s: encryption differs", f.Name)
		}
		plain, err := decrypt(key, f.Index, ct)
		if err != nil || hexSum(plain) != f.PlaintextSHA256Hex || !bytes.Equal(plain, pattern(f.PlaintextLength)) {
			t.Fatalf("%s: decryption: %v", f.Name, err)
		}
		if CiphertextSize(int64(f.PlaintextLength), f.ChunkSize) != int64(len(ct)) {
			t.Fatalf("%s: size", f.Name)
		}
		streams[f.Name] = ct
	}
	for _, c := range vs.FileNegative {
		_, err := decrypt(keyFor(t, key, c.KeyHex), c.Index, build(t, streams, c.Parts))
		if got := errorName(err); got != c.ExpectedError {
			t.Fatalf("file %s: got %s (%v), want %s", c.Name, got, err, c.ExpectedError)
		}
	}
	for _, s := range vs.Sizes {
		p, ok := PlaintextSize(s.Total, s.ChunkSize)
		if ok != s.Valid || p != s.Plaintext || ValidSize(s.Total, s.ChunkSize) != s.Valid {
			t.Fatalf("size %+v: got %d %v", s, p, ok)
		}
	}
	for _, c := range vs.Validator {
		in := build(t, streams, c.Parts)
		for _, step := range []int{len(in), 1} {
			got, complete := runValidator(c.DeclaredSize, in, step)
			if got != c.ExpectedError || complete != c.Complete {
				t.Fatalf("validator %s (step %d): got %q %v", c.Name, step, got, complete)
			}
		}
	}
	for _, m := range vs.Metadata {
		var want Metadata
		var w metadataWire
		if err := json.Unmarshal(m.Metadata, &w); err != nil {
			t.Fatal(err)
		}
		want = Metadata{Index: w.Index, Count: w.Count, Name: w.Name, Path: w.Path, Type: w.Type, Size: w.Size, SHA256: w.SHA256}
		nonce, _ := hex.DecodeString(m.NonceHex)
		if s := sealFixed(t, nonce, func() (string, error) { return SealMetadata(key, m.Index, want) }); s != m.Sealed {
			t.Fatalf("metadata %s: sealing differs", m.Name)
		}
		if s := sealFixed(t, nonce, func() (string, error) { return sealMetadataRaw(key, m.Index, []byte(m.Plaintext)) }); s != m.Sealed {
			t.Fatalf("metadata %s: plaintext differs", m.Name)
		}
		got, err := OpenMetadata(key, m.Index, m.Sealed)
		if err != nil || got != want {
			t.Fatalf("metadata %s: %v", m.Name, err)
		}
	}
	for _, c := range vs.MetadataNegative {
		_, err := OpenMetadata(keyFor(t, key, c.KeyHex), c.Index, c.Sealed)
		if got := errorName(err); got != c.ExpectedError {
			t.Fatalf("metadata %s: got %s (%v), want %s", c.Name, got, err, c.ExpectedError)
		}
	}
	for _, m := range vs.Messages {
		nonce, _ := hex.DecodeString(m.NonceHex)
		if s := sealFixed(t, nonce, func() (string, error) { return SealMessage(key, m.Text) }); s != m.Sealed {
			t.Fatalf("message %s: sealing differs", m.Name)
		}
		if got, err := OpenMessage(key, m.Sealed); err != nil || got != m.Text {
			t.Fatalf("message %s: %v", m.Name, err)
		}
	}
	for _, c := range vs.MessageNegative {
		_, err := OpenMessage(keyFor(t, key, c.KeyHex), c.Sealed)
		if got := errorName(err); got != c.ExpectedError {
			t.Fatalf("message %s: got %s (%v), want %s", c.Name, got, err, c.ExpectedError)
		}
	}
	verifySecrets(t, vs)
}

// runValidator feeds in to a new Validator in slices of step bytes and
// returns the error name and whether the stream is complete.
func runValidator(declared int64, in []byte, step int) (string, bool) {
	v, err := NewValidator(declared)
	if err != nil {
		return errorName(err), false
	}
	for len(in) > 0 {
		n := min(step, len(in))
		if err := v.Check(in[:n]); err != nil {
			return errorName(err), false
		}
		in = in[n:]
	}
	return "", v.Complete()
}
