package tte2

import (
	"bytes"
	"crypto/hkdf"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"golang.org/x/text/unicode/norm"
)

// secretVectorDoc documents the secret vectors inside the vectors file.
const secretVectorDoc = "One-time secrets (e2e-format.md section 3.3, since 2.1). Each secret has its own key (keyHex, keyFragment). " +
	"passphrase is the input before NFC normalization and passphraseNfcHex its UTF-8 bytes after NFC; " +
	"descriptor is absent without a passphrase. passphraseKeyHex is P = PBKDF2-HMAC-SHA256(NFC passphrase, salt, 600000, 32), " +
	"rootKeyHex is K' = HKDF-SHA256(K, salt = P or empty, \"transteira/tte2/v1/secret\"). keyProofHex, keyVerifierHex, proofHex and " +
	"verifierHex are the wire forms of the proofs and their SHA-256. sealedText is the text sealed with textNonceHex. " +
	"file, when present, is a file stream with transfer key K' and index 0 (plaintext: byte i is i mod 251) and its sealed metadata. " +
	"A secretNegative case starts from the secret named by secret, replaces its key (keyHex), passphrase (passphrase, even empty), " +
	"descriptor (descriptor, or none with noDescriptor) and sealed text (sealed); it derives K', then seals text when present, " +
	"else opens the sealed text; expectedError is the first error. keyProofValid tells whether the key proof of the key used matches " +
	"the key verifier of the secret, proofValid whether the proof of the derived K' matches its verifier (false when the derivation fails)."

// descriptorWire is the JSON form of a passphrase descriptor.
type descriptorWire struct {
	KDF        string `json:"kdf"`
	Iterations int    `json:"iterations"`
	Salt       string `json:"salt"`
}

// secretFile is the optional file of a secret vector.
type secretFile struct {
	ChunkSize           int             `json:"chunkSize"`
	SaltHex             string          `json:"saltHex"`
	PlaintextLength     int             `json:"plaintextLength"`
	PlaintextSHA256Hex  string          `json:"plaintextSha256Hex"`
	CiphertextLength    int             `json:"ciphertextLength"`
	CiphertextSHA256Hex string          `json:"ciphertextSha256Hex"`
	CiphertextBase64    string          `json:"ciphertextBase64"`
	MetadataNonceHex    string          `json:"metadataNonceHex"`
	MetadataPlaintext   string          `json:"metadataPlaintext"`
	Metadata            json.RawMessage `json:"metadata"`
	SealedMetadata      string          `json:"sealedMetadata"`
}

// secretVector is a valid one-time secret.
type secretVector struct {
	Name             string          `json:"name"`
	KeyHex           string          `json:"keyHex"`
	KeyFragment      string          `json:"keyFragment"`
	Passphrase       string          `json:"passphrase,omitempty"`
	PassphraseNFCHex string          `json:"passphraseNfcHex,omitempty"`
	Descriptor       *descriptorWire `json:"descriptor,omitempty"`
	PassphraseKeyHex string          `json:"passphraseKeyHex,omitempty"`
	RootKeyHex       string          `json:"rootKeyHex"`
	KeyProofHex      string          `json:"keyProofHex"`
	KeyVerifierHex   string          `json:"keyVerifierHex"`
	ProofHex         string          `json:"proofHex"`
	VerifierHex      string          `json:"verifierHex"`
	TextNonceHex     string          `json:"textNonceHex"`
	Text             string          `json:"text"`
	SealedText       string          `json:"sealedText"`
	File             *secretFile     `json:"file,omitempty"`
}

// secretNegative is a secret case that must fail.
type secretNegative struct {
	Name          string          `json:"name"`
	Secret        string          `json:"secret"`
	KeyHex        string          `json:"keyHex,omitempty"`
	Passphrase    *string         `json:"passphrase,omitempty"`
	Descriptor    *descriptorWire `json:"descriptor,omitempty"`
	NoDescriptor  bool            `json:"noDescriptor,omitempty"`
	Text          *string         `json:"text,omitempty"`
	Sealed        string          `json:"sealed,omitempty"`
	KeyProofValid bool            `json:"keyProofValid"`
	ProofValid    bool            `json:"proofValid"`
	ExpectedError string          `json:"expectedError"`
}

// toWire returns the JSON form of d, nil for the zero descriptor.
func toWire(d PassphraseDescriptor) *descriptorWire {
	if d.IsZero() {
		return nil
	}
	return &descriptorWire{KDF: d.KDF, Iterations: d.Iterations, Salt: d.EncodedSalt()}
}

// fromWire decodes the JSON form of a descriptor, the zero descriptor for nil.
func fromWire(w *descriptorWire) (PassphraseDescriptor, error) {
	if w == nil {
		return PassphraseDescriptor{}, nil
	}
	salt, err := DecodePassphraseSalt(w.Salt)
	if err != nil {
		return PassphraseDescriptor{}, err
	}
	return PassphraseDescriptor{KDF: w.KDF, Iterations: w.Iterations, Salt: salt}, nil
}

// fixedDescriptor returns a descriptor with a fixed salt.
func fixedDescriptor(label string) PassphraseDescriptor {
	return PassphraseDescriptor{KDF: PassphraseKDF, Iterations: PassphraseIterations, Salt: fixed("passphrase salt "+label, PassphraseSaltSize)}
}

// mustHex returns the bytes of a hexadecimal string.
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// generateSecrets builds the secret vectors.
func generateSecrets(t *testing.T) ([]secretVector, []secretNegative) {
	t.Helper()
	specs := []struct {
		name, passphrase, text string
		seed                   byte
		file                   int // plaintext length of the file, -1 for none
	}{
		// "e" + U+0301 and U+2126 (ohm sign) change under NFC.
		{"passphrase-nfc-with-file", "Café au lait ☕ Ω 2026", "Code d'accès : 4F7#kp9\nÉté, 日本語, 😀.", 0x50, 300},
		{"no-passphrase", "", "Le mot de passe du coffre est : correct horse battery staple", 0x51, -1},
		{"no-passphrase-empty-text-with-file", "", "", 0x52, 0},
	}
	var pos []secretVector
	for _, s := range specs {
		key := testKey(s.seed)
		frag, _ := EncodeKey(key)
		v := secretVector{Name: s.name, KeyHex: hex.EncodeToString(key), KeyFragment: frag, Passphrase: s.passphrase, Text: s.text}
		var d PassphraseDescriptor
		if s.passphrase != "" {
			d = fixedDescriptor(s.name)
			nfc := norm.NFC.String(s.passphrase)
			if nfc == s.passphrase {
				t.Fatalf("%s: passphrase does not change under NFC", s.name)
			}
			p, _ := pbkdf2.Key(sha256.New, nfc, d.Salt, PassphraseIterations, KeySize)
			v.PassphraseNFCHex = hex.EncodeToString([]byte(nfc))
			v.PassphraseKeyHex = hex.EncodeToString(p)
			v.Descriptor = toWire(d)
		}
		root, err := DeriveSecretKey(key, s.passphrase, d)
		if err != nil {
			t.Fatal(err)
		}
		kp, _ := SecretKeyProof(key)
		pr, _ := SecretProof(root)
		v.RootKeyHex = hex.EncodeToString(root)
		v.KeyProofHex, v.KeyVerifierHex = EncodeProof(kp), EncodeProof(SecretVerifier(kp))
		v.ProofHex, v.VerifierHex = EncodeProof(pr), EncodeProof(SecretVerifier(pr))
		nonce := fixed("nonce secret "+s.name, NonceSize)
		v.TextNonceHex = hex.EncodeToString(nonce)
		v.SealedText = sealFixed(t, nonce, func() (string, error) { return SealSecret(root, s.text) })
		if s.file >= 0 {
			v.File = generateSecretFile(t, s.name, root, s.file)
		}
		pos = append(pos, v)
	}
	return pos, generateSecretNegative(t, pos)
}

// generateSecretFile builds the file of a secret vector.
func generateSecretFile(t *testing.T, name string, root []byte, n int) *secretFile {
	t.Helper()
	salt := fixed("salt secret "+name, SaltSize)
	ct := encryptFixed(t, root, 0, MinChunkSize, n, salt)
	m := Metadata{Index: 0, Count: 1, Name: "clé.txt", Type: "text/plain", Size: int64(n), SHA256: hexSum(pattern(n))}
	nonce := fixed("nonce secret metadata "+name, NonceSize)
	sealed := sealFixed(t, nonce, func() (string, error) { return SealMetadata(root, 0, m) })
	b, _ := base64.RawURLEncoding.DecodeString(sealed)
	plain, err := metadataAEADOpen(root, 0, b)
	if err != nil {
		t.Fatal(err)
	}
	return &secretFile{
		ChunkSize: MinChunkSize, SaltHex: hex.EncodeToString(salt), PlaintextLength: n,
		PlaintextSHA256Hex: hexSum(pattern(n)), CiphertextLength: len(ct), CiphertextSHA256Hex: hexSum(ct),
		CiphertextBase64: base64.StdEncoding.EncodeToString(ct), MetadataNonceHex: hex.EncodeToString(nonce),
		MetadataPlaintext: string(plain), Metadata: plain, SealedMetadata: sealed,
	}
}

// generateSecretNegative builds the negative secret vectors from the valid
// ones (pos[0] has a passphrase and a file, pos[1] has neither, pos[2] has a
// file and an empty text).
func generateSecretNegative(t *testing.T, pos []secretVector) []secretNegative {
	t.Helper()
	nfc, plain, withFile := pos[0], pos[1], pos[2]
	plainRoot := mustHex(t, plain.RootKeyHex)
	str := func(s string) *string { return &s }
	desc := func(kdf string, iterations int, salt string) *descriptorWire {
		return &descriptorWire{KDF: kdf, Iterations: iterations, Salt: salt}
	}
	good := nfc.Descriptor
	raw := func(name, text string) secretNegative {
		s := sealFixed(t, fixed("nonce secret "+name, NonceSize), func() (string, error) { return sealSecretRaw(plainRoot, []byte(text)) })
		return secretNegative{Name: name, Secret: plain.Name, Sealed: s, KeyProofValid: true, ProofValid: true, ExpectedError: "ErrInvalidSecret"}
	}
	mod := func(f func([]byte) []byte) string {
		b, _ := base64.RawURLEncoding.DecodeString(plain.SealedText)
		return base64.RawURLEncoding.EncodeToString(f(b))
	}
	message := sealFixed(t, fixed("nonce secret message", NonceSize), func() (string, error) { return SealMessage(plainRoot, plain.Text) })
	// A canonical 22-character salt ends with A, Q, g or w (its 4 low bits are zero).
	nonCanonical := good.Salt[:21] + "B"
	if !strings.ContainsRune("AQgw", rune(good.Salt[21])) {
		t.Fatal("unexpected salt encoding")
	}
	return []secretNegative{
		{Name: "wrong-passphrase", Secret: nfc.Name, Passphrase: str("Café au lait ☕ Ω 2027"), KeyProofValid: true, ExpectedError: "ErrAuth"},
		{Name: "passphrase-case-changed", Secret: nfc.Name, Passphrase: str(strings.ToUpper(nfc.Passphrase)), KeyProofValid: true, ExpectedError: "ErrAuth"},
		{Name: "wrong-key", Secret: plain.Name, KeyHex: hex.EncodeToString(testKey(0x41)), ExpectedError: "ErrAuth"},
		{Name: "descriptor-removed", Secret: nfc.Name, Passphrase: str(""), NoDescriptor: true, KeyProofValid: true, ExpectedError: "ErrAuth"},
		{Name: "descriptor-salt-changed", Secret: nfc.Name, Descriptor: desc(good.KDF, good.Iterations, toWire(fixedDescriptor("other")).Salt), KeyProofValid: true, ExpectedError: "ErrAuth"},
		{Name: "descriptor-added", Secret: plain.Name, Passphrase: str("a"), Descriptor: good, KeyProofValid: true, ExpectedError: "ErrAuth"},
		{Name: "other-iteration-count", Secret: nfc.Name, Descriptor: desc(good.KDF, 100000, good.Salt), KeyProofValid: true, ExpectedError: "ErrInvalidPassphrase"},
		{Name: "other-kdf", Secret: nfc.Name, Descriptor: desc("argon2id", good.Iterations, good.Salt), KeyProofValid: true, ExpectedError: "ErrInvalidPassphrase"},
		{Name: "salt-15-bytes", Secret: nfc.Name, Descriptor: desc(good.KDF, good.Iterations, base64.RawURLEncoding.EncodeToString(make([]byte, 15))), KeyProofValid: true, ExpectedError: "ErrInvalidPassphrase"},
		{Name: "salt-17-bytes", Secret: nfc.Name, Descriptor: desc(good.KDF, good.Iterations, base64.RawURLEncoding.EncodeToString(make([]byte, 17))), KeyProofValid: true, ExpectedError: "ErrInvalidPassphrase"},
		{Name: "salt-not-canonical", Secret: nfc.Name, Descriptor: desc(good.KDF, good.Iterations, nonCanonical), KeyProofValid: true, ExpectedError: "ErrInvalidPassphrase"},
		{Name: "salt-padded", Secret: nfc.Name, Descriptor: desc(good.KDF, good.Iterations, good.Salt[:20]+"=="), KeyProofValid: true, ExpectedError: "ErrInvalidPassphrase"},
		{Name: "empty-passphrase", Secret: nfc.Name, Passphrase: str(""), KeyProofValid: true, ExpectedError: "ErrInvalidPassphrase"},
		{Name: "passphrase-without-descriptor", Secret: plain.Name, Passphrase: str("a"), KeyProofValid: true, ExpectedError: "ErrInvalidPassphrase"},
		{Name: "passphrase-over-1024-bytes", Secret: nfc.Name, Passphrase: str(strings.Repeat("a", MaxPassphraseSize+1)), KeyProofValid: true, ExpectedError: "ErrInvalidPassphrase"},
		// U+0958 (3 bytes) is a composition exclusion: NFC gives U+0915 U+093C (6 bytes).
		{Name: "passphrase-over-1024-bytes-after-nfc", Secret: nfc.Name, Passphrase: str(strings.Repeat("क़", 300)), KeyProofValid: true, ExpectedError: "ErrInvalidPassphrase"},
		{Name: "text-over-10000-code-points", Secret: plain.Name, Text: str(strings.Repeat("é", MaxSecretRunes+1)), KeyProofValid: true, ProofValid: true, ExpectedError: "ErrInvalidSecret"},
		raw("sealed-text-over-10000-code-points", strings.Repeat("a", MaxSecretRunes+1)),
		raw("sealed-text-invalid-utf8", "caf\xe9"),
		{Name: "metadata-blob", Secret: withFile.Name, Sealed: withFile.File.SealedMetadata, KeyProofValid: true, ProofValid: true, ExpectedError: "ErrAuth"},
		{Name: "message-blob", Secret: plain.Name, Sealed: message, KeyProofValid: true, ProofValid: true, ExpectedError: "ErrAuth"},
		{Name: "other-secret-text", Secret: plain.Name, Sealed: withFile.SealedText, KeyProofValid: true, ProofValid: true, ExpectedError: "ErrAuth"},
		{Name: "flipped-bit", Secret: plain.Name, Sealed: mod(func(b []byte) []byte { b[len(b)-1] ^= 1; return b }), KeyProofValid: true, ProofValid: true, ExpectedError: "ErrAuth"},
		{Name: "flipped-nonce-bit", Secret: plain.Name, Sealed: mod(func(b []byte) []byte { b[1] ^= 1; return b }), KeyProofValid: true, ProofValid: true, ExpectedError: "ErrAuth"},
		{Name: "truncated", Secret: plain.Name, Sealed: mod(func(b []byte) []byte { return b[:len(b)-1] }), KeyProofValid: true, ProofValid: true, ExpectedError: "ErrAuth"},
		{Name: "bad-version-byte", Secret: plain.Name, Sealed: mod(func(b []byte) []byte { b[0] = 2; return b }), KeyProofValid: true, ProofValid: true, ExpectedError: "ErrEncoding"},
		{Name: "shorter-than-overhead", Secret: plain.Name, Sealed: mod(func(b []byte) []byte { return b[:sealedOverhead-1] }), KeyProofValid: true, ProofValid: true, ExpectedError: "ErrEncoding"},
		{Name: "padding", Secret: plain.Name, Sealed: plain.SealedText + "=", KeyProofValid: true, ProofValid: true, ExpectedError: "ErrEncoding"},
		{Name: "standard-alphabet", Secret: plain.Name, Sealed: "+" + plain.SealedText[1:], KeyProofValid: true, ProofValid: true, ExpectedError: "ErrEncoding"},
		{Name: "too-long-encoding", Secret: plain.Name, Sealed: "AQ" + strings.Repeat("A", MaxSecretEncodedSize-1), KeyProofValid: true, ProofValid: true, ExpectedError: "ErrEncoding"},
	}
}

// verifySecrets checks the secret vectors against the implementation.
func verifySecrets(t *testing.T, vs *vectorSet) {
	t.Helper()
	byName := map[string]secretVector{}
	for _, v := range vs.Secrets {
		byName[v.Name] = v
		verifySecret(t, v)
	}
	for _, c := range vs.SecretNegative {
		got, keyOK, proofOK := runSecretNegative(t, byName[c.Secret], c)
		if got != c.ExpectedError || keyOK != c.KeyProofValid || proofOK != c.ProofValid {
			t.Fatalf("secret %s: got %s key proof %v proof %v, want %s %v %v", c.Name, got, keyOK, proofOK, c.ExpectedError, c.KeyProofValid, c.ProofValid)
		}
	}
}

// verifySecret checks one valid secret vector.
func verifySecret(t *testing.T, v secretVector) {
	t.Helper()
	key := mustHex(t, v.KeyHex)
	if k, err := DecodeKey(v.KeyFragment); err != nil || !bytes.Equal(k, key) {
		t.Fatalf("%s: key fragment: %v", v.Name, err)
	}
	d, err := fromWire(v.Descriptor)
	if err != nil {
		t.Fatal(err)
	}
	var p []byte
	if v.Passphrase != "" {
		nfc := mustHex(t, v.PassphraseNFCHex)
		if norm.NFC.String(v.Passphrase) != string(nfc) {
			t.Fatalf("%s: NFC form differs", v.Name)
		}
		p, _ = pbkdf2.Key(sha256.New, string(nfc), d.Salt, PassphraseIterations, KeySize)
		if hex.EncodeToString(p) != v.PassphraseKeyHex {
			t.Fatalf("%s: P differs", v.Name)
		}
	}
	root, err := DeriveSecretKey(key, v.Passphrase, d)
	if err != nil || hex.EncodeToString(root) != v.RootKeyHex {
		t.Fatalf("%s: K' differs: %v", v.Name, err)
	}
	if want, _ := hkdf.Key(sha256.New, key, p, InfoSecret, KeySize); !bytes.Equal(want, root) {
		t.Fatalf("%s: K' is not HKDF(K, P)", v.Name)
	}
	kp, _ := SecretKeyProof(key)
	pr, _ := SecretProof(root)
	if EncodeProof(kp) != v.KeyProofHex || EncodeProof(pr) != v.ProofHex ||
		EncodeProof(SecretVerifier(kp)) != v.KeyVerifierHex || EncodeProof(SecretVerifier(pr)) != v.VerifierHex {
		t.Fatalf("%s: proofs differ", v.Name)
	}
	for _, pair := range [][2]string{{v.KeyVerifierHex, v.KeyProofHex}, {v.VerifierHex, v.ProofHex}} {
		ver, err1 := ParseProof(pair[0])
		proof, err2 := ParseProof(pair[1])
		if err1 != nil || err2 != nil || !VerifierMatches(ver, proof) {
			t.Fatalf("%s: verifier does not match", v.Name)
		}
	}
	nonce := mustHex(t, v.TextNonceHex)
	if s := sealFixed(t, nonce, func() (string, error) { return SealSecret(root, v.Text) }); s != v.SealedText {
		t.Fatalf("%s: sealing differs", v.Name)
	}
	if got, err := OpenSecret(root, v.SealedText); err != nil || got != v.Text {
		t.Fatalf("%s: open: %v", v.Name, err)
	}
	if err := CheckSecretFraming(v.SealedText); err != nil || SecretTextIsEmpty(v.SealedText) != (v.Text == "") {
		t.Fatalf("%s: framing: %v", v.Name, err)
	}
	if v.File != nil {
		verifySecretFile(t, v, root)
	}
}

// verifySecretFile checks the file of a secret vector.
func verifySecretFile(t *testing.T, v secretVector, root []byte) {
	t.Helper()
	f := v.File
	ct, err := base64.StdEncoding.DecodeString(f.CiphertextBase64)
	if err != nil || len(ct) != f.CiphertextLength || hexSum(ct) != f.CiphertextSHA256Hex {
		t.Fatalf("%s: file encoding", v.Name)
	}
	if again := encryptFixed(t, root, 0, f.ChunkSize, f.PlaintextLength, mustHex(t, f.SaltHex)); !bytes.Equal(again, ct) {
		t.Fatalf("%s: file encryption differs", v.Name)
	}
	plain, err := decrypt(root, 0, ct)
	if err != nil || hexSum(plain) != f.PlaintextSHA256Hex {
		t.Fatalf("%s: file decryption: %v", v.Name, err)
	}
	var w metadataWire
	if err := json.Unmarshal(f.Metadata, &w); err != nil {
		t.Fatal(err)
	}
	want := Metadata{Index: w.Index, Count: w.Count, Name: w.Name, Path: w.Path, Type: w.Type, Size: w.Size, SHA256: w.SHA256}
	nonce := mustHex(t, f.MetadataNonceHex)
	if s := sealFixed(t, nonce, func() (string, error) { return sealMetadataRaw(root, 0, []byte(f.MetadataPlaintext)) }); s != f.SealedMetadata {
		t.Fatalf("%s: metadata plaintext differs", v.Name)
	}
	got, err := OpenMetadata(root, 0, f.SealedMetadata)
	if err != nil || got != want || got.Count != 1 || got.Size != int64(f.PlaintextLength) || got.SHA256 != f.PlaintextSHA256Hex {
		t.Fatalf("%s: metadata: %v", v.Name, err)
	}
}

// runSecretNegative runs a negative secret case and returns the error name
// and whether the key proof and the proof match the base verifiers.
func runSecretNegative(t *testing.T, base secretVector, c secretNegative) (string, bool, bool) {
	t.Helper()
	key := keyFor(t, mustHex(t, base.KeyHex), c.KeyHex)
	kp, _ := SecretKeyProof(key)
	keyOK := VerifierMatches(mustHex(t, base.KeyVerifierHex), kp)
	pass := base.Passphrase
	if c.Passphrase != nil {
		pass = *c.Passphrase
	}
	w := base.Descriptor
	switch {
	case c.NoDescriptor:
		w = nil
	case c.Descriptor != nil:
		w = c.Descriptor
	}
	d, err := fromWire(w)
	if err != nil {
		return errorName(err), keyOK, false
	}
	root, err := DeriveSecretKey(key, pass, d)
	if err != nil {
		return errorName(err), keyOK, false
	}
	pr, _ := SecretProof(root)
	proofOK := VerifierMatches(mustHex(t, base.VerifierHex), pr)
	if c.Text != nil {
		_, err = SealSecret(root, *c.Text)
		return errorName(err), keyOK, proofOK
	}
	sealed := base.SealedText
	if c.Sealed != "" {
		sealed = c.Sealed
		// The keyless check refuses exactly the framing errors.
		if fe := CheckSecretFraming(sealed); (fe != nil) != (c.ExpectedError == "ErrEncoding") || (fe != nil && errorName(fe) != "ErrEncoding") {
			t.Fatalf("secret %s: framing %v", c.Name, fe)
		}
	}
	_, err = OpenSecret(root, sealed)
	return errorName(err), keyOK, proofOK
}
