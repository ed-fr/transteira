package crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding"
	"encoding/hex"
	"encoding/json"
	"flag"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// update regenerates the reference vectors: go test ./internal/crypto -run TestVectors -update
var update = flag.Bool("update", false, "regenerate testdata/vectors.json")

const (
	vectorsFile     = "testdata/vectors.json"
	vectorTenant    = "ten_01JVECTOR0000000000000000"
	vectorFile      = "fil_01JVECTOR0000000000000000"
	vectorRow       = "wk_01JVECTOR0000000000000000"
	vectorChunk     = MinChunkSize
	vectorStream    = 2*vectorChunk + vectorChunk/2 // 2.5 chunks
	vectorPartial   = vectorChunk + 300             // checkpoint offset
	vectorChallenge = "vch_01JVECTOR00000000000000000000"
	vectorCode      = "042137"
	vectorSession   = "ds_01JVECTOR000000000000000000000000000000000"
	vectorEmail     = "alice@entity-a.example.com"
)

// vectors freezes the formats. Any unintended change of a format, label,
// derivation or layout makes TestVectors fail. The layout is checked by an
// independent, standard-library-only implementation in
// vectors_external_test.go. Plaintext bytes are pattern(n) (helpers_test.go):
// byte i = (7*i + i/251) mod 251.
type vectors struct {
	Comment              string `json:"comment"`
	MasterKey            string `json:"master_key_base64"`
	KeyID                string `json:"key_id"`
	TenantID             string `json:"tenant_id"`
	FileID               string `json:"file_id"`
	RowID                string `json:"row_id"`
	DEK                  string `json:"dek_hex"`
	WrappedDEK           string `json:"wrapped_dek_hex"`
	WrappedSecret        string `json:"wrapped_secret_hex"`
	Secret               string `json:"secret"`
	ChunkSize            int    `json:"chunk_size"`
	StreamPlaintextSize  int    `json:"stream_plaintext_size"`
	Stream               string `json:"stream_hex"`
	CheckpointOffset     int    `json:"checkpoint_offset"`
	CheckpointExtra      string `json:"checkpoint_extra_hex"`
	CheckpointState      string `json:"checkpoint_state_hex"`
	CheckpointCiphertext string `json:"checkpoint_ciphertext_hex"`
	MACChallengeID       string `json:"mac_challenge_id"`
	MACCode              string `json:"mac_code"`
	MACOTP               string `json:"mac_otp_hex"`
	MACSessionToken      string `json:"mac_session_token"`
	MACCSRF              string `json:"mac_csrf_hex"`
	MACRecognitionEmail  string `json:"mac_recognition_email"`
	MACRecognition       string `json:"mac_recognition_hex"`
}

// sha256State returns the marshaled SHA-256 state after hashing data, the
// realistic checkpoint payload of a tus upload.
func sha256State(t *testing.T, data []byte) []byte {
	t.Helper()
	h := sha256.New()
	h.Write(data)
	b, err := h.(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// generateVectors computes the vectors with deterministic randomness.
func generateVectors(t *testing.T) vectors {
	t.Helper()
	k := testKey(t)
	full := pattern(vectorStream)
	v := vectors{
		Comment:             "TransTeira encryption reference vectors; plaintext byte i = (7*i + i/251) mod 251; regenerate only for an intended format change",
		MasterKey:           testKeyB64,
		KeyID:               k.ID(),
		TenantID:            vectorTenant,
		FileID:              vectorFile,
		RowID:               vectorRow,
		Secret:              "smtp-password",
		ChunkSize:           vectorChunk,
		StreamPlaintextSize: vectorStream,
		CheckpointOffset:    vectorPartial,
	}

	setRand(t, &detReader{seed: "dek"})
	dek, err := GenerateDEK()
	if err != nil {
		t.Fatal(err)
	}
	v.DEK = hex.EncodeToString(dek)

	setRand(t, &detReader{seed: "wrap"})
	blob, err := k.Wrap(PurposeDEK, vectorTenant, vectorRow, dek)
	if err != nil {
		t.Fatal(err)
	}
	v.WrappedDEK = hex.EncodeToString(blob)
	blob, err = k.Wrap(PurposeSecret, vectorTenant, vectorRow, []byte(v.Secret))
	if err != nil {
		t.Fatal(err)
	}
	v.WrappedSecret = hex.EncodeToString(blob)

	setRand(t, &detReader{seed: "stream"})
	v.Stream = hex.EncodeToString(encrypt(t, dek, vectorTenant, vectorFile, full, vectorChunk, []int{100}))

	setRand(t, &detReader{seed: "checkpoint"})
	var out bytes.Buffer
	w, err := NewWriter(&out, dek, vectorTenant, vectorFile, WithChunkSize(vectorChunk))
	if err != nil {
		t.Fatal(err)
	}
	writePieces(t, w, full[:vectorPartial], nil)
	extra := sha256State(t, full[:vectorPartial])
	st, err := w.Checkpoint(extra)
	if err != nil {
		t.Fatal(err)
	}
	sb, err := st.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	v.CheckpointExtra = hex.EncodeToString(extra)
	v.CheckpointState = hex.EncodeToString(sb)
	v.CheckpointCiphertext = hex.EncodeToString(out.Bytes())

	v.MACChallengeID, v.MACCode, v.MACSessionToken = vectorChallenge, vectorCode, vectorSession
	mac, err := k.MAC(MACPurposeOTP, []byte(vectorChallenge), []byte(vectorCode))
	if err != nil {
		t.Fatal(err)
	}
	v.MACOTP = hex.EncodeToString(mac)
	if mac, err = k.MAC(MACPurposeCSRF, []byte(vectorSession)); err != nil {
		t.Fatal(err)
	}
	v.MACCSRF = hex.EncodeToString(mac)
	v.MACRecognitionEmail = vectorEmail
	if mac, err = k.MAC(MACPurposeRecognition, []byte(vectorTenant), []byte(vectorEmail)); err != nil {
		t.Fatal(err)
	}
	v.MACRecognition = hex.EncodeToString(mac)
	return v
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestVectors(t *testing.T) {
	got := generateVectors(t)
	if *update {
		b, err := json.MarshalIndent(got, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(vectorsFile), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(vectorsFile, append(b, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(vectorsFile)
	if err != nil {
		t.Fatalf("read vectors (run with -update to create them): %v", err)
	}
	var want vectors
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("generated vectors differ from %s: the format changed", vectorsFile)
	}
	if want.KeyID != testKeyID {
		t.Fatalf("key ID %q, frozen %q", want.KeyID, testKeyID)
	}

	// The stored vectors decode with the current code, independently of how
	// they were generated.
	k, err := ParseMasterKey([]byte(want.MasterKey))
	if err != nil {
		t.Fatal(err)
	}
	dek := mustHex(t, want.DEK)
	unwrapped, err := k.Unwrap(PurposeDEK, want.TenantID, want.RowID, mustHex(t, want.WrappedDEK))
	if err != nil || !bytes.Equal(unwrapped, dek) {
		t.Fatalf("wrapped DEK: %v", err)
	}
	secret, err := k.Unwrap(PurposeSecret, want.TenantID, want.RowID, mustHex(t, want.WrappedSecret))
	if err != nil || string(secret) != want.Secret {
		t.Fatalf("wrapped secret: %v", err)
	}
	full := pattern(want.StreamPlaintextSize)
	stream := mustHex(t, want.Stream)
	plain, err := decrypt(dek, want.TenantID, want.FileID, stream)
	if err != nil || !bytes.Equal(plain, full) {
		t.Fatalf("stream: %v", err)
	}
	ra, err := NewReaderAt(bytes.NewReader(stream), int64(len(stream)), dek, want.TenantID, want.FileID)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := io.ReadAll(io.NewSectionReader(ra, 0, ra.Size())); err != nil || !bytes.Equal(got, full) {
		t.Fatalf("stream by ReaderAt: %v", err)
	}

	st, err := UnmarshalState(mustHex(t, want.CheckpointState))
	if err != nil {
		t.Fatal(err)
	}
	prefix := mustHex(t, want.CheckpointCiphertext)
	if st.CiphertextSize() != int64(len(prefix)) || st.PlaintextSize() != int64(want.CheckpointOffset) {
		t.Fatal("checkpoint sizes")
	}
	dst := bytes.NewBuffer(prefix)
	w, extra, err := ResumeWriter(dst, dek, want.TenantID, want.FileID, st, int64(dst.Len()))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(extra, mustHex(t, want.CheckpointExtra)) {
		t.Fatal("checkpoint extra")
	}
	writePieces(t, w, full[want.CheckpointOffset:], nil)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	r, err := NewReader(dst, dek, want.TenantID, want.FileID)
	if err != nil {
		t.Fatal(err)
	}
	if plain, err := io.ReadAll(r); err != nil || !bytes.Equal(plain, full) {
		t.Fatalf("resumed checkpoint: %v", err)
	}

	if ok, err := k.VerifyMAC(MACPurposeOTP, mustHex(t, want.MACOTP), []byte(want.MACChallengeID), []byte(want.MACCode)); !ok || err != nil {
		t.Fatalf("OTP MAC: %v, %v", ok, err)
	}
	if ok, err := k.VerifyMAC(MACPurposeCSRF, mustHex(t, want.MACCSRF), []byte(want.MACSessionToken)); !ok || err != nil {
		t.Fatalf("CSRF MAC: %v, %v", ok, err)
	}
	if ok, err := k.VerifyMAC(MACPurposeRecognition, mustHex(t, want.MACRecognition),
		[]byte(want.TenantID), []byte(want.MACRecognitionEmail)); !ok || err != nil {
		t.Fatalf("recognition MAC: %v, %v", ok, err)
	}
}
