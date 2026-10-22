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
	"time"
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
	vectorTransfer  = "tr_01JVECTOR0000000000000000"
	// vectorGrantExpiry is an expiry encoded as the big-endian uint64 Unix
	// time in seconds (2026-01-01T00:00:00Z).
	vectorGrantExpiry = "000000006955b900"
	// vectorAdminSession is an administrator session token (CSRF vector).
	vectorAdminSession = "as_01JVECTOR000000000000000000000000000000000"
	// vectorTOTPSecret is the HMAC-SHA1 seed of RFC 6238 Appendix B.
	vectorTOTPSecret = "12345678901234567890"
	// vectorRecoveryCode is a recovery code in normalized form.
	vectorRecoveryCode = "rc-0123-4567-89AB"
)

// totpVector is one TOTP reference value: a Unix time and its code.
type totpVector struct {
	Time int64  `json:"time"`
	Code string `json:"code"`
}

// rfc6238SHA1 is the SHA-1 table of RFC 6238 Appendix B, reduced from 8 to 6
// digits (the last 6 digits, since a code is the truncated value modulo
// 10^digits).
var rfc6238SHA1 = [6]totpVector{
	{59, "287082"},          // 94287082
	{1111111109, "081804"},  // 07081804
	{1111111111, "050471"},  // 14050471
	{1234567890, "005924"},  // 89005924
	{2000000000, "279037"},  // 69279037
	{20000000000, "353130"}, // 65353130
}

// vectors freezes the formats. Any unintended change of a format, label,
// derivation or layout makes TestVectors fail. The layout is checked by an
// independent, standard-library-only implementation in
// vectors_external_test.go. Plaintext bytes are pattern(n) (helpers_test.go):
// byte i = (7*i + i/251) mod 251.
type vectors struct {
	Comment              string        `json:"comment"`
	MasterKey            string        `json:"master_key_base64"`
	KeyID                string        `json:"key_id"`
	TenantID             string        `json:"tenant_id"`
	FileID               string        `json:"file_id"`
	RowID                string        `json:"row_id"`
	DEK                  string        `json:"dek_hex"`
	WrappedDEK           string        `json:"wrapped_dek_hex"`
	WrappedSecret        string        `json:"wrapped_secret_hex"`
	Secret               string        `json:"secret"`
	ChunkSize            int           `json:"chunk_size"`
	StreamPlaintextSize  int           `json:"stream_plaintext_size"`
	Stream               string        `json:"stream_hex"`
	CheckpointOffset     int           `json:"checkpoint_offset"`
	CheckpointExtra      string        `json:"checkpoint_extra_hex"`
	CheckpointState      string        `json:"checkpoint_state_hex"`
	CheckpointCiphertext string        `json:"checkpoint_ciphertext_hex"`
	MACChallengeID       string        `json:"mac_challenge_id"`
	MACCode              string        `json:"mac_code"`
	MACOTP               string        `json:"mac_otp_hex"`
	MACSessionToken      string        `json:"mac_session_token"`
	MACCSRF              string        `json:"mac_csrf_hex"`
	MACRecognitionEmail  string        `json:"mac_recognition_email"`
	MACRecognition       string        `json:"mac_recognition_hex"`
	MACGrantTransferID   string        `json:"mac_download_grant_transfer_id"`
	MACGrantExpiry       string        `json:"mac_download_grant_expiry_hex"`
	MACDownloadGrant     string        `json:"mac_download_grant_hex"`
	MACAdminSession      string        `json:"mac_admin_session_token"`
	MACAdminCSRF         string        `json:"mac_admin_csrf_hex"`
	WrappedAdminTOTP     string        `json:"wrapped_admin_totp_hex"`
	TOTPSecret           string        `json:"totp_secret_hex"`
	TOTPSecretBase32     string        `json:"totp_secret_base32"`
	TOTPRFC6238          [6]totpVector `json:"totp_rfc6238"`
	RecoveryCode         string        `json:"recovery_code"`
	RecoveryCodeMAC      string        `json:"recovery_code_mac_hex"`
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
	v.MACGrantTransferID, v.MACGrantExpiry = vectorTransfer, vectorGrantExpiry
	if mac, err = k.MAC(MACPurposeDownloadGrant, []byte(vectorTenant), []byte(vectorTransfer), mustHex(t, vectorGrantExpiry)); err != nil {
		t.Fatal(err)
	}
	v.MACDownloadGrant = hex.EncodeToString(mac)
	v.MACAdminSession = vectorAdminSession
	if mac, err = k.MAC(MACPurposeAdminCSRF, []byte(vectorAdminSession)); err != nil {
		t.Fatal(err)
	}
	v.MACAdminCSRF = hex.EncodeToString(mac)

	totpSecret := []byte(vectorTOTPSecret)
	v.TOTPSecret = hex.EncodeToString(totpSecret)
	v.TOTPSecretBase32 = EncodeTOTPSecret(totpSecret)
	setRand(t, &detReader{seed: "admin-totp"})
	if blob, err = k.Wrap(PurposeAdminTOTP, vectorTenant, vectorRow, totpSecret); err != nil {
		t.Fatal(err)
	}
	v.WrappedAdminTOTP = hex.EncodeToString(blob)
	for i, rv := range rfc6238SHA1 {
		v.TOTPRFC6238[i] = totpVector{rv.Time, TOTPCode(totpSecret, TOTPCounter(time.Unix(rv.Time, 0)))}
	}
	v.RecoveryCode = vectorRecoveryCode
	recoveryMAC, err := RecoveryCodeMAC(totpSecret, vectorRecoveryCode)
	if err != nil {
		t.Fatal(err)
	}
	v.RecoveryCodeMAC = hex.EncodeToString(recoveryMAC)
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
	if ok, err := k.VerifyMAC(MACPurposeDownloadGrant, mustHex(t, want.MACDownloadGrant),
		[]byte(want.TenantID), []byte(want.MACGrantTransferID), mustHex(t, want.MACGrantExpiry)); !ok || err != nil {
		t.Fatalf("download grant MAC: %v, %v", ok, err)
	}
	if ok, err := k.VerifyMAC(MACPurposeAdminCSRF, mustHex(t, want.MACAdminCSRF), []byte(want.MACAdminSession)); !ok || err != nil {
		t.Fatalf("admin CSRF MAC: %v, %v", ok, err)
	}
	if ok, err := k.VerifyMAC(MACPurposeCSRF, mustHex(t, want.MACAdminCSRF), []byte(want.MACAdminSession)); ok || err != nil {
		t.Fatalf("admin CSRF MAC valid as a deposit CSRF MAC: %v, %v", ok, err)
	}
	totpSecret, err := k.Unwrap(PurposeAdminTOTP, want.TenantID, want.RowID, mustHex(t, want.WrappedAdminTOTP))
	if err != nil || !bytes.Equal(totpSecret, mustHex(t, want.TOTPSecret)) {
		t.Fatalf("wrapped admin TOTP secret: %v", err)
	}
	if _, err := k.Unwrap(PurposeSecret, want.TenantID, want.RowID, mustHex(t, want.WrappedAdminTOTP)); err == nil {
		t.Fatal("admin TOTP blob unwraps as a configuration secret")
	}
	if want.TOTPRFC6238 != rfc6238SHA1 {
		t.Fatal("TOTP vectors differ from RFC 6238 Appendix B")
	}
	for _, rv := range want.TOTPRFC6238 {
		if c, ok := VerifyTOTP(totpSecret, rv.Code, time.Unix(rv.Time, 0), 0, false); !ok || c != uint64(rv.Time)/TOTPPeriod {
			t.Fatalf("TOTP vector at %d rejected", rv.Time)
		}
	}
	norm, ok := NormalizeRecoveryCode(want.RecoveryCode)
	if !ok || norm != want.RecoveryCode {
		t.Fatal("recovery code vector")
	}
	if mac, err := RecoveryCodeMAC(totpSecret, norm); err != nil || hex.EncodeToString(mac) != want.RecoveryCodeMAC {
		t.Fatalf("recovery code MAC vector: %v", err)
	}
}
