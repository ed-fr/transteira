package crypto_test

// This file re-implements the documented formats (package documentation of
// internal/crypto) with the standard library only, and checks every item of
// testdata/vectors.json against it. It deliberately does not import the
// package under test: it is the independent implementation that the threat
// model (T-29) relies on to freeze the format.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// extVectors mirrors testdata/vectors.json.
type extVectors struct {
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

// lp returns the big-endian uint32 length of s followed by s.
func lp(s string) []byte {
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(s))), s...)
}

// cat concatenates byte slices.
func cat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

// gcm returns AES-256-GCM keyed with key.
func gcm(t *testing.T, key []byte) cipher.AEAD {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	a, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// hkdf32 derives 32 bytes with HKDF-SHA256 and no salt.
func hkdf32(t *testing.T, secret []byte, info string) []byte {
	t.Helper()
	k, err := hkdf.Key(sha256.New, secret, nil, info, 32)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// plaintextPattern is the documented vector plaintext: byte i = (7*i + i/251) mod 251.
func plaintextPattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte((7*i + i/251) % 251)
	}
	return b
}

func TestVectorsIndependent(t *testing.T) {
	raw, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v extVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	master, err := base64.StdEncoding.DecodeString(v.MasterKey)
	if err != nil || len(master) != 32 {
		t.Fatalf("master key: %v", err)
	}

	// Key ID: "mk_" + hex(HMAC-SHA256(key, "transteira/v1/key-id")[:8]).
	mac := hmac.New(sha256.New, master)
	mac.Write([]byte("transteira/v1/key-id"))
	if id := "mk_" + hex.EncodeToString(mac.Sum(nil)[:8]); id != v.KeyID {
		t.Fatalf("key ID %s, vectors %s", id, v.KeyID)
	}

	// Envelope: version | nonce(12) | GCM, key HKDF(master, "transteira/v1/wrap/"+purpose),
	// AAD lp(label) | lp(purpose) | lp(tenant) | lp(row).
	unwrap := func(purpose, blobHex string) []byte {
		blob := unhex(t, blobHex)
		if len(blob) < 29 || blob[0] != 1 {
			t.Fatalf("%s blob framing", purpose)
		}
		aad := cat(lp("transteira/v1/envelope"), lp(purpose), lp(v.TenantID), lp(v.RowID))
		pt, err := gcm(t, hkdf32(t, master, "transteira/v1/wrap/"+purpose)).Open(nil, blob[1:13], blob[13:], aad)
		if err != nil {
			t.Fatalf("open %s blob: %v", purpose, err)
		}
		return pt
	}
	dek := unhex(t, v.DEK)
	if !bytes.Equal(unwrap("dek", v.WrappedDEK), dek) {
		t.Fatal("wrapped DEK content")
	}
	if string(unwrap("secret", v.WrappedSecret)) != v.Secret {
		t.Fatal("wrapped secret content")
	}

	// Stream: header "TTEF" | 1 | chunk size u32 | prefix(7); chunks sealed with
	// nonce prefix | counter u32 | last flag and AAD
	// lp(label) | header | lp(tenant) | lp(file).
	chunkAEAD := gcm(t, dek)
	decryptStream := func(ct []byte) []byte {
		if len(ct) < 16 || string(ct[:4]) != "TTEF" || ct[4] != 1 {
			t.Fatal("stream header")
		}
		h := ct[:16]
		cs := int(binary.BigEndian.Uint32(h[5:9]))
		if cs != v.ChunkSize {
			t.Fatalf("chunk size %d", cs)
		}
		aad := cat(lp("transteira/v1/stream-chunk"), h, lp(v.TenantID), lp(v.FileID))
		var out []byte
		off := 16
		for counter := uint32(0); ; counter++ {
			end := min(off+cs+16, len(ct))
			last := end-off < cs+16
			nonce := cat(h[9:16], binary.BigEndian.AppendUint32(nil, counter), []byte{0})
			if last {
				nonce[11] = 1
			}
			pt, err := chunkAEAD.Open(nil, nonce, ct[off:end], aad)
			if err != nil {
				t.Fatalf("chunk %d: %v", counter, err)
			}
			out = append(out, pt...)
			off = end
			if last {
				break
			}
		}
		if off != len(ct) {
			t.Fatal("bytes after the final chunk")
		}
		return out
	}
	full := plaintextPattern(v.StreamPlaintextSize)
	stream := unhex(t, v.Stream)
	if !bytes.Equal(decryptStream(stream), full) {
		t.Fatal("stream plaintext")
	}
	if want := 16 + 2*(v.ChunkSize+16) + v.ChunkSize/2 + 16; len(stream) != want {
		t.Fatalf("stream length %d, want %d", len(stream), want)
	}

	// Checkpoint state: "TTCK" | 1 | header(16) | chunks u32 | extra length u32 |
	// tail length u32 | tail; tail = 1 | nonce(12) | GCM(extra | pending) under
	// HKDF(DEK, "transteira/v1/stream-tail"), AAD
	// lp(label) | header | lp(tenant) | lp(file) | chunks u32 | extra length u32.
	st := unhex(t, v.CheckpointState)
	if len(st) < 33 || string(st[:4]) != "TTCK" || st[4] != 1 {
		t.Fatal("state framing")
	}
	h := st[5:21]
	chunks := binary.BigEndian.Uint32(st[21:25])
	extraLen := binary.BigEndian.Uint32(st[25:29])
	tail := st[33:]
	if int(binary.BigEndian.Uint32(st[29:33])) != len(tail) || tail[0] != 1 {
		t.Fatal("tail framing")
	}
	aad := cat(lp("transteira/v1/stream-tail"), h, lp(v.TenantID), lp(v.FileID),
		binary.BigEndian.AppendUint32(nil, chunks), binary.BigEndian.AppendUint32(nil, extraLen))
	pt, err := gcm(t, hkdf32(t, dek, "transteira/v1/stream-tail")).Open(nil, tail[1:13], tail[13:], aad)
	if err != nil {
		t.Fatalf("open tail: %v", err)
	}
	if !bytes.Equal(pt[:extraLen], unhex(t, v.CheckpointExtra)) {
		t.Fatal("checkpoint extra")
	}
	cs := v.ChunkSize
	if !bytes.Equal(pt[extraLen:], full[int(chunks)*cs:v.CheckpointOffset]) {
		t.Fatal("checkpoint pending plaintext")
	}
	// The tail must not be sealed with the DEK itself.
	if _, err := chunkAEAD.Open(nil, tail[1:13], tail[13:], aad); err == nil {
		t.Fatal("tail opens with the DEK")
	}
	// The kept ciphertext is the header and the complete chunks.
	prefix := unhex(t, v.CheckpointCiphertext)
	if !bytes.Equal(prefix[:16], h) || len(prefix) != 16+int(chunks)*(cs+16) {
		t.Fatal("checkpoint ciphertext prefix")
	}
	chunkAAD := cat(lp("transteira/v1/stream-chunk"), h, lp(v.TenantID), lp(v.FileID))
	for c := range chunks {
		off := 16 + int(c)*(cs+16)
		nonce := cat(h[9:16], binary.BigEndian.AppendUint32(nil, c), []byte{0})
		pt, err := chunkAEAD.Open(nil, nonce, prefix[off:off+cs+16], chunkAAD)
		if err != nil || !bytes.Equal(pt, full[int(c)*cs:int(c+1)*cs]) {
			t.Fatalf("checkpoint chunk %d: %v", c, err)
		}
	}

	// Keyed MACs: HMAC-SHA256 under HKDF(master, "transteira/v1/mac/"+purpose)
	// of lp("transteira/v1/mac") | lp(purpose) | lp(part)...
	macOf := func(purpose string, parts ...string) string {
		key := hkdf32(t, master, "transteira/v1/mac/"+purpose)
		m := hmac.New(sha256.New, key)
		m.Write(lp("transteira/v1/mac"))
		m.Write(lp(purpose))
		for _, p := range parts {
			m.Write(lp(p))
		}
		return hex.EncodeToString(m.Sum(nil))
	}
	if v.MACChallengeID == "" || v.MACCode == "" || v.MACSessionToken == "" || v.MACRecognitionEmail == "" {
		t.Fatal("MAC vector inputs missing")
	}
	if got := macOf("otp", v.MACChallengeID, v.MACCode); got != v.MACOTP {
		t.Fatalf("OTP MAC %s, vectors %s", got, v.MACOTP)
	}
	if got := macOf("csrf", v.MACSessionToken); got != v.MACCSRF {
		t.Fatalf("CSRF MAC %s, vectors %s", got, v.MACCSRF)
	}
	if got := macOf("recognition", v.TenantID, v.MACRecognitionEmail); got != v.MACRecognition {
		t.Fatalf("recognition MAC %s, vectors %s", got, v.MACRecognition)
	}
	// The MAC keys are not the wrapping keys of the same name space.
	if bytes.Equal(hkdf32(t, master, "transteira/v1/mac/otp"), hkdf32(t, master, "transteira/v1/wrap/dek")) {
		t.Fatal("MAC key equals a wrapping key")
	}
}
