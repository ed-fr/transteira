package crypto

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// fuzzPlain is the plaintext of every fuzz seed: any authenticated output must
// be a prefix of it.
var fuzzPlain = pattern(3*cs + 200)

func FuzzReader(f *testing.F) {
	dek := testDEK(40)
	setRand(f, &detReader{seed: "fuzz-reader"})
	ct := encrypt(f, dek, tenantA, fileA, fuzzPlain, cs, nil)
	f.Add(ct)
	f.Add(ct[:HeaderSize])
	f.Add(ct[:HeaderSize+cs+tagSize])
	f.Add(ct[:len(ct)-1])
	f.Add(append(append([]byte(nil), ct...), 0))
	f.Add(encrypt(f, dek, tenantA, fileA, nil, cs, nil))
	f.Add([]byte("TTEF"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := NewReader(bytes.NewReader(data), dek, tenantA, fileA)
		if err != nil {
			if !errors.Is(err, ErrBadHeader) && !errors.Is(err, ErrTruncated) {
				t.Fatalf("unexpected NewReader error: %v", err)
			}
			return
		}
		got, err := io.ReadAll(r)
		if len(got) > len(fuzzPlain) || !bytes.Equal(got, fuzzPlain[:len(got)]) {
			t.Fatalf("returned %d unauthenticated bytes", len(got))
		}
		if err == nil {
			if !bytes.Equal(got, fuzzPlain) && len(got) != 0 {
				t.Fatalf("accepted a partial stream of %d bytes", len(got))
			}
			return
		}
		if !errors.Is(err, ErrAuth) && !errors.Is(err, ErrTruncated) && !errors.Is(err, ErrTrailingData) {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func FuzzUnwrap(f *testing.F) {
	k := testKey(f)
	secret := []byte("fuzz-secret")
	blob, err := k.Wrap(PurposeSecret, tenantA, "wk_1", secret)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(blob, "secret", tenantA, "wk_1")
	f.Add(blob, "dek", tenantA, "wk_1")
	f.Add(blob[:envelopeOverhead], "secret", tenantA, "wk_1")
	f.Add([]byte{}, "", "", "")
	f.Fuzz(func(t *testing.T, b []byte, purpose, tenantID, rowID string) {
		got, err := k.Unwrap(Purpose(purpose), tenantID, rowID, b)
		if err != nil {
			if !errors.Is(err, ErrUnwrap) || got != nil {
				t.Fatalf("Unwrap failure: %x, %v", got, err)
			}
			return
		}
		if !bytes.Equal(got, secret) || purpose != "secret" || tenantID != tenantA || rowID != "wk_1" {
			t.Fatalf("forged unwrap: %q %q %q", purpose, tenantID, rowID)
		}
	})
}

func FuzzUnmarshalState(f *testing.F) {
	dek := testDEK(41)
	// Deterministic setup: fuzz workers rebuild it and must get the same seed.
	setRand(f, &detReader{seed: "fuzz-state"})
	w, err := NewWriter(io.Discard, dek, tenantA, fileA, WithChunkSize(cs))
	if err != nil {
		f.Fatal(err)
	}
	if _, err := w.Write(fuzzPlain[:cs+100]); err != nil {
		f.Fatal(err)
	}
	st, err := w.Checkpoint(nil)
	if err != nil {
		f.Fatal(err)
	}
	good, err := st.MarshalBinary()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(good)
	f.Add(good[:stateFixedSize])
	f.Add([]byte("TTCK"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		st, err := UnmarshalState(b)
		if err != nil {
			if !errors.Is(err, ErrBadState) {
				t.Fatalf("unexpected error: %v", err)
			}
			return
		}
		again, err := st.MarshalBinary()
		if err != nil || !bytes.Equal(again, b) {
			t.Fatal("parsed state does not round trip")
		}
		if st.CiphertextSize() < HeaderSize || st.PlaintextSize() < 0 || st.ChunkSize() < MinChunkSize {
			t.Fatal("invalid sizes for a parsed state")
		}
		rw, _, err := ResumeWriter(io.Discard, dek, tenantA, fileA, st, st.CiphertextSize())
		if err != nil {
			if !errors.Is(err, ErrAuth) {
				t.Fatalf("unexpected ResumeWriter error: %v", err)
			}
			return
		}
		if !bytes.Equal(b, good) || !bytes.Equal(rw.buf, fuzzPlain[cs:cs+100]) {
			t.Fatal("forged state resumed")
		}
	})
}

func FuzzVerifyMAC(f *testing.F) {
	k := testKey(f)
	mac, err := k.MAC(MACPurposeOTP, []byte("vch_1"), []byte("123456"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(mac, "otp", []byte("vch_1"), []byte("123456"))
	f.Add(mac, "otp", []byte("vch_11"), []byte("23456"))
	f.Add(mac, "csrf", []byte("vch_1"), []byte("123456"))
	f.Add([]byte{}, "", []byte{}, []byte{})
	f.Fuzz(func(t *testing.T, tag []byte, purpose string, a, b []byte) {
		if len(a) > MaxMACPartSize || len(b) > MaxMACPartSize {
			return // covered by TestMACErrors
		}
		ok, err := k.VerifyMAC(MACPurpose(purpose), tag, a, b)
		if err != nil {
			if ok || !errors.Is(err, ErrUnknownMACPurpose) || purpose == "otp" || purpose == "csrf" {
				t.Fatalf("VerifyMAC failure: %v, %v", ok, err)
			}
			return
		}
		if ok && (purpose != "otp" || !bytes.Equal(a, []byte("vch_1")) || !bytes.Equal(b, []byte("123456"))) {
			t.Fatalf("forged MAC accepted: %q %q %q", purpose, a, b)
		}
		// A freshly computed MAC always verifies.
		own, err := k.MAC(MACPurpose(purpose), a, b)
		if err != nil {
			t.Fatal(err)
		}
		if ok, err := k.VerifyMAC(MACPurpose(purpose), own, a, b); !ok || err != nil {
			t.Fatalf("own MAC rejected: %v, %v", ok, err)
		}
	})
}
