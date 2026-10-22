package crypto

import (
	"bytes"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
	"time"
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
	f.Add(mac, "download-grant", []byte("vch_1"), []byte("123456"))
	f.Add([]byte{}, "", []byte{}, []byte{})
	f.Fuzz(func(t *testing.T, tag []byte, purpose string, a, b []byte) {
		if len(a) > MaxMACPartSize || len(b) > MaxMACPartSize {
			return // covered by TestMACErrors
		}
		ok, err := k.VerifyMAC(MACPurpose(purpose), tag, a, b)
		if err != nil {
			if ok || !errors.Is(err, ErrUnknownMACPurpose) || slices.Contains(macPurposes, MACPurpose(purpose)) {
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

func FuzzVerifyTOTP(f *testing.F) {
	secret := []byte(vectorTOTPSecret)
	f.Add(secret, "287082", int64(59), uint64(0), false)
	f.Add(secret, "287082", int64(59), uint64(1), true)
	f.Add(secret, "287082", int64(89), uint64(0), true)
	f.Add(secret, "28708", int64(59), uint64(0), false)
	f.Add(secret, "2870820", int64(59), uint64(0), false)
	f.Add([]byte{}, "000000", int64(-1), uint64(0), false)
	f.Fuzz(func(t *testing.T, s []byte, code string, sec int64, last uint64, haveLast bool) {
		now := time.Unix(sec, 0)
		c, ok := VerifyTOTP(s, code, now, last, haveLast)
		if !ok {
			if c != 0 {
				t.Fatalf("refused with counter %d", c)
			}
			return
		}
		cur := TOTPCounter(now)
		switch {
		case len(s) == 0 || !ValidTOTPCode(code):
			t.Fatalf("accepted secret %x / code %q", s, code)
		case c+1 < cur || c > cur+1:
			t.Fatalf("counter %d outside the window of %d", c, cur)
		case haveLast && c <= last:
			t.Fatalf("replay: counter %d <= last %d", c, last)
		case TOTPCode(s, c) != code:
			t.Fatalf("counter %d does not produce %q", c, code)
		}
		// The accepted code is never accepted again.
		if _, again := VerifyTOTP(s, code, now, c, true); again && TOTPCode(s, cur+1) != code {
			t.Fatal("accepted code replayed")
		}
	})
}

func FuzzNormalizeRecoveryCode(f *testing.F) {
	f.Add("rc-0123-4567-89AB")
	f.Add("rc 0123 4567 89ab")
	f.Add("0123456789AB")
	f.Add("rc-0123-4567-89AI")
	f.Add("RCRC23456789AB")
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		n, ok := NormalizeRecoveryCode(s)
		if !ok {
			if n != "" {
				t.Fatalf("refused with output %q", n)
			}
			return
		}
		if len(s) > maxRecoveryInput || len(n) != len(RecoveryCodePrefix)+recoverySymbols+recoveryGroups-1 ||
			!strings.HasPrefix(n, RecoveryCodePrefix) {
			t.Fatalf("Normalize(%q) = %q", s, n)
		}
		body := strings.ReplaceAll(n[len(RecoveryCodePrefix):], "-", "")
		for i := range len(body) {
			if strings.IndexByte(recoveryAlphabet, body[i]) < 0 {
				t.Fatalf("symbol %q outside the alphabet in %q", body[i], n)
			}
		}
		// Only case, dashes, spaces and the prefix may differ from the input.
		stripped := strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(s))
		if stripped != body && stripped != "RC"+body {
			t.Fatalf("Normalize(%q) = %q changes symbols", s, n)
		}
		if again, ok := NormalizeRecoveryCode(n); !ok || again != n {
			t.Fatalf("not idempotent: %q -> %q", n, again)
		}
	})
}
