package tte2

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

func TestSecretConstants(t *testing.T) {
	if MinSecretEncodedSize != 39 || MaxSecretSize != 40029 || MaxSecretEncodedSize != 53372 {
		t.Fatalf("bounds %d %d %d", MinSecretEncodedSize, MaxSecretSize, MaxSecretEncodedSize)
	}
	if base64.RawURLEncoding.EncodedLen(MaxSecretSize) != MaxSecretEncodedSize ||
		base64.RawURLEncoding.EncodedLen(sealedOverhead) != MinSecretEncodedSize ||
		base64.RawURLEncoding.EncodedLen(PassphraseSaltSize) != EncodedPassphraseSaltSize {
		t.Fatal("encoded sizes")
	}
}

func TestPassphraseDescriptor(t *testing.T) {
	d, err := NewPassphraseDescriptor()
	if err != nil || d.Validate() != nil || d.IsZero() {
		t.Fatalf("new descriptor: %v", err)
	}
	salt, err := DecodePassphraseSalt(d.EncodedSalt())
	if err != nil || !bytes.Equal(salt, d.Salt) || len(d.EncodedSalt()) != EncodedPassphraseSaltSize {
		t.Fatalf("salt round trip: %v", err)
	}
	if !(PassphraseDescriptor{}).IsZero() || (PassphraseDescriptor{Iterations: 1}).IsZero() {
		t.Fatal("IsZero")
	}
	withRand(t, &errReader{err: errWrite})
	if _, err := NewPassphraseDescriptor(); !errors.Is(err, errWrite) {
		t.Fatalf("random failure: %v", err)
	}
}

func TestDeriveSecretKeyRules(t *testing.T) {
	key := testKey(1)
	d := fixedDescriptor("rules")
	if _, err := DeriveSecretKey(key[:31], "", PassphraseDescriptor{}); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("short key: %v", err)
	}
	if _, err := DeriveSecretKey(key, "caf\xe9", d); !errors.Is(err, ErrInvalidPassphrase) {
		t.Fatalf("invalid UTF-8: %v", err)
	}
	// A surrogate encoded in UTF-8 (CESU-8) is invalid UTF-8, as a lone
	// surrogate is refused by the browser.
	if _, err := DeriveSecretKey(key, "a\xed\xa0\x80", d); !errors.Is(err, ErrInvalidPassphrase) {
		t.Fatalf("surrogate: %v", err)
	}
	if _, err := DeriveSecretKey(key, "a", PassphraseDescriptor{KDF: PassphraseKDF, Iterations: PassphraseIterations}); !errors.Is(err, ErrInvalidPassphrase) {
		t.Fatalf("missing salt: %v", err)
	}
	// Exactly MaxPassphraseSize bytes after NFC is accepted; a composed and a
	// decomposed form give the same key; whitespace and case are kept.
	long := strings.Repeat("é", MaxPassphraseSize/2)
	a, err := DeriveSecretKey(key, long, d)
	if err != nil {
		t.Fatal(err)
	}
	b, err := DeriveSecretKey(key, norm.NFD.String(long), d)
	if err != nil || !bytes.Equal(a, b) {
		t.Fatalf("NFD form: %v", err)
	}
	for _, other := range []string{long[:len(long)-2] + " ", strings.ToUpper(long)} {
		c, err := DeriveSecretKey(key, other, d)
		if err != nil || bytes.Equal(a, c) {
			t.Fatalf("whitespace or case folded: %v", err)
		}
	}
	none, err := DeriveSecretKey(key, "", PassphraseDescriptor{})
	if err != nil || len(none) != KeySize || bytes.Equal(none, a) {
		t.Fatalf("no passphrase: %v", err)
	}
}

func TestSecretProofs(t *testing.T) {
	if _, err := SecretKeyProof(nil); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("key proof: %v", err)
	}
	if _, err := SecretProof(make([]byte, 33)); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("proof: %v", err)
	}
	key := testKey(2)
	kp, _ := SecretKeyProof(key)
	pr, _ := SecretProof(key)
	if bytes.Equal(kp, pr) || len(kp) != ProofSize {
		t.Fatal("proofs are not domain-separated")
	}
	v := SecretVerifier(pr)
	if !VerifierMatches(v, pr) || VerifierMatches(v, kp) || VerifierMatches(v[:31], pr) || VerifierMatches(nil, pr) {
		t.Fatal("VerifierMatches")
	}
	s := EncodeProof(v)
	if got, err := ParseProof(s); err != nil || !bytes.Equal(got, v) || len(s) != EncodedProofSize {
		t.Fatalf("round trip: %v", err)
	}
	for _, bad := range []string{"", s[:63], s + "0", strings.ToUpper(s), s[:63] + "g", " " + s[1:]} {
		if _, err := ParseProof(bad); !errors.Is(err, ErrInvalidSecret) {
			t.Fatalf("ParseProof(%q): %v", bad, err)
		}
	}
}

func TestSecretText(t *testing.T) {
	root := testKey(3)
	if _, err := SealSecret(root[:1], "a"); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("seal key: %v", err)
	}
	if _, err := OpenSecret(nil, "a"); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("open key: %v", err)
	}
	for _, bad := range []string{"caf\xe9", strings.Repeat("a", MaxSecretRunes+1)} {
		if _, err := SealSecret(root, bad); !errors.Is(err, ErrInvalidSecret) {
			t.Fatalf("seal %d bytes: %v", len(bad), err)
		}
	}
	// The largest text: MaxSecretRunes code points of 4 bytes.
	largest := strings.Repeat("😀", MaxSecretRunes)
	s, err := SealSecret(root, largest)
	if err != nil || len(s) != MaxSecretEncodedSize || CheckSecretFraming(s) != nil || SecretTextIsEmpty(s) {
		t.Fatalf("largest: %v %d", err, len(s))
	}
	if got, err := OpenSecret(root, s); err != nil || got != largest {
		t.Fatalf("open largest: %v", err)
	}
	if err := CheckSecretFraming(s + "AAAA"); !errors.Is(err, ErrEncoding) {
		t.Fatalf("over the bound: %v", err)
	}
	empty, err := SealSecret(root, "")
	if err != nil || len(empty) != MinSecretEncodedSize || !SecretTextIsEmpty(empty) {
		t.Fatalf("empty: %v", err)
	}
	if err := CheckSecretFraming(empty[:MinSecretEncodedSize-1]); !errors.Is(err, ErrEncoding) {
		t.Fatalf("below the bound: %v", err)
	}
	if _, err := OpenSecret(testKey(4), empty); !errors.Is(err, ErrAuth) {
		t.Fatalf("wrong key: %v", err)
	}
	a, _ := SealSecret(root, "x")
	b, _ := SealSecret(root, "x")
	if a == b {
		t.Fatal("nonce reused")
	}
}

// FuzzCheckSecretFraming checks the keyless framing check on arbitrary
// strings: it accepts exactly the canonical base64url strings within the
// bounds whose first decoded byte is 1, and agrees with OpenSecret.
func FuzzCheckSecretFraming(f *testing.F) {
	root := testKey(0x70)
	for _, text := range []string{"", "a", "été 😀"} {
		s, _ := SealSecret(root, text)
		f.Add(s)
		f.Add(s[1:])
		f.Add(s + "=")
	}
	f.Add("")
	f.Add(strings.Repeat("A", MaxSecretEncodedSize+1))
	f.Fuzz(func(t *testing.T, s string) {
		err := CheckSecretFraming(s)
		b, decErr := base64.RawURLEncoding.Strict().DecodeString(s)
		want := isBase64URL(s) && decErr == nil && len(s) <= MaxSecretEncodedSize && len(b) >= sealedOverhead && b[0] == sealedVersion
		if (err == nil) != want || (err != nil && !errors.Is(err, ErrEncoding)) {
			t.Fatalf("CheckSecretFraming(%q) = %v, want ok %v", s, err, want)
		}
		if err == nil && SecretTextIsEmpty(s) != (len(b) == sealedOverhead) {
			t.Fatalf("SecretTextIsEmpty(%q)", s)
		}
		if _, openErr := OpenSecret(root, s); err != nil && !errors.Is(openErr, ErrEncoding) {
			t.Fatalf("OpenSecret framing: %v", openErr)
		}
	})
}

// FuzzOpenSecret opens arbitrary blobs: the result is a known error or a
// valid text that seals back to the same blob with the same nonce.
func FuzzOpenSecret(f *testing.F) {
	root := testKey(0x71)
	for _, text := range []string{"", "secret", strings.Repeat("é", 50)} {
		s, _ := SealSecret(root, text)
		f.Add(s)
	}
	raw, _ := sealSecretRaw(root, []byte("caf\xe9"))
	f.Add(raw)
	f.Fuzz(func(t *testing.T, s string) {
		text, err := OpenSecret(root, s)
		if err != nil {
			known := errors.Is(err, ErrEncoding) || errors.Is(err, ErrAuth) || errors.Is(err, ErrInvalidSecret)
			if text != "" || !known {
				t.Fatalf("OpenSecret(%q): %q %v", s, text, err)
			}
			return
		}
		if !utf8.ValidString(text) || utf8.RuneCountInString(text) > MaxSecretRunes {
			t.Fatalf("invalid text accepted")
		}
		b, _ := base64.RawURLEncoding.DecodeString(s)
		defer withFixedRand(b[1 : 1+NonceSize])()
		if again, err := SealSecret(root, text); err != nil || again != s {
			t.Fatalf("reseal differs: %v", err)
		}
	})
}

// FuzzSecretPassphrase checks the passphrase and descriptor rules on
// arbitrary input: an accepted passphrase is non-empty valid UTF-8, NFC, of at
// most MaxPassphraseSize bytes with a valid descriptor; a refused one fails
// DeriveSecretKey with ErrInvalidPassphrase. PBKDF2 is only run for refused
// inputs (where it is skipped), to keep the target fast.
func FuzzSecretPassphrase(f *testing.F) {
	f.Add("Café", PassphraseKDF, PassphraseIterations, "lsSkl3ciGfnIEmp8IAWYQg")
	f.Add("", PassphraseKDF, PassphraseIterations, "lsSkl3ciGfnIEmp8IAWYQg")
	f.Add("a", "", 0, "")
	f.Add("", "", 0, "")
	f.Add("caf\xe9", PassphraseKDF, PassphraseIterations, "lsSkl3ciGfnIEmp8IAWYQg")
	f.Add(strings.Repeat("क़", 300), PassphraseKDF, PassphraseIterations, "lsSkl3ciGfnIEmp8IAWYQg")
	f.Add("a", PassphraseKDF, 100000, "lsSkl3ciGfnIEmp8IAWYQh")
	f.Fuzz(func(t *testing.T, passphrase, kdf string, iterations int, salt string) {
		d := PassphraseDescriptor{KDF: kdf, Iterations: iterations}
		if salt != "" {
			b, err := DecodePassphraseSalt(salt)
			if err != nil {
				if !errors.Is(err, ErrInvalidPassphrase) {
					t.Fatalf("DecodePassphraseSalt: %v", err)
				}
				return
			}
			d.Salt = b
		}
		normalized, err := preparePassphrase(passphrase, d)
		if err != nil {
			if !errors.Is(err, ErrInvalidPassphrase) {
				t.Fatalf("preparePassphrase: %v", err)
			}
			if _, derr := DeriveSecretKey(fuzzKey, passphrase, d); !errors.Is(derr, ErrInvalidPassphrase) {
				t.Fatalf("DeriveSecretKey accepted a refused passphrase: %v", derr)
			}
			return
		}
		if d.IsZero() {
			if passphrase != "" || normalized != "" {
				t.Fatal("passphrase without descriptor accepted")
			}
			return
		}
		if d.Validate() != nil || normalized == "" || !utf8.ValidString(passphrase) ||
			len(normalized) > MaxPassphraseSize || !norm.NFC.IsNormalString(normalized) || normalized != norm.NFC.String(passphrase) {
			t.Fatalf("bad passphrase accepted: %q %+v", passphrase, d)
		}
	})
}
