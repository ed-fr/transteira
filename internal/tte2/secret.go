package tte2

import (
	"crypto/hkdf"
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// One-time secrets of V2.1 (docs/architecture/e2e-format.md section 3.3).
//
// Server and client use different halves of this file. The server only calls
// VerifierMatches (and ParseProof, DecodeKey); NewPassphraseDescriptor,
// SecretVerifier, EncodeProof and SecretKeyProof are client-side mirror
// helpers (the command-line client and the tests) that build what the
// browser builds.
//
// A secret has its own random key K (carried by the link fragment exactly as
// a transfer key, see DecodeKey). K only feeds DeriveSecretKey and
// SecretKeyProof; the secret root key K' returned by DeriveSecretKey feeds
// the text (SealSecret, OpenSecret), the proof (SecretProof) and, as the
// transfer key with index 0, the optional file (Writer, Reader, SealMetadata,
// OpenMetadata).

const (
	// MaxSecretRunes is the largest number of Unicode code points of a secret
	// text.
	MaxSecretRunes = 10000
	// MaxSecretSize is the largest decoded size of a sealed secret text: the
	// sealed blob overhead and 4 bytes per code point.
	MaxSecretSize = sealedOverhead + 4*MaxSecretRunes
	// MinSecretEncodedSize is the length of a sealed empty text, the shortest
	// sealed secret text, in base64url characters.
	MinSecretEncodedSize = (sealedOverhead*8 + 5) / 6
	// MaxSecretEncodedSize is the largest length of a sealed secret text, in
	// base64url characters.
	MaxSecretEncodedSize = MaxSecretSize / 3 * 4

	// PassphraseKDF is the only key derivation function of a passphrase
	// descriptor.
	PassphraseKDF = "pbkdf2-sha256" //nolint:gosec // G101: a format label, not a credential.
	// PassphraseIterations is the PBKDF2 iteration count, a constant of the
	// format: a descriptor with any other count is refused.
	PassphraseIterations = 600000
	// PassphraseSaltSize is the size of the salt of a passphrase descriptor.
	PassphraseSaltSize = 16
	// EncodedPassphraseSaltSize is the length of the salt in base64url without
	// padding.
	EncodedPassphraseSaltSize = 22
	// MaxPassphraseSize is the largest size of a passphrase, in UTF-8 bytes
	// after NFC normalization.
	MaxPassphraseSize = 1024

	// ProofSize is the size of a proof and of a verifier.
	ProofSize = sha256.Size
	// EncodedProofSize is the length of a proof or a verifier in lowercase
	// hexadecimal.
	EncodedProofSize = 2 * ProofSize

	// InfoSecretKeyProof is the HKDF info of the key proof, derived from K.
	InfoSecretKeyProof = "transteira/tte2/v1/secret/key-proof" //nolint:gosec // G101: an HKDF label, not a credential.
	// InfoSecretText is the HKDF info of the secret text key, derived from K'.
	InfoSecretText = "transteira/tte2/v1/secret/text" //nolint:gosec // G101: an HKDF label, not a credential.
	// InfoSecretProof is the HKDF info of the proof, derived from K'.
	InfoSecretProof = "transteira/tte2/v1/secret/proof" //nolint:gosec // G101: an HKDF label, not a credential. gitleaks:allow

	// secretAAD is the AAD of a sealed secret text.
	secretAAD = "TTE2S"
)

var (
	// ErrInvalidSecret is returned for a secret text that is not valid UTF-8
	// or is longer than MaxSecretRunes, and for a proof or a verifier that is
	// not EncodedProofSize lowercase hexadecimal characters.
	ErrInvalidSecret = errors.New("tte2: invalid secret")
	// ErrInvalidPassphrase is returned for a passphrase that breaks the rules
	// (empty, invalid UTF-8, longer than MaxPassphraseSize after NFC), for a
	// descriptor other than PassphraseKDF with PassphraseIterations and a
	// PassphraseSaltSize salt, and for a passphrase without a descriptor or a
	// descriptor without a passphrase.
	ErrInvalidPassphrase = errors.New("tte2: invalid passphrase")
)

// PassphraseDescriptor is the public description of the passphrase of a
// secret, chosen by the creator's client and stored by the server. Its zero
// value means "no passphrase".
type PassphraseDescriptor struct {
	// KDF is the key derivation function, PassphraseKDF.
	KDF string
	// Iterations is the PBKDF2 iteration count, PassphraseIterations.
	Iterations int
	// Salt is the PassphraseSaltSize-byte random PBKDF2 salt.
	Salt []byte
}

// NewPassphraseDescriptor returns a descriptor with a fresh random salt.
func NewPassphraseDescriptor() (PassphraseDescriptor, error) {
	salt := make([]byte, PassphraseSaltSize)
	if err := randomBytes(salt); err != nil {
		return PassphraseDescriptor{}, err
	}
	return PassphraseDescriptor{KDF: PassphraseKDF, Iterations: PassphraseIterations, Salt: salt}, nil
}

// IsZero reports whether d is the zero descriptor (no passphrase).
func (d PassphraseDescriptor) IsZero() bool {
	return d.KDF == "" && d.Iterations == 0 && len(d.Salt) == 0
}

// Validate checks that d is exactly the descriptor of the format:
// PassphraseKDF, PassphraseIterations and a PassphraseSaltSize-byte salt
// (ErrInvalidPassphrase otherwise).
func (d PassphraseDescriptor) Validate() error {
	if d.KDF != PassphraseKDF || d.Iterations != PassphraseIterations || len(d.Salt) != PassphraseSaltSize {
		return fmt.Errorf("%w: unsupported descriptor", ErrInvalidPassphrase)
	}
	return nil
}

// EncodedSalt returns the salt in base64url without padding, its wire form.
func (d PassphraseDescriptor) EncodedSalt() string {
	return base64.RawURLEncoding.EncodeToString(d.Salt)
}

// DecodePassphraseSalt decodes the wire form of a descriptor salt: exactly
// EncodedPassphraseSaltSize canonical base64url characters, else
// ErrInvalidPassphrase.
func DecodePassphraseSalt(s string) ([]byte, error) {
	if len(s) != EncodedPassphraseSaltSize || !isBase64URL(s) {
		return nil, fmt.Errorf("%w: bad salt encoding", ErrInvalidPassphrase)
	}
	salt, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: bad salt encoding", ErrInvalidPassphrase)
	}
	return salt, nil
}

// DeriveSecretKey derives the secret root key K' from the secret key K:
//
//	K' = HKDF-SHA256(K, salt = P, info = InfoSecret)       with a passphrase
//	K' = HKDF-SHA256(K, no salt, info = InfoSecret)        without
//	P  = PBKDF2-HMAC-SHA256(NFC(passphrase), d.Salt, PassphraseIterations, 32)
//
// "No passphrase" is an empty passphrase with the zero descriptor. Otherwise
// the passphrase must be non-empty valid UTF-8 of at most MaxPassphraseSize
// bytes after NFC normalization (no trimming, no case folding) and d must
// pass Validate; a passphrase without a descriptor or a descriptor without a
// passphrase is ErrInvalidPassphrase. A key that is not KeySize bytes is
// ErrInvalidKey.
func DeriveSecretKey(key []byte, passphrase string, d PassphraseDescriptor) ([]byte, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKey
	}
	normalized, err := preparePassphrase(passphrase, d)
	if err != nil {
		return nil, err
	}
	var p []byte
	if normalized != "" {
		// Cannot fail: the key length, the salt size and the hash are valid
		// even in FIPS 140-only mode.
		p, _ = pbkdf2.Key(sha256.New, normalized, d.Salt, PassphraseIterations, KeySize)
		defer clear(p)
	}
	// Cannot fail: 32 bytes is far below the HKDF-SHA256 output limit.
	k, _ := hkdf.Key(sha256.New, key, p, InfoSecret, KeySize)
	return k, nil
}

// preparePassphrase checks the passphrase rules and the descriptor and
// returns the NFC form of the passphrase, "" for no passphrase.
func preparePassphrase(passphrase string, d PassphraseDescriptor) (string, error) {
	if d.IsZero() {
		if passphrase != "" {
			return "", fmt.Errorf("%w: passphrase without descriptor", ErrInvalidPassphrase)
		}
		return "", nil
	}
	if err := d.Validate(); err != nil {
		return "", err
	}
	if passphrase == "" {
		return "", fmt.Errorf("%w: empty passphrase", ErrInvalidPassphrase)
	}
	if !utf8.ValidString(passphrase) {
		return "", fmt.Errorf("%w: not valid UTF-8", ErrInvalidPassphrase)
	}
	normalized := norm.NFC.String(passphrase)
	if len(normalized) > MaxPassphraseSize {
		return "", fmt.Errorf("%w: longer than %d bytes", ErrInvalidPassphrase, MaxPassphraseSize)
	}
	return normalized, nil
}

// SecretKeyProof returns the key proof HKDF(K, no salt, InfoSecretKeyProof),
// which proves possession of the secret key K. A key that is not KeySize
// bytes is ErrInvalidKey.
func SecretKeyProof(key []byte) ([]byte, error) {
	return deriveProof(key, InfoSecretKeyProof)
}

// SecretProof returns the proof HKDF(K', no salt, InfoSecretProof), which
// proves possession of the secret root key K' (hence of the passphrase, if
// any). A root key that is not KeySize bytes is ErrInvalidKey.
func SecretProof(rootKey []byte) ([]byte, error) {
	return deriveProof(rootKey, InfoSecretProof)
}

// deriveProof derives a ProofSize-byte proof from key.
func deriveProof(key []byte, info string) ([]byte, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKey
	}
	// Cannot fail: 32 bytes is far below the HKDF-SHA256 output limit.
	p, _ := hkdf.Key(sha256.New, key, nil, info, ProofSize)
	return p, nil
}

// SecretVerifier returns SHA-256(proof), the verifier of a key proof or of a
// proof that the creator sends and the server stores.
func SecretVerifier(proof []byte) []byte {
	sum := sha256.Sum256(proof)
	return sum[:]
}

// VerifierMatches reports whether SHA-256(proof) equals verifier, comparing
// the two digests in constant time. The server calls it with a received
// proof and the stored verifier.
func VerifierMatches(verifier, proof []byte) bool {
	sum := sha256.Sum256(proof)
	return subtle.ConstantTimeCompare(verifier, sum[:]) == 1
}

// EncodeProof returns a proof or a verifier in lowercase hexadecimal, its
// wire form.
func EncodeProof(b []byte) string {
	return hex.EncodeToString(b)
}

// ParseProof decodes the wire form of a proof or a verifier: exactly
// EncodedProofSize lowercase hexadecimal characters, else ErrInvalidSecret.
func ParseProof(s string) ([]byte, error) {
	if !isLowerHex64(s) {
		return nil, fmt.Errorf("%w: proof is not %d lowercase hexadecimal characters", ErrInvalidSecret, EncodedProofSize)
	}
	// Cannot fail: s holds 64 hexadecimal digits.
	b, _ := hex.DecodeString(s)
	return b, nil
}

// SealSecret encrypts the secret text with the root key K' and returns the
// sealed blob in base64url without padding, framed as metadata blobs, under
// HKDF(K', no salt, InfoSecretText) and AAD "TTE2S". text must be valid UTF-8
// of at most MaxSecretRunes code points (ErrInvalidSecret); it may be empty
// (allowed only for a secret with a file, a rule of the callers).
func SealSecret(rootKey []byte, text string) (string, error) {
	if err := checkSecretText(text); err != nil {
		return "", err
	}
	return sealSecretRaw(rootKey, []byte(text))
}

// sealSecretRaw seals a secret plaintext without checking it. Tests use it
// to build blobs that SealSecret would refuse.
func sealSecretRaw(rootKey, plain []byte) (string, error) {
	if len(rootKey) != KeySize {
		return "", ErrInvalidKey
	}
	return seal(newAEAD(rootKey, nil, InfoSecretText), []byte(secretAAD), plain)
}

// OpenSecret decrypts the sealed secret text s with the root key K'. It
// returns ErrEncoding for a blob that fails CheckSecretFraming, ErrAuth when
// it does not authenticate (wrong key or passphrase, altered, moved from
// another field) and ErrInvalidSecret when the plaintext is not valid UTF-8
// of at most MaxSecretRunes code points.
func OpenSecret(rootKey []byte, s string) (string, error) {
	if len(rootKey) != KeySize {
		return "", ErrInvalidKey
	}
	plain, err := open(newAEAD(rootKey, nil, InfoSecretText), []byte(secretAAD), s, MaxSecretEncodedSize)
	if err != nil {
		return "", err
	}
	text := string(plain)
	if err := checkSecretText(text); err != nil {
		return "", err
	}
	return text, nil
}

// checkSecretText validates a secret plaintext.
func checkSecretText(text string) error {
	if !utf8.ValidString(text) {
		return fmt.Errorf("%w: not valid UTF-8", ErrInvalidSecret)
	}
	if utf8.RuneCountInString(text) > MaxSecretRunes {
		return fmt.Errorf("%w: longer than %d characters", ErrInvalidSecret, MaxSecretRunes)
	}
	return nil
}

// CheckSecretFraming reports whether s has the framing of a sealed secret
// text, without the key: canonical unpadded base64url of
// MinSecretEncodedSize to MaxSecretEncodedSize characters whose first
// decoded byte is 0x01 (ErrEncoding otherwise). These are the checks of
// OpenSecret before decryption.
func CheckSecretFraming(s string) error {
	_, err := decodeSealed(s, MaxSecretEncodedSize)
	return err
}

// SecretTextIsEmpty reports whether the sealed secret text s, which has
// passed CheckSecretFraming, holds an empty text: its decoded size is exactly
// the sealed blob overhead (29 bytes, MinSecretEncodedSize characters). The
// server uses it to refuse an empty text for a secret without a file.
func SecretTextIsEmpty(s string) bool {
	return len(s) == MinSecretEncodedSize
}
