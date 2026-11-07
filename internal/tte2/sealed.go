package tte2

import (
	"bytes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"unicode/utf8"
)

// Metadata is the plaintext description of one file of an end-to-end
// encrypted transfer, sealed by SealMetadata into the encryptedMetadata
// field of the file. Its JSON form is
//
//	{"v":1,"index":i,"count":n,"name":"...","path":"...","type":"...","size":s,"sha256":"..."}
//
// with "path" omitted when empty. Name and Path are the sender's values: this
// package checks their presence, not their content, and a client must
// sanitize them before using them as file names (the browser does).
type Metadata struct {
	// Index is the 0-based position of the file in the transfer.
	Index int
	// Count is the number of files of the transfer, so that a recipient
	// detects a file removed by the server.
	Count int
	// Name is the original file name (required, unsanitized).
	Name string
	// Path is the optional relative folder path of the file (unsanitized).
	Path string
	// Type is the media type of the file, possibly empty.
	Type string
	// Size is the plaintext size in bytes, checked by the recipient after
	// decryption.
	Size int64
	// SHA256 is the lowercase hexadecimal SHA-256 digest of the plaintext,
	// checked by the recipient after decryption.
	SHA256 string
}

// metadataWire is the JSON form of Metadata.
type metadataWire struct {
	V      int    `json:"v"`
	Index  int    `json:"index"`
	Count  int    `json:"count"`
	Name   string `json:"name"`
	Path   string `json:"path,omitempty"`
	Type   string `json:"type"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// metadataFields lists the JSON fields of metadata and whether each is
// required.
var metadataFields = map[string]bool{
	"v": true, "index": true, "count": true, "name": true,
	"path": false, "type": true, "size": true, "sha256": true,
}

// SealMetadata encrypts m, the metadata of file index, with the transfer key K
// and returns the sealed blob in base64url without padding:
//
//	0x01 | 12-byte random nonce | AES-256-GCM ciphertext and tag
//
// under HKDF(K, no salt, InfoMetadata || u32 BE(index)) and AAD
// "TTE2M" || u32 BE(index). m must satisfy the rules OpenMetadata enforces,
// with m.Index equal to index, and the blob must not exceed MaxMetadataSize
// decoded bytes; otherwise the error is ErrInvalidMetadata.
func SealMetadata(key []byte, index int, m Metadata) (string, error) {
	if err := checkKeyIndex(key, index); err != nil {
		return "", err
	}
	if err := m.validate(index); err != nil {
		return "", err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	// Encoding strings and integers cannot fail.
	_ = enc.Encode(metadataWire{
		V: 1, Index: m.Index, Count: m.Count, Name: m.Name, Path: m.Path,
		Type: m.Type, Size: m.Size, SHA256: m.SHA256,
	})
	plain := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
	return sealMetadataRaw(key, index, plain)
}

// sealMetadataRaw seals an already encoded metadata plaintext. Tests use it
// to build blobs that SealMetadata would refuse.
func sealMetadataRaw(key []byte, index int, plain []byte) (string, error) {
	if len(plain)+sealedOverhead > MaxMetadataSize {
		return "", fmt.Errorf("%w: larger than %d bytes", ErrInvalidMetadata, MaxMetadataSize)
	}
	if err := checkKeyIndex(key, index); err != nil {
		return "", err
	}
	aead, aad := metadataAEAD(key, index)
	return seal(aead, aad, plain)
}

// OpenMetadata decrypts and strictly validates the sealed metadata s of file
// index. It returns ErrEncoding for a blob that is not canonical base64url of
// at most MaxMetadataSize bytes with version 1, ErrAuth when it does not
// authenticate (wrong key, wrong index, altered), and ErrInvalidMetadata when
// the JSON is not a single object, has an unknown (names are case-sensitive),
// null or missing field, a value of the wrong type, a version
// other than 1, an index other than index, a count below 1 or not above the
// index, a negative size, an empty name or a digest that is not 64 lowercase
// hexadecimal characters. A field repeated in the object keeps its last value,
// as with JSON.parse.
func OpenMetadata(key []byte, index int, s string) (Metadata, error) {
	if err := checkKeyIndex(key, index); err != nil {
		return Metadata{}, err
	}
	aead, aad := metadataAEAD(key, index)
	plain, err := open(aead, aad, s, base64.RawURLEncoding.EncodedLen(MaxMetadataSize))
	if err != nil {
		return Metadata{}, err
	}
	m, err := decodeMetadata(plain)
	if err != nil {
		return Metadata{}, err
	}
	if err := m.validate(index); err != nil {
		return Metadata{}, err
	}
	return m, nil
}

// decodeMetadata parses the strict JSON form of metadata.
func decodeMetadata(plain []byte) (Metadata, error) {
	// encoding/json would replace invalid UTF-8 by U+FFFD; a browser with a
	// fatal TextDecoder refuses it: refuse it here too, for the same result
	// on every implementation.
	if !utf8.Valid(plain) {
		return Metadata{}, fmt.Errorf("%w: not valid UTF-8", ErrInvalidMetadata)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(plain, &fields); err != nil || fields == nil {
		return Metadata{}, fmt.Errorf("%w: not a JSON object", ErrInvalidMetadata)
	}
	for name, raw := range fields {
		if _, known := metadataFields[name]; !known {
			return Metadata{}, fmt.Errorf("%w: unknown field %q", ErrInvalidMetadata, name)
		}
		if string(raw) == "null" {
			return Metadata{}, fmt.Errorf("%w: null field %q", ErrInvalidMetadata, name)
		}
	}
	for name, required := range metadataFields {
		if _, ok := fields[name]; required && !ok {
			return Metadata{}, fmt.Errorf("%w: missing field %q", ErrInvalidMetadata, name)
		}
	}
	var w metadataWire
	if err := json.Unmarshal(plain, &w); err != nil {
		return Metadata{}, fmt.Errorf("%w: %w", ErrInvalidMetadata, err)
	}
	if w.V != 1 {
		return Metadata{}, fmt.Errorf("%w: version %d", ErrInvalidMetadata, w.V)
	}
	return Metadata{
		Index: w.Index, Count: w.Count, Name: w.Name, Path: w.Path,
		Type: w.Type, Size: w.Size, SHA256: w.SHA256,
	}, nil
}

// validate checks the metadata rules for file index.
func (m *Metadata) validate(index int) error {
	switch {
	case m.Index != index:
		return fmt.Errorf("%w: index %d, expected %d", ErrInvalidMetadata, m.Index, index)
	case m.Count < 1 || m.Index >= m.Count:
		return fmt.Errorf("%w: count %d for index %d", ErrInvalidMetadata, m.Count, m.Index)
	case m.Name == "":
		return fmt.Errorf("%w: empty name", ErrInvalidMetadata)
	case m.Size < 0:
		return fmt.Errorf("%w: negative size", ErrInvalidMetadata)
	case !isLowerHex64(m.SHA256):
		return fmt.Errorf("%w: sha256 is not 64 lowercase hexadecimal characters", ErrInvalidMetadata)
	}
	return nil
}

// isLowerHex64 reports whether s is 64 lowercase hexadecimal characters.
func isLowerHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// metadataAEAD returns the AEAD and AAD of the metadata of file index.
func metadataAEAD(key []byte, index int) (cipher.AEAD, []byte) {
	aead := newAEAD(key, nil, indexedInfo(InfoMetadata, index))
	aad := binary.BigEndian.AppendUint32([]byte(metadataAAD), uint32(index)) //nolint:gosec // G115: index is checked against [0, MaxIndex] by the callers.
	return aead, aad
}

// SealMessage encrypts the transfer message text with the transfer key K and
// returns the sealed blob in base64url without padding, framed as metadata
// blobs, under HKDF(K, no salt, InfoMessage) and AAD "TTE2T". text must be
// valid UTF-8 of at most MaxMessageRunes code points (ErrInvalidMessage).
func SealMessage(key []byte, text string) (string, error) {
	if err := checkMessage(text); err != nil {
		return "", err
	}
	return sealMessageRaw(key, []byte(text))
}

// sealMessageRaw seals a message plaintext without checking it. Tests use it
// to build blobs that SealMessage would refuse.
func sealMessageRaw(key, plain []byte) (string, error) {
	if len(key) != KeySize {
		return "", ErrInvalidKey
	}
	return seal(newAEAD(key, nil, InfoMessage), []byte(messageAAD), plain)
}

// OpenMessage decrypts the sealed message s. It returns ErrEncoding for a blob
// that is not canonical base64url of at most MaxMessageEncodedSize characters
// with version 1, ErrAuth when it does not authenticate and ErrInvalidMessage
// when the plaintext is not valid UTF-8 of at most MaxMessageRunes code
// points.
func OpenMessage(key []byte, s string) (string, error) {
	if len(key) != KeySize {
		return "", ErrInvalidKey
	}
	plain, err := open(newAEAD(key, nil, InfoMessage), []byte(messageAAD), s, MaxMessageEncodedSize)
	if err != nil {
		return "", err
	}
	text := string(plain)
	if err := checkMessage(text); err != nil {
		return "", err
	}
	return text, nil
}

// checkMessage validates a message plaintext.
func checkMessage(text string) error {
	if !utf8.ValidString(text) {
		return fmt.Errorf("%w: not valid UTF-8", ErrInvalidMessage)
	}
	if utf8.RuneCountInString(text) > MaxMessageRunes {
		return fmt.Errorf("%w: longer than %d characters", ErrInvalidMessage, MaxMessageRunes)
	}
	return nil
}

// seal encrypts plain into a sealed blob with a fresh random nonce.
func seal(aead cipher.AEAD, aad, plain []byte) (string, error) {
	b := make([]byte, 1+NonceSize, sealedOverhead+len(plain))
	b[0] = sealedVersion
	if err := randomBytes(b[1:]); err != nil {
		return "", err
	}
	b = aead.Seal(b, b[1:1+NonceSize], plain, aad)
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// open decodes and decrypts a sealed blob of at most maxEncoded characters.
func open(aead cipher.AEAD, aad []byte, s string, maxEncoded int) ([]byte, error) {
	b, err := decodeSealed(s, maxEncoded)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, b[1:1+NonceSize], b[1+NonceSize:], aad)
	if err != nil {
		return nil, ErrAuth
	}
	return plain, nil
}

// decodeSealed decodes the framing of a sealed blob of at most maxEncoded
// characters: canonical unpadded base64url, version byte and room for the
// nonce and the tag. It returns ErrEncoding otherwise.
func decodeSealed(s string, maxEncoded int) ([]byte, error) {
	if len(s) > maxEncoded || !isBase64URL(s) {
		return nil, fmt.Errorf("%w: not base64url or too long", ErrEncoding)
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrEncoding, err)
	}
	if len(b) < sealedOverhead || b[0] != sealedVersion {
		return nil, fmt.Errorf("%w: bad length or version", ErrEncoding)
	}
	return b, nil
}

// CheckMetadataFraming reports whether s has the framing of sealed
// metadata, without the key: the checks of OpenMetadata before decryption
// (ErrEncoding otherwise). The server uses it to refuse, at creation, an
// encryptedMetadata that no recipient could ever open.
func CheckMetadataFraming(s string) error {
	_, err := decodeSealed(s, base64.RawURLEncoding.EncodedLen(MaxMetadataSize))
	return err
}

// CheckMessageFraming is CheckMetadataFraming for a sealed message (the
// checks of OpenMessage before decryption).
func CheckMessageFraming(s string) error {
	_, err := decodeSealed(s, MaxMessageEncodedSize)
	return err
}
