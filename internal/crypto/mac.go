package crypto

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"
)

const (
	// MACSize is the size in bytes of a MAC returned by MasterKey.MAC.
	MACSize = sha256.Size
	// MaxMACPartSize bounds each part given to MasterKey.MAC and VerifyMAC
	// (1 MiB). MACs protect short values such as verification codes and
	// session tokens, never file contents.
	MaxMACPartSize = 1 << 20

	// macInfoPrefix is the HKDF info prefix of the per-purpose MAC keys. It is
	// distinct from wrapInfoPrefix, so that no MAC key ever equals a wrapping
	// key.
	macInfoPrefix = "transteira/v1/mac/"
	// macLabel is the domain label that starts every MAC message.
	macLabel = "transteira/v1/mac"
)

var (
	// ErrUnknownMACPurpose is returned for a MACPurpose that is not defined by
	// this package.
	ErrUnknownMACPurpose = errors.New("crypto: unknown MAC purpose")
	// ErrMACPartTooLarge is returned when a part given to MAC or VerifyMAC is
	// larger than MaxMACPartSize.
	ErrMACPartTooLarge = errors.New("crypto: MAC part larger than 1 MiB")
)

// MACPurpose names what a MAC is used for. Each purpose has its own MAC key
// derived from the master key, so that a MAC computed for one purpose is never
// valid for another.
type MACPurpose string

const (
	// MACPurposeOTP keys the hashes of the one-time verification codes
	// stored in the database.
	MACPurposeOTP MACPurpose = "otp"
	// MACPurposeCSRF keys the CSRF tokens derived from deposit session tokens.
	MACPurposeCSRF MACPurpose = "csrf"
	// MACPurposeRecognition keys the entries of the browser recognition
	// cookie, each one a MAC of a tenant ID and a verified mail address.
	MACPurposeRecognition MACPurpose = "recognition"
	// MACPurposeDownloadGrant keys the entries of the download grant cookie
	// set after a transfer password has been entered, each one a MAC of a
	// tenant ID, a transfer ID and an expiry.
	MACPurposeDownloadGrant MACPurpose = "download-grant"
	// MACPurposeAdminCSRF keys the CSRF tokens derived from administrator
	// session tokens. It is distinct from MACPurposeCSRF, so that a deposit
	// CSRF token is never valid for an administrator session and vice versa.
	MACPurposeAdminCSRF MACPurpose = "admin-csrf"
)

// macPurposes lists every valid MACPurpose.
var macPurposes = []MACPurpose{
	MACPurposeOTP, MACPurposeCSRF, MACPurposeRecognition, MACPurposeDownloadGrant, MACPurposeAdminCSRF,
}

// deriveMACKeys derives the MAC key of every purpose from the master key
// bytes: HKDF-SHA256(master, salt = none, info = "transteira/v1/mac/" +
// purpose).
func deriveMACKeys(master []byte) map[MACPurpose][]byte {
	keys := make(map[MACPurpose][]byte, len(macPurposes))
	for _, p := range macPurposes {
		// hkdf.Key cannot fail here: the requested length (32 bytes) is far
		// below the HKDF-SHA256 limit and the secret is 256 bits long.
		keys[p], _ = hkdf.Key(sha256.New, master, nil, macInfoPrefix+string(p), MasterKeySize)
	}
	return keys
}

// macFor returns a fresh HMAC-SHA256 keyed with the MAC key of purpose p,
// after checking the key and the parts.
func (k *MasterKey) macFor(p MACPurpose, parts [][]byte) (hash.Hash, error) {
	if k == nil || k.m == nil || k.m.destroyed {
		return nil, ErrKeyUnavailable
	}
	key, ok := k.m.mac[p]
	if !ok {
		return nil, ErrUnknownMACPurpose
	}
	for _, part := range parts {
		if len(part) > MaxMACPartSize {
			return nil, ErrMACPartTooLarge
		}
	}
	return hmac.New(sha256.New, key), nil
}

// writeLP writes the big-endian uint32 length of b followed by b to h.
func writeLP(h hash.Hash, b []byte) {
	h.Write(binary.BigEndian.AppendUint32(nil, u32(len(b))))
	h.Write(b)
}

// MAC returns the HMAC-SHA256, under the MAC key of purpose p, of
//
//	lp("transteira/v1/mac") | lp(purpose) | lp(part 1) | ... | lp(part n)
//
// where lp(x) is the big-endian uint32 length of x followed by x, so that
// distinct part lists never produce the same message. The result is MACSize
// bytes long. It fails with ErrKeyUnavailable for a nil or destroyed key,
// ErrUnknownMACPurpose for an undefined purpose and ErrMACPartTooLarge for a
// part larger than MaxMACPartSize.
func (k *MasterKey) MAC(p MACPurpose, parts ...[]byte) ([]byte, error) {
	h, err := k.macFor(p, parts)
	if err != nil {
		return nil, err
	}
	writeLP(h, []byte(macLabel))
	writeLP(h, []byte(p))
	for _, part := range parts {
		writeLP(h, part)
	}
	return h.Sum(nil), nil
}

// VerifyMAC reports whether mac is the MAC of parts for purpose p, comparing
// in constant time. It returns the errors of MAC; a MAC of the wrong length
// is simply not valid.
func (k *MasterKey) VerifyMAC(p MACPurpose, mac []byte, parts ...[]byte) (bool, error) {
	want, err := k.MAC(p, parts...)
	if err != nil {
		return false, err
	}
	return hmac.Equal(want, mac), nil
}
