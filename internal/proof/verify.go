package proof

import (
	"crypto/ed25519"
	"fmt"
	"io"

	"github.com/ed-fr/transteira/internal/pdf"
)

// DefaultVerifyLimit is a reasonable bound of the size of a proof PDF read
// by [Verify]: a statement holds at most a few megabytes (the store bound
// is 4 MiB) and the visible pages a few hundred kilobytes.
const DefaultVerifyLimit = 16 << 20

// Verify reads the proof PDF r (at most limit bytes) and verifies the
// signed statement it embeds against keys, the published public keys of
// the instance. It returns the verified statement: callers display its
// fields, never the visible text of the PDF (T-298).
//
// The PDF must hold exactly two attachments, StatementName and
// SignatureName: any other attachment is rejected rather than ignored,
// since a proof written by TransTeira never has one and a reader could
// mistake it for part of the proof. The statement must be canonical JSON
// following the schema exactly ([ParseStatement]), signed by a key of keys
// with a valid Ed25519 signature, and its latest fact must not be after
// the retirement of that key (T-300).
//
// Every error matches one of ErrInvalidProof, ErrUnknownKey,
// ErrBadSignature and ErrKeyRetired.
func Verify(r io.Reader, keys []PublicKey, limit int64) (Statement, error) {
	files, err := pdf.ReadAttachments(r, limit)
	if err != nil {
		return Statement{}, fmt.Errorf("%w: %w", ErrInvalidProof, err)
	}
	data, okData := files[StatementName]
	sig, okSig := files[SignatureName]
	if !okData || !okSig || len(files) != 2 {
		return Statement{}, fmt.Errorf("%w: the attachments must be exactly %s and %s", ErrInvalidProof, StatementName, SignatureName)
	}
	if len(sig) != ed25519.SignatureSize {
		return Statement{}, fmt.Errorf("%w: malformed signature", ErrInvalidProof)
	}
	return VerifyStatement(data, sig, keys)
}

// VerifyStatement verifies the signed statement data and its signature sig
// against keys, with the rules of [Verify], and returns the statement.
func VerifyStatement(data, sig []byte, keys []PublicKey) (Statement, error) {
	st, err := ParseStatement(data)
	if err != nil {
		return Statement{}, err
	}
	key, err := findKey(keys, st.KeyID)
	if err != nil {
		return Statement{}, err
	}
	if len(key.PublicKey) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize ||
		!ed25519.Verify(key.PublicKey, data, sig) {
		return Statement{}, ErrBadSignature
	}
	if !key.RetiredAt.IsZero() && st.FactTime().After(key.RetiredAt) {
		return Statement{}, ErrKeyRetired
	}
	return st, nil
}

// findKey returns the key kid of keys, or ErrUnknownKey.
func findKey(keys []PublicKey, kid string) (PublicKey, error) {
	for _, k := range keys {
		if k.KeyID == kid {
			return k, nil
		}
	}
	return PublicKey{}, fmt.Errorf("%w: %s", ErrUnknownKey, kid)
}
