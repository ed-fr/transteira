package secret

import (
	"errors"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tte2"
)

// FuzzCreateRequest checks the invariants of the validation of a creation
// request: no panic, every refusal is a *ValidationError or a *FormatError
// with at least one field, and an accepted request holds only what the
// store and the format accept (sealed text framed and within bounds,
// 32-byte verifiers, a 16-byte salt or none, a known duration, a delivery
// with its recipient, a normalized sender address for an API token).
func FuzzCreateRequest(f *testing.F) {
	text := "AQvm_LNcuMssDUaZI6WQ3iGRK4gIg8iiNhOpsnYu-dMoF2eTMvmbWpRI1yivl-6L03VwgcaRxEruSIQs7Q"
	verifier := strings.Repeat("ab", 32)
	f.Add(text, verifier, verifier, "pbkdf2-sha256", 600000, "fYFgqj_v4D4pjxFwzmjGvQ", "1d", "link", "", int64(0), "", "", false)
	f.Add(text, verifier, verifier, "", 0, "", "1h", "email", "Carol@Customer.example.net", int64(48), "AQ"+strings.Repeat("A", 40), "alice@a.example.com", true)
	f.Add("AQ", "AB", "", "argon2", -1, "x", "2d", "sms", "<x>", int64(-1), "a+b", "\x00", true)
	f.Add(strings.Repeat("A", 39), verifier, verifier, "", 0, "", "30d", "link", "", int64(0), "", "", false)
	f.Fuzz(func(t *testing.T, text, verifier, keyVerifier, kdf string, iterations int, salt, expiresIn, delivery, recipient string,
		fileSize int64, metadata, sender string, token bool,
	) {
		req := CreateRequest{
			EncryptedText: text, Verifier: verifier, KeyVerifier: keyVerifier, ExpiresIn: expiresIn, Delivery: delivery,
		}
		if kdf != "" || iterations != 0 || salt != "" {
			req.Passphrase = &Passphrase{KDF: kdf, Iterations: iterations, Salt: salt}
		}
		if recipient != "" {
			req.Recipient = &recipient
		}
		if fileSize != 0 || metadata != "" {
			req.File = &File{Size: fileSize, EncryptedMetadata: metadata}
		}
		if sender != "" {
			req.SenderEmail = &sender
		}
		p, err := validate(req, token)
		if err == nil {
			err = checkFraming(req)
		}
		if err != nil {
			var (
				v  *ValidationError
				fe *FormatError
			)
			switch {
			case errors.As(err, &v) && len(v.Fields) > 0:
			case errors.As(err, &fe) && len(fe.Fields) > 0:
			default:
				t.Fatalf("refusal %v carries no field", err)
			}
			return
		}
		if len(text) < store.MinSecretSealedTextLen || len(text) > store.MaxSecretSealedTextLen || tte2.CheckSecretFraming(text) != nil {
			t.Fatalf("accepted sealed text %q", text)
		}
		if len(p.verifier) != 32 || len(p.keyVerifier) != 32 || (p.salt != nil && len(p.salt) != 16) || !p.duration.Valid() {
			t.Fatalf("accepted plan %+v", p)
		}
		if (p.delivery == store.SecretDeliveryEmail) != (p.recipient != "") {
			t.Fatalf("delivery %q with recipient %q", p.delivery, p.recipient)
		}
		if token {
			if norm, err := store.NormalizeEmail(p.sender); err != nil || norm != p.sender {
				t.Fatalf("token sender %q is not normalized", p.sender)
			}
		}
		if req.File != nil && (req.File.Size < MinFileSize || req.File.Size > MaxFileSize || tte2.CheckMetadataFraming(metadata) != nil) {
			t.Fatalf("accepted file %+v", req.File)
		}
	})
}

// FuzzRevealProofs checks the decoding of the reveal proofs: no panic, and
// an accepted proof is exactly the lowercase hexadecimal form of its bytes.
func FuzzRevealProofs(f *testing.F) {
	f.Add(strings.Repeat("0a", 32))
	f.Add(strings.Repeat("0A", 32))
	f.Add("")
	f.Add(strings.Repeat("g", 64))
	f.Fuzz(func(t *testing.T, s string) {
		var v validator
		out := decodeProof(&v, FieldProof, s)
		if len(v.errs) == 0 && tte2.EncodeProof(out[:]) != s {
			t.Fatalf("proof %q accepted as %x", s, out)
		}
		if len(v.errs) > 1 {
			t.Fatalf("errors %v", v.errs)
		}
	})
}
