// Package crypto implements TransTeira's encryption at rest (specification
// section 16.1, threat model decisions P6 and P7, threats T-28 to T-40).
//
// It provides the following building blocks and depends on no other internal
// package:
//
//   - MasterKey: the 32-byte master key read from a file mounted outside the
//     data volumes. Its bytes are never exposed: it only derives one wrapping
//     key per Purpose and one MAC key per MACPurpose (HKDF-SHA256), and a
//     public identifier (ID) used to detect a wrong key at startup.
//   - Envelope encryption: MasterKey.Wrap and MasterKey.Unwrap seal small
//     secrets (per-file data encryption keys, SMTP passwords, administrator
//     TOTP secrets) with
//     AES-256-GCM, bound to their purpose, tenant and database row so that a
//     blob copied to another row or tenant can no longer be opened.
//   - Chunked file encryption: Writer, Reader and ReaderAt implement a
//     STREAM-like AES-256-GCM format (see the "File format" section below)
//     that encrypts and decrypts in constant memory, sequentially or by range,
//     detects tampering, reordering, truncation and trailing data, and
//     supports resumable (tus) uploads
//     through Writer.Checkpoint and ResumeWriter without ever writing
//     plaintext to disk nor reusing a nonce.
//   - Administrator authentication primitives (specification section 6.5):
//     TOTP codes (RFC 6238) and single-use recovery codes, described in the
//     "TOTP" and "Recovery codes" sections below.
//
// # Wrapped blob format
//
//	version (1 byte, = 1) | nonce (12 random bytes) | AES-256-GCM ciphertext and tag
//
// The purposes are "dek" (PurposeDEK), "secret" (PurposeSecret) and
// "admin-totp" (PurposeAdminTOTP). The key is HKDF-SHA256(master key, salt =
// none, info =
// "transteira/v1/wrap/" + purpose). The additional authenticated data is
// lp("transteira/v1/envelope") | lp(purpose) | lp(tenantID) | lp(rowID),
// where lp(x) is the big-endian uint32 length of x followed by x.
//
// # Keyed MACs
//
// MasterKey.MAC and MasterKey.VerifyMAC compute HMAC-SHA256 tags for short
// values that must not be recomputable without the master key: the stored
// hashes of the one-time verification codes (MACPurposeOTP), the CSRF
// tokens derived from deposit session tokens (MACPurposeCSRF), the
// entries of the browser recognition cookie of verified depositors
// (MACPurposeRecognition, over a tenant ID, a normalized address, its
// recognition salt and an issue day), the entries of the download grant
// cookie set once a transfer password has been entered
// (MACPurposeDownloadGrant, over a tenant ID, a transfer ID and an expiry),
// the CSRF tokens derived from administrator session tokens
// (MACPurposeAdminCSRF, distinct from the deposit CSRF purpose so that a
// token of one kind of session is never valid for the other), and the
// entries of the recipient verification cookie
// (MACPurposeRecipientVerification, over a tenant ID, a recipient link ID
// and an expiry), the rate-limit key of the "my transfers" access link
// requests (MACPurposeAccessRate, over a normalized address), and the CSRF
// tokens derived from "my transfers" session tokens (MACPurposeMeCSRF,
// distinct from the deposit and administrator CSRF purposes).
//
//	key = HKDF-SHA256(master key, salt = none, info = "transteira/v1/mac/" + purpose)
//	MAC = HMAC-SHA256(key, lp("transteira/v1/mac") | lp(purpose) | lp(part 1) | ... | lp(part n))
//
// # Domain separation
//
// Every key derived from the master key has its own HKDF info string, and the
// prefixes "transteira/v1/wrap/" and "transteira/v1/mac/" cannot collide: a
// wrapping key and a MAC key are never equal, and each purpose of either kind
// has its own key: for instance, a recognition cookie entry is never a valid
// download grant, even for the same parts, since "recognition" and
// "download-grant" derive distinct keys and appear in the MAC message. The
// key identifier uses a third, distinct HMAC message
// ("transteira/v1/key-id"). Every authenticated message also starts with the
// length-prefixed domain label of its use ("transteira/v1/envelope",
// "transteira/v1/stream-chunk", "transteira/v1/stream-tail",
// "transteira/v1/mac"), and every variable field is length-prefixed, so that
// no input of one use can be reinterpreted as an input of another.
//
// # TOTP
//
// TOTPCode, TOTPCounter and VerifyTOTP implement RFC 6238 over RFC 4226 with
// the parameters every authenticator app supports: HMAC-SHA1, 6 digits, a
// 30-second step and T0 = 0.
//
//	counter = floor(Unix time / 30)
//	code    = (31 low bits of HMAC-SHA1(secret, counter as uint64 BE) at offset low nibble of the last byte) mod 10^6, zero-padded
//
// GenerateTOTPSecret draws 20 bytes (160 bits) from crypto/rand,
// EncodeTOTPSecret gives their unpadded uppercase base32 form and TOTPURI the
// otpauth:// key URI for the enrollment QR code. VerifyTOTP accepts the steps
// current-1 to current+1, refuses every step lower than or equal to the last
// accepted one (no replay, threat T-60), checks the code format first and
// compares all candidates in constant time. The secrets are stored wrapped
// for PurposeAdminTOTP (threat T-61).
//
// # Recovery codes
//
// GenerateRecoveryCodes returns codes "rc-XXXX-XXXX-XXXX" made of 12 symbols
// of Crockford's base32 alphabet without I, L, O and U, carrying 60 bits of
// entropy each. NormalizeRecoveryCode turns a typed code into that canonical
// form (case, dashes and spaces are tolerated) and RecoveryCodeMAC returns
// the HMAC-SHA256 of the canonical form (purpose admin-recovery), keyed by
// a key derived from the TOTP secret of the administrator, the only value
// stored: the key survives a master key rotation, which rewraps the TOTP
// secret.
//
// # File format
//
// A file starts with a 16-byte header:
//
//	magic "TTEF" (4) | version (1 byte, = 1) | chunk size (uint32 BE) | nonce prefix (7 random bytes)
//
// followed by chunks. Every chunk but the last holds exactly chunk size bytes
// of plaintext; the last one holds between 0 and chunk size - 1 bytes and is
// always present, so that truncation at a chunk boundary is detected. Each
// chunk is sealed with AES-256-GCM under the per-file key (DEK) with:
//
//	nonce = nonce prefix (7) | chunk counter (uint32 BE, from 0) | last flag (1 byte, 0 or 1)
//	AAD   = lp("transteira/v1/stream-chunk") | header (16) | lp(tenantID) | lp(fileID)
//
// A chunk on disk is therefore chunk size + 16 bytes long, except the last one
// (plaintext length + 16).
//
// # Random access
//
// ReaderAt decrypts any range of a file whose ciphertext size is known: the
// position of every chunk, and of the final one, follows from the size
// (PlaintextSize is the inverse of EncryptedSize).
//
// # Resumable uploads
//
// The Writer only emits complete chunks. Writer.Checkpoint returns a State
// holding the header, the number of complete chunks already emitted, and the
// caller's extra payload (at most 1 KiB, for example a SHA-256 state)
// followed by the incomplete tail, both sealed with a fresh random 96-bit
// nonce under a tail subkey distinct from the chunk key:
//
//	tail key = HKDF-SHA256(DEK, salt = none, info = "transteira/v1/stream-tail")
//	tail     = version (1 byte, = 1) | nonce (12 random bytes) | AES-256-GCM(extra | pending plaintext) and tag
//	AAD      = lp("transteira/v1/stream-tail") | header (16) | lp(tenantID) | lp(fileID) | complete chunks (uint32 BE) | extra length (uint32 BE)
//
// The pending plaintext is never encrypted under a counter nonce before it is
// complete, so resuming never encrypts two different plaintexts under the same
// nonce, provided the file on disk has exactly the checkpoint size (enforced
// by ResumeWriter) and a single writer resumes a given state at a time.
// State.MarshalBinary serializes a state as:
//
//	magic "TTCK" (4) | version (1 byte, = 1) | header (16) | complete chunks (uint32 BE) | extra length (uint32 BE) | tail length (uint32 BE) | tail
package crypto
