// Package crypto implements TransTeira's encryption at rest (specification
// section 16.1, threat model decisions P6 and P7, threats T-28 to T-40).
//
// It provides three building blocks and depends on no other internal package:
//
//   - MasterKey: the 32-byte master key read from a file mounted outside the
//     data volumes. Its bytes are never exposed: it only derives one wrapping
//     key per Purpose (HKDF-SHA256) and a public identifier (ID) used to detect
//     a wrong key at startup.
//   - Envelope encryption: MasterKey.Wrap and MasterKey.Unwrap seal small
//     secrets (per-file data encryption keys, SMTP passwords) with
//     AES-256-GCM, bound to their purpose, tenant and database row so that a
//     blob copied to another row or tenant can no longer be opened.
//   - Chunked file encryption: Writer, Reader and ReaderAt implement a
//     STREAM-like AES-256-GCM format (see the "File format" section below)
//     that encrypts and decrypts in constant memory, sequentially or by range,
//     detects tampering, reordering, truncation and trailing data, and
//     supports resumable (tus) uploads
//     through Writer.Checkpoint and ResumeWriter without ever writing
//     plaintext to disk nor reusing a nonce.
//
// # Wrapped blob format
//
//	version (1 byte, = 1) | nonce (12 random bytes) | AES-256-GCM ciphertext and tag
//
// The key is HKDF-SHA256(master key, salt = none, info =
// "transteira/v1/wrap/" + purpose). The additional authenticated data is
// lp("transteira/v1/envelope") | lp(purpose) | lp(tenantID) | lp(rowID),
// where lp(x) is the big-endian uint32 length of x followed by x.
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
