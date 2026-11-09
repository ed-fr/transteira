// Package tte2 implements TTE2, the format of TransTeira's optional end-to-end
// encryption (specification section 22, threat model section 6.53). Files,
// file metadata and the transfer message are encrypted by the sender's client
// with a transfer key K that never reaches the server: it travels in the
// fragment of the download link ("#k=" followed by EncodedKeySize base64url
// characters, see EncodeKey and DecodeKey).
//
// This package is the reference implementation. The server only uses the
// keyless Validator, which checks the header and the stream size of an
// upload; tests and the command-line client use Writer, Reader and the sealed
// blob functions as a client; the browser has a TypeScript port that must
// reproduce testdata/vectors.json. The format is specified in
// docs/architecture/e2e-format.md.
//
// # Keys
//
// Every object has its own key, derived from K with HKDF-SHA256:
//
//	file i     HKDF(K, salt = header salt, info = InfoFile || u32 BE(i))
//	metadata i HKDF(K, no salt,            info = InfoMetadata || u32 BE(i))
//	message    HKDF(K, no salt,            info = InfoMessage)
//
// # One-time secrets (V2.1)
//
// A secret has its own key K, carried by its link like a transfer key. K only
// derives the secret root key K' (DeriveSecretKey, with an optional PBKDF2
// passphrase) and the key proof (SecretKeyProof). K' derives the text key
// (SealSecret, OpenSecret, AAD "TTE2S") and the proof (SecretProof), and
// serves as the transfer key, index 0, of the optional file and its metadata.
// The server stores SecretVerifier of both proofs and checks the proofs sent
// at the reveal with VerifierMatches; keyless, it checks the sealed text with
// CheckSecretFraming and SecretTextIsEmpty.
//
// # File streams
//
// A file is a 32-byte header (see Header) followed by AES-256-GCM chunks in a
// STREAM construction: the nonce of chunk j is seven zero bytes, u32 BE(j)
// and a last-chunk flag (0 or 1), and the AAD of every chunk is the whole
// header. All chunks hold C plaintext bytes except the final one, which holds
// 1 to C bytes, or 0 only for an empty file. Reordering, duplication,
// truncation, appended data, a swapped file index and a wrong key are all
// detected (see Reader). Sizes follow CiphertextSize and PlaintextSize.
//
// # Chunk API
//
// Writer and Reader are built on ChunkCipher, which seals and opens chunk n of
// a stream directly, with the same nonce, AAD, last-flag and length rules.
// The command-line client uses it to encrypt a file twice identically (a
// hashing pass, then the upload, sharing a header from NewHeader through
// WithHeader or NewChunkCipher), to resume an upload from the chunk holding a
// ciphertext offset (ChunkAt) and to resume a download from chunk n after
// re-reading the header (ParseHeader, ChunkOffset, ChunkCount).
//
// # Sealed blobs
//
// Metadata (JSON, see Metadata) and the message (UTF-8 text) are sealed as
// base64url without padding of 0x01 || 12-byte random nonce || ciphertext and
// tag, with the AAD "TTE2M" || u32 BE(i) for metadata and "TTE2T" for the
// message.
//
// Every function fails closed: on any error no plaintext is returned.
package tte2
