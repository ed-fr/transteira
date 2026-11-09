// One-time secrets of V2.1 (docs/architecture/e2e-format.md section 3.3), mirroring
// internal/tte2/secret.go and checked against the same vectors (secrets, secretNegative).
//
// A secret has its own key K (carried by the link fragment exactly as a transfer key, see parseKey).
// K only feeds deriveSecretKey and secretKeyProof; the root key K' returned by deriveSecretKey
// feeds the text (sealSecret, openSecret), the proof (secretProof) and, as the transfer key with
// index 0, the optional file and its metadata (tte2.ts, decrypt.ts, sealMetadata, openMetadata).

import { decodeBase64Url, encodeBase64Url } from './base64url';
import { E2EError } from './errors';
import { SEALED_OVERHEAD, decodeSealed, open, seal, wellFormed, type SealOptions } from './sealed';
import { INFO_SECRET, KEY_SIZE, deriveAesKey, randomBytes, toBaseKey, type TransferKey } from './tte2';

/** Largest number of Unicode code points of a secret text. */
export const MAX_SECRET_RUNES = 10000;
/** Largest decoded size of a sealed secret text (overhead and 4 bytes per code point). */
export const MAX_SECRET_SIZE = SEALED_OVERHEAD + 4 * MAX_SECRET_RUNES;
/** Length of a sealed empty text, the shortest sealed secret text, in base64url characters. */
export const MIN_SECRET_ENCODED_SIZE = Math.ceil((SEALED_OVERHEAD * 4) / 3);
/** Largest length of a sealed secret text, in base64url characters. */
export const MAX_SECRET_ENCODED_SIZE = (MAX_SECRET_SIZE / 3) * 4;
/** The only key derivation function of a passphrase descriptor. */
export const PASSPHRASE_KDF = 'pbkdf2-sha256';
/** PBKDF2 iteration count, a constant of the format. */
export const PASSPHRASE_ITERATIONS = 600000;
/** Size of the salt of a passphrase descriptor. */
export const PASSPHRASE_SALT_SIZE = 16;
/** Length of the salt in base64url without padding. */
export const ENCODED_PASSPHRASE_SALT_SIZE = 22;
/** Largest size of a passphrase, in UTF-8 bytes after NFC normalization. */
export const MAX_PASSPHRASE_SIZE = 1024;
/** Size of a proof and of a verifier. */
export const PROOF_SIZE = 32;
/** HKDF info of the key proof, derived from K. */
export const INFO_SECRET_KEY_PROOF = 'transteira/tte2/v1/secret/key-proof';
/** HKDF info of the secret text key, derived from K'. */
export const INFO_SECRET_TEXT = 'transteira/tte2/v1/secret/text';
/** HKDF info of the proof, derived from K'. */
export const INFO_SECRET_PROOF = 'transteira/tte2/v1/secret/proof'; // gitleaks:allow (HKDF label)

const encoder = new TextEncoder();
// fatal: invalid UTF-8 is an error, as Go utf8.ValidString; ignoreBOM: a leading U+FEFF is kept.
const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

/** Public description of the passphrase of a secret, in its wire form (null means no passphrase). */
export interface PassphraseDescriptor {
  /** Key derivation function, PASSPHRASE_KDF. */
  kdf: string;
  /** PBKDF2 iteration count, PASSPHRASE_ITERATIONS. */
  iterations: number;
  /** PASSPHRASE_SALT_SIZE random bytes in base64url without padding (22 canonical characters). */
  salt: string;
}

/** Returns a descriptor with a fresh random salt. */
export function newPassphraseDescriptor(): PassphraseDescriptor {
  return {
    kdf: PASSPHRASE_KDF,
    iterations: PASSPHRASE_ITERATIONS,
    salt: encodeBase64Url(randomBytes(PASSPHRASE_SALT_SIZE)),
  };
}

/** Decodes a descriptor salt: exactly 22 canonical base64url characters, else invalid-passphrase. */
export function decodePassphraseSalt(s: string): Uint8Array<ArrayBuffer> {
  const salt = s.length === ENCODED_PASSPHRASE_SALT_SIZE ? decodeBase64Url(s) : null;
  if (salt === null) throw new E2EError('invalid-passphrase', 'bad salt encoding');
  return salt;
}

/**
 * Derives the secret root key K' from the secret key K (raw bytes):
 *
 *   K' = HKDF-SHA-256(K, salt = P or empty, INFO_SECRET)
 *   P  = PBKDF2-HMAC-SHA-256(UTF-8(NFC(passphrase)), salt, PASSPHRASE_ITERATIONS, 32)
 *
 * "No passphrase" is an empty passphrase with a null descriptor. Otherwise the passphrase must be
 * non-empty, without lone surrogates, at most MAX_PASSPHRASE_SIZE UTF-8 bytes after NFC (no
 * trimming, no case folding), and the descriptor exactly PASSPHRASE_KDF, PASSPHRASE_ITERATIONS and
 * a 16-byte salt; a passphrase without a descriptor or a descriptor without a passphrase is
 * invalid-passphrase. A key that is not KEY_SIZE bytes is invalid-key.
 */
export async function deriveSecretKey(
  key: Uint8Array,
  passphrase: string,
  descriptor: PassphraseDescriptor | null,
): Promise<Uint8Array<ArrayBuffer>> {
  if (key.length !== KEY_SIZE) throw new E2EError('invalid-key', `${key.length} bytes`);
  let p = new Uint8Array(0);
  if (descriptor === null) {
    if (passphrase !== '') throw new E2EError('invalid-passphrase', 'passphrase without descriptor');
  } else {
    const salt = decodePassphraseSalt(descriptor.salt);
    if (
      descriptor.kdf !== PASSPHRASE_KDF ||
      descriptor.iterations !== PASSPHRASE_ITERATIONS ||
      salt.length !== PASSPHRASE_SALT_SIZE
    ) {
      throw new E2EError('invalid-passphrase', 'unsupported descriptor');
    }
    p = await passphraseKey(passphrase, salt);
  }
  const base = await toBaseKey(key);
  const bits = await globalThis.crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: p, info: encoder.encode(INFO_SECRET) },
    base,
    8 * KEY_SIZE,
  );
  return new Uint8Array(bits);
}

/** Checks the passphrase rules and returns P = PBKDF2-HMAC-SHA-256 of its NFC UTF-8 form. */
async function passphraseKey(
  passphrase: string,
  salt: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  if (passphrase === '') throw new E2EError('invalid-passphrase', 'empty passphrase');
  if (!wellFormed(passphrase)) throw new E2EError('invalid-passphrase', 'lone surrogate');
  const bytes = encoder.encode(passphrase.normalize('NFC'));
  if (bytes.length > MAX_PASSPHRASE_SIZE) {
    throw new E2EError('invalid-passphrase', `longer than ${MAX_PASSPHRASE_SIZE} bytes`);
  }
  const pk = await globalThis.crypto.subtle.importKey('raw', bytes, 'PBKDF2', false, ['deriveBits']);
  const bits = await globalThis.crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: PASSPHRASE_ITERATIONS },
    pk,
    8 * KEY_SIZE,
  );
  return new Uint8Array(bits);
}

/** Returns the key proof HKDF(K, no salt, INFO_SECRET_KEY_PROOF): proves possession of K. */
export async function secretKeyProof(key: TransferKey): Promise<Uint8Array<ArrayBuffer>> {
  return deriveProof(key, INFO_SECRET_KEY_PROOF);
}

/** Returns the proof HKDF(K', no salt, INFO_SECRET_PROOF): proves possession of K'. */
export async function secretProof(rootKey: TransferKey): Promise<Uint8Array<ArrayBuffer>> {
  return deriveProof(rootKey, INFO_SECRET_PROOF);
}

/** Derives a PROOF_SIZE-byte proof. */
async function deriveProof(key: TransferKey, info: string): Promise<Uint8Array<ArrayBuffer>> {
  const base = await toBaseKey(key);
  const bits = await globalThis.crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: encoder.encode(info) },
    base,
    8 * PROOF_SIZE,
  );
  return new Uint8Array(bits);
}

/** Returns SHA-256(proof), the verifier sent at creation. */
export async function secretVerifier(proof: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', new Uint8Array(proof)));
}

/** Encodes a proof or a verifier in lowercase hexadecimal, its wire form. */
export function encodeProof(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

/** Decodes a proof or a verifier: exactly 64 lowercase hexadecimal characters, else invalid-secret. */
export function parseProof(s: string): Uint8Array<ArrayBuffer> {
  if (!/^[0-9a-f]{64}$/.test(s)) {
    throw new E2EError('invalid-secret', 'proof is not 64 lowercase hexadecimal characters');
  }
  const out = new Uint8Array(PROOF_SIZE);
  for (let i = 0; i < PROOF_SIZE; i++) out[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16);
  return out;
}

/**
 * Encrypts the secret text under HKDF(K', no salt, INFO_SECRET_TEXT) with AAD "TTE2S". text must
 * be well-formed (no lone surrogate) and at most MAX_SECRET_RUNES code points (invalid-secret); it
 * may be empty (allowed only for a secret with a file, a rule of the callers).
 */
export async function sealSecret(
  rootKey: TransferKey,
  text: string,
  options: SealOptions = {},
): Promise<string> {
  if (!wellFormed(text)) throw new E2EError('invalid-secret', 'lone surrogate');
  checkSecretLength(text);
  return sealSecretRaw(rootKey, encoder.encode(text), options);
}

/** Seals a secret plaintext without checking it. */
export async function sealSecretRaw(
  rootKey: TransferKey,
  plain: Uint8Array,
  options: SealOptions = {},
): Promise<string> {
  return seal(await deriveSecretTextKey(rootKey), secretAAD(), plain, options);
}

/**
 * Decrypts the sealed secret text s: encoding when it fails checkSecretFraming, auth when it does
 * not authenticate (wrong key or passphrase, altered, moved from another field), invalid-secret
 * when the plaintext is not valid UTF-8 of at most MAX_SECRET_RUNES code points.
 */
export async function openSecret(rootKey: TransferKey, s: string): Promise<string> {
  const plain = await open(await deriveSecretTextKey(rootKey), secretAAD(), s, MAX_SECRET_ENCODED_SIZE);
  let text: string;
  try {
    text = decoder.decode(plain);
  } catch {
    throw new E2EError('invalid-secret', 'not valid UTF-8');
  }
  checkSecretLength(text);
  return text;
}

/**
 * Checks the framing of a sealed secret text without the key: canonical base64url of
 * MIN_SECRET_ENCODED_SIZE to MAX_SECRET_ENCODED_SIZE characters, first decoded byte 0x01
 * (encoding otherwise).
 */
export function checkSecretFraming(s: string): void {
  decodeSealed(s, MAX_SECRET_ENCODED_SIZE);
}

/** Reports whether a sealed secret text that passed checkSecretFraming holds an empty text. */
export function secretTextIsEmpty(s: string): boolean {
  return s.length === MIN_SECRET_ENCODED_SIZE;
}

/** Derives the AES key of the secret text. */
async function deriveSecretTextKey(rootKey: TransferKey): Promise<CryptoKey> {
  return deriveAesKey(rootKey, new Uint8Array(0), encoder.encode(INFO_SECRET_TEXT));
}

/** AAD of a secret text: "TTE2S". */
function secretAAD(): Uint8Array<ArrayBuffer> {
  return encoder.encode('TTE2S');
}

/** Rejects a text of more than MAX_SECRET_RUNES code points. */
function checkSecretLength(text: string): void {
  if ([...text].length > MAX_SECRET_RUNES) {
    throw new E2EError('invalid-secret', `longer than ${MAX_SECRET_RUNES} characters`);
  }
}
