#!/usr/bin/env node
// secret-create.mjs: create and read TransTeira one-time secrets from a script (since 2.1).
//
// Node.js 18 or later, no npm package: the cryptography is WebCrypto (node:crypto webcrypto) and
// the HTTP calls use the built-in fetch. The format is docs/architecture/e2e-format.md section
// 3.3; the self-test mode checks this file against internal/tte2/testdata/vectors.json.
//
// Usage:
//   node secret-create.mjs create            < text      create a secret, print its link (or id)
//   node secret-create.mjs seal              < text      print a createSecret body for curl
//   node secret-create.mjs read              < link      reveal a secret (once) and print its text
//   node secret-create.mjs self-test VECTORS.json        check the format against the vectors
//
// The text is read from standard input as is (no trimming: use printf, not echo, to avoid a
// trailing line break). It must hold 1 to 10 000 Unicode code points. The link to read comes from
// the file named by TT_LINK_FILE or, without it, from standard input, never from the command
// line (other users of the host can read the process list). This example handles
// text only: for the optional file, implement the TTE2 stream of e2e-format.md section 2 with
// the root key K' and index 0.
//
// Environment:
//   TT_URL              tenant URL, e.g. https://transfer.entity-a.example.com (create)
//   TT_TOKEN_FILE       file holding the API token (create)
//   TT_SENDER           creator address: internal domain, allowed by the token (create)
//   TT_EXPIRES          duration offered by the tenant: 1h, 12h, 1d, 3d, 7d or 30d (default 1d)
//   TT_RECIPIENT        e-mail delivery to this address; without it the link is printed
//   TT_READ_RECEIPT     1 to receive a mail when the secret is read, expires or is locked
//   TT_PASSPHRASE_FILE  file holding the passphrase (optional; one trailing line break is
//                       dropped, nothing else is trimmed). Send it by another channel.
//   TT_SKIP_FILE        read: 1 to reveal a secret that has a file, losing the file (this
//                       example cannot decrypt it, and the reveal is one-time)
//   TT_LINK_FILE        read: file holding the link (default: standard input)
//
// The link https://<fqdn>/s/<token>#k=<key> is the secret: print it to a private place only.
// A new key is drawn for every secret, never reused, not even to retry a failed creation.
//
// seal prints {"fragmentKey": "...", "body": {...}}; the body lacks expiresIn, delivery and
// senderEmail, which the caller adds. Example with curl and jq (the key stays on this host, in a
// private work folder removed on exit):
//   umask 077; work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
//   printf 'Authorization: Bearer %s\n' "$(tr -d '\r\n' < "$TT_TOKEN_FILE")" > "$work/auth"
//   printf '%s' "$TEXT" | node secret-create.mjs seal > "$work/sealed.json"
//   jq '.body + {expiresIn: "1d", delivery: "link", senderEmail: env.TT_SENDER}' "$work/sealed.json" |
//     curl -sS --fail-with-body -X POST "$TT_URL/api/v1/secrets" -H @"$work/auth" \
//       -H 'Content-Type: application/json' --data-binary @- > "$work/created.json"
//   echo "$TT_URL/s/$(jq -r .token "$work/created.json")#k=$(jq -r .fragmentKey "$work/sealed.json")"

import { webcrypto } from 'node:crypto';
import { readFileSync } from 'node:fs';

const { subtle } = webcrypto;
const encoder = new TextEncoder();
// fatal: invalid UTF-8 is an error; ignoreBOM: a leading U+FEFF is kept, as in Go.
const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

const KEY_SIZE = 32;
const NONCE_SIZE = 12;
const TAG_SIZE = 16;
const SEALED_OVERHEAD = 1 + NONCE_SIZE + TAG_SIZE; // 29 bytes: version, nonce, tag
const MAX_SECRET_RUNES = 10000;
const MAX_SECRET_ENCODED_SIZE = ((SEALED_OVERHEAD + 4 * MAX_SECRET_RUNES) / 3) * 4; // 53 372
const PASSPHRASE_KDF = 'pbkdf2-sha256';
const PASSPHRASE_ITERATIONS = 600000;
const PASSPHRASE_SALT_SIZE = 16;
const MAX_PASSPHRASE_SIZE = 1024;
const INFO_SECRET = 'transteira/tte2/v1/secret';
const INFO_KEY_PROOF = 'transteira/tte2/v1/secret/key-proof';
const INFO_TEXT = 'transteira/tte2/v1/secret/text';
const INFO_PROOF = 'transteira/tte2/v1/secret/proof';
const SECRET_AAD = 'TTE2S';

/** A format error, named after the Go error of internal/tte2 (e.g. ErrAuth). */
class FormatError extends Error {
  constructor(code, detail) {
    super(`${code}: ${detail}`);
    this.code = code;
  }
}

// --- Encodings ---------------------------------------------------------------------------------

const hex = (b) => Buffer.from(b).toString('hex');
const fromHex = (s) => new Uint8Array(Buffer.from(s, 'hex'));
const b64url = (b) => Buffer.from(b).toString('base64url'); // no padding

/** Strict base64url: alphabet only, no padding, canonical (re-encoding gives the same string). */
function fromB64url(s) {
  if (!/^[A-Za-z0-9_-]*$/.test(s) || s.length % 4 === 1) return null;
  const b = Buffer.from(s, 'base64url');
  return b.toString('base64url') === s ? new Uint8Array(b) : null;
}

/** Decodes the key of a link fragment: 43 canonical base64url characters, 32 bytes. */
function decodeKey(s) {
  const k = s.length === 43 ? fromB64url(s) : null;
  if (k === null) throw new FormatError('ErrInvalidKey', 'not 43 canonical base64url characters');
  return k;
}

/** Reports whether s has no lone surrogate (valid Unicode scalar values only). */
function wellFormed(s) {
  return !/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(s);
}

// --- Derivations (section 3.3.2 and 3.3.4) -----------------------------------------------------

/** HKDF-SHA-256 of 32 bytes. */
async function hkdf(ikm, salt, info) {
  const base = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const bits = await subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info: encoder.encode(info) },
    base,
    8 * KEY_SIZE,
  );
  return new Uint8Array(bits);
}

/** Returns a passphrase descriptor with a fresh random salt. */
function newDescriptor() {
  const salt = webcrypto.getRandomValues(new Uint8Array(PASSPHRASE_SALT_SIZE));
  return { kdf: PASSPHRASE_KDF, iterations: PASSPHRASE_ITERATIONS, salt: b64url(salt) };
}

/**
 * Derives K' = HKDF(K, salt = P or empty, INFO_SECRET), P = PBKDF2-HMAC-SHA-256(NFC passphrase,
 * salt, 600000, 32). No passphrase is an empty passphrase with a null descriptor. The descriptor
 * must be exactly the one of the format, both when creating and when opening (never let a server
 * choose a cheaper derivation).
 */
async function deriveRootKey(key, passphrase, descriptor) {
  if (key.length !== KEY_SIZE) throw new FormatError('ErrInvalidKey', `${key.length} bytes`);
  let p = new Uint8Array(0);
  if (descriptor == null) {
    if (passphrase !== '') {
      throw new FormatError('ErrInvalidPassphrase', 'passphrase without descriptor');
    }
  } else {
    const salt = typeof descriptor.salt === 'string' && descriptor.salt.length === 22 ? fromB64url(descriptor.salt) : null;
    if (
      salt === null ||
      descriptor.kdf !== PASSPHRASE_KDF ||
      descriptor.iterations !== PASSPHRASE_ITERATIONS ||
      salt.length !== PASSPHRASE_SALT_SIZE
    ) {
      throw new FormatError('ErrInvalidPassphrase', 'unsupported descriptor');
    }
    if (passphrase === '') throw new FormatError('ErrInvalidPassphrase', 'empty passphrase');
    if (!wellFormed(passphrase)) throw new FormatError('ErrInvalidPassphrase', 'lone surrogate');
    const bytes = encoder.encode(passphrase.normalize('NFC'));
    if (bytes.length > MAX_PASSPHRASE_SIZE) {
      throw new FormatError('ErrInvalidPassphrase', `longer than ${MAX_PASSPHRASE_SIZE} bytes`);
    }
    const pk = await subtle.importKey('raw', bytes, 'PBKDF2', false, ['deriveBits']);
    p = new Uint8Array(
      await subtle.deriveBits(
        { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: PASSPHRASE_ITERATIONS },
        pk,
        8 * KEY_SIZE,
      ),
    );
  }
  return hkdf(key, p, INFO_SECRET);
}

const keyProof = (key) => hkdf(key, new Uint8Array(0), INFO_KEY_PROOF);
const proof = (rootKey) => hkdf(rootKey, new Uint8Array(0), INFO_PROOF);
const verifier = async (p) => new Uint8Array(await subtle.digest('SHA-256', p));

// --- Text (section 3.3.3) ----------------------------------------------------------------------

async function textKey(rootKey) {
  const raw = await hkdf(rootKey, new Uint8Array(0), INFO_TEXT);
  return subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

function checkText(text) {
  if ([...text].length > MAX_SECRET_RUNES) {
    throw new FormatError('ErrInvalidSecret', `longer than ${MAX_SECRET_RUNES} characters`);
  }
}

/** Seals the text: base64url(0x01 || nonce || AES-256-GCM(text, AAD "TTE2S") || tag). */
async function sealText(rootKey, text, nonce = webcrypto.getRandomValues(new Uint8Array(NONCE_SIZE))) {
  if (!wellFormed(text)) throw new FormatError('ErrInvalidSecret', 'lone surrogate');
  checkText(text);
  const ct = await subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, additionalData: encoder.encode(SECRET_AAD) },
    await textKey(rootKey),
    encoder.encode(text),
  );
  return b64url(Buffer.concat([Buffer.from([1]), nonce, Buffer.from(ct)]));
}

/** Opens a sealed text: strict framing (ErrEncoding), tag (ErrAuth), then the text rules. */
async function openText(rootKey, sealed) {
  const blob = sealed.length <= MAX_SECRET_ENCODED_SIZE ? fromB64url(sealed) : null;
  if (blob === null || blob.length < SEALED_OVERHEAD || blob[0] !== 1) {
    throw new FormatError('ErrEncoding', 'not a sealed secret text');
  }
  let plain;
  try {
    plain = await subtle.decrypt(
      { name: 'AES-GCM', iv: blob.subarray(1, 1 + NONCE_SIZE), additionalData: encoder.encode(SECRET_AAD) },
      await textKey(rootKey),
      blob.subarray(1 + NONCE_SIZE),
    );
  } catch {
    throw new FormatError('ErrAuth', 'wrong key or passphrase, or altered');
  }
  let text;
  try {
    text = decoder.decode(plain);
  } catch {
    throw new FormatError('ErrInvalidSecret', 'not valid UTF-8');
  }
  checkText(text);
  return text;
}

// --- Creation ----------------------------------------------------------------------------------

/**
 * Seals text under a new key and returns the fragment key and the part of the createSecret body
 * that comes from the cryptography. It opens its own sealed text before returning, so that the
 * verifiers never certify a text the recipient could not open.
 */
async function sealSecret(text, passphrase) {
  if (text === '') throw new Error('empty text (allowed only with a file, not handled here)');
  const key = webcrypto.getRandomValues(new Uint8Array(KEY_SIZE));
  const descriptor = passphrase === '' ? null : newDescriptor();
  const rootKey = await deriveRootKey(key, passphrase, descriptor);
  const encryptedText = await sealText(rootKey, text);
  if ((await openText(rootKey, encryptedText)) !== text) throw new Error('self-check failed');
  const body = {
    encryptedText,
    keyVerifier: hex(await verifier(await keyProof(key))),
    verifier: hex(await verifier(await proof(rootKey))),
  };
  if (descriptor !== null) body.passphrase = descriptor;
  return { fragmentKey: b64url(key), body };
}

function env(name, fallback) {
  const v = process.env[name];
  if (v !== undefined && v !== '') return v;
  if (fallback !== undefined) return fallback;
  throw new Error(`${name} is required`);
}

/** Reads the passphrase file, dropping one trailing line break only. */
function readPassphrase() {
  const file = process.env.TT_PASSPHRASE_FILE;
  if (!file) return '';
  // The fatal decoder refuses invalid UTF-8 instead of replacing it with U+FFFD.
  return decoder.decode(readFileSync(file)).replace(/\r?\n$/, '');
}

function readStdin() {
  return decoder.decode(readFileSync(0));
}

/**
 * Calls the API operation op; a non-2xx answer throws with the problem code (RFC 9457). The error
 * names the operation, not the path, which may hold a secret token. Redirects are refused.
 */
async function call(op, method, url, headers, body) {
  const res = await fetch(url, {
    method,
    redirect: 'error',
    headers: { Accept: 'application/json', ...(body ? { 'Content-Type': 'application/json' } : {}), ...headers },
    body: body ? JSON.stringify(body) : undefined,
  });
  const payload = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(`${op}: ${res.status} ${payload.code ?? ''} ${payload.detail ?? ''}`);
    err.status = res.status;
    err.problem = payload;
    throw err;
  }
  return payload;
}

async function create() {
  const base = env('TT_URL').replace(/\/+$/, '');
  if (!base.startsWith('https://')) throw new Error('TT_URL must start with https://');
  const token = readFileSync(env('TT_TOKEN_FILE'), 'utf8').trim();
  const auth = { Authorization: `Bearer ${token}` };
  const recipient = process.env.TT_RECIPIENT ?? '';
  const { fragmentKey, body } = await sealSecret(readStdin(), readPassphrase());
  Object.assign(body, {
    expiresIn: env('TT_EXPIRES', '1d'),
    delivery: recipient === '' ? 'link' : 'email',
    senderEmail: env('TT_SENDER'),
    readReceipt: process.env.TT_READ_RECEIPT === '1',
  });
  if (recipient !== '') body.recipient = recipient;
  const created = await call('createSecret', 'POST', `${base}/api/v1/secrets`, auth, body);
  if (recipient === '') {
    // Link delivery: the secret is active at once. The link is shown here only.
    process.stdout.write(`${base}/s/${created.token}#k=${fragmentKey}\n`);
    return;
  }
  // E-mail delivery: the server composes the link with both halves, sent once. On
  // 503 mail-unavailable the secret stays pending (purged after 1 hour): retry send.
  const sent = await call('sendSecret', 'POST', `${base}/api/v1/secrets/${created.id}/send`, auth, {
    secretToken: created.token,
    fragmentKey,
  });
  process.stdout.write(`${sent.id} ${sent.state} expires ${sent.expiresAt}\n`);
}

async function seal() {
  const out = await sealSecret(readStdin(), readPassphrase());
  process.stdout.write(`${JSON.stringify(out)}\n`);
}

// --- Reading -----------------------------------------------------------------------------------

/** Reads the link from TT_LINK_FILE or standard input, dropping surrounding white space. */
function readLink() {
  const file = process.env.TT_LINK_FILE;
  return decoder.decode(readFileSync(file ? file : 0)).trim();
}

async function read() {
  const m = /^(https:\/\/[^/?#]+)\/s\/(tts_[A-Za-z0-9]{43})#k=([A-Za-z0-9_-]{43})$/.exec(readLink());
  if (!m) throw new Error('read needs https://<fqdn>/s/<token>#k=<key> on standard input or in TT_LINK_FILE');
  const [, origin, secretToken, fragment] = m;
  const key = decodeKey(fragment);
  const url = `${origin}/api/v1/secret-links/${secretToken}`;
  // The status call consumes nothing (404 unknown, 410 secret-gone with a reason).
  const status = await call('getSecretLink', 'GET', url, {});
  if (status.file && process.env.TT_SKIP_FILE !== '1') {
    throw new Error('this secret has a file that this example cannot decrypt; set TT_SKIP_FILE=1 to reveal the text and lose the file');
  }
  const passphrase = status.passphrase ? readPassphrase() : '';
  if (status.passphrase && passphrase === '') throw new Error('this secret needs a passphrase: set TT_PASSPHRASE_FILE');
  const rootKey = await deriveRootKey(key, passphrase, status.passphrase ?? null);
  // One-time: the answer is the only copy (a wrong passphrase gets 403 secret-proof-invalid with
  // attemptsRemaining; the fifth counted failure locks the secret).
  const revealed = await call('revealSecret', 'POST', `${url}/reveal`, {}, {
    keyProof: hex(await keyProof(key)),
    proof: hex(await proof(rootKey)),
  });
  process.stdout.write(await openText(rootKey, revealed.encryptedText));
}

// --- Self-test against internal/tte2/testdata/vectors.json -------------------------------------

async function selfTest(path) {
  const vectors = JSON.parse(readFileSync(path, 'utf8'));
  let failures = 0;
  const check = (name, got, want) => {
    if (got !== want) {
      failures++;
      console.error(`FAIL ${name}: got ${got}, want ${want}`);
    }
  };
  const byName = new Map();
  for (const v of vectors.secrets) {
    byName.set(v.name, v);
    const key = decodeKey(v.keyFragment);
    check(`${v.name} keyFragment`, hex(key), v.keyHex);
    check(`${v.name} encoded key`, b64url(fromHex(v.keyHex)), v.keyFragment);
    if (v.passphraseNfcHex !== undefined) {
      check(`${v.name} NFC`, hex(encoder.encode(v.passphrase.normalize('NFC'))), v.passphraseNfcHex);
    }
    const rootKey = await deriveRootKey(key, v.passphrase ?? '', v.descriptor ?? null);
    check(`${v.name} rootKey`, hex(rootKey), v.rootKeyHex);
    const kp = await keyProof(key);
    check(`${v.name} keyProof`, hex(kp), v.keyProofHex);
    check(`${v.name} keyVerifier`, hex(await verifier(kp)), v.keyVerifierHex);
    const pr = await proof(rootKey);
    check(`${v.name} proof`, hex(pr), v.proofHex);
    check(`${v.name} verifier`, hex(await verifier(pr)), v.verifierHex);
    check(`${v.name} sealedText`, await sealText(rootKey, v.text, fromHex(v.textNonceHex)), v.sealedText);
    check(`${v.name} open`, await openText(rootKey, v.sealedText), v.text);
  }
  for (const n of vectors.secretNegative) {
    const base = byName.get(n.secret);
    const keyHex = n.keyHex ?? base.keyHex;
    const key = fromHex(keyHex);
    const passphrase = 'passphrase' in n ? n.passphrase : (base.passphrase ?? '');
    const descriptor = n.noDescriptor ? null : (n.descriptor ?? base.descriptor ?? null);
    check(`${n.name} keyProofValid`, hex(await verifier(await keyProof(key))) === base.keyVerifierHex, n.keyProofValid);
    let got = 'none';
    let proofValid = false;
    try {
      const rootKey = await deriveRootKey(key, passphrase, descriptor);
      proofValid = hex(await verifier(await proof(rootKey))) === base.verifierHex;
      if (n.text !== undefined) await sealText(rootKey, n.text);
      else await openText(rootKey, n.sealed ?? base.sealedText);
    } catch (e) {
      if (!(e instanceof FormatError)) throw e;
      got = e.code;
    }
    check(`${n.name} error`, got, n.expectedError);
    check(`${n.name} proofValid`, proofValid, n.proofValid);
  }
  if (failures > 0) {
    console.error(`self-test: ${failures} failure(s)`);
    process.exit(1);
  }
  console.log(`self-test: ok (${vectors.secrets.length} secrets, ${vectors.secretNegative.length} negative cases)`);
}

// --- Main --------------------------------------------------------------------------------------

const [mode, arg] = process.argv.slice(2);
const modes = { create, seal, read, 'self-test': () => selfTest(arg) };
if (!(mode in modes) || (mode === 'self-test') !== (arg !== undefined)) {
  console.error('usage: node secret-create.mjs create|seal|read|self-test VECTORS.json');
  process.exit(2);
}
try {
  await modes[mode]();
} catch (e) {
  console.error(`secret-create: ${e.message}`);
  process.exit(1);
}
