// Creation of a one-time secret in the browser (CLAUDE.md section 22.1, docs/architecture/e2e-format.md
// section 3.3): client-side checks mirroring the server rules (api/openapi.yaml createSecret), the
// sealing of the text and of the optional file under the secret root key K', the createSecret
// body and the link. Pure functions over WebCrypto, unit tested; the state machine of the page is
// createFlow.svelte.ts.
//
// Keys: K (32 random bytes, new for every secret, never reused even to retry) only feeds
// deriveSecretKey and secretKeyProof; K' = deriveSecretKey(K, passphrase) seals the text, gives the
// proof and is the transfer key (index 0) of the file stream and of its metadata.
import type { ProblemFieldError } from '../../shared/api/client';
import { normalizeField } from '../../shared/api/problem';
import type { components } from '../../shared/api/schema';
import { wellFormed, sealMetadata } from '../../shared/e2e/sealed';
import {
  MAX_PASSPHRASE_SIZE,
  MAX_SECRET_RUNES,
  deriveSecretKey,
  encodeProof,
  newPassphraseDescriptor,
  openSecret,
  sealSecret,
  secretKeyProof,
  secretProof,
  secretVerifier,
  type PassphraseDescriptor,
} from '../../shared/e2e/secret';
import {
  DEFAULT_CHUNK_SIZE,
  SALT_SIZE,
  ciphertextSize,
  encodeKey,
  generateTransferKey,
  randomBytes,
} from '../../shared/e2e/tte2';
import { createInThreadUploadCrypto, type UploadCrypto } from '../../shared/e2e/upload-crypto';
import { isEmail } from '../../shared/validation/email';

/** Body of POST /secrets. */
export type SecretCreate = components['schemas']['SecretCreate'];
/** Rules of the secrets module for the creation form (PublicTenant.features.secrets). */
export type SecretFeatures = components['schemas']['SecretFeatures'];
/** A duration of a secret. */
export type SecretDuration = components['schemas']['SecretDuration'];
/** How the link reaches the recipient. */
export type SecretDelivery = SecretCreate['delivery'];

export { MAX_SECRET_RUNES };

/** Longest file name accepted in the sealed metadata, in characters (as FileDeclaration.name). */
export const SECRET_FILE_NAME_MAX_LENGTH = 255;

/** Chunk size of the TTE2 stream of a secret file. */
export const SECRET_FILE_CHUNK_SIZE = DEFAULT_CHUNK_SIZE;

/** File-like value of the form (File in the browser). */
export interface SecretFile extends Blob {
  readonly name: string;
}

/** Values of the creation form. */
export interface SecretForm {
  /** The secret text (0 to MAX_SECRET_RUNES code points; empty only with a file). */
  text: string;
  /** Chosen duration, one of the offered durations. */
  expiresIn: SecretDuration | undefined;
  /** Optional passphrase; '' for none. */
  passphrase: string;
  /** Optional file. */
  file: SecretFile | undefined;
  /** Link to copy or mail to one recipient. */
  delivery: SecretDelivery;
  /** Recipient of an e-mail delivery (ignored for a link, imposed for an invited external). */
  recipient: string;
  /** Mail the creator when the secret is read, expires unread or is locked. */
  readReceipt: boolean;
}

/** Fields of the creation form. */
export type SecretField = 'text' | 'expiresIn' | 'passphrase' | 'file' | 'delivery' | 'recipient';

/** Display order of the fields (error summary). */
export const SECRET_FIELDS: readonly SecretField[] = [
  'text',
  'expiresIn',
  'passphrase',
  'file',
  'delivery',
  'recipient',
];

/** A message to display: a translation key with its parameters. */
export interface Message {
  key: string;
  params?: Record<string, string | number>;
}

/** Field errors of the creation form. */
export type SecretErrors = Partial<Record<SecretField, Message>>;

/** Who creates the secret. */
export interface SecretCreator {
  /** Rules of the tenant. */
  features: SecretFeatures;
  /** Invited external: e-mail delivery only, to the inviter. */
  external: boolean;
  /** Address of the inviter (external creators). */
  inviter?: string | undefined;
}

/** Number of Unicode code points of text (the unit of MAX_SECRET_RUNES). */
export function codePoints(text: string): number {
  let n = 0;
  for (const _ of text) n++;
  return n;
}

/** Size of the encrypted stream of a plaintext file of size bytes (what fileMaxBytes bounds). */
export function encryptedFileSize(size: number): number {
  return ciphertextSize(size, SECRET_FILE_CHUNK_SIZE);
}

/** Largest plaintext file whose encrypted stream fits in maxBytes (0 when none fits). */
export function maxPlainFileSize(maxBytes: number): number {
  // ciphertextSize is increasing: search the largest plaintext size that fits.
  let low = 0;
  let high = Math.max(0, maxBytes);
  if (encryptedFileSize(0) > maxBytes) return 0;
  while (low < high) {
    const mid = Math.ceil((low + high) / 2);
    if (encryptedFileSize(mid) <= maxBytes) low = mid;
    else high = mid - 1;
  }
  return low;
}

/** The delivery is imposed: an invited external creator can only mail the secret to the inviter. */
export function emailOnly(creator: SecretCreator): boolean {
  return creator.external;
}

/** The module is offered to this creator. */
export function secretsOffered(features: SecretFeatures | undefined, external: boolean): boolean {
  return features?.enabled === true && features.durations.length > 0 && (!external || features.emailAllowed);
}

/** Preselected duration: the default of the tenant when offered, else the first offered one. */
export function defaultDuration(features: SecretFeatures): SecretDuration | undefined {
  const d = features.defaultDuration;
  return d !== undefined && features.durations.includes(d) ? d : features.durations[0];
}

/** An empty form for these rules. */
export function emptySecretForm(creator: SecretCreator): SecretForm {
  return {
    text: '',
    expiresIn: defaultDuration(creator.features),
    passphrase: '',
    file: undefined,
    delivery: emailOnly(creator) ? 'email' : 'link',
    recipient: '',
    readReceipt: false,
  };
}

/** The delivery actually used (forced to email for an external creator). */
export function effectiveDelivery(form: SecretForm, creator: SecretCreator): SecretDelivery {
  return emailOnly(creator) ? 'email' : form.delivery;
}

/** The recipient actually used: the inviter for an external creator, else the typed address. */
export function effectiveRecipient(form: SecretForm, creator: SecretCreator): string {
  return emailOnly(creator) ? (creator.inviter ?? '') : form.recipient.trim();
}

/** The passphrase is required: e-mail delivery on a tenant that requires one. */
export function passphraseRequired(form: SecretForm, creator: SecretCreator): boolean {
  return effectiveDelivery(form, creator) === 'email' && creator.features.emailRequiresPassphrase === true;
}

const encoder = new TextEncoder();

/** Checks the form against the rules of the tenant; an empty object when it can be submitted. */
export function validateSecret(form: SecretForm, creator: SecretCreator): SecretErrors {
  const { features } = creator;
  const errors: SecretErrors = {};
  if (!wellFormed(form.text)) {
    errors.text = { key: 'fieldErrors.invalid' };
  } else if (codePoints(form.text) > MAX_SECRET_RUNES) {
    errors.text = { key: 'secretCreate.text.tooLong', params: { max: MAX_SECRET_RUNES } };
  } else if (form.text.trim() === '' && form.file === undefined) {
    errors.text = { key: 'secretCreate.text.required' };
  }
  if (form.expiresIn === undefined || !features.durations.includes(form.expiresIn)) {
    errors.expiresIn = { key: 'fieldErrors.required' };
  }
  if (form.passphrase !== '') {
    if (!wellFormed(form.passphrase)) {
      errors.passphrase = { key: 'fieldErrors.invalid' };
    } else if (encoder.encode(form.passphrase.normalize('NFC')).length > MAX_PASSPHRASE_SIZE) {
      errors.passphrase = { key: 'fieldErrors.too-long' };
    }
  } else if (passphraseRequired(form, creator)) {
    errors.passphrase = { key: 'secretCreate.passphrase.requiredByEmail' };
  }
  if (form.file !== undefined) {
    const max = features.fileMaxBytes;
    if (!features.fileAllowed) {
      errors.file = { key: 'secretCreate.file.notAllowed' };
    } else if (encryptedFileSize(form.file.size) > max) {
      errors.file = { key: 'secretCreate.file.tooLarge', params: { max: maxPlainFileSize(max) } };
    } else if (
      form.file.name === '' ||
      form.file.name.length > SECRET_FILE_NAME_MAX_LENGTH ||
      !wellFormed(form.file.name) ||
      !wellFormed(form.file.type)
    ) {
      errors.file = { key: 'fieldErrors.invalid-file-name' };
    }
  }
  const delivery = effectiveDelivery(form, creator);
  if (delivery === 'email' && !features.emailAllowed) {
    errors.delivery = { key: 'secretCreate.delivery.emailNotAllowed' };
  }
  if (delivery === 'email' && !emailOnly(creator)) {
    const recipient = form.recipient.trim();
    if (recipient === '') errors.recipient = { key: 'fieldErrors.required' };
    else if (!isEmail(recipient)) errors.recipient = { key: 'fieldErrors.invalid-email' };
  }
  return errors;
}

/** Fields with an error, in display order. */
export function invalidSecretFields(errors: SecretErrors): SecretField[] {
  return SECRET_FIELDS.filter((f) => errors[f] !== undefined);
}

/** Factory of the encryption service of the file (in the page by default: at most 25 MiB). */
export type SecretCryptoFactory = (rootKey: Uint8Array) => UploadCrypto;

/** Options of sealSecretForm. */
export interface SealSecretOptions {
  /** Encryption service of the file (tests). */
  crypto?: SecretCryptoFactory;
  /** Draws K (tests); 32 random bytes by default. */
  newKey?: () => Uint8Array<ArrayBuffer>;
}

/** A secret sealed in the browser, ready to be declared. */
export interface SealedSecret {
  /** K, the key of the link fragment. Never sent to the server except for the e-mail delivery. */
  key: Uint8Array<ArrayBuffer>;
  /** Body of POST /secrets. */
  body: SecretCreate;
  /** The encrypted stream of the file (uploaded as is, retried with the same bytes). */
  file?: Uint8Array<ArrayBuffer> | undefined;
}

/**
 * Seals a valid form (validateSecret returned no error): draws K and, with a passphrase, a new
 * descriptor; derives K'; seals the text and checks that it opens again (a verifier must never
 * certify a text that cannot be opened); computes the key verifier from K and the verifier from
 * K'; encrypts the file as a TTE2 stream of index 0 under K' and seals its metadata (index 0,
 * count 1). Errors of the crypto layer (E2EError) are rethrown.
 */
export async function sealSecretForm(
  form: SecretForm,
  creator: SecretCreator,
  options: SealSecretOptions = {},
): Promise<SealedSecret> {
  const key = (options.newKey ?? generateTransferKey)();
  const descriptor: PassphraseDescriptor | null = form.passphrase === '' ? null : newPassphraseDescriptor();
  const rootKey = await deriveSecretKey(key, form.passphrase, descriptor);
  const encryptedText = await sealSecret(rootKey, form.text);
  if ((await openSecret(rootKey, encryptedText)) !== form.text) {
    throw new Error('secret: the sealed text does not open to the same text');
  }
  const body: SecretCreate = {
    encryptedText,
    verifier: encodeProof(await secretVerifier(await secretProof(rootKey))),
    keyVerifier: encodeProof(await secretVerifier(await secretKeyProof(key))),
    expiresIn: form.expiresIn as SecretDuration,
    delivery: effectiveDelivery(form, creator),
  };
  if (descriptor !== null) {
    body.passphrase = descriptor as components['schemas']['SecretPassphrase'];
  }
  if (body.delivery === 'email') body.recipient = effectiveRecipient(form, creator);
  if (form.readReceipt) body.readReceipt = true;
  let file: Uint8Array<ArrayBuffer> | undefined;
  if (form.file !== undefined) {
    const sealed = await encryptFile(rootKey, form.file, options.crypto ?? createInThreadUploadCrypto);
    file = sealed.bytes;
    body.file = { size: file.length, encryptedMetadata: sealed.metadata };
  }
  return { key, body, file };
}

/** Encrypts the file (stream index 0 under K') in memory and seals its metadata. */
async function encryptFile(
  rootKey: Uint8Array,
  file: SecretFile,
  factory: SecretCryptoFactory,
): Promise<{ bytes: Uint8Array<ArrayBuffer>; metadata: string }> {
  const crypto = factory(rootKey);
  try {
    const sha256 = await crypto.hash(0, file, SECRET_FILE_CHUNK_SIZE);
    const size = await crypto.prepare(0, file, randomBytes(SALT_SIZE), SECRET_FILE_CHUNK_SIZE);
    const bytes = await crypto.range(0, 0, size);
    const metadata = await sealMetadata(rootKey, 0, {
      index: 0,
      count: 1,
      name: file.name,
      path: '',
      type: file.type,
      size: file.size,
      sha256,
    });
    return { bytes, metadata };
  } finally {
    crypto.dispose();
  }
}

/** The link of a secret: `${origin}/s/<token>#k=<K>` (e2e-format section 3.3.1). */
export function secretLink(origin: string, token: string, key: Uint8Array): string {
  return `${origin.replace(/\/+$/, '')}/s/${encodeURIComponent(token)}#k=${encodeKey(key)}`;
}

/** The key K in its fragment form (the fragmentKey of sendSecret). */
export function fragmentKey(key: Uint8Array): string {
  return encodeKey(key);
}

/** Field of the form a field error of the API (JSON pointer) concerns, if any. */
export function secretFieldOf(pointer: string): SecretField | undefined {
  const head = normalizeField(pointer).split('.')[0];
  switch (head) {
    case 'encryptedText':
      return 'text';
    case 'expiresIn':
    case 'passphrase':
    case 'file':
    case 'delivery':
    case 'recipient':
      return head;
    default:
      return undefined;
  }
}

/**
 * Maps the field errors of a validation-failed (or recipient-domain-refused) problem to the form;
 * has tells whether a fieldErrors.<code> message exists. Errors on fields the form does not have
 * are dropped (the caller then shows the general message).
 */
export function mapSecretErrors(
  errors: readonly ProblemFieldError[] | undefined,
  has: (key: string) => boolean,
): SecretErrors {
  const out: SecretErrors = {};
  for (const error of errors ?? []) {
    const field = secretFieldOf(error.field);
    if (field === undefined || out[field] !== undefined) continue;
    if (field === 'recipient' && error.code === 'domain-denied') {
      out.recipient = { key: 'secretCreate.recipient.domainRefused' };
      continue;
    }
    const key = `fieldErrors.${error.code}`;
    out[field] = { key: has(key) ? key : 'fieldErrors.invalid' };
  }
  return out;
}
