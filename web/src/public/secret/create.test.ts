// Creation of a one-time secret (create.ts): client-side rules, sealing (checked by opening what
// was sealed with the recipient-side primitives) and the mapping of the server field errors.
import { describe, expect, it, vi } from 'vitest';
import { decryptBytes } from '../../shared/e2e/decrypt';
import { openMetadata } from '../../shared/e2e/sealed';
import {
  MAX_PASSPHRASE_SIZE,
  deriveSecretKey,
  encodeProof,
  openSecret,
  secretKeyProof,
  secretProof,
  secretVerifier,
} from '../../shared/e2e/secret';
import { createInThreadUploadCrypto } from '../../shared/e2e/upload-crypto';
import {
  MAX_SECRET_RUNES,
  SECRET_FILE_NAME_MAX_LENGTH,
  codePoints,
  defaultDuration,
  effectiveDelivery,
  effectiveRecipient,
  emailOnly,
  emptySecretForm,
  encryptedFileSize,
  fragmentKey,
  invalidSecretFields,
  mapSecretErrors,
  maxPlainFileSize,
  passphraseRequired,
  sealSecretForm,
  secretFieldOf,
  secretLink,
  secretsOffered,
  validateSecret,
  type SecretCreator,
  type SecretFeatures,
  type SecretForm,
} from './create';

// Lets one test make the self-check of sealSecretForm fail (the sealed text opens differently).
const tamper = vi.hoisted(() => ({ on: false }));
vi.mock('../../shared/e2e/secret', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../shared/e2e/secret')>();
  return {
    ...actual,
    openSecret: async (key: Uint8Array, s: string) => {
      const text = await actual.openSecret(key, s);
      return tamper.on ? `${text}!` : text;
    },
  };
});

// PBKDF2 at 600 000 iterations takes a fraction of a second per derivation.
const SLOW = 30_000;

const features: SecretFeatures = {
  enabled: true,
  durations: ['1h', '1d', '7d'],
  defaultDuration: '1d',
  fileAllowed: true,
  fileMaxBytes: 1024 * 1024,
  emailAllowed: true,
};

const internal: SecretCreator = { features, external: false };
const external: SecretCreator = { features, external: true, inviter: 'bob@entity-a.example.com' };

function form(over: Partial<SecretForm> = {}): SecretForm {
  return { ...emptySecretForm(internal), text: 's3cret', ...over };
}

function file(content: string | Uint8Array, name = 'note.txt', type = 'text/plain'): File {
  return new File([content as BlobPart], name, { type });
}

const fixedKey = () => new Uint8Array(32).fill(7);

describe('sizes and counts', () => {
  it('counts code points, not UTF-16 units', () => {
    expect(codePoints('')).toBe(0);
    expect(codePoints('a😀é')).toBe(3);
  });

  it('gives the size of the encrypted stream', () => {
    expect(encryptedFileSize(0)).toBe(48);
    expect(encryptedFileSize(10)).toBe(58);
    expect(encryptedFileSize(1024 * 1024 + 1)).toBe(32 + 1024 * 1024 + 1 + 32);
  });

  it('finds the largest plaintext that fits', () => {
    expect(maxPlainFileSize(47)).toBe(0);
    expect(maxPlainFileSize(-1)).toBe(0);
    expect(maxPlainFileSize(48)).toBe(0);
    expect(maxPlainFileSize(58)).toBe(10);
    const max = maxPlainFileSize(10 * 1024 * 1024);
    expect(encryptedFileSize(max)).toBeLessThanOrEqual(10 * 1024 * 1024);
    expect(encryptedFileSize(max + 1)).toBeGreaterThan(10 * 1024 * 1024);
  });
});

describe('rules of the tenant', () => {
  it('offers the module when enabled with durations, to externals only with e-mail', () => {
    expect(secretsOffered(undefined, false)).toBe(false);
    expect(secretsOffered({ ...features, enabled: false }, false)).toBe(false);
    expect(secretsOffered({ ...features, durations: [] }, false)).toBe(false);
    expect(secretsOffered(features, false)).toBe(true);
    expect(secretsOffered(features, true)).toBe(true);
    expect(secretsOffered({ ...features, emailAllowed: false }, true)).toBe(false);
    expect(secretsOffered({ ...features, emailAllowed: false }, false)).toBe(true);
  });

  it('preselects the default duration when offered, else the first one', () => {
    expect(defaultDuration(features)).toBe('1d');
    expect(defaultDuration({ ...features, defaultDuration: '30d' })).toBe('1h');
    const { defaultDuration: _omitted, ...rest } = features;
    expect(defaultDuration(rest)).toBe('1h');
    expect(defaultDuration({ ...rest, durations: [] })).toBeUndefined();
  });

  it('builds an empty form, e-mail only for an external', () => {
    expect(emptySecretForm(internal)).toEqual({
      text: '',
      expiresIn: '1d',
      passphrase: '',
      file: undefined,
      delivery: 'link',
      recipient: '',
      readReceipt: false,
    });
    expect(emptySecretForm(external).delivery).toBe('email');
    expect(emailOnly(external)).toBe(true);
    expect(emailOnly(internal)).toBe(false);
  });

  it('forces the delivery and the recipient of an external to the inviter', () => {
    const f = form({ delivery: 'link', recipient: 'x@example.com' });
    expect(effectiveDelivery(f, external)).toBe('email');
    expect(effectiveRecipient(f, external)).toBe('bob@entity-a.example.com');
    expect(effectiveRecipient(f, { ...external, inviter: undefined })).toBe('');
    expect(effectiveDelivery(f, internal)).toBe('link');
    expect(effectiveRecipient(form({ recipient: ' carol@example.net ' }), internal)).toBe(
      'carol@example.net',
    );
  });

  it('requires a passphrase only for e-mail on a tenant that says so', () => {
    const strict: SecretCreator = {
      features: { ...features, emailRequiresPassphrase: true },
      external: false,
    };
    expect(passphraseRequired(form({ delivery: 'email' }), strict)).toBe(true);
    expect(passphraseRequired(form({ delivery: 'link' }), strict)).toBe(false);
    expect(passphraseRequired(form({ delivery: 'email' }), internal)).toBe(false);
  });
});

describe('validateSecret', () => {
  it('accepts a valid form', () => {
    expect(validateSecret(form(), internal)).toEqual({});
    expect(validateSecret(form({ text: '', file: file('x') }), internal)).toEqual({});
  });

  it('checks the text', () => {
    expect(validateSecret(form({ text: '\ud800' }), internal).text?.key).toBe('fieldErrors.invalid');
    expect(validateSecret(form({ text: 'a'.repeat(MAX_SECRET_RUNES + 1) }), internal).text).toEqual({
      key: 'secretCreate.text.tooLong',
      params: { max: MAX_SECRET_RUNES },
    });
    expect(validateSecret(form({ text: '😀'.repeat(MAX_SECRET_RUNES) }), internal)).toEqual({});
    expect(validateSecret(form({ text: '  ' }), internal).text?.key).toBe('secretCreate.text.required');
  });

  it('checks the duration', () => {
    expect(validateSecret(form({ expiresIn: undefined }), internal).expiresIn?.key).toBe(
      'fieldErrors.required',
    );
    expect(validateSecret(form({ expiresIn: '30d' }), internal).expiresIn?.key).toBe('fieldErrors.required');
  });

  it('checks the passphrase', () => {
    expect(validateSecret(form({ passphrase: '\udc00' }), internal).passphrase?.key).toBe(
      'fieldErrors.invalid',
    );
    expect(
      validateSecret(form({ passphrase: 'é'.repeat(MAX_PASSPHRASE_SIZE / 2 + 1) }), internal).passphrase?.key,
    ).toBe('fieldErrors.too-long');
    expect(validateSecret(form({ passphrase: 'é'.repeat(MAX_PASSPHRASE_SIZE / 2) }), internal)).toEqual({});
    const strict: SecretCreator = {
      features: { ...features, emailRequiresPassphrase: true },
      external: false,
    };
    expect(
      validateSecret(form({ delivery: 'email', recipient: 'c@example.net' }), strict).passphrase?.key,
    ).toBe('secretCreate.passphrase.requiredByEmail');
    expect(
      validateSecret(form({ delivery: 'email', recipient: 'c@example.net', passphrase: 'p' }), strict),
    ).toEqual({});
  });

  it('checks the file', () => {
    const noFile: SecretCreator = { features: { ...features, fileAllowed: false }, external: false };
    expect(validateSecret(form({ file: file('x') }), noFile).file?.key).toBe('secretCreate.file.notAllowed');
    const tiny: SecretCreator = { features: { ...features, fileMaxBytes: 58 }, external: false };
    expect(validateSecret(form({ file: file('0123456789') }), tiny)).toEqual({});
    expect(validateSecret(form({ file: file('0123456789a') }), tiny).file).toEqual({
      key: 'secretCreate.file.tooLarge',
      params: { max: 10 },
    });
    const bad = (name: string, type = '') =>
      validateSecret(form({ file: file('x', name, type) }), internal).file?.key;
    expect(bad('')).toBe('fieldErrors.invalid-file-name');
    expect(bad('a'.repeat(SECRET_FILE_NAME_MAX_LENGTH + 1))).toBe('fieldErrors.invalid-file-name');
    expect(bad('a'.repeat(SECRET_FILE_NAME_MAX_LENGTH))).toBeUndefined();
    const lone = { name: 'a\ud800', type: '', size: 1 } as unknown as File;
    expect(validateSecret(form({ file: lone }), internal).file?.key).toBe('fieldErrors.invalid-file-name');
    const loneType = { name: 'a', type: '\ud800', size: 1 } as unknown as File;
    expect(validateSecret(form({ file: loneType }), internal).file?.key).toBe(
      'fieldErrors.invalid-file-name',
    );
  });

  it('checks the delivery and the recipient', () => {
    const noMail: SecretCreator = { features: { ...features, emailAllowed: false }, external: false };
    expect(
      validateSecret(form({ delivery: 'email', recipient: 'c@example.net' }), noMail).delivery?.key,
    ).toBe('secretCreate.delivery.emailNotAllowed');
    expect(validateSecret(form({ delivery: 'email', recipient: ' ' }), internal).recipient?.key).toBe(
      'fieldErrors.required',
    );
    expect(validateSecret(form({ delivery: 'email', recipient: 'nope' }), internal).recipient?.key).toBe(
      'fieldErrors.invalid-email',
    );
    expect(validateSecret(form({ delivery: 'link', recipient: 'nope' }), internal)).toEqual({});
    // The recipient of an external is the inviter: nothing typed to check.
    expect(validateSecret(form({ recipient: '' }), external)).toEqual({});
  });

  it('lists the invalid fields in display order', () => {
    expect(invalidSecretFields({ recipient: { key: 'a' }, text: { key: 'b' }, file: { key: 'c' } })).toEqual([
      'text',
      'file',
      'recipient',
    ]);
  });
});

describe('sealSecretForm', () => {
  it('seals a text-only link secret without passphrase', async () => {
    const sealed = await sealSecretForm(form({ text: 'hunter2 😀' }), internal, { newKey: fixedKey });
    expect(sealed.key).toEqual(fixedKey());
    expect(sealed.file).toBeUndefined();
    const { body } = sealed;
    expect(Object.keys(body).sort()).toEqual([
      'delivery',
      'encryptedText',
      'expiresIn',
      'keyVerifier',
      'verifier',
    ]);
    expect(body.delivery).toBe('link');
    expect(body.expiresIn).toBe('1d');
    // The recipient derives the same K' and proofs, and opens the text.
    const rootKey = await deriveSecretKey(sealed.key, '', null);
    expect(await openSecret(rootKey, body.encryptedText)).toBe('hunter2 😀');
    expect(body.keyVerifier).toBe(encodeProof(await secretVerifier(await secretKeyProof(sealed.key))));
    expect(body.verifier).toBe(encodeProof(await secretVerifier(await secretProof(rootKey))));
    expect(body.keyVerifier).not.toBe(body.verifier);
  });

  it('draws a new random key for every secret', async () => {
    const a = await sealSecretForm(form(), internal);
    const b = await sealSecretForm(form(), internal);
    expect(a.key).toHaveLength(32);
    expect(a.key).not.toEqual(b.key);
    expect(a.body.keyVerifier).not.toBe(b.body.keyVerifier);
  });

  it(
    'seals an e-mail secret with a passphrase, a read receipt and a file',
    async () => {
      const content = new Uint8Array(70_000).map((_, i) => i % 251);
      const f = form({
        text: '',
        passphrase: 'correct horse',
        delivery: 'email',
        recipient: ' carol@example.net ',
        readReceipt: true,
        file: file(content, 'report.pdf', 'application/pdf'),
      });
      const sealed = await sealSecretForm(f, internal);
      const { body } = sealed;
      expect(body.delivery).toBe('email');
      expect(body.recipient).toBe('carol@example.net');
      expect(body.readReceipt).toBe(true);
      expect(body.passphrase?.kdf).toBe('pbkdf2-sha256');
      expect(body.passphrase?.iterations).toBe(600000);
      expect(body.passphrase?.salt).toHaveLength(22);
      const rootKey = await deriveSecretKey(sealed.key, 'correct horse', body.passphrase ?? null);
      expect(await openSecret(rootKey, body.encryptedText)).toBe('');
      expect(body.verifier).toBe(encodeProof(await secretVerifier(await secretProof(rootKey))));
      // K alone (without the passphrase) gives the key proof but not the proof.
      const withoutPassphrase = await deriveSecretKey(sealed.key, '', null);
      expect(body.verifier).not.toBe(encodeProof(await secretVerifier(await secretProof(withoutPassphrase))));
      // The file is a TTE2 stream of index 0 under K', declared with its ciphertext size.
      const bytes = sealed.file as Uint8Array;
      expect(body.file?.size).toBe(bytes.length);
      expect(bytes.length).toBe(encryptedFileSize(content.length));
      expect(await decryptBytes({ key: rootKey, index: 0 }, bytes)).toEqual(content);
      const meta = await openMetadata(rootKey, 0, body.file?.encryptedMetadata as string);
      expect(meta).toMatchObject({
        index: 0,
        count: 1,
        name: 'report.pdf',
        path: '',
        type: 'application/pdf',
      });
      expect(meta.size).toBe(content.length);
      expect(meta.sha256).toMatch(/^[0-9a-f]{64}$/);
    },
    SLOW,
  );

  it('sends the inviter as the recipient of an external', async () => {
    const sealed = await sealSecretForm(form({ delivery: 'link', recipient: 'x@example.net' }), external);
    expect(sealed.body.delivery).toBe('email');
    expect(sealed.body.recipient).toBe('bob@entity-a.example.com');
  });

  it('uses and releases the injected encryption service', async () => {
    const dispose = vi.fn();
    const sealed = await sealSecretForm(form({ file: file('abc') }), internal, {
      crypto: (key) => {
        const real = createInThreadUploadCrypto(key);
        return { ...real, dispose: () => (dispose(), real.dispose()) };
      },
    });
    expect(dispose).toHaveBeenCalledOnce();
    expect(sealed.file).toHaveLength(encryptedFileSize(3));
  });

  it('releases the encryption service when the encryption fails', async () => {
    const dispose = vi.fn();
    await expect(
      sealSecretForm(form({ file: file('abc') }), internal, {
        crypto: () => ({
          hash: () => Promise.reject(new Error('boom')),
          prepare: () => Promise.reject(new Error('unused')),
          range: () => Promise.reject(new Error('unused')),
          dispose,
        }),
      }),
    ).rejects.toThrow('boom');
    expect(dispose).toHaveBeenCalledOnce();
  });

  it('refuses to certify a text that does not open again', async () => {
    tamper.on = true;
    try {
      await expect(sealSecretForm(form(), internal)).rejects.toThrow(/does not open/);
    } finally {
      tamper.on = false;
    }
  });
});

describe('links', () => {
  it('composes the link with the key in the fragment', () => {
    const key = fixedKey();
    const k = fragmentKey(key);
    expect(k).toHaveLength(43);
    expect(secretLink('https://transfer.entity-a.example.com/', 'tts_abc', key)).toBe(
      `https://transfer.entity-a.example.com/s/tts_abc#k=${k}`,
    );
    expect(secretLink('https://t.example.com', 'tts_abc', key)).toBe(
      `https://t.example.com/s/tts_abc#k=${k}`,
    );
  });
});

describe('server field errors', () => {
  it('maps the fields of SecretCreate to the form', () => {
    expect(secretFieldOf('/encryptedText')).toBe('text');
    expect(secretFieldOf('/expiresIn')).toBe('expiresIn');
    expect(secretFieldOf('/passphrase/salt')).toBe('passphrase');
    expect(secretFieldOf('/file/size')).toBe('file');
    expect(secretFieldOf('/delivery')).toBe('delivery');
    expect(secretFieldOf('/recipient')).toBe('recipient');
    expect(secretFieldOf('/verifier')).toBeUndefined();
  });

  it('keeps the first error of each field, known codes and the refused domain', () => {
    const has = (key: string) => key === 'fieldErrors.required';
    expect(
      mapSecretErrors(
        [
          { field: '/recipient', code: 'domain-denied' },
          { field: '/recipient', code: 'required' },
          { field: '/expiresIn', code: 'required' },
          { field: '/file/size', code: 'weird' },
          { field: '/keyVerifier', code: 'invalid-format' },
        ],
        has,
      ),
    ).toEqual({
      recipient: { key: 'secretCreate.recipient.domainRefused' },
      expiresIn: { key: 'fieldErrors.required' },
      file: { key: 'fieldErrors.invalid' },
    });
    expect(mapSecretErrors(undefined, has)).toEqual({});
  });
});
