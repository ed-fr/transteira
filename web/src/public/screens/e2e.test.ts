import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  isEndToEnd,
  keyFromFragment,
  openEndToEnd,
  parseKeyText,
  takeKeyFromLocation,
  webCryptoAvailable,
} from './e2e';
import { sealMessage, sealMetadata, type Metadata } from '../../shared/e2e/sealed';
import { encodeKey, generateTransferKey } from '../../shared/e2e/tte2';
import type { PublicFile, PublicTransfer } from './outcomes';

const SHA = 'b'.repeat(64);

function meta(index: number, count: number, overrides: Partial<Metadata> = {}): Metadata {
  return {
    index,
    count,
    name: `n${index}.txt`,
    path: '',
    type: '',
    size: 10 + index,
    sha256: SHA,
    ...overrides,
  };
}

async function transfer(
  key: Uint8Array,
  metas: (Metadata | undefined)[],
  extra: Partial<PublicTransfer> = {},
): Promise<PublicTransfer> {
  const files: PublicFile[] = [];
  for (const [i, m] of metas.entries()) {
    files.push({
      id: `fil_${i}`,
      name: `file-${i + 1}.tte2`,
      size: 100,
      sha256: 'c'.repeat(64),
      scanStatus: 'not_scanned_e2e',
      downloadUrl: `/api/v1/downloads/dl_x/files/fil_${i}`,
      ...(m === undefined ? {} : { encryptedMetadata: await sealMetadata(key, m.index, m) }),
    });
  }
  return {
    senderEmail: 'alice@entity-a.example.com',
    expiresAt: '2026-12-01T00:00:00Z',
    passwordProtected: false,
    locked: false,
    endToEndEncrypted: true,
    files,
    ...extra,
  } as PublicTransfer;
}

describe('key input', () => {
  it('reads the key of the fragment or of the typed text', () => {
    const k = generateTransferKey();
    const s = encodeKey(k);
    expect(keyFromFragment(`#k=${s}`)).toEqual(k);
    expect(keyFromFragment(`#x=1&k=${s}`)).toEqual(k);
    expect(keyFromFragment('')).toBeUndefined();
    expect(keyFromFragment('#k=short')).toBeUndefined();
    expect(keyFromFragment(s)).toBeUndefined();
    expect(parseKeyText(` ${s} `)).toEqual(k);
    expect(parseKeyText(`https://transfer.entity-a.example.com/d/tok#k=${s}`)).toEqual(k);
    expect(parseKeyText('nope')).toBeUndefined();
  });

  it('recognises an end-to-end encrypted transfer', () => {
    expect(isEndToEnd({ endToEndEncrypted: true } as PublicTransfer)).toBe(true);
    expect(isEndToEnd({} as PublicTransfer)).toBe(false);
  });
});

describe('takeKeyFromLocation', () => {
  function history(state: unknown = { router: 1 }) {
    return { state, replaceState: vi.fn() };
  }

  it('reads the key, then removes the fragment from the URL and the history entry', () => {
    const k = generateTransferKey();
    const h = history();
    const key = takeKeyFromLocation({ pathname: '/d/dl_x', search: '?a=1', hash: `#k=${encodeKey(k)}` }, h);
    expect(key).toEqual(k);
    expect(h.replaceState).toHaveBeenCalledWith({ router: 1 }, '', '/d/dl_x?a=1');
  });

  it('removes an invalid fragment too, and leaves a URL without fragment alone', () => {
    const h = history(null);
    expect(takeKeyFromLocation({ pathname: '/d/dl_x', search: '', hash: '#k=short' }, h)).toBeUndefined();
    expect(h.replaceState).toHaveBeenCalledWith(null, '', '/d/dl_x');
    const untouched = history();
    expect(takeKeyFromLocation({ pathname: '/d/dl_x', search: '', hash: '' }, untouched)).toBeUndefined();
    expect(untouched.replaceState).not.toHaveBeenCalled();
  });
});

describe('openEndToEnd without a usable WebCrypto', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it('is unsupported without crypto.subtle (insecure context)', async () => {
    const k = generateTransferKey();
    const t = await transfer(k, [meta(0, 1)]);
    expect(webCryptoAvailable()).toBe(true);
    vi.stubGlobal('crypto', {});
    expect(webCryptoAvailable()).toBe(false);
    expect(await openEndToEnd(t, k)).toEqual({ kind: 'unsupported' });
    vi.stubGlobal('crypto', undefined);
    expect(await openEndToEnd(t, k)).toEqual({ kind: 'unsupported' });
  });

  it('is unsupported when WebCrypto fails outside of the format', async () => {
    const k = generateTransferKey();
    const withFile = await transfer(k, [meta(0, 1)]);
    const onlyMessage = await transfer(k, [], { encryptedMessage: await sealMessage(k, 'hi') });
    const derive = vi
      .spyOn(globalThis.crypto.subtle, 'deriveKey')
      .mockRejectedValue(new DOMException('no', 'NotSupportedError'));
    expect(await openEndToEnd(withFile, k)).toEqual({ kind: 'unsupported' });
    expect(await openEndToEnd(onlyMessage, k)).toEqual({ kind: 'unsupported' });
    derive.mockRestore();
    vi.spyOn(globalThis.crypto.subtle, 'importKey').mockRejectedValue(new TypeError('no HKDF'));
    expect(await openEndToEnd(withFile, k)).toEqual({ kind: 'unsupported' });
  });

  it('is tampered for an invalid key length (a format error)', async () => {
    const k = generateTransferKey();
    expect(await openEndToEnd(await transfer(k, [meta(0, 1)]), new Uint8Array(3))).toEqual({
      kind: 'tampered',
    });
  });
});

describe('openEndToEnd', () => {
  it('opens names, folders, sizes, fingerprints and the message', async () => {
    const k = generateTransferKey();
    const t = await transfer(
      k,
      [
        meta(0, 3, { path: 'Plans', name: 'a?.pdf' }),
        meta(1, 3),
        meta(2, 3, { name: 'a_.pdf', path: 'plans' }),
      ],
      {
        encryptedMessage: await sealMessage(k, 'Hello <b>'),
      },
    );
    t.files![1]!.downloadUrl = 'https://evil.example/x';
    const got = await openEndToEnd(t, k);
    expect(got.kind).toBe('open');
    if (got.kind !== 'open') return;
    expect(got.message).toBe('Hello <b>');
    expect(got.totalBytes).toBe(33);
    expect(got.key.extractable).toBe(false);
    expect(got.files.map((f) => [f.path, f.name, f.entryName, f.url])).toEqual([
      ['Plans', 'a_.pdf', 'Plans/a_.pdf', '/api/v1/downloads/dl_x/files/fil_0'],
      ['', 'n1.txt', 'n1.txt', undefined],
      ['plans', 'a_.pdf', 'Plans/a_ (2).pdf', '/api/v1/downloads/dl_x/files/fil_2'],
    ]);
    expect(got.files[0]).toMatchObject({
      id: 'fil_0',
      index: 0,
      size: 10,
      sha256: SHA,
      ciphertextSha256: 'c'.repeat(64),
    });
    expect(got.files[0]!.scanStatus).toBe('not_scanned_e2e');
  });

  it('drops an invalid folder and opens a transfer without message', async () => {
    const k = generateTransferKey();
    const got = await openEndToEnd(await transfer(k, [meta(0, 1, { path: 'a//b' })]), k);
    expect(got).toMatchObject({
      kind: 'open',
      message: undefined,
      files: [{ path: '', entryName: 'n0.txt' }],
    });
    const empty = await openEndToEnd(await transfer(k, [], { encryptedMessage: '' }), k);
    expect(empty).toMatchObject({ kind: 'open', files: [], totalBytes: 0 });
    const none = { ...(await transfer(k, [])), files: undefined } as PublicTransfer;
    expect(await openEndToEnd(none, k)).toMatchObject({ kind: 'open', files: [] });
  });

  it('detects a wrong key', async () => {
    const k = generateTransferKey();
    const other = generateTransferKey();
    expect(await openEndToEnd(await transfer(k, [meta(0, 1)]), other)).toEqual({ kind: 'wrong-key' });
    const onlyMessage = await transfer(k, [], { encryptedMessage: await sealMessage(k, 'hi') });
    expect(await openEndToEnd(onlyMessage, other)).toEqual({ kind: 'wrong-key' });
    const partial = await transfer(k, [meta(0, 2), undefined], { encryptedMessage: '' });
    expect(await openEndToEnd(partial, other)).toEqual({ kind: 'wrong-key' });
  });

  it('detects a removed, reordered or altered file', async () => {
    const k = generateTransferKey();
    const other = generateTransferKey();
    // The first file removed, or the files swapped: the key still opens another item.
    const removed = await transfer(k, [meta(0, 2), meta(1, 2)]);
    removed.files!.shift();
    expect(await openEndToEnd(removed, k)).toEqual({ kind: 'tampered' });
    const three = await transfer(k, [meta(0, 3), meta(1, 3), meta(2, 3)]);
    const sealed = three.files![0]!.encryptedMetadata!;
    const flipped = sealed[20] === 'A' ? 'B' : 'A';
    three.files![0]!.encryptedMetadata = sealed.slice(0, 20) + flipped + sealed.slice(21);
    expect(await openEndToEnd(three, k)).toEqual({ kind: 'tampered' });
    const withMessage = await transfer(k, [meta(0, 1)], { encryptedMessage: await sealMessage(k, 'm') });
    withMessage.files![0]!.encryptedMetadata = (
      await transfer(other, [meta(0, 1)])
    ).files![0]!.encryptedMetadata;
    expect(await openEndToEnd(withMessage, k)).toEqual({ kind: 'tampered' });
    // A file removed: the count no longer matches.
    expect(await openEndToEnd(await transfer(k, [meta(0, 2)]), k)).toEqual({ kind: 'tampered' });
    // Files swapped: the metadata of index 1 sits at position 0 (does not authenticate there).
    const swapped = await transfer(k, [meta(0, 2), meta(1, 2)]);
    swapped.files!.reverse();
    expect(await openEndToEnd(swapped, k)).toEqual({ kind: 'tampered' });
    const later = await transfer(k, [meta(0, 2), meta(1, 2)]);
    later.files![1]!.encryptedMetadata = later.files![0]!.encryptedMetadata;
    expect(await openEndToEnd(later, k)).toEqual({ kind: 'tampered' });
    // No metadata.
    expect(await openEndToEnd(await transfer(k, [undefined]), k)).toEqual({ kind: 'tampered' });
    // A message sealed with another key, or not well formed.
    const msg = await transfer(k, [meta(0, 1)], { encryptedMessage: await sealMessage(other, 'x') });
    expect(await openEndToEnd(msg, k)).toEqual({ kind: 'tampered' });
    const bad = await transfer(k, [meta(0, 1)], { encryptedMessage: '!!' });
    expect(await openEndToEnd(bad, k)).toEqual({ kind: 'tampered' });
  });
});
