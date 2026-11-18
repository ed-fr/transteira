// Express secret of 2.3 (express.ts): offered durations and limit, client-side checks of the text
// (code points, lone surrogates, blank), sealing checked against the shared vector without
// passphrase (internal/tte2/testdata/vectors.json, e2e-format section 3.3.9), link composed by the
// page, and the classification and wording of the creation errors.
import { describe, expect, it, vi } from 'vitest';
import vectors from '../../../../internal/tte2/testdata/vectors.json';
import { ApiProblem, NetworkError, type Problem } from '../../shared/api/client';
import type { components } from '../../shared/api/schema';
import { deriveSecretKey, openSecret } from '../../shared/e2e/secret';
import * as secretModule from '../../shared/e2e/secret';
import {
  EXPRESS_DURATIONS,
  EXPRESS_PATH,
  PREFERRED_EXPRESS_DURATION,
  classifyExpressError,
  defaultExpressDuration,
  expressDurations,
  expressFailureMessage,
  expressFeatures,
  expressLink,
  expressMaxChars,
  expressOffered,
  invalidExpressFields,
  sealExpress,
  validateExpress,
  type ExpressFeatures,
  type ExpressFailure,
} from './express';

type PublicTenant = components['schemas']['PublicTenant'];

const ALL: ExpressFeatures = { enabled: true, durations: ['1h', '1d', '7d'], maxChars: 10000 };

function hex(s: string): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16);
  return out;
}

function problem(status: number, body: Partial<Problem> = {}): ApiProblem {
  return new ApiProblem(status, { type: 'about:blank', title: 't', status, ...body } as Problem);
}

const vector = vectors.secrets.find((v) => v.name === 'no-passphrase') as (typeof vectors.secrets)[number];

describe('express rules of the tenant', () => {
  it('reads the features of the public tenant', () => {
    expect(expressFeatures({ features: { expressSecrets: ALL } } as unknown as PublicTenant)).toBe(ALL);
    expect(expressFeatures({ features: {} } as unknown as PublicTenant)).toBeUndefined();
    expect(expressFeatures({} as unknown as PublicTenant)).toBeUndefined();
  });

  it('is offered only when enabled with at least one known duration', () => {
    expect(EXPRESS_PATH).toBe('/x');
    expect(EXPRESS_DURATIONS).toEqual(['1h', '1d', '7d']);
    expect(expressOffered(ALL)).toBe(true);
    expect(expressOffered(undefined)).toBe(false);
    expect(expressOffered({ ...ALL, enabled: false })).toBe(false);
    expect(expressOffered({ ...ALL, durations: [] })).toBe(false);
    expect(expressOffered({ ...ALL, durations: ['30d' as never] })).toBe(false);
  });

  it('keeps the known durations in the order of the format', () => {
    expect(expressDurations({ ...ALL, durations: ['7d', '1h', '12h' as never] })).toEqual(['1h', '7d']);
    expect(expressDurations(undefined)).toEqual([]);
  });

  it('preselects one day when offered, else the first duration', () => {
    expect(PREFERRED_EXPRESS_DURATION).toBe('1d');
    expect(defaultExpressDuration(['1h', '1d', '7d'])).toBe('1d');
    expect(defaultExpressDuration(['1h', '7d'])).toBe('1h');
    expect(defaultExpressDuration([])).toBeUndefined();
  });

  it('never allows more than the limit of the format', () => {
    expect(expressMaxChars(ALL)).toBe(10000);
    expect(expressMaxChars(undefined)).toBe(10000);
    expect(expressMaxChars({ ...ALL, maxChars: 500 as never })).toBe(500);
    expect(expressMaxChars({ ...ALL, maxChars: 20000 as never })).toBe(10000);
    expect(expressMaxChars({ ...ALL, maxChars: 0 as never })).toBe(10000);
  });
});

describe('validateExpress', () => {
  const durations = expressDurations(ALL);
  const check = (text: string, expiresIn: '1h' | '1d' | '7d' | null = '1d', max = 10000) =>
    validateExpress({ text, expiresIn: expiresIn ?? undefined }, durations, max);

  it('accepts a text of 1 to max code points, counted as typed', () => {
    expect(check('x')).toEqual({});
    expect(check('a'.repeat(10000))).toEqual({});
    // An emoji is one code point (two UTF-16 code units).
    expect(check('😀'.repeat(10000))).toEqual({});
    // No trimming nor normalisation: spaces and line breaks count.
    expect(check(` ${'a'.repeat(9998)}\n`)).toEqual({});
  });

  it('refuses a blank, too long or ill-formed text', () => {
    expect(check('')).toEqual({ text: { key: 'secretExpress.text.required' } });
    expect(check(' \n\t ')).toEqual({ text: { key: 'secretExpress.text.required' } });
    expect(check('a'.repeat(10001))).toEqual({
      text: { key: 'secretExpress.text.tooLong', params: { max: 10000 } },
    });
    expect(check('😀'.repeat(10001))).toEqual({
      text: { key: 'secretExpress.text.tooLong', params: { max: 10000 } },
    });
    expect(check('abc', '1d', 2)).toEqual({
      text: { key: 'secretExpress.text.tooLong', params: { max: 2 } },
    });
    expect(check('lone \ud800 surrogate')).toEqual({ text: { key: 'secretExpress.text.invalid' } });
    expect(check('\udc00')).toEqual({ text: { key: 'secretExpress.text.invalid' } });
  });

  it('requires an offered duration', () => {
    expect(check('x', null)).toEqual({ expiresIn: { key: 'secretExpress.duration.required' } });
    expect(validateExpress({ text: 'x', expiresIn: '7d' }, ['1h'], 10000)).toEqual({
      expiresIn: { key: 'secretExpress.duration.required' },
    });
  });

  it('lists the invalid fields in display order', () => {
    expect(invalidExpressFields(check('', null))).toEqual(['text', 'expiresIn']);
    expect(invalidExpressFields({})).toEqual([]);
  });
});

describe('sealExpress', () => {
  it('seals like the shared vector without passphrase (e2e-format 3.3.9)', async () => {
    const key = hex(vector.keyHex);
    const sealed = await sealExpress(vector.text, '1d', { newKey: () => key });
    expect(Object.keys(sealed.body).sort()).toEqual([
      'encryptedText',
      'expiresIn',
      'keyVerifier',
      'verifier',
    ]);
    expect(sealed.body.expiresIn).toBe('1d');
    expect(sealed.body.verifier).toBe(vector.verifierHex);
    expect(sealed.body.keyVerifier).toBe(vector.keyVerifierHex);
    // The recipient opens it with K' derived from K alone.
    const rootKey = await deriveSecretKey(hex(vector.keyHex), '', null);
    expect(await openSecret(rootKey, sealed.body.encryptedText)).toBe(vector.text);
    // The link carries K in its fragment, encoded as in the vector.
    expect(sealed.key).toBe(key);
    expect(expressLink('https://transfer.entity-a.example.com/', 'tts_abc', sealed.key)).toBe(
      `https://transfer.entity-a.example.com/s/tts_abc#k=${vector.keyFragment}`,
    );
  });

  it('draws a new random K for every secret and never puts it in the body', async () => {
    const a = await sealExpress('same text', '1h');
    const b = await sealExpress('same text', '1h');
    expect(a.key).toHaveLength(32);
    expect(a.key).not.toEqual(b.key);
    expect(a.body.encryptedText).not.toBe(b.body.encryptedText);
    const fragment = expressLink('https://x.example.com', 't', a.key).split('#k=')[1] as string;
    expect(JSON.stringify(a.body)).not.toContain(fragment);
    expect(JSON.stringify(a.body)).not.toContain('same text');
  });

  it('wipes K and rethrows when the sealing fails', async () => {
    const key = new Uint8Array(32).fill(7);
    const spy = vi.spyOn(secretModule, 'sealSecret').mockRejectedValueOnce(new Error('no crypto'));
    await expect(sealExpress('text', '1d', { newKey: () => key })).rejects.toThrow('no crypto');
    expect(key.every((b) => b === 0)).toBe(true);
    spy.mockRestore();
  });

  it('refuses a text the format refuses', async () => {
    const key = new Uint8Array(32).fill(9);
    await expect(sealExpress('\ud800', '1d', { newKey: () => key })).rejects.toThrow();
    expect(key.every((b) => b === 0)).toBe(true);
  });
});

describe('creation errors', () => {
  it.each<[unknown, ExpressFailure]>([
    [new NetworkError(new Error('offline')), { kind: 'network' }],
    [problem(403, { code: 'express-secrets-disabled' }), { kind: 'disabled' }],
    [
      problem(429, { code: 'rate-limited', retryAfterSeconds: 1200 }),
      { kind: 'rate-limited', retryAfterSeconds: 1200 },
    ],
    [problem(429, { code: 'rate-limited' }), { kind: 'rate-limited', retryAfterSeconds: undefined }],
    [problem(429, { code: 'express-secret-limit-reached' }), { kind: 'limit-reached' }],
    [problem(503, { code: 'maintenance' }), { kind: 'maintenance' }],
    [problem(503, { code: 'tenant-in-setup' }), { kind: 'in-setup' }],
    [problem(400, { code: 'validation-failed' }), { kind: 'invalid' }],
    [problem(400, { code: 'secret-format-invalid' }), { kind: 'invalid' }],
  ])('classifies %o', (err, expected) => {
    expect(classifyExpressError(err)).toEqual(expected);
  });

  it('keeps any other error for the generic description', () => {
    const csrf = problem(403, { code: 'csrf-invalid' });
    expect(classifyExpressError(csrf)).toEqual({ kind: 'error', cause: csrf });
    const boom = new Error('boom');
    expect(classifyExpressError(boom)).toEqual({ kind: 'error', cause: boom });
  });

  it('words each failure', () => {
    const say = (f: ExpressFailure, time?: string) => expressFailureMessage(f, 'Entity A', time);
    expect(say({ kind: 'seal' })).toEqual({ key: 'secretExpress.error.sealFailed' });
    expect(say({ kind: 'disabled' })).toEqual({
      key: 'secretExpress.error.disabled',
      params: { entity: 'Entity A' },
    });
    expect(say({ kind: 'rate-limited', retryAfterSeconds: undefined })).toEqual({
      key: 'secretExpress.error.rateLimited',
    });
    expect(say({ kind: 'rate-limited', retryAfterSeconds: 60 }, '14:32')).toEqual({
      key: 'secretExpress.error.rateLimitedUntil',
      params: { time: '14:32' },
    });
    expect(say({ kind: 'limit-reached' })).toEqual({ key: 'secretExpress.error.limitReached' });
    expect(say({ kind: 'maintenance' })).toEqual({ key: 'errors.maintenance' });
    expect(say({ kind: 'in-setup' })).toEqual({ key: 'errors.tenant-in-setup' });
    expect(say({ kind: 'invalid' })).toEqual({ key: 'secretExpress.error.invalid' });
    expect(say({ kind: 'network' })).toEqual({ key: 'errors.network' });
    expect(say({ kind: 'error', cause: new Error('x') })).toBeUndefined();
  });
});
