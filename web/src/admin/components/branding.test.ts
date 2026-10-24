import { describe, expect, it } from 'vitest';
import { ApiProblem, NetworkError } from '../../shared/api/client';
import type { Translator } from '../../shared/api/problem';
import type { ContrastRow } from '../forms/contrastView';
import {
  ACCEPT_ATTRIBUTE,
  ASSET_MAX_BYTES,
  DEFAULT_PICKER_VALUE,
  assetUrl,
  colorChanged,
  colorError,
  hexFromPicker,
  isBrandingAsset,
  isHexColor,
  isSafePreviewUrl,
  pickerValue,
  readPreviewUrl,
  rowsForPairs,
  serverFailures,
  uploadErrorMessage,
  validateImageFile,
  type DataUrlReader,
} from './branding';

const MIB = 1024 * 1024;

describe('colour helpers', () => {
  it('recognises #RRGGBB colours only', () => {
    expect(isHexColor('#1a5fb4')).toBe(true);
    expect(isHexColor('#1A5FB4')).toBe(true);
    expect(isHexColor('#1A5FB')).toBe(false);
    expect(isHexColor('1A5FB4')).toBe(false);
    expect(isHexColor('red')).toBe(false);
  });

  it('gives the picker a lowercase valid colour, the fallback, or black', () => {
    expect(pickerValue('#1A5FB4')).toBe('#1a5fb4');
    expect(pickerValue(' #1A5FB4 ')).toBe('#1a5fb4');
    expect(pickerValue('#1A5', '#00875A')).toBe('#00875a');
    expect(pickerValue('#1A5', 'nope')).toBe(DEFAULT_PICKER_VALUE);
    expect(pickerValue('')).toBe(DEFAULT_PICKER_VALUE);
  });

  it('turns a picker value into the uppercase text of the field', () => {
    expect(hexFromPicker('#1a5fb4')).toBe('#1A5FB4');
    expect(hexFromPicker('')).toBeNull();
  });

  it('validates the text of a colour field', () => {
    expect(colorError('#1a5fb4')).toBeUndefined();
    expect(colorError(' #1A5FB4 ')).toBeUndefined();
    expect(colorError('#12')).toBe('invalid');
  });

  it('compares colours without case', () => {
    expect(colorChanged('#1a5fb4', '#1A5FB4')).toBe(false);
    expect(colorChanged('#1a5fb4', '#1A5FB5')).toBe(true);
  });

  it('selects rows by pair and keeps server failures', () => {
    const rows: ContrastRow[] = [
      { pair: 'primary-on-light', ratio: 2.1, level: 'fail', source: 'server' },
      { pair: 'accent-on-light', ratio: 5, level: 'AA', source: 'server' },
      { pair: 'text-on-primary', ratio: 2.1, level: 'fail', source: 'live' },
    ];
    expect(rowsForPairs(rows, ['primary-on-light', 'text-on-primary']).map((r) => r.pair)).toEqual([
      'primary-on-light',
      'text-on-primary',
    ]);
    expect(serverFailures(rows).map((r) => r.pair)).toEqual(['primary-on-light']);
  });
});

describe('image file validation', () => {
  it('accepts PNG, JPEG and WebP within the limit of the asset', () => {
    expect(validateImageFile({ type: 'image/png', size: 5 * MIB }, 'logo')).toBeUndefined();
    expect(validateImageFile({ type: 'IMAGE/JPEG', size: 1 }, 'logo')).toBeUndefined();
    expect(validateImageFile({ type: 'image/webp', size: 10 * MIB }, 'background')).toBeUndefined();
    expect(ACCEPT_ATTRIBUTE).toBe('image/png,image/jpeg,image/webp');
  });

  it('refuses other types, empty files and oversized files', () => {
    expect(validateImageFile({ type: 'image/svg+xml', size: 10 }, 'logo')).toBe('bad-type');
    expect(validateImageFile({ type: '', size: 10 }, 'logo')).toBe('bad-type');
    expect(validateImageFile({ type: 'image/png', size: 0 }, 'logo')).toBe('empty');
    expect(validateImageFile({ type: 'image/png', size: ASSET_MAX_BYTES.logo + 1 }, 'logo')).toBe(
      'too-large',
    );
    expect(validateImageFile({ type: 'image/png', size: 10 * MIB + 1 }, 'background')).toBe('too-large');
  });

  it('knows the branding assets', () => {
    expect(isBrandingAsset('logo')).toBe(true);
    expect(isBrandingAsset('background')).toBe(true);
    expect(isBrandingAsset('favicon')).toBe(false);
  });
});

describe('assetUrl', () => {
  it('builds the same-origin admin URL with a cache-busting version', () => {
    expect(assetUrl('ten_01JAB00000000000000ENT1TYA', 'logo', 1700000000000)).toBe(
      '/api/v1/admin/tenants/ten_01JAB00000000000000ENT1TYA/branding/logo?v=1700000000000',
    );
    expect(assetUrl('ten_A', 'background', 'abc-1')).toBe(
      '/api/v1/admin/tenants/ten_A/branding/background?v=abc-1',
    );
  });

  it('refuses malformed parts', () => {
    expect(assetUrl('../x', 'logo', 1)).toBeNull();
    expect(assetUrl('ten/x', 'logo', 1)).toBeNull();
    expect(assetUrl('', 'logo', 1)).toBeNull();
    expect(assetUrl('ten_A', 'favicon', 1)).toBeNull();
    expect(assetUrl('ten_A', 'logo', 'a&b=c')).toBeNull();
    expect(assetUrl('ten_A', 'logo', '')).toBeNull();
  });
});

describe('local preview', () => {
  it('accepts base64 data: URLs of accepted image types only', () => {
    expect(isSafePreviewUrl('data:image/png;base64,iVBORw0KGgo=')).toBe(true);
    expect(isSafePreviewUrl('data:image/jpeg;base64,/9j/4AAQ')).toBe(true);
    expect(isSafePreviewUrl('data:image/webp;base64,UklGR+/=')).toBe(true);
    expect(isSafePreviewUrl('data:image/svg+xml;base64,PHN2Zz4=')).toBe(false);
    expect(isSafePreviewUrl('data:text/html;base64,PGI+')).toBe(false);
    expect(isSafePreviewUrl('data:image/png,raw')).toBe(false);
    expect(isSafePreviewUrl('javascript:alert(1)')).toBe(false);
    expect(isSafePreviewUrl('https://example.com/a.png')).toBe(false);
    expect(isSafePreviewUrl(null)).toBe(false);
    expect(isSafePreviewUrl(new ArrayBuffer(1))).toBe(false);
  });

  function fakeReader(
    behaviour: 'load' | 'error' | 'throw',
    result: string | null = null,
  ): () => DataUrlReader {
    return () => {
      const reader: DataUrlReader = {
        result: null,
        onload: null,
        onerror: null,
        readAsDataURL() {
          if (behaviour === 'throw') {
            throw new Error('boom');
          }
          reader.result = result;
          if (behaviour === 'load') {
            reader.onload?.();
          } else {
            reader.onerror?.();
          }
        },
      };
      return reader;
    };
  }

  it('resolves to the data: URL read from the file', async () => {
    const url = 'data:image/png;base64,iVBORw0KGgo=';
    await expect(readPreviewUrl(new Blob(['x']), fakeReader('load', url))).resolves.toBe(url);
  });

  it('resolves to null for an unsafe result or a failure', async () => {
    const blob = new Blob(['x']);
    await expect(
      readPreviewUrl(blob, fakeReader('load', 'data:image/svg+xml;base64,PHN2Zz4=')),
    ).resolves.toBeNull();
    await expect(readPreviewUrl(blob, fakeReader('error'))).resolves.toBeNull();
    await expect(readPreviewUrl(blob, fakeReader('throw'))).resolves.toBeNull();
  });
});

describe('uploadErrorMessage', () => {
  const tr: Translator = {
    t: (key) => `t:${key}`,
    has: (key) => key === 'errors.validation-failed' || key === 'fieldErrors.invalid-image',
  };

  it('maps 413 and 415 to their messages', () => {
    expect(uploadErrorMessage(tr, new ApiProblem(413, undefined))).toBe(
      't:adminTenants.branding.image.tooLargeServer',
    );
    expect(uploadErrorMessage(tr, new ApiProblem(415, undefined))).toBe(
      't:adminTenants.branding.image.unsupportedServer',
    );
  });

  it('shows the first field error of a 400', () => {
    const problem = new ApiProblem(400, {
      type: 'about:blank',
      title: 'Validation failed',
      status: 400,
      code: 'validation-failed',
      errors: [{ field: 'body', code: 'invalid-image' }],
    } as ConstructorParameters<typeof ApiProblem>[1]);
    expect(uploadErrorMessage(tr, problem)).toBe('t:fieldErrors.invalid-image');
  });

  it('falls back to the problem message', () => {
    const problem = new ApiProblem(400, {
      type: 'about:blank',
      title: 'Validation failed',
      status: 400,
      code: 'validation-failed',
    } as ConstructorParameters<typeof ApiProblem>[1]);
    expect(uploadErrorMessage(tr, problem)).toBe('t:errors.validation-failed');
    expect(uploadErrorMessage(tr, new NetworkError(new Error('offline')))).toBe('t:errors.network');
    expect(uploadErrorMessage(tr, new ApiProblem(500, undefined))).toBe('t:errors.unknown');
  });
});
