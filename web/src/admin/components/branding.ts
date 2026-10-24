// Logic of the branding components (ColorField, BrandPreview, ImageUpload) and of the branding
// screen, kept out of the components so that it is unit tested in Node.
//
// The image checks are indicative only (threat model T-166): the server sniffs, decodes and
// re-encodes every uploaded image whatever the browser claims.
import { ApiProblem } from '../../shared/api/client';
import { fieldMessage, problemMessage, type Translator } from '../../shared/api/problem';
import { HEX_COLOR } from '../../shared/theme/contrast';
import type { ContrastRow } from '../forms/contrastView';

// ---- Colours -------------------------------------------------------------------------------

/** Value shown by <input type="color"> when no valid colour is known. */
export const DEFAULT_PICKER_VALUE = '#000000';

/** Reports whether value is a #RRGGBB colour (HexColor of the API). */
export function isHexColor(value: string): boolean {
  return HEX_COLOR.test(value);
}

/**
 * Value of the colour picker for the text of the hexadecimal field: the colour in lowercase
 * (the form <input type="color"> uses), or fallback when the text is not a colour yet (the
 * picker cannot show an invalid value), or DEFAULT_PICKER_VALUE.
 */
export function pickerValue(hex: string, fallback?: string): string {
  const value = hex.trim();
  if (isHexColor(value)) {
    return value.toLowerCase();
  }
  if (fallback !== undefined && isHexColor(fallback)) {
    return fallback.toLowerCase();
  }
  return DEFAULT_PICKER_VALUE;
}

/** Text of the hexadecimal field for a value of the picker (uppercase), or null if invalid. */
export function hexFromPicker(value: string): string | null {
  return isHexColor(value) ? value.toUpperCase() : null;
}

/** Error of a colour field: 'invalid' unless the (trimmed) text is a #RRGGBB colour. */
export function colorError(hex: string): 'invalid' | undefined {
  return isHexColor(hex.trim()) ? undefined : 'invalid';
}

/** Reports whether two colours differ, ignoring case and surrounding spaces. */
export function colorChanged(a: string, b: string): boolean {
  return a.trim().toLowerCase() !== b.trim().toLowerCase();
}

/** Contrast rows of the given pairs, in the order of rows. */
export function rowsForPairs(rows: readonly ContrastRow[], pairs: readonly string[]): ContrastRow[] {
  return rows.filter((r) => pairs.includes(r.pair));
}

/** Contrast rows that fail the AA level and come from the server (authoritative warnings). */
export function serverFailures(rows: readonly ContrastRow[]): ContrastRow[] {
  return rows.filter((r) => r.source === 'server' && r.level === 'fail');
}

// ---- Images --------------------------------------------------------------------------------

/** A branding image of a tenant (path parameter asset of the API). */
export type BrandingAsset = 'logo' | 'background';

/** The branding images, in display order. */
export const BRANDING_ASSETS: readonly BrandingAsset[] = ['logo', 'background'];

/** Upload size limits of the API (uploadBrandingAsset): 5 MiB for the logo, 10 MiB for the background. */
export const ASSET_MAX_BYTES: Readonly<Record<BrandingAsset, number>> = {
  logo: 5 * 1024 * 1024,
  background: 10 * 1024 * 1024,
};

/** Media types accepted by the API for a branding image. */
export const ACCEPTED_IMAGE_TYPES: readonly string[] = ['image/png', 'image/jpeg', 'image/webp'];

/** accept attribute of the file input. */
export const ACCEPT_ATTRIBUTE = ACCEPTED_IMAGE_TYPES.join(',');

/** Client-side error of a chosen image. */
export type ImageFileError = 'bad-type' | 'too-large' | 'empty';

/** Reports whether value names a branding image. */
export function isBrandingAsset(value: string): value is BrandingAsset {
  return (BRANDING_ASSETS as readonly string[]).includes(value);
}

/** Checks the media type and size of a chosen image against the limits of asset. */
export function validateImageFile(
  file: { type: string; size: number },
  asset: BrandingAsset,
): ImageFileError | undefined {
  if (!ACCEPTED_IMAGE_TYPES.includes(file.type.toLowerCase())) {
    return 'bad-type';
  }
  if (file.size <= 0) {
    return 'empty';
  }
  if (file.size > ASSET_MAX_BYTES[asset]) {
    return 'too-large';
  }
  return undefined;
}

/** Base path of the API (default baseUrl of the client). */
const API_BASE = '/api/v1';
const TENANT_ID = /^[A-Za-z0-9_-]{1,128}$/;
const VERSION = /^[A-Za-z0-9_-]{1,64}$/;

/**
 * Same-origin URL of the stored image of a tenant (GET /admin/tenants/{tenantId}/branding/{asset},
 * answered with no-store and sent with the admin session cookie). version is a cache-busting
 * token changed after each upload or deletion. Returns null when a part is not well formed,
 * so that no other URL is ever built from route parameters.
 */
export function assetUrl(tenantId: string, asset: string, version: string | number): string | null {
  const v = String(version);
  if (!TENANT_ID.test(tenantId) || !isBrandingAsset(asset) || !VERSION.test(v)) {
    return null;
  }
  return `${API_BASE}/admin/tenants/${encodeURIComponent(tenantId)}/branding/${asset}?v=${encodeURIComponent(v)}`;
}

/** Pattern of the local preview of a chosen image: a base64 data: URL of an accepted type. */
const PREVIEW_URL = /^data:image\/(?:png|jpeg|webp);base64,[A-Za-z0-9+/]+={0,2}$/;

/**
 * Reports whether url may be shown as the local preview of a chosen image: only a base64
 * data: URL of PNG, JPEG or WebP (the admin CSP allows img-src data:). Anything else, such as
 * an SVG or a script URL, is never put in an <img>.
 */
export function isSafePreviewUrl(url: unknown): url is string {
  return typeof url === 'string' && PREVIEW_URL.test(url);
}

/** The part of FileReader used to read a local preview (a fake in tests). */
export interface DataUrlReader {
  result: string | ArrayBuffer | null;
  onload: (() => void) | null;
  onerror: (() => void) | null;
  readAsDataURL(blob: Blob): void;
}

/**
 * Reads file as a data: URL for its local preview. Resolves to null when reading fails or the
 * result is not a safe preview URL (isSafePreviewUrl).
 */
export function readPreviewUrl(file: Blob, createReader: () => DataUrlReader): Promise<string | null> {
  return new Promise((resolve) => {
    const reader = createReader();
    reader.onload = () => resolve(isSafePreviewUrl(reader.result) ? reader.result : null);
    reader.onerror = () => resolve(null);
    try {
      reader.readAsDataURL(file);
    } catch {
      resolve(null);
    }
  });
}

/**
 * Translated message of a failed upload: 413 (file or dimensions too large) and 415 (not
 * recognised as an accepted image) have their own messages; a 400 shows its first field
 * error, else the problem message; anything else the generic problem message.
 */
export function uploadErrorMessage(tr: Translator, err: unknown): string {
  if (err instanceof ApiProblem) {
    if (err.status === 413) {
      return tr.t('adminTenants.branding.image.tooLargeServer');
    }
    if (err.status === 415) {
      return tr.t('adminTenants.branding.image.unsupportedServer');
    }
    const first = err.status === 400 ? err.errors?.[0] : undefined;
    if (first !== undefined) {
      return fieldMessage(tr, first.code);
    }
  }
  return problemMessage(tr, err);
}
