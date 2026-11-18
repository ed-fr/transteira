// Express secret of version 2.3 (CLAUDE.md section 22.2): a one-time text secret created by
// anyone who reaches the FQDN of the tenant, without any identification, on the page /x. It is the
// restricted profile of a 2.1 secret (docs/architecture/e2e-format.md section 3.3.9): no
// passphrase (K' derived with an empty salt), no file, link delivery only, durations 1h, 1d or 7d,
// 1 to 10 000 Unicode code points counted here (the server never sees the text). Pure functions,
// unit tested; the state machine of the page is expressFlow.svelte.ts.
//
// Keys: K (32 random bytes, new for every secret, never reused even to retry) never leaves the
// page: the body of POST /express-secrets carries the sealed text and the two verifiers only, and
// the page composes the link `${origin}/s/<token>#k=<K>` itself from the token of the answer
// (threat model T-399).
import { ApiProblem, NetworkError } from '../../shared/api/client';
import { expressSecretDurationValues, type components } from '../../shared/api/schema';
import { wellFormed } from '../../shared/e2e/sealed';
import { generateTransferKey } from '../../shared/e2e/tte2';
import { MAX_SECRET_RUNES, codePoints, sealSecretText, secretLink, type Message } from './create';

/** What the express page needs (PublicTenant.features.expressSecrets). */
export type ExpressFeatures = components['schemas']['ExpressSecretFeatures'];
/** A duration of an express secret. */
export type ExpressDuration = components['schemas']['ExpressSecretDuration'];
/** Body of POST /express-secrets. */
export type ExpressSecretCreate = components['schemas']['ExpressSecretCreate'];

/** Public tenant description (GET /tenant). */
type PublicTenant = components['schemas']['PublicTenant'];

/** Path of the express secret page (served by internal/httpserver/webui.go). */
export const EXPRESS_PATH = '/x';

/** Durations of the format, in display order. */
export const EXPRESS_DURATIONS: readonly ExpressDuration[] = expressSecretDurationValues;

/**
 * Preselected duration when offered: one day leaves the recipient time to read the secret while
 * keeping it short (the threat model asks for short durations, section 3.3.9); the shortest one,
 * one hour, too often expires before a recipient in another time zone or in a meeting reads it.
 */
export const PREFERRED_EXPRESS_DURATION: ExpressDuration = '1d';

/** Fields of the express form. */
export type ExpressField = 'text' | 'expiresIn';

/** Display order of the fields (error summary). */
export const EXPRESS_FIELDS: readonly ExpressField[] = ['text', 'expiresIn'];

/** Field errors of the express form. */
export type ExpressErrors = Partial<Record<ExpressField, Message>>;

/** Values of the express form. */
export interface ExpressForm {
  /** The secret text, 1 to maxChars code points. */
  text: string;
  /** Chosen duration, one of the offered ones. */
  expiresIn: ExpressDuration | undefined;
}

/** The express rules of a tenant, undefined when the server does not describe them (before 2.3). */
export function expressFeatures(tenant: Pick<PublicTenant, 'features'>): ExpressFeatures | undefined {
  return tenant.features?.expressSecrets;
}

/** Offered durations: those of the tenant that the format knows, in the order of the format. */
export function expressDurations(features: ExpressFeatures | undefined): ExpressDuration[] {
  const offered = features?.durations ?? [];
  return EXPRESS_DURATIONS.filter((d) => offered.includes(d));
}

/** The anonymous express secret is offered on the tenant (header link and form of /x). */
export function expressOffered(features: ExpressFeatures | undefined): boolean {
  return features?.enabled === true && expressDurations(features).length > 0;
}

/** Preselected duration: PREFERRED_EXPRESS_DURATION when offered, else the first offered one. */
export function defaultExpressDuration(durations: readonly ExpressDuration[]): ExpressDuration | undefined {
  return durations.includes(PREFERRED_EXPRESS_DURATION) ? PREFERRED_EXPRESS_DURATION : durations[0];
}

/**
 * Largest text in code points: maxChars of the tenant, never more than the limit of the format
 * (a longer text could not be opened by the recipient, e2e-format section 3.3.3).
 */
export function expressMaxChars(features: ExpressFeatures | undefined): number {
  const max = features?.maxChars;
  return typeof max === 'number' && max > 0 ? Math.min(max, MAX_SECRET_RUNES) : MAX_SECRET_RUNES;
}

/**
 * Checks the form (e2e-format section 3.3.9): a well-formed text (no lone surrogate, which
 * TextEncoder would silently replace), of at most max code points as typed (no normalisation, no
 * trimming), not blank, and an offered duration. An empty object when it can be submitted.
 */
export function validateExpress(
  form: ExpressForm,
  durations: readonly ExpressDuration[],
  max: number,
): ExpressErrors {
  const errors: ExpressErrors = {};
  if (!wellFormed(form.text)) {
    errors.text = { key: 'secretExpress.text.invalid' };
  } else if (codePoints(form.text) > max) {
    errors.text = { key: 'secretExpress.text.tooLong', params: { max } };
  } else if (form.text.trim() === '') {
    errors.text = { key: 'secretExpress.text.required' };
  }
  if (form.expiresIn === undefined || !durations.includes(form.expiresIn)) {
    errors.expiresIn = { key: 'secretExpress.duration.required' };
  }
  return errors;
}

/** Fields with an error, in display order. */
export function invalidExpressFields(errors: ExpressErrors): ExpressField[] {
  return EXPRESS_FIELDS.filter((f) => errors[f] !== undefined);
}

/** An express secret sealed in the page, ready to be created. */
export interface SealedExpress {
  /** K, the key of the link fragment; never sent to the server. */
  key: Uint8Array<ArrayBuffer>;
  /** Body of POST /express-secrets: exactly the four members of the profile. */
  body: ExpressSecretCreate;
}

/** Options of sealExpress. */
export interface SealExpressOptions {
  /** Draws K (tests); 32 random bytes by default. */
  newKey?: () => Uint8Array<ArrayBuffer>;
}

/**
 * Seals a valid text (validateExpress returned no error): draws a new K, derives K' without
 * passphrase, seals the text and checks that it opens again, computes the two verifiers, then
 * wipes K'. On failure K is wiped too and the error is rethrown.
 */
export async function sealExpress(
  text: string,
  expiresIn: ExpressDuration,
  options: SealExpressOptions = {},
): Promise<SealedExpress> {
  const key = (options.newKey ?? generateTransferKey)();
  try {
    const sealed = await sealSecretText(key, '', null, text);
    sealed.rootKey.fill(0);
    return {
      key,
      body: {
        encryptedText: sealed.encryptedText,
        verifier: sealed.verifier,
        keyVerifier: sealed.keyVerifier,
        expiresIn,
      },
    };
  } catch (err) {
    key.fill(0);
    throw err;
  }
}

/** The link of an express secret, composed by the page: `${origin}/s/<token>#k=<K>`. */
export function expressLink(origin: string, token: string, key: Uint8Array): string {
  return secretLink(origin, token, key);
}

/** Why a creation was refused. */
export type ExpressFailure =
  /** The page could not seal the text (WebCrypto missing or failing). */
  | { kind: 'seal' }
  /** 403 express-secrets-disabled: the service was closed since the page was loaded. */
  | { kind: 'disabled' }
  /** 429 rate-limited: too many creations from this connection. */
  | { kind: 'rate-limited'; retryAfterSeconds: number | undefined }
  /** 429 express-secret-limit-reached: too many express secrets waiting on the tenant. */
  | { kind: 'limit-reached' }
  /** 503 maintenance. */
  | { kind: 'maintenance' }
  /** 503 tenant-in-setup. */
  | { kind: 'in-setup' }
  /** 400: the server refused the body (a faulty page). */
  | { kind: 'invalid' }
  /** No HTTP answer. */
  | { kind: 'network' }
  /** Any other error, described by the generic problem mapping. */
  | { kind: 'error'; cause: unknown };

/** Classifies an error of POST /express-secrets. */
export function classifyExpressError(err: unknown): ExpressFailure {
  if (err instanceof NetworkError) return { kind: 'network' };
  if (err instanceof ApiProblem) {
    switch (err.code) {
      case 'express-secrets-disabled':
        return { kind: 'disabled' };
      case 'rate-limited':
        return { kind: 'rate-limited', retryAfterSeconds: err.retryAfterSeconds };
      case 'express-secret-limit-reached':
        return { kind: 'limit-reached' };
      case 'maintenance':
        return { kind: 'maintenance' };
      case 'tenant-in-setup':
        return { kind: 'in-setup' };
    }
    if (err.status === 400) return { kind: 'invalid' };
  }
  return { kind: 'error', cause: err };
}

/**
 * Message of a failure, or undefined for 'error' (described by problemMessage). entity is the
 * name of the tenant; time the formatted clock time after which a rate-limited creation may be
 * tried again (undefined when the server gave no delay).
 */
export function expressFailureMessage(
  failure: ExpressFailure,
  entity: string,
  time: string | undefined,
): Message | undefined {
  switch (failure.kind) {
    case 'seal':
      return { key: 'secretExpress.error.sealFailed' };
    case 'disabled':
      return { key: 'secretExpress.error.disabled', params: { entity } };
    case 'rate-limited':
      return time === undefined
        ? { key: 'secretExpress.error.rateLimited' }
        : { key: 'secretExpress.error.rateLimitedUntil', params: { time } };
    case 'limit-reached':
      return { key: 'secretExpress.error.limitReached' };
    case 'maintenance':
      return { key: 'errors.maintenance' };
    case 'in-setup':
      return { key: 'errors.tenant-in-setup' };
    case 'invalid':
      return { key: 'secretExpress.error.invalid' };
    case 'network':
      return { key: 'errors.network' };
    case 'error':
      return undefined;
  }
}
