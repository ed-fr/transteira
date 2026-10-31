// Version display and update check of the administration (since 1.2). The running version is
// shown in the footer for every admin (GET /version); the super admin also sees whether a newer
// release exists (GET /admin/system/version) in a discreet notice and on the system overview,
// where "Check now" runs the check at once. TransTeira never updates itself: the notice only
// points to the release page and to the update procedure.
import type { ApiClient } from '../shared/api/client';
import type { components } from '../shared/api/schema';
import type { Translate } from '../shared/i18n/messages';

/** Running version and outcome of the last update check (GET /admin/system/version). */
export type SystemVersion = components['schemas']['SystemVersion'];
/** Outcome of the check for a newer release. */
export type UpdateCheck = components['schemas']['UpdateCheck'];

/** Shown in place of the version when it cannot be read. */
export const UNKNOWN_VERSION = '—';

/** Prefix of the release pages that may be linked (defence in depth, the server filters too). */
export const RELEASE_URL_PREFIX = 'https://github.com/ed-fr/transteira/releases/';

/** Version of the running instance (GET /version), UNKNOWN_VERSION when it cannot be read. */
export async function loadRunningVersion(api: Pick<ApiClient, 'get'>): Promise<string> {
  try {
    const { data } = await api.get('/version');
    return data.version.trim() === '' ? UNKNOWN_VERSION : data.version;
  } catch {
    return UNKNOWN_VERSION;
  }
}

/** Loads the version and update check state (super admin only). */
export async function loadSystemVersion(api: Pick<ApiClient, 'get'>): Promise<SystemVersion> {
  return (await api.get('/admin/system/version')).data;
}

/** Runs the update check at once (super admin only). */
export async function runVersionCheck(api: Pick<ApiClient, 'post'>): Promise<SystemVersion> {
  return (await api.post('/admin/system/version/check')).data;
}

/** The release link, only when it is a page of the project releases (never any other URL). */
export function safeReleaseUrl(url: string | null): string | undefined {
  return url !== null && url.startsWith(RELEASE_URL_PREFIX) ? url : undefined;
}

/** Translation key of the last error, undefined on success. */
export function lastErrorKey(error: UpdateCheck['lastError']): string | undefined {
  return error === 'none' ? undefined : `sysVersion.error.${error}`;
}

/** What the notice and the block show: hidden, or a newer release with its optional link. */
export type UpdateNotice =
  | { visible: false; latest?: undefined; releaseUrl?: undefined }
  | { visible: true; latest: string; releaseUrl: string | undefined };

/** View of the notice for an update check state (undefined while unknown). */
export function updateNotice(state: SystemVersion | undefined): UpdateNotice {
  const check = state?.updateCheck;
  if (check === undefined || !check.enabled || !check.updateAvailable || check.latestVersion === null) {
    return { visible: false };
  }
  return { visible: true, latest: check.latestVersion, releaseUrl: safeReleaseUrl(check.releaseUrl) };
}

/** Text announced after "Check now" succeeded. */
export function checkResultText(state: SystemVersion, t: Translate): string {
  const error = lastErrorKey(state.updateCheck.lastError);
  if (error !== undefined) {
    return t(error);
  }
  return state.updateCheck.updateAvailable && state.updateCheck.latestVersion !== null
    ? t('sysVersion.resultAvailable', { version: state.updateCheck.latestVersion })
    : t('sysVersion.resultUpToDate');
}

/** Message of a failed "Check now": rate limit and disabled check get their own sentence. */
export function checkFailureText(code: string | undefined, fallback: string, t: Translate): string {
  if (code === 'rate-limited') {
    return t('sysVersion.rateLimited');
  }
  return code === 'update-check-disabled' ? t('sysVersion.disabledNow') : fallback;
}

/** Version in the footer: "1.2.0". */
export function footerVersionText(version: string | undefined, t: Translate): string {
  return t('sysVersion.footer', { version: version ?? UNKNOWN_VERSION });
}
