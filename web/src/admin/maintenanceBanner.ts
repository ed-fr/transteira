// Maintenance banner of the administration (AdminLayout): shown to every admin while the
// maintenance mode is in effect, with its start date, the mention "forced by the environment"
// when TT_MAINTENANCE imposes it, and a link to the maintenance screen for the super admin. The
// maintenance message itself is meant for the public pages and is not repeated here.
import type { components } from '../shared/api/schema';
import type { Translate } from '../shared/i18n/messages';
import { systemPath } from './shell';

/** Maintenance state (GET /admin/system/maintenance). */
export type Maintenance = components['schemas']['Maintenance'];

/** What the banner shows. */
export interface MaintenanceBannerView {
  /** The maintenance mode is in effect: the banner is shown. */
  visible: boolean;
  /** Translation key of the text (adminSystem.banner.text or textSince with {date}). */
  textKey: string;
  /** Start of the maintenance (valid date-time from the server), to format as {date}. */
  since: string | undefined;
  /** Translation key of the source mention, when the environment forces the mode. */
  sourceKey: string | undefined;
  /** Link to the maintenance screen (super admin only). */
  linkPath: string | undefined;
}

/** View of the banner for a maintenance state (undefined while unknown) and an admin role. */
export function maintenanceBanner(
  state: Maintenance | undefined,
  role: string | undefined,
): MaintenanceBannerView {
  const visible = state?.enabled === true;
  const since =
    visible && state.since !== undefined && !Number.isNaN(Date.parse(state.since)) ? state.since : undefined;
  return {
    visible,
    textKey: since === undefined ? 'adminSystem.banner.text' : 'adminSystem.banner.textSince',
    since,
    sourceKey: visible && state.source === 'environment' ? 'adminSystem.banner.environment' : undefined,
    linkPath: visible && role === 'super_admin' ? systemPath('maintenance') : undefined,
  };
}

/** Text of the banner, the start date formatted by formatDate (formatDate of shared/i18n). */
export function maintenanceBannerText(
  view: MaintenanceBannerView,
  t: Translate,
  formatDate: (iso: string) => string,
): string {
  const text = view.since === undefined ? t(view.textKey) : t(view.textKey, { date: formatDate(view.since) });
  return view.sourceKey === undefined ? text : `${text} ${t(view.sourceKey)}`;
}
