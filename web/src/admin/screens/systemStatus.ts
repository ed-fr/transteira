// "System status" card of the home of the super admin (CLAUDE.md section 13.2): getSystemStatus
// (GET /admin/system/status, super admin only) turned into labelled rows: application, database
// (engine and status), antivirus (engine and status, or disabled), file storage, maintenance mode
// (inactive, or active with its source) and version (up to date, update available, not checked,
// check off). Every text comes from a closed list of values: an unknown value (a newer server)
// shows the "Unknown" text, never the raw value, and the server never returns the cause of a
// failed check (threat model T-415: the engines are disclosed to the super admin only).
import type { ApiClient } from '../../shared/api/client';
import type { components } from '../../shared/api/schema';
import type { Translate } from '../../shared/i18n/messages';
import type { StatusVariant } from '../components/fields';
import { systemPath } from '../shell';

/** State of the instance components (getSystemStatus). */
export type SystemStatus = components['schemas']['SystemStatus'];

/** Path of the maintenance screen ("Manage maintenance mode"). */
export const MAINTENANCE_PATH = systemPath('maintenance');

/** Loads the state of the instance components (the API client is passed in, e.g. adminApi). */
export async function loadSystemStatus(api: Pick<ApiClient, 'get'>): Promise<SystemStatus> {
  const res = await api.get('/admin/system/status');
  return res.data;
}

/** One row of the card: a label and its value, as a status pill or as plain text. */
export interface StatusRow {
  id: 'application' | 'database' | 'antivirus' | 'storage' | 'maintenance' | 'version';
  label: string;
  /** Text of the value (the pill text, or the plain text when variant is undefined). */
  value: string;
  /** Pill variant; undefined for a plain muted text (the version when nothing is to report). */
  variant: StatusVariant | undefined;
  /** Extra text after the value (source of the maintenance mode), or undefined. */
  detail: string | undefined;
}

type Pill = { key: string; variant: StatusVariant };

const UNKNOWN: Pill = { key: 'unknown', variant: 'neutral' };

const APPLICATION: Readonly<Record<string, Pill>> = {
  ok: { key: 'operational', variant: 'ok' },
  degraded: { key: 'degraded', variant: 'warning' },
};

const COMPONENT: Readonly<Record<string, Pill>> = {
  ok: { key: 'available', variant: 'ok' },
  unavailable: { key: 'unavailable', variant: 'error' },
};

const ANTIVIRUS: Readonly<Record<string, Pill>> = {
  ...COMPONENT,
  disabled: { key: 'disabled', variant: 'neutral' },
};

const DATABASE_ENGINES: readonly string[] = ['sqlite', 'postgres'];
const ANTIVIRUS_ENGINES: readonly string[] = ['clamd', 'icap', 'http'];
const MAINTENANCE_SOURCES: readonly string[] = ['environment', 'admin'];

function pill(table: Readonly<Record<string, Pill>>, value: string): Pill {
  return Object.hasOwn(table, value) ? (table[value] as Pill) : UNKNOWN;
}

function statusText(p: Pill, t: Translate): string {
  return t(`adminHome.system.status.${p.key}`);
}

/** Name of a database engine ("SQLite", "PostgreSQL"), or the "unknown" text. */
export function databaseEngineName(engine: string, t: Translate): string {
  return t(
    DATABASE_ENGINES.includes(engine)
      ? `adminHome.system.engines.${engine}`
      : 'adminHome.system.status.unknown',
  );
}

/** Label of the antivirus row: "Antivirus (clamd)", or "Antivirus" without a known engine. */
export function antivirusLabel(engine: string, t: Translate): string {
  return ANTIVIRUS_ENGINES.includes(engine)
    ? t('adminHome.system.antivirusEngine', { engine: t(`adminHome.system.engines.${engine}`) })
    : t('adminHome.system.antivirus');
}

/** Value of the version row, and whether an update is available (an info pill then). */
export function versionValue(
  version: SystemStatus['version'],
  t: Translate,
): { text: string; update: boolean } {
  const current = version.version;
  if (!version.updateCheckEnabled) {
    return { text: t('adminHome.system.version.checkOff', { version: current }), update: false };
  }
  if (version.latestVersion === null || version.latestVersion === '') {
    return { text: t('adminHome.system.version.unchecked', { version: current }), update: false };
  }
  return version.updateAvailable
    ? {
        text: t('adminHome.system.version.update', { version: current, latest: version.latestVersion }),
        update: true,
      }
    : { text: t('adminHome.system.version.upToDate', { version: current }), update: false };
}

/** Rows of the "System status" card, in display order. */
export function systemStatusRows(status: SystemStatus, t: Translate): StatusRow[] {
  const application = pill(APPLICATION, status.status);
  const database = pill(COMPONENT, status.database.status);
  const antivirus = pill(ANTIVIRUS, status.antivirus.status);
  const storage = pill(COMPONENT, status.storage.status);
  const maintenanceOn = status.maintenance.enabled;
  const source = status.maintenance.source;
  const version = versionValue(status.version, t);
  return [
    {
      id: 'application',
      label: t('adminHome.system.application'),
      value: statusText(application, t),
      variant: application.variant,
      detail: undefined,
    },
    {
      id: 'database',
      label: t('adminHome.system.database'),
      value: t('adminHome.system.databaseValue', {
        engine: databaseEngineName(status.database.engine, t),
        status: statusText(database, t),
      }),
      variant: database.variant,
      detail: undefined,
    },
    {
      id: 'antivirus',
      label: antivirusLabel(status.antivirus.engine, t),
      value: statusText(antivirus, t),
      variant: antivirus.variant,
      detail: undefined,
    },
    {
      id: 'storage',
      label: t('adminHome.system.storage'),
      value: statusText(storage, t),
      variant: storage.variant,
      detail: undefined,
    },
    {
      id: 'maintenance',
      label: t('adminHome.system.maintenance'),
      value: t(maintenanceOn ? 'adminHome.system.status.active' : 'adminHome.system.status.inactive'),
      variant: maintenanceOn ? 'warning' : 'neutral',
      detail:
        maintenanceOn && MAINTENANCE_SOURCES.includes(source)
          ? t(`adminHome.system.source.${source}`)
          : undefined,
    },
    {
      id: 'version',
      label: t('adminHome.system.version.label'),
      value: version.text,
      variant: version.update ? 'info' : undefined,
      detail: undefined,
    },
  ];
}
