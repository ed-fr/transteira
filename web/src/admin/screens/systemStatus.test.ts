import { describe, expect, it, vi } from 'vitest';
import en from '../../locales/en/adminHome.json';
import fr from '../../locales/fr/adminHome.json';
import {
  MAINTENANCE_PATH,
  antivirusLabel,
  databaseEngineName,
  loadSystemStatus,
  systemStatusRows,
  versionValue,
  type SystemStatus,
} from './systemStatus';

const t = (key: string, params?: Record<string, string | number>): string =>
  params === undefined ? key : `${key} ${JSON.stringify(params)}`;

/** A message of a bundle by its dotted key. */
function message(bundle: unknown, key: string): string | undefined {
  let node: unknown = bundle;
  for (const part of key.split('.')) {
    node = typeof node === 'object' && node !== null ? (node as Record<string, unknown>)[part] : undefined;
  }
  return typeof node === 'string' ? node : undefined;
}

/** A translation that resolves the real English messages of adminHome (and echoes the others). */
const real = (key: string, params?: Record<string, string | number>): string => {
  const text = key.startsWith('adminHome.') ? message(en, key.slice('adminHome.'.length)) : undefined;
  if (text === undefined) {
    return key;
  }
  return text.replace(/\{(\w+)\}/g, (_m, name: string) => String(params?.[name] ?? `{${name}}`));
};

const status: SystemStatus = {
  status: 'ok',
  checkedAt: '2026-11-19T08:00:00Z',
  database: { engine: 'sqlite', status: 'ok' },
  antivirus: { engine: 'clamd', status: 'ok' },
  storage: { status: 'ok' },
  maintenance: { enabled: false, source: 'none' },
  version: { version: '2.3.0', updateCheckEnabled: true, latestVersion: '2.3.0', updateAvailable: false },
};

describe('loadSystemStatus', () => {
  it('reads GET /admin/system/status', async () => {
    const get = vi.fn(async () => ({ data: status, status: 200, headers: new Headers() }));
    expect(await loadSystemStatus({ get } as never)).toBe(status);
    expect(get).toHaveBeenCalledWith('/admin/system/status');
    expect(MAINTENANCE_PATH).toBe('/system/maintenance');
  });
});

describe('systemStatusRows', () => {
  it('lists every component of a healthy instance', () => {
    expect(systemStatusRows(status, real)).toEqual([
      { id: 'application', label: 'Application', value: 'Operational', variant: 'ok', detail: undefined },
      { id: 'database', label: 'Database', value: 'SQLite · Available', variant: 'ok', detail: undefined },
      { id: 'antivirus', label: 'Antivirus (clamd)', value: 'Available', variant: 'ok', detail: undefined },
      { id: 'storage', label: 'File storage', value: 'Available', variant: 'ok', detail: undefined },
      {
        id: 'maintenance',
        label: 'Maintenance mode',
        value: 'Inactive',
        variant: 'neutral',
        detail: undefined,
      },
      { id: 'version', label: 'Version', value: '2.3.0 · up to date', variant: undefined, detail: undefined },
    ]);
  });

  it('shows the failures, the disabled antivirus and the maintenance source', () => {
    const rows = systemStatusRows(
      {
        ...status,
        status: 'degraded',
        database: { engine: 'postgres', status: 'unavailable' },
        antivirus: { engine: 'none', status: 'disabled' },
        storage: { status: 'unavailable' },
        maintenance: { enabled: true, source: 'environment' },
      },
      real,
    );
    expect(rows.map((r) => [r.id, r.label, r.value, r.variant, r.detail])).toEqual([
      ['application', 'Application', 'Degraded', 'warning', undefined],
      ['database', 'Database', 'PostgreSQL · Unavailable', 'error', undefined],
      ['antivirus', 'Antivirus', 'Disabled', 'neutral', undefined],
      ['storage', 'File storage', 'Unavailable', 'error', undefined],
      ['maintenance', 'Maintenance mode', 'Active', 'warning', 'Forced by the environment'],
      ['version', 'Version', '2.3.0 · up to date', undefined, undefined],
    ]);
    const admin = systemStatusRows({ ...status, maintenance: { enabled: true, source: 'admin' } }, real);
    expect(admin[4]?.detail).toBe('Turned on by a super administrator');
  });

  it('never shows an unknown value as such', () => {
    const odd = {
      ...status,
      status: 'weird',
      database: { engine: 'oracle', status: 'odd' },
      antivirus: { engine: 'other', status: 'strange' },
      storage: { status: 'odd' },
      maintenance: { enabled: true, source: 'odd' },
    } as unknown as SystemStatus;
    const rows = systemStatusRows(odd, real);
    expect(rows.map((r) => [r.label, r.value, r.variant, r.detail])).toEqual([
      ['Application', 'Unknown', 'neutral', undefined],
      ['Database', 'Unknown · Unknown', 'neutral', undefined],
      ['Antivirus', 'Unknown', 'neutral', undefined],
      ['File storage', 'Unknown', 'neutral', undefined],
      ['Maintenance mode', 'Active', 'warning', undefined],
      ['Version', '2.3.0 · up to date', undefined, undefined],
    ]);
    expect(JSON.stringify(rows)).not.toMatch(/weird|oracle|odd|other|strange/);
  });

  it('names the engines', () => {
    expect(databaseEngineName('sqlite', t)).toBe('adminHome.system.engines.sqlite');
    expect(databaseEngineName('postgres', real)).toBe('PostgreSQL');
    expect(databaseEngineName('x', t)).toBe('adminHome.system.status.unknown');
    expect(antivirusLabel('icap', real)).toBe('Antivirus (ICAP)');
    expect(antivirusLabel('http', real)).toBe('Antivirus (HTTP API)');
    expect(antivirusLabel('none', t)).toBe('adminHome.system.antivirus');
  });
});

describe('versionValue', () => {
  const version = status.version;

  it('tells whether the instance is up to date', () => {
    expect(versionValue(version, t)).toEqual({
      text: 'adminHome.system.version.upToDate {"version":"2.3.0"}',
      update: false,
    });
    expect(versionValue({ ...version, latestVersion: '2.4.0', updateAvailable: true }, t)).toEqual({
      text: 'adminHome.system.version.update {"version":"2.3.0","latest":"2.4.0"}',
      update: true,
    });
  });

  it('says when the check is off or has not run yet', () => {
    expect(versionValue({ ...version, updateCheckEnabled: false }, t).text).toBe(
      'adminHome.system.version.checkOff {"version":"2.3.0"}',
    );
    expect(versionValue({ ...version, latestVersion: null }, t).text).toBe(
      'adminHome.system.version.unchecked {"version":"2.3.0"}',
    );
    expect(versionValue({ ...version, latestVersion: '' }, t).update).toBe(false);
  });

  it('marks an available update with an info pill', () => {
    const rows = systemStatusRows(
      { ...status, version: { ...version, latestVersion: '2.4.0', updateAvailable: true } },
      t,
    );
    expect(rows[5]?.variant).toBe('info');
  });
});

describe('translations of the keys built at runtime', () => {
  it('exist in English and in French', () => {
    const keys = [
      ...[
        'operational',
        'degraded',
        'available',
        'unavailable',
        'disabled',
        'active',
        'inactive',
        'unknown',
      ].map((k) => `system.status.${k}`),
      ...['sqlite', 'postgres', 'clamd', 'icap', 'http'].map((k) => `system.engines.${k}`),
      'system.source.environment',
      'system.source.admin',
    ];
    for (const key of keys) {
      expect(message(en, key), `en ${key}`).toBeTypeOf('string');
      expect(message(fr, key), `fr ${key}`).toBeTypeOf('string');
    }
  });
});
