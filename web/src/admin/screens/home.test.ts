import { describe, expect, it } from 'vitest';
import type { AdminMe } from '../auth/machine';
import {
  DASHBOARD_PERIOD,
  DISK_CARD_PERIOD,
  QUICK_SECTIONS,
  STATS_CONCURRENCY,
  cardFigures,
  cardHeadingLevel,
  dashboardKind,
  diskCard,
  initialCards,
  maintenanceLine,
  mapLimit,
  quickLinks,
  tenantRow,
  withError,
  withLoading,
  withStats,
  type Tenant,
  type TenantStats,
} from './home';

const t = (key: string, params?: Record<string, string | number>): string =>
  params === undefined ? key : `${key} ${JSON.stringify(params)}`;
const GiB = 2 ** 30;
const bytes = (n: number): string => `${n / GiB} GiB`;
const percent = (r: number): string => `${Math.round(r * 100)} %`;

function deferred<T>(): { promise: Promise<T>; resolve: (v: T) => void; reject: (e: unknown) => void } {
  let resolve!: (v: T) => void;
  let reject!: (e: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

const me: AdminMe = {
  id: 'adm_1',
  username: 'alice',
  email: 'alice@entity-a.example.com',
  role: 'delegated_admin',
  totpEnabled: true,
  tenants: [
    { id: 'ten_A', name: 'Entity A', fqdn: 'transfer.entity-a.example.com' },
    { id: 'ten_B', name: 'Entity B', fqdn: 'transfer.entity-b.example.com' },
  ],
  csrfToken: 'x',
};

const stats: TenantStats = {
  period: '30d',
  transferCount: 61,
  bytesUploaded: 3 * GiB,
  downloadCount: 0,
  bytesDownloaded: 0,
  virusDetections: 0,
  storageUsedBytes: 25 * GiB,
  storageQuotaBytes: 100 * GiB,
  storageUsedRatio: 0.25,
  series: [],
};

describe('mapLimit', () => {
  it('keeps the order of the items', async () => {
    const results = await mapLimit([30, 10, 20], 2, async (n) => {
      await new Promise((r) => setTimeout(r, n));
      return n * 2;
    });
    expect(results).toEqual([
      { status: 'fulfilled', value: 60 },
      { status: 'fulfilled', value: 20 },
      { status: 'fulfilled', value: 40 },
    ]);
  });

  it('never runs more than limit calls at once', async () => {
    const gates = Array.from({ length: 6 }, () => deferred<number>());
    let running = 0;
    let peak = 0;
    const started: number[] = [];
    const all = mapLimit([0, 1, 2, 3, 4, 5], 4, async (i) => {
      started.push(i);
      running++;
      peak = Math.max(peak, running);
      try {
        return await (gates[i] as { promise: Promise<number> }).promise;
      } finally {
        running--;
      }
    });
    await Promise.resolve();
    expect(started).toEqual([0, 1, 2, 3]);
    gates[1]?.resolve(1);
    await new Promise((r) => setTimeout(r, 0));
    expect(started).toEqual([0, 1, 2, 3, 4]);
    for (const [i, g] of gates.entries()) {
      g.resolve(i);
    }
    const results = await all;
    expect(peak).toBe(4);
    expect(results.map((r) => (r.status === 'fulfilled' ? r.value : -1))).toEqual([0, 1, 2, 3, 4, 5]);
  });

  it('isolates the failures', async () => {
    const results = await mapLimit(['a', 'b', 'c'], 1, async (s, index) => {
      if (s === 'b') {
        throw new Error('boom');
      }
      return `${s}${index}`;
    });
    expect(results[0]).toEqual({ status: 'fulfilled', value: 'a0' });
    expect(results[1]?.status).toBe('rejected');
    expect(results[2]).toEqual({ status: 'fulfilled', value: 'c2' });
  });

  it('handles no items and invalid limits', async () => {
    expect(await mapLimit([], 4, async () => 1)).toEqual([]);
    expect(await mapLimit([1, 2], 0, async (n) => n)).toHaveLength(2);
    expect(await mapLimit([1, 2], Number.NaN, async (n) => n)).toHaveLength(2);
  });

  it('uses 4 requests at most for 30-day statistics', () => {
    expect(STATS_CONCURRENCY).toBe(4);
    expect(DASHBOARD_PERIOD).toBe('30d');
  });
});

describe('dashboard kind', () => {
  it('depends on the role', () => {
    expect(dashboardKind(undefined)).toBe('none');
    expect(dashboardKind(me)).toBe('delegated');
    expect(dashboardKind({ ...me, role: 'super_admin', tenants: [] })).toBe('super');
  });
});

describe('delegated cards', () => {
  it('starts loading, then shows stats or an error per card', () => {
    const cards = initialCards(me.tenants);
    expect(cards).toEqual([
      { id: 'ten_A', name: 'Entity A', state: 'loading' },
      { id: 'ten_B', name: 'Entity B', state: 'loading' },
    ]);
    const ready = withStats(cards, 'ten_A', stats);
    expect(ready[0]).toEqual({ id: 'ten_A', name: 'Entity A', state: 'ready', stats });
    expect(ready[1]?.state).toBe('loading');
    const failed = withError(ready, 'ten_B', 'Not found');
    expect(failed[1]).toEqual({ id: 'ten_B', name: 'Entity B', state: 'error', message: 'Not found' });
    expect(failed[0]?.state).toBe('ready');
    expect(withLoading(failed, 'ten_B')[1]).toEqual({ id: 'ten_B', name: 'Entity B', state: 'loading' });
    expect(withLoading(failed, 'ten_B')[0]?.state).toBe('ready');
  });

  it('adapts the heading level to the number of tenants', () => {
    expect(cardHeadingLevel(0)).toBe(2);
    expect(cardHeadingLevel(1)).toBe(2);
    expect(cardHeadingLevel(2)).toBe(3);
  });

  it('builds the figures', () => {
    expect(cardFigures(stats, t, (n) => `#${n}`, bytes)).toEqual([
      { id: 'transfers', label: 'adminHome.card.transfers', value: '#61' },
      { id: 'volume', label: 'adminHome.card.volume', value: '3 GiB' },
    ]);
  });

  it('builds the quick links', () => {
    expect(QUICK_SECTIONS).toEqual(['transfers', 'audit', 'stats']);
    expect(quickLinks({ id: 'ten A', name: 'Entity A' }, t)).toEqual([
      {
        section: 'transfers',
        path: '/tenants/ten%20A/transfers',
        label: 'adminHome.links.transfers {"name":"Entity A"}',
      },
      {
        section: 'audit',
        path: '/tenants/ten%20A/audit',
        label: 'adminHome.links.audit {"name":"Entity A"}',
      },
      {
        section: 'stats',
        path: '/tenants/ten%20A/stats',
        label: 'adminHome.links.stats {"name":"Entity A"}',
      },
    ]);
  });
});

describe('super admin table', () => {
  const tenant: Tenant = {
    id: 'ten_A',
    name: 'Entity A',
    fqdn: 'transfer.entity-a.example.com',
    defaultLanguage: 'fr',
    maxTransferBytes: 10 * GiB,
    maxTransferCeiling: 20 * GiB,
    status: 'active',
    storageQuotaBytes: 100 * GiB,
    storageUsedBytes: 25 * GiB,
  } as Tenant;

  it('builds a row with an ok level', () => {
    const row = tenantRow(tenant, t, bytes, percent);
    expect(row).toEqual({
      id: 'ten_A',
      name: 'Entity A',
      fqdn: 'transfer.entity-a.example.com',
      path: '/tenants/ten_A/general',
      statusVariant: 'ok',
      statusKey: 'adminTenants.status.active',
      usage: 'adminComponents.quota.usage {"used":"25 GiB","quota":"100 GiB","percent":"25 %"}',
      level: 'ok',
      levelVariant: 'ok',
      levelLabel: 'adminComponents.quota.level.ok',
    });
  });

  it('flags nearly full and full quotas, and tenants being deleted', () => {
    const warning = tenantRow({ ...tenant, storageUsedBytes: 85 * GiB }, t, bytes, percent);
    expect(warning.level).toBe('warning');
    expect(warning.levelVariant).toBe('warning');
    const full = tenantRow({ ...tenant, storageUsedBytes: 120 * GiB, status: 'deleting' }, t, bytes, percent);
    expect(full.level).toBe('full');
    expect(full.levelVariant).toBe('error');
    expect(full.statusVariant).toBe('warning');
    expect(full.statusKey).toBe('adminTenants.status.deleting');
  });
});

describe('super admin disk card', () => {
  const disk = {
    totalBytes: 1000 * GiB,
    usedBytes: 900 * GiB,
    usedRatio: 0.9,
    alertThreshold: 0.85,
    alertActive: true,
    alertMailConfigured: false,
  };

  it('uses 30 days and maps the disk part of the global statistics', () => {
    expect(DISK_CARD_PERIOD).toBe('30d');
    const card = diskCard({ disk }, t, percent);
    expect(card.state).toBe('ready');
    if (card.state !== 'ready') {
      return;
    }
    expect(card.disk).toMatchObject({
      used: 900 * GiB,
      total: 1000 * GiB,
      thresholdLabel: 'sysStats.disk.threshold {"percent":"85 %"}',
      alertVariant: 'error',
      alertLabel: 'sysStats.disk.alertActive',
      mailWarning: true,
    });
  });
});

describe('maintenanceLine', () => {
  const date = (iso: string): string => `D(${iso})`;

  it('is unknown before the first read', () => {
    expect(maintenanceLine(undefined, t, date)).toEqual({
      known: false,
      failed: false,
      variant: 'ok',
      label: 'sysStats.home.maintenanceOff',
      text: '',
      linkPath: '/system/maintenance',
    });
  });

  it('is unknown when the read failed, until a state is known', () => {
    expect(maintenanceLine(undefined, t, date, true)).toMatchObject({ known: false, failed: true });
    const off = { enabled: false, source: 'none', adminEnabled: false } as const;
    expect(maintenanceLine(off, t, date, true)).toMatchObject({ known: true, failed: false });
  });

  it('shows the off state', () => {
    const line = maintenanceLine({ enabled: false, source: 'none', adminEnabled: false }, t, date);
    expect(line).toMatchObject({
      known: true,
      variant: 'ok',
      label: 'sysStats.home.maintenanceOff',
      text: '',
    });
  });

  it('shows the on state with its start date and source', () => {
    const line = maintenanceLine(
      { enabled: true, source: 'environment', since: '2026-10-24T08:00:00Z', adminEnabled: false },
      t,
      date,
    );
    expect(line.known).toBe(true);
    expect(line.variant).toBe('warning');
    expect(line.label).toBe('sysStats.home.maintenanceOn');
    expect(line.text).toBe(
      'adminSystem.banner.textSince {"date":"D(2026-10-24T08:00:00Z)"} adminSystem.banner.environment',
    );
  });
});
