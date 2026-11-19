import { describe, expect, it } from 'vitest';
import en from '../../locales/en/adminHome.json';
import fr from '../../locales/fr/adminHome.json';
import type { AdminMe } from '../auth/machine';
import {
  AUDITOR_QUICK_SECTIONS,
  DASHBOARD_PERIOD,
  HOME_TENANT_ROWS,
  QUICK_SECTIONS,
  STATS_CONCURRENCY,
  TREND_DAYS,
  createLoadGenerations,
  dashboardKind,
  diskTile,
  figureTiles,
  globalFigures,
  greeting,
  homeTenantRows,
  initialCards,
  mapLimit,
  quickLinks,
  rowAction,
  storageTile,
  tenantFigures,
  tenantRow,
  tenantTilesState,
  withError,
  withLoading,
  withStats,
  type HomeFormatters,
  type Tenant,
  type TenantStats,
} from './home';
import type { GlobalStats } from './system/overview';

const t = (key: string, params?: Record<string, string | number>): string =>
  params === undefined ? key : `${key} ${JSON.stringify(params)}`;
const GiB = 2 ** 30;
const bytes = (n: number): string => `${n / GiB} GiB`;
const percent = (r: number): string => `${Math.round(r * 1000) / 10} %`;
const fmt: HomeFormatters = {
  number: (n) => `#${n}`,
  bytes,
  percent,
  trendPercent: (r) => `${Math.round(r * 100)} %`,
};

/** A message of a bundle by its dotted key (a plural group resolves through "other"). */
function message(bundle: unknown, key: string): string | undefined {
  let node: unknown = bundle;
  for (const part of key.split('.')) {
    node = typeof node === 'object' && node !== null ? (node as Record<string, unknown>)[part] : undefined;
  }
  if (typeof node === 'object' && node !== null) {
    node = (node as Record<string, unknown>)['other'];
  }
  return typeof node === 'string' ? node : undefined;
}

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
  virusDetections: 2,
  storageUsedBytes: 25 * GiB,
  storageQuotaBytes: 100 * GiB,
  storageUsedRatio: 0.25,
  series: [],
  previous: {
    transferCount: 50,
    bytesUploaded: 3 * GiB,
    downloadCount: 0,
    bytesDownloaded: 0,
    virusDetections: 0,
    secretsCreated: 0,
  },
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
    expect(TREND_DAYS).toBe(30);
  });
});

describe('dashboard kind', () => {
  it('depends on the role', () => {
    expect(dashboardKind(undefined)).toBe('none');
    expect(dashboardKind(me)).toBe('delegated');
    expect(dashboardKind({ ...me, role: 'super_admin', tenants: [] })).toBe('super');
    expect(dashboardKind({ ...me, role: 'auditor' })).toBe('auditor');
  });
});

describe('greeting', () => {
  const one = { ...me, tenants: me.tenants.slice(0, 1) };

  it('greets the super admin with the overview of the instance and its entity count', () => {
    // The tenants of the profile: every tenant of the instance for a super admin.
    expect(greeting(me, 'super', t)).toBe('adminHome.greeting.superCount {"username":"alice","count":2}');
    expect(greeting(one, 'super', t)).toBe('adminHome.greeting.superCount {"username":"alice","count":1}');
    expect(greeting({ ...me, tenants: [] }, 'super', t)).toBe(
      'adminHome.greeting.superCount {"username":"alice","count":0}',
    );
  });

  it('names the only entity of a delegated admin or an auditor, or counts them', () => {
    expect(greeting(one, 'delegated', t)).toBe(
      'adminHome.greeting.delegatedOne {"username":"alice","name":"Entity A"}',
    );
    expect(greeting(me, 'delegated', t)).toBe(
      'adminHome.greeting.delegatedMany {"username":"alice","count":2}',
    );
    expect(greeting(one, 'auditor', t)).toBe(
      'adminHome.greeting.auditorOne {"username":"alice","name":"Entity A"}',
    );
    expect(greeting(me, 'auditor', t)).toBe('adminHome.greeting.auditorMany {"username":"alice","count":2}');
  });

  it('greets alone without entity', () => {
    expect(greeting({ ...me, tenants: [] }, 'delegated', t)).toBe(
      'adminHome.greeting.plain {"username":"alice"}',
    );
    expect(greeting(me, 'none', t)).toBe('adminHome.greeting.plain {"username":"alice"}');
  });
});

describe('generations of the loads', () => {
  it('ignores the answers of a previous generation', () => {
    const loads = createLoadGenerations();
    expect(loads.current()).toBe(0);
    const first = loads.next();
    expect(loads.isCurrent(first)).toBe(true);
    const second = loads.next();
    expect(second).toBe(first + 1);
    expect(loads.current()).toBe(second);
    expect(loads.isCurrent(first)).toBe(false);
    expect(loads.isCurrent(second)).toBe(true);
  });

  it('ignores every answer once stopped', () => {
    const loads = createLoadGenerations();
    const gen = loads.next();
    loads.stop();
    expect(loads.isCurrent(gen)).toBe(false);
    expect(loads.isCurrent(loads.next())).toBe(false);
  });
});

describe('statistics of the tenants of an admin', () => {
  it('start loading, then hold stats or an error per tenant', () => {
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

  it('give the tiles once every tenant is loaded, one error for any failure', () => {
    const cards = initialCards(me.tenants);
    expect(tenantTilesState(cards)).toEqual({ state: 'loading' });
    const half = withStats(cards, 'ten_A', stats);
    expect(tenantTilesState(half)).toEqual({ state: 'loading' });
    expect(tenantTilesState(withStats(half, 'ten_B', stats))).toEqual({
      state: 'ready',
      stats: [stats, stats],
    });
    expect(tenantTilesState(withError(half, 'ten_B', 'Boom'))).toEqual({
      state: 'error',
      failed: ['ten_B'],
      names: 'Entity B',
      message: 'Boom',
    });
    const both = withError(withError(cards, 'ten_A', 'First'), 'ten_B', 'Second');
    expect(tenantTilesState(both)).toEqual({
      state: 'error',
      failed: ['ten_A', 'ten_B'],
      names: 'Entity A, Entity B',
      message: 'First',
    });
    expect(tenantTilesState([])).toEqual({ state: 'ready', stats: [] });
  });
});

describe('key figures', () => {
  const row = (over: Partial<GlobalStats['tenants'][number]>): GlobalStats['tenants'][number] => ({
    tenantId: 'ten_A',
    name: 'Entity A',
    transferCount: 0,
    bytesUploaded: 0,
    storageUsedBytes: 0,
    storageQuotaBytes: 0,
    storageUsedRatio: 0,
    ...over,
  });

  it('sum the rows of the global statistics and their previous period', () => {
    const previous = {
      transferCount: 80,
      bytesUploaded: GiB,
      downloadCount: 0,
      bytesDownloaded: 0,
      virusDetections: 0,
      secretsCreated: 0,
    };
    const figures = globalFigures({
      tenants: [
        row({ transferCount: 100, bytesUploaded: 2 * GiB, virusDetections: 1, previous }),
        // A row without virus count (older server), and invalid counters counted as 0.
        row({ transferCount: 28, bytesUploaded: GiB, previous: { ...previous, transferCount: 20 } }),
        row({ transferCount: -5, bytesUploaded: Number.NaN, previous }),
      ],
    });
    expect(figures).toEqual({
      current: { transferCount: 128, bytesUploaded: 3 * GiB, virusDetections: 1 },
      previous: { transferCount: 180, bytesUploaded: 3 * GiB, virusDetections: 0 },
    });
  });

  it('have no previous period unless every row carries one', () => {
    const previous = { ...stats.previous! };
    // A partial previous sum is never compared with a full current one.
    expect(
      globalFigures({ tenants: [row({ transferCount: 3, previous }), row({ transferCount: 1 })] }).previous,
    ).toBeUndefined();
    expect(globalFigures({ tenants: [row({ transferCount: 3 })] }).previous).toBeUndefined();
    expect(globalFigures({ tenants: [] })).toEqual({
      current: { transferCount: 0, bytesUploaded: 0, virusDetections: 0 },
      previous: undefined,
    });
  });

  it('sum the statistics of the tenants of an admin', () => {
    expect(tenantFigures([stats, stats])).toEqual({
      current: { transferCount: 122, bytesUploaded: 6 * GiB, virusDetections: 4 },
      previous: { transferCount: 100, bytesUploaded: 6 * GiB, virusDetections: 0 },
    });
    expect(tenantFigures([stats, { ...stats, previous: undefined }]).previous).toBeUndefined();
  });

  it('build the three tiles with neutral trends', () => {
    const tiles = figureTiles(tenantFigures([stats]), t, fmt);
    expect(tiles).toEqual([
      {
        id: 'transfers',
        label: 'adminHome.tiles.transfers',
        value: '#61',
        trend: 'adminComponents.trend.up {"percent":"22 %","days":30}',
      },
      {
        id: 'volume',
        label: 'adminHome.tiles.volume',
        value: '3 GiB',
        trend: 'adminComponents.trend.flat {"days":30}',
      },
      {
        id: 'viruses',
        label: 'adminHome.tiles.viruses',
        value: '#2',
        trend: 'adminComponents.trend.new {"days":30}',
      },
    ]);
    const without = figureTiles(
      { current: { transferCount: 1, bytesUploaded: 0, virusDetections: 0 }, previous: undefined },
      t,
      fmt,
    );
    expect(without.map((tile) => tile.trend)).toEqual([undefined, undefined, undefined]);
  });
});

describe('disk tile of the super admin', () => {
  const disk = {
    totalBytes: 1000 * GiB,
    usedBytes: 470 * GiB,
    usedRatio: 0.47,
    alertThreshold: 0.85,
    alertActive: false,
    alertMailConfigured: true,
  };

  it('shows the usage, the threshold marker and the free space', () => {
    expect(diskTile(disk, t, fmt)).toEqual({
      label: 'adminHome.tiles.disk',
      value: '47 %',
      gauge: {
        value: 470 * GiB,
        max: 1000 * GiB,
        threshold: 850 * GiB,
        level: 'default',
        valueText: 'adminHome.tiles.diskValueText {"percent":"47 %","used":"470 GiB","total":"1000 GiB"}',
        label: 'sysStats.disk.label',
      },
      text: 'adminHome.tiles.diskText {"threshold":"85 %","free":"530 GiB"}',
      variant: 'default',
      hint: undefined,
    });
  });

  it('is in the danger variant while the alert is raised, and says when it is not mailed', () => {
    const raised = diskTile(
      { ...disk, usedBytes: 900 * GiB, alertActive: true, alertMailConfigured: false },
      t,
      fmt,
    );
    expect(raised.variant).toBe('danger');
    expect(raised.gauge?.level).toBe('warning');
    expect(raised.hint).toBe('adminHome.tiles.diskAlertActive adminHome.tiles.diskMailOff');
    // The alert stays raised until the usage falls 5 points below the threshold.
    const clearing = diskTile({ ...disk, usedBytes: 820 * GiB, alertActive: true }, t, fmt);
    expect(clearing.gauge?.level).toBe('warning');
    expect(clearing.hint).toBe('adminHome.tiles.diskAlertActive');
    expect(diskTile({ ...disk, usedBytes: 1000 * GiB }, t, fmt).gauge?.level).toBe('danger');
  });

  it('copes with an invalid threshold and an empty disk', () => {
    const noThreshold = diskTile({ ...disk, alertThreshold: 1.5 }, t, fmt);
    expect(noThreshold.gauge?.threshold).toBeUndefined();
    expect(noThreshold.text).toBe('adminHome.tiles.diskFree {"free":"530 GiB"}');
    const empty = diskTile({ ...disk, totalBytes: 0, usedBytes: 0 }, t, fmt);
    expect(empty.gauge).toBeUndefined();
    expect(empty.value).toBe('0 %');
    // A used size above the total is clamped.
    expect(diskTile({ ...disk, usedBytes: 2000 * GiB }, t, fmt).value).toBe('100 %');
  });
});

describe('storage tile of the other roles', () => {
  it('sums the storage of the tenants against their quotas, marker at 80 %', () => {
    const tile = storageTile([stats, { ...stats, storageUsedBytes: 5 * GiB }], t, fmt);
    expect(tile).toEqual({
      label: 'adminHome.tiles.storage',
      value: '15 %',
      gauge: {
        value: 30 * GiB,
        max: 200 * GiB,
        threshold: 160 * GiB,
        level: 'default',
        valueText: 'adminComponents.quota.usage {"used":"30 GiB","quota":"200 GiB","percent":"15 %"}',
        label: 'adminHome.tiles.storage',
      },
      text: 'adminHome.tiles.storageText {"used":"30 GiB","quota":"200 GiB","threshold":"80 %"}',
      variant: 'default',
      hint: undefined,
    });
  });

  it('warns from 80 % and is full from 100 %', () => {
    const warning = storageTile([{ storageUsedBytes: 85 * GiB, storageQuotaBytes: 100 * GiB }], t, fmt);
    expect(warning.variant).toBe('warning');
    expect(warning.gauge?.level).toBe('warning');
    expect(warning.hint).toBe('adminComponents.quota.level.warning');
    const full = storageTile([{ storageUsedBytes: 120 * GiB, storageQuotaBytes: 100 * GiB }], t, fmt);
    expect(full.variant).toBe('danger');
    expect(full.gauge).toMatchObject({ value: 100 * GiB, max: 100 * GiB, level: 'danger' });
    expect(full.hint).toBe('adminComponents.quota.level.full');
  });

  it('shows the bytes used alone without quota', () => {
    expect(storageTile([{ storageUsedBytes: 2 * GiB, storageQuotaBytes: 0 }], t, fmt)).toEqual({
      label: 'adminHome.tiles.storage',
      value: '2 GiB',
      gauge: undefined,
      text: 'adminComponents.quota.noQuota {"used":"2 GiB"}',
      variant: 'default',
      hint: undefined,
    });
  });
});

describe('quick links', () => {
  it('lead a delegated admin to the transfers, audit log and statistics', () => {
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

  it('only lead an auditor to the consultation sections, the security log included', () => {
    expect(AUDITOR_QUICK_SECTIONS).toEqual(['transfers', 'audit', 'security', 'stats']);
    const links = quickLinks({ id: 'ten_A', name: 'Entity A' }, t, 'auditor');
    expect(links.map((l) => l.path)).toEqual([
      '/tenants/ten_A/transfers',
      '/tenants/ten_A/audit',
      '/tenants/ten_A/security-events',
      '/tenants/ten_A/stats',
    ]);
    expect(links[2]?.label).toBe('adminHome.links.security {"name":"Entity A"}');
  });
});

describe('entity table', () => {
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
    primaryColor: '#1D4ED8',
  } as Tenant;

  it('builds a row with an ok level and the colour of the tenant', () => {
    const row = tenantRow(tenant, t, bytes, percent);
    expect(row).toEqual({
      id: 'ten_A',
      name: 'Entity A',
      fqdn: 'transfer.entity-a.example.com',
      color: '#1D4ED8',
      path: '/tenants/ten_A/general',
      statusVariant: 'ok',
      statusKey: 'adminTenants.status.active',
      used: 25 * GiB,
      quota: 100 * GiB,
      usage: 'adminComponents.quota.usage {"used":"25 GiB","quota":"100 GiB","percent":"25 %"}',
      level: 'ok',
      levelVariant: 'ok',
      levelLabel: 'adminComponents.quota.level.ok',
    });
  });

  it('flags nearly full and full quotas, and tenants being set up or deleted', () => {
    const warning = tenantRow({ ...tenant, storageUsedBytes: 85 * GiB }, t, bytes, percent);
    expect(warning.level).toBe('warning');
    expect(warning.levelVariant).toBe('warning');
    const full = tenantRow({ ...tenant, storageUsedBytes: 120 * GiB, status: 'deleting' }, t, bytes, percent);
    expect(full.level).toBe('full');
    expect(full.levelVariant).toBe('error');
    expect(full.statusVariant).toBe('warning');
    expect(full.statusKey).toBe('adminTenants.status.deleting');
    const setup = tenantRow({ ...tenant, setupState: 'setup' } as Tenant, t, bytes, percent);
    expect(setup.statusKey).toBe('adminTenants.status.setup');
    const plain = { ...tenant, primaryColor: undefined } as unknown as Tenant;
    expect(tenantRow(plain, t, bytes, percent).color).toBeUndefined();
  });

  it('keeps the first 10 tenants', () => {
    expect(HOME_TENANT_ROWS).toBe(10);
    const many = Array.from({ length: 12 }, (_, i) => ({ ...tenant, id: `ten_${i}`, name: `E${i}` }));
    const rows = homeTenantRows(many, t, bytes, percent);
    expect(rows.map((r) => r.id)).toEqual(many.slice(0, 10).map((x) => x.id));
    expect(homeTenantRows([], t, bytes, percent)).toEqual([]);
  });

  it('names the action of a row after the tenant: configure, or open for an auditor', () => {
    expect(rowAction({ name: 'Entity A' }, 'super', t)).toEqual({
      text: 'adminHome.table.configure',
      name: 'adminHome.table.configureName {"name":"Entity A"}',
    });
    expect(rowAction({ name: 'Entity A' }, 'delegated', t).text).toBe('adminHome.table.configure');
    expect(rowAction({ name: 'Entity A' }, 'auditor', t)).toEqual({
      text: 'adminHome.table.open',
      name: 'adminHome.table.openName {"name":"Entity A"}',
    });
  });
});

describe('translations of the keys built at runtime', () => {
  it('exist in English and in French', () => {
    const keys = [
      ...['superCount', 'delegatedOne', 'delegatedMany', 'auditorOne', 'auditorMany'].map(
        (k) => `greeting.${k}`,
      ),
      ...['transfers', 'audit', 'stats', 'security'].map((k) => `links.${k}`),
    ];
    for (const key of keys) {
      expect(message(en, key), `en ${key}`).toBeTypeOf('string');
      expect(message(fr, key), `fr ${key}`).toBeTypeOf('string');
    }
  });
});

describe('accessible names of the links with a hidden name', () => {
  // The accessible name starts with the visible text (WCAG 2.5.3, RGAA 6.1): a voice control user
  // saying the visible label reaches the link.
  it('start with the visible label in English and in French', () => {
    const pairs = [
      ['seeAll', 'seeAllName'],
      ['table.configure', 'table.configureName'],
      ['table.open', 'table.openName'],
    ] as const;
    for (const bundle of [en, fr]) {
      for (const [visible, name] of pairs) {
        const text = message(bundle, visible);
        expect(text, visible).toBeTypeOf('string');
        expect(message(bundle, name)?.startsWith(text ?? '\0'), name).toBe(true);
      }
    }
  });
});
