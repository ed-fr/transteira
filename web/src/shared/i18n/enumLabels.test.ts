// Labels of the values of the API enumerations, translated with keys built at runtime
// (t(`opsSecurity.types.${type}`) and the like). locales.test.ts only scans literal keys, so a
// value added to the specification without its label showed the raw key (2.3: express_refused).
// For every value known to this version, each label helper (or the key a component builds) must
// ask for a key, and that key must exist in every language.
import { describe, expect, it } from 'vitest';
import { roleKey } from '../../admin/shell';
import { CREATABLE_ROLES } from '../../admin/screens/admins/admins';
import {
  categoryLabel as abuseCategoryLabel,
  reportStatusView,
  reporterText,
  statusFilterOptions,
} from '../../admin/screens/ops/abuseReports';
import {
  AUDIT_OBJECT_KINDS,
  actionLabel,
  actorKindLabel,
  auditActionGroups,
  objectKindLabel,
} from '../../admin/screens/ops/auditLabels';
import { creatorKindLabel, deliveryText, secretStateView } from '../../admin/screens/ops/secrets';
import { typeLabel } from '../../admin/screens/ops/securityLog';
import { periodOptions } from '../../admin/screens/ops/stats';
import { originLabel, scanView, statusView } from '../../admin/screens/ops/transfers';
import {
  categoryLabel as webhookCategoryLabel,
  eventLabel,
  kindLabel,
} from '../../admin/screens/ops/webhooks';
import { antivirusLabel, databaseEngineName } from '../../admin/screens/systemStatus';
import { categoryOptions } from '../../public/screens/abuseReport';
import {
  abuseReportCategoryValues,
  abuseReportStatusValues,
  adminRoleValues,
  adminSecretCreatorKindValues,
  antivirusEngineValues,
  auditActionValues,
  auditEventActorKindValues,
  contrastResultLevelValues,
  contrastResultPairValues,
  e2ePolicyValues,
  expressSecretDurationValues,
  globalStatsPeriodValues,
  legalDocumentDocumentValues,
  maintenanceSourceValues,
  scanStatusValues,
  secretDeliveryValues,
  secretDurationValues,
  secretStateValues,
  securityEventTypeValues,
  systemStatusDatabaseEngineValues,
  tenantStatsPeriodValues,
  transferOriginValues,
  transferStatusValues,
  webhookErrorCategoryValues,
  webhookEventTypeValues,
  webhookKindValues,
} from '../api/schema';
import { lookup, type Messages, type Translate } from './messages';

const bundles = import.meta.glob<Messages>('../../locales/*/*.json', { eager: true, import: 'default' });

/** Message trees by language: { <area>: <content of area.json> }. */
function byLanguage(): Map<string, Messages> {
  const out = new Map<string, Messages>();
  for (const [path, content] of Object.entries(bundles)) {
    const match = /\/locales\/([^/]+)\/([^/]+)\.json$/.exec(path);
    if (match === null) continue;
    const [, lang, area] = match as unknown as [string, string, string];
    const tree = out.get(lang) ?? {};
    tree[area] = content;
    out.set(lang, tree);
  }
  return out;
}

const languages = byLanguage();

/** Reports whether a key resolves like the i18n module: a message, or a plural group. */
function resolves(messages: Messages, key: string): boolean {
  const node = lookup(messages, key);
  return typeof node === 'string' || (typeof node === 'object' && typeof node['other'] === 'string');
}

/** A translation that records the keys it is asked for. */
function recorder(): { t: Translate; keys: string[] } {
  const keys: string[] = [];
  return {
    keys,
    t: (key) => {
      keys.push(key);
      return key;
    },
  };
}

/** A label site: the values it translates, and how it builds the label of one value. */
interface Site {
  name: string;
  values: readonly string[];
  label: (value: string, t: Translate) => unknown;
}

const without = (values: readonly string[], ...left: string[]): string[] =>
  values.filter((v) => !left.includes(v));

const sites: Site[] = [
  // Admin logs.
  { name: 'security event types', values: securityEventTypeValues, label: typeLabel },
  { name: 'audit actions', values: auditActionValues, label: actionLabel },
  { name: 'audit actor kinds', values: auditEventActorKindValues, label: actorKindLabel },
  { name: 'audit object kinds', values: AUDIT_OBJECT_KINDS, label: objectKindLabel },
  { name: 'audit action groups', values: ['all'], label: (_v, t) => auditActionGroups(t) },
  // Secrets (2.1, express since 2.3).
  { name: 'secret creator kinds', values: adminSecretCreatorKindValues, label: creatorKindLabel },
  { name: 'secret states', values: secretStateValues, label: secretStateView },
  {
    name: 'secret deliveries',
    values: secretDeliveryValues,
    label: (v, t) => deliveryText({ delivery: v as 'link' | 'email' }, t),
  },
  {
    name: 'secret durations (settings)',
    values: secretDurationValues,
    label: (v, t) => t(`adminSecrets.duration.${v}`),
  },
  {
    name: 'secret durations (creation)',
    values: [...new Set([...secretDurationValues, ...expressSecretDurationValues])],
    label: (v, t) => t(`secretCreate.duration.${v}`),
  },
  // Transfers.
  { name: 'transfer statuses', values: transferStatusValues, label: statusView },
  { name: 'scan statuses', values: scanStatusValues, label: scanView },
  { name: 'transfer origins', values: transferOriginValues, label: originLabel },
  // Abuse reports.
  { name: 'abuse categories (admin)', values: abuseReportCategoryValues, label: abuseCategoryLabel },
  { name: 'abuse categories (public)', values: ['all'], label: (_v, t) => categoryOptions(t) },
  { name: 'abuse report statuses', values: abuseReportStatusValues, label: reportStatusView },
  { name: 'abuse status filter', values: ['all'], label: (_v, t) => statusFilterOptions(t) },
  {
    name: 'abuse reporter of a secret report',
    values: ['secret'],
    label: (_v, t) =>
      reporterText(
        {
          id: 'abr_1',
          category: 'spam',
          status: 'open',
          reportedAt: '2026-11-19T08:00:00Z',
          reporterVerified: false,
          secretId: 'sec_1',
        },
        t,
      ),
  },
  // Webhooks.
  { name: 'webhook events', values: webhookEventTypeValues, label: eventLabel },
  { name: 'webhook kinds', values: webhookKindValues, label: kindLabel },
  {
    name: 'webhook kind hints',
    values: webhookKindValues,
    label: (v, t) => t(`opsWebhooks.form.kind.hints.${v}`),
  },
  { name: 'webhook error categories', values: webhookErrorCategoryValues, label: webhookCategoryLabel },
  // Accounts, statistics, system.
  { name: 'admin roles', values: adminRoleValues, label: (v, t) => t(roleKey(v)) },
  {
    name: 'creatable role hints',
    values: CREATABLE_ROLES,
    label: (v, t) => t(`adminAccounts.form.role.${v}Hint`),
  },
  {
    name: 'statistics periods',
    values: [...new Set([...tenantStatsPeriodValues, ...globalStatsPeriodValues])],
    label: (v, t) => periodOptions(t).find((o) => o.value === v) ?? t(`opsStats.periods.${v}`),
  },
  {
    name: 'maintenance sources',
    values: without(maintenanceSourceValues, 'none'),
    label: (v, t) => t(`adminHome.system.source.${v}`),
  },
  { name: 'database engines', values: systemStatusDatabaseEngineValues, label: databaseEngineName },
  { name: 'antivirus engines', values: without(antivirusEngineValues, 'none'), label: antivirusLabel },
  // Tenant configuration.
  {
    name: 'legal documents',
    values: legalDocumentDocumentValues,
    label: (v, t) => t(`adminTenants.legal.document.${v}`),
  },
  {
    name: 'contrast pairs',
    values: contrastResultPairValues,
    label: (v, t) => t(`adminTenants.branding.contrast.pair.${v}`),
  },
  {
    name: 'contrast levels',
    values: contrastResultLevelValues,
    label: (v, t) => t(`adminTenants.branding.contrast.level.${v}`),
  },
  { name: 'end-to-end policies', values: e2ePolicyValues, label: (v, t) => t(`adminTenants.e2ePolicy.${v}`) },
];

describe('labels of the enumeration values', () => {
  it('cover a value of every site', () => {
    expect(languages.size).toBeGreaterThanOrEqual(2);
    for (const site of sites) {
      expect(site.values.length, site.name).toBeGreaterThan(0);
    }
    expect(securityEventTypeValues).toContain('express_refused');
    expect(adminSecretCreatorKindValues).toContain('anonymous');
  });

  it.each(sites.map((s) => [s.name, s] as const))('translate every value: %s', (_name, site) => {
    const problems: string[] = [];
    for (const value of site.values) {
      const { t, keys } = recorder();
      site.label(value, t);
      if (keys.length === 0) {
        problems.push(`${value}: shown raw, no translation asked`);
      }
      for (const key of keys) {
        for (const [lang, messages] of languages) {
          if (!resolves(messages, key)) {
            problems.push(`${lang}: missing ${key} (value ${value})`);
          }
        }
      }
    }
    expect(problems).toEqual([]);
  });

  it('notices a missing label', () => {
    const messages = languages.get('en') as Messages;
    expect(resolves(messages, 'opsSecurity.types.express_refused')).toBe(true);
    expect(resolves(messages, 'opsSecurity.types.not_a_type')).toBe(false);
    expect(resolves(messages, 'opsSecurity.types')).toBe(false);
    expect(resolves(messages, 'adminSecrets.express.purge.done')).toBe(true);
  });
});
