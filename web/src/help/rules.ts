// Real rules of the current tenant shown in the public guides (CLAUDE.md section 4.2, rules
// blocks rendered by HelpRules.svelte), kept out of the component so that it is unit tested in
// Node. Every value of the tenant (name, level labels and descriptions) is returned as plain
// text, to be rendered as Svelte text nodes: never HTML, never Markdown (threat model T-232).
// The rules come from GET /tenant, resolved by the server from the Host of the request (T-235),
// and only hold what helps a depositor (T-233: the recipient domain restriction is an on/off).
import type { components } from '../shared/api/schema';
import type { TranslateParams } from '../shared/i18n/i18n.svelte';
import type { HelpFeature } from './types';

type PublicTenant = components['schemas']['PublicTenant'];

/** Rules of the tenant used by the help: the subset of GET /tenant the rules blocks read. */
export type HelpTenantRules = Pick<PublicTenant, 'name' | 'limits' | 'features' | 'confidentialityLevels'>;

/** A confidentiality level as offered to the senders. */
export type HelpLevel = components['schemas']['PublicConfidentialityLevel'];

/** Formatting functions of the current language (i18n.svelte.ts in the application). */
export interface RulesFormat {
  t: (key: string, params?: TranslateParams) => string;
  /** Byte count with binary multiples ("20 GB", "20 Go"). */
  bytes: (n: number) => string;
  /** Conjunction of items ("1 day, 7 days and 30 days"). */
  list: (items: readonly string[]) => string;
}

/** Options listed by the summary, in display order (the antivirus comes last). */
const SUMMARY_FEATURES: readonly HelpFeature[] = [
  'remoteInternalDeposit',
  'transferReply',
  'recipientVerification',
  'maxDownloads',
  'folders',
];

/** Durations as worded by the deposit form ("1 day", "7 days"), joined. */
export function durationsText(days: readonly number[], fmt: RulesFormat): string {
  return fmt.list(days.map((count) => fmt.t('deposit.form.expiry.days', { count })));
}

/** Maximum size per transfer and available durations, one sentence each. */
export function limitItems(rules: Pick<HelpTenantRules, 'limits'>, fmt: RulesFormat): string[] {
  return [
    fmt.t('help.rules.maxSize', { size: fmt.bytes(rules.limits.maxTransferBytes) }),
    fmt.t('help.rules.durations', { durations: durationsText(rules.limits.expiryDays, fmt) }),
  ];
}

/**
 * Overview of the rules: size and durations, then the options that are on or off for the tenant
 * (absent with a server that does not send them).
 */
export function summaryItems(rules: HelpTenantRules, fmt: RulesFormat): string[] {
  const items = limitItems(rules, fmt);
  const features = rules.features;
  if (features === undefined) {
    return items;
  }
  for (const feature of SUMMARY_FEATURES) {
    items.push(fmt.t(`help.rules.features.${feature}.${features[feature] ? 'on' : 'off'}`));
  }
  items.push(
    fmt.t(`help.rules.features.recipientRestrictions.${features.recipientRestrictions ? 'on' : 'off'}`),
  );
  items.push(fmt.t(`help.rules.features.antivirus.${features.antivirus === 'disabled' ? 'off' : 'on'}`));
  return items;
}

/** Reports whether a set of durations allows something the tenant durations do not, or less. */
function restrictsDurations(allowed: readonly number[], tenant: readonly number[]): boolean {
  return tenant.some((d) => !allowed.includes(d)) || allowed.some((d) => !tenant.includes(d));
}

/** Rules a level imposes, in words; empty when it imposes nothing beyond the tenant rules. */
export function levelRuleItems(level: HelpLevel, tenantDays: readonly number[], fmt: RulesFormat): string[] {
  const { rules } = level;
  const items: string[] = [];
  if (restrictsDurations(rules.allowedExpiryDays, tenantDays)) {
    items.push(
      fmt.t('help.rules.levels.durations', { durations: durationsText(rules.allowedExpiryDays, fmt) }),
    );
  }
  if (rules.requirePassword) items.push(fmt.t('help.rules.levels.password'));
  if (rules.requireRecipientVerification) items.push(fmt.t('help.rules.levels.recipientVerification'));
  if (rules.internalRecipientsOnly) items.push(fmt.t('help.rules.levels.internalRecipients'));
  if (rules.forceDeleteAfterFirstDownload) items.push(fmt.t('help.rules.levels.deleteAfterFirst'));
  if (rules.maxDownloads !== null) {
    items.push(fmt.t('help.rules.levels.maxDownloads', { count: rules.maxDownloads }));
  }
  return items;
}

/** A confidentiality level as shown by the help. */
export interface LevelView {
  key: string;
  /** Label written by the admins (plain text). */
  label: string;
  /** Description written by the admins (plain text), if any. */
  description: string | undefined;
  isDefault: boolean;
  /** Rules of the level in words; empty when it imposes nothing. */
  rules: string[];
}

/**
 * Confidentiality levels of the tenant, in display order; empty (nothing shown) without levels,
 * or with a single level that imposes nothing: the sender then never chooses a level.
 */
export function levelViews(rules: HelpTenantRules, fmt: RulesFormat): LevelView[] {
  const levels = rules.confidentialityLevels ?? [];
  const views = levels.map((level) => ({
    key: level.key,
    label: level.label,
    description: level.description?.trim() === '' ? undefined : level.description,
    isDefault: level.isDefault,
    rules: levelRuleItems(level, rules.limits.expiryDays, fmt),
  }));
  if (views.length === 1 && views[0]?.rules.length === 0) {
    return [];
  }
  return views;
}
