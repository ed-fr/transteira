// Logic of QuotaMeter, kept out of the component so that it is unit tested in Node. The level
// of a storage quota is always written out (badge and text), never conveyed by colour alone.
import type { Translate } from '../../shared/i18n/messages';

/** Translation function (the t of the i18n module). */
export type { Translate };

/** Alert threshold of a quota (CLAUDE.md section 8.5: preventive alert at 80 %). */
export const QUOTA_WARNING_RATIO = 0.8;

/** Level of a quota: ok, warning from 80 %, full from 100 %. */
export type QuotaLevel = 'ok' | 'warning' | 'full';

/**
 * Fill ratio of a quota (used / quota, not capped so that an overrun shows). A quota of 0 (or
 * not finite) yields 0 when nothing is used and 1 (full) otherwise; negative values count as 0.
 */
export function quotaRatio(used: number, quota: number): number {
  const u = Number.isFinite(used) && used > 0 ? used : 0;
  if (!Number.isFinite(quota) || quota <= 0) {
    return u > 0 ? 1 : 0;
  }
  return u / quota;
}

/** Level of a fill ratio: full from 1, warning from QUOTA_WARNING_RATIO, ok below. */
export function quotaLevel(ratio: number): QuotaLevel {
  if (ratio >= 1) {
    return 'full';
  }
  return ratio >= QUOTA_WARNING_RATIO ? 'warning' : 'ok';
}

/** StatusBadge variant of a level. */
export function quotaBadgeVariant(level: QuotaLevel): 'ok' | 'warning' | 'error' {
  return level === 'full' ? 'error' : level;
}

/** Attributes of the native <meter> of a quota (max at least 1 so that the meter stays valid). */
export interface QuotaMeterAttributes {
  min: number;
  max: number;
  value: number;
  low: number;
  high: number;
  optimum: number;
}

/**
 * Attributes of the <meter>: low at 80 % of the quota, high at the quota, optimum 0 (the less
 * used, the better). The value is clamped to [0, max] as the element would do.
 */
export function quotaMeterAttributes(used: number, quota: number): QuotaMeterAttributes {
  const max = Number.isFinite(quota) && quota > 0 ? quota : 1;
  const u = Number.isFinite(used) && used > 0 ? used : 0;
  const value = quota > 0 ? Math.min(u, max) : u > 0 ? max : 0;
  return { min: 0, max, value, low: QUOTA_WARNING_RATIO * max, high: max, optimum: 0 };
}

/** Texts of a quota meter. */
export interface QuotaTexts {
  /** "12 GiB of 100 GiB (12 %)", or the no-quota notice. */
  usage: string;
  /** Text of the level badge. */
  level: string;
}

/**
 * Texts of a quota meter. The percentage is formatted by formatPercent (e.g. Intl percent
 * style), from the uncapped ratio.
 */
export function quotaTexts(
  used: number,
  quota: number,
  formatBytes: (n: number) => string,
  formatPercent: (ratio: number) => string,
  t: Translate,
): QuotaTexts {
  const ratio = quotaRatio(used, quota);
  const level = quotaLevel(ratio);
  const usedText = formatBytes(Number.isFinite(used) && used > 0 ? used : 0);
  const usage =
    Number.isFinite(quota) && quota > 0
      ? t('adminComponents.quota.usage', {
          used: usedText,
          quota: formatBytes(quota),
          percent: formatPercent(ratio),
        })
      : t('adminComponents.quota.noQuota', { used: usedText });
  return { usage, level: t(`adminComponents.quota.level.${level}`) };
}
