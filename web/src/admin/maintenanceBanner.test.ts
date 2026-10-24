import { describe, expect, it } from 'vitest';
import { maintenanceBanner, maintenanceBannerText, type Maintenance } from './maintenanceBanner';

const t = (key: string, params?: Record<string, string | number>): string =>
  params === undefined ? key : `${key}|${JSON.stringify(params)}`;
const fmt = (iso: string): string => `fmt(${iso})`;

const off: Maintenance = { enabled: false, source: 'none', adminEnabled: false };
const byAdmin: Maintenance = {
  enabled: true,
  source: 'admin',
  adminEnabled: true,
  since: '2026-10-24T08:00:00Z',
  message: { en: 'Back soon.' },
};
const byEnv: Maintenance = {
  enabled: true,
  source: 'environment',
  adminEnabled: false,
  since: '2026-10-24T07:00:00Z',
};

describe('maintenanceBanner', () => {
  it('is hidden while the state is unknown or the mode is off', () => {
    for (const state of [undefined, off]) {
      expect(maintenanceBanner(state, 'super_admin')).toEqual({
        visible: false,
        textKey: 'adminSystem.banner.text',
        since: undefined,
        sourceKey: undefined,
        linkPath: undefined,
      });
    }
  });

  it('shows the start date and the link for the super admin', () => {
    expect(maintenanceBanner(byAdmin, 'super_admin')).toEqual({
      visible: true,
      textKey: 'adminSystem.banner.textSince',
      since: '2026-10-24T08:00:00Z',
      sourceKey: undefined,
      linkPath: '/system/maintenance',
    });
  });

  it('gives no link to a delegated admin', () => {
    expect(maintenanceBanner(byAdmin, 'delegated_admin').linkPath).toBeUndefined();
    expect(maintenanceBanner(byAdmin, undefined).linkPath).toBeUndefined();
    expect(maintenanceBanner(byAdmin, 'delegated_admin').visible).toBe(true);
  });

  it('mentions the environment when it forces the mode', () => {
    expect(maintenanceBanner(byEnv, 'delegated_admin').sourceKey).toBe('adminSystem.banner.environment');
  });

  it('drops a missing or invalid start date', () => {
    const { since: _since, ...noDate } = byAdmin;
    expect(maintenanceBanner(noDate, 'super_admin')).toMatchObject({
      textKey: 'adminSystem.banner.text',
      since: undefined,
    });
    expect(maintenanceBanner({ ...byAdmin, since: 'not a date' }, 'super_admin').since).toBeUndefined();
  });
});

describe('maintenanceBannerText', () => {
  it('formats the date and appends the source', () => {
    expect(maintenanceBannerText(maintenanceBanner(byEnv, 'super_admin'), t, fmt)).toBe(
      'adminSystem.banner.textSince|{"date":"fmt(2026-10-24T07:00:00Z)"} adminSystem.banner.environment',
    );
  });

  it('uses the text without date', () => {
    expect(maintenanceBannerText(maintenanceBanner({ ...byAdmin, since: '' }, 'super_admin'), t, fmt)).toBe(
      'adminSystem.banner.text',
    );
  });
});
