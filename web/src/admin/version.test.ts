import { describe, expect, it, vi } from 'vitest';
import {
  UNKNOWN_VERSION,
  checkFailureText,
  checkResultText,
  footerVersionText,
  lastErrorKey,
  loadRunningVersion,
  loadSystemVersion,
  runVersionCheck,
  safeReleaseUrl,
  updateNotice,
  type SystemVersion,
} from './version';

const t = (key: string, params?: Record<string, string | number>): string =>
  params === undefined ? key : `${key} ${JSON.stringify(params)}`;

function state(check: Partial<SystemVersion['updateCheck']> = {}): SystemVersion {
  return {
    version: '1.2.0',
    updateCheck: {
      enabled: true,
      latestVersion: null,
      releaseUrl: null,
      updateAvailable: false,
      checkedAt: null,
      lastError: 'none',
      ...check,
    },
  };
}

describe('loadRunningVersion', () => {
  it('returns the version', async () => {
    const get = vi.fn().mockResolvedValue({ data: { version: '1.2.0' } });
    expect(await loadRunningVersion({ get } as never)).toBe('1.2.0');
    expect(get).toHaveBeenCalledWith('/version');
  });
  it('falls back on a blank version or a failure', async () => {
    expect(
      await loadRunningVersion({ get: vi.fn().mockResolvedValue({ data: { version: ' ' } }) } as never),
    ).toBe(UNKNOWN_VERSION);
    expect(await loadRunningVersion({ get: vi.fn().mockRejectedValue(new Error('x')) } as never)).toBe(
      UNKNOWN_VERSION,
    );
  });
});

describe('system version calls', () => {
  it('reads and checks', async () => {
    const data = state();
    const get = vi.fn().mockResolvedValue({ data });
    const post = vi.fn().mockResolvedValue({ data });
    expect(await loadSystemVersion({ get } as never)).toBe(data);
    expect(get).toHaveBeenCalledWith('/admin/system/version');
    expect(await runVersionCheck({ post } as never)).toBe(data);
    expect(post).toHaveBeenCalledWith('/admin/system/version/check');
  });
});

describe('safeReleaseUrl', () => {
  it('accepts only project release pages', () => {
    const ok = 'https://github.com/ed-fr/transteira/releases/tag/v1.3.0';
    expect(safeReleaseUrl(ok)).toBe(ok);
    expect(safeReleaseUrl('https://evil.example.com/releases/')).toBeUndefined();
    expect(safeReleaseUrl('javascript:alert(1)')).toBeUndefined();
    expect(safeReleaseUrl(null)).toBeUndefined();
  });
});

describe('lastErrorKey', () => {
  it('maps errors to keys', () => {
    expect(lastErrorKey('none')).toBeUndefined();
    expect(lastErrorKey('network')).toBe('sysVersion.error.network');
    expect(lastErrorKey('http')).toBe('sysVersion.error.http');
    expect(lastErrorKey('parse')).toBe('sysVersion.error.parse');
  });
});

describe('updateNotice', () => {
  it('is hidden while unknown, disabled or up to date', () => {
    expect(updateNotice(undefined).visible).toBe(false);
    expect(
      updateNotice(state({ enabled: false, updateAvailable: true, latestVersion: '1.3.0' })).visible,
    ).toBe(false);
    expect(updateNotice(state()).visible).toBe(false);
    expect(updateNotice(state({ updateAvailable: true })).visible).toBe(false);
  });
  it('shows the latest version and a safe link', () => {
    const notice = updateNotice(
      state({
        updateAvailable: true,
        latestVersion: '1.3.0',
        releaseUrl: 'https://github.com/ed-fr/transteira/releases/tag/v1.3.0',
      }),
    );
    expect(notice).toEqual({
      visible: true,
      latest: '1.3.0',
      releaseUrl: 'https://github.com/ed-fr/transteira/releases/tag/v1.3.0',
    });
  });
  it('drops an unsafe link', () => {
    const notice = updateNotice(
      state({ updateAvailable: true, latestVersion: '1.3.0', releaseUrl: 'https://evil.example.com/' }),
    );
    expect(notice.visible).toBe(true);
    expect(notice.releaseUrl).toBeUndefined();
  });
});

describe('checkResultText', () => {
  it('reports an error, an available update or an up to date instance', () => {
    expect(checkResultText(state({ lastError: 'network' }), t)).toBe('sysVersion.error.network');
    expect(checkResultText(state({ updateAvailable: true, latestVersion: '1.3.0' }), t)).toContain(
      'sysVersion.resultAvailable',
    );
    expect(checkResultText(state({ latestVersion: '1.2.0' }), t)).toBe('sysVersion.resultUpToDate');
  });
});

describe('checkFailureText / footerVersionText', () => {
  it('uses its own sentence for the rate limit only', () => {
    expect(checkFailureText('rate-limited', 'raw', t)).toBe('sysVersion.rateLimited');
    expect(checkFailureText('update-check-disabled', 'translated', t)).toBe('sysVersion.disabledNow');
    expect(checkFailureText('other', 'translated', t)).toBe('translated');
    expect(checkFailureText(undefined, 'translated', t)).toBe('translated');
  });
  it('formats the footer version', () => {
    expect(footerVersionText('1.2.0', t)).toContain('1.2.0');
    expect(footerVersionText(undefined, t)).toContain(UNKNOWN_VERSION);
  });
});
