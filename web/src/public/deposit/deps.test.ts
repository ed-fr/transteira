import { afterEach, describe, expect, it, vi } from 'vitest';
import { browserDeps } from './deps';

describe('browserDeps', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('wires the browser dependencies of the deposit flow', async () => {
    const confirm = vi.fn(() => false);
    vi.stubGlobal('window', { confirm });
    const deps = browserDeps();
    expect(deps.confirm('Leave?')).toBe(false);
    expect(confirm).toHaveBeenCalledWith('Leave?');
    expect(typeof deps.language()).toBe('string');
    expect(deps.tr.has('deposit.scan.other')).toBeTypeOf('boolean');
    deps.clearCsrf();

    const engine = deps.createEngine([], async () => {});
    expect(engine.getSnapshot()).toMatchObject({ phase: 'idle', totalBytes: 0 });

    // An aborted signal stops before any request.
    const controller = new AbortController();
    controller.abort();
    await expect(deps.finalize('trf_1', { signal: controller.signal })).resolves.toEqual({ kind: 'stopped' });
    await expect(deps.poll('trf_1', { signal: controller.signal })).resolves.toEqual({ kind: 'stopped' });
  });
});
