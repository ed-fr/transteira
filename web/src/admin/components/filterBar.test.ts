import { describe, expect, it } from 'vitest';
import en from '../../locales/en/adminComponents.json';
import fr from '../../locales/fr/adminComponents.json';
import { createFilterAnnouncer } from './filterBar';

describe('createFilterAnnouncer', () => {
  it('does not announce the initial load nor changes while idle (load more)', () => {
    const a = createFilterAnnouncer();
    expect(a.state).toBe('idle');
    expect(a.result(undefined)).toBeUndefined();
    expect(a.result('50 rows, more available')).toBeUndefined();
    expect(a.result('100 rows')).toBeUndefined();
  });

  it('announces the same text again after an apply that reloads (text, undefined, same text)', () => {
    const a = createFilterAnnouncer();
    a.result('3 rows');
    a.trigger();
    expect(a.state).toBe('pending');
    expect(a.result(undefined)).toBeUndefined();
    expect(a.result('')).toBeUndefined();
    expect(a.result('3 rows')).toBe('3 rows');
    expect(a.state).toBe('idle');
    // The action then settles: already announced, nothing more.
    expect(a.settle('3 rows', true)).toBeUndefined();
  });

  it('announces a new text after a reset, then stays silent for load more', () => {
    const a = createFilterAnnouncer();
    a.result('3 rows');
    a.trigger();
    a.result(undefined);
    expect(a.result('50 rows, more available')).toBe('50 rows, more available');
    expect(a.result('100 rows')).toBeUndefined();
  });

  it('announces on settle when nothing reloaded, and waits when the list is still loading', () => {
    const a = createFilterAnnouncer();
    a.trigger();
    expect(a.settle('3 rows', true)).toBe('3 rows');
    expect(a.state).toBe('idle');
    a.trigger();
    expect(a.settle(undefined, true)).toBeUndefined();
    expect(a.state).toBe('pending');
    expect(a.result('4 rows')).toBe('4 rows');
  });

  it('cancels when the action applied nothing (validation refused)', () => {
    const a = createFilterAnnouncer();
    a.result('3 rows');
    a.trigger();
    expect(a.settle('3 rows', false)).toBeUndefined();
    expect(a.state).toBe('idle');
    expect(a.result('4 rows')).toBeUndefined();
  });

  it('has the labels in every language', () => {
    for (const bundle of [en, fr]) {
      expect(bundle.filter.label && bundle.filter.apply && bundle.filter.reset).toBeTruthy();
    }
  });
});
