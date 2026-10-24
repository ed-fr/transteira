import { describe, expect, it } from 'vitest';
import { flattenOptions, hasOption, isSelectGroup, type SelectEntry } from './select';

const all: SelectEntry = { value: '', label: 'All' };
const files: SelectEntry = {
  group: 'files',
  label: 'Files',
  options: [
    { value: 'email', label: 'Address' },
    { value: 'sha256', label: 'SHA-256', disabled: true },
  ],
};
const entries: SelectEntry[] = [all, files];

describe('select entries', () => {
  it('tells groups from options', () => {
    expect(isSelectGroup(all)).toBe(false);
    expect(isSelectGroup(files)).toBe(true);
  });

  it('flattens groups in order', () => {
    expect(flattenOptions(entries).map((o) => o.value)).toEqual(['', 'email', 'sha256']);
  });

  it('finds an option by value', () => {
    expect(hasOption(entries, 'sha256')).toBe(true);
    expect(hasOption(entries, 'domain')).toBe(false);
  });
});
