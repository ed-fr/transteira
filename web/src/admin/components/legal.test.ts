import { describe, expect, it } from 'vitest';
import {
  LEGAL_DOCUMENTS,
  LEGAL_MAX_LENGTH,
  cellOf,
  isBlank,
  loadLegalRows,
  type LegalDocument,
} from './legal';

describe('isBlank', () => {
  it('treats empty and whitespace-only texts as blank', () => {
    expect(isBlank('')).toBe(true);
    expect(isBlank(' \n\t')).toBe(true);
    expect(isBlank('# Title')).toBe(false);
  });
});

describe('cellOf', () => {
  it('reports a written document with its date', () => {
    const doc: LegalDocument = {
      document: 'legal-notice',
      language: 'fr',
      markdown: 'x',
      updatedAt: '2026-10-01T09:00:00Z',
    };
    expect(cellOf(doc)).toEqual({ state: 'present', updatedAt: '2026-10-01T09:00:00Z' });
  });

  it('reports an empty document as absent', () => {
    expect(cellOf({ document: 'privacy-policy', language: 'en', markdown: '  ' })).toEqual({
      state: 'absent',
    });
  });
});

describe('loadLegalRows', () => {
  it('loads every document in every language, an error failing one cell only', async () => {
    const calls: string[] = [];
    const rows = await loadLegalRows(
      async (document, language) => {
        calls.push(`${document}/${language}`);
        if (document === 'privacy-policy' && language === 'en') {
          throw new Error('boom');
        }
        return { document, language: language as 'fr' | 'en', markdown: language === 'fr' ? 'text' : '' };
      },
      ['fr', 'en'],
    );
    expect(calls.sort()).toEqual([
      'legal-notice/en',
      'legal-notice/fr',
      'privacy-policy/en',
      'privacy-policy/fr',
    ]);
    expect(rows.map((r) => r.document)).toEqual([...LEGAL_DOCUMENTS]);
    expect(rows[0]?.cells).toEqual({
      fr: { state: 'present', updatedAt: undefined },
      en: { state: 'absent' },
    });
    expect(rows[1]?.cells['en']).toEqual({ state: 'error' });
  });

  it('caps the text at the server limit', () => {
    expect(LEGAL_MAX_LENGTH).toBe(100000);
  });
});
