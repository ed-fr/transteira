// Logic of the legal text screens (CLAUDE.md section 13), kept out of the components so that it
// is unit tested in Node: list of the documents per language (written or not), blank texts.
import type { components } from '../../shared/api/schema';

export type LegalDocument = components['schemas']['LegalDocument'];
export type LegalDocumentName = LegalDocument['document'];

/** Legal documents of a tenant, in display order. */
export const LEGAL_DOCUMENTS: readonly LegalDocumentName[] = ['legal-notice', 'privacy-policy'];

/** Maximum length of a legal text (LegalDocumentUpdate.markdown). */
export const LEGAL_MAX_LENGTH = 100000;

/** Reports whether a Markdown text is empty or blank (saving it deletes the document). */
export function isBlank(markdown: string): boolean {
  return markdown.trim() === '';
}

/** State of one document in one language. */
export type LegalCell =
  { state: 'present'; updatedAt: string | undefined } | { state: 'absent' } | { state: 'error' };

/** One document with its state per language. */
export interface LegalRow {
  document: LegalDocumentName;
  cells: Record<string, LegalCell>;
}

/** State of a loaded document. */
export function cellOf(doc: LegalDocument): LegalCell {
  return isBlank(doc.markdown) ? { state: 'absent' } : { state: 'present', updatedAt: doc.updatedAt };
}

/**
 * Loads every document in every language in parallel (there is no list operation) and returns
 * one row per document. A failed load gives an error cell; it does not fail the others.
 */
export async function loadLegalRows(
  load: (document: LegalDocumentName, language: string) => Promise<LegalDocument>,
  languages: readonly string[],
): Promise<LegalRow[]> {
  return Promise.all(
    LEGAL_DOCUMENTS.map(async (document) => {
      const cells: Record<string, LegalCell> = {};
      await Promise.all(
        languages.map(async (language) => {
          try {
            cells[language] = cellOf(await load(document, language));
          } catch {
            cells[language] = { state: 'error' };
          }
        }),
      );
      return { document, cells };
    }),
  );
}
