// Logic of the tenant recipient domain rules screen (CLAUDE.md section 8.4, version 1.1), kept
// out of the component so that it is unit tested in Node: client-side validation of both
// domain lists, warnings, request body, dirty state and server normalisation.
import type { components } from '../../../shared/api/schema';
import type { FieldRef, SummaryError } from '../../components/form';
import { parseDomain, type DomainError } from '../../forms/domain';
import { parseLineList, type LineList } from '../../forms/lines';
import type { Msg, Translate } from './network';

/** Allowed and denied recipient domains of a tenant. */
export type RecipientRules = components['schemas']['RecipientRules'];

/** Maximum number of entries of each list (RecipientRules). */
export const MAX_RECIPIENT_DOMAINS = 500;

/** Parses a domain list text with the limit of this screen. */
export function parseRuleList(text: string): LineList<DomainError> {
  return parseLineList(text, parseDomain, MAX_RECIPIENT_DOMAINS);
}

/** The two fields of the form, for the error summary. */
export interface RecipientFields {
  allowedDomains: FieldRef;
  deniedDomains: FieldRef;
}

function listError(list: LineList<string>): Msg | undefined {
  if (list.errors.length > 0) {
    return { key: 'adminComponents.lineList.invalidLines', params: { count: list.errors.length } };
  }
  return list.tooMany ? { key: 'fieldErrors.too-many' } : undefined;
}

/** Client-side validation: the save is refused while a list has invalid lines or too many entries. */
export function validateRecipientRules(
  allowed: LineList<string>,
  denied: LineList<string>,
  fields: RecipientFields,
  t: Translate,
): SummaryError[] {
  const out: SummaryError[] = [];
  const pairs: [LineList<string>, FieldRef][] = [
    [allowed, fields.allowedDomains],
    [denied, fields.deniedDomains],
  ];
  for (const [list, ref] of pairs) {
    const err = listError(list);
    if (err !== undefined) {
      out.push({ id: ref.id, label: ref.label, message: t(err.key, err.params) });
    }
  }
  return out;
}

/**
 * Warnings (never blocking): a domain in both lists is denied (deny wins); a non-empty allow
 * list restricts every recipient to it.
 */
export function recipientWarnings(allowed: LineList<string>, denied: LineList<string>): Msg[] {
  const out: Msg[] = [];
  for (const domain of allowed.values.filter((d) => denied.values.includes(d))) {
    out.push({ key: 'adminTenants.recipientRules.warnings.both', params: { domain } });
  }
  if (allowed.values.length > 0) {
    out.push({
      key: 'adminTenants.recipientRules.warnings.restricts',
      params: { count: allowed.values.length },
    });
  }
  return out;
}

/** Body of the PUT. */
export function recipientRulesBody(allowed: LineList<string>, denied: LineList<string>): RecipientRules {
  return { allowedDomains: [...allowed.values], deniedDomains: [...denied.values] };
}

function sameList(a: readonly string[], b: readonly string[]): boolean {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

/** Reports whether the rules differ (in order) from the saved ones. */
export function sameRecipientRules(a: RecipientRules, b: RecipientRules): boolean {
  return sameList(a.allowedDomains, b.allowedDomains) && sameList(a.deniedDomains, b.deniedDomains);
}

function typedLines(text: string): string[] {
  return text
    .split(/\r\n|\r|\n/)
    .map((l) => l.trim())
    .filter((l) => l !== '');
}

/** Reports whether the saved rules differ from what was typed (a value rewritten or dropped). */
export function recipientRulesNormalized(
  allowedText: string,
  deniedText: string,
  saved: RecipientRules,
): boolean {
  return (
    !sameList(typedLines(allowedText), saved.allowedDomains) ||
    !sameList(typedLines(deniedText), saved.deniedDomains)
  );
}
