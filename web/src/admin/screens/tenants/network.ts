// Logic of the tenant network screen (CLAUDE.md section 6.2), kept out of the component so that
// it is unit tested in Node: translation of the line errors, warnings on the lists, client-side
// validation before saving, dirty state and server normalisation.
import type { components } from '../../../shared/api/schema';
import type { FieldRef, SummaryError } from '../../components/form';
import { isCatchAll, type CidrError, type CidrList } from '../../forms/cidr';
import type { DomainError } from '../../forms/domain';
import type { LineError, LineList } from '../../forms/lines';

/** Internal IP ranges and mail domains of a tenant. */
export type NetworkRules = components['schemas']['NetworkRules'];

/** A message to translate: a key and its parameters. */
export interface Msg {
  key: string;
  params?: Record<string, string | number>;
}

/** Translation function (t of the i18n module). */
export type Translate = (key: string, params?: Record<string, string | number>) => string;

/** Message key of each reason for which a range line is refused. */
const CIDR_ERROR_KEYS: Record<CidrError, string> = {
  syntax: 'adminTenants.network.errors.cidr.syntax',
  zone: 'adminTenants.network.errors.cidr.zone',
  'prefix-range': 'adminTenants.network.errors.cidr.prefixRange',
  'host-bits': 'adminTenants.network.errors.cidr.hostBits',
};

/** Message key of each reason for which a domain line is refused. */
const DOMAIN_ERROR_KEYS: Record<DomainError, string> = {
  syntax: 'adminTenants.network.errors.domain.syntax',
  'ip-literal': 'adminTenants.network.errors.domain.ipLiteral',
  'trailing-dot': 'adminTenants.network.errors.domain.trailingDot',
  idn: 'adminTenants.network.errors.domain.idn',
  'too-long': 'adminTenants.network.errors.domain.tooLong',
  'single-label': 'adminTenants.network.errors.domain.singleLabel',
  label: 'adminTenants.network.errors.domain.label',
  tld: 'adminTenants.network.errors.domain.tld',
};

/**
 * Message of an invalid range line (without the "Line N:" prefix): one per reason, naming the
 * masked range when host bits are set.
 */
export function cidrLineMessage(error: LineError<CidrError>): Msg {
  if (error.error === 'host-bits' && error.suggestion !== undefined) {
    return {
      key: 'adminTenants.network.errors.cidr.hostBitsSuggestion',
      params: { network: error.suggestion },
    };
  }
  return { key: CIDR_ERROR_KEYS[error.error] };
}

/**
 * Message of an invalid domain line (without the "Line N:" prefix): one per reason, naming the
 * domain without its trailing dot when that one is valid.
 */
export function domainLineMessage(error: LineError<DomainError>): Msg {
  if (error.error === 'trailing-dot' && error.suggestion !== undefined) {
    return {
      key: 'adminTenants.network.errors.domain.trailingDotSuggestion',
      params: { domain: error.suggestion },
    };
  }
  return { key: DOMAIN_ERROR_KEYS[error.error] };
}

/**
 * Warnings shown above the save button; they never block the save:
 * - an empty list makes nobody internal (only invitations allow deposits);
 * - a catch-all range makes every client of an internal domain internal.
 */
export function networkWarnings(cidrs: CidrList, domains: LineList<string>): Msg[] {
  const out: Msg[] = [];
  if (cidrs.values.length === 0) {
    out.push({ key: 'adminTenants.network.warnings.emptyCidrs' });
  }
  if (domains.values.length === 0) {
    out.push({ key: 'adminTenants.network.warnings.emptyDomains' });
  }
  for (const range of cidrs.values.filter(isCatchAll)) {
    out.push({ key: 'adminTenants.network.warnings.catchAll', params: { range } });
  }
  return out;
}

/** The two fields of the form, for the error summary. */
export interface NetworkFields {
  internalCidrs: FieldRef;
  internalDomains: FieldRef;
}

/** Error of one list, or undefined when it can be saved: an invalid line or too many entries. */
function listError(list: LineList<string>): Msg | undefined {
  if (list.errors.length > 0) {
    return { key: 'adminComponents.lineList.invalidLines', params: { count: list.errors.length } };
  }
  if (list.tooMany) {
    return { key: 'fieldErrors.too-many' };
  }
  return undefined;
}

/** Client-side validation: the save is refused while a list has invalid lines or too many entries. */
export function validateNetwork(
  cidrs: LineList<string>,
  domains: LineList<string>,
  fields: NetworkFields,
  t: Translate,
): SummaryError[] {
  const out: SummaryError[] = [];
  const pairs: [LineList<string>, FieldRef][] = [
    [cidrs, fields.internalCidrs],
    [domains, fields.internalDomains],
  ];
  for (const [list, ref] of pairs) {
    const err = listError(list);
    if (err !== undefined) {
      out.push({ id: ref.id, label: ref.label, message: t(err.key, err.params) });
    }
  }
  return out;
}

/** Body of the PUT: the normalised values of both lists. */
export function networkBody(cidrs: LineList<string>, domains: LineList<string>): NetworkRules {
  return { internalCidrs: [...cidrs.values], internalDomains: [...domains.values] };
}

function sameList(a: readonly string[], b: readonly string[]): boolean {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

/** Reports whether the rules differ (in order) from the saved ones. */
export function sameRules(a: NetworkRules, b: NetworkRules): boolean {
  return sameList(a.internalCidrs, b.internalCidrs) && sameList(a.internalDomains, b.internalDomains);
}

/** Non-blank, trimmed lines of a text area, as typed. */
function typedLines(text: string): string[] {
  return text
    .split(/\r\n|\r|\n/)
    .map((l) => l.trim())
    .filter((l) => l !== '');
}

/**
 * Reports whether the saved rules differ from what was typed (a value rewritten, a duplicate
 * dropped): the screen then says that the lists now show the saved values.
 */
export function wasNormalized(cidrText: string, domainText: string, saved: NetworkRules): boolean {
  return (
    !sameList(typedLines(cidrText), saved.internalCidrs) ||
    !sameList(typedLines(domainText), saved.internalDomains)
  );
}
