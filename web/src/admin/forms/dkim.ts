// DKIM selectors probed by the mail DNS check (checkMailDns, query parameter dkimSelector).

/** Maximum number of selectors accepted by the API. */
export const MAX_DKIM_SELECTORS = 5;
/** Maximum length of a selector. */
export const MAX_DKIM_SELECTOR_LENGTH = 63;
/** Pattern of a selector in the API: DNS labels separated by dots. */
export const DKIM_SELECTOR =
  /^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$/;

/** Result of the parsing of the selectors field. */
export interface DkimSelectors {
  /** Valid selectors, in order and without duplicates. */
  selectors: string[];
  /** Entries refused by the pattern or the length, as typed. */
  invalid: string[];
  /** True when more than MAX_DKIM_SELECTORS valid selectors were given. */
  tooMany: boolean;
}

/** Reports whether s is a selector accepted by the API. */
export function isDkimSelector(s: string): boolean {
  return s.length <= MAX_DKIM_SELECTOR_LENGTH && DKIM_SELECTOR.test(s);
}

/** Parses a list of selectors separated by commas, spaces or line breaks. */
export function parseDkimSelectors(text: string): DkimSelectors {
  const out: DkimSelectors = { selectors: [], invalid: [], tooMany: false };
  for (const item of text.split(/[\s,;]+/)) {
    if (item === '') {
      continue;
    }
    if (!isDkimSelector(item)) {
      out.invalid.push(item);
    } else if (!out.selectors.includes(item)) {
      out.selectors.push(item);
    }
  }
  out.tooMany = out.selectors.length > MAX_DKIM_SELECTORS;
  return out;
}

/** Reports whether the parsed selectors can be sent to the API. */
export function dkimSelectorsValid(parsed: DkimSelectors): boolean {
  return parsed.invalid.length === 0 && !parsed.tooMany;
}
