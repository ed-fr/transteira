// Logic of the recipient input (RecipientInput.svelte, CLAUDE.md section 13.2): the addresses
// typed or pasted are split on commas, semicolons and line breaks, "Name <address>" is reduced to
// the address, and each complete address becomes a chip. Pure functions, unit tested in Node; the
// component only wires them to the keyboard, the clipboard and the announcements.

/** Separators between addresses: comma, semicolon, line break. */
export const RECIPIENT_SEPARATORS = /[,;\r\n]+/;

/**
 * Splits a text into addresses, in order, duplicates kept: entries trimmed, "Name <address>"
 * reduced to the address, empty entries dropped.
 */
export function splitRecipients(text: string): string[] {
  const out: string[] = [];
  for (const part of text.split(RECIPIENT_SEPARATORS)) {
    let address = part.trim();
    const bracket = /<([^<>]*)>/.exec(address);
    if (bracket !== null) {
      address = (bracket[1] ?? '').trim();
    }
    if (address !== '') {
      out.push(address);
    }
  }
  return out;
}

/**
 * Splits a text into addresses (see splitRecipients) and removes the duplicates
 * (case-insensitive), keeping the first spelling and the order.
 */
export function parseRecipients(text: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const address of splitRecipients(text)) {
    const folded = address.toLowerCase();
    if (!seen.has(folded)) {
      seen.add(folded);
      out.push(address);
    }
  }
  return out;
}

/** Outcome of the commit of a draft to the list of recipients. */
export interface RecipientCommit {
  /** The list after the commit (the committed addresses, then the added ones). */
  list: string[];
  /** Addresses added to the list, in order. */
  added: string[];
  /** Addresses of the draft left out because already in the list (case-insensitive). */
  duplicates: string[];
}

/**
 * Adds the addresses of a draft to a committed list: duplicates of the list, or within the draft,
 * are left out and reported (case-insensitive).
 */
export function commitRecipients(committed: readonly string[], draft: string): RecipientCommit {
  const list = [...committed];
  const seen = new Set(committed.map((a) => a.toLowerCase()));
  const added: string[] = [];
  const duplicates: string[] = [];
  for (const address of splitRecipients(draft)) {
    const folded = address.toLowerCase();
    if (seen.has(folded)) {
      duplicates.push(address);
    } else {
      seen.add(folded);
      list.push(address);
      added.push(address);
    }
  }
  return { list, added, duplicates };
}

/** A message of the recipient input: a translation key and its parameters. */
export interface RecipientMessage {
  key: string;
  params: Record<string, string | number>;
}

/** What the recipient input tells after a commit. */
export interface CommitFeedback {
  /** Visible notice of the addresses left out (already in the list); undefined when none. */
  notice: RecipientMessage | undefined;
  /** Messages to announce, in order: the added addresses, the invalid ones among them, the notice. */
  announcements: RecipientMessage[];
}

/**
 * Feedback of a commit: the addresses added, those of them that are not valid (isValid returns
 * false: the chip is shown as refused), and the duplicates left out, also shown as a notice.
 * No announcement when the commit changed nothing.
 */
export function commitFeedback(
  result: Pick<RecipientCommit, 'added' | 'duplicates'>,
  isValid: (address: string) => boolean,
): CommitFeedback {
  const list = (addresses: readonly string[]) => ({
    count: addresses.length,
    addresses: addresses.join(', '),
  });
  const notice =
    result.duplicates.length > 0
      ? { key: 'components.recipientInput.duplicates', params: list(result.duplicates) }
      : undefined;
  const announcements: RecipientMessage[] = [];
  if (result.added.length > 0) {
    announcements.push({ key: 'components.recipientInput.added', params: list(result.added) });
  }
  const invalid = result.added.filter((address) => !isValid(address));
  if (invalid.length > 0) {
    announcements.push({ key: 'components.recipientInput.invalidAdded', params: list(invalid) });
  }
  if (notice !== undefined) {
    announcements.push(notice);
  }
  return { notice, announcements };
}

/** Text of a committed list, as kept in a form value (parsed back by parseRecipients). */
export function joinRecipients(list: readonly string[]): string {
  return list.join(', ');
}

/** A typed value split at its last separator. */
export interface DraftSplit {
  /** Text up to the last separator (complete addresses), '' when there is no separator. */
  complete: string;
  /** Text after the last separator (the address being typed). */
  rest: string;
}

/**
 * Splits a typed value at its last separator: what precedes it is complete (to commit), what
 * follows is still being typed. "a@x.example, b" gives complete "a@x.example," and rest " b"
 * trimmed at the start.
 */
export function splitDraft(value: string): DraftSplit {
  const match = /[,;\r\n](?=[^,;\r\n]*$)/.exec(value);
  if (match === null) {
    return { complete: '', rest: value };
  }
  return { complete: value.slice(0, match.index + 1), rest: value.slice(match.index + 1).trimStart() };
}

/** Value of the input after a paste replaced its selection (start to end) with text. */
export function pastedValue(value: string, start: number | null, end: number | null, text: string): string {
  const from = Math.max(0, Math.min(start ?? value.length, value.length));
  const to = Math.max(from, Math.min(end ?? from, value.length));
  return value.slice(0, from) + text + value.slice(to);
}

/** What a key pressed in the input does. */
export type RecipientKeyAction = 'commit' | 'focus-last' | 'none';

/**
 * Action of a key pressed in the input: Enter commits a non-empty draft (instead of submitting
 * the form); Backspace in an empty input moves the focus to the last chip (its remove button).
 */
export function recipientKeyAction(key: string, draft: string, chips: number): RecipientKeyAction {
  if (key === 'Enter' && draft.trim() !== '') {
    return 'commit';
  }
  if (key === 'Backspace' && draft === '' && chips > 0) {
    return 'focus-last';
  }
  return 'none';
}

/** Keys that remove a focused chip. */
export function removesChip(key: string): boolean {
  return key === 'Backspace' || key === 'Delete';
}

/**
 * The draft left in the input becomes a chip when the input has lost the focus, once the pointer
 * press that blurred it is over (PointerPress): only a draft that is not blank, and not when the
 * focus came back to the input meanwhile (e.g. after the removal of a chip).
 */
export function commitsLeftDraft(draft: string, focusedAgain: boolean): boolean {
  return !focusedAgain && draft.trim() !== '';
}
