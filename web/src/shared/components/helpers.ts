// Logic of the shared components, kept out of the .svelte files so that it is unit tested in
// Node (no DOM): the browser objects it needs (clipboard, document, elements) are injected.
import { collectDrop, type ItemLike, type PickedFile } from './folders';

/** Anything with a byte size (File, or a file description from the API). */
export interface Sized {
  size: number;
}

/** Returns the total size of files, in bytes. */
export function totalBytes(files: readonly Sized[]): number {
  let total = 0;
  for (const f of files) {
    total += Math.max(0, f.size);
  }
  return total;
}

/** Joins the ids of the elements describing a control, skipping absent ones (aria-describedby). */
export function describedBy(...ids: (string | false | null | undefined)[]): string | undefined {
  const list = ids.filter((id): id is string => typeof id === 'string' && id !== '');
  return list.length === 0 ? undefined : list.join(' ');
}

/** The part of a DataTransfer read by the drop zone. */
export interface DropData {
  readonly types: readonly string[];
  readonly files?: ArrayLike<File> | null;
  /** Items of the drop, from which dropped folders are read (webkitGetAsEntry). */
  readonly items?: ArrayLike<ItemLike> | null;
}

/** Reports whether a drag operation carries files (not text or links). */
export function dragHasFiles(data: DropData | null | undefined): boolean {
  return data != null && Array.from(data.types).includes('Files');
}

/** Returns the files of a drop or of a file input, as an array (empty when there are none). */
export function filesOf(list: ArrayLike<File> | null | undefined): File[] {
  return list == null ? [] : Array.from(list);
}

/** Handlers of a file drop target. */
export interface DropHandlers {
  /** Called with the dropped files (never with an empty list). */
  onfiles: (files: File[]) => void;
  /**
   * When set and folders() is true, drops go here instead of onfiles: the promise resolves to the
   * dropped files with their relative folder (dropped folders walked recursively).
   */
  onpicked?: (picked: Promise<PickedFile[]>) => void;
  /** Reports whether dropped folders are accepted. */
  folders?: () => boolean;
  /** Called when the drag-over state changes (to toggle the drag-over class). */
  onactive: (active: boolean) => void;
  /** When it returns true, drops are ignored. */
  disabled?: () => boolean;
}

/** The part of a drag event used by the drop target. */
export interface DropEventLike {
  readonly dataTransfer: (DropData & { dropEffect?: string }) | null;
  readonly relatedTarget?: unknown;
  preventDefault(): void;
}

/** The part of an element used by the drop target. */
export interface DropElement {
  addEventListener(type: string, listener: (event: DropEventLike) => void): void;
  removeEventListener(type: string, listener: (event: DropEventLike) => void): void;
  contains(other: unknown): boolean;
}

/**
 * Makes an element a file drop target: dragging files over it activates it, dropping them calls
 * onfiles. Listeners are attached with addEventListener (a Svelte attachment), so that the drop
 * zone stays a plain container and the real file input remains the keyboard path. Returns the
 * cleanup function.
 */
export function dropTarget(handlers: DropHandlers): (element: DropElement) => () => void {
  return (element) => {
    const isDisabled = (): boolean => handlers.disabled?.() === true;
    const over = (event: DropEventLike): void => {
      if (!dragHasFiles(event.dataTransfer)) {
        return;
      }
      event.preventDefault();
      if (event.dataTransfer !== null) {
        event.dataTransfer.dropEffect = isDisabled() ? 'none' : 'copy';
      }
      if (!isDisabled()) {
        handlers.onactive(true);
      }
    };
    const leave = (event: DropEventLike): void => {
      if (event.relatedTarget != null && element.contains(event.relatedTarget)) {
        return;
      }
      handlers.onactive(false);
    };
    const drop = (event: DropEventLike): void => {
      if (!dragHasFiles(event.dataTransfer)) {
        return;
      }
      event.preventDefault();
      handlers.onactive(false);
      const files = filesOf(event.dataTransfer?.files);
      if (isDisabled()) {
        return;
      }
      if (files.length === 0) {
        // An empty or unreadable folder: in folders mode, let the zone tell the user.
        if (handlers.onpicked !== undefined && handlers.folders?.() === true) {
          handlers.onpicked(Promise.resolve([]));
        }
        return;
      }
      if (handlers.onpicked !== undefined && handlers.folders?.() === true) {
        // The entries are taken now, synchronously: the browser empties the items after the event.
        handlers.onpicked(collectDrop(event.dataTransfer?.items, event.dataTransfer?.files, true));
        return;
      }
      handlers.onfiles(files);
    };
    element.addEventListener('dragenter', over);
    element.addEventListener('dragover', over);
    element.addEventListener('dragleave', leave);
    element.addEventListener('drop', drop);
    return () => {
      element.removeEventListener('dragenter', over);
      element.removeEventListener('dragover', over);
      element.removeEventListener('dragleave', leave);
      element.removeEventListener('drop', drop);
    };
  };
}

/** The browser objects used by copyText (navigator.clipboard and document by default). */
export interface CopyEnvironment {
  clipboard?: { writeText(text: string): Promise<void> } | undefined;
  document?: CopyDocument | undefined;
}

/** The part of document used by the copy fallback. */
export interface CopyDocument {
  createElement(tag: 'textarea'): CopyTextArea;
  body: { appendChild(node: CopyTextArea): unknown; removeChild(node: CopyTextArea): unknown };
  execCommand(command: 'copy'): boolean;
  activeElement: unknown;
}

/** The part of a textarea used by the copy fallback. */
export interface CopyTextArea {
  value: string;
  className: string;
  readOnly: boolean;
  select(): void;
  setAttribute(name: string, value: string): void;
}

function defaultEnvironment(): CopyEnvironment {
  return {
    clipboard: typeof navigator === 'undefined' ? undefined : navigator.clipboard,
    document: typeof document === 'undefined' ? undefined : (document as unknown as CopyDocument),
  };
}

/**
 * Copies text to the clipboard: the asynchronous Clipboard API when available (secure context),
 * otherwise a hidden read-only textarea and execCommand('copy'). Resolves to true on success.
 */
export async function copyText(text: string, env: CopyEnvironment = defaultEnvironment()): Promise<boolean> {
  if (env.clipboard !== undefined) {
    try {
      await env.clipboard.writeText(text);
      return true;
    } catch {
      // Permission refused or insecure context: try the fallback.
    }
  }
  const doc = env.document;
  if (doc === undefined) {
    return false;
  }
  const previous = doc.activeElement;
  const area = doc.createElement('textarea');
  area.value = text;
  area.readOnly = true;
  area.className = 'visually-hidden';
  area.setAttribute('aria-hidden', 'true');
  doc.body.appendChild(area);
  try {
    area.select();
    return doc.execCommand('copy');
  } catch {
    return false;
  } finally {
    doc.body.removeChild(area);
    if (isFocusable(previous)) {
      previous.focus();
    }
  }
}

/** Reports whether a value has a focus method (an element that can take the focus back). */
export function isFocusable(value: unknown): value is { focus(): void } {
  return (
    typeof value === 'object' && value !== null && typeof (value as { focus?: unknown }).focus === 'function'
  );
}

/**
 * Returns the name of a language in that language ("fr" → "français"), for the language switch:
 * a language is always offered under its own name (RGAA 8.7, with a lang attribute).
 */
export function languageName(code: string): string {
  try {
    const name = new Intl.DisplayNames([code], { type: 'language' }).of(code);
    if (name === undefined || name === code) {
      return code;
    }
    return name.charAt(0).toLocaleUpperCase(code) + name.slice(1);
  } catch {
    return code;
  }
}

/** Pattern of a help topic: a slug, also used as the path segment of /help/<topic>. */
export const HELP_TOPIC = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

/**
 * Returns the URL of the integrated help for a topic (the help index for an invalid topic),
 * under base ("" on tenant hosts, "/admin" in the administration).
 */
export function helpHref(topic: string | undefined, base = ''): string {
  const prefix = base.replace(/\/+$/, '');
  return topic !== undefined && HELP_TOPIC.test(topic) ? `${prefix}/help/${topic}` : `${prefix}/help`;
}

/** Returns a percentage between 0 and 100 (0 when max is not positive). */
export function percentOf(value: number, max: number): number {
  if (!(max > 0) || !Number.isFinite(value)) {
    return 0;
  }
  return Math.min(100, Math.max(0, (value / max) * 100));
}
