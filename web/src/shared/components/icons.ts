// Path data of the inline icons drawn by Icon.svelte: 24 × 24 view box, 2 px round strokes in
// currentColor, no fill. Each icon is a list of SVG path "d" attributes (circles and rectangles
// are written as paths), so that the component renders plain <path> elements: no external
// sprite, no data: URI, nothing the CSP or check-dist.mjs would reject.

/** Name of an icon of the set. */
export type IconName =
  | 'alert'
  | 'check'
  | 'chevron'
  | 'clock'
  | 'copy'
  | 'download'
  | 'file'
  | 'folder'
  | 'globe'
  | 'help'
  | 'info'
  | 'list'
  | 'lock'
  | 'moon'
  | 'send'
  | 'shield'
  | 'sun'
  | 'upload'
  | 'x';

const CIRCLE_9 = 'M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0z';

/** Paths of each icon. */
export const ICONS: Readonly<Record<IconName, readonly string[]>> = {
  alert: ['M12 3l10 18H2z', 'M12 10v4M12 17.5v.5'],
  check: ['M5 12l5 5 9-10'],
  chevron: ['M6 9l6 6 6-6'],
  clock: [CIRCLE_9, 'M12 7v5l3 2'],
  copy: [
    'M11 9h9a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2h-9a2 2 0 0 1-2-2v-9a2 2 0 0 1 2-2z',
    'M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1',
  ],
  download: ['M12 4v12M6 10l6 6 6-6', 'M4 20h16'],
  file: ['M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z', 'M14 3v5h5'],
  folder: ['M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z'],
  globe: [CIRCLE_9, 'M3 12h18', 'M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18'],
  help: [CIRCLE_9, 'M9.1 9a3 3 0 0 1 5.8 1c0 2-2.9 3-2.9 3', 'M12 17h.01'],
  info: [CIRCLE_9, 'M12 16v-5', 'M12 8h.01'],
  list: ['M3 7h18M3 12h18M3 17h12'],
  lock: [
    'M7 11h10a2 2 0 0 1 2 2v6a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2v-6a2 2 0 0 1 2-2z',
    'M8 11V7a4 4 0 0 1 8 0v4',
  ],
  moon: ['M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z'],
  send: ['M22 2L11 13', 'M22 2l-7 20-4-9-9-4z'],
  shield: ['M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z'],
  sun: [
    'M16 12a4 4 0 1 1-8 0 4 4 0 0 1 8 0z',
    'M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41',
  ],
  upload: ['M12 16V4M6 10l6-6 6 6', 'M4 16v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2'],
  x: ['M6 6l12 12M18 6L6 18'],
};

/** Names of the icons, in alphabetical order. */
export const ICON_NAMES: readonly IconName[] = Object.keys(ICONS).sort() as IconName[];
