// Page title of the help screen, read by the two applications when they build document.title
// (the route title is only "Help"; the help screen sets "Section – Guide" once a guide is shown).

/** Reactive title of the help page; undefined outside the help or before a guide is shown. */
export const helpTitle: { current: string | undefined } = $state({ current: undefined });

/** Returns the help page title when on a help route and one is set, otherwise fallback. */
export function pageTitleOf(isHelp: boolean, fallback: string): string {
  return isHelp && helpTitle.current !== undefined ? helpTitle.current : fallback;
}
