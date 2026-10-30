// Applies the theme before the first paint (CLAUDE.md section 13.1), loaded synchronously in the
// <head> of both entry pages: an external classic script, since the CSP forbids inline scripts.
// The theme is the one stored in the technical cookie tt_theme when it is exactly light or dark
// (closed list, threat model T-231: any other value is ignored and never copied into the page),
// else the system setting. src/shared/theme/mode.svelte.ts applies the same rule afterwards.
// ES2017 syntax, no module: it runs before the application bundle, on every supported browser.
(function () {
  try {
    let theme = null;
    const parts = document.cookie.split(';');
    for (let i = 0; i < parts.length; i++) {
      const eq = parts[i].indexOf('=');
      if (eq >= 0 && parts[i].slice(0, eq).trim() === 'tt_theme') {
        const value = parts[i].slice(eq + 1).trim();
        theme = value === 'light' || value === 'dark' ? value : null;
        break;
      }
    }
    if (theme === null) {
      const dark =
        typeof window.matchMedia === 'function' && window.matchMedia('(prefers-color-scheme: dark)').matches;
      theme = dark ? 'dark' : 'light';
    }
    document.documentElement.setAttribute('data-theme', theme);
    // ES2017 has no optional catch binding: the error is named and ignored.
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
  } catch (error) {
    // Without a theme, the light palette of :root applies.
  }
})();
