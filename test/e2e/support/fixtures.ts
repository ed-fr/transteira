// Playwright fixtures of the suite. Every browser context of a test (the default one and those
// opened with the newContext fixture) is watched by the guards, which fail the test at its end on:
//   - a Content Security Policy violation (securitypolicyviolation event or Chromium's report);
//   - an uncaught JavaScript error of a page;
//   - a request to an origin other than the three e2e hosts (no CDN, no third party);
//   - a server error (HTTP 5xx) on any request, unless allowed with guards.allowHttpError;
//   - a console error, unless allowed for this test. The browser logs every 4xx answer as a
//     console error: a test that provokes a 401, 403 or 409 on purpose declares it with
//     guards.allowHttpError(status, url); other expected console errors use
//     guards.allowConsoleErrors(pattern). DEFAULT_HTTP_ALLOWANCES lists the answers the
//     interfaces provoke by design on every visit (anonymous session probes).
// Every context also gets its own client IP (clientIp option, see clientip.ts), and the module
// provides checkA11y (axe-core WCAG 2.1 A/AA, zero violations) and expectCleanStorage.
//
// Shared state: tests run in parallel against the same seeded entities. Instance-wide changes
// (maintenance mode) live in the "system-serial" project (playwright.config.ts). One test of the
// main project mutates shared data on purpose: the legal text test of admin-tenants.spec.ts
// replaces the English legal notice of entity A with unique content and restores it at the end,
// so no other test may assert the content of entity A's English legal notice.
import {
  test as base,
  expect,
  type BrowserContext,
  type BrowserContextOptions,
  type Page,
  type TestInfo,
} from '@playwright/test';
import fs from 'node:fs';
import { createRequire } from 'node:module';
import { CLIENT_IP_HEADER, randomInternalIp } from './clientip';
import { ALLOWED_ORIGINS } from './env';
import { loadState, type E2EState } from './state';

/** Marker of the console message written by the CSP listener injected in every page. */
const CSP_MARKER = 'E2E-CSP-VIOLATION';

/** Per-test controls of the guards. */
export interface Guards {
  /** Allows console errors matching one of the patterns for the rest of the test. */
  allowConsoleErrors(...patterns: RegExp[]): void;
  /**
   * Allows the browser's "Failed to load resource" console error for an HTTP status, on the
   * URLs matching url (any URL when omitted: prefer a precise pattern). For a 5xx status, the
   * server-error guard also accepts those answers (a provoked 503 maintenance, for example).
   */
  allowHttpError(status: number, url?: RegExp): void;
  /** Problems recorded so far (for tests that check them before the end). */
  problems(): string[];
}

/** Options of the newContext fixture. */
export interface NewContextOptions extends BrowserContextOptions {
  /** Client IP announced for this context (default: a fresh random internal address). */
  clientIp?: string;
}

interface Options {
  /**
   * Client IP the server sees for the default browser context of the test. Default: a random
   * address in 10.0.0.0/8 (inside the seeded tenants' internal ranges), unique per test. Use an
   * address of a documentation range (e.g. 203.0.113.7) to simulate an external client.
   */
  clientIp: string;
}

interface Fixtures {
  guards: Guards;
  /** Seeded state of the run (state.json). */
  state: E2EState;
  /** Opens an extra guarded browser context (closed at the end of the test). */
  newContext: (options?: NewContextOptions) => Promise<BrowserContext>;
}

/** An expected HTTP error answer. */
interface HttpAllowance {
  status: number;
  url?: RegExp;
}

/**
 * Error answers the interfaces provoke by design on every visit, allowed in every test: the
 * public interface (deposit and "my transfers") and the admin interface ask whether a session
 * exists (401 when anonymous).
 */
export const DEFAULT_HTTP_ALLOWANCES: readonly HttpAllowance[] = [
  { status: 401, url: /\/api\/v1\/deposit-sessions\/current$/ },
  { status: 401, url: /\/api\/v1\/me\/sessions\/current$/ },
  { status: 401, url: /\/api\/v1\/admin\/me$/ },
];

const FAILED_RESOURCE = /^Failed to load resource: the server responded with a status of (\d{3})\b/;

function isAllowedUrl(url: string): boolean {
  if (/^(data|blob|about):/.test(url)) return true;
  let origin: string;
  try {
    origin = new URL(url).origin;
  } catch {
    return false;
  }
  return ALLOWED_ORIGINS.includes(origin);
}

/** Guard state shared by every context of one test. */
class GuardRecorder {
  readonly problems: string[] = [];
  readonly allowed: RegExp[] = [];
  readonly httpAllowed: HttpAllowance[] = [...DEFAULT_HTTP_ALLOWANCES];

  private isAllowedStatus(status: number, url: string): boolean {
    return this.httpAllowed.some((a) => a.status === status && (!a.url || a.url.test(url)));
  }

  private isAllowedConsoleError(text: string, resourceUrl: string): boolean {
    const failed = FAILED_RESOURCE.exec(text);
    if (failed && this.isAllowedStatus(Number(failed[1]), resourceUrl)) return true;
    return this.allowed.some((re) => re.test(text));
  }

  async attach(context: BrowserContext): Promise<void> {
    await context.addInitScript((marker: string) => {
      document.addEventListener('securitypolicyviolation', (e) => {
        console.error(
          `${marker} ${e.violatedDirective} blocked=${e.blockedURI} source=${e.sourceFile}:${e.lineNumber} sample=${e.sample}`,
        );
      });
    }, CSP_MARKER);
    context.on('console', (msg) => {
      if (msg.type() !== 'error') return;
      const text = msg.text();
      const where = msg.page()?.url() ?? '?';
      if (text.includes(CSP_MARKER) || /Content Security Policy/i.test(text)) {
        this.problems.push(`CSP violation on ${where}: ${text}`);
      } else if (!this.isAllowedConsoleError(text, msg.location().url)) {
        this.problems.push(`console error on ${where}: ${text} (${msg.location().url})`);
      }
    });
    context.on('weberror', (err) => {
      this.problems.push(`page error on ${err.page()?.url() ?? '?'}: ${err.error().message}`);
    });
    context.on('request', (req) => {
      if (!isAllowedUrl(req.url()))
        this.problems.push(`request to a foreign origin: ${req.method()} ${req.url()}`);
    });
    context.on('response', (res) => {
      if (res.status() >= 500 && !this.isAllowedStatus(res.status(), res.url())) {
        this.problems.push(`server error ${res.status()} on ${res.request().method()} ${res.url()}`);
      }
    });
  }
}

const recorders = new WeakMap<TestInfo, GuardRecorder>();
function recorderOf(testInfo: TestInfo): GuardRecorder {
  let r = recorders.get(testInfo);
  if (!r) {
    r = new GuardRecorder();
    recorders.set(testInfo, r);
  }
  return r;
}

export const test = base.extend<Options & Fixtures>({
  clientIp: [async ({}, use) => use(randomInternalIp()), { option: true }],

  extraHTTPHeaders: async ({ extraHTTPHeaders, clientIp }, use) => {
    await use({ ...extraHTTPHeaders, [CLIENT_IP_HEADER]: clientIp });
  },

  state: async ({}, use) => {
    await use(loadState());
  },

  newContext: async ({ browser, contextOptions }, use, testInfo) => {
    const opened: BrowserContext[] = [];
    await use(async (options = {}) => {
      const { clientIp, ...rest } = options;
      const context = await browser.newContext({
        ...contextOptions,
        ignoreHTTPSErrors: true,
        locale: 'en-US',
        timezoneId: 'Europe/Paris',
        viewport: { width: 1280, height: 800 },
        acceptDownloads: true,
        ...rest,
        extraHTTPHeaders: { ...rest.extraHTTPHeaders, [CLIENT_IP_HEADER]: clientIp ?? randomInternalIp() },
      });
      await recorderOf(testInfo).attach(context);
      opened.push(context);
      return context;
    });
    for (const c of opened) await c.close();
  },

  guards: [
    async ({ context }, use, testInfo) => {
      const recorder = recorderOf(testInfo);
      await recorder.attach(context);
      await use({
        allowConsoleErrors: (...patterns) => recorder.allowed.push(...patterns),
        allowHttpError: (status, url) => recorder.httpAllowed.push({ status, url }),
        problems: () => [...recorder.problems],
      });
      if (recorder.problems.length > 0) {
        const problems = recorder.problems;
        throw new Error(`browser guards reported ${problems.length} problem(s):\n  ${problems.join('\n  ')}`);
      }
    },
    { auto: true },
  ],
});

export { expect };

const axeSource = fs.readFileSync(createRequire(import.meta.url).resolve('axe-core/axe.min.js'), 'utf8');

/** Options of checkA11y. */
export interface A11yOptions {
  /** CSS selectors excluded from the analysis (justify each use in the test). */
  exclude?: string[];
  /** axe rule ids disabled for this check (justify each use in the test). */
  disableRules?: string[];
}

/**
 * Runs axe-core (WCAG 2.0 / 2.1, levels A and AA) on the current page, in the current theme and
 * then in the other one (the data-theme attribute of the root element is switched, then
 * restored), and fails on any violation; messages are prefixed with the theme. axe is injected
 * from node_modules through the DevTools protocol (no CDN, no CSP exception needed on the
 * server).
 */
export async function checkA11y(page: Page, opts: A11yOptions = {}): Promise<void> {
  await page.evaluate(axeSource);
  const original = await page.evaluate(() => document.documentElement.dataset.theme ?? 'light');
  const other = original === 'dark' ? 'light' : 'dark';
  const violations: string[] = [];
  try {
    for (const theme of [original, other]) {
      await page.evaluate((t) => {
        document.documentElement.dataset.theme = t;
      }, theme);
      const found = await runAxe(page, opts);
      violations.push(...found.map((v) => `[${theme} theme] ${v}`));
    }
  } finally {
    await page.evaluate((t) => {
      document.documentElement.dataset.theme = t;
    }, original);
  }
  expect(violations, `axe violations on ${page.url()}`).toEqual([]);
}

/** One axe-core run on the page in its current state; returns one message per violation. */
async function runAxe(page: Page, opts: A11yOptions): Promise<string[]> {
  return page.evaluate(
    async ({ exclude, disableRules }) => {
      const axe = (window as unknown as { axe: { run: (ctx: unknown, o: unknown) => Promise<AxeResults> } })
        .axe;
      interface AxeResults {
        violations: {
          id: string;
          impact: string;
          help: string;
          nodes: { target: string[]; failureSummary?: string }[];
        }[];
      }
      const rules = Object.fromEntries(disableRules.map((id) => [id, { enabled: false }]));
      const result = await axe.run(
        { include: [document], exclude: exclude.map((s) => [s]) },
        { runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'] }, rules },
      );
      return result.violations.map(
        (v) =>
          `${v.id} (${v.impact}) ${v.help}: ` +
          v.nodes
            .slice(0, 5)
            .map((n) => `${n.target.join(' ')} -> ${(n.failureSummary ?? '').replace(/\s+/g, ' ')}`)
            .join(' | '),
      );
    },
    { exclude: opts.exclude ?? [], disableRules: opts.disableRules ?? [] },
  );
}

/**
 * Checks the browser storage of the page's origin: localStorage may only hold the language
 * choice (tt.lang) and sessionStorage only the listed keys (none by default; the deposit screen
 * keeps "tt.upload" while an upload is resumable). Threat model T-160.
 */
export async function expectCleanStorage(page: Page, opts: { allowSession?: string[] } = {}): Promise<void> {
  const keys = await page.evaluate(() => ({
    local: Object.keys(localStorage),
    session: Object.keys(sessionStorage),
  }));
  expect(
    keys.local.filter((k) => k !== 'tt.lang'),
    'unexpected localStorage keys',
  ).toEqual([]);
  const allowSession = opts.allowSession ?? [];
  expect(
    keys.session.filter((k) => !allowSession.includes(k)),
    'unexpected sessionStorage keys',
  ).toEqual([]);
}
