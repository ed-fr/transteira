// Integrated help (CLAUDE.md section 4.2, plan step 20): the contextual links of the public and
// admin screens (footer "Help" link, "?" icon next to complex screen headings) open
// /help/<topic> on the right section, which receives the focus, with the page title
// "Section – Guide"; the screenshots of the opened guide load lazily from /assets/ under the
// strict CSP; the table of contents, the links to other topics and the language switch work;
// a delegated admin is never offered the super-admin guide; an unknown topic falls back to the
// index with a message; the help passes axe in both languages; and the first load of the public
// home downloads neither a guide nor a screenshot.
//
// Expected section titles are read from the guides themselves (docs/user/<lang>/<guide>.md,
// "<!-- topic: x -->" markers), so that an editorial change of a heading does not break the
// scenarios, while a topic moved to another section or guide does.
import type { Page, Request } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
import { internalEmail, textFile } from '../support/data';
import { downloadPath, tokenDeposit } from '../support/deposit';
import { HOSTS, ORIGINS, REPO_ROOT, STORAGE_DELEGATE, STORAGE_SUPER } from '../support/env';
import { checkA11y, expect, expectCleanStorage, test } from '../support/fixtures';
import { BROWSER_LOCALE, LANGS, msg, type Lang } from '../support/i18n';

type GuideId = 'depositor' | 'recipient' | 'delegated-admin' | 'super-admin';

/** A section of a guide, as written in the Markdown source. */
interface Section {
  title: string;
  level: number;
  topic?: string;
  /** Alternative texts of the screenshots of the section. */
  images: string[];
  /** Links to other help topics ([text](topic:x)) of the section. */
  topicLinks: { text: string; topic: string }[];
}

/** Outline of a guide: its title and its sections (the first one is the title). */
interface Outline {
  title: string;
  sections: Section[];
}

/** Plain text of an inline Markdown fragment (the subset of the guides). */
function plain(markdown: string): string {
  return markdown
    .replace(/\[([^\]]*)\]\([^)]*\)/g, '$1')
    .replace(/\*\*|\*|`/g, '')
    .trim();
}

const outlines = new Map<string, Outline>();

/** Outline of docs/user/<lang>/<guide>.md (implicit topic of the title: the guide id). */
function outline(lang: Lang, guide: GuideId): Outline {
  const key = `${lang}/${guide}`;
  const cached = outlines.get(key);
  if (cached) return cached;
  const source = fs.readFileSync(path.join(REPO_ROOT, 'docs', 'user', lang, `${guide}.md`), 'utf8');
  const sections: Section[] = [];
  let pendingTopic: string | undefined;
  for (const line of source.split(/\r?\n/)) {
    const marker = /^<!--\s*topic:\s*(\S+)\s*-->$/.exec(line.trim());
    if (marker) {
      pendingTopic = marker[1];
      continue;
    }
    const heading = /^(#{1,3})\s+(.*)$/.exec(line);
    if (heading) {
      const level = heading[1]!.length;
      sections.push({
        title: plain(heading[2]!),
        level,
        topic: level === 1 ? guide : pendingTopic,
        images: [],
        topicLinks: [],
      });
      pendingTopic = undefined;
      continue;
    }
    const current = sections[sections.length - 1];
    if (!current) continue;
    const image = /^!\[([^\]]*)\]\(/.exec(line.trim());
    if (image) current.images.push(image[1]!);
    for (const link of line.matchAll(/\[([^\]]+)\]\(topic:([a-z0-9-]+)\)/g)) {
      current.topicLinks.push({ text: plain(link[1]!), topic: link[2]! });
    }
  }
  const result = { title: sections[0]!.title, sections };
  outlines.set(key, result);
  return result;
}

/** Section of a topic in a guide (fails when the guide does not hold the topic). */
function section(lang: Lang, guide: GuideId, topic: string): Section {
  const found = outline(lang, guide).sections.find((s) => s.topic === topic);
  if (!found) throw new Error(`topic ${topic} is not in docs/user/${lang}/${guide}.md`);
  return found;
}

/** Page title of a help section without the site name: "Section – Guide" (the guide title alone on its title). */
function helpTitle(lang: Lang, guide: GuideId, topic: string): string {
  const s = section(lang, guide, topic);
  const guideTitle = outline(lang, guide).title;
  return s.level === 1 ? guideTitle : `${s.title} – ${guideTitle}`;
}

/** Heading of a help section in the page. */
function sectionHeading(page: Page, s: Section) {
  return page.getByRole('heading', { name: s.title, level: s.level, exact: true });
}

/**
 * Checks that the help shows the section of the topic: URL /…/help/<topic>, the section heading
 * holds the focus (the help moves it there after the router focused the page title), and the
 * document title starts with "Section – Guide".
 */
async function expectHelpSection(
  page: Page,
  lang: Lang,
  guide: GuideId,
  topic: string,
  base: '' | '/admin',
): Promise<void> {
  await expect(page).toHaveURL(new RegExp(`${base}/help/${topic}$`));
  const s = section(lang, guide, topic);
  await expect(sectionHeading(page, s)).toBeFocused();
  await expect(page).toHaveTitle(new RegExp(`^${escapeRegExp(helpTitle(lang, guide, topic))}( – |$)`));
}

function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** The footer help link ("Help"). */
function footerHelp(page: Page, lang: Lang = 'en') {
  return page
    .getByRole('contentinfo')
    .getByRole('link', { name: msg(lang, 'components.help.label'), exact: true });
}

/**
 * Scrolls every screenshot of the rendered guide into view (they are lazy) and checks that each
 * one is served from /assets/ and decoded (naturalWidth > 0). The guards fail the test on a CSP
 * violation (img-src) or a request to another origin.
 */
async function expectGuideImagesLoaded(page: Page, expectedAlts: string[]): Promise<void> {
  const images = page.getByRole('article').getByRole('img');
  await expect(images).toHaveCount(expectedAlts.length);
  for (let i = 0; i < expectedAlts.length; i++) {
    const img = images.nth(i);
    await expect(img).toHaveAttribute('alt', expectedAlts[i]!);
    await expect(img).toHaveAttribute('loading', 'lazy');
    const src = await img.getAttribute('src');
    expect(new URL(src!, page.url()).pathname, `screenshot ${i}`).toMatch(/^\/assets\/[^/]+\.png$/);
    await img.scrollIntoViewIfNeeded();
    await expect
      .poll(() => img.evaluate((el: HTMLImageElement) => el.complete && el.naturalWidth), {
        message: `screenshot "${expectedAlts[i]}" decoded`,
      })
      .toBeGreaterThan(0);
  }
}

/** Alternative texts of every screenshot of a guide, in order. */
function guideImages(lang: Lang, guide: GuideId): string[] {
  return outline(lang, guide).sections.flatMap((s) => s.images);
}

/** Creates an available transfer of entity A (API token) and returns the path of its download page. */
async function downloadPage(token: string, label: string): Promise<string> {
  const transfer = await tokenDeposit(
    token,
    internalEmail(`${label}-sender`),
    { recipients: [internalEmail(`${label}-recipient`)], files: [textFile(`${label}.txt`, `help ${label}`)] },
    { host: HOSTS.a },
  );
  return downloadPath(transfer.downloadUrl!);
}

test.describe('public contextual help', () => {
  test('footer link of the deposit home opens the deposit section, focused', async ({ page, state }) => {
    await page.goto(`${state.tenants.a.origin}/`);
    await expect(
      page.getByRole('heading', { name: msg('en', 'deposit.email.title'), level: 1 }),
    ).toBeVisible();
    await footerHelp(page).click();
    await expectHelpSection(page, 'en', 'depositor', 'deposit', '');
    // The help page has no help link of its own, and offers a way back.
    await expect(footerHelp(page)).toHaveCount(0);
    await expect(page.getByRole('link', { name: msg('en', 'help.back') })).toBeVisible();
    await expect(page.getByRole('navigation', { name: msg('en', 'help.toc') })).toBeVisible();
    await expectCleanStorage(page);

    // "Back to the previous screen" returns to the deposit home.
    await page.getByRole('link', { name: msg('en', 'help.back') }).click();
    await expect(page).toHaveURL(`${state.tenants.a.origin}/`);
    await expect(
      page.getByRole('heading', { name: msg('en', 'deposit.email.title'), level: 1 }),
    ).toBeVisible();
  });

  test('footer link of the download page opens the recipient guide; screenshots, TOC, topic links', async ({
    page,
    state,
  }) => {
    await page.goto(`${state.tenants.a.origin}${await downloadPage(state.apiTokenA, 'help-download')}`);
    await expect(page.getByRole('heading', { name: msg('en', 'download.title'), level: 1 })).toBeVisible();
    await footerHelp(page).click();
    await expectHelpSection(page, 'en', 'recipient', 'download', '');
    await expectGuideImagesLoaded(page, guideImages('en', 'recipient'));

    // Table of contents: a section of the same guide gets the focus, the URL does not change.
    const helpUrl = page.url();
    const integrity = section('en', 'recipient', 'download-integrity');
    await page
      .getByRole('navigation', { name: msg('en', 'help.toc') })
      .getByRole('link', { name: integrity.title, exact: true })
      .click();
    await expect(sectionHeading(page, integrity)).toBeFocused();
    await expect(sectionHeading(page, integrity)).toBeInViewport();
    expect(page.url()).toBe(helpUrl);

    // A topic: link opens another topic (here in the depositor guide), focused.
    const files = section('en', 'recipient', 'download-files');
    const link = files.topicLinks[0];
    expect(link, 'the "one file or all at once" section links to another topic').toBeDefined();
    await page.getByRole('article').getByRole('link', { name: link!.text, exact: true }).click();
    const target = link!.topic;
    const guide: GuideId = outline('en', 'recipient').sections.some((s) => s.topic === target)
      ? 'recipient'
      : 'depositor';
    await expectHelpSection(page, 'en', guide, target, '');
  });

  test('language switch reloads the same topic in French', async ({ page, state }) => {
    await page.goto(`${state.tenants.a.origin}/help/download`);
    await expectHelpSection(page, 'en', 'recipient', 'download', '');
    const url = page.url();
    const englishSrc = await page.getByRole('article').getByRole('img').first().getAttribute('src');
    await page
      .getByRole('combobox', { name: msg('en', 'components.languageSwitch.label') })
      .selectOption('fr');
    await expect(page.locator('html')).toHaveAttribute('lang', 'fr');
    await expect(sectionHeading(page, section('fr', 'recipient', 'download'))).toBeFocused();
    await expect(page).toHaveTitle(new RegExp(`^${escapeRegExp(helpTitle('fr', 'recipient', 'download'))}`));
    expect(page.url()).toBe(url);
    await expectGuideImagesLoaded(page, guideImages('fr', 'recipient'));
    // The French guide shows the French screenshots.
    expect(await page.getByRole('article').getByRole('img').first().getAttribute('src')).not.toBe(englishSrc);
    await expectCleanStorage(page);
  });

  test('an unknown topic shows the index with a message', async ({ page, state }) => {
    await page.goto(`${state.tenants.a.origin}/help/no-such-topic`);
    await expect(page.getByRole('heading', { name: msg('en', 'common.help.title'), level: 1 })).toBeVisible();
    await expect(page.getByText(msg('en', 'help.unknownTopic', { topic: 'no-such-topic' }))).toBeVisible();
    for (const guide of ['depositor', 'recipient'] as const) {
      await expect(page.getByRole('link', { name: outline('en', guide).title, exact: true })).toBeVisible();
    }
    // Admin guides are never offered by the public application.
    await expect(page.getByRole('link', { name: outline('en', 'delegated-admin').title })).toHaveCount(0);
    await expect(page.getByRole('link', { name: outline('en', 'super-admin').title })).toHaveCount(0);
    // An admin topic is unknown here too.
    await page.goto(`${state.tenants.a.origin}/help/tenant-network`);
    await expect(page.getByText(msg('en', 'help.unknownTopic', { topic: 'tenant-network' }))).toBeVisible();
  });

  test('the first load of the public home requests neither a guide nor a screenshot', async ({
    page,
    state,
  }) => {
    const before: string[] = [];
    const record = (into: string[]) => (req: Request) => into.push(new URL(req.url()).pathname);
    const onBefore = record(before);
    page.on('request', onBefore);
    await page.goto(`${state.tenants.a.origin}/`);
    await expect(
      page.getByRole('heading', { name: msg('en', 'deposit.email.title'), level: 1 }),
    ).toBeVisible();
    await page.waitForLoadState('networkidle');
    page.off('request', onBefore);
    expect(
      before.filter((p) => p.endsWith('.png')),
      'screenshots requested by the home',
    ).toEqual([]);

    // Opening the help (in-app navigation) loads the guide chunks: none was loaded before.
    const after: string[] = [];
    page.on('request', record(after));
    await footerHelp(page).click();
    await expectHelpSection(page, 'en', 'depositor', 'deposit', '');
    const helpChunks = after.filter((p) => p.startsWith('/assets/') && p.endsWith('.js'));
    expect(helpChunks.length, 'the help loads its guides on demand').toBeGreaterThan(0);
    expect(
      helpChunks.filter((p) => before.includes(p)),
      'help chunks requested by the home',
    ).toEqual([]);
  });
});

test.describe('admin contextual help', () => {
  test.use({ storageState: STORAGE_SUPER });

  /** Admin screens with a "?" icon next to their heading. */
  const iconScreens: { name: string; path: (tenantId: string) => string; titleKey: string; topic: string }[] =
    [
      {
        name: 'tenant network',
        path: (id) => `/admin/tenants/${id}/network`,
        titleKey: 'adminTenants.network.title',
        topic: 'tenant-network',
      },
      {
        name: 'tenant SMTP',
        path: (id) => `/admin/tenants/${id}/smtp`,
        titleKey: 'adminTenants.smtp.title',
        topic: 'tenant-smtp',
      },
      {
        name: 'API tokens',
        path: (id) => `/admin/tenants/${id}/tokens`,
        titleKey: 'adminOps.tokens.title',
        topic: 'tenant-tokens',
      },
      {
        name: 'master key',
        path: () => '/admin/system/master-key',
        titleKey: 'adminSystem.masterKey.title',
        topic: 'system-master-key',
      },
    ];

  for (const screen of iconScreens) {
    test(`help icon of the ${screen.name} screen opens its section, focused`, async ({ page, state }) => {
      await page.goto(`${ORIGINS.admin}${screen.path(state.tenants.a.id)}`);
      const title = msg('en', screen.titleKey);
      await expect(page.getByRole('heading', { name: title, level: 1 })).toBeVisible();
      const guide: GuideId = screen.topic.startsWith('system-') ? 'super-admin' : 'delegated-admin';
      // The footer link points at the same topic.
      await expect(footerHelp(page)).toHaveAttribute('href', `/admin/help/${screen.topic}`);
      await page.getByRole('link', { name: msg('en', 'help.icon', { title }), exact: true }).click();
      await expectHelpSection(page, 'en', guide, screen.topic, '/admin');
    });
  }

  test('footer link of the dashboard opens the home page section; screenshots load', async ({ page }) => {
    await page.goto(`${ORIGINS.admin}/admin/`);
    await expect(page.getByRole('heading', { name: msg('en', 'admin.home.title'), level: 1 })).toBeVisible();
    await footerHelp(page).click();
    await expectHelpSection(page, 'en', 'delegated-admin', 'admin', '/admin');
    await expectGuideImagesLoaded(page, guideImages('en', 'delegated-admin'));

    // The super-admin guide opens for a super admin, directly by its topic (the build refuses a
    // topic: link from the delegated-admin guide to the super-admin guide).
    await page.goto(`${ORIGINS.admin}/admin/help/super-admin`);
    await expectHelpSection(page, 'en', 'super-admin', 'super-admin', '/admin');
    await expect(page).toHaveTitle(new RegExp(`^${escapeRegExp(outline('en', 'super-admin').title)} – `));
    await expectGuideImagesLoaded(page, guideImages('en', 'super-admin'));
  });

  test('the help index of a super admin lists both admin guides', async ({ page }) => {
    await page.goto(`${ORIGINS.admin}/admin/help`);
    await expect(page.getByRole('heading', { name: msg('en', 'common.help.title'), level: 1 })).toBeVisible();
    for (const guide of ['delegated-admin', 'super-admin'] as const) {
      await expect(page.getByRole('link', { name: outline('en', guide).title, exact: true })).toBeVisible();
    }
  });
});

test.describe('delegated admin help', () => {
  test.use({ storageState: STORAGE_DELEGATE });

  test('the super-admin guide is neither listed nor reachable', async ({ page }) => {
    await page.goto(`${ORIGINS.admin}/admin/help`);
    await expect(page.getByRole('heading', { name: msg('en', 'common.help.title'), level: 1 })).toBeVisible();
    await expect(
      page.getByRole('link', { name: outline('en', 'delegated-admin').title, exact: true }),
    ).toBeVisible();
    await expect(page.getByRole('link', { name: outline('en', 'super-admin').title })).toHaveCount(0);

    await page.goto(`${ORIGINS.admin}/admin/help/system-master-key`);
    await expect(
      page.getByText(msg('en', 'help.unknownTopic', { topic: 'system-master-key' })),
    ).toBeVisible();
    await expect(
      page.getByRole('heading', { name: section('en', 'super-admin', 'system-master-key').title }),
    ).toHaveCount(0);
    await expect(page.getByRole('link', { name: outline('en', 'super-admin').title })).toHaveCount(0);

    // Its own guide opens from the dashboard footer.
    await page.goto(`${ORIGINS.admin}/admin/`);
    await footerHelp(page).click();
    await expectHelpSection(page, 'en', 'delegated-admin', 'admin', '/admin');
  });
});

test.describe('anonymous admin help', () => {
  test('footer link of the sign-in page opens the sign-in section', async ({ page }) => {
    await page.goto(`${ORIGINS.admin}/admin/login`);
    await expect(
      page.getByRole('heading', { name: msg('en', 'adminAuth.login.title'), level: 1 }),
    ).toBeVisible();
    await footerHelp(page).click();
    await expectHelpSection(page, 'en', 'delegated-admin', 'login', '/admin');
    // A visitor not signed in (first-run setup, sign-in) is offered both admin guides.
    await page.getByRole('link', { name: msg('en', 'help.indexLink') }).click();
    for (const guide of ['delegated-admin', 'super-admin'] as const) {
      await expect(page.getByRole('link', { name: outline('en', guide).title, exact: true })).toBeVisible();
    }
    await expectCleanStorage(page);
  });
});

for (const lang of LANGS) {
  test.describe(`help accessibility (${lang})`, () => {
    test.use({ locale: BROWSER_LOCALE[lang] });

    test('public index and guide', async ({ page, state }) => {
      await page.goto(`${state.tenants.a.origin}/help`);
      await expect(
        page.getByRole('heading', { name: msg(lang, 'common.help.title'), level: 1 }),
      ).toBeVisible();
      await expect(page.locator('html')).toHaveAttribute('lang', lang);
      await expect(
        page.getByRole('link', { name: outline(lang, 'depositor').title, exact: true }),
      ).toBeVisible();
      await checkA11y(page);

      await page.getByRole('link', { name: outline(lang, 'recipient').title, exact: true }).click();
      await expectHelpSection(page, lang, 'recipient', 'recipient', '');
      await expectGuideImagesLoaded(page, guideImages(lang, 'recipient'));
      await checkA11y(page);
    });

    test.describe('signed in as the super admin', () => {
      test.use({ storageState: STORAGE_SUPER });

      test('admin index and guide', async ({ page }) => {
        await page.goto(`${ORIGINS.admin}/admin/help`);
        await expect(
          page.getByRole('heading', { name: msg(lang, 'common.help.title'), level: 1 }),
        ).toBeVisible();
        await checkA11y(page);
        await page.goto(`${ORIGINS.admin}/admin/help/tenant-network`);
        await expectHelpSection(page, lang, 'delegated-admin', 'tenant-network', '/admin');
        await checkA11y(page);
      });
    });
  });
}
