import type { ComponentProps } from 'svelte';
import { render } from 'svelte/server';
import { beforeAll, describe, expect, it, vi } from 'vitest';
import { setLocale } from '../shared/i18n/i18n.svelte';
import HelpPrintDocument from './HelpPrintDocument.svelte';
import { PLAIN_LINKS, UNKNOWN_VERSION, loadVersion, printGuides, printPage } from './print';
import type { HelpTenantRules } from './rules';
import type { HelpGuide, HelpGuideSet } from './types';

const guide = (
  id: 'depositor' | 'recipient',
  title: string,
  extra: HelpGuide['sections'] = [],
): HelpGuide => ({
  id,
  title,
  sections: [{ id: `${id}-guide`, level: 1, title, topic: id, blocks: [] }, ...extra],
});

const depositor = guide('depositor', 'Depositor guide', [
  {
    id: 'send',
    level: 2,
    title: 'Send files',
    blocks: [
      {
        type: 'paragraph',
        content: [
          { type: 'text', text: 'See ' },
          { type: 'topic', topic: 'download', children: [{ type: 'text', text: 'the download' }] },
          { type: 'text', text: ' and ' },
          { type: 'anchor', target: 'reply', children: [{ type: 'text', text: 'replies' }] },
        ],
      },
      { type: 'rules', set: 'limits' },
      { type: 'figure', src: '/assets/shot.png', alt: 'Deposit form', width: 10, height: 10 },
    ],
  },
  { id: 'reply', level: 2, title: 'Receive a reply', when: 'transferReply', blocks: [] },
]);
const recipient = guide('recipient', 'Recipient guide', [
  { id: 'download', level: 2, title: 'Download', blocks: [] },
]);

const set: HelpGuideSet = {
  lang: 'en',
  app: 'public',
  // Recipient first: the printable version still starts with the depositor guide.
  guides: [recipient, depositor],
  topics: {},
};

const rules: HelpTenantRules = {
  name: 'Entity A',
  limits: { maxTransferBytes: 2048, expiryDays: [7] },
  features: {
    remoteInternalDeposit: false,
    transferReply: false,
    recipientVerification: false,
    maxDownloads: false,
    folders: false,
    recipientRestrictions: false,
    antivirus: 'enabled',
  },
};

describe('printable version logic', () => {
  it('orders the guides depositor then recipient', () => {
    expect(printGuides(set).map((g) => g.id)).toEqual(['depositor', 'recipient']);
    expect(printGuides({ ...set, guides: [recipient] }).map((g) => g.id)).toEqual(['recipient']);
  });

  it('reads the version, a dash when it fails or is empty', async () => {
    await expect(loadVersion(() => Promise.resolve({ version: '1.1.0' }))).resolves.toBe('1.1.0');
    await expect(loadVersion(() => Promise.resolve({ version: ' ' }))).resolves.toBe(UNKNOWN_VERSION);
    await expect(loadVersion(() => Promise.reject(new Error('offline')))).resolves.toBe(UNKNOWN_VERSION);
    expect(UNKNOWN_VERSION).toBe('—');
  });

  it('opens the print dialog', () => {
    const target = { print: vi.fn() };
    printPage(target);
    expect(target.print).toHaveBeenCalledOnce();
  });

  it('renders links as text', () => {
    expect(PLAIN_LINKS.plain).toBe(true);
    expect(PLAIN_LINKS.topicHref('download')).toBe('');
    expect(() => PLAIN_LINKS.link({} as HTMLAnchorElement).destroy()).not.toThrow();
    expect(PLAIN_LINKS.onanchor('send', {} as MouseEvent)).toBeUndefined();
  });
});

describe('HelpPrintDocument', () => {
  beforeAll(async () => {
    await setLocale('en');
  });

  const generatedAt = new Date(2026, 9, 30, 12);
  const html = (props: Partial<ComponentProps<typeof HelpPrintDocument>> = {}): string =>
    render(HelpPrintDocument, {
      props: {
        rules,
        guides: printGuides(set),
        failed: false,
        version: '1.1.0',
        generatedAt,
        helpHref: '/help',
        link: () => ({ destroy: () => undefined }),
        onretry: () => undefined,
        ...props,
      },
    }).body.replace(/<!--.*?-->/g, '');

  it('shows the tenant, the date, the version and the notice', () => {
    const body = html({ logoUrl: '/api/v1/tenant/assets/logo' });
    expect(body).toContain('User documentation – Entity A');
    expect(body).toContain('Generated on October 30, 2026');
    expect(body).toContain('Application version 1.1.0');
    expect(body).toContain('The rules in force are always those applied by the service');
    expect(body).toContain('Print / Save as PDF');
    expect(body).toContain('src="/api/v1/tenant/assets/logo"');
    expect(html({ logoUrl: 'javascript:alert(1)' })).not.toContain('javascript:');
  });

  it('shows a dash when the version is unknown', () => {
    expect(html({ version: undefined })).toContain('Application version —');
  });

  it('prints the guides in order, with rules, hidden sections left out and links as text', () => {
    const body = html();
    const dep = body.indexOf('Depositor guide');
    const rec = body.indexOf('Recipient guide');
    expect(dep).toBeGreaterThan(-1);
    expect(rec).toBeGreaterThan(dep);
    expect(body).toMatch(/<h2[^>]*>\s*Depositor guide/);
    expect(body).toMatch(/<h3[^>]*>\s*Send files/);
    expect(body).not.toContain('Receive a reply');
    expect(body).toContain('Maximum size per transfer: 2 kB.');
    expect(body).toContain('src="/assets/shot.png"');
    expect(body).toContain('See the download and replies');
    expect(body).not.toContain('id="help-send"');
    expect(body).not.toContain('Contents');
  });

  it('shows the loading state and the error with a retry', () => {
    expect(html({ guides: undefined })).toContain('Loading the help');
    const failed = html({ failed: true });
    expect(failed).toContain('The help could not be loaded.');
    expect(failed).not.toContain('Depositor guide');
  });
});
