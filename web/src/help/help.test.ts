import { describe, expect, it, vi } from 'vitest';
import {
  ADMIN_GUIDES,
  MAX_SHOWN_TOPIC_LENGTH,
  PUBLIC_GUIDES,
  adminGuides,
  guideTopic,
  helpPageTitle,
  plainClick,
  resolveHelp,
  sectionDomId,
  shownTopic,
  tableOfContents,
  visibleGuides,
} from './help';
import { createHelpLoader, HELP_FALLBACK_LANGUAGE } from './load';
import { helpTitle, pageTitleOf } from './title.svelte';
import type { HelpGuide, HelpGuideSet } from './types';

const delegated: HelpGuide = {
  id: 'delegated-admin',
  title: 'Delegated admin guide',
  sections: [
    {
      id: 'delegated-admin-guide',
      level: 1,
      title: 'Delegated admin guide',
      topic: 'delegated-admin',
      blocks: [],
    },
    { id: 'entities', level: 2, title: 'Entities', topic: 'tenants', blocks: [] },
    { id: 'network', level: 3, title: 'Network', topic: 'tenant-network', blocks: [] },
    { id: 'smtp', level: 3, title: 'SMTP', blocks: [] },
    { id: 'tokens', level: 2, title: 'Tokens', blocks: [] },
  ],
};
const superGuide: HelpGuide = {
  id: 'super-admin',
  title: 'Super admin guide',
  sections: [
    { id: 'super-admin-guide', level: 1, title: 'Super admin guide', topic: 'super-admin', blocks: [] },
    { id: 'key', level: 2, title: 'Master key', topic: 'system-master-key', blocks: [] },
  ],
};
const set: HelpGuideSet = {
  lang: 'en',
  app: 'admin',
  guides: [delegated, superGuide],
  topics: {
    'delegated-admin': { guide: 'delegated-admin', section: 'delegated-admin-guide' },
    tenants: { guide: 'delegated-admin', section: 'entities' },
    'tenant-network': { guide: 'delegated-admin', section: 'network' },
    'super-admin': { guide: 'super-admin', section: 'super-admin-guide' },
    'system-master-key': { guide: 'super-admin', section: 'key' },
    broken: { guide: 'delegated-admin', section: 'missing' },
  },
};

describe('guides offered', () => {
  it('splits the guides between the applications', () => {
    expect(PUBLIC_GUIDES).toEqual(['depositor', 'recipient']);
    expect(ADMIN_GUIDES).toEqual(['delegated-admin', 'super-admin']);
  });

  it('hides the super-admin guide from a signed-in delegated admin only', () => {
    expect(adminGuides('super_admin')).toEqual(ADMIN_GUIDES);
    expect(adminGuides(undefined)).toEqual(ADMIN_GUIDES);
    expect(adminGuides('delegated_admin')).toEqual(['delegated-admin']);
    expect(visibleGuides(set, ['delegated-admin'])).toEqual([delegated]);
  });
});

describe('resolveHelp', () => {
  it('shows the index without a topic', () => {
    expect(resolveHelp(set, undefined, ADMIN_GUIDES)).toEqual({
      kind: 'index',
      guides: [delegated, superGuide],
    });
    expect(resolveHelp(set, '', ADMIN_GUIDES)).toMatchObject({ kind: 'index' });
  });

  it('opens the guide and the section of a topic', () => {
    expect(resolveHelp(set, 'tenant-network', ADMIN_GUIDES)).toEqual({
      kind: 'guide',
      guide: delegated,
      section: delegated.sections[2],
    });
  });

  it('falls back to the index for an unknown, hidden or broken topic', () => {
    for (const topic of ['nope', 'toString', '__proto__', 'broken']) {
      expect(resolveHelp(set, topic, ADMIN_GUIDES)).toEqual({
        kind: 'index',
        guides: [delegated, superGuide],
        unknownTopic: topic,
      });
    }
    expect(resolveHelp(set, 'system-master-key', ['delegated-admin'])).toEqual({
      kind: 'index',
      guides: [delegated],
      unknownTopic: 'system-master-key',
    });
  });
});

describe('guide helpers', () => {
  it('gives the topic of a guide', () => {
    expect(guideTopic(delegated)).toBe('delegated-admin');
    expect(guideTopic({ id: 'recipient', title: 'R', sections: [] })).toBe('recipient');
  });

  it('builds a nested table of contents', () => {
    expect(tableOfContents(delegated)).toEqual([
      {
        id: 'entities',
        title: 'Entities',
        children: [
          { id: 'network', title: 'Network', children: [] },
          { id: 'smtp', title: 'SMTP', children: [] },
        ],
      },
      { id: 'tokens', title: 'Tokens', children: [] },
    ]);
    const orphan: HelpGuide = {
      id: 'recipient',
      title: 'R',
      sections: [{ id: 'x', level: 3, title: 'X', blocks: [] }],
    };
    expect(tableOfContents(orphan)).toEqual([{ id: 'x', title: 'X', children: [] }]);
  });

  it('prefixes the element ids of the sections', () => {
    expect(sectionDomId('créer-une-entité')).toBe('help-créer-une-entité');
  });

  it('titles the page', () => {
    expect(helpPageTitle(undefined, 'Help')).toBe('Help');
    expect(helpPageTitle(resolveHelp(set, undefined, ADMIN_GUIDES), 'Help')).toBe('Help');
    expect(helpPageTitle(resolveHelp(set, 'delegated-admin', ADMIN_GUIDES), 'Help')).toBe(
      'Delegated admin guide',
    );
    expect(helpPageTitle(resolveHelp(set, 'tenants', ADMIN_GUIDES), 'Help')).toBe(
      'Entities – Delegated admin guide',
    );
  });
});

describe('help page title store', () => {
  it('overrides the route title on the help routes only', () => {
    expect(pageTitleOf(true, 'Help')).toBe('Help');
    helpTitle.current = 'SMTP – Guide';
    expect(pageTitleOf(true, 'Help')).toBe('SMTP – Guide');
    expect(pageTitleOf(false, 'Home')).toBe('Home');
    helpTitle.current = undefined;
  });
});

describe('createHelpLoader', () => {
  const frAdmin: HelpGuideSet = { ...set, lang: 'fr' };

  it('loads a set once and caches it', async () => {
    const loader = vi.fn(async () => ({ default: frAdmin }));
    const load = createHelpLoader({ './generated/fr-admin.ts': loader });
    expect(await load('admin', 'fr')).toBe(frAdmin);
    expect(await load('admin', 'fr')).toBe(frAdmin);
    expect(loader).toHaveBeenCalledTimes(1);
  });

  it('falls back to English for a language without guides', async () => {
    const load = createHelpLoader({
      [`./generated/${HELP_FALLBACK_LANGUAGE}-admin.ts`]: async () => ({ default: set }),
    });
    expect(await load('admin', 'de')).toBe(set);
  });

  it('rejects when no guides exist, and retries a failed load', async () => {
    await expect(createHelpLoader({})('public', 'fr')).rejects.toThrow('no guides for public');
    const loader = vi
      .fn<() => Promise<{ default: HelpGuideSet }>>()
      .mockRejectedValueOnce(new Error('network'))
      .mockResolvedValueOnce({ default: frAdmin });
    const load = createHelpLoader({ './generated/fr-admin.ts': loader });
    await expect(load('admin', 'fr')).rejects.toThrow('network');
    await Promise.resolve();
    expect(await load('admin', 'fr')).toBe(frAdmin);
    expect(loader).toHaveBeenCalledTimes(2);
  });

  it('loads the generated modules', async () => {
    const { loadPublicGuides } = await import('./publicGuides');
    const { loadAdminGuides } = await import('./adminGuides');
    const publicSet = await loadPublicGuides('fr');
    expect(publicSet).toMatchObject({ lang: 'fr', app: 'public' });
    expect(publicSet.guides.map((g) => g.id)).toEqual(PUBLIC_GUIDES);
    const adminSet = await loadAdminGuides('de');
    expect(adminSet).toMatchObject({ lang: 'en', app: 'admin' });
    expect(adminSet.guides.map((g) => g.id)).toEqual(ADMIN_GUIDES);
  });
});

describe('shownTopic', () => {
  it('repeats a well-formed topic only', () => {
    expect(shownTopic('no-such-topic')).toBe('no-such-topic');
    expect(shownTopic('a'.repeat(MAX_SHOWN_TOPIC_LENGTH))).toBe('a'.repeat(MAX_SHOWN_TOPIC_LENGTH));
    expect(shownTopic('a'.repeat(MAX_SHOWN_TOPIC_LENGTH + 1))).toBeUndefined();
    expect(shownTopic('Call 555-0100 now')).toBeUndefined();
    expect(shownTopic('<b>x</b>')).toBeUndefined();
    expect(shownTopic('')).toBeUndefined();
  });
});

describe('plainClick', () => {
  const click = {
    defaultPrevented: false,
    button: 0,
    metaKey: false,
    ctrlKey: false,
    shiftKey: false,
    altKey: false,
  };

  it('accepts a plain primary click only', () => {
    expect(plainClick(click)).toBe(true);
    expect(plainClick({ ...click, defaultPrevented: true })).toBe(false);
    expect(plainClick({ ...click, button: 1 })).toBe(false);
    for (const key of ['metaKey', 'ctrlKey', 'shiftKey', 'altKey'] as const) {
      expect(plainClick({ ...click, [key]: true })).toBe(false);
    }
  });
});
