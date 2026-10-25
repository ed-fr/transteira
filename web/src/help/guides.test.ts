// The real user guides of docs/user against the route tables of the two applications: every help
// topic of a screen opens a section in both languages, in a guide of the right application, and
// a topic of a screen a delegated admin can open is in the guide offered to a delegated admin;
// every contextual help icon (HelpIcon) uses the topic of a route of its application.
import { describe, expect, it } from 'vitest';
import manifestEntries from '../../../docs/user/screenshots/manifest.json';
import { notFoundRoute as adminNotFound, routes as adminRoutes } from '../admin/routes';
import { notFoundRoute as publicNotFound, routes as publicRoutes } from '../public/routes';
import { GUIDE_APPS, GUIDE_IDS, HELP_LANGUAGES, buildHelp, formatError, type GuideSource } from './build';
import type { GuideId, HelpGuideSet } from './types';

const DOCS = '../../../docs/user/';
const guideFiles = import.meta.glob<string>('../../../docs/user/*/*.md', {
  eager: true,
  query: '?raw',
  import: 'default',
});
const images = new Set(Object.keys(import.meta.glob('../../../docs/user/screenshots/*/*.png')));
const manifest = new Set<string>(manifestEntries.map((e) => e.name));
const sources: GuideSource[] = HELP_LANGUAGES.flatMap((lang) =>
  GUIDE_IDS.map((id) => ({
    lang,
    id,
    file: `docs/user/${lang}/${id}.md`,
    source: guideFiles[`${DOCS}${lang}/${id}.md`] ?? '',
  })),
);
const { sets, errors } = buildHelp(sources, {
  manifest,
  imageExists: (lang, name) => images.has(`${DOCS}screenshots/${lang}/${name}.png`),
});

function topicGuide(set: HelpGuideSet | undefined, topic: string): GuideId | undefined {
  return set !== undefined && Object.hasOwn(set.topics, topic) ? set.topics[topic]?.guide : undefined;
}

describe('user guides', () => {
  it('build without error', () => {
    expect(errors.map(formatError)).toEqual([]);
  });

  it.each(HELP_LANGUAGES)('cover every topic of the public routes (%s)', (lang) => {
    const set = sets.find((s) => s.lang === lang && s.app === 'public');
    const missing = [...publicRoutes, publicNotFound]
      .flatMap((r) => (r.helpTopic === undefined ? [] : [r.helpTopic]))
      .filter((topic) => topicGuide(set, topic) === undefined);
    expect(missing).toEqual([]);
  });

  it.each(HELP_LANGUAGES)(
    'cover every topic of the admin routes, where the admin can read it (%s)',
    (lang) => {
      const set = sets.find((s) => s.lang === lang && s.app === 'admin');
      const problems: string[] = [];
      for (const route of [...adminRoutes, adminNotFound]) {
        if (route.helpTopic === undefined) continue;
        const guide = topicGuide(set, route.helpTopic);
        if (guide === undefined) {
          problems.push(`${route.pattern}: topic ${route.helpTopic} missing`);
        } else if (route.access !== 'super' && route.access !== 'setup' && guide !== 'delegated-admin') {
          problems.push(`${route.pattern}: topic ${route.helpTopic} must be in the delegated-admin guide`);
        }
      }
      expect(problems).toEqual([]);
    },
  );

  it('keep the topics of each guide in the guides of its application', () => {
    for (const set of sets) {
      for (const target of Object.values(set.topics)) {
        expect(GUIDE_APPS[target.guide]).toBe(set.app);
      }
    }
  });

  it('have the same topics in every language', () => {
    const topicsOf = (lang: string): string[] =>
      sets
        .filter((s) => s.lang === lang)
        .flatMap((s) => Object.entries(s.topics).map(([topic, target]) => `${target.guide}:${topic}`))
        .sort();
    for (const lang of HELP_LANGUAGES) {
      expect(topicsOf(lang)).toEqual(topicsOf(HELP_LANGUAGES[0] as string));
    }
  });

  it('only use screenshots of the manifest, in their own language', () => {
    const problems: string[] = [];
    for (const set of sets) {
      for (const guide of set.guides) {
        for (const section of guide.sections) {
          for (const block of section.blocks) {
            if (block.type !== 'figure') continue;
            const [lang, file] = block.src.split('/');
            if (lang !== set.lang || !manifest.has((file ?? '').replace(/\.png$/, ''))) {
              problems.push(`${set.lang}/${guide.id}: ${block.src}`);
            }
          }
        }
      }
    }
    expect(problems).toEqual([]);
  });
});

// Sources of every component, to find the topics of the contextual help icons (HelpIcon).
const components = import.meta.glob<string>('../**/*.svelte', {
  eager: true,
  query: '?raw',
  import: 'default',
});

/** Every <HelpIcon …/> of the components: file, application and topic (undefined: not literal). */
function helpIcons(): { file: string; app: string | undefined; topic: string | undefined }[] {
  const icons: { file: string; app: string | undefined; topic: string | undefined }[] = [];
  for (const [file, source] of Object.entries(components)) {
    const app = file.startsWith('../admin/') ? 'admin' : file.startsWith('../public/') ? 'public' : undefined;
    for (const [tag] of source.matchAll(/<HelpIcon\b[\s\S]*?\/?>/g)) {
      const attr = /\btopic=(?:"([^"]*)"|'([^']*)'|\{\s*(["'])([^"']*)\3\s*\})/.exec(tag);
      icons.push({ file, app, topic: attr?.[1] ?? attr?.[2] ?? attr?.[4] });
    }
  }
  return icons;
}

const routeTopics = {
  admin: new Set(
    [...adminRoutes, adminNotFound].flatMap((r) => (r.helpTopic === undefined ? [] : [r.helpTopic])),
  ),
  public: new Set(
    [...publicRoutes, publicNotFound].flatMap((r) => (r.helpTopic === undefined ? [] : [r.helpTopic])),
  ),
};

describe('contextual help icons', () => {
  it('use the literal topic of a route, which opens a section of their application in every language', () => {
    const icons = helpIcons();
    expect(icons.length).toBeGreaterThan(0);
    const problems: string[] = [];
    for (const icon of icons) {
      if (icon.app === undefined) {
        problems.push(`${icon.file}: HelpIcon outside the public and admin applications`);
        continue;
      }
      if (icon.topic === undefined) {
        problems.push(`${icon.file}: the HelpIcon topic must be a literal string (checked by this test)`);
        continue;
      }
      if (!routeTopics[icon.app as 'admin' | 'public'].has(icon.topic)) {
        problems.push(
          `${icon.file}: topic ${icon.topic} is not the help topic of a route (use the topic of the screen)`,
        );
      }
      for (const lang of HELP_LANGUAGES) {
        const set = sets.find((s) => s.lang === lang && s.app === icon.app);
        if (topicGuide(set, icon.topic) === undefined) {
          problems.push(`${icon.file}: topic ${icon.topic} missing in the ${icon.app} guides (${lang})`);
        }
      }
    }
    expect(problems).toEqual([]);
  });
});
