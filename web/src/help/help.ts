// Logic of the help screen (HelpScreen.svelte), kept out of the components so that it is unit
// tested in Node: which guides an application offers, what /help and /help/<topic> show, the
// table of contents, the sections hidden for the tenant and the page title.
import { HELP_TOPIC } from '../shared/components/helpers';
import type { HelpTenantRules } from './rules';
import type { GuideId, HelpGuide, HelpGuideSet, HelpSection } from './types';

/** Options of the tenant read by the help (GET /tenant), undefined outside a tenant. */
export type HelpFeatures = HelpTenantRules['features'];

/** Guides of the public application. */
export const PUBLIC_GUIDES: readonly GuideId[] = ['depositor', 'recipient'];

/** Guides of the administration (the super-admin guide only for a super admin, see adminGuides). */
export const ADMIN_GUIDES: readonly GuideId[] = ['delegated-admin', 'super-admin'];

/**
 * Guides offered by the administration: a signed-in delegated admin only gets the delegated-admin
 * guide; a super admin, and a visitor not signed in (first-run setup, sign-in, activation), get
 * both.
 */
export function adminGuides(signedInRole: string | undefined): readonly GuideId[] {
  return signedInRole === undefined || signedInRole === 'super_admin' ? ADMIN_GUIDES : ['delegated-admin'];
}

/** What the help screen shows. */
export type HelpView =
  | { kind: 'index'; guides: HelpGuide[]; unknownTopic?: string }
  | { kind: 'guide'; guide: HelpGuide; section: HelpSection };

/** Guides of a set that are offered, in the order of the set. */
export function visibleGuides(set: HelpGuideSet, allowed: readonly GuideId[]): HelpGuide[] {
  return set.guides.filter((guide) => allowed.includes(guide.id));
}

/**
 * Sections of a guide shown to the tenant: a section whose feature (when) is off is left out with
 * its deeper sub-sections (the level 3 sections up to the next level 2 heading). Without
 * features (admin application, no tenant), every section is shown.
 */
export function visibleSections(guide: HelpGuide, features: HelpFeatures): HelpSection[] {
  if (features === undefined) {
    return guide.sections;
  }
  const out: HelpSection[] = [];
  let hiddenLevel: number | undefined;
  for (const section of guide.sections) {
    if (hiddenLevel !== undefined && section.level > hiddenLevel) {
      continue;
    }
    hiddenLevel = undefined;
    if (section.when !== undefined && !features[section.when]) {
      hiddenLevel = section.level;
      continue;
    }
    out.push(section);
  }
  return out;
}

/**
 * Resolves /help (topic undefined: the index) or /help/<topic>: the guide holding the topic and
 * its section, or the index with the unknown topic when the topic does not exist or is in a guide
 * that is not offered. A topic in a section hidden for the tenant (visibleSections) opens its
 * guide at the top: the address is valid, the option is just not offered here.
 */
export function resolveHelp(
  set: HelpGuideSet,
  topic: string | undefined,
  allowed: readonly GuideId[],
  features?: HelpFeatures,
): HelpView {
  const guides = visibleGuides(set, allowed);
  if (topic === undefined || topic === '') {
    return { kind: 'index', guides };
  }
  const target = Object.hasOwn(set.topics, topic) ? set.topics[topic] : undefined;
  const guide = guides.find((g) => g.id === target?.guide);
  const section = guide?.sections.find((s) => s.id === target?.section);
  if (guide === undefined || section === undefined) {
    return { kind: 'index', guides, unknownTopic: topic };
  }
  const first = guide.sections[0];
  if (first !== undefined && !visibleSections(guide, features).includes(section)) {
    return { kind: 'guide', guide, section: first };
  }
  return { kind: 'guide', guide, section };
}

/** Topic opening a guide at its title (the implicit topic: the guide id). */
export function guideTopic(guide: HelpGuide): string {
  return guide.sections[0]?.topic ?? guide.id;
}

/** An entry of the table of contents of a guide: a level 2 heading and its level 3 headings. */
export interface TocEntry {
  id: string;
  title: string;
  children: TocEntry[];
}

/**
 * Table of contents of a guide: its level 2 headings, each with its level 3 headings (the build
 * refuses a level 3 heading right after the title).
 */
export function tableOfContents(guide: HelpGuide): TocEntry[] {
  const out: TocEntry[] = [];
  for (const { id, title, level } of guide.sections) {
    const parent = out[out.length - 1];
    if (level === 2 || (level === 3 && parent === undefined)) {
      out.push({ id, title, children: [] });
    } else if (level === 3 && parent !== undefined) {
      parent.children.push({ id, title, children: [] });
    }
  }
  return out;
}

/** Links of the rendered guide (HelpInline): a section of the same guide, or another topic. */
export interface HelpLinks {
  /** Links rendered as their plain text (printable version). */
  plain?: boolean;
  /** URL of a help topic (/help/<topic>, under the base path of the application). */
  topicHref: (topic: string) => string;
  /** Svelte action of the router for internal links (in-app navigation). */
  link: (node: HTMLAnchorElement) => { destroy(): void };
  /** Called when a link to a section of the same guide is activated. */
  onanchor: (sectionId: string, event: MouseEvent) => void;
}

/** Prefix of the element ids of the help sections (kept apart from the ids of the application). */
export function sectionDomId(sectionId: string): string {
  return `help-${sectionId}`;
}

/**
 * Page title of a help view (without the site name, added by the application): "Section – Guide"
 * in a guide, the guide title on its first section, helpTitle on the index.
 */
export function helpPageTitle(view: HelpView | undefined, helpTitle: string): string {
  if (view === undefined || view.kind === 'index') {
    return helpTitle;
  }
  return view.section.level === 1 ? view.guide.title : `${view.section.title} – ${view.guide.title}`;
}

/** Longest unknown topic repeated in the message of the help index. */
export const MAX_SHOWN_TOPIC_LENGTH = 64;

/**
 * Unknown topic as it may be repeated to the user: only a well-formed topic (a slug, HELP_TOPIC)
 * of at most MAX_SHOWN_TOPIC_LENGTH characters, so that a crafted URL cannot put arbitrary text
 * (a fake instruction, a phone number) in the page; undefined otherwise (generic message).
 */
export function shownTopic(topic: string): string | undefined {
  return topic.length <= MAX_SHOWN_TOPIC_LENGTH && HELP_TOPIC.test(topic) ? topic : undefined;
}

/** The parts of a click event plainClick reads. */
export type ClickLike = Pick<
  MouseEvent,
  'defaultPrevented' | 'button' | 'metaKey' | 'ctrlKey' | 'shiftKey' | 'altKey'
>;

/**
 * Reports whether a click on a link is a plain primary click that the page may handle itself; a
 * modified or non-primary click (new tab, new window, download) is left to the browser.
 */
export function plainClick(event: ClickLike): boolean {
  return (
    !event.defaultPrevented &&
    event.button === 0 &&
    !event.metaKey &&
    !event.ctrlKey &&
    !event.shiftKey &&
    !event.altKey
  );
}
