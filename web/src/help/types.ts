// Data model of the integrated help (CLAUDE.md section 4.2). The user guides of docs/user/ are
// converted at build time (scripts/build-help.mjs, logic in build.ts) into these structures,
// written to src/help/generated/<lang>-<app>.ts and rendered by the Svelte components of this
// directory: the help never goes through HTML ({@html} is not used, threat model T-91).
//
// Type-only module: build.ts imports it with `import type`, which Node erases when it runs the
// build script (no runtime import between the two, so no file extension is needed).

/** Identifier of a user guide: one guide per profile, same file name in every language. */
export type GuideId = 'depositor' | 'recipient' | 'delegated-admin' | 'super-admin';

/** Application that shows a guide: the public application or the administration. */
export type HelpApp = 'public' | 'admin';

/** Inline content of a paragraph, list item, note or link. */
export type HelpInline =
  | { type: 'text'; text: string }
  | { type: 'strong'; children: HelpInline[] }
  | { type: 'em'; children: HelpInline[] }
  | { type: 'code'; text: string }
  /** Link to a section of the same guide (target: section id). */
  | { type: 'anchor'; target: string; children: HelpInline[] }
  /** Link to a help topic of the same application, possibly in another guide. */
  | { type: 'topic'; topic: string; children: HelpInline[] };

/** Block of a section. */
export type HelpBlock =
  | { type: 'paragraph'; content: HelpInline[] }
  | { type: 'list'; ordered: boolean; items: HelpInline[][] }
  /** Highlighted note ("> **Note** text"): label written by the author ("Note", "À savoir"). */
  | { type: 'note'; label: string; content: HelpInline[] }
  /**
   * Screenshot: src is the URL of the image (an asset fingerprinted by Vite under /assets/);
   * width and height are the pixel size of the PNG, read at build time.
   */
  | { type: 'figure'; src: string; alt: string; caption?: string; width?: number; height?: number }
  /**
   * Real rules of the current tenant ("<!-- rules: <set> -->", public guides only), rendered as
   * text from GET /tenant by HelpRules.svelte; renders nothing without a tenant.
   */
  | { type: 'rules'; set: RulesSet };

/** Rules shown by a rules block: overview, size and durations, or confidentiality levels. */
export type RulesSet = 'summary' | 'limits' | 'levels';

/** Tenant feature a section depends on ("<!-- when: <feature> -->", public guides only). */
export type HelpFeature =
  'remoteInternalDeposit' | 'transferReply' | 'recipientVerification' | 'maxDownloads' | 'folders';

/** A section: a heading and the blocks up to the next heading. */
export interface HelpSection {
  /** Section id, unique in the guide (GitHub-compatible slug of the heading). */
  id: string;
  /** Help topic opening this section (/help/<topic>), if any. */
  topic?: string;
  /**
   * Feature the section depends on: with a tenant whose feature is off, the section and its
   * sub-sections are hidden.
   */
  when?: HelpFeature;
  /** Heading level: 1 (guide title, first section only), 2 or 3. */
  level: 1 | 2 | 3;
  /** Heading text (plain text). */
  title: string;
  blocks: HelpBlock[];
}

/** A user guide in one language. */
export interface HelpGuide {
  id: GuideId;
  /** Guide title (the level 1 heading). */
  title: string;
  /** Sections in document order; the first one is the level 1 heading. */
  sections: HelpSection[];
}

/** Location of a help topic. */
export interface HelpTopicTarget {
  guide: GuideId;
  section: string;
}

/** The guides of one application in one language (one generated module). */
export interface HelpGuideSet {
  lang: string;
  app: HelpApp;
  guides: HelpGuide[];
  /** Every topic of these guides, including the implicit topic of each guide (its id). */
  topics: Record<string, HelpTopicTarget>;
}
