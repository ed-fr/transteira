<script lang="ts">
  // Preview of a rendered mail template (POST .../preview, EmailPreview). This is the second and
  // last component allowed to use {@html} (eslint svelte/no-at-html-tags, threat model T-163;
  // the other is shared LegalContent). The HTML comes from internal/mail: the template is
  // sanitized by an allowlist when saved and previewed (formatting tags, https:/mailto: links,
  // cid: images only; no script, style element, form, frame or event handler), and the CSP
  // (script-src 'self', style-src 'self') stays the last barrier. For the preview only, the
  // server also removes every style attribute (the default templates and the mail layout use
  // them for the mail clients) and replaces every image by its alt text (sanitize.ForPreview):
  // the CSP would block them, logging a violation for each. The preview thus shows the structure
  // and content of the email without its styles, as the visible note says, and triggers no CSP
  // violation; the mails sent keep their styles. Once rendered, the inertPreview action removes
  // the href of every link and the roles, ids and tabindex of the email, and nests its headings
  // (the default templates start with an <h1>) below the "HTML version" sub-heading through
  // role="heading" and aria-level (neutralizePreview), so that the page keeps a single h1. Never
  // pass any other string here.
  import { t } from '../../shared/i18n/i18n.svelte';
  import { neutralizePreview, previewBody, type EmailPreview } from './templates';

  interface Props {
    /** Answer of previewEmailTemplate. */
    preview: EmailPreview;
    /** Level of the heading of the preview (default 2). */
    headingLevel?: 2 | 3;
  }

  let { preview, headingLevel = 2 }: Props = $props();

  const uid = $props.id();
  const headingId = `${uid}-heading`;
  const htmlId = `${uid}-html`;
  const textId = `${uid}-text`;
  const body = $derived(previewBody(preview.bodyHtml));
  const subLevel = $derived(headingLevel + 1);
  const sub = $derived(`h${subLevel}`);

  /**
   * Runs once the HTML is in the DOM ({#key} below mounts a new container for each preview); the
   * headings of the email are nested below the sub-heading of level subLevel.
   */
  function inertPreview(node: HTMLElement, title: string): void {
    neutralizePreview(node, title, subLevel);
  }
</script>

<section class="tt-template-preview" aria-labelledby={headingId}>
  <svelte:element this={`h${headingLevel}`} id={headingId} tabindex="-1">
    {t('adminTenants.templates.preview.title')}
  </svelte:element>
  <p>{t('adminTenants.templates.preview.intro')}</p>
  <p class="tt-template-preview__note">{t('adminTenants.templates.preview.note')}</p>
  <p class="tt-template-preview__subject tt-break">
    {t('adminTenants.templates.preview.subject', { subject: preview.subject })}
  </p>

  <svelte:element this={sub} id={htmlId}>{t('adminTenants.templates.preview.html')}</svelte:element>
  {#key body}
    <div
      class="tt-template-preview__html tt-break"
      role="region"
      aria-labelledby={htmlId}
      use:inertPreview={t('adminTenants.templates.preview.linkDisabled')}
    >
      <!-- eslint-disable-next-line svelte/no-at-html-tags -- server-sanitized by internal/mail (allowlist), links made inert (T-163) -->
      {@html body}
    </div>
  {/key}

  <svelte:element this={sub} id={textId}>{t('adminTenants.templates.preview.text')}</svelte:element>
  <pre class="tt-template-preview__text">{preview.bodyText}</pre>
</section>

<style>
  .tt-template-preview__note {
    color: var(--tt-muted);
  }

  .tt-template-preview__subject {
    font-weight: var(--tt-font-weight-bold);
  }

  .tt-template-preview__html,
  .tt-template-preview__text {
    padding: var(--tt-space-3);
    border: var(--tt-border-width) solid var(--tt-border);
    border-radius: var(--tt-radius-sm);
    background: var(--tt-surface);
    color: var(--tt-text);
  }

  .tt-template-preview__html :global(a) {
    text-decoration: underline;
    cursor: not-allowed;
  }

  .tt-template-preview__text {
    margin: 0;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
    font-family: var(--tt-font-mono);
  }
</style>
