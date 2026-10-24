<script lang="ts">
  // Editor of one legal text of a tenant in one language (CLAUDE.md section 13): Markdown source
  // (GET/PUT .../legal/{document}/{lang}, at most 100 000 characters) and a preview of the saved
  // text from the sanitized HTML returned by the API (shared LegalContent, the same rendering as
  // the public page), made inert like the email preview (neutralizePreview, threat model T-163:
  // links lose their href, ids and roles are removed, headings nest below the preview heading;
  // the public page is unchanged). Saving an empty text deletes the document: it asks for
  // confirmation first. FormSection guards the unsaved changes. The tenant sub-navigation is
  // rendered by App.svelte.
  import { describeError } from '../../../shared/api/problem';
  import type { components } from '../../../shared/api/schema';
  import { Alert, LegalContent, Spinner, TextArea, languageName } from '../../../shared/components';
  import { formatDate, i18n, t } from '../../../shared/i18n/i18n.svelte';
  import { adminApi } from '../../api';
  import ConfirmDialog from '../../components/ConfirmDialog.svelte';
  import FormSection from '../../components/FormSection.svelte';
  import { errorFor, summaryFromFields, type SubmitOutcome, type SummaryError } from '../../components/form';
  import {
    LEGAL_MAX_LENGTH,
    isBlank,
    type LegalDocument,
    type LegalDocumentName,
  } from '../../components/legal';
  import { neutralizePreview } from '../../components/templates';
  import type { AdminScreenProps } from '../types';

  type Language = components['schemas']['Language'];
  type View = { kind: 'loading' } | { kind: 'error'; message: string } | { kind: 'ready' };

  let { params, nav }: AdminScreenProps = $props();

  const fieldId = 'legal-markdown';
  const uid = $props.id();
  const previewHeadingId = `${uid}-preview`;

  /** Runs once the HTML is in the DOM ({#key} below mounts a new container for each text). */
  function inertPreview(node: HTMLElement, title: string): void {
    // Headings of the text are nested below the h2 of the preview section.
    neutralizePreview(node, title, 2);
  }
  const tenantId = $derived(params['id'] ?? '');
  const documentName = $derived(params['document'] ?? '');
  const lang = $derived(params['lang'] ?? '');
  const apiPath = $derived({
    tenantId,
    document: documentName as LegalDocumentName,
    language: lang as Language,
  });
  const listHref = $derived(nav.href(`/tenants/${encodeURIComponent(tenantId)}/legal`));
  const documentKey = $derived(`adminTenants.legal.document.${documentName}`);
  const title = $derived(
    t('adminTenants.legal.editor.title', {
      document: i18n.has(documentKey) ? t(documentKey) : documentName,
      language: languageName(lang),
    }),
  );
  const fieldLabel = $derived(t('adminTenants.legal.editor.markdown.label'));
  let view = $state<View>({ kind: 'loading' });
  let doc = $state<LegalDocument | undefined>();
  let markdown = $state('');
  let saved = $state('');
  let errors = $state<SummaryError[]>([]);
  let confirmOpen = $state(false);
  let pending: ((outcome: SubmitOutcome) => void) | undefined;
  let ticket = 0;

  const dirty = $derived(markdown !== saved);

  async function load(): Promise<void> {
    const mine = ++ticket;
    view = { kind: 'loading' };
    try {
      const { data } = await adminApi.get('/admin/tenants/{tenantId}/legal/{document}/{language}', {
        path: apiPath,
      });
      if (mine === ticket) {
        doc = data;
        markdown = data.markdown;
        saved = data.markdown;
        view = { kind: 'ready' };
      }
    } catch (err) {
      if (mine === ticket) {
        view = { kind: 'error', message: describeError(i18n, err).message };
      }
    }
  }

  $effect(() => {
    void apiPath;
    void load();
  });

  async function put(): Promise<SubmitOutcome> {
    try {
      const { data } = await adminApi.put('/admin/tenants/{tenantId}/legal/{document}/{language}', {
        path: apiPath,
        body: { markdown },
      });
      doc = data;
      markdown = data.markdown;
      saved = data.markdown;
      const key = isBlank(data.markdown) ? 'removed' : 'saved';
      return { ok: true, message: t(`adminTenants.legal.editor.${key}`) };
    } catch (err) {
      const described = describeError(i18n, err);
      const { errors: fieldErrors } = summaryFromFields(described.fields, {
        markdown: { id: fieldId, label: fieldLabel },
      });
      return {
        ok: false,
        message: fieldErrors.length > 0 ? undefined : described.message,
        errors: fieldErrors,
      };
    }
  }

  function settle(outcome: SubmitOutcome): void {
    const resolve = pending;
    pending = undefined;
    resolve?.(outcome);
  }

  function save(): Promise<SubmitOutcome> {
    if (isBlank(markdown) && !isBlank(saved)) {
      // Deleting the document: the outcome waits for the confirmation dialog.
      return new Promise((resolve) => {
        pending = resolve;
        confirmOpen = true;
      });
    }
    return put();
  }

  async function confirmRemove(): Promise<string | void> {
    const outcome = await put();
    if (!outcome.ok) {
      return outcome.message ?? outcome.errors?.[0]?.message ?? t('errors.unknown');
    }
    settle(outcome);
  }
</script>

<p><a href={listHref} use:nav.link>{t('adminTenants.legal.editor.back')}</a></p>
<h1 tabindex="-1">{title}</h1>

{#if view.kind === 'loading'}
  <Spinner label={t('admin.common.loading')} />
{:else if view.kind === 'error'}
  <Alert severity="error">{view.message}</Alert>
{:else}
  {#if doc?.updatedAt && !isBlank(saved)}
    <p>{t('admin.common.lastUpdated', { date: formatDate(doc.updatedAt) })}</p>
  {/if}
  <FormSection
    title={t('adminTenants.legal.editor.formTitle')}
    {dirty}
    addGuard={(guard) => nav.addGuard(guard)}
    bind:errors
    onsubmit={save}
    saveLabel={t('adminTenants.legal.editor.save')}
  >
    <TextArea
      id={fieldId}
      label={fieldLabel}
      hint={t('adminTenants.legal.editor.markdown.hint')}
      bind:value={markdown}
      maxlength={LEGAL_MAX_LENGTH}
      rows={20}
      lang={lang || undefined}
      error={errorFor(errors, fieldId)}
    />
  </FormSection>

  <section class="tt-legal-preview" aria-labelledby={previewHeadingId}>
    <h2 id={previewHeadingId}>{t('adminTenants.legal.editor.preview')}</h2>
    {#if doc?.html}
      <p class="tt-legal-preview__note">{t('adminTenants.legal.editor.previewNote')}</p>
      {#key doc.html}
        <div
          class="tt-legal-preview__body"
          lang={lang || undefined}
          use:inertPreview={t('adminTenants.templates.preview.linkDisabled')}
        >
          <LegalContent html={doc.html} />
        </div>
      {/key}
    {:else}
      <p>{t('adminTenants.legal.editor.previewEmpty')}</p>
    {/if}
  </section>

  <ConfirmDialog
    bind:open={confirmOpen}
    title={t('adminTenants.legal.editor.emptyConfirm.title')}
    text={t('adminTenants.legal.editor.emptyConfirm.text')}
    confirmLabel={t('adminTenants.legal.editor.emptyConfirm.action')}
    danger
    onconfirm={confirmRemove}
    onclose={() => settle({ ok: true, message: '' })}
  />
{/if}

<style>
  .tt-legal-preview__note {
    color: var(--tt-muted);
  }

  .tt-legal-preview__body {
    padding: var(--tt-space-3);
    border: var(--tt-border-width) solid var(--tt-border);
    border-radius: var(--tt-radius-sm);
    background: var(--tt-surface);
  }
</style>
