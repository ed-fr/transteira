<script lang="ts">
  // Editor of one mail template of a tenant in one language (CLAUDE.md section 12.3):
  // GET .../email-templates/{key}/{lang}, save (PUT; 400 issues listed with part, line and
  // column), preview of the current, unsaved content (POST .../preview, TemplatePreview) and
  // restoration of the default template (DELETE, after confirmation). A successful DELETE is
  // a success even when reloading the template afterwards fails: the editor is then replaced by
  // "restored, but not reloaded" and a retry button (never the stale customized content, which a
  // save would put back). FormSection guards the unsaved changes. The tenant sub-navigation is
  // rendered by App.svelte.
  import { tick } from 'svelte';
  import { ApiProblem } from '../../../shared/api/client';
  import { describeError, fieldMessage } from '../../../shared/api/problem';
  import type { components } from '../../../shared/api/schema';
  import { Alert, Button, Spinner, announce, languageName } from '../../../shared/components';
  import { formatDate, i18n, t } from '../../../shared/i18n/i18n.svelte';
  import { adminApi } from '../../api';
  import ConfirmDialog from '../../components/ConfirmDialog.svelte';
  import FormSection from '../../components/FormSection.svelte';
  import type { SubmitOutcome } from '../../components/form';
  import TemplateEditor from '../../components/TemplateEditor.svelte';
  import TemplatePreview from '../../components/TemplatePreview.svelte';
  import {
    partsDiffer,
    partsOf,
    templateIssues,
    type EmailPreview,
    type EmailTemplate,
    type TemplateIssue,
  } from '../../components/templates';
  import type { TemplateParts } from '../../forms/template';
  import type { AdminScreenProps } from '../types';

  type TemplateKey = components['schemas']['EmailTemplateKey'];
  type Language = components['schemas']['Language'];
  type View = { kind: 'loading' } | { kind: 'error'; message: string } | { kind: 'ready' };

  let { params, nav }: AdminScreenProps = $props();

  const tenantId = $derived(params['id'] ?? '');
  const key = $derived(params['key'] ?? '');
  const lang = $derived(params['lang'] ?? '');
  const apiPath = $derived({
    tenantId,
    templateKey: key as TemplateKey,
    language: lang as Language,
  });
  const listHref = $derived(nav.href(`/tenants/${encodeURIComponent(tenantId)}/templates`));
  const keyLabelKey = $derived(`adminTenants.templates.key.${key}`);
  const keyLabel = $derived(i18n.has(keyLabelKey) ? t(keyLabelKey) : key);
  const keyDescriptionKey = $derived(`adminTenants.templates.keyDescription.${key}`);
  const title = $derived(
    t('adminTenants.templates.editor.title', { template: keyLabel, language: languageName(lang) }),
  );
  const empty: TemplateParts = { subject: '', bodyHtml: '', bodyText: '' };
  let view = $state<View>({ kind: 'loading' });
  let template = $state<EmailTemplate | undefined>();
  let parts = $state<TemplateParts>({ ...empty });
  let saved = $state<TemplateParts>({ ...empty });
  let issues = $state<TemplateIssue[]>([]);
  let preview = $state<EmailPreview | undefined>();
  let previewing = $state(false);
  let previewError = $state('');
  let previewBox: HTMLDivElement | undefined = $state();
  let resetOpen = $state(false);
  // Reload after a successful reset: error message ('' when none) and retry state.
  let reloadError = $state('');
  let reloading = $state(false);
  let retryButton: HTMLButtonElement | undefined = $state();
  let heading: HTMLHeadingElement | undefined = $state();
  let ticket = 0;

  const dirty = $derived(partsDiffer(parts, saved));

  function show(data: EmailTemplate): void {
    template = data;
    parts = partsOf(data);
    saved = partsOf(data);
  }

  async function load(): Promise<void> {
    const mine = ++ticket;
    view = { kind: 'loading' };
    issues = [];
    preview = undefined;
    previewError = '';
    try {
      const { data } = await adminApi.get(
        '/admin/tenants/{tenantId}/email-templates/{templateKey}/{language}',
        {
          path: apiPath,
        },
      );
      if (mine === ticket) {
        show(data);
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

  /** Issues of a 400 validation-failed, or undefined for any other error. */
  function issuesOf(err: unknown): TemplateIssue[] | undefined {
    if (err instanceof ApiProblem && err.code === 'validation-failed') {
      return templateIssues(err.errors, (code) => fieldMessage(i18n, code));
    }
    return undefined;
  }

  async function save(): Promise<SubmitOutcome> {
    try {
      const { data } = await adminApi.put(
        '/admin/tenants/{tenantId}/email-templates/{templateKey}/{language}',
        {
          path: apiPath,
          body: $state.snapshot(parts),
        },
      );
      show(data);
      issues = [];
      return { ok: true, message: t('adminTenants.templates.editor.saved') };
    } catch (err) {
      const found = issuesOf(err);
      if (found !== undefined) {
        issues = found;
        return { ok: false, message: t('adminTenants.templates.serverError.notSaved') };
      }
      return { ok: false, message: describeError(i18n, err).message };
    }
  }

  async function runPreview(): Promise<void> {
    if (previewing) {
      return;
    }
    previewing = true;
    previewError = '';
    try {
      const { data } = await adminApi.post(
        '/admin/tenants/{tenantId}/email-templates/{templateKey}/{language}/preview',
        { path: apiPath, body: $state.snapshot(parts) },
      );
      preview = data;
      issues = [];
      await tick();
      previewBox?.querySelector<HTMLElement>('[tabindex="-1"]')?.focus();
    } catch (err) {
      preview = undefined;
      const found = issuesOf(err);
      if (found !== undefined) {
        issues = found;
      }
      previewError =
        found !== undefined
          ? t('adminTenants.templates.serverError.title')
          : describeError(i18n, err).message;
    } finally {
      previewing = false;
    }
  }

  async function reset(): Promise<string | void> {
    try {
      await adminApi.delete('/admin/tenants/{tenantId}/email-templates/{templateKey}/{language}', {
        path: apiPath,
      });
    } catch (err) {
      return describeError(i18n, err).message;
    }
    issues = [];
    preview = undefined;
    previewError = '';
    if (await reloadAfterReset()) {
      announce(t('adminTenants.templates.reset.done'));
    }
  }

  /**
   * Reloads the template after a successful reset, in place (not through load(): the dialog
   * must stay mounted while it closes). Returns false and keeps the error when it fails.
   */
  async function reloadAfterReset(): Promise<boolean> {
    reloading = true;
    try {
      const { data } = await adminApi.get(
        '/admin/tenants/{tenantId}/email-templates/{templateKey}/{language}',
        {
          path: apiPath,
        },
      );
      show(data);
      reloadError = '';
      return true;
    } catch (err) {
      reloadError = describeError(i18n, err).message;
      return false;
    } finally {
      reloading = false;
    }
  }

  async function retryReload(): Promise<void> {
    if (await reloadAfterReset()) {
      announce(t('adminTenants.templates.reset.reloaded'));
      await tick();
      heading?.focus();
    }
  }

  /** After the dialog closed: a failed reload leaves the focus on the retry button. */
  function afterResetDialog(): void {
    if (reloadError !== '') {
      retryButton?.focus();
    }
  }
</script>

<p><a href={listHref} use:nav.link>{t('adminTenants.templates.editor.back')}</a></p>
<h1 tabindex="-1" bind:this={heading}>{title}</h1>
{#if i18n.has(keyDescriptionKey)}<p>{t(keyDescriptionKey)}</p>{/if}

{#if view.kind === 'loading'}
  <Spinner label={t('admin.common.loading')} />
{:else if view.kind === 'error'}
  <Alert severity="error">{view.message}</Alert>
{:else if template !== undefined && reloadError !== ''}
  <Alert severity="warning">
    {t('adminTenants.templates.reset.reloadFailed', { message: reloadError })}
  </Alert>
  <Button
    variant="secondary"
    loading={reloading}
    loadingLabel={t('admin.common.loading')}
    bind:element={retryButton}
    onclick={() => void retryReload()}
  >
    {t('adminTenants.templates.reset.retry')}
  </Button>
{:else if template !== undefined}
  <p>
    {template.customised ? t('adminTenants.templates.customized') : t('adminTenants.templates.default')}
    {#if template.customised && template.updatedAt}
      · {t('admin.common.lastUpdated', { date: formatDate(template.updatedAt) })}
    {/if}
  </p>
  <FormSection
    title={t('adminTenants.templates.editor.formTitle')}
    {dirty}
    addGuard={(guard) => nav.addGuard(guard)}
    onsubmit={save}
    saveLabel={t('adminTenants.templates.editor.save')}
  >
    <TemplateEditor
      bind:value={parts}
      variables={template.variables}
      required={template.requiredVariables}
      {issues}
      idPrefix="template"
    />
    {#snippet actions()}
      <Button
        variant="secondary"
        loading={previewing}
        loadingLabel={t('adminTenants.templates.preview.loading')}
        onclick={() => void runPreview()}
      >
        {t('adminTenants.templates.preview.action')}
      </Button>
      {#if template?.customised}
        <Button variant="danger" onclick={() => (resetOpen = true)}>
          {t('adminTenants.templates.reset.action')}
        </Button>
      {/if}
    {/snippet}
  </FormSection>

  {#if previewError !== ''}
    <Alert severity="error">{previewError}</Alert>
  {/if}
  {#if preview !== undefined}
    <div bind:this={previewBox}>
      <TemplatePreview {preview} />
    </div>
  {/if}

  <ConfirmDialog
    bind:open={resetOpen}
    title={t('adminTenants.templates.reset.confirmTitle')}
    text={t('adminTenants.templates.reset.confirmText')}
    confirmLabel={t('adminTenants.templates.reset.confirmAction')}
    danger
    onconfirm={reset}
    onclose={afterResetDialog}
  />
{/if}
