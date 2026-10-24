<script lang="ts">
  // Fields of a mail template (CLAUDE.md section 12.3): subject, HTML body and text body.
  // - Variable buttons insert {{name}} at the cursor (replacing the selection) of the last
  //   focused field, put the focus back there after the inserted text, and announce the
  //   insertion; required variables are marked in text, not by colour alone.
  // - Client warnings (checkTemplate) list the required variables missing from a body and the
  //   unknown ones; they never block saving, the server stays authoritative.
  // - Issues of the server (400 validation-failed) are listed with their part, line and column,
  //   each with a "Go to" button that focuses the field and places the cursor (offsetOf). Their
  //   messages are in English (lang="en", RGAA 8.7).
  //
  //   <TemplateEditor bind:value={parts} variables={tpl.variables}
  //                   required={tpl.requiredVariables} {issues} idPrefix="tpl" />
  import { tick } from 'svelte';
  import { Alert, Button, TextArea, TextField, announce } from '../../shared/components';
  import { i18n, t } from '../../shared/i18n/i18n.svelte';
  import { checkTemplate, type TemplateParts } from '../forms/template';
  import {
    insertIntoPart,
    issueByPart,
    issueOffset,
    partFieldId,
    partLabelKey,
    type TemplateIssue,
    type TemplatePart,
  } from './templates';

  interface Props {
    /** Bound parts of the template. */
    value: TemplateParts;
    /** Variables offered for this template (EmailTemplate.variables). */
    variables: readonly string[];
    /** Required variables (EmailTemplate.requiredVariables). */
    required: readonly string[];
    /** Issues of the last refused save or preview. */
    issues?: readonly TemplateIssue[];
    /** Prefix of the field ids. */
    idPrefix: string;
  }

  let { value = $bindable(), variables, required, issues = [], idPrefix }: Props = $props();

  const uid = $props.id();
  const variablesHeadingId = `${uid}-variables`;
  let subjectEl: HTMLInputElement | undefined = $state();
  let htmlEl: HTMLTextAreaElement | undefined = $state();
  let textEl: HTMLTextAreaElement | undefined = $state();

  function elementOf(part: TemplatePart): HTMLInputElement | HTMLTextAreaElement | undefined {
    return part === 'subject' ? subjectEl : part === 'bodyHtml' ? htmlEl : textEl;
  }
  let lastPart: TemplatePart = 'bodyHtml';

  const check = $derived(checkTemplate(value, variables, required));
  const missingText = $derived(check.missing.map((m) => `${m.name} (${t(partLabelKey(m.part))})`).join(', '));
  const fieldErrors = $derived(issueByPart(issues));
  const requiredSet = $derived(new Set(required));

  const label = (part: TemplatePart): string => t(partLabelKey(part));

  function describeVariable(name: string): string {
    const key = `adminTenants.templates.variables.description.${name}`;
    return i18n.has(key) ? t(key) : '';
  }

  async function insert(name: string): Promise<void> {
    const part = lastPart;
    const el = elementOf(part);
    const start = el?.selectionStart ?? value[part].length;
    const end = el?.selectionEnd ?? start;
    const result = insertIntoPart(value, part, name, start, end);
    value = result.parts;
    await tick();
    el?.focus();
    el?.setSelectionRange(result.cursor, result.cursor);
    announce(t('adminTenants.templates.variables.inserted', { name: `{{${name}}}`, field: label(part) }));
  }

  function goTo(issue: TemplateIssue): void {
    const offset = issueOffset(value, issue);
    if (issue.part === undefined || offset === null) {
      return;
    }
    const el = elementOf(issue.part);
    el?.focus();
    el?.setSelectionRange(offset, offset);
  }

  /** Part and position of an issue, ending with a colon (the message follows). */
  function location(issue: TemplateIssue): string {
    const part = issue.part === undefined ? '' : label(issue.part);
    if (issue.line === undefined) {
      return t('adminTenants.templates.serverError.noLocation', { part });
    }
    return t('adminTenants.templates.serverError.location', {
      part,
      line: issue.line,
      column: issue.column ?? 1,
    });
  }
</script>

{#if issues.length > 0}
  <Alert severity="error" live={false} title={t('adminTenants.templates.serverError.title')}>
    <ul class="tt-template-editor__issues">
      {#each issues as issue, i (i)}
        <li>
          {#if issue.part !== undefined}<span>{location(issue)}</span>{/if}
          <span lang={issue.fromServer ? 'en' : undefined}>{issue.message}</span>
          {#if issue.part !== undefined && issue.line !== undefined}
            <Button variant="link" onclick={() => goTo(issue)}>
              {t('adminTenants.templates.serverError.goTo', { part: label(issue.part), line: issue.line })}
            </Button>
          {/if}
        </li>
      {/each}
    </ul>
    {#if issues.some((i) => i.fromServer)}<p>{t('adminTenants.templates.serverError.note')}</p>{/if}
  </Alert>
{/if}

<p class="tt-template-editor__syntax">
  {t('adminTenants.templates.editor.syntax', { example: '{{tenant_name}}' })}
</p>

<TextField
  id={partFieldId(idPrefix, 'subject')}
  label={label('subject')}
  bind:value={value.subject}
  bind:element={subjectEl}
  error={fieldErrors.subject}
  required
  spellcheck="true"
  onfocus={() => (lastPart = 'subject')}
/>
<TextArea
  id={partFieldId(idPrefix, 'bodyHtml')}
  label={label('bodyHtml')}
  bind:value={value.bodyHtml}
  bind:element={htmlEl}
  error={fieldErrors.bodyHtml}
  rows={14}
  required
  spellcheck="false"
  class="tt-template-editor__code"
  onfocus={() => (lastPart = 'bodyHtml')}
/>
<TextArea
  id={partFieldId(idPrefix, 'bodyText')}
  label={label('bodyText')}
  hint={t('adminTenants.templates.editor.text.hint')}
  bind:value={value.bodyText}
  bind:element={textEl}
  error={fieldErrors.bodyText}
  rows={10}
  required
  class="tt-template-editor__code"
  onfocus={() => (lastPart = 'bodyText')}
/>

{#if check.missing.length > 0 || check.unknown.length > 0}
  <Alert severity="warning" live={false}>
    {#if check.missing.length > 0}
      <p>
        {t('adminTenants.templates.warnings.missing', { count: check.missing.length, names: missingText })}
      </p>
    {/if}
    {#if check.unknown.length > 0}
      <p>
        {t('adminTenants.templates.warnings.unknown', {
          count: check.unknown.length,
          names: check.unknown.join(', '),
        })}
      </p>
    {/if}
  </Alert>
{/if}

<section class="tt-template-editor__variables" aria-labelledby={variablesHeadingId}>
  <h3 id={variablesHeadingId}>{t('adminTenants.templates.variables.title')}</h3>
  <p>{t('adminTenants.templates.variables.intro')}</p>
  {#if required.length > 0}<p>{t('adminTenants.templates.variables.requiredNote')}</p>{/if}
  <ul class="tt-template-editor__chips">
    {#each variables as name (name)}
      {@const description = describeVariable(name)}
      <li>
        <button
          type="button"
          class="tt-template-editor__chip"
          aria-label={t('adminTenants.templates.variables.insert', { name: `{{${name}}}` })}
          onclick={() => void insert(name)}
        >
          <code>{`{{${name}}}`}</code>
        </button>
        {#if requiredSet.has(name)}
          <strong class="tt-template-editor__required"
            >({t('adminTenants.templates.variables.required')})</strong
          >
        {/if}
        {#if description}<span class="tt-template-editor__description">{description}</span>{/if}
      </li>
    {/each}
  </ul>
</section>

<style>
  .tt-template-editor__syntax {
    color: var(--tt-muted);
  }

  .tt-template-editor__issues {
    margin: 0;
    padding-left: var(--tt-space-5);
  }

  :global(.tt-template-editor__code textarea) {
    font-family: var(--tt-font-mono);
  }

  .tt-template-editor__variables h3 {
    margin: var(--tt-space-4) 0 var(--tt-space-2);
    font-size: var(--tt-font-size-lg);
  }

  .tt-template-editor__chips {
    margin: 0;
    padding: 0;
    list-style: none;
    display: grid;
    gap: var(--tt-space-2);
  }

  .tt-template-editor__chips li {
    display: flex;
    flex-wrap: wrap;
    align-items: baseline;
    gap: var(--tt-space-2);
  }

  .tt-template-editor__chip {
    min-height: 2.75rem;
    padding: var(--tt-space-1) var(--tt-space-3);
    border: var(--tt-border-width) solid var(--tt-border);
    border-radius: var(--tt-radius-sm);
    background: var(--tt-surface-muted);
    color: var(--tt-text);
    cursor: pointer;
  }

  .tt-template-editor__chip:hover {
    border-color: var(--tt-primary);
  }

  .tt-template-editor__chip:focus-visible {
    outline: var(--tt-focus-width) solid var(--tt-focus);
    outline-offset: 2px;
  }

  .tt-template-editor__chip code {
    font-family: var(--tt-font-mono);
  }

  .tt-template-editor__description {
    color: var(--tt-muted);
  }
</style>
