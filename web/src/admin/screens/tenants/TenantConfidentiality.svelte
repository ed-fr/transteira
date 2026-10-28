<script lang="ts">
  // Confidentiality levels of a tenant (CLAUDE.md section 8.3, version 1.1): GET/PUT
  // /admin/tenants/{id}/confidentiality-levels. An editable list of 1 to 10 levels, each in a
  // fieldset: key, label and description in each language, default level (radio), rules
  // (durations, password, recipient verification, internal recipients, forced deletion, cap of
  // downloads). Levels can be added, removed and reordered with buttons (no drag and drop, for
  // the keyboard). Client-side validation mirrors the spec; the server answer is shown again once
  // saved, and its field errors are mapped to the fields of the levels.
  // The tenant sub-navigation is rendered by App.svelte.
  import { tick } from 'svelte';
  import { describeError } from '../../../shared/api/problem';
  import {
    Alert,
    Button,
    Checkbox,
    HelpIcon,
    Spinner,
    TextArea,
    TextField,
  } from '../../../shared/components';
  import { i18n, locale, t } from '../../../shared/i18n/i18n.svelte';
  import { adminApi } from '../../api';
  import FormSection from '../../components/FormSection.svelte';
  import { errorFor, type SubmitOutcome, type SummaryError } from '../../components/form';
  import type { AdminScreenProps } from '../types';
  import {
    DESCRIPTION_MAX_LENGTH,
    EXPIRY_CHOICES,
    LABEL_MAX_LENGTH,
    LEVEL_LANGUAGES,
    MAX_DOWNLOADS_CAP,
    MAX_LEVELS,
    addLevel,
    levelsBody,
    levelsChanged,
    moveLevel,
    removeLevel,
    serverLevelErrors,
    setDefault,
    toDraft,
    validateLevels,
    type ConfidentialityLevel,
    type FieldRefOf,
    type LevelDraft,
    type LevelField,
  } from './confidentiality';

  const { params, nav }: AdminScreenProps = $props();

  const uid = $props.id();

  let loading = $state(true);
  let loadError = $state('');
  let saved = $state.raw<ConfidentialityLevel[] | undefined>(undefined);
  let drafts = $state<LevelDraft[]>([]);
  let errors = $state<SummaryError[]>([]);
  let nextUid = 1;

  const tenantId = $derived(params['id'] ?? '');
  const dirty = $derived(saved !== undefined && levelsChanged(saved, drafts));

  /** Id of the element of a field of a level. */
  function fieldId(draft: LevelDraft, field: string): string {
    return `${uid}-l${draft.uid}-${field.replace('.', '-')}`;
  }

  function levelName(draft: LevelDraft, index: number): string {
    const label = (draft.labels[locale.current] ?? '').trim() || draft.key.trim();
    return label === '' ? t('adminTenants.confidentiality.level.unnamed', { n: index + 1 }) : label;
  }

  function fieldName(field: LevelField | 'list'): string {
    if (field === 'list') {
      return t('adminTenants.confidentiality.fields.default');
    }
    if (field.startsWith('label.')) {
      return t('adminTenants.confidentiality.fields.label', { lang: field.slice(6).toUpperCase() });
    }
    if (field.startsWith('description.')) {
      return t('adminTenants.confidentiality.fields.description', { lang: field.slice(12).toUpperCase() });
    }
    return t(`adminTenants.confidentiality.fields.${field}`);
  }

  const ref: FieldRefOf = (index, field) => {
    const draft = drafts[index];
    if (draft === undefined) {
      return { id: `${uid}-add`, label: t('adminTenants.confidentiality.add') };
    }
    const target = field === 'list' ? 'default' : field;
    return {
      id: fieldId(draft, target),
      label: `${levelName(draft, index)} - ${fieldName(field)}`,
    };
  };

  function show(levels: ConfidentialityLevel[]): void {
    saved = levels;
    drafts = levels.map((l) => toDraft(l, nextUid++));
  }

  async function load(id: string): Promise<void> {
    loading = true;
    loadError = '';
    try {
      const res = await adminApi.get('/admin/tenants/{tenantId}/confidentiality-levels', {
        path: { tenantId: id },
      });
      show(res.data.items);
    } catch (err) {
      loadError = describeError(i18n, err).message;
    } finally {
      loading = false;
    }
  }

  $effect(() => {
    void load(tenantId);
  });

  function toggleDay(draft: LevelDraft, day: number, on: boolean): void {
    const rest = draft.allowedExpiryDays.filter((d) => d !== day);
    draft.allowedExpiryDays = on ? [...rest, day].sort((a, b) => a - b) : rest;
  }

  /** Focuses the first of the elements that exists and is enabled, once the list is rendered. */
  async function focusAfter(...ids: string[]): Promise<void> {
    await tick();
    for (const id of ids) {
      const el = document.getElementById(id);
      if (el !== null && !(el instanceof HTMLButtonElement && el.disabled)) {
        el.focus();
        return;
      }
    }
  }

  function move(index: number, delta: number): void {
    const draft = drafts[index];
    drafts = moveLevel(drafts, index, delta);
    if (draft !== undefined) {
      const up = `${uid}-l${draft.uid}-up`;
      const down = `${uid}-l${draft.uid}-down`;
      void (delta < 0 ? focusAfter(up, down) : focusAfter(down, up));
    }
  }

  function remove(index: number): void {
    drafts = removeLevel(drafts, index);
    void focusAfter(`${uid}-add`);
  }

  function add(): void {
    const before = drafts.length;
    drafts = addLevel(drafts, nextUid++);
    const created = drafts[before];
    if (created !== undefined) {
      void focusAfter(fieldId(created, 'key'));
    }
  }

  async function save(): Promise<SubmitOutcome> {
    try {
      const res = await adminApi.put('/admin/tenants/{tenantId}/confidentiality-levels', {
        path: { tenantId },
        body: levelsBody(drafts),
      });
      show(res.data.items);
      return { ok: true, message: t('adminTenants.confidentiality.saved') };
    } catch (err) {
      const view = describeError(i18n, err);
      const mapped = serverLevelErrors(view.fields, drafts, ref);
      const message = mapped.errors.length === 0 || mapped.unmatched.length > 0 ? view.message : undefined;
      return message === undefined
        ? { ok: false, errors: mapped.errors }
        : { ok: false, errors: mapped.errors, message };
    }
  }
</script>

<div class="tt-title-row">
  <h1 tabindex="-1">{t('adminTenants.confidentiality.title')}</h1>
  <HelpIcon topic="tenant-confidentiality" title={t('adminTenants.confidentiality.title')} {nav} />
</div>

{#if loading}
  <p><Spinner showLabel /></p>
{:else if loadError !== ''}
  <Alert severity="error">{loadError}</Alert>
{:else}
  <FormSection
    title={t('adminTenants.confidentiality.form.title')}
    intro={t('adminTenants.confidentiality.intro')}
    {dirty}
    addGuard={(guard) => nav.addGuard(guard)}
    validate={() => validateLevels(drafts, ref, t)}
    onsubmit={save}
    bind:errors
  >
    {#each drafts as draft, index (draft.uid)}
      <fieldset class="tt-level">
        <legend class="tt-level__legend">
          {t('adminTenants.confidentiality.level.legend', { n: index + 1, name: levelName(draft, index) })}
        </legend>

        <div class="tt-level__row">
          <input
            type="radio"
            id={fieldId(draft, 'default')}
            name="{uid}-default"
            checked={draft.isDefault}
            onchange={() => (drafts = setDefault(drafts, index))}
          />
          <label for={fieldId(draft, 'default')}>{t('adminTenants.confidentiality.fields.default')}</label>
        </div>

        <TextField
          id={fieldId(draft, 'key')}
          label={t('adminTenants.confidentiality.fields.key')}
          hint={t('adminTenants.confidentiality.hints.key')}
          required
          autocomplete="off"
          spellcheck={false}
          bind:value={draft.key}
          error={errorFor(errors, fieldId(draft, 'key'))}
        />

        {#each LEVEL_LANGUAGES as lang (lang)}
          <TextField
            id={fieldId(draft, `label.${lang}`)}
            label={t('adminTenants.confidentiality.fields.label', { lang: lang.toUpperCase() })}
            required
            maxlength={LABEL_MAX_LENGTH}
            bind:value={draft.labels[lang] as string}
            error={errorFor(errors, fieldId(draft, `label.${lang}`))}
          />
        {/each}
        {#each LEVEL_LANGUAGES as lang (lang)}
          <TextArea
            id={fieldId(draft, `description.${lang}`)}
            label={t('adminTenants.confidentiality.fields.description', { lang: lang.toUpperCase() })}
            hint={t('adminTenants.confidentiality.hints.description')}
            rows={2}
            counterMax={DESCRIPTION_MAX_LENGTH}
            bind:value={draft.descriptions[lang] as string}
            error={errorFor(errors, fieldId(draft, `description.${lang}`))}
          />
        {/each}

        <fieldset
          class="tt-level__rules"
          id={fieldId(draft, 'days')}
          tabindex="-1"
          aria-describedby={errorFor(errors, fieldId(draft, 'days')) === undefined
            ? undefined
            : `${fieldId(draft, 'days')}-error`}
        >
          <legend>{t('adminTenants.confidentiality.fields.days')}</legend>
          <div class="tt-level__inline">
            {#each EXPIRY_CHOICES as day (day)}
              <Checkbox
                label={t('adminTenants.confidentiality.dayChoice', { count: day })}
                checked={draft.allowedExpiryDays.includes(day)}
                onchange={(e) => toggleDay(draft, day, e.currentTarget.checked)}
              />
            {/each}
          </div>
          {#if errorFor(errors, fieldId(draft, 'days'))}
            <p class="tt-text-danger" id="{fieldId(draft, 'days')}-error">
              {errorFor(errors, fieldId(draft, 'days'))}
            </p>
          {/if}
        </fieldset>

        <Checkbox
          label={t('adminTenants.confidentiality.fields.requirePassword')}
          bind:checked={draft.requirePassword}
        />
        <Checkbox
          label={t('adminTenants.confidentiality.fields.requireRecipientVerification')}
          hint={t('adminTenants.confidentiality.hints.recipientVerification')}
          bind:checked={draft.requireRecipientVerification}
        />
        <Checkbox
          label={t('adminTenants.confidentiality.fields.internalRecipientsOnly')}
          hint={t('adminTenants.confidentiality.hints.internalRecipientsOnly')}
          bind:checked={draft.internalRecipientsOnly}
        />
        <Checkbox
          label={t('adminTenants.confidentiality.fields.forceDeleteAfterFirstDownload')}
          bind:checked={draft.forceDeleteAfterFirstDownload}
        />
        <TextField
          id={fieldId(draft, 'maxDownloads')}
          label={t('adminTenants.confidentiality.fields.maxDownloads')}
          hint={t('adminTenants.confidentiality.hints.maxDownloads', { max: MAX_DOWNLOADS_CAP })}
          type="number"
          inputmode="numeric"
          min={1}
          max={MAX_DOWNLOADS_CAP}
          bind:value={draft.maxDownloadsText}
          error={errorFor(errors, fieldId(draft, 'maxDownloads'))}
        />

        <div class="tt-level__actions">
          <Button
            id={fieldId(draft, 'up')}
            variant="secondary"
            small
            disabled={index === 0}
            aria-label={t('adminTenants.confidentiality.moveUp', { name: levelName(draft, index) })}
            onclick={() => move(index, -1)}
          >
            {t('adminTenants.confidentiality.up')}
          </Button>
          <Button
            id={fieldId(draft, 'down')}
            variant="secondary"
            small
            disabled={index === drafts.length - 1}
            aria-label={t('adminTenants.confidentiality.moveDown', { name: levelName(draft, index) })}
            onclick={() => move(index, 1)}
          >
            {t('adminTenants.confidentiality.down')}
          </Button>
          <Button
            variant="danger"
            small
            disabled={drafts.length <= 1}
            aria-label={t('adminTenants.confidentiality.removeLevel', { name: levelName(draft, index) })}
            onclick={() => remove(index)}
          >
            {t('adminTenants.confidentiality.remove')}
          </Button>
        </div>
      </fieldset>
    {/each}

    <div>
      <Button id="{uid}-add" variant="secondary" disabled={drafts.length >= MAX_LEVELS} onclick={add}>
        {t('adminTenants.confidentiality.add')}
      </Button>
      <p class="tt-hint">
        {t('adminTenants.confidentiality.count', { count: drafts.length, max: MAX_LEVELS })}
      </p>
    </div>
  </FormSection>
{/if}

<style>
  .tt-level {
    margin: 0 0 var(--tt-space-5);
    padding: var(--tt-space-4);
    border: var(--tt-border-width) solid var(--tt-border);
    border-radius: var(--tt-radius);
  }

  .tt-level__legend {
    padding: 0 var(--tt-space-2);
    font-weight: var(--tt-font-weight-bold);
  }

  .tt-level__row {
    display: flex;
    align-items: center;
    gap: var(--tt-space-2);
    margin-bottom: var(--tt-space-3);
  }

  .tt-level__rules {
    margin: 0 0 var(--tt-space-3);
    padding: 0;
    border: 0;
  }

  .tt-level__inline {
    display: flex;
    flex-wrap: wrap;
    gap: var(--tt-space-4);
  }

  .tt-level__actions {
    display: flex;
    flex-wrap: wrap;
    gap: var(--tt-space-2);
    margin-top: var(--tt-space-3);
  }
</style>
