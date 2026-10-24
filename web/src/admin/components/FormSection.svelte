<script lang="ts">
  // Form of one settings section (RGAA 11.10, 11.11):
  // - a section with its heading (or a fieldset with its legend) around a <form>;
  // - a save button with its loading state; the result is shown inline and announced by a
  //   live region (success: polite; general error: in an alert);
  // - an error summary listing the fields in error, each a link that focuses its field; after
  //   a failed submission the focus moves to the first field in error (or to the summary);
  // - while dirty, a navigation guard (addGuard, e.g. router.addGuard) asks for confirmation
  //   before leaving the page, and beforeunload warns before closing or reloading the tab.
  // When dirty is given and false, submitting announces "No changes to save." without calling
  // onsubmit. validate runs before onsubmit: its errors fill the summary.
  //
  //   <FormSection title={text} dirty={isDirty} addGuard={(g) => nav.addGuard(g)}
  //                validate={checkFields} onsubmit={save}>
  //     <TextField id="tenant-name" ... error={errorFor(errors, 'tenant-name')} />
  //   </FormSection>
  import { tick, type Snippet } from 'svelte';
  import Alert from '../../shared/components/Alert.svelte';
  import Button from '../../shared/components/Button.svelte';
  import LiveRegion from '../../shared/components/LiveRegion.svelte';
  import { t } from '../../shared/i18n/i18n.svelte';
  import {
    beforeUnloadWarning,
    focusById,
    normalizeOutcome,
    unsavedChangesGuard,
    type SubmitOutcome,
    type SummaryError,
  } from './form';

  interface Props {
    /** Heading (or legend) of the section. */
    title: string;
    /** Level of the heading (default 2); ignored with the fieldset layout. */
    headingLevel?: 2 | 3 | 4;
    /** Layout: a section with a heading (default) or a fieldset with a legend. */
    as?: 'section' | 'fieldset';
    /** Introduction under the heading. */
    intro?: string;
    /** Whether the form has unsaved changes (enables the guards); undefined: not tracked. */
    dirty?: boolean | undefined;
    /** Registers a navigation guard and returns its removal (router.addGuard). */
    addGuard?: ((guard: (path: string) => boolean) => () => void) | undefined;
    /** Asks the user to confirm leaving (default window.confirm). */
    confirmLeave?: (message: string) => boolean;
    /** Client-side validation before onsubmit; returned errors fill the summary. */
    validate?: () => readonly SummaryError[];
    /** Saves the form; see SubmitOutcome. A rejection shows errorMessage (or the generic one). */
    onsubmit: () => Promise<SubmitOutcome | void>;
    /** Bound errors of the summary (to show them on the fields with errorFor). */
    errors?: SummaryError[];
    /** Label of the save button (default "Save"); while saving: savingLabel ("Saving…"). */
    saveLabel?: string;
    savingLabel?: string;
    /** Default success message (default "Changes saved."). */
    successMessage?: string;
    /** Message shown when onsubmit rejects (default: the generic unknown error). */
    errorMessage?: string;
    /** Disables the save button. */
    disabled?: boolean;
    /** Fields of the form. */
    children: Snippet;
    /** Extra buttons next to the save button (e.g. "Send a test email"). */
    actions?: Snippet;
    class?: string;
  }

  let {
    title,
    headingLevel = 2,
    as = 'section',
    intro,
    dirty = undefined,
    addGuard,
    confirmLeave,
    validate,
    onsubmit,
    errors = $bindable([]),
    saveLabel,
    savingLabel,
    successMessage,
    errorMessage,
    disabled = false,
    children,
    actions,
    class: className = '',
  }: Props = $props();

  const uid = $props.id();
  const headingId = `${uid}-heading`;
  let saving = $state(false);
  let success = $state('');
  let failure = $state('');
  let summary: HTMLDivElement | undefined = $state();

  const isDirty = (): boolean => dirty === true;
  const ask = (message: string): boolean => (confirmLeave ?? ((m: string) => window.confirm(m)))(message);
  const onBeforeUnload = beforeUnloadWarning(isDirty);

  // The navigation guard is registered only while the form is dirty.
  $effect(() => {
    if (dirty !== true || addGuard === undefined) {
      return;
    }
    return addGuard(unsavedChangesGuard(isDirty, ask, t('adminComponents.form.leaveConfirm')));
  });

  // The success message no longer applies once the form is edited again.
  $effect(() => {
    if (dirty === true) {
      success = '';
    }
  });

  async function focusFirstError(): Promise<void> {
    await tick();
    const first = errors[0];
    if (first === undefined || !focusById(document, first.id)) {
      summary?.focus();
    }
  }

  async function submit(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    if (saving) {
      return;
    }
    success = '';
    failure = '';
    if (dirty === false) {
      errors = [];
      success = t('admin.common.noChanges');
      return;
    }
    const clientErrors = validate?.() ?? [];
    if (clientErrors.length > 0) {
      errors = [...clientErrors];
      await focusFirstError();
      return;
    }
    errors = [];
    saving = true;
    let outcome;
    try {
      outcome = normalizeOutcome(await onsubmit());
    } catch {
      outcome = { ok: false, message: errorMessage ?? t('errors.unknown'), errors: [] };
    } finally {
      saving = false;
    }
    if (outcome.ok) {
      success = outcome.message ?? successMessage ?? t('admin.common.saved');
      return;
    }
    errors = outcome.errors;
    failure = outcome.message ?? '';
    if (errors.length > 0) {
      await focusFirstError();
    } else if (failure !== '') {
      await tick();
      summary?.focus();
    }
  }

  function goTo(event: MouseEvent, id: string): void {
    // The link would change the URL hash (and trigger popstate): focus the field instead.
    event.preventDefault();
    focusById(document, id);
  }
</script>

<svelte:window onbeforeunload={onBeforeUnload} />

{#snippet body()}
  {#if intro}<p class="tt-form__intro">{intro}</p>{/if}
  {#if errors.length > 0 || failure !== ''}
    <Alert
      severity="error"
      bind:element={summary}
      title={errors.length > 0 ? t('admin.common.errorSummary.title') : undefined}
    >
      {#if failure !== ''}<p>{failure}</p>{/if}
      {#if errors.length > 0}
        <p>{t('admin.common.errorSummary.count', { count: errors.length })}</p>
        <ul class="tt-form__summary">
          {#each errors as item (item.id)}
            <li>
              <a href="#{item.id}" onclick={(e) => goTo(e, item.id)}>
                {t('adminComponents.form.errorLink', { label: item.label, message: item.message })}
              </a>
            </li>
          {/each}
        </ul>
      {/if}
    </Alert>
  {/if}
  {@render children()}
  <div class="tt-form__actions">
    <Button type="submit" loading={saving} loadingLabel={savingLabel ?? t('admin.common.saving')} {disabled}>
      {saveLabel ?? t('admin.common.save')}
    </Button>
    {#if actions}{@render actions()}{/if}
  </div>
  <div class="tt-form__result">
    <LiveRegion message={success} visible />
  </div>
{/snippet}

{#if as === 'fieldset'}
  <form class="tt-form {className}" novalidate onsubmit={submit}>
    <fieldset class="tt-form__fieldset">
      <legend class="tt-form__legend">{title}</legend>
      {@render body()}
    </fieldset>
  </form>
{:else}
  <section class="tt-form {className}" aria-labelledby={headingId}>
    <svelte:element this={`h${headingLevel}`} id={headingId} class="tt-form__heading">{title}</svelte:element>
    <form novalidate onsubmit={submit} aria-labelledby={headingId}>
      {@render body()}
    </form>
  </section>
{/if}

<style>
  .tt-form {
    margin-bottom: var(--tt-space-8);
  }

  .tt-form__fieldset {
    margin: 0;
    padding: 0;
    border: 0;
    min-width: 0;
  }

  .tt-form__legend {
    padding: 0;
    margin-bottom: var(--tt-space-3);
    font-size: var(--tt-font-size-lg);
    font-weight: var(--tt-font-weight-bold);
  }

  .tt-form__heading {
    margin: 0 0 var(--tt-space-3);
  }

  .tt-form__intro {
    margin: 0 0 var(--tt-space-4);
    color: var(--tt-muted);
  }

  .tt-form__summary {
    margin: var(--tt-space-1) 0 0;
    padding-left: var(--tt-space-5);
  }

  .tt-form__summary a {
    color: var(--tt-link);
  }

  .tt-form__actions {
    display: flex;
    flex-wrap: wrap;
    gap: var(--tt-space-3);
    align-items: center;
    margin-top: var(--tt-space-4);
  }

  .tt-form__result {
    margin-top: var(--tt-space-2);
    font-weight: var(--tt-font-weight-bold);
  }
</style>
