<script lang="ts">
  // Search form of the transfers of the administration (CLAUDE.md section 13.2; plan of step 3c,
  // deviation 3), in the header of the home page and on the /search screen: a search landmark
  // holding a labelled search input (label visually hidden in the header, visible on the screen)
  // and a 44 px submit button with the search icon, named "Search". The query is checked by
  // checkQuery (screens/search.ts: not empty, no address for an auditor) before onsearch is
  // called with the trimmed query; an invalid query shows its error under the input (aria-invalid,
  // aria-describedby) and moves the focus there, or announces it when the input already has the
  // focus (sent with Enter: signalQueryError). The query never goes to the URL nor to a browser
  // storage (threat model T-412): the screen keeps it in memory (searchQuery store).
  //
  //   <TransferSearchForm auditor={isAuditor} bind:value={query} error={fieldError}
  //                       onsearch={(q) => run(q)} />
  //
  // Props:
  //   value        the text of the input (bindable)
  //   auditor      an auditor: identifier only (placeholder, hint and check)
  //   error        error message of the input (e.g. from the server), shown under it
  //   busy         a search is running: the button shows its loading state
  //   labelHidden  the label is read by screen readers only (default true, the page header)
  //   hint         visible help text under the label (the /search screen)
  //   onsearch     called with the checked query
  //   input        the input element (bindable), to move the focus to it
  import { tick } from 'svelte';
  import Button from '../../shared/components/Button.svelte';
  import Icon from '../../shared/components/Icon.svelte';
  import { announce } from '../../shared/components/announce.svelte';
  import { describedBy } from '../../shared/components/helpers';
  import { t } from '../../shared/i18n/i18n.svelte';
  import { QUERY_MAX_LENGTH, checkQuery, signalQueryError } from '../screens/search';

  interface Props {
    value?: string;
    auditor: boolean;
    error?: string | undefined;
    busy?: boolean;
    labelHidden?: boolean;
    hint?: string | undefined;
    onsearch: (query: string) => void | Promise<void>;
    input?: HTMLInputElement | undefined;
    class?: string;
  }

  let {
    value = $bindable(''),
    auditor,
    error,
    busy = false,
    labelHidden = true,
    hint,
    onsearch,
    input = $bindable(),
    class: className = '',
  }: Props = $props();

  const uid = $props.id();
  const inputId = `${uid}-q`;
  const hintId = `${uid}-hint`;
  const errorId = `${uid}-error`;

  // A local error (the client-side check) hides the error given by the screen until the next
  // search: the screen clears its own error when a search starts.
  let localError = $state('');
  const shown = $derived(localError !== '' ? localError : (error ?? ''));
  const invalid = $derived(shown !== '');

  async function submit(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    if (busy) {
      return;
    }
    const check = checkQuery(value, auditor, t);
    if (!check.ok) {
      const active = document.activeElement;
      localError = check.error;
      // The error and the aria-describedby of the input are rendered before the focus moves.
      await tick();
      signalQueryError(input, active, check.error, t, (message) => announce(message, 'assertive'));
      return;
    }
    localError = '';
    void onsearch(check.query);
  }
</script>

<form
  class="tt-search {className}"
  role="search"
  aria-label={t('adminSearch.form.landmark')}
  novalidate
  onsubmit={(event) => void submit(event)}
>
  <label class="tt-search__label" class:visually-hidden={labelHidden} for={inputId}
    >{t('adminSearch.form.label')}</label
  >
  {#if hint}
    <p class="tt-search__hint" id={hintId}>{hint}</p>
  {/if}
  <div class="tt-search__row">
    <input
      bind:this={input}
      bind:value
      id={inputId}
      class="tt-search__input"
      type="search"
      enterkeyhint="search"
      autocomplete="off"
      autocapitalize="off"
      spellcheck="false"
      maxlength={QUERY_MAX_LENGTH}
      placeholder={t(auditor ? 'adminSearch.form.placeholderAuditor' : 'adminSearch.form.placeholder')}
      aria-invalid={invalid ? 'true' : undefined}
      aria-describedby={describedBy(hint && hintId, invalid && errorId)}
    />
    <Button
      type="submit"
      class="tt-search__submit"
      loading={busy}
      loadingLabel={t('adminSearch.form.searching')}
    >
      <Icon name="search" size="sm" />
      <span class="visually-hidden">{t('adminSearch.form.submit')}</span>
    </Button>
  </div>
  {#if invalid}
    <p class="tt-search__error" id={errorId}>
      <span class="visually-hidden">{t('components.field.errorPrefix')}</span>
      {shown}
    </p>
  {/if}
</form>

<style>
  .tt-search {
    display: flex;
    flex-direction: column;
    gap: var(--tt-space-1);
    min-width: 0;
    max-width: 100%;
  }

  .tt-search__label {
    font-weight: var(--tt-font-weight-bold);
  }

  .tt-search__hint {
    margin: 0 0 var(--tt-space-1);
    color: var(--tt-muted);
    font-size: var(--tt-font-size-sm);
  }

  .tt-search__row {
    display: flex;
    align-items: stretch;
    gap: var(--tt-space-2);
    min-width: 0;
  }

  /*
   * 340 px wide at the base font size, so that the longest placeholder ("Rechercher une adresse, un
   * transfert…") is visible whole; shrinking on narrow screens.
   */
  .tt-search__input {
    flex: 1 1 auto;
    width: 21.25rem;
    min-width: 0;
    min-height: var(--tt-control-height);
    padding: var(--tt-space-2) 0.875rem;
    border: var(--tt-border-width) solid var(--tt-border);
    border-radius: 0.625rem;
    background: var(--tt-surface);
    color: var(--tt-text);
  }

  .tt-search__input::placeholder {
    color: var(--tt-muted);
    opacity: 1;
  }

  .tt-search__input[aria-invalid='true'] {
    border-width: 2px;
    border-color: var(--tt-danger);
  }

  .tt-search :global(.tt-search__submit) {
    flex: none;
    min-width: var(--tt-control-height);
    padding: var(--tt-space-2) 0.875rem;
    border-radius: 0.625rem;
  }

  .tt-search__error {
    margin: 0;
    color: var(--tt-danger);
    font-size: var(--tt-font-size-sm);
    font-weight: var(--tt-font-weight-bold);
  }

  @media (forced-colors: active) {
    .tt-search__input::placeholder {
      color: GrayText;
    }
  }
</style>
