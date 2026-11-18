<script lang="ts">
  // Form of the express secret page /x (CLAUDE.md section 22.2): the text (with a counter in
  // Unicode code points, e2e-format section 3.3.9, read by screen readers once typing pauses), the
  // duration and the button. Client-side checks mirror the format (express.ts); on refusal, the
  // error summary (or the error message) takes the focus and links to the fields (RGAA 11.10).
  // The text is kept out of spell checkers and autofill (spellcheck off, autocomplete off) and has
  // no maxlength: a textarea counts UTF-16 code units, which would refuse texts of fewer than
  // 10 000 code points.
  import { onDestroy, tick, untrack } from 'svelte';
  import { Alert, Button, LiveRegion, RadioGroup, TextArea } from '../../shared/components';
  import { t } from '../../shared/i18n/i18n.svelte';
  import { Countdown } from '../screens/countdown.svelte';
  import { codePoints } from './create';
  import type { ExpressField } from './express';
  import type { ExpressSecretFlow } from './expressFlow.svelte';
  import { LiveCounter } from './liveCounter.svelte';

  interface Props {
    /** The express flow, on its form or working step. */
    flow: ExpressSecretFlow;
  }

  let { flow }: Props = $props();

  const ids: Record<ExpressField, string> = {
    text: 'tt-express-text',
    expiresIn: 'tt-express-duration',
  };

  let summary: HTMLDivElement | undefined = $state();
  let problem: HTMLDivElement | undefined = $state();

  const errors = $derived(flow.errors);
  const fields = $derived(flow.invalidFields);
  const busy = $derived(flow.busy);
  const durationOptions = $derived(
    flow.durations.map((d) => ({ value: d, label: t(`secretCreate.duration.${d}`) })),
  );
  const phaseLabel = $derived(t(`secretExpress.working.${flow.phase ?? 'sealing'}`));

  function counterText(count: number): string {
    const max = flow.maxChars;
    return count > max
      ? t('secretExpress.text.counterOver', { count, max })
      : t('components.textArea.counter', { count, max });
  }

  // The count is announced after a pause in typing (the visible counter is TextArea's own).
  const counter = new LiveCounter(untrack(() => counterText(flow.textLength)));
  onDestroy(() => counter.reset());

  // A rate-limited creation: the button stays disabled until the time given by the server.
  const limit = new Countdown();
  onDestroy(() => limit.stop());
  $effect(() => {
    if (flow.retryAt !== undefined) limit.start(flow.secondsBeforeRetry());
  });

  function fieldLabel(field: ExpressField): string {
    return field === 'text' ? t('secretExpress.text.label') : t('secretExpress.duration.legend');
  }

  function focusField(event: MouseEvent, field: ExpressField): void {
    event.preventDefault();
    const target =
      field === 'expiresIn'
        ? document.querySelector<HTMLElement>(`input[name="${ids.expiresIn}"]`)
        : document.getElementById(ids.text);
    target?.focus();
  }

  // Focus the error summary (or the error message) each time the form is refused.
  let refusals = untrack(() => flow.refusals);
  $effect(() => {
    const count = flow.refusals;
    if (count !== refusals) {
      refusals = count;
      void tick().then(() => (summary ?? problem)?.focus());
    }
  });

  function submit(event: SubmitEvent): void {
    event.preventDefault();
    void flow.submit();
  }
</script>

<h1 tabindex="-1">{t('secretExpress.title')}</h1>
<p>{t('secretExpress.intro')}</p>
<p class="tt-text-sm tt-text-muted">{t('secretExpress.anonymous')}</p>

{#if flow.errorText}
  <Alert severity="error" bind:element={problem}>
    <span id="tt-express-error">{flow.errorText}</span>
  </Alert>
{/if}

{#if fields.length > 0}
  <Alert severity="error" title={t('secretCreate.summary', { count: fields.length })} bind:element={summary}>
    <ul class="tt-mb-0">
      {#each fields as field (field)}
        <li><a href="#{ids[field]}" onclick={(e) => focusField(e, field)}>{fieldLabel(field)}</a></li>
      {/each}
    </ul>
  </Alert>
{/if}

<form id="tt-express-form" class="tt-stack" novalidate onsubmit={submit} aria-busy={busy}>
  <TextArea
    id={ids.text}
    label={t('secretExpress.text.label')}
    hint={t('secretExpress.text.hint', { max: flow.maxChars })}
    required
    rows={8}
    spellcheck={false}
    autocomplete="off"
    autocapitalize="off"
    counterMax={flow.maxChars}
    countLength={codePoints}
    readonly={busy}
    error={errors.text === undefined ? undefined : t(errors.text.key, errors.text.params)}
    oninput={(event) => counter.update(counterText(codePoints(event.currentTarget.value)))}
    bind:value={flow.text}
  />
  <LiveRegion message={counter.message} />

  <RadioGroup
    legend={t('secretExpress.duration.legend')}
    hint={t('secretExpress.duration.hint')}
    name={ids.expiresIn}
    options={durationOptions}
    required
    inline
    disabled={busy}
    error={errors.expiresIn === undefined ? undefined : t(errors.expiresIn.key, errors.expiresIn.params)}
    bind:value={flow.expiresIn}
  />

  <Button
    id="tt-express-submit"
    type="submit"
    loading={busy}
    disabled={limit.active}
    loadingLabel={phaseLabel}
  >
    {t('secretExpress.submit')}
  </Button>
</form>
