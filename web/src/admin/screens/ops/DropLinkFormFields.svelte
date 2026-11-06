<script lang="ts">
  // Fields shared by the creation screen and the edition dialog of a drop link: label,
  // recipients (internal addresses, one per line), validity (1, 7 or 30 days), confidentiality
  // level (the tenant default or one of its levels) and enabled switch.
  import { Checkbox, RadioGroup, TextField } from '../../../shared/components';
  import { t } from '../../../shared/i18n/i18n.svelte';
  import LineListEditor from '../../components/LineListEditor.svelte';
  import SelectField from '../../components/SelectField.svelte';
  import { errorFor, type SummaryError } from '../../components/form';
  import { todayInput } from './tokens';
  import {
    DROP_LABEL_MAX,
    MAX_DROP_RECIPIENTS,
    MAX_DEPOSITS_PER_HOUR,
    MIN_DEPOSITS_PER_HOUR,
    VALIDITY_CHOICES,
    parseDropRecipient,
    recipientLineMessage,
    type DropLinkForm,
  } from './dropLinks';

  interface Props {
    /** Bound form values. */
    form: DropLinkForm;
    /** Element ids of the fields. */
    ids: { label: string; recipients: string; validity: string; level: string; expiry: string; cap: string };
    /** Errors of the surrounding FormSection. */
    errors: readonly SummaryError[];
    /** Options of the level select (the first one is the tenant default). */
    levels: readonly { value: string; label: string }[];
  }

  let { form = $bindable(), ids, errors, levels }: Props = $props();

  const validityOptions = $derived(
    VALIDITY_CHOICES.map((d) => ({ value: d, label: t('opsDropLinks.form.validity.days', { count: d }) })),
  );

  const minDate = todayInput(new Date());
</script>

<TextField
  id={ids.label}
  label={t('opsDropLinks.form.label.label')}
  hint={t('opsDropLinks.form.label.hint')}
  bind:value={form.label}
  required
  maxlength={DROP_LABEL_MAX}
  autocomplete="off"
  error={errorFor(errors, ids.label)}
/>

<LineListEditor
  id={ids.recipients}
  label={t('opsDropLinks.form.recipients.label')}
  hint={t('opsDropLinks.form.recipients.hint')}
  bind:value={form.recipientText}
  parse={parseDropRecipient}
  max={MAX_DROP_RECIPIENTS}
  required
  rows={4}
  message={(e) => {
    const m = recipientLineMessage(e);
    return t(m.key, m.params);
  }}
  error={errorFor(errors, ids.recipients)}
/>

<RadioGroup
  legend={t('opsDropLinks.form.validity.legend')}
  hint={t('opsDropLinks.form.validity.hint')}
  name={ids.validity}
  options={validityOptions}
  required
  inline
  error={errorFor(errors, ids.validity)}
  bind:value={form.validityDays}
/>

<SelectField
  id={ids.level}
  label={t('opsDropLinks.form.level.label')}
  hint={t('opsDropLinks.form.level.hint')}
  options={levels}
  bind:value={form.level}
  error={errorFor(errors, ids.level)}
/>

<TextField
  id={ids.expiry}
  label={t('opsDropLinks.form.expiry.label')}
  hint={t('opsDropLinks.form.expiry.hint')}
  type="date"
  min={minDate}
  bind:value={form.expiry}
  error={errorFor(errors, ids.expiry)}
/>

<TextField
  id={ids.cap}
  label={t('opsDropLinks.form.cap.label')}
  hint={t('opsDropLinks.form.cap.hint', { max: MAX_DEPOSITS_PER_HOUR })}
  type="number"
  min={String(MIN_DEPOSITS_PER_HOUR)}
  max={String(MAX_DEPOSITS_PER_HOUR)}
  inputmode="numeric"
  bind:value={form.maxDepositsPerHour}
  required
  error={errorFor(errors, ids.cap)}
/>

<Checkbox
  label={t('opsDropLinks.form.enabled.label')}
  hint={t('opsDropLinks.form.enabled.hint')}
  bind:checked={form.enabled}
/>
