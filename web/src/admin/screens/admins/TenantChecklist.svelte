<script lang="ts">
  // Entities attached to a delegated admin: one checkbox per entity in a fieldset with its
  // legend, hint and error (RGAA 11.5, 11.6). The first checkbox has the id idPrefix-0, the
  // target of the error summary link.
  import { t } from '../../../shared/i18n/i18n.svelte';
  import Checkbox from '../../../shared/components/Checkbox.svelte';
  import { describedBy } from '../../../shared/components/helpers';

  interface Props {
    /** Entities offered, in display order. */
    tenants: readonly { id: string; name: string }[];
    /** Bound ids of the selected entities. */
    selected?: string[];
    /** Prefix of the checkbox ids. */
    idPrefix: string;
    /** Error message, linked to the group. */
    error?: string | undefined;
    /** Disables the whole group. */
    disabled?: boolean;
  }

  let { tenants, selected = $bindable([]), idPrefix, error, disabled = false }: Props = $props();

  const hintId = $derived(`${idPrefix}-hint`);
  const errorId = $derived(`${idPrefix}-error`);
  const invalid = $derived(error !== undefined && error !== '');

  function toggle(id: string, on: boolean): void {
    const rest = selected.filter((value) => value !== id);
    selected = on ? [...rest, id] : rest;
  }
</script>

<fieldset class="tt-tenants" {disabled} aria-describedby={describedBy(hintId, invalid && errorId)}>
  <legend class="tt-tenants__legend">
    {t('adminAccounts.form.tenants.legend')}
    <span class="tt-tenants__required">{t('components.field.required')}</span>
  </legend>
  <p class="tt-tenants__hint" id={hintId}>{t('adminAccounts.form.tenants.hint')}</p>
  {#if tenants.length === 0}
    <p>{t('adminAccounts.list.noTenant')}</p>
  {:else}
    <ul class="tt-list-plain">
      {#each tenants as tenant, index (tenant.id)}
        <li>
          <Checkbox
            id="{idPrefix}-{index}"
            label={tenant.name}
            checked={selected.includes(tenant.id)}
            onchange={(event) => toggle(tenant.id, event.currentTarget.checked)}
          />
        </li>
      {/each}
    </ul>
  {/if}
  {#if invalid}
    <p class="tt-tenants__error" id={errorId}>
      <span class="visually-hidden">{t('components.field.errorPrefix')}</span>
      {error}
    </p>
  {/if}
</fieldset>

<style>
  .tt-tenants {
    margin: 0 0 var(--tt-space-4);
    padding: 0;
    border: 0;
    min-width: 0;
  }

  .tt-tenants__legend {
    padding: 0;
    margin-bottom: var(--tt-space-1);
    font-weight: var(--tt-font-weight-bold);
  }

  .tt-tenants__required {
    font-weight: normal;
    color: var(--tt-muted);
  }

  .tt-tenants__hint {
    margin: 0 0 var(--tt-space-2);
    color: var(--tt-muted);
  }

  .tt-tenants__error {
    margin: var(--tt-space-1) 0 0;
    color: var(--tt-danger);
    font-weight: var(--tt-font-weight-bold);
  }
</style>
