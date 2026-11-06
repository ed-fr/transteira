<script lang="ts">
  // Edition of a drop link in a modal dialog (PATCH …/drop-links/{dropLinkId}, JSON Merge Patch):
  // label, recipients, validity, level (null: the tenant default) and enabled switch; only the
  // changed fields are sent. The token never changes (rotate the link for that). A revoked link
  // answers 409, shown as a general message. The form is rebuilt from the link at each opening;
  // closing with unsaved changes asks for a confirmation first.
  import { untrack } from 'svelte';
  import { describeError } from '../../../shared/api/problem';
  import { Button, Dialog } from '../../../shared/components';
  import { i18n, t } from '../../../shared/i18n/i18n.svelte';
  import { adminApi } from '../../api';
  import FormSection from '../../components/FormSection.svelte';
  import { unsavedChangesGuard, type SubmitOutcome, type SummaryError } from '../../components/form';
  import type { AddGuard } from '../types';
  import DropLinkFormFields from './DropLinkFormFields.svelte';
  import {
    buildDropLinkPatch,
    dropFormFrom,
    dropLinkErrorOutcome,
    dropPatchEmpty,
    validateDropLink,
    type DropLink,
    type DropLinkForm,
  } from './dropLinks';

  interface Props {
    /** Bound open state. */
    open?: boolean;
    /** The link to edit. */
    link: DropLink;
    /** Tenant of the link. */
    tenantId: string;
    /** Options of the level select (the first one is the tenant default). */
    levels: readonly { value: string; label: string }[];
    /** Registers a navigation guard (router.addGuard). */
    addGuard: AddGuard;
    /** Called with the updated link after a successful save (the dialog then closes). */
    onsaved: (link: DropLink) => void;
    /** Asks the user to confirm discarding changes (default window.confirm). */
    confirmDiscard?: (message: string) => boolean;
  }

  let {
    open = $bindable(false),
    link,
    tenantId,
    levels,
    addGuard,
    onsaved,
    confirmDiscard,
  }: Props = $props();

  const uid = $props.id();
  const ids = {
    label: `${uid}-label`,
    recipients: `${uid}-recipients`,
    validity: `${uid}-validity`,
    level: `${uid}-level`,
    expiry: `${uid}-expiry`,
    cap: `${uid}-cap`,
  };

  let form = $state<DropLinkForm>(untrack(() => dropFormFrom(link)));
  let errors = $state<SummaryError[]>([]);

  const fields = $derived({
    label: { id: ids.label, label: t('opsDropLinks.form.label.label') },
    recipients: { id: ids.recipients, label: t('opsDropLinks.form.recipients.label') },
    validityDays: { id: ids.validity, label: t('opsDropLinks.form.validity.legend') },
    confidentialityLevel: { id: ids.level, label: t('opsDropLinks.form.level.label') },
    expiresAt: { id: ids.expiry, label: t('opsDropLinks.form.expiry.label') },
    maxDepositsPerHour: { id: ids.cap, label: t('opsDropLinks.form.cap.label') },
  });
  const dirty = $derived(open && !dropPatchEmpty(buildDropLinkPatch(link, form)));

  const ask = (message: string): boolean => (confirmDiscard ?? ((m: string) => window.confirm(m)))(message);
  /** True when the dialog may close: no unsaved change, or discarding them confirmed. */
  const mayClose = (): boolean =>
    unsavedChangesGuard(() => dirty, ask, t('opsDropLinks.edit.discardConfirm'))('');

  function cancel(): void {
    if (mayClose()) {
      open = false;
    }
  }

  // Each opening starts again from the link as listed.
  $effect.pre(() => {
    if (open) {
      untrack(() => {
        form = dropFormFrom(link);
        errors = [];
      });
    }
  });

  async function save(): Promise<SubmitOutcome> {
    try {
      const res = await adminApi.patch('/admin/tenants/{tenantId}/drop-links/{dropLinkId}', {
        path: { tenantId, dropLinkId: link.id },
        body: buildDropLinkPatch(link, form),
      });
      onsaved(res.data);
      open = false;
      return { ok: true, message: t('opsDropLinks.edit.saved') };
    } catch (err) {
      return dropLinkErrorOutcome(describeError(i18n, err), fields, t);
    }
  }
</script>

<Dialog bind:open title={t('opsDropLinks.edit.title', { label: link.label })} beforeclose={mayClose}>
  {#if open}
    <FormSection
      as="fieldset"
      title={t('opsDropLinks.edit.legend')}
      intro={t('opsDropLinks.edit.intro')}
      {dirty}
      {addGuard}
      validate={() => validateDropLink(form, fields, t)}
      onsubmit={save}
      bind:errors
    >
      <DropLinkFormFields bind:form {ids} {errors} {levels} />
      {#snippet actions()}
        <Button variant="secondary" onclick={cancel}>
          {t('admin.common.cancel')}
        </Button>
      {/snippet}
    </FormSection>
  {/if}
</Dialog>
