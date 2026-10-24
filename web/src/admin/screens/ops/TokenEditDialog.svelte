<script lang="ts">
  // Edition of an API token in a modal dialog (PATCH …/api-tokens/{tokenId}, JSON Merge Patch):
  // name, allowed ranges and allowed senders; only the changed fields are sent, an emptied sender
  // list is sent as [] (any internal address again). The expiry cannot be changed. A revoked
  // token answers 409, shown as a general message. The form is rebuilt from the token at each
  // opening and dropped when the dialog closes; closing with unsaved changes (Cancel, Escape,
  // close button) asks for a confirmation first, as leaving a page with unsaved changes does.
  import { untrack } from 'svelte';
  import { describeError } from '../../../shared/api/problem';
  import { Button, Dialog, TextField } from '../../../shared/components';
  import { i18n, t } from '../../../shared/i18n/i18n.svelte';
  import { adminApi } from '../../api';
  import FormSection from '../../components/FormSection.svelte';
  import LineListEditor from '../../components/LineListEditor.svelte';
  import {
    errorFor,
    unsavedChangesGuard,
    type SubmitOutcome,
    type SummaryError,
  } from '../../components/form';
  import { isEmptyPatch } from '../../forms/patch';
  import type { AddGuard } from '../types';
  import {
    buildTokenPatch,
    editFormFrom,
    MAX_TOKEN_CIDRS,
    MAX_TOKEN_SENDERS,
    parseSender,
    senderLineMessage,
    TOKEN_NAME_MAX,
    tokenCidrLineMessage,
    tokenErrorOutcome,
    validateEdit,
    type ApiToken,
    type EditForm,
  } from './tokens';
  import { parseCidr } from '../../forms/cidr';

  interface Props {
    /** Bound open state. */
    open?: boolean;
    /** The token to edit. */
    token: ApiToken;
    /** Tenant of the token. */
    tenantId: string;
    /** Registers a navigation guard (router.addGuard). */
    addGuard: AddGuard;
    /** Called with the updated token after a successful save (the dialog then closes). */
    onsaved: (token: ApiToken) => void;
    /** Asks the user to confirm discarding changes (default window.confirm). */
    confirmDiscard?: (message: string) => boolean;
  }

  let { open = $bindable(false), token, tenantId, addGuard, onsaved, confirmDiscard }: Props = $props();

  const uid = $props.id();
  const ids = { name: `${uid}-name`, cidrs: `${uid}-cidrs`, senders: `${uid}-senders` };

  let form = $state<EditForm>(untrack(() => editFormFrom(token)));
  let errors = $state<SummaryError[]>([]);

  const fields = $derived({
    name: { id: ids.name, label: t('opsTokens.form.name.label') },
    allowedCidrs: { id: ids.cidrs, label: t('opsTokens.form.cidrs.label') },
    allowedSenders: { id: ids.senders, label: t('opsTokens.form.senders.label') },
  });
  const patch = $derived(buildTokenPatch(token, form));
  const dirty = $derived(open && !isEmptyPatch(patch));

  const ask = (message: string): boolean => (confirmDiscard ?? ((m: string) => window.confirm(m)))(message);
  /** True when the dialog may close: no unsaved change, or discarding them confirmed. */
  const mayClose = (): boolean =>
    unsavedChangesGuard(() => dirty, ask, t('opsTokens.edit.discardConfirm'))('');

  function cancel(): void {
    if (mayClose()) {
      open = false;
    }
  }

  // Each opening starts again from the token as listed.
  $effect.pre(() => {
    if (open) {
      untrack(() => {
        form = editFormFrom(token);
        errors = [];
      });
    }
  });

  async function save(): Promise<SubmitOutcome> {
    const body = buildTokenPatch(token, form);
    const sent = { cidrText: form.cidrText, senderText: form.senderText };
    try {
      const res = await adminApi.patch('/admin/tenants/{tenantId}/api-tokens/{tokenId}', {
        path: { tenantId, tokenId: token.id },
        body,
      });
      onsaved(res.data);
      open = false;
      return { ok: true, message: t('opsTokens.edit.saved') };
    } catch (err) {
      return tokenErrorOutcome(describeError(i18n, err), fields, sent, t);
    }
  }
</script>

<Dialog bind:open title={t('opsTokens.edit.title', { name: token.name })} beforeclose={mayClose}>
  {#if open}
    <FormSection
      as="fieldset"
      title={t('opsTokens.edit.legend')}
      intro={t('opsTokens.edit.intro')}
      {dirty}
      {addGuard}
      validate={() => validateEdit(form, fields, t)}
      onsubmit={save}
      bind:errors
    >
      <TextField
        id={ids.name}
        label={t('opsTokens.form.name.label')}
        bind:value={form.name}
        required
        maxlength={TOKEN_NAME_MAX}
        autocomplete="off"
        error={errorFor(errors, ids.name)}
      />
      <LineListEditor
        id={ids.cidrs}
        label={t('opsTokens.form.cidrs.label')}
        hint={t('opsTokens.form.cidrs.hint')}
        bind:value={form.cidrText}
        parse={parseCidr}
        max={MAX_TOKEN_CIDRS}
        required
        rows={4}
        message={(e) => {
          const m = tokenCidrLineMessage(e);
          return t(m.key, m.params);
        }}
        error={errorFor(errors, ids.cidrs)}
      />
      <LineListEditor
        id={ids.senders}
        label={t('opsTokens.form.senders.label')}
        hint={t('opsTokens.form.senders.hint')}
        bind:value={form.senderText}
        parse={parseSender}
        max={MAX_TOKEN_SENDERS}
        rows={4}
        message={(e) => {
          const m = senderLineMessage(e);
          return t(m.key, m.params);
        }}
        error={errorFor(errors, ids.senders)}
      />
      {#snippet actions()}
        <Button variant="secondary" onclick={cancel}>
          {t('admin.common.cancel')}
        </Button>
      {/snippet}
    </FormSection>
  {/if}
</Dialog>
