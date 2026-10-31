<script lang="ts">
  // Delivery of the activation link of a delegated admin (since API 1.2): radio group "send by
  // mail" (default) or "show the link to copy", and, with the mail, the language of the mail.
  // Used by the admin creation, the new invitation of an account and the creation of a tenant
  // with its first administrator. With allowMail false (super admin account) the mail is not
  // offered: the delivery is forced to the copy and a note says why.
  import { RadioGroup } from '../../shared/components';
  import { locale, t } from '../../shared/i18n/i18n.svelte';
  import {
    INVITATION_LANGUAGES,
    asInvitationLanguage,
    type InvitationDelivery,
    type InvitationLanguage,
  } from '../screens/admins/admins';
  import { languageLabel } from '../screens/tenants/tenants';
  import SelectField from './SelectField.svelte';

  interface Props {
    /** Prefix of the element ids. */
    idPrefix: string;
    /** Bound delivery. */
    delivery: InvitationDelivery;
    /** Bound language of the mail. */
    language: InvitationLanguage;
    /** The mail delivery is offered (false for a super admin account). */
    allowMail?: boolean;
    /** Error message of the delivery. */
    error?: string | undefined;
  }

  let { idPrefix, delivery = $bindable(), language = $bindable(), allowMail = true, error }: Props = $props();

  const languageOptions = $derived(
    INVITATION_LANGUAGES.map((code) => ({ value: code, label: languageLabel(code, locale.current) })),
  );
  const deliveryOptions = $derived<{ value: InvitationDelivery; label: string; hint: string }[]>([
    {
      value: 'mail',
      label: t('adminAccounts.invitation.delivery.mail.label'),
      hint: t('adminAccounts.invitation.delivery.mail.hint'),
    },
    {
      value: 'copy',
      label: t('adminAccounts.invitation.delivery.copy.label'),
      hint: t('adminAccounts.invitation.delivery.copy.hint'),
    },
  ]);
</script>

{#if allowMail}
  <RadioGroup
    name="{idPrefix}-delivery"
    legend={t('adminAccounts.invitation.delivery.legend')}
    options={deliveryOptions}
    {error}
    bind:value={delivery}
  />
  {#if delivery === 'mail'}
    <SelectField
      id="{idPrefix}-language"
      label={t('adminAccounts.invitation.language.label')}
      hint={t('adminAccounts.invitation.language.hint')}
      options={languageOptions}
      bind:value={() => language, (value) => (language = asInvitationLanguage(value, language))}
    />
  {/if}
{:else}
  <p id="{idPrefix}-copy-only">{t('adminAccounts.invitation.copyOnly')}</p>
{/if}
