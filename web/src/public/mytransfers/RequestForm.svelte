<script lang="ts">
  // Request of a "My transfers" access link (CLAUDE.md section 8.7): the sender types their
  // address, the answer is always the same neutral confirmation (no enumeration). The link is
  // mailed only when the address was verified before.
  import { onMount } from 'svelte';
  import { api } from '../../shared/api/api';
  import { languageValues } from '../../shared/api/schema';
  import { Alert, Button, TextField, announce } from '../../shared/components';
  import { i18n, t } from '../../shared/i18n/i18n.svelte';
  import { isEmail } from '../../shared/validation/email';
  import Countdown from '../deposit/Countdown.svelte';
  import { requestFailure } from './logic';

  interface Props {
    /** Why the form is shown instead of the list. */
    notice?: 'expired-session' | 'invalid-link' | undefined;
    /** Called once the request was accepted. */
    onsent: () => void;
  }

  let { notice, onsent }: Props = $props();

  let email = $state('');
  let emailError = $state<string | undefined>();
  let formError = $state<string | undefined>();
  let busy = $state(false);
  let retryAt = $state<number | undefined>(undefined);
  let remaining = $state(0);
  let heading: HTMLElement | undefined = $state();
  let input: HTMLInputElement | undefined = $state();

  onMount(() => heading?.focus());

  function language(): 'fr' | 'en' {
    const current = i18n.locale.current;
    return (languageValues as readonly string[]).includes(current) ? (current as 'fr' | 'en') : 'en';
  }

  async function submit(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    if (busy || remaining > 0) {
      return;
    }
    const value = email.trim();
    formError = undefined;
    if (value === '' || !isEmail(value)) {
      emailError = value === '' ? t('myTransfers.request.required') : t('myTransfers.request.invalid');
      input?.focus();
      return;
    }
    emailError = undefined;
    busy = true;
    try {
      await api.post('/me/access-links', { body: { email: value, language: language() } });
      announce(t('myTransfers.request.sentTitle'));
      onsent();
    } catch (err) {
      const failure = requestFailure(err);
      switch (failure.kind) {
        case 'rate-limited':
          retryAt = Date.now() + (failure.retryAfterSeconds ?? 60) * 1000;
          formError = t('myTransfers.request.rateLimited');
          break;
        case 'mail-unavailable':
          formError = t('myTransfers.request.mailUnavailable');
          break;
        case 'invalid-email':
          emailError = t('myTransfers.request.invalid');
          input?.focus();
          break;
        default:
          formError = t('common.error.text');
      }
    } finally {
      busy = false;
    }
  }
</script>

<h1 tabindex="-1" bind:this={heading}>{t('myTransfers.title')}</h1>

{#if notice === 'expired-session'}
  <Alert severity="info">{t('myTransfers.notice.expiredSession')}</Alert>
{:else if notice === 'invalid-link'}
  <Alert severity="warning">{t('myTransfers.notice.invalidLink')}</Alert>
{/if}

<p>{t('myTransfers.request.intro')}</p>
{#if formError}
  <Alert severity="error">{formError}</Alert>
{/if}
<form class="tt-stack" novalidate onsubmit={submit}>
  <TextField
    label={t('myTransfers.request.label')}
    type="email"
    autocomplete="email"
    spellcheck={false}
    required
    hint={t('myTransfers.request.hint')}
    error={emailError}
    bind:value={email}
    bind:element={input}
  />
  <Countdown until={retryAt} bind:remaining />
  <div class="tt-cluster">
    <Button type="submit" loading={busy} disabled={remaining > 0}>{t('myTransfers.request.submit')}</Button>
  </div>
</form>
