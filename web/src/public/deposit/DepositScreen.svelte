<script lang="ts">
  // Public deposit page (CLAUDE.md sections 7, 8, 9): mounted at "/" and, after the invitation
  // landing, at "/i/:token" with the invitation context. Renders the step of the deposit flow
  // (flow.svelte.ts) inside the page layout provided by the application; moves the focus to the
  // heading of each new step and warns before leaving the page during an upload.
  //
  // Contract with the application (public App.svelte):
  //   <DepositScreen tenant={publicTenant} invitation={{ token, email, invitedBy, message }}
  //                  onnavigate={(path) => router.navigate(path)}
  //                  addGuard={(guard) => router.addGuard(guard)} />
  // The guard asks for a confirmation before an in-app navigation interrupts an upload.
  // Key the component on the invitation token: the flow is built from the initial props.
  import { onDestroy, onMount, tick, untrack } from 'svelte';
  import { Alert, Button, Spinner } from '../../shared/components';
  import { t } from '../../shared/i18n/i18n.svelte';
  import CodeStep from './CodeStep.svelte';
  import { browserDeps } from './deps';
  import DoneStep from './DoneStep.svelte';
  import EmailStep from './EmailStep.svelte';
  import FinalizeStep from './FinalizeStep.svelte';
  import {
    DepositFlow,
    type DepositFlowDeps,
    type InvitationContext,
    type PublicTenant,
    type Step,
  } from './flow.svelte';
  import ResumePrompt from './ResumePrompt.svelte';
  import TransferForm from './TransferForm.svelte';
  import UploadStep from './UploadStep.svelte';

  interface Props {
    /** Public description of the tenant (GET /tenant). */
    tenant: PublicTenant;
    /** Invitation the depositor arrived with (external deposit). */
    invitation?: InvitationContext | undefined;
    /** In-app navigation (router.navigate), used by the "Invite someone" link. */
    onnavigate?: ((path: string) => void) | undefined;
    /** Registers a navigation guard (router.addGuard) and returns its removal. */
    addGuard?: ((guard: (path: string) => boolean) => () => void) | undefined;
    /** Dependencies of the flow (tests); the browser ones by default. */
    deps?: DepositFlowDeps | undefined;
  }

  let { tenant, invitation, onnavigate, addGuard, deps }: Props = $props();

  const flow = untrack(() => new DepositFlow(tenant, invitation, deps ?? browserDeps()));
  let container: HTMLElement | undefined = $state();

  onMount(() => {
    void flow.start();
    return addGuard?.(() => flow.confirmLeave());
  });

  onDestroy(() => flow.dispose());

  // Focus the heading of each new step (not on the first render: the router handles it).
  let previous: Step = 'loading';
  $effect(() => {
    const step = flow.step;
    if (step === previous) {
      return;
    }
    const first = previous === 'loading';
    previous = step;
    if (!first) {
      void tick().then(() => container?.querySelector<HTMLElement>('h1')?.focus());
    }
  });

  function beforeUnload(event: BeforeUnloadEvent): void {
    if (flow.isUploading()) {
      event.preventDefault();
      // Legacy browsers need returnValue set to show the confirmation.
      event.returnValue = '';
    }
  }
</script>

<svelte:window onbeforeunload={beforeUnload} />

<div class="tt-stack" bind:this={container}>
  {#if flow.step === 'loading'}
    <h1 tabindex="-1" class="visually-hidden">{t('deposit.loading')}</h1>
    <Spinner label={t('deposit.loading')} showLabel />
  {:else if flow.step === 'maintenance'}
    <h1 tabindex="-1">{t('deposit.maintenance.title')}</h1>
    <p class="tt-break">{flow.maintenanceMessage ?? t('deposit.maintenance.text')}</p>
  {:else if flow.step === 'error'}
    <h1 tabindex="-1">{t('deposit.error.title')}</h1>
    <Alert severity="error">{flow.errorText ?? t('errors.unknown')}</Alert>
    <Button onclick={() => void flow.start()}>{t('deposit.error.retry')}</Button>
  {:else if flow.step === 'email'}
    <EmailStep {flow} />
  {:else if flow.step === 'code'}
    <CodeStep {flow} />
  {:else if flow.step === 'form'}
    <TransferForm {flow} {onnavigate} />
  {:else if flow.step === 'resume'}
    <ResumePrompt {flow} />
  {:else if flow.step === 'upload'}
    <UploadStep {flow} />
  {:else if flow.step === 'finalizing'}
    <FinalizeStep {flow} />
  {:else if flow.step === 'done'}
    <DoneStep {flow} {onnavigate} />
  {/if}
</div>
