<script lang="ts">
  // Resume after a reload (design decision D4): the browser cannot reopen files by itself, the
  // depositor selects the same files again; they are matched by name, size and modification
  // date, then the upload continues where it stopped.
  import { Alert, Button, FileDrop, FileList } from '../../shared/components';
  import { fullName } from '../../shared/components/folders';
  import { t } from '../../shared/i18n/i18n.svelte';
  import type { DepositFlow } from './flow.svelte';

  interface Props {
    flow: DepositFlow;
  }

  let { flow }: Props = $props();

  const missing = $derived(flow.resumeMissing);
  const expected = $derived(flow.resumeRecord?.files ?? []);
</script>

<h1 tabindex="-1">{t('upload.resume.title')}</h1>

<p>{t('upload.resume.text')}</p>

<FileList files={expected} label={t('deposit.resume.expected')} />

<FileDrop
  label={t('deposit.resume.select')}
  onfiles={(files) => flow.addResumeFiles(files)}
  folders={flow.foldersEnabled}
  onpicked={(files) => flow.addResumePicked(files)}
/>

{#if missing.length > 0}
  <Alert severity="info" live={false}>
    <span class="tt-break"
      >{t('upload.resume.missing', { names: missing.map((f) => fullName(f.path, f.name)).join(', ') })}</span
    >
  </Alert>
{:else}
  <Alert severity="success">{t('deposit.resume.ready')}</Alert>
{/if}

<div class="tt-cluster">
  <Button disabled={missing.length > 0} onclick={() => flow.continueResume()}
    >{t('deposit.resume.continue')}</Button
  >
  <Button variant="link" onclick={() => void flow.discardResume()}>{t('upload.resume.discard')}</Button>
</div>
