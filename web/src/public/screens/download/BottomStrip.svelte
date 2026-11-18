<script lang="ts">
  // Bottom strip of the download page (CLAUDE.md section 13.2), on the muted surface: "Reply with
  // files" (version 1.1, when the recipient may reply: a button styled as a text link, described by
  // "Send files back to <sender>", busy while the reply session opens, its error shown above) and
  // "Report an abuse" (the link variant of ReportAbuse). Links on the muted surface use --tt-text,
  // underlined, never the tenant colour.
  //
  // Props:
  //   token       link token of the download page (abuse report)
  //   canReply    shows "Reply with files"
  //   replyBusy   the reply session is opening
  //   replyError  error of the last reply attempt
  //   replyHint   description of the reply button ("Send files back to …")
  //   onreply     called on "Reply with files"
  import { Alert, Button } from '../../../shared/components';
  import { t } from '../../../shared/i18n/i18n.svelte';
  import ReportAbuse from '../ReportAbuse.svelte';

  interface Props {
    /** Link token of the download page. */
    token: string;
    /** Shows "Reply with files". */
    canReply?: boolean;
    /** The reply session is opening. */
    replyBusy?: boolean;
    /** Error of the last reply attempt. */
    replyError?: string | undefined;
    /** Description of the reply button. */
    replyHint?: string;
    /** Called on "Reply with files". */
    onreply?: () => void;
  }

  let { token, canReply = false, replyBusy = false, replyError, replyHint = '', onreply }: Props = $props();

  const HINT_ID = 'tt-reply-hint';
</script>

<div class="tt-dlstrip">
  {#if replyError}
    <Alert severity="error">{replyError}</Alert>
  {/if}
  <div class="tt-dlstrip__links">
    {#if canReply}
      <span class="tt-dlstrip__reply">
        <Button
          variant="link"
          class="tt-dlstrip__link"
          loading={replyBusy}
          aria-describedby={replyHint === '' ? undefined : HINT_ID}
          onclick={() => onreply?.()}
        >
          {t('download.reply.button')}
        </Button>
        {#if replyHint !== ''}
          <span id={HINT_ID} class="visually-hidden">{replyHint}</span>
        {/if}
      </span>
    {/if}
    <ReportAbuse {token} variant="link" />
  </div>
</div>

<style>
  .tt-dlstrip {
    margin-top: var(--tt-space-6);
    padding: var(--tt-space-2) var(--tt-space-5);
    border-radius: var(--tt-radius-lg);
    background: var(--tt-surface-muted);
    color: var(--tt-text);
  }

  .tt-dlstrip :global(.tt-alert) {
    margin: var(--tt-space-3) 0 var(--tt-space-1);
  }

  .tt-dlstrip__links {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: 0 var(--tt-space-6);
  }

  /* Text link look on the muted surface: --tt-text, underlined (Button variant "link"). */
  .tt-dlstrip__reply :global(.tt-dlstrip__link) {
    color: var(--tt-text);
    font-weight: var(--tt-font-weight-bold);
  }

  @media (max-width: 40rem) {
    .tt-dlstrip {
      padding: var(--tt-space-1) var(--tt-space-4);
    }
  }
</style>
