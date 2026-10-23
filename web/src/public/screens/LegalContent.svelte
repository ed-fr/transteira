<script lang="ts">
  // Display of a legal document rendered by the server (LegalDocument.html). This is the only
  // component allowed to use {@html} (eslint svelte/no-at-html-tags, threat model T-91): the
  // HTML comes from internal/markup, which renders limited Markdown, never passes raw HTML
  // through and sanitizes the result with an allowlist. Never pass any other string here.
  interface Props {
    /** Sanitized HTML of GET /tenant/legal/{document} (internal/markup). */
    html: string;
  }

  let { html }: Props = $props();
</script>

<div class="legal-content tt-break">
  <!-- eslint-disable-next-line svelte/no-at-html-tags -- server-sanitized by internal/markup (allowlist) -->
  {@html html}
</div>

<style>
  .legal-content :global(h1),
  .legal-content :global(h2),
  .legal-content :global(h3) {
    margin-top: var(--tt-space-4);
  }

  .legal-content :global(table) {
    border-collapse: collapse;
  }

  .legal-content :global(th),
  .legal-content :global(td) {
    padding: var(--tt-space-1) var(--tt-space-2);
    border: 1px solid var(--tt-border);
  }
</style>
