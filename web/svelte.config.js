import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

/** @type {import('svelte/compiler').CompileOptions} */
const compilerOptions = {
  // Svelte 5 runes everywhere ($state, $derived, $props, $effect).
  runes: true,
};

export default {
  preprocess: vitePreprocess(),
  compilerOptions,
  // Accessibility warnings are failures: `svelte-check --fail-on-warnings` (make web-check).
};
