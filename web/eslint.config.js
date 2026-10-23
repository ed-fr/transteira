import svelte from 'eslint-plugin-svelte';
import tseslint from 'typescript-eslint';
import svelteConfig from './svelte.config.js';

// CSP rules for contributors (web/README.md): no inline style attribute, no style: directive,
// no Svelte transition (they all write inline styles, blocked by style-src 'self'), and
// {@html} only in the legal page component (server-sanitised HTML, internal/markup).
// scripts/check-dist.mjs checks the same properties on the built output.
export default tseslint.config(
  {
    ignores: ['dist/', 'node_modules/', 'coverage/', 'apidocs/', 'src/shared/api/schema.ts'],
  },
  ...tseslint.configs.recommended,
  ...svelte.configs['flat/recommended'],
  {
    files: ['**/*.svelte', '**/*.svelte.ts', '**/*.svelte.js'],
    languageOptions: {
      parserOptions: {
        projectService: false,
        extraFileExtensions: ['.svelte'],
        parser: tseslint.parser,
        svelteConfig,
      },
    },
  },
  {
    rules: {
      'svelte/no-inline-styles': ['error', { allowTransitions: false }],
      'svelte/no-at-html-tags': 'error',
      'svelte/no-target-blank': 'error',
      'svelte/button-has-type': 'error',
      'no-restricted-syntax': [
        'error',
        {
          selector: "CallExpression[callee.property.name='setAttribute'][arguments.0.value='style']",
          message: 'Inline style attributes are blocked by the CSP: use classes or style.setProperty.',
        },
        {
          selector: "MemberExpression[property.name='innerHTML']",
          message: 'innerHTML is forbidden: render text through Svelte (escaped).',
        },
        {
          selector: "MemberExpression[property.name='outerHTML']",
          message: 'outerHTML is forbidden: render text through Svelte (escaped).',
        },
        {
          selector: "CallExpression[callee.property.name='insertAdjacentHTML']",
          message: 'insertAdjacentHTML is forbidden: render text through Svelte (escaped).',
        },
        {
          selector: "CallExpression[callee.property.name=/^write(ln)?$/][callee.object.name='document']",
          message: 'document.write is forbidden: render through Svelte.',
        },
        {
          selector: "Identifier[name='srcdoc'], SvelteAttribute[key.name='srcdoc']",
          message: 'srcdoc is forbidden: it renders unescaped HTML.',
        },
        {
          selector: "CallExpression[callee.property.name='createContextualFragment']",
          message: 'createContextualFragment is forbidden: render text through Svelte (escaped).',
        },
        {
          selector: "NewExpression[callee.name='DOMParser']",
          message: 'DOMParser is forbidden: render text through Svelte (escaped).',
        },
        {
          selector: "CallExpression[callee.name='eval']",
          message: 'eval is blocked by the CSP.',
        },
        {
          selector: "NewExpression[callee.name='Function']",
          message: 'new Function is blocked by the CSP.',
        },
      ],
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
    },
  },
);
