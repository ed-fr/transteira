import tseslint from 'typescript-eslint';

// Same base as web/eslint.config.js (typescript-eslint recommended), plus the rules that keep the
// end-to-end suite deterministic: no fixed sleeps (wait for a condition instead) and no focused
// or skipped tests left behind by mistake.
export default tseslint.config(
  {
    ignores: ['node_modules/', 'test-results/', 'playwright-report/', '.run/', '.run.lock*/'],
  },
  ...tseslint.configs.recommended,
  {
    rules: {
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
      'no-restricted-syntax': [
        'error',
        {
          selector: "CallExpression[callee.property.name='waitForTimeout']",
          message: 'Fixed waits make tests slow and flaky: wait for a condition (expect.poll, waitFor...).',
        },
        {
          selector: "CallExpression[callee.object.name='test'][callee.property.name='only']",
          message: 'test.only must not be committed.',
        },
        {
          selector: "CallExpression[callee.object.property.name='describe'][callee.property.name='only']",
          message: 'test.describe.only must not be committed.',
        },
      ],
    },
  },
);
