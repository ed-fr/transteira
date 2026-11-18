// Rendering of the end of a secret creation, express (2.3) and one-time (2.1), server-side (no
// DOM): the full link, which carries the key, is excluded from the page translation of the
// browser, whose service would otherwise receive it (threat model T-399).
import { render } from 'svelte/server';
import { beforeAll, describe, expect, it } from 'vitest';
import { setLocale } from '../../shared/i18n/i18n.svelte';
import ExpressDone from './ExpressDone.svelte';
import type { DepositFlow } from '../deposit/flow.svelte';
import type { SecretCreateFlow } from './createFlow.svelte';
import type { ExpressSecretFlow } from './expressFlow.svelte';
import SecretDone from './SecretDone.svelte';

const LINK = `https://transfer.entity-a.example.com/s/tts_${'A'.repeat(43)}#k=${'B'.repeat(43)}`;

beforeAll(async () => {
  await setLocale('en');
});

/** Checks that the page shows the link in a code element excluded from the translation. */
function expectUntranslatedLink(body: string): void {
  const code = /<code[^>]*>([\s\S]*?)<\/code>/.exec(body);
  expect(code).not.toBeNull();
  const [whole, content] = code as unknown as [string, string];
  expect(content).toContain(LINK);
  expect(whole).toContain('translate="no"');
  expect(whole).toMatch(/class="[^"]*\bnotranslate\b/);
}

describe('end of a secret creation', () => {
  it('excludes the full link of an express secret from the page translation', () => {
    const flow = { link: LINK, expiresAt: '2026-11-18T09:00:00Z' } as unknown as ExpressSecretFlow;
    expectUntranslatedLink(render(ExpressDone, { props: { flow } }).body);
  });

  it('excludes the full link of a one-time secret from the page translation', () => {
    const flow = { session: undefined } as unknown as DepositFlow;
    const secret = {
      link: LINK,
      expiresAt: '2026-11-18T09:00:00Z',
      forgetResult: () => undefined,
    } as unknown as SecretCreateFlow;
    expectUntranslatedLink(render(SecretDone, { props: { flow, secret } }).body);
  });
});
