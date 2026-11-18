// Rendering of the read page of a secret (server-side render, no DOM): the revealed text is plain
// text, never HTML, Markdown nor a clickable URL (threat model T-397, decision P88), and the banner
// of an express secret names the entity that is not its author.
import { render } from 'svelte/server';
import { beforeAll, describe, expect, it } from 'vitest';
import { setLocale } from '../../shared/i18n/i18n.svelte';
import ExpressBanner from './ExpressBanner.svelte';
import RevealedText from './RevealedText.svelte';

const HOSTILE = [
  'Your account is locked: log in at https://evil.example/login now.',
  '<b>x</b> <a href="https://evil.example/">click</a> <img src=x onerror=alert(1)> <script>alert(1)</script>',
  '[a Markdown link](https://evil.example/) **bold** _italic_',
].join('\n');

beforeAll(async () => {
  await setLocale('en');
});

describe('RevealedText', () => {
  it('renders the text as the plain value of a read-only text area', () => {
    const { body } = render(RevealedText, { props: { text: HOSTILE } });
    const area = /<textarea[^>]*>([\s\S]*?)<\/textarea>/.exec(body);
    expect(area).not.toBeNull();
    const [whole, content] = area as unknown as [string, string];
    expect(whole).toMatch(/\sreadonly(\s|=|>)/);
    expect(whole).toContain('id="tt-secret-text"');
    // Every markup character of the text is escaped: nothing is interpreted.
    expect(content).not.toMatch(/<[a-z/]/i);
    expect(content).toContain('&lt;b>x&lt;/b>');
    expect(content).toContain('https://evil.example/login');
    expect(content).toContain('[a Markdown link](https://evil.example/) **bold** _italic_');
    // No element of the page comes from the text: no link, no bold, no image, no script.
    const outside = body.replace(whole, '');
    expect(outside).not.toContain('evil.example');
    expect(body).not.toMatch(/<a\s/i);
    expect(body).not.toMatch(/<(b|strong|em|img|script)[\s>]/i);
  });
});

describe('ExpressBanner', () => {
  it('says that the entity is not the author, as a static note', () => {
    const { body } = render(ExpressBanner, { props: { entity: 'Entity <A>' } });
    expect(body).toContain('role="note"');
    expect(body).toContain('id="tt-secret-express-banner"');
    expect(body).toContain('Content created by an unverified third party: Entity &lt;A> is not its author.');
    expect(body).not.toContain('aria-live');
  });

  it('is translated in French', async () => {
    await setLocale('fr');
    const { body } = render(ExpressBanner, { props: { entity: 'Entité A' } });
    expect(body).toContain('Contenu créé par un tiers non vérifié : Entité A n’en est pas l’auteur.');
    await setLocale('en');
  });
});
