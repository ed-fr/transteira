// Administration search (CLAUDE.md section 13.2, step 3 of V2.3): the header search of the home
// page finds the transfers of an address or of an identifier in every entity of the admin's
// scope. Checks: the super admin finds the transfers of both entities; the delegated admin of
// entity A never sees entity B (address or identifier: empty answer, nothing of B in the page);
// an identifier opens the detail directly; the "all transfers of this address" link; the auditor
// may search by identifier only, and an address is refused in the browser, without any request;
// the query lives in memory only (never in the URL nor in the storage, threat T-412).
import type { Page } from '@playwright/test';
import { internalEmail, textFile } from '../support/data';
import { createTenantToken, tokenDeposit } from '../support/deposit';
import { openAsAuditor } from '../support/auditor';
import { HOSTS, ORIGINS, STORAGE_DELEGATE, STORAGE_SUPER } from '../support/env';
import { checkA11y, expect, expectCleanStorage, test } from '../support/fixtures';

const SEARCH_API = /\/api\/v1\/admin\/transfers\/search$/;

/** Transfers of entities A and B sharing one recipient address, and one sender per entity. */
interface Seeded {
  shared: string;
  onlyB: string;
  senderB: string;
  idA: string;
  idB: string;
}

/** One transfer per entity with a common recipient, and an address only used by entity B. */
async function seedBoth(b: { id: string }, apiTokenA: string): Promise<Seeded> {
  const shared = internalEmail('search-shared');
  const onlyB = internalEmail('search-only-b');
  const tokenB = await createTenantToken(b.id, `search ${Date.now()}`);
  const inA = await tokenDeposit(
    apiTokenA,
    internalEmail('search-sender-a'),
    { recipients: [shared], files: [textFile('search-a.txt', 'entity A content')] },
    { host: HOSTS.a },
  );
  const senderB = internalEmail('search-sender-b');
  const inB = await tokenDeposit(
    tokenB.token,
    senderB,
    { recipients: [shared, onlyB], files: [textFile('search-b.txt', 'entity B content')] },
    { host: HOSTS.b },
  );
  expect(inA.status).toBe('available');
  expect(inB.status).toBe('available');
  return { shared, onlyB, senderB, idA: inA.id, idB: inB.id };
}

/** Types a query in the search form of the page and submits it with Enter. */
async function search(page: Page, query: string): Promise<void> {
  const box = page.getByRole('searchbox', { name: 'Search', exact: true });
  await box.fill(query);
  await box.press('Enter');
}

/** The query is never in the URL (nor in the storage): checked after every search. */
async function expectNoQueryTrace(page: Page, query: string): Promise<void> {
  expect(page.url()).not.toContain(query);
  expect(decodeURIComponent(page.url())).not.toContain(query);
  await expectCleanStorage(page);
}

test.describe('administration search (super admin)', () => {
  test.use({ storageState: STORAGE_SUPER });

  test('an address finds the transfers of both entities, the query stays out of the URL', async ({
    page,
    state,
  }) => {
    const seeded = await seedBoth(state.tenants.b, state.apiTokenA);
    await page.goto(`${ORIGINS.admin}/admin/`);
    await expect(page.getByRole('heading', { name: 'Home', level: 1 })).toBeVisible();
    const answer = page.waitForResponse((r) => SEARCH_API.test(r.url()));
    await search(page, seeded.shared);
    const res = await answer;
    expect(res.request().postDataJSON()).toEqual({ q: seeded.shared, limit: 50 });

    await expect(page.getByRole('heading', { name: 'Search', level: 1 })).toBeVisible();
    expect(new URL(page.url()).pathname).toBe('/admin/search');
    expect(new URL(page.url()).search).toBe('');
    const results = page.getByRole('region', { name: 'Results' });
    await expect(results.getByText('2 transfers found.')).toBeVisible();
    const table = page.getByRole('table', { name: 'Transfers found' });
    await expect(table.getByRole('link', { name: seeded.idA, exact: true })).toBeVisible();
    await expect(table.getByRole('link', { name: seeded.idB, exact: true })).toBeVisible();
    await expect(table.getByText(state.tenants.a.name).first()).toBeVisible();
    await expect(table.getByText(state.tenants.b.name).first()).toBeVisible();
    await expectNoQueryTrace(page, seeded.shared);
    await checkA11y(page);

    // A transfer of the results opens its detail.
    await table.getByRole('link', { name: seeded.idB, exact: true }).click();
    await expect(page).toHaveURL(
      `${ORIGINS.admin}/admin/tenants/${state.tenants.b.id}/transfers/${seeded.idB}`,
    );
    await expect(page.getByRole('heading', { name: 'Transfer details', level: 1 })).toBeVisible();
  });

  test('a transfer identifier opens the detail directly', async ({ page, state }) => {
    const seeded = await seedBoth(state.tenants.b, state.apiTokenA);
    await page.goto(`${ORIGINS.admin}/admin/`);
    await search(page, seeded.idA);
    await expect(page).toHaveURL(
      `${ORIGINS.admin}/admin/tenants/${state.tenants.a.id}/transfers/${seeded.idA}`,
    );
    await expect(page.getByRole('heading', { name: 'Transfer details', level: 1 })).toBeVisible();
    // The identifier is in the path of the detail, as for any link to it: only the storage is checked.
    await expectCleanStorage(page);
  });

  test('an address without transfer gives an announced empty answer, a malformed query an error', async ({
    page,
    guards,
  }) => {
    guards.allowHttpError(400, SEARCH_API);
    await page.goto(`${ORIGINS.admin}/admin/`);
    await search(page, internalEmail('search-nobody'));
    await expect(
      page.getByText('No transfer of your entities was sent from or to this address.'),
    ).toBeVisible();
    await expect(page.getByRole('table', { name: 'Transfers found' })).toHaveCount(0);

    // Empty query: refused in the browser, no request.
    const requests: string[] = [];
    page.on('request', (req) => {
      if (SEARCH_API.test(req.url())) requests.push(req.url());
    });
    await search(page, '   ');
    const fieldError = page.locator('.tt-search__error');
    await expect(fieldError).toContainText('Enter an address or a transfer identifier.');
    expect(requests).toEqual([]);

    // A bare word is refused by the server (field error on the query).
    await search(page, 'not-an-address');
    await expect(fieldError).toContainText(
      'Enter a complete address, or a transfer identifier: trf_ followed by 26 letters and digits.',
    );
    // The error is also announced in the assertive live region (the input kept the focus).
    await expect(page.getByRole('alert').filter({ hasText: 'Error: Enter a complete address' })).toHaveCount(
      1,
    );
  });

  test('"All transfers of this address" links to the filtered transfer list when more are left out', async ({
    page,
    state,
  }) => {
    const seeded = await seedBoth(state.tenants.b, state.apiTokenA);
    // More than 50 matches of one address in one entity would be needed for the server to say
    // so: the real answer is patched to flag entity B as having more, to check the link.
    await page.route(SEARCH_API, async (route) => {
      const response = await route.fetch();
      const body = (await response.json()) as {
        truncated: boolean;
        tenants: { tenantId: string; more: boolean }[];
      };
      body.truncated = true;
      for (const t of body.tenants) t.more = t.tenantId === state.tenants.b.id;
      await route.fulfill({ response, json: body });
    });
    await page.goto(`${ORIGINS.admin}/admin/`);
    await search(page, seeded.shared);
    await expect(page.getByText('Only the most recent transfers are shown.')).toBeVisible();
    const more = page.getByRole('link', {
      name: `All transfers of this address in ${state.tenants.b.name}`,
    });
    await expect(more).toBeVisible();
    await expect(
      page.getByRole('link', { name: `All transfers of this address in ${state.tenants.a.name}` }),
    ).toHaveCount(0);
    await more.click();
    await expect(page).toHaveURL(new RegExp(`/admin/tenants/${state.tenants.b.id}/transfers\\?.*email=`));
    await expect(page.getByRole('heading', { name: 'Transfers', level: 1 })).toBeVisible();
    await expect(page.getByRole('table').getByText(seeded.senderB, { exact: true })).toBeVisible();
  });
});

test.describe('administration search (delegated admin of entity A)', () => {
  test.use({ storageState: STORAGE_DELEGATE });

  test('never reveals entity B: its address and its identifier give an empty answer', async ({
    page,
    state,
  }) => {
    const seeded = await seedBoth(state.tenants.b, state.apiTokenA);
    await page.goto(`${ORIGINS.admin}/admin/`);

    // An address used in both entities: only the transfer of A.
    await search(page, seeded.shared);
    await expect(page.getByRole('region', { name: 'Results' }).getByText('1 transfer found.')).toBeVisible();
    const table = page.getByRole('table', { name: 'Transfers found' });
    await expect(table.getByRole('link', { name: seeded.idA, exact: true })).toBeVisible();
    await expect(table.getByRole('link', { name: seeded.idB, exact: true })).toHaveCount(0);

    // An address only used in B, then the identifier of the transfer of B.
    for (const [query, text] of [
      [seeded.onlyB, 'No transfer of your entities was sent from or to this address.'],
      [seeded.idB, 'No transfer of your entities has this identifier.'],
    ] as const) {
      await search(page, query);
      await expect(page.getByText(text)).toBeVisible();
      await expect(page.getByRole('table', { name: 'Transfers found' })).toHaveCount(0);
      expect(new URL(page.url()).pathname).toBe('/admin/search');
      // The searched text is the only trace allowed (the search field keeps it).
      const html = (await page.content()).replaceAll(query, '');
      for (const marker of [state.tenants.b.name, state.tenants.b.fqdn, state.tenants.b.id, seeded.idB]) {
        expect(html, `DOM must not reveal "${marker}"`).not.toContain(marker);
      }
      await expectNoQueryTrace(page, query);
    }
  });
});

test.describe('administration search (auditor)', () => {
  test('searches by identifier only: an address is refused in the browser without any request', async ({
    state,
    newContext,
  }) => {
    const seeded = await seedBoth(state.tenants.b, state.apiTokenA);
    const page = await openAsAuditor(newContext, state, state.tenants.a.id);
    const requests: string[] = [];
    page.on('request', (req) => {
      if (SEARCH_API.test(req.url())) requests.push(req.url());
    });

    const box = page.getByRole('searchbox', { name: 'Search', exact: true });
    await expect(box).toHaveAttribute('placeholder', 'Transfer ID (trf_…)');
    await search(page, seeded.shared);
    await expect(
      page.getByText('Auditors cannot search by address. Enter a transfer identifier (trf_…).'),
    ).toBeVisible();
    expect(requests).toEqual([]);
    // The refusal is the field error and is announced in the assertive live region.
    await expect(page.locator('.tt-search__error')).toContainText('Auditors cannot search by address.');
    await expect(
      page.getByRole('alert').filter({ hasText: 'Error: Auditors cannot search by address' }),
    ).toHaveCount(1);
    expect(new URL(page.url()).pathname).toBe('/admin/');
    await expectNoQueryTrace(page, seeded.shared);

    // An identifier of the audited entity opens its detail.
    await search(page, seeded.idA);
    await expect(page).toHaveURL(
      `${ORIGINS.admin}/admin/tenants/${state.tenants.a.id}/transfers/${seeded.idA}`,
    );
    await expect(page.getByRole('heading', { name: 'Transfer details', level: 1 })).toBeVisible();
    expect(requests).toHaveLength(1);

    // The identifier of entity B (outside the scope) gives an empty answer.
    await page.goto(`${ORIGINS.admin}/admin/`);
    await search(page, seeded.idB);
    await expect(page.getByText('No transfer of your entities has this identifier.')).toBeVisible();
    expect(await page.content()).not.toContain(state.tenants.b.name);
    await expectNoQueryTrace(page, seeded.idB);
  });
});
