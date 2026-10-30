// Folder upload (CLAUDE.md section 8.2, V1.1): a folder chosen with the "Add a folder" button keeps
// its tree. System files are left out and counted, hidden files are flagged, empty folders are
// ignored; the download page shows the folders and the ZIP archive keeps the tree.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { internalEmail, sha256 } from '../support/data';
import { checkA11y, expect, test } from '../support/fixtures';
import { waitForMail } from '../support/mailpit';
import { download, identify, mailLink, sendTransfer } from '../support/publicflow';
import { escapeRegExp, re } from '../support/regexp';
import { readStoredZip } from '../support/zip';

/** Writes a small folder tree in a temporary directory and returns its root and the folder path. */
function makeTree(): { root: string; folder: string; files: Map<string, Buffer> } {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'transteira-folder-'));
  const folder = path.join(root, 'project');
  const files = new Map<string, Buffer>([
    ['project/readme.txt', Buffer.from('read me first\n')],
    ['project/src/main.txt', Buffer.from('main content\n'.repeat(100))],
    ['project/src/.secret', Buffer.from('hidden but kept\n')],
  ]);
  for (const [relative, data] of files) {
    const target = path.join(root, ...relative.split('/'));
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, data);
  }
  // Left out or ignored: a system file and an empty folder.
  fs.writeFileSync(path.join(folder, '.DS_Store'), 'system');
  fs.mkdirSync(path.join(folder, 'empty'));
  return { root, folder, files };
}

test.describe('public: folder upload', () => {
  test('a folder keeps its tree from the form to the ZIP archive', async ({ page, state, newContext }) => {
    const tenant = state.tenants.a;
    const sender = internalEmail('folder-sender');
    const recipient = internalEmail('folder-recipient');
    const tree = makeTree();
    try {
      await identify(page, tenant.origin, sender);
      await page.getByRole('textbox', { name: /^Recipients/ }).fill(recipient);

      // The "Add a folder" button is a real button; the directory input behind it takes the folder.
      await expect(page.getByRole('button', { name: 'Add a folder' })).toBeVisible();
      await page.locator('input[webkitdirectory]').setInputFiles(tree.folder);

      const list = page.getByRole('list', { name: 'Selected files' });
      await expect(list.getByRole('listitem')).toHaveCount(3);
      await expect(list.getByText('project/', { exact: false }).first()).toBeVisible();
      await expect(list.getByText('project/src/')).toHaveCount(2);
      // The hidden file is kept and flagged for screen readers too; the system file is reported.
      const hidden = list.getByRole('listitem').filter({ hasText: '.secret' });
      await expect(hidden.getByText(/Hidden file/)).toBeAttached();
      await expect(page.getByText(/1 system file was left out/)).toBeVisible();
      await expect(list.getByText('.DS_Store')).toHaveCount(0);
      await checkA11y(page);

      await sendTransfer(page);

      // The recipient's download page shows the folders; the ZIP keeps the tree.
      const notification = await waitForMail(recipient, {
        subject: new RegExp(`^${escapeRegExp(sender)} sent you files via`),
      });
      const link = mailLink(notification, '/d/', tenant.origin);
      const rctx = await newContext();
      const rpage = await rctx.newPage();
      await rpage.goto(link);
      const table = rpage.getByRole('table', { name: 'Files of this transfer' });
      await expect(table.getByRole('row', { name: re('project/src/main.txt') })).toBeVisible();
      await expect(table.getByRole('row', { name: re('project/readme.txt') })).toBeVisible();
      await checkA11y(rpage);

      const zip = await download(rpage, () =>
        rpage.getByRole('link', { name: 'Download all files (ZIP)' }).click(),
      );
      const entries = readStoredZip(zip.data);
      expect(entries.map((e) => e.name).sort()).toEqual([...tree.files.keys()].sort());
      for (const [name, data] of tree.files) {
        expect(sha256(entries.find((e) => e.name === name)!.data), `content of ${name}`).toBe(sha256(data));
      }
    } finally {
      fs.rmSync(tree.root, { recursive: true, force: true });
    }
  });
});
