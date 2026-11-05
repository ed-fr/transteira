import { describe, expect, it } from 'vitest';
import type { ErrorView } from '../../../shared/api/problem';
import {
  MAX_IMPORT_FILE_BYTES,
  configFileMessage,
  configFileTooLarge,
  configLanguage,
  duplicateSource,
  emptyImportForm,
  errorLocation,
  exportUrl,
  importBody,
  importFailure,
  importPath,
  parseConfigText,
  webhookCount,
  type TenantConfigExport,
} from './tenantTransfer';
import { emptyDelegatedForm } from './tenants';

const t = (key: string, params?: Record<string, string | number>): string =>
  params === undefined ? key : `${key} ${JSON.stringify(params)}`;

function view(partial: Partial<ErrorView>): ErrorView {
  return {
    code: undefined,
    status: undefined,
    message: 'general',
    fields: {},
    attemptsRemaining: undefined,
    retryAfterSeconds: undefined,
    maxTransferBytes: undefined,
    files: undefined,
    ...partial,
  };
}

const config = { schemaVersion: 1, exportedAt: '2026-11-04T10:00:00Z', sourceVersion: '2.0.0' };
const refs = {
  name: { id: 'n', label: 'Name' },
  fqdn: { id: 'f', label: 'FQDN' },
  storageQuotaBytes: { id: 'q', label: 'Quota' },
};
const file = { id: 'file', label: 'File' };

describe('exportUrl and importPath', () => {
  it('builds the export URL with the branding switch', () => {
    expect(exportUrl('ten_1', false)).toBe('/api/v1/admin/tenants/ten_1/export?includeBranding=false');
    expect(exportUrl('a b', true)).toBe('/api/v1/admin/tenants/a%20b/export?includeBranding=true');
  });

  it('builds the import path, with the source tenant of a duplication', () => {
    expect(importPath()).toBe('/tenants/import');
    expect(importPath('ten 1')).toBe('/tenants/import?from=ten%201');
  });

  it('reads the source tenant from the query string', () => {
    expect(duplicateSource('?from=ten_1')).toBe('ten_1');
    expect(duplicateSource('?from=')).toBeUndefined();
    expect(duplicateSource('')).toBeUndefined();
  });
});

describe('configuration file', () => {
  it('refuses a file above 32 MiB', () => {
    expect(configFileTooLarge(MAX_IMPORT_FILE_BYTES)).toBe(false);
    expect(configFileTooLarge(MAX_IMPORT_FILE_BYTES + 1)).toBe(true);
  });

  it('parses a JSON object, with or without a byte order mark', () => {
    expect(parseConfigText(JSON.stringify(config))).toEqual({ ok: true, config });
    expect(parseConfigText(`﻿${JSON.stringify(config)}`)).toEqual({ ok: true, config });
  });

  it('refuses text that is not JSON and JSON that is not an object', () => {
    expect(parseConfigText('not json')).toEqual({ ok: false, problem: 'not-json' });
    expect(parseConfigText('')).toEqual({ ok: false, problem: 'not-json' });
    for (const text of ['[]', '3', '"x"', 'null']) {
      expect(parseConfigText(text)).toEqual({ ok: false, problem: 'not-an-object' });
    }
  });

  it('gives the message of a problem', () => {
    expect(configFileMessage('not-json', t)).toBe('adminTenants.import.file.errors.not-json');
  });
});

describe('import body', () => {
  const form = { name: '  Entity C ', fqdn: '  Transfer.Entity-C.example.com ', storageQuotaBytes: 1024 };

  it('sends the trimmed name, the normalised FQDN and the configuration', () => {
    const body = importBody(form, config as TenantConfigExport, undefined, 'fr');
    expect(body).toEqual({
      name: 'Entity C',
      fqdn: 'transfer.entity-c.example.com',
      storageQuotaBytes: 1024,
      config,
    });
  });

  it('waits for the quota', () => {
    expect(importBody(emptyImportForm(), config as TenantConfigExport, undefined, 'fr')).toBeUndefined();
  });

  it('adds the first administrator when enabled, in the chosen or default language', () => {
    const delegated = {
      ...emptyDelegatedForm(),
      enabled: true,
      username: ' ann ',
      email: ' ann@example.com ',
    };
    expect(importBody(form, config as TenantConfigExport, delegated, 'fr')?.delegatedAdmin).toEqual({
      username: 'ann',
      email: 'ann@example.com',
      language: 'fr',
      delivery: 'mail',
    });
    expect(
      importBody(form, config as TenantConfigExport, { ...delegated, language: 'en', delivery: 'copy' }, 'fr')
        ?.delegatedAdmin,
    ).toMatchObject({ language: 'en', delivery: 'copy' });
    expect(
      importBody(form, config as TenantConfigExport, { ...delegated, enabled: false }, 'fr'),
    ).not.toHaveProperty('delegatedAdmin');
  });

  it('proposes the language of the configuration', () => {
    expect(
      configLanguage({ ...config, settings: { defaultLanguage: 'fr' } } as TenantConfigExport, 'en'),
    ).toBe('fr');
    expect(configLanguage(config as TenantConfigExport, 'en')).toBe('en');
    expect(configLanguage(undefined, 'fr')).toBe('fr');
  });

  it('counts the webhooks noted in the configuration', () => {
    expect(webhookCount(undefined)).toBe(0);
    expect(webhookCount(config as TenantConfigExport)).toBe(0);
    expect(
      webhookCount({
        ...config,
        webhooks: [{ name: 'a', kind: 'teams', events: [], enabled: false }],
      } as TenantConfigExport),
    ).toBe(1);
  });
});

describe('error location', () => {
  it('decodes a JSON pointer', () => {
    expect(errorLocation('/config/network/internalCidrs/3')).toBe('/config/network/internalCidrs/3');
    expect(errorLocation('/config/a~1b/c~0d')).toBe('/config/a/b/c~d');
  });

  it('keeps another notation as is', () => {
    expect(errorLocation('config.network')).toBe('config.network');
  });
});

describe('import failure', () => {
  it('locates an invalid file on the file field', () => {
    expect(
      importFailure(
        view({ code: 'import-invalid', status: 422 }),
        '/config/network/internalCidrs/3',
        refs,
        t,
        { file },
      ),
    ).toEqual({
      ok: false,
      errors: [
        {
          id: 'file',
          label: 'File',
          message: 'adminTenants.import.errors.location {"location":"/config/network/internalCidrs/3"}',
        },
      ],
    });
  });

  it('gives a general message in duplication, where there is no file field', () => {
    expect(
      importFailure(view({ code: 'import-invalid', status: 422 }), '/config/smtp/port', refs, t),
    ).toEqual({
      ok: false,
      message: 'adminTenants.import.errors.location {"location":"/config/smtp/port"}',
    });
  });

  it('falls back on the server message without a pointer', () => {
    expect(importFailure(view({ code: 'import-invalid', status: 422 }), undefined, refs, t)).toEqual({
      ok: false,
      message: 'general',
    });
    expect(importFailure(view({ code: 'import-invalid', status: 422 }), '', refs, t).ok).toBe(false);
  });

  it('reports an unsupported schema and a file too large', () => {
    expect(
      importFailure(view({ code: 'import-schema-unsupported', status: 422 }), undefined, refs, t),
    ).toEqual({
      ok: false,
      message: 'general',
    });
    expect(
      importFailure(view({ code: 'payload-too-large', status: 413 }), undefined, refs, t, { file }),
    ).toEqual({
      ok: false,
      errors: [{ id: 'file', label: 'File', message: 'general' }],
    });
  });

  it('puts a 409 on the FQDN field', () => {
    expect(importFailure(view({ code: 'already-exists', status: 409 }), undefined, refs, t)).toEqual({
      ok: false,
      errors: [{ id: 'f', label: 'FQDN', message: 'adminTenants.fields.fqdn.taken' }],
    });
  });

  it('keeps the administrator wording of the creation with an administrator', () => {
    const delegatedRefs = { username: { id: 'u', label: 'U' }, email: { id: 'e', label: 'E' } };
    expect(
      importFailure(view({ code: 'already-exists', status: 409 }), undefined, refs, t, { delegatedRefs }),
    ).toEqual({ ok: false, message: 'adminTenants.create.delegated.conflict' });
  });
});
