import { describe, expect, it, vi } from 'vitest';
import {
  accountActions,
  accountErrorMessage,
  accountStatus,
  adminPath,
  adminRow,
  buildAdminPatch,
  canPromote,
  conflictKey,
  createBody,
  editFormFrom,
  emptyCreateForm,
  loadAllPages,
  roleKey,
  splitActivation,
  statusVariant,
  tenantLabel,
  tenantNameMap,
  totpStatus,
  validateCreate,
  validateEdit,
  type Admin,
  type AdminWithActivation,
} from './admins';

const t = (key: string, params?: Record<string, string | number>): string =>
  params === undefined ? key : `${key} ${JSON.stringify(params)}`;

function delegated(overrides: Partial<Admin> = {}): Admin {
  return {
    id: 'adm_1',
    username: 'admin.a',
    email: 'admin@entity-a.example.com',
    role: 'delegated_admin',
    tenantIds: ['ten_b', 'ten_a'],
    totpEnabled: true,
    activated: true,
    requireTotp: true,
    disabled: false,
    lastLoginAt: '2026-10-19T08:30:00Z',
    createdAt: '2026-09-01T08:00:00Z',
    ...overrides,
  };
}

function superAdmin(overrides: Partial<Admin> = {}): Admin {
  return delegated({ id: 'adm_s', username: 'root', role: 'super_admin', tenantIds: [], ...overrides });
}

describe('splitActivation', () => {
  it('separates the link from the account', () => {
    const data: AdminWithActivation = {
      ...delegated(),
      activationUrl: 'https://admin.example.com/admin/activate#act_x',
      activationExpiresAt: '2026-10-22T16:25:00Z',
    };
    const { account, link } = splitActivation(data);
    expect(link).toEqual({
      url: 'https://admin.example.com/admin/activate#act_x',
      expiresAt: '2026-10-22T16:25:00Z',
    });
    expect(account).toEqual(delegated());
    expect(JSON.stringify(account)).not.toContain('act_x');
  });
});

describe('adminPath and roleKey', () => {
  it('encodes the id', () => {
    expect(adminPath('adm/1 x')).toBe('/admins/adm%2F1%20x');
  });

  it('maps known roles and falls back for others', () => {
    expect(roleKey('super_admin')).toBe('admin.role.super_admin');
    expect(roleKey('delegated_admin')).toBe('admin.role.delegated_admin');
    expect(roleKey('auditor')).toBe('admin.role.unknown');
    expect(roleKey(undefined)).toBe('admin.role.unknown');
  });
});

describe('accountStatus', () => {
  it('puts disabled first, then pending activation', () => {
    expect(accountStatus({ disabled: true, activated: false })).toBe('disabled');
    expect(accountStatus({ disabled: false, activated: false })).toBe('pendingActivation');
    expect(accountStatus({ disabled: false, activated: true })).toBe('active');
  });
});

describe('totpStatus', () => {
  it('derives enabled, required and disabled', () => {
    expect(totpStatus({ totpEnabled: true, requireTotp: false, role: 'delegated_admin' })).toBe('enabled');
    expect(totpStatus({ totpEnabled: false, requireTotp: true, role: 'delegated_admin' })).toBe('required');
    expect(totpStatus({ totpEnabled: false, role: 'super_admin' })).toBe('required');
    expect(totpStatus({ totpEnabled: false, requireTotp: false, role: 'delegated_admin' })).toBe('disabled');
    expect(totpStatus({ totpEnabled: false, role: 'delegated_admin' })).toBe('disabled');
  });
});

describe('statusVariant', () => {
  it('maps every status', () => {
    expect(statusVariant('active')).toBe('ok');
    expect(statusVariant('enabled')).toBe('ok');
    expect(statusVariant('pendingActivation')).toBe('warning');
    expect(statusVariant('required')).toBe('warning');
    expect(statusVariant('disabled')).toBe('info');
  });
});

describe('tenantLabel', () => {
  const names = tenantNameMap([
    { id: 'ten_a', name: 'Zeta' },
    { id: 'ten_b', name: 'Alpha' },
  ]);

  it('says all entities for a super admin', () => {
    expect(tenantLabel(superAdmin(), names, t)).toBe('adminAccounts.list.allTenants');
  });

  it('says no entity when there is none', () => {
    expect(tenantLabel(delegated({ tenantIds: [] }), names, t)).toBe('adminAccounts.list.noTenant');
  });

  it('lists sorted names, with the id for an unknown tenant', () => {
    expect(tenantLabel(delegated({ tenantIds: ['ten_a', 'ten_b', 'ten_c'] }), names, t)).toBe(
      'Alpha, ten_c, Zeta',
    );
  });
});

describe('adminRow', () => {
  const ctx = {
    names: tenantNameMap([{ id: 'ten_a', name: 'A' }]),
    meId: 'adm_1',
    t,
    formatDate: (iso: string) => `D(${iso})`,
  };

  it('builds the row of an account', () => {
    expect(adminRow(delegated({ tenantIds: ['ten_a'] }), ctx)).toEqual({
      id: 'adm_1',
      username: 'admin.a',
      email: 'admin@entity-a.example.com',
      path: '/admins/adm_1',
      role: 'admin.role.delegated_admin',
      tenants: 'A',
      totp: 'enabled',
      status: 'active',
      lastLogin: 'D(2026-10-19T08:30:00Z)',
      self: true,
    });
  });

  it('says never without a sign-in and marks other rows as not self', () => {
    const row = adminRow(superAdmin({ lastLoginAt: null }), ctx);
    expect(row.lastLogin).toBe('adminAccounts.list.never');
    expect(row.self).toBe(false);
    const { lastLoginAt: _omit, ...withoutLogin } = superAdmin();
    expect(adminRow(withoutLogin, ctx).lastLogin).toBe('adminAccounts.list.never');
  });
});

describe('loadAllPages', () => {
  it('follows the cursor until the last page', async () => {
    const fetchPage = vi
      .fn<(cursor: string | undefined) => Promise<{ items: number[]; nextCursor?: string | null }>>()
      .mockResolvedValueOnce({ items: [1, 2], nextCursor: 'c1' })
      .mockResolvedValueOnce({ items: [3], nextCursor: '' });
    expect(await loadAllPages(fetchPage)).toEqual([1, 2, 3]);
    expect(fetchPage.mock.calls).toEqual([[undefined], ['c1']]);
  });

  it('stops on a null or absent cursor', async () => {
    expect(await loadAllPages(() => Promise.resolve({ items: ['a'], nextCursor: null }))).toEqual(['a']);
    expect(await loadAllPages(() => Promise.resolve({ items: ['b'] }))).toEqual(['b']);
  });

  it('stops after maxPages', async () => {
    const fetchPage = vi.fn(() => Promise.resolve({ items: [0], nextCursor: 'again' }));
    expect(await loadAllPages(fetchPage, 3)).toEqual([0, 0, 0]);
    expect(fetchPage).toHaveBeenCalledTimes(3);
  });

  it('propagates a failure', async () => {
    await expect(loadAllPages(() => Promise.reject(new Error('boom')))).rejects.toThrow('boom');
  });
});

describe('creation form', () => {
  it('requires two-factor authentication by default', () => {
    expect(emptyCreateForm()).toEqual({ username: '', email: '', tenantIds: [], requireTotp: true });
  });

  it('reports the missing fields in the order of the form', () => {
    expect(validateCreate(emptyCreateForm())).toEqual([
      { field: 'username', key: 'fieldErrors.required' },
      { field: 'email', key: 'fieldErrors.required' },
      { field: 'tenantIds', key: 'adminAccounts.form.tenants.required' },
    ]);
  });

  it('checks the username and email formats', () => {
    expect(
      validateCreate({ username: 'Bad Name', email: 'nope', tenantIds: ['ten_a'], requireTotp: true }),
    ).toEqual([
      { field: 'username', key: 'fieldErrors.invalid-username' },
      { field: 'email', key: 'fieldErrors.invalid-email' },
    ]);
    expect(
      validateCreate({ username: 'ab', email: 'a@b.example', tenantIds: ['x'], requireTotp: false }),
    ).toEqual([{ field: 'username', key: 'fieldErrors.invalid-username' }]);
  });

  it('accepts a valid form', () => {
    expect(
      validateCreate({
        username: ' admin.b ',
        email: ' admin@entity-b.example.com ',
        tenantIds: ['ten_b'],
        requireTotp: true,
      }),
    ).toEqual([]);
  });

  it('builds a delegated admin body with trimmed, unique and sorted values', () => {
    expect(
      createBody({
        username: ' admin.b ',
        email: ' b@example.com ',
        tenantIds: ['ten_b', 'ten_a', 'ten_b'],
        requireTotp: false,
      }),
    ).toEqual({
      username: 'admin.b',
      email: 'b@example.com',
      role: 'delegated_admin',
      tenantIds: ['ten_a', 'ten_b'],
      requireTotp: false,
    });
  });
});

describe('edit form', () => {
  it('is filled from the account, tenants sorted', () => {
    expect(editFormFrom(delegated({ requireTotp: false }))).toEqual({
      email: 'admin@entity-a.example.com',
      role: 'delegated_admin',
      tenantIds: ['ten_a', 'ten_b'],
      requireTotp: false,
      disabled: false,
    });
  });

  it('always requires TOTP for a super admin', () => {
    const { requireTotp: _omit, ...account } = superAdmin();
    expect(editFormFrom(account).requireTotp).toBe(true);
    const { requireTotp: _omit2, ...other } = delegated();
    expect(editFormFrom(other).requireTotp).toBe(false);
  });

  it('validates the email and, for a delegated admin, the entities', () => {
    const form = editFormFrom(delegated());
    expect(validateEdit(form)).toEqual([]);
    expect(validateEdit({ ...form, email: ' ', tenantIds: [] })).toEqual([
      { field: 'email', key: 'fieldErrors.required' },
      { field: 'tenantIds', key: 'adminAccounts.form.tenants.required' },
    ]);
    expect(validateEdit({ ...form, role: 'super_admin', tenantIds: [] })).toEqual([]);
  });
});

describe('buildAdminPatch', () => {
  it('is empty without changes, whatever the order of the tenants', () => {
    const admin = delegated();
    expect(
      buildAdminPatch(admin, { ...editFormFrom(admin), tenantIds: ['ten_b', 'ten_a', 'ten_a'] }),
    ).toEqual({});
  });

  it('sends the changed fields of a delegated admin', () => {
    const admin = delegated();
    const form = {
      ...editFormFrom(admin),
      email: ' new@example.com ',
      tenantIds: ['ten_c'],
      requireTotp: false,
      disabled: true,
    };
    expect(buildAdminPatch(admin, form)).toEqual({
      email: 'new@example.com',
      disabled: true,
      requireTotp: false,
      tenantIds: ['ten_c'],
    });
  });

  it('sends only the role on a promotion', () => {
    const admin = delegated();
    expect(
      buildAdminPatch(admin, {
        ...editFormFrom(admin),
        role: 'super_admin',
        requireTotp: false,
        tenantIds: [],
      }),
    ).toEqual({
      role: 'super_admin',
    });
  });

  it('sends the role and the tenants on a demotion', () => {
    const admin = superAdmin();
    expect(
      buildAdminPatch(admin, { ...editFormFrom(admin), role: 'delegated_admin', tenantIds: ['ten_a'] }),
    ).toEqual({
      role: 'delegated_admin',
      tenantIds: ['ten_a'],
    });
  });

  it('never sends tenants or requireTotp for a super admin', () => {
    const admin = superAdmin();
    expect(
      buildAdminPatch(admin, {
        ...editFormFrom(admin),
        tenantIds: ['ten_a'],
        requireTotp: false,
        disabled: true,
      }),
    ).toEqual({
      disabled: true,
    });
  });
});

describe('canPromote and accountActions', () => {
  it('requires an activated account with TOTP', () => {
    expect(canPromote({ activated: true, totpEnabled: true })).toBe(true);
    expect(canPromote({ activated: false, totpEnabled: true })).toBe(false);
    expect(canPromote({ activated: true, totpEnabled: false })).toBe(false);
  });

  it('hides the dangerous actions on the own account', () => {
    expect(accountActions({ id: 'adm_1' }, 'adm_1')).toEqual({
      self: true,
      changeRole: false,
      disable: false,
      reset: false,
      remove: false,
    });
    expect(accountActions({ id: 'adm_1' }, 'adm_2')).toEqual({
      self: false,
      changeRole: true,
      disable: true,
      reset: true,
      remove: true,
    });
    expect(accountActions({ id: 'adm_1' }, undefined).self).toBe(false);
  });
});

describe('conflictKey', () => {
  it('names the own account first', () => {
    expect(conflictKey(delegated(), { kind: 'delete' }, 'adm_1')).toBe('adminAccounts.errors.ownAccount');
  });

  it('explains a refused promotion', () => {
    const promote = { kind: 'update' as const, patch: { role: 'super_admin' as const } };
    expect(conflictKey(delegated({ totpEnabled: false }), promote, 'me')).toBe(
      'adminAccounts.errors.notPromotable',
    );
    expect(conflictKey(delegated({ activated: false }), promote, 'me')).toBe(
      'adminAccounts.errors.notPromotable',
    );
    expect(conflictKey(delegated(), promote, 'me')).toBe('adminAccounts.errors.conflict');
  });

  it('explains a reset of a disabled account', () => {
    expect(conflictKey(delegated({ disabled: true }), { kind: 'reset' }, 'me')).toBe(
      'adminAccounts.errors.accountDisabled',
    );
    expect(conflictKey(superAdmin({ disabled: true }), { kind: 'reset' }, 'me')).toBe(
      'adminAccounts.errors.accountDisabled',
    );
  });

  it('names the last super admin for actions removing its access', () => {
    const admin = superAdmin();
    expect(conflictKey(admin, { kind: 'delete' }, 'me')).toBe('adminAccounts.errors.lastSuperAdmin');
    expect(conflictKey(admin, { kind: 'reset' }, 'me')).toBe('adminAccounts.errors.lastSuperAdmin');
    expect(conflictKey(admin, { kind: 'update', patch: { disabled: true } }, 'me')).toBe(
      'adminAccounts.errors.lastSuperAdmin',
    );
    expect(
      conflictKey(admin, { kind: 'update', patch: { role: 'delegated_admin', tenantIds: ['t'] } }, 'me'),
    ).toBe('adminAccounts.errors.lastSuperAdmin');
  });

  it('falls back to the generic conflict', () => {
    expect(conflictKey(superAdmin(), { kind: 'update', patch: { email: 'x@example.com' } }, 'me')).toBe(
      'adminAccounts.errors.conflict',
    );
    expect(conflictKey(superAdmin(), { kind: 'update', patch: { role: 'super_admin' } }, 'me')).toBe(
      'adminAccounts.errors.conflict',
    );
    expect(conflictKey(delegated(), { kind: 'delete' }, undefined)).toBe('adminAccounts.errors.conflict');
  });
});

describe('accountErrorMessage', () => {
  it('words a state conflict from the context', () => {
    expect(
      accountErrorMessage(
        { code: 'state-conflict', message: 'generic' },
        superAdmin(),
        { kind: 'delete' },
        'me',
        t,
      ),
    ).toBe('adminAccounts.errors.lastSuperAdmin');
  });

  it('keeps the message of another error', () => {
    expect(
      accountErrorMessage({ code: 'not-found', message: 'Gone' }, delegated(), { kind: 'delete' }, 'me', t),
    ).toBe('Gone');
    expect(
      accountErrorMessage({ code: undefined, message: 'Network' }, delegated(), { kind: 'reset' }, 'me', t),
    ).toBe('Network');
  });
});
