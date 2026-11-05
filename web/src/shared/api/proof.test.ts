import { describe, expect, it, vi } from 'vitest';
import { ApiProblem, NetworkError } from './client';
import {
  deliveryProofAvailable,
  depositProofAvailable,
  fetchProof,
  proofFileName,
  proofUrl,
  recipientsWithDelivery,
  saveFile,
} from './proof';

describe('proofUrl', () => {
  it('builds a deposit URL without recipient', () => {
    expect(proofUrl('/me/transfers/trf_1', 'deposit', 'a@b.c')).toBe(
      '/api/v1/me/transfers/trf_1/proof?kind=deposit',
    );
  });
  it('encodes the recipient of a delivery', () => {
    expect(proofUrl('/me/transfers/trf_1', 'delivery', 'a+b&c@x.example')).toBe(
      '/api/v1/me/transfers/trf_1/proof?kind=delivery&recipient=a%2Bb%26c%40x.example',
    );
  });
  it('omits an empty recipient', () => {
    expect(proofUrl('/admin/tenants/t/transfers/x', 'delivery', '')).toBe(
      '/api/v1/admin/tenants/t/transfers/x/proof?kind=delivery',
    );
    expect(proofUrl('/x', 'delivery', undefined, '/api/v2')).toBe('/api/v2/x/proof?kind=delivery');
  });
});

describe('availability', () => {
  it('deposit proof needs a finished analysis', () => {
    expect(depositProofAvailable('available')).toBe(true);
    expect(depositProofAvailable('expired')).toBe(true);
    expect(depositProofAvailable('deleted')).toBe(true);
    expect(depositProofAvailable('uploading')).toBe(false);
    expect(depositProofAvailable('scanning')).toBe(false);
    expect(depositProofAvailable('rejected')).toBe(false);
  });
  it('delivery proof needs a first download', () => {
    expect(deliveryProofAvailable('2026-01-01T00:00:00Z')).toBe(true);
    expect(deliveryProofAvailable(null)).toBe(false);
    expect(deliveryProofAvailable(undefined)).toBe(false);
    expect(deliveryProofAvailable('')).toBe(false);
  });
  it('lists the recipients who downloaded', () => {
    expect(recipientsWithDelivery(undefined)).toEqual([]);
    expect(
      recipientsWithDelivery([
        { email: 'a@x.example', firstDownloadedAt: '2026-01-01T00:00:00Z' },
        { email: 'b@x.example', firstDownloadedAt: null },
      ]),
    ).toEqual(['a@x.example']);
  });
});

describe('proofFileName', () => {
  it('reads Content-Disposition', () => {
    expect(proofFileName('attachment; filename="proof-1.pdf"', 'deposit')).toBe('proof-1.pdf');
    expect(proofFileName('attachment; filename=p.pdf', 'deposit')).toBe('p.pdf');
  });
  it('falls back', () => {
    expect(proofFileName(null, 'delivery')).toBe('transteira-proof-delivery.pdf');
  });
});

describe('fetchProof', () => {
  it('returns the blob and the name', async () => {
    const fetcher = vi.fn().mockResolvedValue(
      new Response('%PDF', {
        status: 200,
        headers: { 'Content-Disposition': 'attachment; filename="a.pdf"' },
      }),
    );
    const file = await fetchProof('/u', 'deposit', fetcher, 'fr');
    expect(file.fileName).toBe('a.pdf');
    expect(file.blob.size).toBe(4);
    expect(fetcher.mock.calls[0]?.[1]).toMatchObject({ credentials: 'same-origin', method: 'GET' });
  });
  it('throws the problem', async () => {
    const fetcher = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ status: 404, code: 'proof-not-available' }), {
        status: 404,
        headers: { 'Content-Type': 'application/problem+json' },
      }),
    );
    await expect(fetchProof('/u', 'deposit', fetcher)).rejects.toMatchObject({
      status: 404,
      code: 'proof-not-available',
    });
  });
  it('throws an ApiProblem without body', async () => {
    const fetcher = vi.fn().mockResolvedValue(new Response('oops', { status: 429 }));
    const err = await fetchProof('/u', 'deposit', fetcher).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiProblem);
    expect((err as ApiProblem).status).toBe(429);
  });
  it('throws a NetworkError', async () => {
    const fetcher = vi.fn().mockRejectedValue(new TypeError('down'));
    await expect(fetchProof('/u', 'deposit', fetcher)).rejects.toBeInstanceOf(NetworkError);
  });
});

describe('saveFile', () => {
  it('clicks a temporary link', () => {
    vi.useFakeTimers();
    const click = vi.fn();
    const link = { click, remove: vi.fn(), href: '', download: '', rel: '' };
    vi.stubGlobal('document', {
      createElement: () => link,
      body: { appendChild: vi.fn() },
    });
    vi.stubGlobal('URL', { createObjectURL: () => 'blob:x', revokeObjectURL: vi.fn() });
    saveFile({ blob: new Blob(['x']), fileName: 'p.pdf' });
    expect(click).toHaveBeenCalled();
    expect(link.download).toBe('p.pdf');
    vi.runAllTimers();
    expect(URL.revokeObjectURL).toHaveBeenCalledWith('blob:x');
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });
});
