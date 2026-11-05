// Proofs of deposit and delivery (V2): URL building, availability rules and the download of the
// signed PDF. The PDF is fetched with the session cookie (GET, no CSRF token needed), then saved
// from an object URL, so that a Problem answer (404 proof-not-available, 429) can be shown in the
// page instead of replacing it.
import { ApiProblem, NetworkError, type Problem } from './client';
import type { components } from './schema';

/** Kind of a proof. */
export type ProofKind = components['schemas']['ProofKind'];

/** Tracking of one recipient (per-recipient links). */
type Tracking = Pick<components['schemas']['RecipientTracking'], 'email' | 'firstDownloadedAt'>;

/**
 * URL of a proof. base is the transfer URL without the API prefix, for example
 * "/me/transfers/trf_1" or "/admin/tenants/ten_1/transfers/trf_1"; every segment must already be
 * encoded. The recipient (delivery only) is encoded in the query string.
 */
export function proofUrl(base: string, kind: ProofKind, recipient?: string, apiBase = '/api/v1'): string {
  const query = new URLSearchParams({ kind });
  if (kind === 'delivery' && recipient !== undefined && recipient !== '') {
    query.set('recipient', recipient);
  }
  return `${apiBase}${base}/proof?${query.toString().replace(/\+/g, '%20')}`;
}

/** The proof of deposit exists once the antivirus analysis is over (and outlives the transfer). */
export function depositProofAvailable(status: string): boolean {
  return status === 'available' || status === 'expired' || status === 'deleted';
}

/** The proof of delivery exists once the transfer has been downloaded. */
export function deliveryProofAvailable(firstDownloadedAt: string | null | undefined): boolean {
  return firstDownloadedAt !== null && firstDownloadedAt !== undefined && firstDownloadedAt !== '';
}

/** Recipients with a proof of delivery of their own: those who completed a download. */
export function recipientsWithDelivery(tracking: readonly Tracking[] | undefined): string[] {
  return (tracking ?? []).filter((r) => deliveryProofAvailable(r.firstDownloadedAt)).map((r) => r.email);
}

/** File name of a proof: the Content-Disposition one, else a generic name. */
export function proofFileName(contentDisposition: string | null, kind: ProofKind): string {
  const match = /filename="?([^";]+)"?/i.exec(contentDisposition ?? '');
  const name = match?.[1]?.trim();
  return name !== undefined && name !== '' ? name : `transteira-proof-${kind}.pdf`;
}

/** Downloaded proof. */
export interface ProofFile {
  blob: Blob;
  fileName: string;
}

/** Fetches a proof. Throws ApiProblem (status, code) on an error answer, NetworkError without answer. */
export async function fetchProof(
  url: string,
  kind: ProofKind,
  fetcher: typeof fetch = (input, init) => globalThis.fetch(input, init),
  language = 'en',
): Promise<ProofFile> {
  let response: Response;
  try {
    response = await fetcher(url, {
      method: 'GET',
      headers: { Accept: 'application/pdf, application/problem+json', 'Accept-Language': language },
      credentials: 'same-origin',
    });
  } catch (err) {
    throw new NetworkError(err);
  }
  if (!response.ok) {
    let problem: Problem | undefined;
    try {
      problem = (await response.json()) as Problem;
    } catch {
      problem = undefined;
    }
    throw new ApiProblem(response.status, problem);
  }
  return {
    blob: await response.blob(),
    fileName: proofFileName(response.headers.get('Content-Disposition'), kind),
  };
}

/** Hands a downloaded file to the browser (object URL and temporary link). */
export function saveFile(file: ProofFile): void {
  const href = URL.createObjectURL(file.blob);
  const link = document.createElement('a');
  link.href = href;
  link.download = file.fileName;
  link.rel = 'noopener';
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(href), 10_000);
}
