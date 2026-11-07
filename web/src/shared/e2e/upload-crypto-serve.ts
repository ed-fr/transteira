// Worker side of the upload encryption (upload.worker.ts): answers the requests of the page
// (upload-crypto.ts) with an UploadCryptoCore. The bytes of an encrypted range are returned as a
// transferred ArrayBuffer (moved, not copied).

import {
  UploadCryptoCore,
  errorResponse,
  type CryptoRequest,
  type CryptoResponse,
} from './upload-crypto-core';

/** The part of DedicatedWorkerGlobalScope used here. */
export interface WorkerScope {
  onmessage: ((event: { data: CryptoRequest }) => void) | null;
  postMessage(message: CryptoResponse, transfer?: Transferable[]): void;
}

/** Serves the upload encryption requests posted to scope. */
export function serveUploadCrypto(scope: WorkerScope): void {
  let core: UploadCryptoCore | undefined;
  const aborted = new Set<number>();

  const ready = (): UploadCryptoCore => {
    if (core === undefined) throw new Error('upload crypto: not initialised');
    return core;
  };

  async function handle(req: CryptoRequest): Promise<void> {
    switch (req.op) {
      case 'init':
        core?.clear();
        core = new UploadCryptoCore(req.key);
        scope.postMessage({ id: req.id, kind: 'ok' });
        return;
      case 'abort':
        aborted.add(req.target);
        return;
      case 'hash': {
        const value = await ready().hash(
          req.index,
          req.file,
          req.chunkSize,
          (bytes) => scope.postMessage({ id: req.id, kind: 'progress', bytes }),
          () => aborted.has(req.id),
        );
        scope.postMessage({ id: req.id, kind: 'ok', value });
        return;
      }
      case 'prepare': {
        const value = await ready().prepare(req.index, req.file, req.salt, req.chunkSize);
        scope.postMessage({ id: req.id, kind: 'ok', value });
        return;
      }
      case 'range': {
        const bytes = await ready().range(req.index, req.start, req.end);
        scope.postMessage({ id: req.id, kind: 'ok', value: bytes.buffer }, [bytes.buffer]);
        return;
      }
    }
  }

  scope.onmessage = (event) => {
    const req = event.data;
    handle(req)
      .catch((err: unknown) => scope.postMessage(errorResponse(req.id, err)))
      .finally(() => {
        if (req.op === 'hash') aborted.delete(req.id);
      });
  };
}
