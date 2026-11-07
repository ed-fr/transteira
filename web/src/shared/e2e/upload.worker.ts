// Dedicated module Worker of the end-to-end encrypted upload: hashes the plaintext files and
// encrypts the ranges the upload engine asks for, off the main thread. Created by upload-crypto.ts
// with new Worker(new URL('./upload.worker.ts', import.meta.url), { type: 'module' }), which Vite
// emits as a fingerprinted file under /assets/ (CSP script-src 'self': no blob: Worker, no wasm).

import { serveUploadCrypto, type WorkerScope } from './upload-crypto-serve';

// The project is typed with the DOM library only: self is the Worker global scope here.
serveUploadCrypto(self as unknown as WorkerScope);
