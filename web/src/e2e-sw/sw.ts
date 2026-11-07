// Entry point of the Service Worker of the end-to-end encrypted downloads, built by
// vite.sw.config.ts into dist/e2e-sw.js (a classic script: module Service Workers are not
// supported by every browser) and registered by shared/e2e/download.ts with the scope /e2e/.
// It only wires the events to handler.ts, where the logic lives and is tested.
//
// The project is type-checked with the DOM library only (tsconfig.json), which lacks the Service
// Worker global scope: the few members used here are declared below.
import { EntryRegistry, handleMessage, routeRequest, type WorkerContext } from './handler';

interface ExtendableEventLike extends Event {
  waitUntil(promise: Promise<unknown>): void;
}

interface FetchEventLike extends ExtendableEventLike {
  readonly request: Request;
  respondWith(response: Promise<Response>): void;
}

interface ExtendableMessageEventLike extends ExtendableEventLike {
  readonly data: unknown;
  readonly ports: readonly MessagePort[];
}

interface ServiceWorkerScopeLike {
  readonly location: { readonly origin: string };
  readonly clients: { claim(): Promise<void> };
  skipWaiting(): Promise<void>;
  fetch(input: string, init: RequestInit): Promise<Response>;
  setTimeout(handler: () => void, ms: number): number;
  addEventListener(type: 'install' | 'activate', listener: (event: ExtendableEventLike) => void): void;
  addEventListener(type: 'fetch', listener: (event: FetchEventLike) => void): void;
  addEventListener(type: 'message', listener: (event: ExtendableMessageEventLike) => void): void;
}

const scope = globalThis as unknown as ServiceWorkerScopeLike;

const ctx: WorkerContext = {
  origin: scope.location.origin,
  registry: new EntryRegistry(),
  fetch: (input, init) => scope.fetch(input, init),
  now: () => Date.now(),
  sleep: (ms) => new Promise((resolve) => scope.setTimeout(resolve, ms)),
};

// A new version takes over at once: the worker keeps no state worth waiting for.
scope.addEventListener('install', (event) => event.waitUntil(scope.skipWaiting()));
scope.addEventListener('activate', (event) => event.waitUntil(scope.clients.claim()));
scope.addEventListener('message', (event) => event.waitUntil(handleMessage(event.data, event.ports, ctx)));
scope.addEventListener('fetch', (event) => {
  const response = routeRequest(event.request, ctx);
  if (response !== undefined) event.respondWith(response);
});
