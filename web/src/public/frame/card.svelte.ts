// Size of the public card (CLAUDE.md section 13.2). App.svelte creates one CardFrame, provides it to
// the screens through a Svelte context and passes frame.size to PageLayout (cardSize). Each route
// has a default size (routeCardSize); a screen whose steps need another width requests it while it
// is shown, and releases it when it no longer needs it (or when it is destroyed):
//
//   const frame = useCardFrame();
//   $effect.pre(() => frame?.request(step === 'form' ? 'split' : 'narrow'));
//
// The effect returns the release function of the request, so Svelte releases it before the next
// run and when the screen is destroyed. The last active request wins; releasing it restores the
// previous one, then the route size. useCardFrame() returns undefined outside the public
// application (admin brand preview, tests), hence the optional call.
import { getContext, setContext, untrack } from 'svelte';

/** Width of the public card: .tt-pcard--narrow, --medium, --split or --wide (styles/layout.css). */
export type CardSize = 'narrow' | 'medium' | 'split' | 'wide';

/** Every card size, from the narrowest. */
export const CARD_SIZES: readonly CardSize[] = ['narrow', 'medium', 'split', 'wide'];

/**
 * Default card size of a route pattern of the public application: "/me" (tables) is wide, the
 * legal texts and the help are medium, every other route starts narrow (its screen may request
 * another size: the deposit form is split, the download page medium).
 */
export function routeCardSize(pattern: string): CardSize {
  if (pattern === '/me') {
    return 'wide';
  }
  if (pattern.startsWith('/legal/') || pattern === '/help' || pattern.startsWith('/help/')) {
    return 'medium';
  }
  return 'narrow';
}

/** One active size request. */
interface CardRequest {
  readonly size: CardSize;
}

/** Card size of the public frame: the latest active request, else the size of the route. */
export class CardFrame {
  #requests = $state.raw<readonly CardRequest[]>([]);
  readonly #route: () => CardSize;

  /** route: reactive getter of the size of the current route (narrow when absent). */
  constructor(route: () => CardSize = () => 'narrow') {
    this.#route = route;
  }

  /** Current size (reactive): the latest active request, else the route size. */
  get size(): CardSize {
    const last = this.#requests.at(-1);
    return last === undefined ? this.#route() : last.size;
  }

  /**
   * The card is split (reactive): it has no padding of its own, its content lays out padded
   * sections and panes (.tt-pcard__section, .tt-pcard__pane).
   */
  get split(): boolean {
    return this.size === 'split';
  }

  /**
   * Requests a size until the returned function is called (calling it again does nothing). The
   * state is updated without tracking, so that calling request() inside an effect does not make
   * the effect depend on the requests.
   */
  request(size: CardSize): () => void {
    const entry: CardRequest = { size };
    untrack(() => {
      this.#requests = [...this.#requests, entry];
    });
    return () => {
      untrack(() => {
        if (this.#requests.includes(entry)) {
          this.#requests = this.#requests.filter((r) => r !== entry);
        }
      });
    };
  }
}

/** Key of the card frame in the Svelte context. */
const CARD_FRAME = Symbol('tt-card-frame');

/** The Svelte context functions used here (injectable for tests). */
export interface ContextApi {
  set<T>(key: unknown, value: T): T;
  get<T>(key: unknown): T | undefined;
}

const svelteContext: ContextApi = {
  set: (key, value) => setContext(key, value),
  get: (key) => getContext(key),
};

/** Makes frame available to the components below (call during the initialisation of App.svelte). */
export function provideCardFrame(frame: CardFrame, context: ContextApi = svelteContext): CardFrame {
  return context.set(CARD_FRAME, frame);
}

/**
 * Returns the card frame provided by an ancestor (call during the initialisation of a component),
 * or undefined outside the public application.
 */
export function useCardFrame(context: ContextApi = svelteContext): CardFrame | undefined {
  return context.get<CardFrame>(CARD_FRAME);
}
