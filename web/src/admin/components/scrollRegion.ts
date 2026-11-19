// Horizontal scroll area of a data table (DataTable; plan of step 3c, deviation 7): on a narrow
// screen the real <table> keeps its columns and scrolls horizontally inside its card instead of
// stacking its rows (a data table is exempt from the reflow rule). Only while the table overflows
// its area, the area becomes a focusable named region (role="region", aria-labelledby the caption,
// tabindex="0"), so that keyboard users can scroll it (WCAG 2.1.1) and screen readers announce
// what scrolls; when everything fits, the area is a plain box and adds no tab stop.
//
// The overflow is followed with a ResizeObserver on the area and on the table (resized window,
// rows added by "Load more", language change); without ResizeObserver (unit tests, old engines)
// the state is computed once and on update.

/** The parts of the scroll area the action uses (an HTMLElement). */
export interface ScrollRegionNode {
  readonly scrollWidth: number;
  readonly clientWidth: number;
  readonly firstElementChild: object | null;
  setAttribute(name: string, value: string): void;
  removeAttribute(name: string): void;
}

/** The parts of a ResizeObserver the action uses. */
export interface ResizeObserverLike {
  observe(target: never): void;
  disconnect(): void;
}

/** Constructor of a ResizeObserver (injectable for tests). */
export type ResizeObserverFactory = new (callback: () => void) => ResizeObserverLike;

/** Reports whether the content of the area is wider than the area (1 px of rounding allowed). */
export function overflows(node: Pick<ScrollRegionNode, 'scrollWidth' | 'clientWidth'>): boolean {
  return node.scrollWidth > node.clientWidth + 1;
}

/** Sets (overflowing) or removes the region role, its name and its tab stop. */
export function applyScrollRegion(node: ScrollRegionNode, labelledBy: string, overflowing: boolean): void {
  if (overflowing) {
    node.setAttribute('role', 'region');
    node.setAttribute('aria-labelledby', labelledBy);
    node.setAttribute('tabindex', '0');
  } else {
    node.removeAttribute('role');
    node.removeAttribute('aria-labelledby');
    node.removeAttribute('tabindex');
  }
}

/** Svelte action of the scroll area: use:scrollRegion={captionId}. */
export type ScrollRegionAction = (
  node: ScrollRegionNode,
  labelledBy: string,
) => { update(labelledBy: string): void; destroy(): void };

/** Creates the action with the given ResizeObserver (none: computed once and on update). */
export function createScrollRegion(Observer: ResizeObserverFactory | undefined): ScrollRegionAction {
  return (node, labelledBy) => {
    let label = labelledBy;
    const check = (): void => applyScrollRegion(node, label, overflows(node));
    check();
    let observer: ResizeObserverLike | undefined;
    if (Observer !== undefined) {
      observer = new Observer(check);
      observer.observe(node as never);
      if (node.firstElementChild !== null) {
        observer.observe(node.firstElementChild as never);
      }
    }
    return {
      update(next) {
        label = next;
        check();
      },
      destroy() {
        observer?.disconnect();
      },
    };
  };
}

/** The ResizeObserver of the environment, undefined without one (Node, old engines). */
export function environmentObserver(): ResizeObserverFactory | undefined {
  return (globalThis as { ResizeObserver?: ResizeObserverFactory }).ResizeObserver;
}

/** The action of the running application (ResizeObserver of the browser when available). */
export const scrollRegion: ScrollRegionAction = (node, labelledBy) =>
  createScrollRegion(environmentObserver())(node, labelledBy);
