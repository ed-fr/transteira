import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  applyScrollRegion,
  createScrollRegion,
  environmentObserver,
  overflows,
  scrollRegion,
  type ResizeObserverLike,
  type ScrollRegionNode,
} from './scrollRegion';

class FakeNode implements ScrollRegionNode {
  attributes = new Map<string, string>();
  scrollWidth = 400;
  clientWidth = 400;
  firstElementChild: object | null = { table: true };
  setAttribute(name: string, value: string): void {
    this.attributes.set(name, value);
  }
  removeAttribute(name: string): void {
    this.attributes.delete(name);
  }
}

class FakeObserver implements ResizeObserverLike {
  static last: FakeObserver | undefined;
  observed: unknown[] = [];
  disconnected = false;
  constructor(readonly callback: () => void) {
    FakeObserver.last = this;
  }
  observe(target: never): void {
    this.observed.push(target);
  }
  disconnect(): void {
    this.disconnected = true;
  }
}

describe('overflows', () => {
  it('allows one pixel of rounding', () => {
    expect(overflows({ scrollWidth: 401, clientWidth: 400 })).toBe(false);
    expect(overflows({ scrollWidth: 402, clientWidth: 400 })).toBe(true);
    expect(overflows({ scrollWidth: 300, clientWidth: 400 })).toBe(false);
  });
});

describe('applyScrollRegion', () => {
  it('names the area and adds a tab stop only while it overflows', () => {
    const node = new FakeNode();
    applyScrollRegion(node, 'cap-1', true);
    expect(Object.fromEntries(node.attributes)).toEqual({
      role: 'region',
      'aria-labelledby': 'cap-1',
      tabindex: '0',
    });
    applyScrollRegion(node, 'cap-1', false);
    expect(node.attributes.size).toBe(0);
  });
});

describe('scrollRegion action', () => {
  it('follows the overflow with a ResizeObserver on the area and the table', () => {
    const node = new FakeNode();
    const action = createScrollRegion(FakeObserver)(node, 'cap-1');
    const observer = FakeObserver.last as FakeObserver;
    expect(observer.observed).toEqual([node, node.firstElementChild]);
    expect(node.attributes.size).toBe(0);

    node.clientWidth = 320;
    observer.callback();
    expect(node.attributes.get('role')).toBe('region');
    expect(node.attributes.get('aria-labelledby')).toBe('cap-1');

    action.update('cap-2');
    expect(node.attributes.get('aria-labelledby')).toBe('cap-2');

    node.clientWidth = 800;
    observer.callback();
    expect(node.attributes.size).toBe(0);

    action.destroy();
    expect(observer.disconnected).toBe(true);
  });

  it('observes the area alone when it holds no element yet', () => {
    const node = new FakeNode();
    node.firstElementChild = null;
    createScrollRegion(FakeObserver)(node, 'cap');
    expect(FakeObserver.last?.observed).toEqual([node]);
  });

  it('computes the state once and on update without ResizeObserver', () => {
    const node = new FakeNode();
    node.clientWidth = 100;
    const action = createScrollRegion(undefined)(node, 'cap');
    expect(node.attributes.get('tabindex')).toBe('0');
    node.clientWidth = 400;
    action.update('cap');
    expect(node.attributes.size).toBe(0);
    action.destroy();
  });

  it('runs in Node without ResizeObserver', () => {
    expect(environmentObserver()).toBeUndefined();
    const node = new FakeNode();
    scrollRegion(node, 'cap').destroy();
    expect(node.attributes.size).toBe(0);
  });

  describe('with the ResizeObserver of the browser', () => {
    afterEach(() => {
      vi.unstubAllGlobals();
    });

    it('uses it', () => {
      vi.stubGlobal('ResizeObserver', FakeObserver);
      expect(environmentObserver()).toBe(FakeObserver);
      const node = new FakeNode();
      const action = scrollRegion(node, 'cap');
      expect(FakeObserver.last?.observed).toEqual([node, node.firstElementChild]);
      action.destroy();
      expect(FakeObserver.last?.disconnected).toBe(true);
    });
  });
});
