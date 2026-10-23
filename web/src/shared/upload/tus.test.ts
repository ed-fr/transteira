import { expect, it } from 'vitest';
import { CHUNK_SIZE, TUS_VERSION } from './tus';

it('exposes the protocol constants', () => {
  expect(TUS_VERSION).toBe('1.0.0');
  expect(CHUNK_SIZE).toBe(32 * 1024 * 1024);
});
