import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRateLimiter, matchAccessKey, parseAccessKeys } from '../src/access.js';

test('access keys: label:secret pairs, short secrets rejected, wrong keys refused', () => {
  const keys = parseAccessKeys('alice:0123456789abcdef-alice, bob:0123456789abcdef-bob');
  assert.equal(matchAccessKey(keys, '0123456789abcdef-bob'), 'bob');
  assert.equal(matchAccessKey(keys, 'wrong-key-0123456789'), null);
  assert.equal(matchAccessKey(keys, ''), null);
  assert.throws(() => parseAccessKeys('eve:short'), /shorter than 16/);
});

test('rate limiter allows the limit per window, then reports when to retry', () => {
  const limiter = createRateLimiter({ limit: 2, windowMs: 1000 });
  assert.equal(limiter.take('k', 0).ok, true);
  assert.equal(limiter.take('k', 100).ok, true);
  const blocked = limiter.take('k', 200);
  assert.equal(blocked.ok, false);
  assert.equal(blocked.retryAfterSeconds, 1);
  assert.equal(limiter.take('k', 1001).ok, true); // first event has left the window
  assert.equal(limiter.take('other', 200).ok, true); // limits are per id
});
