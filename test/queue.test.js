// test/queue.test.js
'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { LRUSet, JobQueue } = require('../lib/queue.js');

test('LRUSet evicts oldest when at capacity', () => {
  const s = new LRUSet(3);
  s.add('a'); s.add('b'); s.add('c');
  s.add('d'); // evicts 'a'
  assert.equal(s.has('a'), false);
  assert.equal(s.has('d'), true);
  assert.equal(s.size, 3);
});

test('LRUSet ignores duplicate adds', () => {
  const s = new LRUSet(3);
  s.add('a'); s.add('a');
  assert.equal(s.size, 1);
});

test('JobQueue deduplicates hostnames', () => {
  const q = new JobQueue();
  const e1 = q.push('foo.vercel.app');
  const e2 = q.push('foo.vercel.app');
  assert.ok(e1);
  assert.equal(e2, null);
});

test('JobQueue priority entries go to front', () => {
  const q = new JobQueue();
  q.push('normal.vercel.app');
  q.push('login-app.vercel.app'); // priority keyword
  const first = q.shift();
  assert.equal(first.hostname, 'login-app.vercel.app');
});

test('JobQueue update patches entry in place', () => {
  const q = new JobQueue();
  const entry = q.push('foo.vercel.app');
  q.update(entry.id, { status: 'clean' });
  assert.equal(q.getAll()[0].status, 'clean');
});
