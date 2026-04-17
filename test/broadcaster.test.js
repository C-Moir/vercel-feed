'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { Broadcaster } = require('../lib/broadcaster.js');

test('Broadcaster tracks and removes clients', () => {
  const b = new Broadcaster();
  let closeFn;
  const fakeRes = {
    write: () => {},
    on: (event, fn) => { if (event === 'close') closeFn = fn; }
  };
  b.addClient(fakeRes, []);
  assert.equal(b.clientCount, 1);
  closeFn();
  assert.equal(b.clientCount, 0);
});

test('Broadcaster replays existing entries on new connection', () => {
  const b = new Broadcaster();
  const entries = [
    { id: '1', url: 'https://a.vercel.app', status: 'clean' },
    { id: '2', url: 'https://b.vercel.app', status: 'pending' }
  ];
  const received = [];
  const fakeRes = { write: (chunk) => received.push(chunk), on: () => {} };
  b.addClient(fakeRes, entries);
  assert.equal(received.length, 2);
  assert.ok(received[0].includes('a.vercel.app'));
});

test('Broadcaster broadcast sends to all clients', () => {
  const b = new Broadcaster();
  const chunks1 = [], chunks2 = [];
  b.addClient({ write: c => chunks1.push(c), on: () => {} }, []);
  b.addClient({ write: c => chunks2.push(c), on: () => {} }, []);
  b.broadcast({ id: '1', status: 'clean' });
  assert.equal(chunks1.length, 1);
  assert.equal(chunks2.length, 1);
});
