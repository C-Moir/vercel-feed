// test/scanner.test.js
'use strict';
const { test, mock } = require('node:test');
const assert = require('node:assert/strict');

const mockFetch = mock.fn();
global.fetch = mockFetch;

const { checkUrlhaus, submitUrlscan, isVercelIp } = require('../lib/scanner.js');

test('checkUrlhaus returns flagged=true for known malicious URL', async () => {
  mockFetch.mock.mockImplementationOnce(async () => ({
    ok: true,
    json: async () => ({ query_status: 'is_host', urls: [{ url_status: 'online' }] })
  }));
  const result = await checkUrlhaus('https://bad.vercel.app');
  assert.equal(result.flagged, true);
});

test('checkUrlhaus returns flagged=false for clean URL', async () => {
  mockFetch.mock.mockImplementationOnce(async () => ({
    ok: true,
    json: async () => ({ query_status: 'no_results' })
  }));
  const result = await checkUrlhaus('https://clean.vercel.app');
  assert.equal(result.flagged, false);
});

test('checkUrlhaus returns flagged=false on fetch error', async () => {
  mockFetch.mock.mockImplementationOnce(async () => { throw new Error('network'); });
  const result = await checkUrlhaus('https://anything.vercel.app');
  assert.equal(result.flagged, false);
});

test('submitUrlscan returns scan id on success', async () => {
  mockFetch.mock.mockImplementationOnce(async () => ({
    ok: true,
    json: async () => ({ uuid: 'test-uuid-123' })
  }));
  const id = await submitUrlscan('https://foo.vercel.app', null);
  assert.equal(id, 'test-uuid-123');
});

test('submitUrlscan returns null on rate limit', async () => {
  mockFetch.mock.mockImplementationOnce(async () => ({ ok: false, status: 429 }));
  const id = await submitUrlscan('https://foo.vercel.app', null);
  assert.equal(id, null);
});

test('isVercelIp filters known Vercel prefix', () => {
  assert.equal(isVercelIp('76.76.21.1'), true);
  assert.equal(isVercelIp('1.2.3.4'), false);
});
