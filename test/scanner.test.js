// test/scanner.test.js
'use strict';
const { test, mock } = require('node:test');
const assert = require('node:assert/strict');

const mockFetch = mock.fn();
global.fetch = mockFetch;

const { checkUrlhaus, submitUrlscan, extractScanData, isFirstParty } = require('../lib/scanner.js');

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

// ── isFirstParty ──────────────────────────────────────────────────────────

test('isFirstParty matches the page domain and its subdomains', () => {
  assert.equal(isFirstParty('my-app.pages.dev', 'my-app.pages.dev'), true);
  assert.equal(isFirstParty('cdn.my-app.pages.dev', 'my-app.pages.dev'), true);
  assert.equal(isFirstParty('other-site.pages.dev', 'my-app.pages.dev'), false);
  assert.equal(isFirstParty('fonts.googleapis.com', 'my-app.pages.dev'), false);
});

test('isFirstParty returns false for missing inputs', () => {
  assert.equal(isFirstParty('', 'x.pages.dev'), false);
  assert.equal(isFirstParty('x.pages.dev', null), false);
});

// ── extractScanData ───────────────────────────────────────────────────────

test('extractScanData does NOT report CDN IPs as C2 on clean verdicts', () => {
  const result = {
    page: { domain: 'cool-site.pages.dev' },
    verdicts: { overall: { score: 0, malicious: false } },
    data: { requests: [
      { request: { url: 'https://cool-site.pages.dev/index.html' },
        response: { remoteAddress: '104.21.12.34:443' } },
      { request: { url: 'https://fonts.googleapis.com/css' },
        response: { remoteAddress: '142.250.181.170:443' } },
    ]}
  };
  const scan = extractScanData(result);
  assert.deepEqual(scan.c2Ips, []);
  assert.equal(scan.malicious, false);
});

test('extractScanData reports IPs as C2 only when verdict is malicious', () => {
  const result = {
    page: { domain: 'bad.pages.dev' },
    verdicts: { overall: { score: 100, malicious: true } },
    data: { requests: [
      { request: { url: 'https://bad.pages.dev/' },
        response: { remoteAddress: '1.2.3.4:443' } },
    ]}
  };
  const scan = extractScanData(result);
  assert.deepEqual(scan.c2Ips, ['1.2.3.4']);
  assert.equal(scan.malicious, true);
});

test('extractScanData treats page subdomains as first-party', () => {
  const result = {
    page: { domain: 'my-app.pages.dev' },
    verdicts: { overall: { score: 0, malicious: false } },
    data: { requests: [
      // First-party subdomain — should NOT appear in redirectDomains/scriptSources
      { request: { url: 'https://assets.my-app.pages.dev/logo.png' },
        response: { remoteAddress: '1.1.1.1:443' } },
      // Third-party script
      { request: { url: 'https://cdn.jsdelivr.net/npm/lib.js' },
        response: { remoteAddress: '2.2.2.2:443' } },
    ]}
  };
  const scan = extractScanData(result);
  assert.ok(!scan.redirectDomains.includes('assets.my-app.pages.dev'));
  assert.ok(scan.scriptSources.includes('cdn.jsdelivr.net'));
});

test('extractScanData returns null for null input', () => {
  assert.equal(extractScanData(null), null);
});
