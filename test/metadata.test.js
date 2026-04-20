'use strict';
const { test, mock } = require('node:test');
const assert = require('node:assert/strict');

const mockFetch = mock.fn();
global.fetch = mockFetch;

const {
  extractFromUrlscan,
  buildFaviconUrl,
  fetchDom,
  extractTitle,
  extractMetaDescription,
} = require('../lib/metadata.js');

test('extractFromUrlscan pulls title and description', () => {
  const result = { page: { title: 'My App', description: 'A cool app' } };
  const meta = extractFromUrlscan(result);
  assert.equal(meta.title, 'My App');
  assert.equal(meta.description, 'A cool app');
});

test('extractFromUrlscan returns null fields for missing data', () => {
  const meta = extractFromUrlscan({ page: {} });
  assert.equal(meta.title, null);
  assert.equal(meta.description, null);
});

test('buildFaviconUrl returns correct favicon path', () => {
  assert.equal(buildFaviconUrl('https://my-app.vercel.app'), 'https://my-app.vercel.app/favicon.ico');
});

// ── fetchDom ──────────────────────────────────────────────────────────────

function mockHtmlResponse(html, status = 200) {
  const bytes = Buffer.from(html, 'utf8');
  let sent = false;
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: new Map([['content-type', 'text/html; charset=utf-8']]),
    body: {
      getReader: () => ({
        read: async () => {
          if (sent) return { done: true };
          sent = true;
          return { done: false, value: bytes };
        },
        cancel: async () => {},
      }),
      cancel: async () => {},
    },
  };
}

test('fetchDom returns body and headers on 200 HTML', async () => {
  mockFetch.mock.mockImplementationOnce(async () => mockHtmlResponse('<html><title>Hi</title></html>'));
  const { dom, headers, status } = await fetchDom('https://x.pages.dev');
  assert.equal(status, 200);
  assert.match(dom, /<title>Hi<\/title>/);
  assert.equal(headers['content-type'], 'text/html; charset=utf-8');
});

test('fetchDom returns empty dom on non-HTML content-type', async () => {
  mockFetch.mock.mockImplementationOnce(async () => ({
    ok: true, status: 200,
    headers: new Map([['content-type', 'application/json']]),
    body: { cancel: async () => {} },
  }));
  const { dom, status } = await fetchDom('https://x.pages.dev/api');
  assert.equal(dom, '');
  assert.equal(status, 200);
});

test('fetchDom returns status on 404 without body parse', async () => {
  mockFetch.mock.mockImplementationOnce(async () => ({
    ok: false, status: 404,
    headers: new Map([['content-type', 'text/html']]),
    body: { cancel: async () => {} },
  }));
  const { dom, status } = await fetchDom('https://gone.pages.dev');
  assert.equal(status, 404);
  assert.equal(dom, '');
});

test('fetchDom returns status 0 on network error', async () => {
  mockFetch.mock.mockImplementationOnce(async () => { throw new Error('ECONNREFUSED'); });
  const { dom, status } = await fetchDom('https://broken.pages.dev');
  assert.equal(status, 0);
  assert.equal(dom, '');
});

// ── extractTitle ──────────────────────────────────────────────────────────

test('extractTitle pulls title text', () => {
  assert.equal(extractTitle('<html><head><title>Hello World</title></head>'), 'Hello World');
});

test('extractTitle collapses whitespace', () => {
  assert.equal(extractTitle('<title>\n  Hello\n  World\n</title>'), 'Hello World');
});

test('extractTitle returns null when no title', () => {
  assert.equal(extractTitle('<html><body>no title</body></html>'), null);
});

test('extractTitle returns null on empty title', () => {
  assert.equal(extractTitle('<title>   </title>'), null);
});

// ── extractMetaDescription ────────────────────────────────────────────────

test('extractMetaDescription pulls name=description', () => {
  const html = '<meta name="description" content="A cool app for X">';
  assert.equal(extractMetaDescription(html), 'A cool app for X');
});

test('extractMetaDescription handles content-before-name order', () => {
  const html = '<meta content="Reversed order" name="description">';
  assert.equal(extractMetaDescription(html), 'Reversed order');
});

test('extractMetaDescription returns null when missing', () => {
  assert.equal(extractMetaDescription('<html></html>'), null);
});
