'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { extractFromUrlscan, buildFaviconUrl } = require('../lib/metadata.js');

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
