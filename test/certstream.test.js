// test/certstream.test.js
// Covers hostname validation from lib/platforms.js (shared by certstream + github-pages).
// The file is named certstream for historical reasons; the actual isValidDeployment
// function lives in lib/platforms.js.
'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { isValidDeployment } = require('../lib/platforms.js');

test('isValidDeployment accepts normal vercel.app hostname', () => {
  assert.equal(isValidDeployment('my-app.vercel.app'), true);
  assert.equal(isValidDeployment('graffiti-is-art-v2.vercel.app'), true);
  assert.equal(isValidDeployment('doughboy-prd.vercel.app'), true);
});

test('isValidDeployment rejects Vercel internal domains', () => {
  assert.equal(isValidDeployment('api.vercel.app'), false);
  assert.equal(isValidDeployment('www.vercel.app'), false);
});

test('isValidDeployment rejects Vercel preview pattern', () => {
  assert.equal(isValidDeployment('my-app-abc123def-username.vercel.app'), false);
});

test('isValidDeployment rejects non-platform domains', () => {
  assert.equal(isValidDeployment('evil.com'), false);
});

test('isValidDeployment accepts Netlify auto-generated names (brilliant-* is NOT internal)', () => {
  // 'brilliant-' is one of Netlify's default adjective prefixes for auto-named sites.
  // Previously it was in internalRe which silently dropped roughly 1 in N free-tier
  // Netlify deployments (where N = number of adjectives in Netlify's pool).
  assert.equal(isValidDeployment('brilliant-curie-abc123.netlify.app'), true);
  assert.equal(isValidDeployment('jolly-einstein-456.netlify.app'), true);
});

test('isValidDeployment still rejects actual Netlify infrastructure', () => {
  assert.equal(isValidDeployment('app.netlify.app'), false);
  assert.equal(isValidDeployment('api.netlify.app'), false);
});
