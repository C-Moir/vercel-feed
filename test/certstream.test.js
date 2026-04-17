// test/certstream.test.js
'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { isValidDeployment, extractHostnames } = require('../lib/certstream.js');

test('isValidDeployment accepts normal vercel.app hostname', () => {
  assert.equal(isValidDeployment('my-app.vercel.app'), true);
});

test('isValidDeployment rejects Vercel internal domains', () => {
  assert.equal(isValidDeployment('api.vercel.app'), false);
  assert.equal(isValidDeployment('www.vercel.app'), false);
});

test('isValidDeployment rejects CI preview pattern', () => {
  assert.equal(isValidDeployment('my-app-abc123def456-username.vercel.app'), false);
});

test('isValidDeployment rejects non-vercel domains', () => {
  assert.equal(isValidDeployment('evil.com'), false);
});

test('extractHostnames pulls vercel.app SANs from cert data', () => {
  const certData = {
    data: {
      leaf_cert: {
        all_domains: [
          'my-app.vercel.app',
          'my-app.vercel.app',   // duplicate - excluded
          'api.vercel.app',      // internal - excluded
          'unrelated.com'
        ]
      }
    }
  };
  assert.deepEqual(extractHostnames(certData), ['my-app.vercel.app']);
});

test('extractHostnames returns empty array for malformed cert', () => {
  assert.deepEqual(extractHostnames({}), []);
  assert.deepEqual(extractHostnames(null), []);
});
