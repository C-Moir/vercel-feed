'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { writeEntry, readEntries, ROTATE_AT, ARCHIVE_KEEP } = require('../lib/threat-intel.js');

function tmpFile() {
  return path.join(os.tmpdir(), `ti-test-${Date.now()}.json`);
}

test('writeEntry creates file with first entry', () => {
  const file = tmpFile();
  writeEntry(file, { deployment: 'https://bad.vercel.app', c2Ips: ['1.2.3.4'] });
  const entries = readEntries(file);
  assert.equal(entries.length, 1);
  assert.equal(entries[0].deployment, 'https://bad.vercel.app');
  fs.unlinkSync(file);
});

test('writeEntry appends subsequent entries', () => {
  const file = tmpFile();
  writeEntry(file, { deployment: 'https://a.vercel.app', c2Ips: [] });
  writeEntry(file, { deployment: 'https://b.vercel.app', c2Ips: [] });
  assert.equal(readEntries(file).length, 2);
  fs.unlinkSync(file);
});

test('writeEntry rotates when at ROTATE_AT limit', () => {
  const file = tmpFile();
  for (let i = 0; i < ROTATE_AT; i++) {
    writeEntry(file, { deployment: `https://app${i}.vercel.app`, c2Ips: [] });
  }
  writeEntry(file, { deployment: 'https://trigger.vercel.app', c2Ips: [] });
  const entries = readEntries(file);
  assert.equal(entries.length, ROTATE_AT - ARCHIVE_KEEP + 1);
  fs.unlinkSync(file);
});
