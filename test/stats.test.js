'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { computeStats, detectTrending } = require('../lib/stats.js');

function entry(overrides = {}) {
  return { timestamp: new Date().toISOString(), status: 'clean', framework: 'Next.js', aiTool: 'v0', ...overrides };
}

test('computeStats counts flagged and suspicious together', () => {
  const stats = computeStats([
    entry({ status: 'clean' }),
    entry({ status: 'flagged' }),
    entry({ status: 'suspicious' })
  ]);
  assert.equal(stats.totalSeen, 3);
  assert.equal(stats.flaggedCount, 2);
});

test('computeStats builds framework breakdown', () => {
  const stats = computeStats([
    entry({ framework: 'Next.js' }),
    entry({ framework: 'Next.js' }),
    entry({ framework: 'Static' })
  ]);
  assert.equal(stats.frameworkBreakdown['Next.js'], 2);
  assert.equal(stats.frameworkBreakdown['Static'], 1);
});

test('computeStats builds AI tool leaderboard', () => {
  const stats = computeStats([
    entry({ aiTool: 'v0' }),
    entry({ aiTool: 'v0' }),
    entry({ aiTool: 'Bolt' })
  ]);
  assert.equal(stats.aiToolLeaderboard['v0'], 2);
  assert.equal(stats.aiToolLeaderboard['Bolt'], 1);
});

test('detectTrending returns spike message when rate doubles', () => {
  const now = Date.now();
  const prior = Array.from({ length: 2 }, (_, i) => ({
    timestamp: new Date(now - 90 * 60 * 1000 + i * 1000).toISOString()
  }));
  const recent = Array.from({ length: 10 }, (_, i) => ({
    timestamp: new Date(now - 10 * 60 * 1000 + i * 1000).toISOString()
  }));
  assert.ok(detectTrending([...prior, ...recent]) !== null);
});
