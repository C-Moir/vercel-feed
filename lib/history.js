'use strict';
const fs   = require('node:fs');
const path = require('node:path');

const HISTORY_DIR = path.join(__dirname, '..', 'history');

// Ensure the directory exists
try { fs.mkdirSync(HISTORY_DIR, { recursive: true }); } catch (_) {}

function todayKey() {
  return new Date().toISOString().slice(0, 10); // YYYY-MM-DD in UTC
}

function dayFile(dateKey) {
  return path.join(HISTORY_DIR, `${dateKey}.ndjson`);
}

function appendHistory(entry) {
  const record = {
    id:               entry.id,
    hostname:         entry.hostname,
    url:              entry.url,
    platform:         entry.platform || 'Unknown',
    timestamp:        entry.timestamp,
    title:            entry.meta?.title || null,
    status:           entry.status,
    screenshot:       entry.screenshot || null,
    screenshotSource: entry.screenshotSource || null,
    scan:             entry.scan || null,
    meta:             entry.meta || null,
    framework:        entry.framework || null,
    aiTool:           entry.aiTool || null,
    contentTags:      entry.contentTags || null,
  };
  try {
    fs.appendFileSync(dayFile(todayKey()), JSON.stringify(record) + '\n');
  } catch (_) {}
}

// Read one day's entries. dateKey defaults to today.
function readDay(dateKey) {
  const file = dayFile(dateKey || todayKey());
  try {
    const content = fs.readFileSync(file, 'utf8');
    return content.trim().split('\n').filter(Boolean).map(l => {
      try { return JSON.parse(l); } catch (_) { return null; }
    }).filter(Boolean).reverse(); // newest first
  } catch (_) {
    return [];
  }
}

// List available date keys, newest first
function listDates() {
  try {
    return fs.readdirSync(HISTORY_DIR)
      .filter(f => /^\d{4}-\d{2}-\d{2}\.ndjson$/.test(f))
      .map(f => f.replace('.ndjson', ''))
      .sort()
      .reverse();
  } catch (_) {
    return [];
  }
}

// Backwards-compat shim — reads across all day files up to limit, newest first
function readHistory(limit = 1000) {
  const dates = listDates();
  const results = [];
  for (const d of dates) {
    const entries = readDay(d);
    results.push(...entries);
    if (results.length >= limit) break;
  }
  return results.slice(0, limit);
}

module.exports = { appendHistory, readHistory, readDay, listDates };
