'use strict';
const fs = require('node:fs');
const path = require('node:path');

const ROTATE_AT = 1000;
const ARCHIVE_KEEP = 200;
const DEFAULT_FILE = path.join(process.cwd(), 'threat-intel.json');

function readEntries(file = DEFAULT_FILE) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch (_) { return []; }
}

function writeEntry(file = DEFAULT_FILE, entry) {
  let entries = readEntries(file);
  if (entries.length >= ROTATE_AT) {
    const archived = entries.slice(0, ARCHIVE_KEEP);
    const archivePath = file.replace('.json', `-archive-${Date.now()}.json`);
    fs.writeFileSync(archivePath, JSON.stringify(archived, null, 2));
    entries = entries.slice(ARCHIVE_KEEP);
    console.log(`[threat-intel] rotated - archived ${ARCHIVE_KEEP} entries to ${archivePath}`);
  }
  entries.push({ ...entry, timestamp: new Date().toISOString() });
  fs.writeFileSync(file, JSON.stringify(entries, null, 2));
}

async function reportToAbuseIPDB(ip, apiKey) {
  if (!apiKey) return;
  try {
    await fetch('https://api.abuseipdb.com/api/v2/report', {
      method: 'POST',
      headers: {
        'Key': apiKey,
        'Accept': 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: `ip=${encodeURIComponent(ip)}&categories=20&comment=C2+server+identified+via+vercel-feed`,
      signal: AbortSignal.timeout(5_000)
    });
  } catch (_) {}
}

module.exports = { readEntries, writeEntry, reportToAbuseIPDB, ROTATE_AT, ARCHIVE_KEEP, DEFAULT_FILE };
