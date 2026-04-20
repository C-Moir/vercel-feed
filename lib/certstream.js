// lib/certstream.js
// Primary source: direct CT log polling (Google/Cloudflare) — works for CF Pages, Workers, etc.
// Supplement: crt.sh polling — catches Vercel/Netlify/GitHub which use wildcard certs
'use strict';

const { X509Certificate } = require('crypto');
const fs = require('node:fs');
const path = require('node:path');
const { PLATFORMS, isValidDeployment } = require('./platforms.js');

const STATE_FILE = path.join(__dirname, '..', '.crtsh-state.json');
const POLL_INTERVAL_MS = 10_000;  // CT log polling interval
const BATCH_SIZE = 256;

// CT logs — Google Argon/Xenon + Cloudflare Nimbus 2026.
// LE (used by Render/Railway/Fly.io/Deno) submits to all three.
// Nimbus also gets CF's own certs but the 3D map caps nodes per planet
// so visual balance is handled at the display layer, not the data layer.
const CT_LOGS = [
  'https://ct.googleapis.com/logs/us1/argon2026h1',
  'https://ct.googleapis.com/logs/eu1/xenon2026h1',
  'https://ct.cloudflare.com/logs/nimbus2026',
];

// crt.sh supplement — all platforms, not just wildcard ones.
// CT log sampling misses low-volume platforms (Render, Railway, Fly.io, Deno)
// because there are so few deployments per hour vs global cert volume.
// crt.sh lets us query SPECIFICALLY for %.onrender.com etc — guaranteed coverage.
// 2 minutes per platform, 12 platforms = full cycle every ~24 minutes.
const CRTSH_PLATFORMS = PLATFORMS; // all 12
const CRTSH_POLL_MS = 2 * 60_000; // one platform every 2 minutes

// Persisted state: CT log cursors + crt.sh cursors together
let state = {};
try {
  state = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));
} catch (_) {}

// Backwards compat: old state files just had CT log cursors at top level
let logState    = state.logs    || state; // CT log tree positions
let crtshCursors = state.crtsh  || {};    // crt.sh max cert ID per domain

// If it looks like the old flat format (no .logs key), treat the whole thing as logState
if (state.logs === undefined && Object.values(state).some(v => typeof v === 'number' && v > 1_000_000)) {
  logState = state;
  crtshCursors = {};
}

console.log(`[ct] resuming state for ${Object.keys(logState).length} log(s), ${Object.keys(crtshCursors).length} crt.sh cursor(s)`);

function saveState() {
  try {
    fs.writeFileSync(STATE_FILE, JSON.stringify({ logs: logState, crtsh: crtshCursors }));
  } catch (_) {}
}

async function fetchJson(url) {
  const res = await fetch(url, { signal: AbortSignal.timeout(20_000) });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

function extractHostnames(leafInputB64) {
  const buf = Buffer.from(leafInputB64, 'base64');
  // MerkleTreeLeaf: 1 version + 1 leaf_type + 8 timestamp + 2 entry_type = 12 bytes
  const entryType = buf.readUInt16BE(10);

  let certDer;
  if (entryType === 0) {
    // x509_entry: 3-byte length then DER cert
    const len = (buf[12] << 16) | (buf[13] << 8) | buf[14];
    certDer = buf.slice(15, 15 + len);
  } else {
    // precert_entry: skip 32-byte issuer_key_hash + 3-byte len
    const len = (buf[45] << 16) | (buf[46] << 8) | buf[47];
    certDer = buf.slice(48, 48 + len);
  }

  try {
    const cert = new X509Certificate(certDer);
    const san = cert.subjectAltName || '';
    return san
      .split(', ')
      .map(s => s.replace(/^DNS:/, '').trim().replace(/^\*\./, ''))
      .filter(h => h && isValidDeployment(h));
  } catch (_) {
    return [];
  }
}

async function pollLog(logUrl, queue, onNew) {
  const key = logUrl;
  try {
    const sth = await fetchJson(`${logUrl}/ct/v1/get-sth`);
    const treeSize = sth.tree_size;

    if (logState[key] == null) {
      // First run - start near the tip, not from the beginning
      logState[key] = Math.max(0, treeSize - BATCH_SIZE);
      saveState();
      return;
    }

    if (logState[key] >= treeSize) return; // nothing new

    let cursor = logState[key];
    let totalNew = 0;
    const MAX_PER_POLL = BATCH_SIZE * 8; // scan up to ~2000 entries per poll

    while (cursor < treeSize && (cursor - logState[key]) < MAX_PER_POLL) {
      const end = Math.min(cursor + BATCH_SIZE - 1, treeSize - 1);
      const data = await fetchJson(`${logUrl}/ct/v1/get-entries?start=${cursor}&end=${end}`);
      const entries = data.entries || [];
      if (!entries.length) break;

      for (const entry of entries) {
        for (const hostname of extractHostnames(entry.leaf_input)) {
          const qEntry = queue.push(hostname);
          if (qEntry) { onNew(qEntry); totalNew++; }
        }
      }

      cursor += entries.length;
    }

    logState[key] = cursor;
    saveState();

    if (totalNew > 0) console.log(`[ct] ${new URL(logUrl).pathname.split('/').pop()}: +${totalNew} new deployments`);
  } catch (err) {
    console.warn(`[ct] ${logUrl}: ${err.message}`);
  }
}

async function fetchCrtsh(url) {
  // One retry after 5s — crt.sh drops connections occasionally
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(25_000) });
      return res;
    } catch (err) {
      const transient = err.message.includes('fetch failed') ||
                        err.message.includes('timeout') ||
                        err.message.includes('aborted');
      if (!transient || attempt === 1) throw err;
      await new Promise(r => setTimeout(r, 5_000));
    }
  }
}

async function pollCrtsh(platform, queue, onNew) {
  const url = `https://crt.sh/?q=%.${platform.domain}&output=json&exclude=expired`;
  try {
    const res = await fetchCrtsh(url);
    if (res.status === 429) { console.warn(`[crt.sh] rate limited on ${platform.domain}`); return; }
    if (!res.ok) return;
    const certs = await res.json();
    if (!Array.isArray(certs)) return;

    const lastId = crtshCursors[platform.domain] || 0;
    let newMaxId = lastId;
    let found = 0;

    for (const cert of certs) {
      if (cert.id <= lastId) continue;
      if (cert.id > newMaxId) newMaxId = cert.id;
      for (const raw of (cert.name_value || '').split('\n')) {
        const hostname = raw.trim().replace(/^\*\./, '');
        if (hostname && isValidDeployment(hostname)) {
          const entry = queue.push(hostname);
          if (entry) { onNew(entry); found++; }
        }
      }
    }

    if (newMaxId > lastId) { crtshCursors[platform.domain] = newMaxId; saveState(); }
    if (found > 0) console.log(`[crt.sh] ${platform.domain}: +${found} new deployments`);
  } catch (_) {
    // Silently skip — transient network issues. Will retry on next cycle.
  }
}

function connect(queue, onNew) {
  console.log(`[ct] polling ${CT_LOGS.length} CT logs every ${POLL_INTERVAL_MS / 1000}s`);

  // CT log polling — staggered start
  CT_LOGS.forEach((log, i) => {
    setTimeout(() => {
      pollLog(log, queue, onNew);
      setInterval(() => pollLog(log, queue, onNew), POLL_INTERVAL_MS);
    }, i * 3_000);
  });

  // crt.sh supplement — all 12 platforms, one every 2 minutes (~24min full cycle)
  // Guarantees coverage of low-volume platforms that rarely appear in CT log samples
  const cycleMins = Math.round((CRTSH_PLATFORMS.length * CRTSH_POLL_MS) / 60_000);
  console.log(`[crt.sh] polling all ${CRTSH_PLATFORMS.length} platforms (~${cycleMins}min full cycle)`);
  let crtshIdx = 0;
  const crtshTick = () => {
    const platform = CRTSH_PLATFORMS[crtshIdx % CRTSH_PLATFORMS.length];
    crtshIdx++;
    pollCrtsh(platform, queue, onNew);
  };
  setTimeout(crtshTick, 30_000); // first poll 30s after startup
  setInterval(crtshTick, CRTSH_POLL_MS);
}

module.exports = { connect };
