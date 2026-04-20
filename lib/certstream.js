// lib/certstream.js
// CT log polling: three logs, each with different characteristics.
//   Nimbus  (Cloudflare) — fastest, polls every 10s. CF Pages/Workers dominant.
//   Argon   (Google US)  — broader CA coverage, polls every 30s.
//   Xenon   (Google EU)  — EU-issued certs + LE redundancy, polls every 30s.
// All three carry Let's Encrypt certs (Render/Railway/Fly.io/Deno).
// Those platforms are low-volume so nodes appear slowly — expected behaviour.
// Supplement: crt.sh polling — catches wildcard-cert platforms when service is up.
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { X509Certificate } = require('crypto');
const { PLATFORMS, isValidDeployment } = require('./platforms.js');

const STATE_FILE = path.join(__dirname, '..', '.crtsh-state.json');

const NIMBUS_URL   = 'https://ct.cloudflare.com/logs/nimbus2026';
const ARGON_URL    = 'https://ct.googleapis.com/logs/us1/argon2026h1';
const XENON_URL    = 'https://ct.googleapis.com/logs/eu1/xenon2026h1';

const NIMBUS_INTERVAL = 10_000;  // fast — CF certs land here immediately
const GOOGLE_INTERVAL = 30_000;  // slower — avoids hammering, still timely
const BATCH_SIZE = 256;

// crt.sh supplement — all platforms, one every 2 minutes (~24min full cycle)
const CRTSH_PLATFORMS = PLATFORMS;
const CRTSH_POLL_MS   = 2 * 60_000;

// ─── Persisted state ─────────────────────────────────────────────────────────

let state = {};
try { state = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8')); } catch (_) {}

let logState     = state.logs  || state;
let crtshCursors = state.crtsh || {};

if (state.logs === undefined && Object.values(state).some(v => typeof v === 'number' && v > 1_000_000)) {
  logState = state;
  crtshCursors = {};
}

console.log(`[ct] resuming state for ${Object.keys(logState).length} log(s), ${Object.keys(crtshCursors).length} crt.sh cursor(s)`);

function saveState() {
  try { fs.writeFileSync(STATE_FILE, JSON.stringify({ logs: logState, crtsh: crtshCursors })); } catch (_) {}
}

// ─── CT log polling ───────────────────────────────────────────────────────────

async function fetchJson(url) {
  const res = await fetch(url, { signal: AbortSignal.timeout(30_000) });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

function extractHostnames(leafInputB64) {
  const buf = Buffer.from(leafInputB64, 'base64');
  const entryType = buf.readUInt16BE(10);
  let certDer;
  if (entryType === 0) {
    const len = (buf[12] << 16) | (buf[13] << 8) | buf[14];
    certDer = buf.slice(15, 15 + len);
  } else {
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
  } catch (_) { return []; }
}

async function pollLog(logUrl, label, queue, onNew) {
  const key = logUrl;
  try {
    const sth = await fetchJson(`${logUrl}/ct/v1/get-sth`);
    const treeSize = sth.tree_size;

    if (logState[key] == null) {
      logState[key] = Math.max(0, treeSize - BATCH_SIZE);
      saveState();
      return;
    }
    if (logState[key] >= treeSize) return;

    let cursor = logState[key];
    let totalNew = 0;
    const MAX_PER_POLL = BATCH_SIZE * 8;

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
    if (totalNew > 0) console.log(`[${label}] +${totalNew} new deployments`);
  } catch (err) {
    // Transient timeouts are normal — don't spam the console
    if (!err.message.includes('timeout') && !err.message.includes('aborted')) {
      console.warn(`[${label}] ${err.message}`);
    }
  }
}

// ─── crt.sh supplement ───────────────────────────────────────────────────────

async function fetchCrtsh(url) {
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      return await fetch(url, { signal: AbortSignal.timeout(25_000) });
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
  } catch (_) {}
}

// ─── Entry point ─────────────────────────────────────────────────────────────

function connect(queue, onNew) {
  // Nimbus — Cloudflare's own log, fast. CF Pages/Workers land here immediately.
  console.log(`[nimbus] polling every ${NIMBUS_INTERVAL / 1000}s`);
  setTimeout(() => {
    pollLog(NIMBUS_URL, 'nimbus', queue, onNew);
    setInterval(() => pollLog(NIMBUS_URL, 'nimbus', queue, onNew), NIMBUS_INTERVAL);
  }, 2_000);

  // Argon + Xenon — Google's logs. Broader CA coverage including LE certs.
  // Render/Railway/Fly.io/Deno appear here but infrequently — nodes accumulate over time.
  // 30s interval to avoid hammering; occasional timeouts silently retried next cycle.
  console.log(`[argon/xenon] polling every ${GOOGLE_INTERVAL / 1000}s`);
  setTimeout(() => {
    pollLog(ARGON_URL, 'argon', queue, onNew);
    setInterval(() => pollLog(ARGON_URL, 'argon', queue, onNew), GOOGLE_INTERVAL);
  }, 5_000);
  setTimeout(() => {
    pollLog(XENON_URL, 'xenon', queue, onNew);
    setInterval(() => pollLog(XENON_URL, 'xenon', queue, onNew), GOOGLE_INTERVAL);
  }, 18_000);

  // crt.sh — wildcard platform supplement, recovers automatically when service is up
  const cycleMins = Math.round((CRTSH_PLATFORMS.length * CRTSH_POLL_MS) / 60_000);
  console.log(`[crt.sh] polling all ${CRTSH_PLATFORMS.length} platforms (~${cycleMins}min full cycle)`);
  let crtshIdx = 0;
  const crtshTick = () => {
    pollCrtsh(CRTSH_PLATFORMS[crtshIdx++ % CRTSH_PLATFORMS.length], queue, onNew);
  };
  setTimeout(crtshTick, 30_000);
  setInterval(crtshTick, CRTSH_POLL_MS);
}

module.exports = { connect };
