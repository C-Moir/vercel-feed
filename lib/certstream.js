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
// Per-poll cap. Google's logs ingest thousands of certs/minute, so we bump this
// to catch a larger share of Let's Encrypt issuance (Fly/Render/Railway/Deno).
// Previous value was BATCH_SIZE * 8 = 2048 which left us permanently behind.
const MAX_PER_POLL = BATCH_SIZE * 32;  // = 8192

// crt.sh supplement — only platforms where crt.sh actually returns useful data
// (verified by hand: Fly.io 404s, Vercel/Netlify return wildcards only).
// Polling only the relevant 4 gives a full cycle every 8 minutes instead of 24.
const CRTSH_PLATFORMS = PLATFORMS.filter(p => p.crtshSupplement);
const CRTSH_POLL_MS   = 2 * 60_000;

// Exponential backoff for transient crt.sh failures (502/504/429).
// After this many consecutive failures, a platform is paused until cooldown elapses.
const CRTSH_FAIL_THRESHOLD = 3;
const CRTSH_COOLDOWN_MS    = 30 * 60_000;  // 30 min
const crtshFailures = new Map();           // domain → { count, pausedUntil }

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

// crt.sh returns non-JSON bodies on error (HTML 404/502/504), so reading as JSON
// throws. Fetch with backoff on transient failures; treat persistent failures as
// "paused" so the poller stops hammering.
async function fetchCrtsh(url) {
  const backoff = [5_000, 15_000, 45_000];
  for (let attempt = 0; attempt <= backoff.length; attempt++) {
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(25_000) });
      // 502/504 are crt.sh backend errors — retry; 429 is rate limit — retry
      if ((res.status === 502 || res.status === 504 || res.status === 429) && attempt < backoff.length) {
        await new Promise(r => setTimeout(r, backoff[attempt]));
        continue;
      }
      return res;
    } catch (err) {
      const transient = /fetch failed|timeout|aborted/i.test(err.message);
      if (!transient || attempt === backoff.length) throw err;
      await new Promise(r => setTimeout(r, backoff[attempt]));
    }
  }
}

function crtshIsPaused(domain) {
  const entry = crtshFailures.get(domain);
  return !!(entry && entry.pausedUntil && entry.pausedUntil > Date.now());
}

function recordCrtshFailure(domain, reason) {
  const entry = crtshFailures.get(domain) || { count: 0, pausedUntil: 0 };
  entry.count++;
  if (entry.count >= CRTSH_FAIL_THRESHOLD) {
    entry.pausedUntil = Date.now() + CRTSH_COOLDOWN_MS;
    console.warn(`[crt.sh] ${domain} paused for 30min after ${entry.count} consecutive ${reason} errors`);
    entry.count = 0;
  }
  crtshFailures.set(domain, entry);
}

function recordCrtshSuccess(domain) {
  crtshFailures.delete(domain);
}

async function pollCrtsh(platform, queue, onNew) {
  if (crtshIsPaused(platform.domain)) return;

  const url = `https://crt.sh/?q=%.${platform.domain}&output=json&exclude=expired`;
  let res;
  try {
    res = await fetchCrtsh(url);
  } catch (err) {
    recordCrtshFailure(platform.domain, 'network');
    return;
  }

  if (res.status === 404) {
    // Indicates crt.sh doesn't index this domain — no point retrying soon
    recordCrtshFailure(platform.domain, '404');
    return;
  }
  if (!res.ok) {
    recordCrtshFailure(platform.domain, `HTTP ${res.status}`);
    return;
  }

  let certs;
  try {
    certs = await res.json();
  } catch (err) {
    // crt.sh served HTML instead of JSON — count as a failure
    recordCrtshFailure(platform.domain, 'non-JSON');
    return;
  }
  if (!Array.isArray(certs)) {
    recordCrtshFailure(platform.domain, 'unexpected-shape');
    return;
  }

  recordCrtshSuccess(platform.domain);

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

  // crt.sh — supplement for platforms where it actually returns useful data.
  // Platforms without per-deployment cert issuance (wildcard-only) or where
  // crt.sh is unreliable (Fly.io 404s) are excluded to tighten the cycle time.
  if (CRTSH_PLATFORMS.length > 0) {
    const cycleMins = Math.round((CRTSH_PLATFORMS.length * CRTSH_POLL_MS) / 60_000);
    const names = CRTSH_PLATFORMS.map(p => p.name).join(', ');
    console.log(`[crt.sh] polling ${CRTSH_PLATFORMS.length} platforms (${names}) ~${cycleMins}min cycle`);
    let crtshIdx = 0;
    const crtshTick = () => {
      pollCrtsh(CRTSH_PLATFORMS[crtshIdx++ % CRTSH_PLATFORMS.length], queue, onNew);
    };
    setTimeout(crtshTick, 30_000);
    setInterval(crtshTick, CRTSH_POLL_MS);
  }
}

module.exports = { connect };
