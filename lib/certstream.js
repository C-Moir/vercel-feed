// lib/certstream.js
'use strict';
const WebSocket = require('ws');

const CERTSTREAM_URL = 'wss://certstream.calidog.io';
const CRTSH_URL = 'https://crt.sh/?q=%.vercel.app&output=json';
const CRTSH_POLL_MS = 60_000;
const CI_PREVIEW_RE = /^([a-z0-9]+-)*[a-z0-9]+-[a-z0-9]{6,}-[a-z0-9]+\.vercel\.app$/;
const INTERNAL_RE = /^(api|www|vercel)\.vercel\.app$/;

function isValidDeployment(hostname) {
  if (!hostname || !hostname.endsWith('.vercel.app')) return false;
  if (INTERNAL_RE.test(hostname)) return false;
  if (CI_PREVIEW_RE.test(hostname)) return false;
  return true;
}

function extractHostnames(certData) {
  if (!certData?.data?.leaf_cert?.all_domains) return [];
  const seen = new Set();
  const results = [];
  for (const raw of certData.data.leaf_cert.all_domains) {
    for (const h of raw.split('\n').map(s => s.trim().replace(/^\*\./, ''))) {
      if (!h || !isValidDeployment(h) || seen.has(h)) continue;
      seen.add(h);
      results.push(h);
    }
  }
  return results;
}

function connect(queue, onNew, retryDelay = 1000) {
  let fallbackInterval = null;

  function startFallback() {
    if (fallbackInterval) return;
    console.log('[certstream] down - switching to crt.sh fallback');
    fallbackInterval = setInterval(() => pollCrtSh(queue, onNew), 60_000);
    pollCrtSh(queue, onNew);
  }

  function stopFallback() {
    if (!fallbackInterval) return;
    clearInterval(fallbackInterval);
    fallbackInterval = null;
    console.log('[certstream] reconnected - stopping crt.sh fallback');
  }

  // Always poll crt.sh regardless of certstream status
  setInterval(() => pollCrtSh(queue, onNew), CRTSH_POLL_MS);
  pollCrtSh(queue, onNew);

  function tryConnect() {
    const ws = new WebSocket(CERTSTREAM_URL);

    ws.on('open', () => {
      retryDelay = 1000;
      stopFallback();
      console.log('[certstream] connected');
    });

    ws.on('message', (data) => {
      try {
        const cert = JSON.parse(data);
        for (const hostname of extractHostnames(cert)) {
          const entry = queue.push(hostname);
          if (entry) onNew(entry);
        }
      } catch (err) {
        if (!(err instanceof SyntaxError)) throw err;
      }
    });

    ws.on('error', (err) => {
      console.error('[certstream] ws error:', err.code || err.message);
    });

    ws.on('close', () => {
      startFallback();
      const next = Math.min(retryDelay * 2, 60_000);
      console.log(`[certstream] closed - retry in ${retryDelay}ms`);
      setTimeout(() => { retryDelay = next; tryConnect(); }, retryDelay);
    });
  }

  tryConnect();
}

let lastSeenCrtShId = 0;

async function pollCrtSh(queue, onNew) {
  try {
    const res = await fetch(CRTSH_URL, { signal: AbortSignal.timeout(30_000) });
    if (!res.ok) return;
    const certs = await res.json();
    if (!Array.isArray(certs)) return;
    // crt.sh returns newest first - stop when we hit already-seen IDs
    let newMaxId = lastSeenCrtShId;
    for (const cert of certs) {
      if (cert.id <= lastSeenCrtShId) break;
      if (cert.id > newMaxId) newMaxId = cert.id;
      for (const raw of (cert.name_value || '').split('\n')) {
        const hostname = raw.trim().replace(/^\*\./, '');
        if (hostname && isValidDeployment(hostname)) {
          const entry = queue.push(hostname);
          if (entry) onNew(entry);
        }
      }
    }
    lastSeenCrtShId = newMaxId;
  } catch (_) {}
}

module.exports = { connect, pollCrtSh, isValidDeployment, extractHostnames };
