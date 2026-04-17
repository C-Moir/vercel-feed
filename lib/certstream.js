// lib/certstream.js
'use strict';
const WebSocket = require('ws');

const CERTSTREAM_URL = 'wss://certstream.calidog.io';
const CRTSH_URL = 'https://crt.sh/?q=%.vercel.app&output=json';
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
  return certData.data.leaf_cert.all_domains.filter(h => {
    if (!isValidDeployment(h)) return false;
    if (seen.has(h)) return false;
    seen.add(h);
    return true;
  });
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
      } catch (_) {}
    });

    ws.on('error', () => {});

    ws.on('close', () => {
      startFallback();
      const next = Math.min(retryDelay * 2, 60_000);
      console.log(`[certstream] closed - retry in ${retryDelay}ms`);
      setTimeout(() => { retryDelay = next; tryConnect(); }, retryDelay);
    });
  }

  tryConnect();
}

async function pollCrtSh(queue, onNew) {
  try {
    const res = await fetch(CRTSH_URL, { signal: AbortSignal.timeout(10_000) });
    if (!res.ok) return;
    const certs = await res.json();
    for (const cert of certs) {
      const hostname = cert.name_value?.trim().replace(/^\*\./, '');
      if (hostname && isValidDeployment(hostname)) {
        const entry = queue.push(hostname);
        if (entry) onNew(entry);
      }
    }
  } catch (_) {}
}

module.exports = { connect, pollCrtSh, isValidDeployment, extractHostnames };
