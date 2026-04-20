// lib/scanner.js
'use strict';

const URLHAUS_API = 'https://urlhaus-api.abuse.ch/v1/host/';
const URLSCAN_SUBMIT = 'https://urlscan.io/api/v1/scan/';
const URLSCAN_RESULT = 'https://urlscan.io/api/v1/result/';
const POLL_INTERVAL_MS = 5_000;
const POLL_TIMEOUT_MS = 30_000;

// First-party boundary for a scan result: the page's own domain and its subdomains.
// Previously this was hardcoded to 'vercel.app', which meant every Netlify/CF/etc
// asset got classified as a third-party "redirect domain".
function isFirstParty(hostname, pageDomain) {
  if (!hostname || !pageDomain) return false;
  return hostname === pageDomain || hostname.endsWith('.' + pageDomain);
}

async function checkUrlhaus(url) {
  try {
    const hostname = new URL(url).hostname;
    const res = await fetch(URLHAUS_API, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `host=${encodeURIComponent(hostname)}`,
      signal: AbortSignal.timeout(5_000)
    });
    if (!res.ok) return { flagged: false };
    const data = await res.json();
    const flagged = data.query_status === 'is_host' &&
      data.urls?.some(u => u.url_status === 'online');
    return { flagged: !!flagged };
  } catch (_) {
    return { flagged: false };
  }
}

async function submitUrlscan(url, apiKey) {
  try {
    const headers = { 'Content-Type': 'application/json' };
    if (apiKey) headers['API-Key'] = apiKey;
    const res = await fetch(URLSCAN_SUBMIT, {
      method: 'POST',
      headers,
      body: JSON.stringify({ url, visibility: 'public' }),
      signal: AbortSignal.timeout(10_000)
    });
    if (!res.ok) return null;
    const data = await res.json();
    return data.uuid || null;
  } catch (_) {
    return null;
  }
}

async function pollUrlscan(uuid) {
  const deadline = Date.now() + POLL_TIMEOUT_MS;
  while (Date.now() < deadline) {
    await new Promise(r => setTimeout(r, POLL_INTERVAL_MS));
    try {
      const res = await fetch(`${URLSCAN_RESULT}${uuid}/`, {
        signal: AbortSignal.timeout(10_000)
      });
      if (res.status === 404) continue;
      if (!res.ok) return null;
      return await res.json();
    } catch (_) {}
  }
  return null;
}

function extractScanData(result) {
  if (!result) return null;
  const score = result.verdicts?.overall?.score ?? 0;
  const malicious = result.verdicts?.overall?.malicious === true;
  const screenshot = result.screenshot || null;
  const requests = result.data?.requests || [];
  const pageDomain = result.page?.domain || null;

  // Only report C2 IPs when URLScan's own verdict says the scan is malicious.
  // Previously this listed every non-Vercel remote IP, which for a multi-platform
  // tool meant every CDN (Cloudflare, Fastly, Google Fonts, analytics) got reported
  // as C2 and — if ABUSEIPDB_KEY was set — auto-reported to AbuseIPDB. Catastrophic
  // false positive rate, hence the shift to verdict-gated reporting.
  const c2Ips = [];
  if (malicious) {
    for (const req of requests) {
      const ip = req.response?.remoteAddress?.split(':')[0];
      if (ip && !c2Ips.includes(ip)) c2Ips.push(ip);
    }
  }

  const redirectDomains = [];
  const scriptSources = [];
  for (const req of requests) {
    const reqUrl = req.request?.url;
    if (!reqUrl) continue;
    try {
      const u = new URL(reqUrl);
      if (isFirstParty(u.hostname, pageDomain)) continue;
      if (/\.(js|mjs)(\?|$)/.test(reqUrl)) {
        if (!scriptSources.includes(u.hostname)) scriptSources.push(u.hostname);
      } else {
        if (!redirectDomains.includes(u.hostname)) redirectDomains.push(u.hostname);
      }
    } catch (_) {}
  }

  return {
    score,
    malicious,
    screenshot,
    c2Ips,
    redirectDomains,
    scriptSources,
    urlscanId: result.task?.uuid,
    title: result.page?.title || null,
    description: result.page?.description || null
  };
}

module.exports = { checkUrlhaus, submitUrlscan, pollUrlscan, extractScanData, isFirstParty };
