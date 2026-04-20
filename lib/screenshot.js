'use strict';

let playwrightAvailable = null;
let sharedBrowser = null;
let browserPromise = null;

async function checkPlaywright() {
  if (playwrightAvailable !== null) return playwrightAvailable;
  try {
    require('playwright');
    playwrightAvailable = true;
  } catch (_) {
    playwrightAvailable = false;
    console.log('[screenshot] Playwright not installed. Run: npx playwright install chromium');
  }
  return playwrightAvailable;
}

// Launch chromium once and reuse across workers. Launching per-screenshot
// spawned up to 5 parallel chromium processes on a 5-worker pool, which
// thrashed memory on lower-spec machines and serialised the whole pipeline
// behind browser startup (~1-3s each).
async function getBrowser() {
  if (sharedBrowser && sharedBrowser.isConnected()) return sharedBrowser;
  if (browserPromise) return browserPromise;
  const { chromium } = require('playwright');
  browserPromise = chromium.launch().then(b => {
    sharedBrowser = b;
    b.on('disconnected', () => { sharedBrowser = null; browserPromise = null; });
    browserPromise = null;
    return b;
  }).catch(err => {
    browserPromise = null;
    throw err;
  });
  return browserPromise;
}

async function closeBrowser() {
  if (sharedBrowser) {
    try { await sharedBrowser.close(); } catch (_) {}
    sharedBrowser = null;
  }
}

async function tryPlaywright(url) {
  if (!await checkPlaywright()) return null;
  let page;
  try {
    const browser = await getBrowser();
    page = await browser.newPage();
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 10_000 });
    const buf = await page.screenshot({ type: 'jpeg', quality: 70 });
    return `data:image/jpeg;base64,${buf.toString('base64')}`;
  } catch (_) {
    return null;
  } finally {
    if (page) { try { await page.close(); } catch (_) {} }
  }
}

async function tryMicrolink(url) {
  try {
    const apiUrl = `https://api.microlink.io?url=${encodeURIComponent(url)}&screenshot=true&meta=false`;
    const res = await fetch(apiUrl, { signal: AbortSignal.timeout(10_000) });
    if (!res.ok) return null;
    const data = await res.json();
    return data?.data?.screenshot?.url || null;
  } catch (_) {
    return null;
  }
}

function makePlaceholderSvg(hostname) {
  // hostname comes from our own cert filtering - safe to interpolate but escape anyway
  const safe = hostname.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  return [
    '<svg xmlns="http://www.w3.org/2000/svg" width="640" height="360">',
    '<rect width="640" height="360" fill="#1a1a2e"/>',
    `<text x="320" y="170" font-family="monospace" font-size="14" fill="#6c63ff" text-anchor="middle">${safe}</text>`,
    '<text x="320" y="200" font-family="monospace" font-size="12" fill="#444" text-anchor="middle">preview unavailable</text>',
    '</svg>'
  ].join('');
}

async function getScreenshot(url) {
  const pw = await tryPlaywright(url);
  if (pw) return { screenshot: pw, source: 'playwright' };
  const ml = await tryMicrolink(url);
  if (ml) return { screenshot: ml, source: 'microlink' };
  const hostname = new URL(url).hostname;
  const svg = makePlaceholderSvg(hostname);
  const b64 = Buffer.from(svg).toString('base64');
  return { screenshot: `data:image/svg+xml;base64,${b64}`, source: 'placeholder' };
}

module.exports = { getScreenshot, tryPlaywright, tryMicrolink, makePlaceholderSvg, checkPlaywright, closeBrowser };
