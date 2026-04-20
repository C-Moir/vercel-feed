'use strict';

const MAX_DOM_BYTES = 1_000_000;
const DOM_FETCH_TIMEOUT_MS = 5_000;

function extractFromUrlscan(result) {
  return {
    title: result?.page?.title || null,
    description: result?.page?.description || null,
    favicon: null // populated by fetchFavicon
  };
}

function buildFaviconUrl(url) {
  return `${new URL(url).origin}/favicon.ico`;
}

async function fetchFavicon(url) {
  try {
    const res = await fetch(buildFaviconUrl(url), {
      method: 'HEAD',
      signal: AbortSignal.timeout(3_000)
    });
    return res.ok ? buildFaviconUrl(url) : null;
  } catch (_) {
    return null;
  }
}

// Direct HTML fetch for clean-path fingerprinting. Caps body size so a 1GB
// response can't swallow worker memory. Returns { dom, headers, status } —
// dom is '' for non-HTML responses, errors, or timeouts. status 0 = network error.
async function fetchDom(url) {
  try {
    const res = await fetch(url, {
      signal: AbortSignal.timeout(DOM_FETCH_TIMEOUT_MS),
      redirect: 'follow',
      headers: { 'User-Agent': 'deployment-feed/1.0 (+https://github.com/C-Moir/deployment-feed)' },
    });
    const headers = {};
    for (const [k, v] of res.headers) headers[k.toLowerCase()] = v;
    const ct = headers['content-type'] || '';
    if (!res.ok || !ct.includes('text/html')) {
      if (res.body && typeof res.body.cancel === 'function') await res.body.cancel().catch(() => {});
      return { dom: '', headers, status: res.status };
    }
    const reader = res.body.getReader();
    const chunks = [];
    let total = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > MAX_DOM_BYTES) { await reader.cancel(); break; }
      chunks.push(value);
    }
    return { dom: Buffer.concat(chunks).toString('utf8'), headers, status: res.status };
  } catch (_) {
    return { dom: '', headers: {}, status: 0 };
  }
}

function extractTitle(html) {
  if (!html) return null;
  const m = html.match(/<title[^>]*>([\s\S]{0,300}?)<\/title>/i);
  return m ? m[1].replace(/\s+/g, ' ').trim() || null : null;
}

function extractMetaDescription(html) {
  if (!html) return null;
  const m = html.match(/<meta\s+[^>]*name=["']description["'][^>]+content=["']([^"']{0,500})["']/i)
        || html.match(/<meta\s+[^>]*content=["']([^"']{0,500})["'][^>]+name=["']description["']/i);
  return m ? m[1].trim() || null : null;
}

module.exports = {
  extractFromUrlscan,
  buildFaviconUrl,
  fetchFavicon,
  fetchDom,
  extractTitle,
  extractMetaDescription,
};
