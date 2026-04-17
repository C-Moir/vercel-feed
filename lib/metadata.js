'use strict';

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

module.exports = { extractFromUrlscan, buildFaviconUrl, fetchFavicon };
