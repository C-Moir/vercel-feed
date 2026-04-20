// lib/fingerprint.js
'use strict';
const { AI_TOOLS, FRAMEWORKS, CONTENT_CATEGORIES } = require('../fingerprints.js');
const { PRIORITY_KEYWORDS } = require('./queue.js');

function detectAiTool(html) {
  if (!html) return null;
  for (const { name, pattern } of AI_TOOLS) {
    if (pattern.test(html)) return name;
  }
  return null;
}

function detectFramework(html, headers = {}) {
  for (const f of FRAMEWORKS) {
    if (f.headerKey && f.headerVal) {
      if (f.headerVal.test(headers[f.headerKey] || '')) return f.name;
    }
    if (f.htmlPattern && html && f.htmlPattern.test(html)) return f.name;
  }
  return 'Static';
}

// Detect content categories from page text (dom), meta (title + description), and hostname.
// Hostname is included so a bare, empty DOM (e.g. SPA shell before JS hydrates) still gets tagged
// when the hostname itself is a strong signal (e.g. ledger-wallet.pages.dev).
// Returns array of tag strings, e.g. ['crypto', 'ai-app'], or null if none matched.
function detectContentTags(dom, meta, hostname = '') {
  const text = [
    dom || '',
    meta?.title || '',
    meta?.description || '',
    hostname || '',
  ].join(' ');

  if (!text.trim()) return null;

  const tags = [];
  for (const cat of CONTENT_CATEGORIES) {
    if (cat.patterns.some(p => p.test(text))) {
      tags.push(cat.tag);
    }
  }
  return tags.length ? tags : null;
}

// Hostname-based suspicion. Reuses the same keyword list as queue priority ordering
// so we have one source of truth for "this name smells off".
function detectSuspiciousHostname(hostname) {
  if (!hostname) return null;
  const lower = hostname.toLowerCase();
  const matches = PRIORITY_KEYWORDS.filter(kw => lower.includes(kw));
  return matches.length ? matches : null;
}

module.exports = {
  detectAiTool,
  detectFramework,
  detectContentTags,
  detectSuspiciousHostname,
};
