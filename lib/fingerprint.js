// lib/fingerprint.js
'use strict';
const { AI_TOOLS, FRAMEWORKS, CONTENT_CATEGORIES } = require('../fingerprints.js');

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

// Detect content categories from page text (dom) and meta (title + description).
// Returns array of tag strings, e.g. ['crypto', 'ai-app'], or null if none matched.
function detectContentTags(dom, meta) {
  const text = [
    dom || '',
    meta?.title || '',
    meta?.description || '',
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

module.exports = { detectAiTool, detectFramework, detectContentTags };
