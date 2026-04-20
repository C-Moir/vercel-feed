'use strict';

function esc(str) {
  return (str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function buildRss(entries) {
  const dangerous = entries.filter(e => e.status === 'flagged' || e.status === 'suspicious');
  const items = dangerous.map(e => [
    '    <item>',
    `      <title>${esc(e.hostname)} - ${esc(e.status)}</title>`,
    `      <link>https://urlscan.io/result/${esc(e.scan?.urlscanId)}/</link>`,
    `      <description>Score: ${e.scan?.urlscanScore ?? '?'}/100</description>`,
    `      <pubDate>${new Date(e.timestamp).toUTCString()}</pubDate>`,
    `      <guid>${esc(e.url)}</guid>`,
    '    </item>'
  ].join('\n')).join('\n');

  return [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<rss version="2.0">',
    '  <channel>',
    '    <title>deployment-feed - Flagged Deployments</title>',
    '    <link>http://localhost:3000</link>',
    '    <description>Malicious and suspicious deployments detected across 12 free hosting platforms in real-time</description>',
    items,
    '  </channel>',
    '</rss>'
  ].join('\n');
}

module.exports = { buildRss };
