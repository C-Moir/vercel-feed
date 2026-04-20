'use strict';

// Each platform that gets free subdomain hosting and shows up in CT logs.
// ciPreviewRe - patterns that indicate automated/CI deploys, not real deployments
// internalRe  - platform's own infrastructure subdomains
// ingestion   - how per-deployment hostnames become visible to this tool:
//   'ct-log'     — cert per deployment lands in CT logs (Nimbus/Argon/Xenon)
//   'events-api' — GitHub Events API is the primary source
//   'wildcard'   — platform issues a single *.domain wildcard. No public firehose
//                  exists for individual deployment names. Listed for completeness
//                  but the UI should mark these as "no live feed".
// crtshSupplement - true if crt.sh returns useful per-deployment rows for this
//   platform (verified by hand). False means crt.sh either 404s, 502s, or only
//   returns wildcards — not worth polling.
const PLATFORMS = [
  {
    name: 'Vercel',
    domain: 'vercel.app',
    color: '#e0e0e0',
    ingestion: 'wildcard',
    crtshSupplement: false,
    ciPreviewRe: /^([a-z0-9]+-)*[a-z0-9]+-[a-z0-9]{6,}-[a-z0-9]+\.vercel\.app$/,
    internalRe: /^(api|www|vercel)\.vercel\.app$/,
  },
  {
    name: 'Netlify',
    domain: 'netlify.app',
    color: '#00ad9f',
    ingestion: 'wildcard',
    crtshSupplement: false,
    ciPreviewRe: /^deploy-preview-\d+--[^.]+\.netlify\.app$/,
    internalRe: /^(app|www|api|staging)\.netlify\.app$/,
  },
  {
    name: 'CF Pages',
    domain: 'pages.dev',
    color: '#f6821f',
    ingestion: 'ct-log',
    crtshSupplement: false,
    // branch previews are <hash>.<project>.pages.dev (two subdomain levels)
    ciPreviewRe: /^[a-f0-9]+\.[^.]+\.pages\.dev$/,
    internalRe: /^(www|dash|workers|api)\.pages\.dev$/,
  },
  {
    name: 'Render',
    domain: 'onrender.com',
    color: '#46e3b7',
    ingestion: 'ct-log',
    crtshSupplement: true,   // verified: crt.sh returns real per-deployment rows
    ciPreviewRe: /^pr-\d+-[^.]+\.onrender\.com$/,
    internalRe: /^(www|api|dashboard|app|docs)\.onrender\.com$/,
  },
  {
    name: 'GitHub',
    domain: 'github.io',
    color: '#9b59b6',
    ingestion: 'events-api',
    crtshSupplement: false,
    ciPreviewRe: null,
    internalRe: /^(www|pages|api|skills)\.github\.io$/,
  },
  {
    name: 'Glitch',
    domain: 'glitch.me',
    color: '#3333ff',
    ingestion: 'wildcard',
    crtshSupplement: false,
    ciPreviewRe: null,
    internalRe: /^(www|api|cdn|help|support)\.glitch\.me$/,
  },
  {
    name: 'Replit',
    domain: 'replit.app',
    color: '#f26207',
    ingestion: 'ct-log',
    crtshSupplement: true,   // verified: crt.sh returns real per-deployment rows
    ciPreviewRe: null,
    internalRe: /^(www|api|dev)\.replit\.app$/,
  },
  {
    name: 'Surge',
    domain: 'surge.sh',
    color: '#6bbe3f',
    ingestion: 'wildcard',
    crtshSupplement: false,
    ciPreviewRe: null,
    internalRe: /^(www|surge)\.surge\.sh$/,
  },
  {
    name: 'Deno',
    domain: 'deno.dev',
    color: '#70ffaf',
    ingestion: 'ct-log',
    crtshSupplement: true,   // Let's Encrypt per deployment; try crt.sh for coverage
    ciPreviewRe: null,
    internalRe: /^(www|dash|api|fresh|docs|subhosting|.*\.subhosting|gcp\..*)\.deno\.dev$/,
  },
  {
    name: 'Railway',
    domain: 'railway.app',
    color: '#a855f7',
    ingestion: 'ct-log',
    crtshSupplement: true,   // Let's Encrypt per deployment; try crt.sh for coverage
    ciPreviewRe: null,
    internalRe: /^(www|app|docs|help|blog)\.railway\.app$/,
  },
  {
    name: 'Fly.io',
    domain: 'fly.dev',
    color: '#7b2bf9',
    ingestion: 'ct-log',
    crtshSupplement: false,  // crt.sh 404s on %.fly.dev — rely on CT logs only
    ciPreviewRe: null,
    internalRe: /^(www|fly|api|dash|registry|community)\.fly\.dev$/,
  },
  {
    name: 'Workers',
    domain: 'workers.dev',
    color: '#f6821f',
    ingestion: 'ct-log',
    crtshSupplement: false,
    ciPreviewRe: null,
    internalRe: /^(www|dash|api)\.workers\.dev$/,
  },
];

// Build a lookup map for fast hostname → platform resolution
const DOMAIN_MAP = new Map(PLATFORMS.map(p => [p.domain, p]));

function getPlatform(hostname) {
  if (!hostname) return null;
  // Walk from the longest possible suffix match
  for (const p of PLATFORMS) {
    if (hostname === p.domain || hostname.endsWith('.' + p.domain)) return p;
  }
  return null;
}

function isValidDeployment(hostname) {
  if (!hostname) return false;
  const p = getPlatform(hostname);
  if (!p) return false;
  // Root domain itself is never a user deployment
  if (hostname === p.domain) return false;
  if (p.internalRe?.test(hostname)) return false;
  if (p.ciPreviewRe?.test(hostname)) return false;
  return true;
}

module.exports = { PLATFORMS, getPlatform, isValidDeployment };
