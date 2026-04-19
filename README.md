# deploy-feed

A real-time live ledger of new deployments across 12 free hosting platforms — with security scanning, AI tool detection, a 3D interactive map, and crowd-sourced abuse reporting.

![License: MIT](https://img.shields.io/badge/license-MIT-blue)

## What it does

- **Real-time** - polls Google and Cloudflare Certificate Transparency logs every 10s. New deployments appear within seconds of their TLS cert being issued
- **12 platforms** - Vercel, Netlify, Cloudflare Pages, Cloudflare Workers, Render, GitHub Pages, Glitch, Replit, Surge, Deno Deploy, Railway, Fly.io
- **Security scanning** - URLhaus fast check + URLScan.io deep scan. Flagged sites are never directly linked
- **AI tool detection** - detects v0, Bolt, Lovable, Cursor, Windsurf, Replit Agent and more from page fingerprints
- **3D galaxy map** - interactive Three.js visualization of deployments as they appear. Each platform is a planet with its own orbital ring of deployments. Click a planet to focus and browse its deployments
- **History page** - dense log of all seen deployments with hover screenshot preview
- **Safety first** - flagged and suspicious sites only link to URLScan sandbox results, never the live site
- **RSS feed** - subscribe to flagged deployments
- **Webhook alerts** - Discord/Slack notifications for flagged deployments

## Screenshots

| Live feed | 3D Map |
|-----------|--------|
| Cards appear as certs are issued | Planets with orbital deployment rings |

## How it works

Certificate Transparency logs are public infrastructure — every TLS cert issued globally is logged by design. When a new deployment goes live, the platform provisions a cert. That cert hits a CT log within seconds. This tool reads those logs continuously.

For platforms that issue per-deployment certs (Cloudflare Pages, Workers, Render, Railway, Fly.io, Replit) this gives genuine real-time detection. For platforms using wildcard certs (Vercel, Netlify, GitHub Pages) the feed relies on crt.sh polling when available.

## Install

```bash
git clone https://github.com/C-Moir/deployment-feed
cd deploy-feed
npm install
npx playwright install chromium   # for screenshots
node index.js
```

Open `http://localhost:3000`

## Setup

Progressive — each step unlocks more features. Nothing is required to start.

| What to add | What it unlocks |
|-------------|----------------|
| `node index.js` | Live feed with CT log detection |
| `URLSCAN_KEY` | Full security scanning (free at urlscan.io) |
| `npx playwright install chromium` | Local screenshots of clean sites |
| `UPSTASH_REDIS_URL` + `UPSTASH_REDIS_TOKEN` | Consensus abuse reporting |
| `ABUSEIPDB_KEY` | Automatic C2 IP reporting to AbuseIPDB |
| `WEBHOOK_URL` | Discord/Slack alerts for flagged deployments |

Copy `.env.example` to `.env` and add what you want.

## Routes

| Route | Description |
|-------|-------------|
| `/` | Live feed with filters |
| `/map` | 3D interactive galaxy map |
| `/history` | Full deployment log with hover previews |
| `/rss` | RSS feed of flagged deployments |
| `/events` | SSE stream (raw) |
| `/api/stats` | JSON stats |
| `/api/history` | JSON history |

## Is this legal?

CT logs are public infrastructure operated by Google, Cloudflare, DigiCert and others. Every TLS cert issued globally is logged publicly by design — this is a security requirement, not optional. This tool reads that data.

Page content is scanned via URLScan.io's sandboxed environment. The tool never directly fetches flagged or suspicious deployment URLs.

## Responsible Use

This tool reads public infrastructure. A few things worth being clear about:

**What it does:** Reads TLS certificate metadata from public CT logs. Scans URLs via URLScan.io's sandboxed environment. Never visits flagged sites directly.

**What it doesn't do:** Scrape private data, access anything behind auth, or store personal information. Every cert this reads was already publicly logged before this tool existed.

**What you should do:**
- Don't use the abuse reporting feature to harass legitimate deployments
- Don't automate requests to crt.sh beyond the built-in rate limits
- Report genuine abuse through the tool's URLScan links, not by directly accessing flagged sites
- If you find a security vulnerability in a deployment you discover here, follow responsible disclosure

CT log monitoring is standard practice in security research. This tool makes it accessible.

## Contributing

See CONTRIBUTING.md to add AI tool or framework detection signatures.

## Licence

MIT - see [LICENCE](./LICENCE)
