# deployment-feed

A real-time live ledger of new deployments across 12 free hosting platforms - with security scanning, content detection, AI tool fingerprinting, a 3D interactive map, and date-tabbed history.

![License: MIT](https://img.shields.io/badge/license-MIT-blue)

## What it does

- **Real-time** - polls 3 Certificate Transparency logs (Google Argon/Xenon + Cloudflare Nimbus) every 10s, plus the GitHub Events API for GitHub Pages. New deployments appear within seconds
- **12 platforms** - Vercel, Netlify, Cloudflare Pages, Cloudflare Workers, Render, GitHub Pages, Glitch, Replit, Surge, Deno Deploy, Railway, Fly.io
- **Security scanning** - URLhaus fast check + URLScan.io deep scan. Flagged sites are never directly linked, only via URLScan's sandbox
- **Content tagging** - 9 categories detected from page content: Crypto/Web3, AI App, E-commerce, Game, SaaS/Tool, Portfolio, Blog/Media, Adult, Template
- **AI tool detection** - detects v0, Bolt, Lovable, Cursor, Claude, Windsurf and more from page fingerprints
- **Framework detection** - Next.js, Nuxt, SvelteKit, Remix, Astro and more
- **3D galaxy map** - interactive Three.js visualisation. Each platform is a planet with its own orbital ring of deployments. Click a planet to focus and browse
- **24h history with date tabs** - full day-by-day log. Each day stored as a separate NDJSON file, retained indefinitely. Hover any row for a screenshot preview
- **Safety first** - flagged and suspicious sites only ever link to URLScan sandbox results, never the live site
- **RSS feed** - subscribe to flagged deployments
- **Webhook alerts** - Discord/Slack notifications for flagged deployments
- **Session persistence** - main feed survives navigating to the map and back

## How it works

Certificate Transparency logs are public infrastructure - every TLS cert issued globally is logged by design. When a new deployment goes live, the platform provisions a cert. That cert hits a CT log within seconds. This tool reads those logs continuously.

Four CT logs are polled in parallel, staggered to avoid bursts:
- **Google Argon 2026h1** - broad coverage of all CAs globally
- **Google Xenon 2026h1** - redundancy + EU-issued certs
- **Cloudflare Nimbus 2025** - Cloudflare's own CA (fastest for pages.dev, workers.dev) + Let's Encrypt certs
- **Cloudflare Nimbus 2026** - same, active log for 2026 issuances

For platforms that use wildcard certs (Vercel, Netlify, GitHub Pages, Glitch, Surge) where individual deployments don't appear in CT logs, the feed also polls crt.sh as a supplement - one platform every 3 minutes, cycling through all six.

## Install

```bash
git clone https://github.com/C-Moir/deployment-feed
cd deployment-feed
npm install
npx playwright install chromium   # for screenshots
node index.js
```

Open `http://localhost:3000`

## Setup

Progressive - each step unlocks more features. Nothing is required to start.

| What to add | What it unlocks |
|-------------|----------------|
| `node index.js` | Live feed with CT log detection + GitHub Pages |
| `GITHUB_TOKEN` | GitHub Pages polling every 30s instead of 65s (free, no scopes needed) |
| `URLSCAN_KEY` | Full security scanning (free at urlscan.io) |
| `npx playwright install chromium` | Local screenshots of clean sites |
| `UPSTASH_REDIS_URL` + `UPSTASH_REDIS_TOKEN` | Consensus abuse reporting |
| `ABUSEIPDB_KEY` | Automatic C2 IP reporting to AbuseIPDB |
| `WEBHOOK_URL` | Discord/Slack alerts for flagged deployments |

Copy `.env.example` to `.env` and fill in what you want.

## Routes

| Route | Description |
|-------|-------------|
| `/` | Live feed with status and content filters |
| `/map` | 3D interactive galaxy map |
| `/history` | Date-tabbed full history with hover screenshot preview |
| `/rss` | RSS feed of flagged deployments |
| `/events` | Raw SSE stream |
| `/api/stats` | JSON stats |
| `/api/history` | JSON history for today |
| `/api/history?date=YYYY-MM-DD` | JSON history for a specific day |
| `/api/history/dates` | JSON list of all available day keys |

## Content tags

Deployments are tagged by category based on DOM text and meta content:

| Tag | Detected from |
|-----|--------------|
| 🪙 Crypto/Web3 | crypto, defi, nft, wallet, blockchain, token... |
| 🤖 AI App | ai chat, chatbot, llm, gpt, openai, claude... |
| 🛍️ E-commerce | shop, store, add to cart, checkout, shipping... |
| 🎮 Game | game, play now, arcade, leaderboard, multiplayer... |
| 🔧 SaaS/Tool | dashboard, analytics, api, subscription, free trial... |
| 🎨 Portfolio | portfolio, my work, freelance, hire me, resume... |
| 📰 Blog/Media | blog, article, newsletter, podcast, latest post... |
| 🔞 Adult | adult content keywords |
| 🏗️ Template | starter, boilerplate, template, hello world, coming soon... |

Tags are filterable on the main feed and visible in history rows.

## Is this legal?

CT logs are public infrastructure operated by Google, Cloudflare, DigiCert and others. Every TLS cert issued globally is logged publicly by design - this is a security requirement, not optional. This tool reads that data.

Page content is scanned via URLScan.io's sandboxed environment. The tool never directly fetches flagged or suspicious deployment URLs.

## Responsible use

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

See CONTRIBUTING.md to add AI tool, framework, or content tag detection signatures.

## Licence

MIT - see [LICENCE](./LICENCE)
