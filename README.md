# deployment-feed

Real-time feed of TLS cert activity on free hosting platforms, pulled from Certificate Transparency logs.

A TLS cert issuance or renewal hits a public CT log within seconds. This tool polls three CT logs, extracts hostnames that belong to free hosting platforms, and shows them in a live feed, a 3D galaxy map, and a date-tabbed archive. Each hostname is cross-checked against crt.sh to tell genuinely new deployments apart from 90-day Let's Encrypt renewals.

![License: MIT](https://img.shields.io/badge/license-MIT-blue)

## What it actually shows

Every TLS cert issued for a covered hostname. That's a mix of:

- First-time certs for brand new deployments
- 90-day renewals of sites that have been up for a while (most LE-backed platforms)
- Reissues when configs change

Cards are labelled `new` or `renewal` via a crt.sh lookup per hostname, so you can filter for genuinely new deployments with the `🆕 New only` chip.

## Platforms covered

**Tracked (per-deployment certs land in CT logs):**

| Platform | Domain | Primary source |
|---|---|---|
| Cloudflare Pages | `*.pages.dev` | CT log (Nimbus) |
| Cloudflare Workers | `*.workers.dev` | CT log (Nimbus) |
| Render | `*.onrender.com` | CT log + crt.sh supplement |
| Replit | `*.replit.app` | CT log + crt.sh supplement |
| Deno Deploy | `*.deno.dev` | CT log + crt.sh supplement |
| Railway | `*.railway.app` | CT log + crt.sh supplement |
| Fly.io | `*.fly.dev` | CT log only (crt.sh 404s) |
| GitHub Pages | `*.github.io` | GitHub Events API |

**Not tracked (wildcard certs only, no public firehose):**

- Vercel (`*.vercel.app`)
- Netlify (`*.netlify.app`)
- Glitch (`*.glitch.me`)
- Surge (`*.surge.sh`)

These platforms issue a single wildcard cert per domain. Individual deployment hostnames never appear in CT logs. Pulling them would need per-user API tokens, which this tool doesn't require.

Volume skews heavily toward Cloudflare because Nimbus (CF's own CT log) polls every 10s. Low-volume platforms like Fly.io may show only a handful of hits per hour.

## Install

```bash
git clone https://github.com/C-Moir/deployment-feed
cd deployment-feed
npm install
npx playwright install chromium   # optional, local screenshots
node index.js
```

Open http://localhost:3000.

## Configuration

Everything is optional. The feed works without any env vars; each one unlocks an extra capability.

| Variable | What it does |
|---|---|
| `URLSCAN_KEY` | Lets the tool escalate suspicious hostnames to URLScan's sandbox. Free at urlscan.io. |
| `GITHUB_TOKEN` | Lifts GitHub Events polling from 60 to 5000 req/hr. Classic token, no scopes. |
| `UPSTASH_REDIS_URL` and `UPSTASH_REDIS_TOKEN` | Consensus abuse reporting across instances. |
| `WEBHOOK_URL` | Discord/Slack notifications for flagged deployments. |
| `ABUSEIPDB_KEY` | Reserved. Auto-reporting is currently disabled (see Known limitations). |

Copy `.env.example` to `.env` and fill in what you want.

## How it works

Three Certificate Transparency logs are polled in parallel:

- Cloudflare Nimbus 2026 every 10s. Primary source for `*.pages.dev` and `*.workers.dev`.
- Google Argon 2026h1 every 30s. Broader coverage including Let's Encrypt issuance.
- Google Xenon 2026h1 every 30s. EU-issued certs plus LE redundancy.

Hostnames matching a tracked platform are pushed onto a queue. Workers pull from the queue, run a fast URLhaus check, fetch the live page's HTML for framework + AI tool + content fingerprinting, take a Playwright screenshot for clean sites, or escalate to a URLScan sandbox scan for suspicious ones. URLScan is only called on URLhaus hits or hostnames with phishing-shaped keywords (wallet, login, verify, etc.) so free-tier credits last.

A separate rotation polls crt.sh for Render, Replit, Deno and Railway every few minutes as a supplement. Platforms where crt.sh isn't useful (Fly.io 404s, wildcards return nothing) are skipped so the cycle stays tight.

GitHub Pages is handled separately via the GitHub Events API - it catches `PageBuildEvent` transitions to `built` status.

## Routes

| Route | Description |
|---|---|
| `/` | Live feed with status, content, and new-only filters |
| `/map` | 3D galaxy map, one planet per tracked platform |
| `/history` | Date-tabbed archive with hover screenshot preview |
| `/rss` | RSS of flagged and suspicious deployments |
| `/events` | Raw SSE stream |
| `/api/stats` | Platform, framework, and AI tool breakdown |
| `/api/history` | JSON of today's deployments |
| `/api/history?date=YYYY-MM-DD` | JSON of a specific day |
| `/api/history/dates` | List of available day keys |

## Content tags

Each card is tagged based on page title, meta description, fetched HTML, and the hostname itself:

| Tag | Detected from |
|---|---|
| 🪙 Crypto/Web3 | crypto, defi, nft, wallet, blockchain, ledger, solana, etc. |
| 🤖 AI App | ai chat, chatbot, llm, gpt, claude, etc. |
| 🛍️ E-commerce | shop, buy now, add to cart, checkout, shipping |
| 🎮 Game | game, play now, arcade, leaderboard |
| 🔧 SaaS/Tool | dashboard, analytics, api, subscription |
| 🎨 Portfolio | portfolio, hire me, case studies |
| 📰 Blog/Media | blog, article, podcast, newsletter |
| 🔞 Adult | explicit content keywords |
| 🏗️ Template | starter, boilerplate, hello world, coming soon |

Tag accuracy depends on what the deployment actually serves. SPAs that hydrate client-side often have bare DOM shells, so tags lean on the hostname and meta tags more than page text.

## Known limitations

- **Wildcard platforms aren't covered.** Vercel, Netlify, Glitch and Surge don't expose individual deployments publicly. This isn't going to change without per-user API tokens.
- **Low-volume platforms surface slowly.** Fly.io, Deno Deploy and Railway issue a modest number of LE certs per day globally. Expect sparse activity on those planets.
- **Framework / AI tool detection is signature-based.** If a site doesn't advertise itself in HTML, it gets tagged `Static`. Most AI-generated sites don't leave any trace.
- **URLScan is escalation-only.** Free tier is about 2 scans/min. Running URLScan on every clean deployment would back the queue up for hours, so it runs only on URLhaus hits or hostnames with phishing-shaped keywords.
- **AbuseIPDB auto-reporting is disabled.** The previous extractor treated every non-Vercel remote IP as C2, which would have mass-reported CDN operators. Needs real verdict-based filtering before it's safe to re-enable.
- **`new` vs `renewal` is a best-effort classification.** Based on crt.sh returning only one cert ever for a hostname. If crt.sh times out or 502s, the card shows `unknown`.

## Is this legal

CT logs are public infrastructure operated by Google, Cloudflare, DigiCert and others. Every TLS cert issued globally is published there by design - it's a security requirement, not optional. This tool reads that stream.

Page content is fetched directly for clean sites (bog standard HTTP GET) and via URLScan's sandbox for anything suspicious or flagged. The tool never follows links on flagged deployments.

## Responsible use

- Don't use the abuse reporting feature to harass legitimate deployments.
- Don't hammer crt.sh beyond the built-in rate limits and backoff.
- Report genuine abuse through the sandboxed URLScan links, not by visiting flagged sites directly.
- If you find a security issue on a deployment you discovered here, follow responsible disclosure.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) to add AI tool, framework, or content tag signatures.

## Licence

MIT - see [LICENCE](./LICENCE).
