# vercel-feed

Live feed of Vercel deployments as they happen - with security scanning, AI tool detection, and crowd-sourced abuse reporting.

## What it does

- Streams new deployments in real-time via certificate transparency logs
- Scans for malware (URLhaus + URLScan.io)
- Detects which AI tool built it (v0, Bolt, Lovable, Cursor, Windsurf)
- Live AI tool leaderboard
- Extracts C2 infrastructure from malicious deployments
- Crowd-sourced abuse reporting to Vercel (requires Upstash)
- Discord/Slack webhook alerts for flagged deployments
- RSS feed of flagged deployments

## Is this legal?

Certificate Transparency logs are public infrastructure. Every TLS cert issued globally is logged publicly by design. This tool reads that data. All page content is fetched via URLScan.io's sandboxed environment - the tool never connects to deployment URLs directly.

## Verify this package

Every release is cryptographically signed via npm provenance attestation:

    npm audit signatures vercel-feed

This confirms the published package matches the exact GitHub commit it was built from.

## Install

    git clone https://github.com/C-Moir/vercel-feed
    cd vercel-feed
    npm install
    node index.js

Or without cloning:

    npx vercel-feed

## Setup (progressive)

| Step | What it unlocks |
|------|----------------|
| node index.js | Live feed, no scanning |
| URLSCAN_KEY | Real-time scanning (free at urlscan.io) |
| npx playwright install chromium | Local screenshots |
| Upstash credentials | Consensus abuse reporting |
| ABUSEIPDB_KEY | Automatic C2 IP reporting |
| WEBHOOK_URL | Discord/Slack flagged alerts |

Copy `.env.example` to `.env` and fill in what you want.

## RSS

Subscribe to flagged deployments: `http://localhost:3000/rss`

## Contributing

See CONTRIBUTING.md to add AI tool signatures.
