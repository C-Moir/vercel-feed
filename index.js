#!/usr/bin/env node
'use strict';
require('dotenv').config({ path: '.env' });

const express = require('express');
const path = require('node:path');

const { JobQueue } = require('./lib/queue.js');
const { connect: connectCertstream } = require('./lib/certstream.js');
const { checkUrlhaus, submitUrlscan, pollUrlscan, extractScanData } = require('./lib/scanner.js');
const { writeEntry, reportToAbuseIPDB } = require('./lib/threat-intel.js');
const { recordAndCheck, buildMailtoLink } = require('./lib/upstash.js');
const { getScreenshot } = require('./lib/screenshot.js');
const { extractFromUrlscan, fetchFavicon } = require('./lib/metadata.js');
const { detectAiTool, detectFramework } = require('./lib/fingerprint.js');
const { Broadcaster } = require('./lib/broadcaster.js');
const { computeStats, detectTrending } = require('./lib/stats.js');
const { sendWebhook } = require('./lib/webhook.js');
const { buildRss } = require('./lib/rss.js');

const PORT = process.env.PORT || 3000;
const URLSCAN_KEY = process.env.URLSCAN_KEY || null;
const ABUSEIPDB_KEY = process.env.ABUSEIPDB_KEY || null;
const WEBHOOK_URL = process.env.WEBHOOK_URL || null;

const queue = new JobQueue();
const broadcaster = new Broadcaster();

async function preflight404(url) {
  try {
    const res = await fetch(url, { method: 'HEAD', signal: AbortSignal.timeout(8_000), redirect: 'follow' });
    return res.status === 404;
  } catch (_) {
    return false;
  }
}

async function processEntry(entry) {
  queue.update(entry.id, { status: 'scanning' });
  broadcaster.broadcast(queue.all.get(entry.id));

  // Skip dead deployments - saves URLScan credits and keeps feed clean
  if (await preflight404(entry.url)) {
    queue.update(entry.id, { status: '404' });
    broadcaster.broadcast(queue.all.get(entry.id));
    return;
  }

  // URLhaus fast check
  const { flagged } = await checkUrlhaus(entry.url);

  if (flagged) {
    const uuid = await submitUrlscan(entry.url, URLSCAN_KEY);
    const result = uuid ? await pollUrlscan(uuid) : null;
    const scan = extractScanData(result);

    const patch = {
      status: 'flagged',
      scan: {
        urlhausFlagged: true,
        urlscanScore: scan?.score ?? 100,
        urlscanId: scan?.urlscanId || uuid,
        urlscanScreenshot: scan?.screenshot || null
      },
      screenshot: scan?.screenshot || null,
      screenshotSource: 'urlscan',
      threatIntel: {
        c2Ips: scan?.c2Ips || [],
        redirectDomains: scan?.redirectDomains || [],
        scriptSources: scan?.scriptSources || []
      }
    };
    queue.update(entry.id, patch);
    const updated = queue.all.get(entry.id);

    writeEntry(undefined, {
      deployment: entry.url,
      urlscanResult: `https://urlscan.io/result/${patch.scan.urlscanId}/`,
      ...patch.threatIntel
    });

    for (const ip of patch.threatIntel.c2Ips) {
      await reportToAbuseIPDB(ip, ABUSEIPDB_KEY);
    }

    const confirmedBy = await recordAndCheck(entry.url);
    if (confirmedBy) {
      queue.update(entry.id, { mailtoLink: buildMailtoLink(updated, confirmedBy) });
    }

    await sendWebhook(updated, WEBHOOK_URL);
    broadcaster.broadcast(queue.all.get(entry.id));
    return;
  }

  // URLScan deep scan
  const uuid = await submitUrlscan(entry.url, URLSCAN_KEY);
  const result = uuid ? await pollUrlscan(uuid) : null;
  const scan = extractScanData(result);
  const status = !scan ? 'clean' : scan.score > 50 ? 'suspicious' : 'clean';

  const meta = extractFromUrlscan(result);
  meta.favicon = await fetchFavicon(entry.url);

  const dom = result?.dom || '';
  const headers = result?.data?.requests?.[0]?.response?.headers || {};

  const patch = {
    status,
    scan: {
      urlhausFlagged: false,
      urlscanScore: scan?.score ?? 0,
      urlscanId: scan?.urlscanId || uuid,
      urlscanScreenshot: scan?.screenshot || null
    },
    meta,
    framework: detectFramework(dom, headers),
    aiTool: detectAiTool(dom),
    threatIntel: status === 'suspicious' ? {
      c2Ips: scan?.c2Ips || [],
      redirectDomains: scan?.redirectDomains || [],
      scriptSources: scan?.scriptSources || []
    } : null
  };
  queue.update(entry.id, patch);

  // Screenshot: use URLScan's if suspicious (already captured), otherwise fetch our own
  if (status === 'suspicious') {
    await sendWebhook(queue.all.get(entry.id), WEBHOOK_URL);
    queue.update(entry.id, { screenshot: scan?.screenshot, screenshotSource: 'urlscan' });
  } else {
    const { screenshot, source } = await getScreenshot(entry.url);
    queue.update(entry.id, { screenshot, screenshotSource: source });
  }

  broadcaster.broadcast(queue.all.get(entry.id));
}

// Worker pool
async function runWorker() {
  while (true) {
    const entry = queue.shift();
    if (entry) {
      await processEntry(entry).catch(err =>
        console.error(`[worker] ${entry.url}:`, err.message)
      );
    } else {
      await new Promise(r => setTimeout(r, 500));
    }
  }
}

// Express
const app = express();
app.use(express.static(path.join(__dirname, 'public')));

app.get('/events', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  broadcaster.addClient(res, queue.getAll());
});

app.get('/rss', (req, res) => {
  res.setHeader('Content-Type', 'application/rss+xml');
  res.send(buildRss(queue.getAll()));
});

app.get('/api/stats', (req, res) => {
  res.json(computeStats(queue.getAll()));
});

app.listen(PORT, () => {
  console.log(`vercel-feed running at http://localhost:${PORT}`);
  if (!URLSCAN_KEY) console.log('[warn] URLSCAN_KEY not set - rate-limited scanning');
  if (!process.env.UPSTASH_REDIS_URL) console.log('[warn] Upstash not set - auto-reporting disabled');
});

for (let i = 0; i < 3; i++) runWorker();

// Seed queue with known public Vercel deployments so the UI has data on startup
// (certstream / crt.sh may be slow to produce entries on first boot)
const SEED_HOSTNAMES = [
  'swr.vercel.app',
  'nextjs-blog.vercel.app',
  'react-tweet.vercel.app',
  'ai-sdk-preview.vercel.app',
  'geist-font.vercel.app',
  'nextjs-commerce.vercel.app',
  'next-blog-starter.vercel.app',
  'nextjs-portfolio.vercel.app',
  'examples-nextjs.vercel.app',
  'vercel-storage.vercel.app',
];

for (const hostname of SEED_HOSTNAMES) {
  const entry = queue.push(hostname);
  if (entry) broadcaster.broadcast(entry);
}

setInterval(() => {
  broadcaster.broadcastStats(computeStats(queue.getAll()));
  const alert = detectTrending(queue.getAll());
  if (alert) console.log(`[trending] ${alert}`);
}, 10_000);

connectCertstream(queue, (entry) => broadcaster.broadcast(entry));
