#!/usr/bin/env node
'use strict';
require('dotenv').config({ path: '.env' });

const express = require('express');
const path = require('node:path');

const { JobQueue } = require('./lib/queue.js');
const { connect: connectCertstream } = require('./lib/certstream.js');
const { connect: connectGitHubPages } = require('./lib/github-pages.js');

const { checkUrlhaus, submitUrlscan, pollUrlscan, extractScanData } = require('./lib/scanner.js');
const { writeEntry } = require('./lib/threat-intel.js');
const { recordAndCheck, buildMailtoLink } = require('./lib/upstash.js');
const { getScreenshot, closeBrowser } = require('./lib/screenshot.js');
const { fetchFavicon, fetchDom, extractTitle, extractMetaDescription } = require('./lib/metadata.js');
const { detectAiTool, detectFramework, detectContentTags, detectSuspiciousHostname } = require('./lib/fingerprint.js');
const { Broadcaster } = require('./lib/broadcaster.js');
const { computeStats, detectTrending } = require('./lib/stats.js');
const { sendWebhook } = require('./lib/webhook.js');
const { buildRss } = require('./lib/rss.js');
const { appendHistory, readHistory, readDay, listDates } = require('./lib/history.js');

const PORT = process.env.PORT || 3000;
const URLSCAN_KEY = process.env.URLSCAN_KEY || null;
const WEBHOOK_URL = process.env.WEBHOOK_URL || null;

const queue = new JobQueue();
const broadcaster = new Broadcaster();

// One-time migration: move legacy history.ndjson into the per-day history/ directory
{
  const fs = require('node:fs');
  const legacyFile = path.join(__dirname, 'history.ndjson');
  if (fs.existsSync(legacyFile)) {
    try {
      const lines = fs.readFileSync(legacyFile, 'utf8').trim().split('\n').filter(Boolean);
      const byDay = {};
      for (const line of lines) {
        try {
          const e = JSON.parse(line);
          const day = (e.timestamp || new Date().toISOString()).slice(0, 10);
          (byDay[day] = byDay[day] || []).push(line);
        } catch (_) {}
      }
      for (const [day, dayLines] of Object.entries(byDay)) {
        const dest = path.join(__dirname, 'history', `${day}.ndjson`);
        fs.appendFileSync(dest, dayLines.join('\n') + '\n');
      }
      fs.renameSync(legacyFile, legacyFile + '.migrated');
      console.log(`[history] migrated legacy history.ndjson (${lines.length} entries) into history/`);
    } catch (err) {
      console.warn('[history] migration failed:', err.message);
    }
  }
}

// Restore recent history into queue so the feed isn't empty after a restart
{
  const history = readHistory(200);
  const toPreload = history.filter(e => e.id && e.status !== 'pending' && e.status !== 'scanning');
  queue.preload(toPreload);
  if (toPreload.length) {
    console.log(`[history] preloaded ${toPreload.length} entries from disk`);
  }
}

// URLScan was previously called on every clean deployment which jammed the worker
// pool (free tier is ~2/min). The new flow only spends URLScan credits when we
// already have a signal: URLhaus hit, or a hostname that looks like phishing.
async function processEntry(entry) {
  // Helper: get the live queue entry, fall back to the snapshot we have.
  // Entries can be evicted from RAM (MAX_ALL_SIZE cap) while a worker is mid-flight.
  const get = () => queue.all.get(entry.id) || entry;

  queue.update(entry.id, { status: 'scanning' });
  broadcaster.broadcast(get());

  // URLhaus fast check — confirmed malicious, worth a URLScan credit
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
    const updated = get();

    writeEntry(undefined, {
      deployment: entry.url,
      urlscanResult: `https://urlscan.io/result/${patch.scan.urlscanId}/`,
      ...patch.threatIntel
    });

    // AbuseIPDB auto-reporting disabled: scanner.js currently treats every
    // non-Vercel IP as C2, so reporting would spam CDN operators with false
    // positives. Re-enable once extractScanData uses real URLScan verdicts.

    const confirmedBy = await recordAndCheck(entry.url);
    if (confirmedBy) {
      queue.update(entry.id, { mailtoLink: buildMailtoLink(updated, confirmedBy) });
    }

    await sendWebhook(updated, WEBHOOK_URL);
    const finalFlagged = get();
    broadcaster.broadcast(finalFlagged);
    appendHistory(finalFlagged);
    return;
  }

  // Clean path: direct fetch, no URLScan credits spent
  const { dom, headers, status: httpStatus } = await fetchDom(entry.url);

  if (httpStatus === 404) {
    queue.update(entry.id, { status: '404' });
    const e404 = get();
    broadcaster.broadcast(e404);
    appendHistory(e404);
    return;
  }

  const meta = {
    title: extractTitle(dom),
    description: extractMetaDescription(dom),
    favicon: await fetchFavicon(entry.url),
  };

  const framework     = detectFramework(dom, headers);
  const aiTool        = detectAiTool(dom);
  const contentTags   = detectContentTags(dom, meta, entry.hostname);
  const hostSuspicion = detectSuspiciousHostname(entry.hostname);
  const isSuspicious  = !!hostSuspicion;

  queue.update(entry.id, {
    status: isSuspicious ? 'suspicious' : 'clean',
    meta,
    framework,
    aiTool,
    contentTags,
    suspicionReason: hostSuspicion,
  });

  if (isSuspicious && URLSCAN_KEY) {
    // Escalate: capture sandboxed evidence without visiting the live site ourselves
    const uuid = await submitUrlscan(entry.url, URLSCAN_KEY);
    const result = uuid ? await pollUrlscan(uuid) : null;
    const scan = extractScanData(result);
    queue.update(entry.id, {
      scan: {
        urlhausFlagged: false,
        urlscanScore: scan?.score ?? 0,
        urlscanId: scan?.urlscanId || uuid,
        urlscanScreenshot: scan?.screenshot || null,
      },
      screenshot: scan?.screenshot || null,
      screenshotSource: 'urlscan',
    });
    await sendWebhook(get(), WEBHOOK_URL);
  } else if (!isSuspicious) {
    const { screenshot, source } = await getScreenshot(entry.url);
    queue.update(entry.id, { screenshot, screenshotSource: source });
  }

  const final = get();
  broadcaster.broadcast(final);
  appendHistory(final);
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


// List available history dates
app.get('/api/history/dates', (req, res) => {
  res.json(listDates());
});

app.get('/api/history', (req, res) => {
  const dateKey = req.query.date || null;

  if (dateKey) {
    // Past day — read from disk only, no dedup needed
    return res.json(readDay(dateKey));
  }

  // Today — merge disk (today only) with completed in-memory entries, deduped
  const disk = readDay(); // today
  const diskHostnames = new Set(disk.map(e => e.hostname));
  const mem = queue.getAll()
    .filter(e => !diskHostnames.has(e.hostname) && e.status !== 'pending' && e.status !== 'scanning')
    .map(e => ({
      id: e.id,
      hostname: e.hostname,
      url: e.url,
      platform: e.platform,
      timestamp: e.timestamp,
      title: e.meta?.title || null,
      status: e.status,
      screenshot: e.screenshot || null,
      screenshotSource: e.screenshotSource || null,
      scan: e.scan || null,
      contentTags: e.contentTags || null,
    }));
  const combined = [...mem, ...disk]
    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
  res.json(combined);
});

app.get('/history', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'history.html'));
});

app.get('/map', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'map.html'));
});

// Suppress favicon.ico 404s without shipping a binary asset
app.get('/favicon.ico', (_req, res) => res.status(204).end());

app.listen(PORT, () => {
  console.log(`deployment-feed running at http://localhost:${PORT}`);
  if (!URLSCAN_KEY) console.log('[warn] URLSCAN_KEY not set - rate-limited scanning');
  if (!process.env.UPSTASH_REDIS_URL) console.log('[warn] Upstash not set - auto-reporting disabled');
});

// Tidy shutdown — chromium is expensive to leave dangling
for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, async () => {
    console.log(`[exit] ${sig} received, closing browser`);
    await closeBrowser();
    process.exit(0);
  });
}

setInterval(() => {
  broadcaster.broadcastStats(computeStats(queue.getAll()));
  const alert = detectTrending(queue.getAll());
  if (alert) console.log(`[trending] ${alert}`);
}, 10_000);

// Start worker pool - 5 concurrent so the queue doesn't back up
const WORKER_COUNT = 5;
for (let i = 0; i < WORKER_COUNT; i++) runWorker();

connectCertstream(queue, (entry) => broadcaster.broadcast(entry));
connectGitHubPages(queue, (entry) => broadcaster.broadcast(entry));
