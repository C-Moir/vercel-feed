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
const { detectAiTool, detectFramework, detectContentTags } = require('./lib/fingerprint.js');
const { Broadcaster } = require('./lib/broadcaster.js');
const { computeStats, detectTrending } = require('./lib/stats.js');
const { sendWebhook } = require('./lib/webhook.js');
const { buildRss } = require('./lib/rss.js');
const { appendHistory, readHistory, readDay, listDates } = require('./lib/history.js');

const PORT = process.env.PORT || 3000;
const URLSCAN_KEY = process.env.URLSCAN_KEY || null;
const ABUSEIPDB_KEY = process.env.ABUSEIPDB_KEY || null;
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
    appendHistory(queue.all.get(entry.id));
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
    appendHistory(queue.all.get(entry.id));
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
    contentTags: detectContentTags(dom, meta),
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
  appendHistory(queue.all.get(entry.id));
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

app.listen(PORT, () => {
  console.log(`vercel-feed running at http://localhost:${PORT}`);
  if (!URLSCAN_KEY) console.log('[warn] URLSCAN_KEY not set - rate-limited scanning');
  if (!process.env.UPSTASH_REDIS_URL) console.log('[warn] Upstash not set - auto-reporting disabled');
});

setInterval(() => {
  broadcaster.broadcastStats(computeStats(queue.getAll()));
  const alert = detectTrending(queue.getAll());
  if (alert) console.log(`[trending] ${alert}`);
}, 10_000);

// Start worker pool - 5 concurrent so the queue doesn't back up
const WORKER_COUNT = 5;
for (let i = 0; i < WORKER_COUNT; i++) runWorker();

connectCertstream(queue, (entry) => broadcaster.broadcast(entry));
