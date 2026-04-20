'use strict';

const { getPlatform } = require('./platforms.js');

const PRIORITY_KEYWORDS = [
  'login', 'wallet', 'verify', 'secure', 'bank',
  'confirm', 'account', 'recover', 'update-payment'
];
const MAX_DEDUP_SIZE = 100_000;
// Max entries kept in RAM - older ones are in history.ndjson
// SSE replay is capped at 200, so RAM beyond that is just for stats/dedup
const MAX_ALL_SIZE = 5_000;

class LRUSet {
  constructor(maxSize) {
    this.maxSize = maxSize;
    this.map = new Map();
  }
  has(key) { return this.map.has(key); }
  add(key) {
    if (this.map.has(key)) return;
    if (this.map.size >= this.maxSize) {
      this.map.delete(this.map.keys().next().value);
    }
    this.map.set(key, true);
  }
  get size() { return this.map.size; }
}

class JobQueue {
  constructor() {
    this.seen = new LRUSet(MAX_DEDUP_SIZE);
    this.pending = [];
    this.all = new Map(); // full job history - never pruned, used for SSE state replay on reconnect
  }

  isPriority(hostname) {
    return PRIORITY_KEYWORDS.some(kw => hostname.includes(kw));
  }

  push(hostname, urlOverride = null) {
    if (this.seen.has(hostname)) return null;
    this.seen.add(hostname);
    const priority = this.isPriority(hostname);

    const entry = {
      id: crypto.randomUUID(),
      url: urlOverride || `https://${hostname}`,
      hostname,
      platform: getPlatform(hostname)?.name || 'Unknown',
      timestamp: new Date().toISOString(),
      status: 'pending',
      priority,
      scan: null,
      screenshot: null,
      screenshotSource: null,
      meta: null,
      framework: null,
      aiTool: null,
      threatIntel: null
    };

    if (priority) this.pending.unshift(entry);
    else this.pending.push(entry);
    this.all.set(entry.id, entry);

    // Evict oldest entries from RAM once we exceed the cap
    if (this.all.size > MAX_ALL_SIZE) {
      this.all.delete(this.all.keys().next().value);
    }

    return entry;
  }

  shift() { return this.pending.shift() || null; }

  update(id, patch) {
    const entry = this.all.get(id);
    if (!entry) return null;
    // Strip identity fields - callers must not overwrite id/hostname/url
    const { id: _id, hostname: _h, url: _u, ...safe } = patch;
    Object.assign(entry, safe);
    return entry;
  }

  getAll() { return Array.from(this.all.values()); }

  // Pre-populate from persisted history so restarts don't wipe the feed
  preload(entries) {
    for (const entry of entries) {
      if (this.all.has(entry.id)) continue;
      if (this.all.size >= MAX_ALL_SIZE) {
        this.all.delete(this.all.keys().next().value);
      }
      this.seen.add(entry.hostname);
      this.all.set(entry.id, entry);
    }
  }
}

module.exports = { LRUSet, JobQueue, PRIORITY_KEYWORDS };
