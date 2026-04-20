'use strict';

// GitHub Events API poller — catches PageBuildEvent when a GitHub Pages site builds.
// Unauthenticated: 60 req/hr limit — poll every 65s.
// With GITHUB_TOKEN: 5000 req/hr — poll every 30s.
// Uses If-None-Match (Etag) so unchanged polls don't count against the rate limit.

const { isValidDeployment } = require('./platforms.js');

const UNAUTHED_INTERVAL = 65_000;
const AUTHED_INTERVAL   = 30_000;

let lastEventId = null;
let lastEtag    = null;

async function pollGitHubEvents(queue, onNew) {
  const token = process.env.GITHUB_TOKEN;
  const headers = {
    'Accept': 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
    'User-Agent': 'deployment-feed/1.0 (https://github.com/C-Moir/deployment-feed)',
  };
  if (token)    headers['Authorization'] = `Bearer ${token}`;
  if (lastEtag) headers['If-None-Match'] = lastEtag;

  try {
    const res = await fetch(
      'https://api.github.com/events?per_page=100',
      { headers, signal: AbortSignal.timeout(15_000) }
    );

    const etag = res.headers.get('etag');
    if (etag) lastEtag = etag;

    if (res.status === 304) return; // nothing new — no rate limit cost
    if (res.status === 403 || res.status === 429) {
      console.warn('[github] rate limited');
      return;
    }
    if (!res.ok) return;

    const events = await res.json();
    if (!Array.isArray(events) || !events.length) return;

    const newestId = events[0].id;
    let found = 0;

    for (const event of events) {
      // Stop at the last event we already processed. GitHub returns IDs as strings
      // that can exceed Number.MAX_SAFE_INTEGER, so compare by equality — with
      // 100-per-page polls we catch up before missing anything.
      if (lastEventId && event.id === lastEventId) break;
      if (event.type !== 'PageBuildEvent') continue;
      if (event.payload?.build?.status !== 'built') continue;

      const repoFullName = event.repo?.name;
      if (!repoFullName) continue;

      const [owner, repo] = repoFullName.split('/');
      if (!owner || !repo) continue;

      // Construct GitHub Pages hostname and URL.
      // User/org pages: {owner}.github.io repo → https://{owner}.github.io
      // Project pages:  any other repo        → https://{owner}.github.io/{repo}/
      const hostname     = `${owner}.github.io`;
      const isUserPage   = repo.toLowerCase() === `${owner.toLowerCase()}.github.io`;
      const urlOverride  = isUserPage ? null : `https://${owner}.github.io/${repo}/`;

      if (!isValidDeployment(hostname)) continue;

      const entry = queue.push(hostname, urlOverride);
      if (entry) { onNew(entry); found++; }
    }

    lastEventId = newestId;
    if (found > 0) console.log(`[github] +${found} new GitHub Pages deployments`);
  } catch (err) {
    // Silently drop transient network failures
    const transient = err.message.includes('timeout') || err.message.includes('fetch failed') || err.message.includes('aborted');
    if (!transient) console.warn(`[github] ${err.message}`);
  }
}

function connect(queue, onNew) {
  const token    = process.env.GITHUB_TOKEN;
  const interval = token ? AUTHED_INTERVAL : UNAUTHED_INTERVAL;
  const note     = token
    ? '(authenticated — 5000 req/hr)'
    : '(unauthenticated — 60 req/hr; set GITHUB_TOKEN for higher limits)';
  console.log(`[github] polling GitHub Events every ${interval / 1000}s ${note}`);

  // Start 15s after boot so CT logs get going first
  setTimeout(() => {
    pollGitHubEvents(queue, onNew);
    setInterval(() => pollGitHubEvents(queue, onNew), interval);
  }, 15_000);
}

module.exports = { connect };
