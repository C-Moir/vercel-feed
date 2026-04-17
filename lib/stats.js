'use strict';

function computeStats(entries) {
  const now = Date.now();
  const oneHourAgo = now - 60 * 60 * 1000;
  const deploysPerHour = entries.filter(e => new Date(e.timestamp).getTime() > oneHourAgo).length;
  const flaggedCount = entries.filter(e => e.status === 'flagged' || e.status === 'suspicious').length;
  const frameworkBreakdown = {};
  const aiToolLeaderboard = {};

  for (const e of entries) {
    if (e.framework) frameworkBreakdown[e.framework] = (frameworkBreakdown[e.framework] || 0) + 1;
    if (e.aiTool) aiToolLeaderboard[e.aiTool] = (aiToolLeaderboard[e.aiTool] || 0) + 1;
  }

  return {
    totalSeen: entries.length,
    deploysPerHour,
    flaggedCount,
    flaggedPercent: entries.length ? Math.round((flaggedCount / entries.length) * 100) : 0,
    frameworkBreakdown,
    aiToolLeaderboard
  };
}

function detectTrending(entries) {
  const now = Date.now();
  const thirtyMinAgo = now - 30 * 60 * 1000;
  const ninetyMinAgo = now - 90 * 60 * 1000;
  const recent = entries.filter(e => new Date(e.timestamp).getTime() > thirtyMinAgo).length;
  const prior = entries.filter(e => {
    const t = new Date(e.timestamp).getTime();
    return t > ninetyMinAgo && t <= thirtyMinAgo;
  }).length;
  if (prior > 0 && recent >= prior * 2 && recent >= 5) {
    return `Deploy rate spike: ${recent} in last 30min vs ${prior} in prior 30min`;
  }
  return null;
}

module.exports = { computeStats, detectTrending };
