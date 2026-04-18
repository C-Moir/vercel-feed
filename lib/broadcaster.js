'use strict';

class Broadcaster {
  constructor() {
    this.clients = new Set();
  }
  get clientCount() { return this.clients.size; }

  addClient(res, existingEntries) {
    this.clients.add(res);
    // Replay the 200 most recent entries only — replaying thousands kills the browser
    const recent = existingEntries
      .slice()
      .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
      .slice(0, 200);
    for (const entry of recent) {
      res.write(`data: ${JSON.stringify(entry)}\n\n`);
    }
    res.on('close', () => this.clients.delete(res));
  }

  broadcast(entry) {
    const chunk = `data: ${JSON.stringify(entry)}\n\n`;
    for (const res of this.clients) res.write(chunk);
  }

  broadcastStats(stats) {
    const chunk = `event: stats\ndata: ${JSON.stringify(stats)}\n\n`;
    for (const res of this.clients) res.write(chunk);
  }
}

module.exports = { Broadcaster };
