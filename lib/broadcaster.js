'use strict';

class Broadcaster {
  constructor() {
    this.clients = new Set();
  }
  get clientCount() { return this.clients.size; }

  addClient(res, existingEntries) {
    this.clients.add(res);
    // Replay state so a fresh connection never sees a blank feed
    for (const entry of existingEntries) {
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
