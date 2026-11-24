// MIT License
// Copyright 2026 David J Goehrig <dave@dloh.org>
//
// mesgd transport client. One Mesgd == one wss connection == one path == one
// JWT; open several for several topics or grants. send/on are the headline
// surface. Security is opt-in: plain, signed (sig over body), or signed +
// sealed (body encrypted, routable fields left in cleartext).
//
// Browser-first: uses the standard WebSocket API and the bearer token as the
// second subprotocol value ['json', token]. Node (>=22) exposes the same
// global WebSocket, so the module runs there too.

import { PKI } from './pki.mjs';

export class Mesgd {
  static async connect(url, opts = {}) {
    const m = new Mesgd();
    m.pki = opts.pki || PKI;
    m.pub = opts.serverPub || null;
    m.handlers = {};
    if (opts.keys) await m.pki.importJWKS(opts.keys);
    else if (opts.keyFile) await m.pki.init(opts.keyFile);
    const WS = opts.WebSocket || globalThis.WebSocket;
    m.ws = new WS(url, opts.token ? ['json', opts.token] : ['json']);
    m.ws.onmessage = (e) => m._incoming(e.data);
    await new Promise((resolve, reject) => { m.ws.onopen = resolve; m.ws.onerror = reject; });
    return m;
  }

  on(type, handler) { this.handlers[type] = handler; return this; }

  async send(message, opts = {}) { this.ws.send(await this._frame(message, opts)); }

  close() { this.ws.close(); }

  async _frame(message, opts) {
    if (!opts.sign && !opts.seal) return JSON.stringify(message);
    const body = JSON.stringify(message.body);
    const out = { ...message };
    if (opts.sign) out.sig = await this.pki.sign(body);
    if (opts.seal) { delete out.body; out.enc = await this.pki.seal(this.pub, body); }
    return JSON.stringify(out);
  }

  async _incoming(raw) {
    const m = JSON.parse(raw);
    if (m.enc !== undefined) { m.body = JSON.parse(await this.pki.open(m.enc)); delete m.enc; }
    const handler = this.handlers[m.type || '*'] || this.handlers['*'];
    if (handler) handler(m);
  }
}
