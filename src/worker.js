import { connect } from 'cloudflare:sockets';
import { ServerInstance } from './server.js';
import { ByteStream } from './stream.js';
import {
  CMD_TCP,
  CMD_UDP,
  parseRequest,
  parseUUID,
  responseHeader,
  uuidEquals,
} from './vless.js';
import { concat } from './framing.js';
import { botConfigured, handleUpdate } from './bot.js';

let instance = null;
let instanceKey = null;

export default {
  async fetch(request, env, ctx) {
    if (request.headers.get('Upgrade') !== 'websocket') {
      if (request.method === 'POST' && botConfigured(env)) {
        const handled = await handleUpdate(request, env);
        if (handled) return handled;
      }
      return notAWorker(request, env);
    }
    if (!env.DECRYPTION || !env.UUID) {
      return new Response('not configured', { status: 500 });
    }
    if (instanceKey !== env.DECRYPTION) {
      instance = new ServerInstance(env.DECRYPTION);
      instanceKey = env.DECRYPTION;
    }

    const pair = new WebSocketPair();
    const [client, ws] = Object.values(pair);
    ws.accept();

    const stream = new ByteStream({
      write: (u8) => ws.send(u8),
      close: () => {
        try {
          ws.close(1000);
        } catch {
          /* already closing */
        }
      },
    });

    // Early data rides in the subprotocol header on the very first frame.
    const early = request.headers.get('sec-websocket-protocol');
    if (early) {
      try {
        stream.push(decodeEarlyData(early));
      } catch {
        /* not early data, ignore */
      }
    }

    ws.addEventListener('message', async (e) => {
      const d = e.data;
      if (d instanceof ArrayBuffer) stream.push(new Uint8Array(d));
      else if (typeof d === 'string') stream.push(new TextEncoder().encode(d));
      else stream.push(new Uint8Array(await d.arrayBuffer())); // Blob
    });
    ws.addEventListener('close', () => stream.end());
    ws.addEventListener('error', () => stream.fail(new Error('ws error')));

    ctx.waitUntil(
      serve(stream, env).catch(() => {
        try {
          ws.close(1011);
        } catch {
          /* gone */
        }
      })
    );

    return new Response(null, {
      status: 101,
      webSocket: client,
      headers: early ? { 'sec-websocket-protocol': early } : undefined,
    });
  },
};

async function serve(stream, env) {
  const conn = await instance.handshake(stream);
  const uuid = parseUUID(env.UUID);

  let head = new Uint8Array(0);
  let req = null;
  while (!req) {
    const rec = await conn.read();
    if (!rec) throw new Error('eof before request');
    head = concat(head, rec);
    req = parseRequest(head);
  }
  if (!uuidEquals(req.uuid, uuid)) throw new Error('bad uuid');

  const payload = head.subarray(req.offset);
  if (req.command === CMD_UDP) {
    if (req.port !== 53) throw new Error('udp is only served for dns');
    return serveDNS(conn, req, payload, env);
  }
  if (req.command !== CMD_TCP) throw new Error('unsupported command');

  const socket = connect(
    { hostname: req.address, port: req.port },
    { allowHalfOpen: false }
  );
  const writer = socket.writable.getWriter();
  if (payload.length) await writer.write(payload);

  const down = (async () => {
    const reader = socket.readable.getReader();
    let sentHeader = false;
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      await conn.write(
        sentHeader ? value : concat(responseHeader(req.version), value)
      );
      sentHeader = true;
    }
    if (!sentHeader) await conn.write(responseHeader(req.version));
  })();

  const up = (async () => {
    for (;;) {
      const rec = await conn.read();
      if (!rec) break;
      await writer.write(rec);
    }
    // Workers sockets have no half-close, so we do not close the write side
    // here: doing so tears down the whole socket and cuts the downlink.
  })();

  try {
    await down;
  } finally {
    conn.close();
  }
  await up.catch(() => {});
}

/** VPN-mode clients send DNS as UDP through the tunnel; answer over DoH. */
async function serveDNS(conn, req, payload, env) {
  const endpoint = env.DOH || 'https://1.1.1.1/dns-query';
  let sentHeader = false;
  let buf = payload;

  const handle = async () => {
    while (buf.length >= 2) {
      const n = (buf[0] << 8) | buf[1];
      if (buf.length < 2 + n) break;
      const query = buf.slice(2, 2 + n);
      buf = buf.subarray(2 + n);
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'content-type': 'application/dns-message' },
        body: query,
      });
      const answer = new Uint8Array(await res.arrayBuffer());
      const framed = concat(
        new Uint8Array([(answer.length >> 8) & 0xff, answer.length & 0xff]),
        answer
      );
      await conn.write(
        sentHeader ? framed : concat(responseHeader(req.version), framed)
      );
      sentHeader = true;
    }
  };

  await handle();
  for (;;) {
    const rec = await conn.read();
    if (!rec) break;
    buf = concat(buf, rec);
    await handle();
  }
  conn.close();
}

function decodeEarlyData(protocol) {
  const norm = protocol.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(norm);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Anything that is not a WebSocket upgrade should look unremarkable. */
function notAWorker(request, env) {
  if (env.FALLBACK) {
    return fetch(new Request(env.FALLBACK + new URL(request.url).pathname, request));
  }
  return new Response('', { status: 404 });
}
