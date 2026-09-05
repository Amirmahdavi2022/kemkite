// Test harness only. Runs the exact same src/ modules the Worker uses, but
// over a plain TCP socket so the real Xray binary can be pointed at it.

import net from 'node:net';
import { ServerInstance } from '../src/server.js';
import { ByteStream } from '../src/stream.js';
import { parseRequest, parseUUID, responseHeader, uuidEquals } from '../src/vless.js';

const DECRYPTION = process.env.DECRYPTION;
const UUID = parseUUID(process.env.UUID);
const PORT = Number(process.env.PORT || 10086);

const instance = new ServerInstance(DECRYPTION);
const log = (...a) => console.log(new Date().toISOString().slice(11, 23), ...a);

const server = net.createServer((socket) => {
  socket.on('error', () => {});
  const stream = new ByteStream({
    write: (u8) =>
      new Promise((resolve, reject) =>
        socket.write(u8, (e) => (e ? reject(e) : resolve()))
      ),
    close: () => socket.destroy(),
  });
  socket.on('data', (b) => stream.push(new Uint8Array(b)));
  socket.on('end', () => stream.end());
  socket.on('close', () => stream.end());

  handle(stream).catch((e) => {
    log('CONN FAIL:', e.message);
    socket.destroy();
  });
});

async function handle(stream) {
  const conn = await instance.handshake(stream);
  log('handshake ok', JSON.stringify(instance.stats), 'aes=' + conn.useAES);

  let head = new Uint8Array(0);
  let req = null;
  while (!req) {
    const rec = await conn.read();
    if (!rec) throw new Error('eof before request');
    head = concat(head, rec);
    req = parseRequest(head);
  }
  if (!uuidEquals(req.uuid, UUID)) throw new Error('bad uuid');
  log('request', req.command, req.address + ':' + req.port);
  if (req.command !== 1) throw new Error('only TCP in this harness');

  const target = net.connect(req.port, req.address);
  await new Promise((res, rej) => {
    target.once('connect', res);
    target.once('error', rej);
  });

  const initial = head.subarray(req.offset);
  if (initial.length) target.write(initial);

  // downlink: target -> client, with real backpressure
  const down = (async () => {
    let sentHeader = false;
    for await (const chunk of target) {
      const payload = new Uint8Array(chunk);
      await conn.write(
        sentHeader ? payload : concat(responseHeader(req.version), payload)
      );
      sentHeader = true;
    }
    if (!sentHeader) await conn.write(responseHeader(req.version));
  })();

  // uplink: client -> target
  const up = (async () => {
    for (;;) {
      const rec = await conn.read();
      if (!rec) break;
      target.write(rec);
    }
    target.end();
  })();

  try {
    await down;
  } finally {
    conn.close();
  }
  await up.catch(() => {});
}

function concat(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

server.listen(PORT, '127.0.0.1', () => log('kemkite test server on ' + PORT));
