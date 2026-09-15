// gRPC transport, the same wire format Xray calls "gun".
//
// Each VLESS connection is one bidirectional gRPC stream on
// /<service>/Tun (or /TunMulti). Every chunk travels as a length-prefixed
// gRPC message wrapping a tiny protobuf: `message Hunk { bytes data = 1; }`.
// MultiHunk is the same field repeated, so one parser covers both.
//
// A Worker cannot send real HTTP/2 trailers, so the stream simply ends when
// the connection is done. The client only complains about that at the very
// end, after the data has already gone through. The zone's gRPC switch in
// the Cloudflare dashboard (Network tab) has to be on, or nothing arrives.

const TUN_RE = /\/(Tun|TunMulti)$/;

/** Stable, boring-looking service name derived from the deployment key. */
export function serviceName(env) {
  if (env.GRPC_SERVICE) return env.GRPC_SERVICE;
  const seed = String(env.DECRYPTION || env.UUID || 'kemkite');
  let h = 0x811c9dc5;
  for (let i = 0; i < seed.length; i++) {
    h ^= seed.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return 'api.v' + ((h % 3) + 1) + '.Sync' + h.toString(36).slice(0, 5);
}

export function isGrpc(request, env) {
  if (request.method !== 'POST') return false;
  const ct = request.headers.get('content-type') || '';
  if (!ct.startsWith('application/grpc')) return false;
  const path = new URL(request.url).pathname;
  const m = TUN_RE.exec(path);
  if (!m) return false;
  if (env.GRPC_STRICT === '1') {
    const svc = encodeURIComponent(serviceName(env));
    return path === '/' + svc + '/' + m[1];
  }
  return true;
}

function varint(n) {
  const out = [];
  while (n > 0x7f) {
    out.push((n & 0x7f) | 0x80);
    n >>>= 7;
  }
  out.push(n);
  return out;
}

/** One chunk of stream bytes -> one complete gRPC message. */
export function encodeHunk(data) {
  const vi = varint(data.length);
  const protoLen = 1 + vi.length + data.length;
  const out = new Uint8Array(5 + protoLen);
  out[0] = 0; // not compressed
  out[1] = (protoLen >>> 24) & 0xff;
  out[2] = (protoLen >>> 16) & 0xff;
  out[3] = (protoLen >>> 8) & 0xff;
  out[4] = protoLen & 0xff;
  out[5] = 0x0a; // field 1, length-delimited
  out.set(vi, 6);
  out.set(data, 6 + vi.length);
  return out;
}

function readVarint(buf, pos) {
  let result = 0;
  let shift = 0;
  for (;;) {
    if (pos >= buf.length) throw new Error('truncated varint');
    const b = buf[pos++];
    if (shift < 28) result |= (b & 0x7f) << shift;
    else result += (b & 0x7f) * 2 ** shift;
    if (!(b & 0x80)) break;
    shift += 7;
    if (shift > 63) throw new Error('varint too long');
  }
  return [result, pos];
}

/** Pulls every `data` field out of a Hunk / MultiHunk body. */
export function parseHunk(msg, onData) {
  let pos = 0;
  while (pos < msg.length) {
    let key;
    [key, pos] = readVarint(msg, pos);
    const field = key >>> 3;
    const wire = key & 7;
    if (wire === 2) {
      let len;
      [len, pos] = readVarint(msg, pos);
      if (pos + len > msg.length) throw new Error('truncated field');
      if (field === 1 && len) onData(msg.subarray(pos, pos + len));
      pos += len;
    } else if (wire === 0) {
      [, pos] = readVarint(msg, pos);
    } else if (wire === 5) {
      pos += 4;
    } else if (wire === 1) {
      pos += 8;
    } else {
      throw new Error('unsupported wire type ' + wire);
    }
  }
}

/** Incremental gRPC message splitter. Feed raw body bytes in any sizes. */
export class GrpcDecoder {
  constructor(onData) {
    this.onData = onData;
    this.buf = new Uint8Array(0);
  }

  push(chunk) {
    if (!chunk.length) return;
    if (this.buf.length) {
      const joined = new Uint8Array(this.buf.length + chunk.length);
      joined.set(this.buf);
      joined.set(chunk, this.buf.length);
      this.buf = joined;
    } else {
      this.buf = chunk;
    }
    let off = 0;
    while (this.buf.length - off >= 5) {
      const b = this.buf;
      if (b[off] & 1) throw new Error('compressed grpc message');
      const len =
        ((b[off + 1] << 24) | (b[off + 2] << 16) | (b[off + 3] << 8) | b[off + 4]) >>> 0;
      if (b.length - off - 5 < len) break;
      parseHunk(b.subarray(off + 5, off + 5 + len), this.onData);
      off += 5 + len;
    }
    // keep only the unfinished tail, as a copy so the source can be freed
    this.buf = off ? this.buf.slice(off) : this.buf;
  }
}
