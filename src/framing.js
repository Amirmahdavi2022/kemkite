// Wire primitives, ported byte-for-byte from Xray-core
// proxy/vless/encryption/common.go

export const MAX_NONCE = new Uint8Array(12).fill(0xff);

/** Records are shaped like a TLS 1.3 application-data record so a middlebox
 *  sees nothing unusual: 23 03 03 <len:u16>. */
export function encodeHeader(out, l) {
  out[0] = 23;
  out[1] = 3;
  out[2] = 3;
  out[3] = (l >> 8) & 0xff;
  out[4] = l & 0xff;
}

/** Returns the payload length, or throws with a message containing
 *  "invalid header: " — the client relies on that exact substring. */
export function decodeHeader(h) {
  let l = (h[3] << 8) | h[4];
  if (h[0] !== 23 || h[1] !== 3 || h[2] !== 3) l = 0;
  // TLS 1.3 max record: 16384 + 256 (RFC 8446 5.2)
  if (l < 17 || l > 16640) {
    throw new Error('invalid header: ' + Array.from(h.slice(0, 5)).join(','));
  }
  return l;
}

export function encodeLength(l) {
  return new Uint8Array([(l >> 8) & 0xff, l & 0xff]);
}

export function decodeLength(b) {
  return (b[0] << 8) | b[1];
}

/** In-place big-endian increment from the last byte. Mutates and returns. */
export function increaseNonce(nonce) {
  for (let i = 0; i < 12; i++) {
    nonce[11 - i]++;
    if (nonce[11 - i] !== 0) break;
  }
  return nonce;
}

export function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export function concat(...arrays) {
  let total = 0;
  for (const a of arrays) total += a.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

/**
 * Padding grammar: len/gap groups separated by ".", each "chance-min-max".
 * Even-indexed groups are lengths, odd-indexed are gaps (milliseconds).
 */
export function parsePadding(padding) {
  const paddingLens = [];
  const paddingGaps = [];
  if (!padding) return { paddingLens, paddingGaps };
  let maxLen = 0;
  const parts = padding.split('.');
  for (let i = 0; i < parts.length; i++) {
    const x = parts[i].split('-');
    if (x.length < 3 || x[0] === '' || x[1] === '' || x[2] === '') {
      throw new Error('invalid padding length/gap parameter: ' + parts[i]);
    }
    const y = [Number(x[0]), Number(x[1]), Number(x[2])];
    if (y.some((n) => !Number.isInteger(n))) {
      throw new Error('invalid padding length/gap parameter: ' + parts[i]);
    }
    if (i === 0 && (y[0] < 100 || y[1] < 35 || y[2] < 35)) {
      throw new Error('first padding length must not be smaller than 35');
    }
    if (i % 2 === 0) {
      paddingLens.push(y);
      maxLen += Math.max(y[1], y[2]);
    } else {
      paddingGaps.push(y);
    }
  }
  if (maxLen > 18 + 65535) {
    throw new Error('total padding length must not be larger than 65553');
  }
  return { paddingLens, paddingGaps };
}

function randBetween(from, to) {
  if (from === to) return from;
  const buf = new Uint32Array(1);
  crypto.getRandomValues(buf);
  return from + (buf[0] % (to - from + 1));
}

/** Mirrors CreatPadding: default 100-111-1111 / 75-0-111 / 50-0-3333. */
export function createPadding(paddingLens, paddingGaps) {
  if (paddingLens.length === 0) {
    paddingLens = [
      [100, 111, 1111],
      [50, 0, 3333],
    ];
    paddingGaps = [[75, 0, 111]];
  }
  let length = 0;
  const lens = [];
  const gaps = [];
  for (const y of paddingLens) {
    let l = 0;
    if (y[0] >= randBetween(0, 100)) l = randBetween(y[1], y[2]);
    lens.push(l);
    length += l;
  }
  for (const y of paddingGaps) {
    let g = 0;
    if (y[0] >= randBetween(0, 100)) g = randBetween(y[1], y[2]);
    gaps.push(g);
  }
  return { length, lens, gaps };
}
