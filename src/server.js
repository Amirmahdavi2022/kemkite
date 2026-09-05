// Server side of VLESS Encryption, ported from
// Xray-core proxy/vless/encryption/server.go
//
// Shape of a 1-RTT client hello on the wire:
//
//   iv(16) | relays(nfs key exchange) | enc(len:2)+16 | enc(mlkemEK 1184 + x25519 32)+16 | enc padding
//
// and the server answers:
//
//   enc(mlkemCT 1088 + x25519 32)+16 | enc(ticket 16)+16 | enc padding
//
// Two independent key exchanges are stacked. The "nfs" one is long-term (the
// key that lives in the config) and the "pfs" one is ephemeral per connection,
// so a recorded session cannot be decrypted later even if the config leaks.
// Both halves are post-quantum: ML-KEM-768 for the ephemeral exchange always,
// and optionally for the long-term one too.

import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { x25519 } from '@noble/curves/ed25519.js';
import { blake3 } from '@noble/hashes/blake3.js';
import { Aead, newCTR } from './aead.js';
import { RecordConn } from './conn.js';
import {
  MAX_NONCE,
  concat,
  createPadding,
  decodeHeader,
  decodeLength,
  encodeLength,
  equalBytes,
  parsePadding,
} from './framing.js';
import { parseDecryption, publicFromPrivate } from './keys.js';

const MLKEM_SEED = 64;
const MLKEM_EK = 1184;
const MLKEM_CT = 1088;
const X25519_LEN = 32;

export class ServerInstance {
  constructor(decryption) {
    const parsed = parseDecryption(decryption);
    this.xorMode = parsed.xorMode;
    this.secondsFrom = parsed.secondsFrom;
    this.secondsTo = parsed.secondsTo;
    const { paddingLens, paddingGaps } = parsePadding(parsed.padding);
    this.paddingLens = paddingLens;
    this.paddingGaps = paddingGaps;

    if (parsed.keys.length === 0) throw new Error('empty key set');
    this.keys = parsed.keys;
    this.pubKeys = [];
    this.hash32s = [];
    this.relaysLength = 0;
    for (const k of parsed.keys) {
      if (k.length !== X25519_LEN && k.length !== MLKEM_SEED) {
        throw new Error('bad server key length: ' + k.length);
      }
      const pub = publicFromPrivate(k);
      this.pubKeys.push(pub);
      this.hash32s.push(blake3(pub, { dkLen: 32 }));
      this.relaysLength += (k.length === X25519_LEN ? X25519_LEN : MLKEM_CT) + 32;
    }
    this.relaysLength -= 32;

    this.stats = { full: 0, resumed: 0 };

    // 0-RTT session store. On Workers this only spans one isolate unless a
    // Durable Object is wired in, so the default config uses 0s (1-RTT only).
    this.sessions = new Map();
  }

  get allows0RTT() {
    return this.secondsFrom > 0 || this.secondsTo > 0;
  }

  /** Recovers the long-term shared secret from the client's relay block. */
  async _nfsKey(iv, relaysIn) {
    let relays = relaysIn;
    let nfsKey = null;
    let lastCTR = null;
    for (let j = 0; j < this.keys.length; j++) {
      const k = this.keys[j];
      if (lastCTR) {
        relays.set(await lastCTR.xor(relays.subarray(0, 32)), 0);
      }
      const index = k.length === X25519_LEN ? X25519_LEN : MLKEM_CT;
      if (this.xorMode > 0) {
        const ctr = await newCTR(this.pubKeys[j], iv);
        relays.set(await ctr.xor(relays.subarray(0, index)), 0);
      }
      if (k.length === X25519_LEN) {
        const peer = relays.slice(0, index);
        if (peer[31] > 127) {
          throw new Error(
            'the highest bit of the last byte of the peer-sent X25519 public key is not 0'
          );
        }
        nfsKey = x25519.getSharedSecret(k, peer);
      } else {
        nfsKey = ml_kem768.decapsulate(
          relays.slice(0, index),
          ml_kem768.keygen(k).secretKey
        );
      }
      if (j === this.keys.length - 1) break;

      relays = relays.subarray(index);
      lastCTR = await newCTR(nfsKey, iv);
      relays.set(await lastCTR.xor(relays.subarray(0, 32)), 0);
      if (!equalBytes(relays.subarray(0, 32), this.hash32s[j + 1])) {
        throw new Error('unexpected hash32');
      }
      relays = relays.subarray(32);
    }
    return nfsKey;
  }

  /**
   * Runs the handshake and returns a RecordConn carrying the inner VLESS
   * stream. Throws on any protocol error — the caller should then behave
   * like an ordinary web server rather than reporting anything.
   */
  async handshake(stream) {
    const ivAndRelays = await stream.readFull(16 + this.relaysLength);
    const iv = ivAndRelays.slice(0, 16);
    const nfsKey = await this._nfsKey(iv, ivAndRelays.subarray(16));

    // The client picks AES-GCM or ChaCha20-Poly1305 based on whether its CPU
    // has AES instructions, and does not announce which. Try one, then the
    // other: a wrong guess simply fails to authenticate.
    let useAES = true;
    let nfsAead = Aead.create(iv, nfsKey, useAES);
    const encryptedLength = await stream.readFull(18);
    let decryptedLength;
    try {
      decryptedLength = await nfsAead.open(encryptedLength, null);
    } catch {
      useAES = false;
      nfsAead = Aead.create(iv, nfsKey, useAES);
      decryptedLength = await nfsAead.open(encryptedLength, null);
    }
    const length = decodeLength(decryptedLength);

    if (length === 32) {
      this.stats.resumed++;
      return this._resume(stream, nfsAead, nfsKey, iv, useAES);
    }
    if (length < MLKEM_EK + 32 + 16) throw new Error('too short length');
    this.stats.full++;

    // --- ephemeral (perfect forward secrecy) exchange ---
    const encryptedPfsPublicKey = await stream.readFull(length);
    const peerPfsPublicKey = await nfsAead.open(encryptedPfsPublicKey, null);

    const { cipherText: encapsulatedPfsKey, sharedSecret: mlkemKey } =
      ml_kem768.encapsulate(peerPfsPublicKey.slice(0, MLKEM_EK));
    const x25519Secret = x25519.utils.randomSecretKey();
    const x25519Key = x25519.getSharedSecret(
      x25519Secret,
      peerPfsPublicKey.slice(MLKEM_EK, MLKEM_EK + X25519_LEN)
    );

    const pfsKey = concat(mlkemKey, x25519Key);
    const pfsPublicKey = concat(
      encapsulatedPfsKey,
      x25519.getPublicKey(x25519Secret)
    );
    const unitedKey = concat(pfsKey, nfsKey);

    const aead = Aead.create(pfsPublicKey, unitedKey, useAES);
    const peerAead = Aead.create(
      peerPfsPublicKey.slice(0, MLKEM_EK + X25519_LEN),
      unitedKey,
      useAES
    );

    // --- ticket for a later 0-RTT resume ---
    const ticket = new Uint8Array(16);
    crypto.getRandomValues(ticket);
    let seconds;
    if (this.secondsTo === 0) {
      seconds = Math.floor((this.secondsFrom * randBetween(50, 100)) / 100);
    } else {
      seconds = randBetween(this.secondsFrom, this.secondsTo);
    }
    ticket.set(encodeLength(seconds), 0);
    if (seconds > 0) {
      this.sessions.set(hex(ticket), {
        pfsKey,
        nfsKeys: new Set(),
        expires: Date.now() + (seconds + 60) * 1000,
      });
      this._sweep();
    }

    // --- server hello, written in fragments with pauses so 1-RTT does not
    //     have a fixed size/timing fingerprint ---
    const sealedPfs = await nfsAead.seal(pfsPublicKey, null, MAX_NONCE);
    const sealedTicket = await aead.seal(ticket, null);
    const { length: paddingLength, lens, gaps } = createPadding(
      this.paddingLens,
      this.paddingGaps
    );
    const paddingBody = new Uint8Array(paddingLength - 18 - 16);
    const serverHello = concat(
      sealedPfs,
      sealedTicket,
      await aead.seal(encodeLength(paddingLength - 18), null),
      await aead.seal(paddingBody, null)
    );
    await this._writeFragmented(stream, serverHello, lens, gaps, sealedPfs.length + sealedTicket.length);

    // --- the client's own padding, read after the hello so it may arrive
    //     slowly without changing the pattern ---
    const clientPaddingLength = decodeLength(
      await nfsAead.open(await stream.readFull(18), null)
    );
    await nfsAead.open(await stream.readFull(clientPaddingLength), null);

    if (this.xorMode === 2) {
      stream = await wrapXor(stream, unitedKey, ticket, iv, 0, 0);
    }
    return new RecordConn(stream, { useAES, unitedKey, aead, peerAead });
  }

  async _resume(stream, nfsAead, nfsKey, iv, useAES) {
    if (!this.allows0RTT) throw new Error('0-RTT is not allowed');
    const encryptedTicket = await stream.readFull(32);
    const ticket = await nfsAead.open(encryptedTicket, null);
    const s = this.sessions.get(hex(ticket));
    if (!s) {
      // Reply with noise that cannot parse as a record header, which is the
      // client's cue to fall back to a full handshake.
      let noises;
      do {
        noises = new Uint8Array(randBetween(1279, 2279));
        crypto.getRandomValues(noises);
      } while (tryDecodeHeader(noises));
      await stream.write(noises);
      throw new Error('expired ticket');
    }
    const nfsKeyHex = hex(nfsKey);
    if (s.nfsKeys.has(nfsKeyHex)) throw new Error('replay detected');
    s.nfsKeys.add(nfsKeyHex);

    const unitedKey = concat(s.pfsKey, nfsKey);
    const preWrite = new Uint8Array(16);
    crypto.getRandomValues(preWrite);
    const aead = Aead.create(preWrite, unitedKey, useAES);
    const peerAead = Aead.create(encryptedTicket, unitedKey, useAES);
    if (this.xorMode === 2) {
      stream = await wrapXor(stream, unitedKey, preWrite, iv, 16, 0);
    }
    return new RecordConn(stream, {
      useAES,
      unitedKey,
      aead,
      peerAead,
      preWrite,
    });
  }

  async _writeFragmented(stream, hello, lens, gaps, headLength) {
    const sizes = lens.slice();
    sizes[0] = headLength + sizes[0];
    let rest = hello;
    for (let i = 0; i < sizes.length; i++) {
      if (sizes[i] > 0) {
        await stream.write(rest.subarray(0, sizes[i]));
        rest = rest.subarray(sizes[i]);
      }
      if (gaps.length > i && gaps[i] > 0) {
        await sleep(gaps[i]);
      }
    }
    if (rest.length) await stream.write(rest);
  }

  _sweep() {
    const now = Date.now();
    for (const [k, v] of this.sessions) {
      if (v.expires < now) this.sessions.delete(k);
    }
  }
}

function tryDecodeHeader(b) {
  try {
    decodeHeader(b);
    return true;
  } catch {
    return false;
  }
}

function randBetween(from, to) {
  if (from >= to) return from;
  const buf = new Uint32Array(1);
  crypto.getRandomValues(buf);
  return from + (buf[0] % (to - from + 1));
}

function hex(u8) {
  let s = '';
  for (const b of u8) s += b.toString(16).padStart(2, '0');
  return s;
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

/** "random" mode: the 5-byte record headers are additionally CTR-masked so
 *  even the TLS-looking prefix is indistinguishable from noise. */
async function wrapXor(stream, unitedKey, outIv, inIv, outSkip, inSkip) {
  const ctr = await newCTR(unitedKey, outIv);
  const peerCTR = await newCTR(unitedKey, inIv);
  return new XorStream(stream, ctr, peerCTR, outSkip, inSkip);
}

class XorStream {
  constructor(inner, ctr, peerCTR, outSkip, inSkip) {
    this.inner = inner;
    this.ctr = ctr;
    this.peerCTR = peerCTR;
    this.outSkip = outSkip;
    this.outHeader = [];
    this.inSkip = inSkip;
    this.inHeader = [];
    this.pending = new Uint8Array(0);
  }

  async readFull(n) {
    while (this.pending.length < n) {
      const chunk = await this.inner.readSome();
      if (chunk === null) throw new Error('unexpected EOF');
      this.pending = concat(this.pending, await this._unmask(chunk));
    }
    const out = this.pending.slice(0, n);
    this.pending = this.pending.slice(n);
    return out;
  }

  async readSome() {
    if (this.pending.length === 0) {
      const chunk = await this.inner.readSome();
      if (chunk === null) return null;
      this.pending = await this._unmask(chunk);
    }
    const out = this.pending;
    this.pending = new Uint8Array(0);
    return out;
  }

  async _unmask(buf) {
    let p = buf;
    let off = 0;
    for (;;) {
      if (p.length - off <= this.inSkip) {
        this.inSkip -= p.length - off;
        break;
      }
      off += this.inSkip;
      this.inSkip = 0;
      const need = 5 - this.inHeader.length;
      if (p.length - off < need) {
        const seg = await this.peerCTR.xor(p.subarray(off));
        p.set(seg, off);
        this.inHeader.push(...seg);
        break;
      }
      const seg = await this.peerCTR.xor(p.subarray(off, off + need));
      p.set(seg, off);
      this.inHeader.push(...seg);
      this.inSkip = decodeHeader(Uint8Array.from(this.inHeader));
      this.inHeader = [];
      off += need;
    }
    return p;
  }

  async write(b) {
    const out = b.slice();
    let off = 0;
    for (;;) {
      if (out.length - off <= this.outSkip) {
        this.outSkip -= out.length - off;
        break;
      }
      off += this.outSkip;
      this.outSkip = 0;
      const need = 5 - this.outHeader.length;
      if (out.length - off < need) {
        this.outHeader.push(...out.subarray(off));
        out.set(await this.ctr.xor(out.subarray(off)), off);
        break;
      }
      this.outHeader.push(...out.subarray(off, off + need));
      out.set(await this.ctr.xor(out.subarray(off, off + need)), off);
      this.outSkip = decodeHeader(Uint8Array.from(this.outHeader));
      this.outHeader = [];
      off += need;
    }
    return this.inner.write(out);
  }

  close() {
    this.inner.close();
  }
}
