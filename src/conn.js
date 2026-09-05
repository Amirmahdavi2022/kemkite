// Post-handshake record layer (CommonConn in Xray).
//
// Every record is <23 03 03 len:u16> followed by AEAD(payload) with the
// 5-byte header as associated data. Payload is capped at 8192 so the peer
// never has to copy. When a nonce reaches all-0xFF the key is re-derived
// from the record that used it.

import { Aead } from './aead.js';
import {
  MAX_NONCE,
  concat,
  decodeHeader,
  encodeHeader,
  equalBytes,
} from './framing.js';

const MAX_CHUNK = 8192;

export class RecordConn {
  /**
   * @param {ByteStream} stream
   * @param {object} o - { useAES, unitedKey, aead, peerAead, preWrite }
   */
  constructor(stream, o) {
    this.stream = stream;
    this.useAES = o.useAES;
    this.unitedKey = o.unitedKey;
    this.aead = o.aead;
    this.peerAead = o.peerAead;
    this.preWrite = o.preWrite || null;
    this.leftover = null;
  }

  async write(b) {
    if (b.length === 0) return 0;
    for (let n = 0; n < b.length; ) {
      let chunk = b.subarray(n);
      if (chunk.length > MAX_CHUNK) chunk = chunk.subarray(0, MAX_CHUNK);
      n += chunk.length;

      const header = new Uint8Array(5);
      encodeHeader(header, chunk.length + 16);

      const max = equalBytes(this.aead.nonce, MAX_NONCE);
      const sealed = await this.aead.seal(chunk, header);
      let record = concat(header, sealed);
      if (max) this.aead = Aead.create(record, this.unitedKey, this.useAES);

      if (this.preWrite) {
        record = concat(this.preWrite, record);
        this.preWrite = null;
      }
      await this.stream.write(record);
    }
    return b.length;
  }

  /** One decrypted record, or null at EOF. */
  async read() {
    if (this.leftover) {
      const out = this.leftover;
      this.leftover = null;
      return out;
    }
    let header;
    try {
      header = await this.stream.readFull(5);
    } catch {
      return null;
    }
    const l = decodeHeader(header);
    const payload = await this.stream.readFull(l);

    let newAead = null;
    if (equalBytes(this.peerAead.nonce, MAX_NONCE)) {
      newAead = Aead.create(
        concat(header, payload),
        this.unitedKey,
        this.useAES
      );
    }
    const plain = await this.peerAead.open(payload, header);
    if (newAead) this.peerAead = newAead;
    return plain;
  }

  close() {
    this.stream.close();
  }
}
