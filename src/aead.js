// AEAD layer. Keys come out of BLAKE3 in derive_key mode, exactly as
// Xray does it: blake3.DeriveKey(k, string(ctx), key).

import { blake3 } from '@noble/hashes/blake3.js';
import { chacha20poly1305 } from '@noble/ciphers/chacha.js';
import { increaseNonce } from './framing.js';

export function deriveKey(ctx, key) {
  return blake3(key, { context: ctx, dkLen: 32 });
}

/** AES-256-CTR as a real stream cipher: the keystream position is kept
 *  between calls, so a 5-byte call followed by a 3-byte call lines up with
 *  Go's cipher.Stream. Rounding up to block boundaries here silently
 *  desynchronises every record header in "random" mode. */
export async function newCTR(key, iv) {
  const k = deriveKey(new TextEncoder().encode('VLESS'), key);
  const ck = await crypto.subtle.importKey('raw', k, 'AES-CTR', false, [
    'encrypt',
  ]);
  let counter = iv.slice(0, 16);
  let keystream = new Uint8Array(0);
  let ksOff = 0;

  const refill = async (want) => {
    const blocks = Math.max(1, Math.ceil(want / 16));
    const zeros = new Uint8Array(blocks * 16);
    keystream = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: 'AES-CTR', counter, length: 128 },
        ck,
        zeros
      )
    );
    ksOff = 0;
    const c = counter.slice();
    for (let n = 0; n < blocks; n++) {
      for (let i = 15; i >= 0; i--) {
        c[i]++;
        if (c[i] !== 0) break;
      }
    }
    counter = c;
  };

  return {
    async xor(data) {
      const out = new Uint8Array(data.length);
      for (let i = 0; i < data.length; ) {
        if (ksOff >= keystream.length) {
          await refill(Math.max(4096, data.length - i));
        }
        const n = Math.min(data.length - i, keystream.length - ksOff);
        for (let j = 0; j < n; j++) out[i + j] = data[i + j] ^ keystream[ksOff + j];
        i += n;
        ksOff += n;
      }
      return out;
    },
  };
}

export class Aead {
  constructor(useAES, key) {
    this.useAES = useAES;
    this.rawKey = key;
    this.nonce = new Uint8Array(12);
    this._ck = null;
  }

  static create(ctx, key, useAES) {
    return new Aead(useAES, deriveKey(ctx, key));
  }

  async _cryptoKey() {
    if (!this._ck) {
      this._ck = await crypto.subtle.importKey(
        'raw',
        this.rawKey,
        'AES-GCM',
        false,
        ['encrypt', 'decrypt']
      );
    }
    return this._ck;
  }

  /** nonce === null means "use and advance the internal counter". */
  async seal(plaintext, aad, nonce = null) {
    const n = nonce === null ? increaseNonce(this.nonce) : nonce;
    if (this.useAES) {
      const ck = await this._cryptoKey();
      const params = { name: 'AES-GCM', iv: n, tagLength: 128 };
      if (aad) params.additionalData = aad;
      return new Uint8Array(await crypto.subtle.encrypt(params, ck, plaintext));
    }
    return chacha20poly1305(this.rawKey, n, aad || undefined).encrypt(
      plaintext
    );
  }

  async open(ciphertext, aad, nonce = null) {
    const n = nonce === null ? increaseNonce(this.nonce) : nonce;
    if (this.useAES) {
      const ck = await this._cryptoKey();
      const params = { name: 'AES-GCM', iv: n, tagLength: 128 };
      if (aad) params.additionalData = aad;
      return new Uint8Array(await crypto.subtle.decrypt(params, ck, ciphertext));
    }
    return chacha20poly1305(this.rawKey, n, aad || undefined).decrypt(
      ciphertext
    );
  }
}
