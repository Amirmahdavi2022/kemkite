// The "decryption" / "encryption" strings:
//
//   mlkem768x25519plus.<native|xorpub|random>.<seconds>s[.padding].<key>...
//   mlkem768x25519plus.<native|xorpub|random>.<1rtt|0rtt>[.padding].<key>...
//
// Anything shorter than 20 chars after field 3 is a padding spec, everything
// else is a base64url key. Server keys are 32 bytes (X25519 private) or 64
// bytes (ML-KEM-768 seed); client keys are 32 or 1184 bytes.

import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { x25519 } from '@noble/curves/ed25519.js';

export const PREFIX = 'mlkem768x25519plus';
export const XOR_MODES = { native: 0, xorpub: 1, random: 2 };

export function b64decode(s) {
  const norm = s.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(norm + '='.repeat((4 - (norm.length % 4)) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function b64encode(u8) {
  let bin = '';
  for (let i = 0; i < u8.length; i++) bin += String.fromCharCode(u8[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Splits off mode / seconds / padding and returns the raw key strings. */
export function parseDecryption(decryption) {
  const s = decryption.split('.');
  if (s.length < 4 || s[0] !== PREFIX) {
    throw new Error('unsupported decryption: ' + decryption);
  }
  const xorMode = XOR_MODES[s[1]];
  if (xorMode === undefined) throw new Error('unknown mode: ' + s[1]);

  const t = s[2].replace(/s$/, '').split('-');
  const secondsFrom = Number(t[0]);
  if (!Number.isInteger(secondsFrom)) throw new Error('bad seconds: ' + s[2]);
  const secondsTo = t.length === 2 ? Number(t[1]) : 0;
  if (!Number.isInteger(secondsTo)) throw new Error('bad seconds: ' + s[2]);

  let paddingChars = 0;
  for (const r of s.slice(3)) {
    if (r.length < 20) {
      paddingChars += r.length + 1;
      continue;
    }
    const b = b64decode(r);
    if (b.length !== 32 && b.length !== 64) {
      throw new Error('bad server key length: ' + b.length);
    }
  }

  let rest = decryption.slice(27 + s[2].length);
  let padding = '';
  if (paddingChars > 0) {
    padding = rest.slice(0, paddingChars - 1);
    rest = rest.slice(paddingChars);
  }
  return {
    xorMode,
    secondsFrom,
    secondsTo,
    padding,
    keys: rest.split('.').map(b64decode),
  };
}

/** Derives the matching client "encryption" value from a server key set. */
export function publicFromPrivate(key) {
  if (key.length === 32) return x25519.getPublicKey(key);
  if (key.length === 64) return ml_kem768.keygen(key).publicKey;
  throw new Error('bad server key length: ' + key.length);
}

/**
 * Generates a fresh pair of strings.
 * @param {'x25519'|'mlkem768'} auth
 */
export function generate(auth = 'mlkem768', mode = 'native', seconds = 0) {
  let priv;
  if (auth === 'x25519') {
    priv = x25519.utils.randomSecretKey();
  } else {
    priv = new Uint8Array(64);
    crypto.getRandomValues(priv);
  }
  const pub = publicFromPrivate(priv);
  return {
    decryption: `${PREFIX}.${mode}.${seconds}s.${b64encode(priv)}`,
    encryption: `${PREFIX}.${mode}.${seconds > 0 ? '0rtt' : '1rtt'}.${b64encode(pub)}`,
  };
}
