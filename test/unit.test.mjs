import test from 'node:test';
import assert from 'node:assert';
import { blake3 } from '@noble/hashes/blake3.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { x25519 } from '@noble/curves/ed25519.js';

import {
  MAX_NONCE,
  concat,
  createPadding,
  decodeHeader,
  decodeLength,
  encodeHeader,
  encodeLength,
  equalBytes,
  increaseNonce,
  parsePadding,
} from '../src/framing.js';
import { Aead, deriveKey, newCTR } from '../src/aead.js';
import { RecordConn } from '../src/conn.js';
import { ByteStream } from '../src/stream.js';
import {
  b64decode,
  b64encode,
  generate,
  parseDecryption,
  publicFromPrivate,
} from '../src/keys.js';
import { ServerInstance } from '../src/server.js';
import { parseRequest, parseUUID, uuidEquals } from '../src/vless.js';

const enc = (s) => new TextEncoder().encode(s);

test('record header is shaped like a TLS 1.3 application-data record', () => {
  const h = new Uint8Array(5);
  encodeHeader(h, 1234);
  assert.deepEqual(Array.from(h), [23, 3, 3, 4, 210]);
  assert.equal(decodeHeader(h), 1234);
});

test('header rejects out-of-range and non-TLS-looking lengths', () => {
  assert.throws(() => decodeHeader(new Uint8Array([23, 3, 3, 0, 16])));
  assert.throws(() => decodeHeader(new Uint8Array([23, 3, 3, 255, 255])));
  // wrong prefix zeroes the length, which then fails the range check
  assert.throws(() => decodeHeader(new Uint8Array([22, 3, 3, 4, 210])));
});

test('header error text keeps the substring the client keys off', () => {
  try {
    decodeHeader(new Uint8Array([1, 2, 3, 4, 5]));
    assert.fail('should throw');
  } catch (e) {
    assert.ok(e.message.includes('invalid header: '));
  }
});

test('length codec round-trips', () => {
  for (const n of [0, 1, 255, 256, 65535]) {
    assert.equal(decodeLength(encodeLength(n)), n);
  }
});

test('nonce counts up from the last byte and carries', () => {
  const n = new Uint8Array(12);
  increaseNonce(n);
  assert.equal(n[11], 1);
  n[11] = 255;
  increaseNonce(n);
  assert.equal(n[11], 0);
  assert.equal(n[10], 1);
});

test('nonce wraps from all-ones back to zero', () => {
  const n = MAX_NONCE.slice();
  increaseNonce(n);
  assert.ok(n.every((b) => b === 0));
});

test('blake3 derive_key matches the official test vector', () => {
  const ctx = enc('BLAKE3 2019-12-27 16:29:52 test vectors context');
  const got = Buffer.from(blake3(new Uint8Array(0), { context: ctx, dkLen: 32 }));
  assert.equal(
    got.toString('hex'),
    '2cc39783c223154fea8dfb7c1b1660f2ac2dcbd1c1de8277b0b0dd39b7e50d7d'
  );
});

test('derive_key is bound to the context, not just the key', () => {
  const key = new Uint8Array(32).fill(1);
  assert.ok(!equalBytes(deriveKey(enc('a'), key), deriveKey(enc('b'), key)));
});

test('AES-CTR keeps its keystream position across ragged calls', async () => {
  const key = new Uint8Array(32).fill(3);
  const iv = new Uint8Array(16).fill(9);
  const a = await newCTR(key, iv);
  const b = await newCTR(key, iv);
  const data = new Uint8Array(100);
  const whole = await a.xor(data);
  const parts = [];
  let off = 0;
  for (const n of [5, 3, 8, 17, 5, 62]) {
    parts.push(await b.xor(data.subarray(off, off + n)));
    off += n;
  }
  assert.ok(equalBytes(whole, concat(...parts)));
});

test('AEAD seals and opens with the counting nonce', async () => {
  const a = Aead.create(enc('ctx'), new Uint8Array(32).fill(7), true);
  const b = Aead.create(enc('ctx'), new Uint8Array(32).fill(7), true);
  const msg = enc('hello');
  const aad = new Uint8Array([23, 3, 3, 0, 21]);
  assert.ok(equalBytes(await b.open(await a.seal(msg, aad), aad), msg));
});

test('AEAD nonces advance, so replaying a record fails', async () => {
  const a = Aead.create(enc('ctx'), new Uint8Array(32).fill(7), true);
  const b = Aead.create(enc('ctx'), new Uint8Array(32).fill(7), true);
  const first = await a.seal(enc('one'), null);
  await a.seal(enc('two'), null);
  await b.open(first, null);
  await assert.rejects(() => b.open(first, null));
});

test('chacha20-poly1305 path round-trips too', async () => {
  const a = Aead.create(enc('ctx'), new Uint8Array(32).fill(5), false);
  const b = Aead.create(enc('ctx'), new Uint8Array(32).fill(5), false);
  const msg = enc('non-aes clients take this branch');
  assert.ok(equalBytes(await b.open(await a.seal(msg, null), null), msg));
});

test('base64url round-trips without padding', () => {
  const raw = new Uint8Array([251, 255, 190, 1, 2, 3]);
  assert.ok(equalBytes(b64decode(b64encode(raw)), raw));
});

test('generated key strings parse back to the same key', () => {
  for (const auth of ['x25519', 'mlkem768']) {
    const g = generate(auth, 'native', 0);
    const p = parseDecryption(g.decryption);
    assert.equal(p.keys.length, 1);
    assert.equal(p.xorMode, 0);
    assert.equal(p.secondsFrom, 0);
    const pub = publicFromPrivate(p.keys[0]);
    assert.equal(g.encryption.split('.').pop(), b64encode(pub));
  }
});

test('decryption string carries mode, seconds and padding', () => {
  const g = generate('x25519', 'random', 600);
  const withPadding = g.decryption.replace(
    '.600s.',
    '.600s.100-111-1111.75-0-111.'
  );
  const p = parseDecryption(withPadding);
  assert.equal(p.xorMode, 2);
  assert.equal(p.secondsFrom, 600);
  assert.equal(p.padding, '100-111-1111.75-0-111');
  assert.equal(p.keys.length, 1);
});

test('a seconds range is accepted', () => {
  const g = generate('x25519', 'native', 0);
  const p = parseDecryption(g.decryption.replace('.0s.', '.60-600s.'));
  assert.equal(p.secondsFrom, 60);
  assert.equal(p.secondsTo, 600);
});

test('unknown prefixes and modes are rejected', () => {
  assert.throws(() => parseDecryption('none'));
  assert.throws(() => parseDecryption('mlkem768x25519plus.wat.0s.AAAA'));
});

test('padding spec parses into length and gap groups', () => {
  const { paddingLens, paddingGaps } = parsePadding('100-111-1111.75-0-111.50-0-3333');
  assert.equal(paddingLens.length, 2);
  assert.equal(paddingGaps.length, 1);
  assert.throws(() => parsePadding('99-111-1111'));
  assert.throws(() => parsePadding('100-1-2'));
});

test('default padding stays inside the documented bounds', () => {
  for (let i = 0; i < 50; i++) {
    const { length, lens, gaps } = createPadding([], []);
    assert.equal(lens.length, 2);
    assert.equal(gaps.length, 1);
    assert.ok(length <= 1111 + 3333);
  }
});

test('relay length matches the advertised key type', () => {
  const x = new ServerInstance(generate('x25519', 'native', 0).decryption);
  assert.equal(x.relaysLength, 32);
  const m = new ServerInstance(generate('mlkem768', 'native', 0).decryption);
  assert.equal(m.relaysLength, 1088);
});

test('server keys hash to the value xray prints as Hash32', () => {
  const g = generate('x25519', 'native', 0);
  const priv = parseDecryption(g.decryption).keys[0];
  const pub = x25519.getPublicKey(priv);
  const inst = new ServerInstance(g.decryption);
  assert.ok(equalBytes(inst.hash32s[0], blake3(pub, { dkLen: 32 })));
});

test('ml-kem-768 keygen is deterministic from the 64-byte seed', () => {
  const seed = new Uint8Array(64).fill(11);
  assert.ok(
    equalBytes(ml_kem768.keygen(seed).publicKey, ml_kem768.keygen(seed).publicKey)
  );
});

test('0-RTT is refused unless the config asks for it', () => {
  assert.equal(new ServerInstance(generate('x25519', 'native', 0).decryption).allows0RTT, false);
  assert.equal(new ServerInstance(generate('x25519', 'native', 600).decryption).allows0RTT, true);
});

test('byte stream hands back exactly what was asked for', async () => {
  const s = new ByteStream({ write() {}, close() {} });
  s.push(new Uint8Array([1, 2, 3]));
  s.push(new Uint8Array([4, 5]));
  assert.deepEqual(Array.from(await s.readFull(4)), [1, 2, 3, 4]);
  assert.deepEqual(Array.from(await s.readFull(1)), [5]);
});

test('byte stream waits for bytes that have not arrived yet', async () => {
  const s = new ByteStream({ write() {}, close() {} });
  const p = s.readFull(3);
  s.push(new Uint8Array([9]));
  s.push(new Uint8Array([8, 7]));
  assert.deepEqual(Array.from(await p), [9, 8, 7]);
});

test('byte stream throws rather than returning a short read at EOF', async () => {
  const s = new ByteStream({ write() {}, close() {} });
  s.push(new Uint8Array([1]));
  s.end();
  await assert.rejects(() => s.readFull(2));
});

/** Two RecordConns wired to each other, as the client and server would be. */
function pair(useAES) {
  const key = new Uint8Array(96).fill(42);
  const aKey = Aead.create(enc('a'), key, useAES);
  const bKey = Aead.create(enc('b'), key, useAES);
  const left = new ByteStream({ write: (u8) => right.push(u8), close() {} });
  const right = new ByteStream({ write: (u8) => left.push(u8), close() {} });
  return [
    new RecordConn(left, {
      useAES,
      unitedKey: key,
      aead: aKey,
      peerAead: Aead.create(enc('b'), key, useAES),
    }),
    new RecordConn(right, {
      useAES,
      unitedKey: key,
      aead: bKey,
      peerAead: Aead.create(enc('a'), key, useAES),
    }),
  ];
}

test('record layer round-trips a message', async () => {
  const [a, b] = pair(true);
  await a.write(enc('over the wire'));
  assert.equal(new TextDecoder().decode(await b.read()), 'over the wire');
});

test('record layer splits payloads larger than 8192', async () => {
  const [a, b] = pair(true);
  const big = new Uint8Array(20000);
  crypto.getRandomValues(big);
  await a.write(big);
  const parts = [await b.read(), await b.read(), await b.read()];
  assert.deepEqual(parts.map((p) => p.length), [8192, 8192, 3616]);
  assert.ok(equalBytes(concat(...parts), big));
});

test('record layer round-trips on the chacha branch as well', async () => {
  const [a, b] = pair(false);
  await a.write(enc('no aes here'));
  assert.equal(new TextDecoder().decode(await b.read()), 'no aes here');
});

test('a tampered record fails to open', async () => {
  const key = new Uint8Array(96).fill(1);
  const sink = [];
  const out = new ByteStream({ write: (u8) => sink.push(u8), close() {} });
  const a = new RecordConn(out, {
    useAES: true,
    unitedKey: key,
    aead: Aead.create(enc('x'), key, true),
    peerAead: Aead.create(enc('y'), key, true),
  });
  await a.write(enc('tamper me'));
  const record = sink[0];
  record[record.length - 1] ^= 0xff;
  const inS = new ByteStream({ write() {}, close() {} });
  inS.push(record);
  const b = new RecordConn(inS, {
    useAES: true,
    unitedKey: key,
    aead: Aead.create(enc('y'), key, true),
    peerAead: Aead.create(enc('x'), key, true),
  });
  await assert.rejects(() => b.read());
});

test('rekey fires when the nonce is exhausted', async () => {
  const [a, b] = pair(true);
  a.aead.nonce = MAX_NONCE.slice();
  b.peerAead.nonce = MAX_NONCE.slice();
  const before = a.aead;
  await a.write(enc('last one on this key'));
  assert.notEqual(a.aead, before);
  assert.equal(new TextDecoder().decode(await b.read()), 'last one on this key');
  await a.write(enc('first one on the next key'));
  assert.equal(
    new TextDecoder().decode(await b.read()),
    'first one on the next key'
  );
});

test('vless request parses an ipv4 target', () => {
  const uuid = parseUUID('11111111-2222-3333-4444-555555555555');
  const buf = concat(
    new Uint8Array([0]),
    uuid,
    new Uint8Array([0, 1, 0x01, 0xbb, 1, 1, 2, 3, 4]),
    enc('GET /')
  );
  const r = parseRequest(buf);
  assert.equal(r.command, 1);
  assert.equal(r.port, 443);
  assert.equal(r.address, '1.2.3.4');
  assert.equal(new TextDecoder().decode(buf.subarray(r.offset)), 'GET /');
});

test('vless request parses a domain target', () => {
  const uuid = parseUUID('11111111-2222-3333-4444-555555555555');
  const host = enc('example.com');
  const buf = concat(
    new Uint8Array([0]),
    uuid,
    new Uint8Array([0, 1, 0, 80, 2, host.length]),
    host
  );
  const r = parseRequest(buf);
  assert.equal(r.address, 'example.com');
  assert.equal(r.port, 80);
});

test('vless request parses an ipv6 target', () => {
  const uuid = parseUUID('11111111-2222-3333-4444-555555555555');
  const addr = new Uint8Array(16);
  addr[0] = 0x20;
  addr[1] = 0x01;
  addr[15] = 1;
  const buf = concat(new Uint8Array([0]), uuid, new Uint8Array([0, 1, 0, 53, 3]), addr);
  assert.equal(parseRequest(buf).address, '2001:0:0:0:0:0:0:1');
});

test('a partial request asks for more bytes instead of guessing', () => {
  const uuid = parseUUID('11111111-2222-3333-4444-555555555555');
  const host = enc('example.com');
  const full = concat(
    new Uint8Array([0]),
    uuid,
    new Uint8Array([0, 1, 0, 80, 2, host.length]),
    host
  );
  for (let n = 0; n < full.length; n++) {
    assert.equal(parseRequest(full.subarray(0, n)), null, 'at ' + n);
  }
  assert.ok(parseRequest(full));
});

test('uuid comparison is length-safe', () => {
  const a = parseUUID('11111111-2222-3333-4444-555555555555');
  const b = parseUUID('11111111-2222-3333-4444-555555555556');
  assert.ok(uuidEquals(a, a.slice()));
  assert.ok(!uuidEquals(a, b));
  assert.ok(!uuidEquals(a, a.slice(0, 15)));
  assert.throws(() => parseUUID('nope'));
});
