#!/usr/bin/env node
// Prints a matching decryption / encryption pair.
//   node scripts/keys.mjs [mlkem768|x25519] [native|xorpub|random] [seconds]
import { generate } from '../src/keys.js';

const auth = process.argv[2] || 'mlkem768';
const mode = process.argv[3] || 'random';
const seconds = Number(process.argv[4] ?? 0);

if (!['mlkem768', 'x25519'].includes(auth)) {
  console.error('auth must be mlkem768 or x25519');
  process.exit(1);
}
if (!['native', 'xorpub', 'random'].includes(mode)) {
  console.error('mode must be native, xorpub or random');
  process.exit(1);
}

const { decryption, encryption } = generate(auth, mode, seconds);
console.log('DECRYPTION (server, keep secret):');
console.log(decryption);
console.log();
console.log('encryption (client side of the config):');
console.log(encryption);
