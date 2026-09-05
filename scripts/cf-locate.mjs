#!/usr/bin/env node
// Runs inside GitHub Actions, where api.cloudflare.com is reachable.
// Reports which of the configured tokens can see a given hostname.
// Token values are never printed, only a short fingerprint.

import { createHash } from 'node:crypto';

const API = 'https://api.cloudflare.com/client/v4';
const target = (process.env.TARGET_HOST || '').trim().toLowerCase();

const fingerprint = (t) =>
  createHash('sha256').update(t).digest('hex').slice(0, 8);

async function cf(token, path) {
  const res = await fetch(API + path, {
    headers: { Authorization: 'Bearer ' + token },
  });
  const body = await res.json().catch(() => ({}));
  return { ok: res.ok && body.success !== false, status: res.status, body };
}

/** a.b.example.com -> [a.b.example.com, b.example.com, example.com] */
function suffixes(host) {
  const parts = host.split('.');
  const out = [];
  for (let i = 0; i < parts.length - 1; i++) out.push(parts.slice(i).join('.'));
  return out;
}

const slots = [1, 2, 3, 4]
  .map((n) => ({ n, token: process.env['CF_TOKEN_' + n] }))
  .filter((s) => s.token);

if (slots.length === 0) {
  console.error('no CF_TOKEN_* secrets are set');
  process.exit(1);
}

const wanted = target ? suffixes(target) : [];
const matches = [];

for (const { n, token } of slots) {
  console.log('\n=== CF_TOKEN_' + n + ' (fp ' + fingerprint(token) + ') ===');

  const verify = await cf(token, '/user/tokens/verify');
  if (!verify.ok) {
    console.log('  token rejected: HTTP ' + verify.status);
    continue;
  }
  console.log('  status: ' + (verify.body.result?.status || 'unknown'));

  const accounts = await cf(token, '/accounts?per_page=50');
  if (accounts.ok) {
    for (const a of accounts.body.result || []) {
      console.log('  account: ' + a.name + '  (' + a.id + ')');
    }
  } else {
    console.log('  cannot list accounts (HTTP ' + accounts.status + ')');
  }

  const zones = await cf(token, '/zones?per_page=100');
  if (!zones.ok) {
    console.log('  cannot list zones (HTTP ' + zones.status + ')');
    continue;
  }
  for (const z of zones.body.result || []) {
    const hit = wanted.includes(z.name.toLowerCase());
    console.log(
      '  zone: ' + z.name + '  [' + z.status + ']  account=' +
        (z.account?.name || '?') + (hit ? '   <<< MATCH' : '')
    );
    if (hit) {
      matches.push({
        slot: n,
        zone: z.name,
        zoneId: z.id,
        accountId: z.account?.id,
        accountName: z.account?.name,
      });
    }
  }
}

console.log('\n--------------------------------------------');
if (!target) {
  console.log('no TARGET_HOST given, listing only');
} else if (matches.length === 0) {
  console.log('no token holds a zone covering ' + target);
  console.log('(if it is a free subdomain, the zone may be the full name itself)');
} else {
  for (const m of matches) {
    console.log(
      'FOUND ' + target + ' -> use CF_TOKEN_' + m.slot +
        '  zone=' + m.zone + ' (' + m.zoneId + ')' +
        '  account=' + m.accountName + ' (' + m.accountId + ')'
    );
  }
}
