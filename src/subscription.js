// Subscription endpoint.
//
// The encryption value has no place in a vless:// link, so a plain base64
// subscription cannot carry it. This serves the JSON form instead: an array
// of complete configs, each with a remarks label, which is what Happ and
// v2rayN read. The response also carries the usual panel headers so the
// entry looks and behaves like any other subscription in the list.

import { allHosts, clientConfig } from './bot.js';
import { findUser, parseUsers } from './users.js';

// Ports Cloudflare terminates TLS on. Spreading across them gives real
// variety rather than ten copies of the same thing.
const PORTS = [443, 8443, 2053, 2083, 2087, 2096];

// Paths that all resolve to the same worker. ed=2048 turns on early data,
// which shaves a round trip off connection setup.
const PATHS = ['/', '/assets/', '/static/?ed=2048', '/cdn/?ed=2048'];

export function subVariants(env, hosts, count = 10, user = null) {
  const out = [];
  for (let i = 0; out.length < count; i++) {
    const host = hosts[i % hosts.length];
    const port = PORTS[Math.floor(i / hosts.length) % PORTS.length];
    const path = PATHS[i % PATHS.length];
    const cfg = clientConfig(env, host, user ? user.uuid : env.UUID);
    const ss = cfg.outbounds[0].streamSettings;
    cfg.outbounds[0].settings.vnext[0].port = port;
    ss.wsSettings.path = path;
    cfg.remarks =
      (user ? user.name : env.SUB_NAME || 'kemkite') +
      ' | ' +
      host.split('.')[0] +
      '-' +
      port +
      ' | ' +
      String(out.length + 1).padStart(2, '0');
    out.push(cfg);
    if (i > count * 8) break;
  }
  return out;
}

function b64(s) {
  return btoa(String.fromCharCode(...new TextEncoder().encode(s)));
}

/**
 * Traffic and expiry are cosmetic. Nothing here is metered, the numbers only
 * exist so the entry renders like the paid subscriptions sitting next to it.
 */
export function userinfo(env) {
  const total = Number(env.SUB_TOTAL_GB || 100) * 1024 * 1024 * 1024;
  const days = Number(env.SUB_DAYS || 30);
  // A stable pseudo-usage that creeps up over the month instead of jumping
  // around on every refresh.
  const cycle = days * 24 * 3600;
  const now = Math.floor(Date.now() / 1000);
  const expire = Math.ceil(now / cycle) * cycle;
  const elapsed = 1 - (expire - now) / cycle;
  const download = Math.floor(total * 0.11 * elapsed);
  return {
    header:
      'upload=' + Math.floor(download * 0.06) +
      '; download=' + download +
      '; total=' + total +
      '; expire=' + expire,
    expire,
  };
}

export function handleSubscription(request, env) {
  const url = new URL(request.url);
  const want = (env.SUB_PATH || '').trim();
  if (!want || url.pathname !== '/' + want.replace(/^\/+/, '')) return null;

  // ?u= selects who the subscription is for, by name or by uuid. An unknown
  // value is refused rather than quietly falling back to somebody else.
  const users = parseUsers(env);
  const key = url.searchParams.get('u');
  const user = findUser(users, key);
  if (!user) return new Response('', { status: 404 });

  const hosts = allHosts(env, url.hostname);
  const count = Math.max(1, Math.min(30, Number(url.searchParams.get('n')) || 10));
  const configs = subVariants(env, hosts, count, user);
  const info = userinfo(env);

  return new Response(JSON.stringify(configs, null, 2), {
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'subscription-userinfo': info.header,
      'profile-update-interval': env.SUB_INTERVAL || '12',
      'profile-title': 'base64:' + b64((env.SUB_NAME || 'kemkite') + ' - ' + user.name),
      'profile-web-page-url': 'https://' + url.hostname + '/',
      'cache-control': 'no-store',
    },
  });
}
