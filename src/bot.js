// Optional personal Telegram bot. Only wakes up when TG_TOKEN, TG_OWNER and
// TG_SECRET are all set. Anything that does not carry Telegram's secret
// header gets the same 404 as any other stray request, so the endpoint does
// not stand out from the outside.

import { parseDecryption, publicFromPrivate, b64encode } from './keys.js';
import { findUser, parseUsers } from './users.js';
import { serviceName } from './grpc.js';

const TG = 'https://api.telegram.org/bot';

export function botConfigured(env) {
  return Boolean(env.TG_TOKEN && env.TG_OWNER && env.TG_SECRET);
}

/** Rebuilds the client-side "encryption" value from the server key. */
export function clientEncryption(decryption) {
  const p = parseDecryption(decryption);
  const mode = decryption.split('.')[1];
  const rtt = p.secondsFrom > 0 || p.secondsTo > 0 ? '0rtt' : '1rtt';
  const pub = b64encode(publicFromPrivate(p.keys[0]));
  const padding = p.padding ? p.padding + '.' : '';
  return `mlkem768x25519plus.${mode}.${rtt}.${padding}${pub}`;
}

/** Every hostname this deployment answers on, primary first. */
export function allHosts(env, fallback) {
  const list = (env.HOSTS || '')
    .split(',')
    .map((h) => h.trim().toLowerCase())
    .filter(Boolean);
  if (fallback && !list.includes(fallback.toLowerCase())) list.unshift(fallback);
  return list.length ? list : fallback ? [fallback] : [];
}

/** Stable subscription hostnames if there are any, the proxy hosts if not. */
function subLinkHosts(env, hosts) {
  const stable = (env.SUB_HOSTS || '')
    .split(',')
    .map((h) => h.trim().toLowerCase())
    .filter(Boolean);
  return stable.length ? stable : hosts;
}

/** Transport block for one host. "grpc" needs the zone's gRPC switch on. */
export function streamFor(env, host, transport = 'ws') {
  if (transport === 'grpc') {
    return {
      network: 'grpc',
      security: 'tls',
      tlsSettings: {
        serverName: host,
        allowInsecure: false,
        fingerprint: 'chrome',
        alpn: ['h2'],
      },
      grpcSettings: { serviceName: serviceName(env), multiMode: false },
    };
  }
  return {
    network: 'ws',
    security: 'tls',
    tlsSettings: { serverName: host, allowInsecure: false, fingerprint: 'chrome' },
    wsSettings: { path: '/', headers: { Host: host } },
  };
}

/**
 * gRPC on/off, optionally per host. GRPC_SKIP lists zones whose gRPC switch
 * is still off, so they only get ws entries instead of dead grpc ones.
 */
export function grpcEnabled(env, host) {
  if (env.GRPC === '0') return false;
  if (!host) return true;
  const h = host.toLowerCase();
  return !(env.GRPC_SKIP || '')
    .split(',')
    .map((z) => z.trim().toLowerCase())
    .filter(Boolean)
    .some((z) => h === z || h.endsWith('.' + z));
}

function outbound(env, host, tag, uuid, transport = 'ws') {
  return {
    tag,
    protocol: 'vless',
    settings: {
      vnext: [
        {
          address: host,
          port: 443,
          users: [
            { id: uuid, encryption: clientEncryption(env.DECRYPTION), level: 0 },
          ],
        },
      ],
    },
    streamSettings: streamFor(env, host, transport),
  };
}

/**
 * All hosts in one config, with an observatory probing them and a balancer
 * picking whichever is alive. If one account or zone gets blocked the client
 * moves on by itself instead of waiting for you to notice.
 */
export function multiConfig(env, hosts, uuid) {
  const legs = [];
  for (const h of hosts) {
    legs.push([h, 'ws']);
    if (grpcEnabled(env, h)) legs.push([h, 'grpc']);
  }
  return {
    log: { loglevel: 'warning' },
    inbounds: [
      {
        tag: 'socks',
        port: 10808,
        listen: '127.0.0.1',
        protocol: 'socks',
        settings: { udp: true },
        sniffing: { enabled: true, destOverride: ['http', 'tls'] },
      },
    ],
    outbounds: [
      ...legs.map(([h, t], i) => outbound(env, h, 'w' + (i + 1), uuid || env.UUID, t)),
      { tag: 'direct', protocol: 'freedom' },
      { tag: 'block', protocol: 'blackhole' },
    ],
    observatory: {
      subjectSelector: ['w'],
      probeUrl: 'https://www.gstatic.com/generate_204',
      probeInterval: '5m',
      enableConcurrency: true,
    },
    routing: {
      domainStrategy: 'AsIs',
      balancers: [
        { tag: 'balance', selector: ['w'], strategy: { type: 'leastPing' } },
      ],
      rules: [{ type: 'field', network: 'tcp,udp', balancerTag: 'balance' }],
    },
  };
}

export function clientConfig(env, host, uuid, transport = 'ws') {
  const out = outbound(env, host, 'proxy', uuid || env.UUID, transport);
  return {
    log: { loglevel: 'warning' },
    inbounds: [
      {
        tag: 'socks',
        port: 10808,
        listen: '127.0.0.1',
        protocol: 'socks',
        settings: { udp: true },
        sniffing: { enabled: true, destOverride: ['http', 'tls'] },
      },
    ],
    outbounds: [out, { tag: 'direct', protocol: 'freedom' }],
  };
}

// --- adding users -----------------------------------------------------------
//
// A new user means a new line in USERS on every worker, which only takes
// effect after a redeploy. The bot can't reach Cloudflare, but it can ask
// GitHub to run the fleet deploy: it reads the current USERS secret's names,
// appends name:uuid, writes the secret back, and dispatches the workflow.
// The deploy step already reads the rest of the config from the live worker,
// so USERS is the only thing that has to change.

async function gh(env, method, path, body) {
  return fetch('https://api.github.com' + path, {
    method,
    headers: {
      Authorization: 'Bearer ' + env.GH_TOKEN,
      Accept: 'application/vnd.github+json',
      'User-Agent': 'kemkite-bot',
      'content-type': 'application/json',
    },
    body: body ? JSON.stringify(body) : undefined,
  });
}

/**
 * libsodium crypto_box_seal against the repo's base64 X25519 public key.
 * Verified byte-for-byte against PyNaCl's SealedBox before shipping.
 *   ephemeral X25519 keypair
 *   key   = HSalsa20(scalarmult(ephSec, recipientPub), zero)   [crypto_box beforenm]
 *   nonce = blake2b(ephPub || recipientPub, 24)
 *   body  = XSalsa20-Poly1305(key, nonce, message)
 *   output = base64(ephPub || body)
 */
// tweetnacl core_hsalsa20 (public domain), trimmed to the 32-byte subkey output.
function core_hsalsa20(out, inp, k, c) {
  let x0=c[0]|c[1]<<8|c[2]<<16|c[3]<<24,
      x5=c[4]|c[5]<<8|c[6]<<16|c[7]<<24,
      x10=c[8]|c[9]<<8|c[10]<<16|c[11]<<24,
      x15=c[12]|c[13]<<8|c[14]<<16|c[15]<<24,
      x1=k[0]|k[1]<<8|k[2]<<16|k[3]<<24,
      x2=k[4]|k[5]<<8|k[6]<<16|k[7]<<24,
      x3=k[8]|k[9]<<8|k[10]<<16|k[11]<<24,
      x4=k[12]|k[13]<<8|k[14]<<16|k[15]<<24,
      x6=inp[0]|inp[1]<<8|inp[2]<<16|inp[3]<<24,
      x7=inp[4]|inp[5]<<8|inp[6]<<16|inp[7]<<24,
      x8=inp[8]|inp[9]<<8|inp[10]<<16|inp[11]<<24,
      x9=inp[12]|inp[13]<<8|inp[14]<<16|inp[15]<<24,
      x11=k[16]|k[17]<<8|k[18]<<16|k[19]<<24,
      x12=k[20]|k[21]<<8|k[22]<<16|k[23]<<24,
      x13=k[24]|k[25]<<8|k[26]<<16|k[27]<<24,
      x14=k[28]|k[29]<<8|k[30]<<16|k[31]<<24;
  let u;
  for (let i=0;i<20;i+=2){
    u=x0+x12|0; x4^=u<<7|u>>>25; u=x4+x0|0; x8^=u<<9|u>>>23;
    u=x8+x4|0; x12^=u<<13|u>>>19; u=x12+x8|0; x0^=u<<18|u>>>14;
    u=x5+x1|0; x9^=u<<7|u>>>25; u=x9+x5|0; x13^=u<<9|u>>>23;
    u=x13+x9|0; x1^=u<<13|u>>>19; u=x1+x13|0; x5^=u<<18|u>>>14;
    u=x10+x6|0; x14^=u<<7|u>>>25; u=x14+x10|0; x2^=u<<9|u>>>23;
    u=x2+x14|0; x6^=u<<13|u>>>19; u=x6+x2|0; x10^=u<<18|u>>>14;
    u=x15+x11|0; x3^=u<<7|u>>>25; u=x3+x15|0; x7^=u<<9|u>>>23;
    u=x7+x3|0; x11^=u<<13|u>>>19; u=x11+x7|0; x15^=u<<18|u>>>14;
    u=x0+x3|0; x1^=u<<7|u>>>25; u=x1+x0|0; x2^=u<<9|u>>>23;
    u=x2+x1|0; x3^=u<<13|u>>>19; u=x3+x2|0; x0^=u<<18|u>>>14;
    u=x5+x4|0; x6^=u<<7|u>>>25; u=x6+x5|0; x7^=u<<9|u>>>23;
    u=x7+x6|0; x4^=u<<13|u>>>19; u=x4+x7|0; x5^=u<<18|u>>>14;
    u=x10+x9|0; x11^=u<<7|u>>>25; u=x11+x10|0; x8^=u<<9|u>>>23;
    u=x8+x11|0; x9^=u<<13|u>>>19; u=x9+x8|0; x10^=u<<18|u>>>14;
    u=x15+x14|0; x12^=u<<7|u>>>25; u=x12+x15|0; x13^=u<<9|u>>>23;
    u=x13+x12|0; x14^=u<<13|u>>>19; u=x14+x13|0; x15^=u<<18|u>>>14;
  }
  const o=[x0,x5,x10,x15,x6,x7,x8,x9];
  for(let i=0;i<8;i++){ out[4*i]=o[i]&0xff; out[4*i+1]=o[i]>>>8&0xff; out[4*i+2]=o[i]>>>16&0xff; out[4*i+3]=o[i]>>>24&0xff; }
}
function boxKey(shared){
  const sigma=new TextEncoder().encode('expand 32-byte k');
  const out=new Uint8Array(32);
  core_hsalsa20(out, new Uint8Array(16), shared, sigma);
  return out;
}

async function sealedBox(message, recipientPubB64) {
  const { x25519 } = await import('@noble/curves/ed25519.js');
  const { xsalsa20poly1305 } = await import('@noble/ciphers/salsa.js');
  const { blake2b } = await import('@noble/hashes/blake2.js');
  const pub = Uint8Array.from(atob(recipientPubB64), (c) => c.charCodeAt(0));
  const ephSec = x25519.utils.randomSecretKey();
  const ephPub = x25519.getPublicKey(ephSec);
  const shared = x25519.getSharedSecret(ephSec, pub);
  const key = boxKey(shared);
  const nonce = blake2b(new Uint8Array([...ephPub, ...pub]), { dkLen: 24 });
  const body = xsalsa20poly1305(key, nonce).encrypt(new TextEncoder().encode(message));
  const out = new Uint8Array(ephPub.length + body.length);
  out.set(ephPub);
  out.set(body, ephPub.length);
  return btoa(String.fromCharCode(...out));
}

export function __boxKeyHex(sharedHex) {
  const shared = Uint8Array.from(sharedHex.match(/../g).map((h) => parseInt(h, 16)));
  return [...boxKey(shared)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function ghConfigured(env) {
  return Boolean(env.GH_TOKEN && env.GH_REPO && env.GH_WORKFLOW);
}

/**
 * The USERS line with one person added or taken out. "main" (env.UUID) is
 * never part of it. An empty result is written as "-": GitHub treats an
 * empty secret as unset and the deploy would fall back to the old list, so
 * the removal would silently not happen. parseUsers skips "-" as malformed.
 */
export function usersLine(users, { add, remove } = {}) {
  let list = users.filter((u) => u.name !== 'main');
  if (remove) list = list.filter((u) => u.uuid.toLowerCase() !== remove.uuid.toLowerCase());
  const parts = list.map((u) => u.name + ':' + u.uuid);
  if (add) parts.push(add.name + ':' + add.uuid);
  return parts.length ? parts.join(',') : '-';
}

/**
 * Writes the USERS secret and triggers the fleet deploy.
 * Returns true if the workflow dispatch was accepted.
 */
async function writeUsers(env, line) {
  // Encrypt USERS against the repo public key (libsodium sealed box).
  const keyRes = await gh(env, 'GET', '/repos/' + env.GH_REPO + '/actions/secrets/public-key');
  if (!keyRes.ok) return false;
  const { key, key_id } = await keyRes.json();
  const sealed = await sealedBox(line, key);
  const put = await gh(env, 'PUT', '/repos/' + env.GH_REPO + '/actions/secrets/WORKER_USERS', {
    encrypted_value: sealed,
    key_id,
  });
  if (!put.ok) return false;

  const disp = await gh(env, 'POST',
    '/repos/' + env.GH_REPO + '/actions/workflows/' + env.GH_WORKFLOW + '/dispatches',
    { ref: env.GH_REF || 'main', inputs: { mode: 'fleet' } });
  return disp.ok;
}

async function call(env, method, body) {
  return fetch(TG + env.TG_TOKEN + '/' + method, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
}

async function sendDocument(env, chatId, filename, text, caption) {
  const form = new FormData();
  form.append('chat_id', String(chatId));
  if (caption) form.append('caption', caption);
  form.append(
    'document',
    new Blob([text], { type: 'application/json' }),
    filename
  );
  return fetch(TG + env.TG_TOKEN + '/sendDocument', {
    method: 'POST',
    body: form,
  });
}

const HELP = [
  'kemkite is up.',
  '',
  '/adduser <name>  make a new user and redeploy, then hand back their links',
  '/deluser <name>  cut a user off everywhere (name or uuid), then redeploy',
  '/config  one file per host (ws, and grpc when it is on)',
  '',
  'Add a name to any of those to pick a user, e.g. /sub ali',
  '/multi   all hosts in one config, auto failover',
  '/sub     subscription links, ten variants each',
  '/show    primary config as text',
  '/hosts   list every hostname in service',
  '/users   who has a uuid on this deployment',
  '/help    this message',
  '',
  'The encryption value cannot travel in a vless:// link, so import',
  'the JSON. In v2rayNG use + then Custom Config, not the link import.',
].join('\n');

export async function handleUpdate(request, env) {
  if (request.headers.get('x-telegram-bot-api-secret-token') !== env.TG_SECRET) {
    return null; // caller falls through to the ordinary 404
  }

  let update;
  try {
    update = await request.json();
  } catch {
    return new Response('ok');
  }

  const msg = update.message || update.edited_message;
  if (!msg || !msg.text) return new Response('ok');

  // Personal bot: one owner, everyone else is ignored silently.
  if (String(msg.from?.id) !== String(env.TG_OWNER)) return new Response('ok');

  const chatId = msg.chat.id;
  const cmd = msg.text.trim().split(/\s+/)[0].split('@')[0].toLowerCase();
  const host = env.HOST || new URL(request.url).hostname;
  const hosts = allHosts(env, host);
  const users = parseUsers(env);
  const arg = msg.text.trim().split(/\s+/)[1];
  const who = findUser(users, arg) || users[0];

  // A bare name typed right after /adduser (or after being asked) is treated
  // as the new user's name.
  const pending = cmd === '/adduser';
  const nameArg = pending ? arg : (env._awaitName ? cmd.replace(/^\//, '') : null);

  try {
    if (cmd === '/adduser' || cmd === '/newuser') {
      if (!ghConfigured(env)) {
        await call(env, 'sendMessage', { chat_id: chatId, text: 'adding users needs GH_TOKEN, GH_REPO and GH_WORKFLOW set on the worker.' });
        return new Response('ok');
      }
      if (!arg) {
        await call(env, 'sendMessage', { chat_id: chatId, text: 'send: /adduser <name>   e.g. /adduser ali' });
        return new Response('ok');
      }
      const clean = arg.replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 24);
      if (!clean) {
        await call(env, 'sendMessage', { chat_id: chatId, text: 'that name has no usable characters, try letters or numbers' });
        return new Response('ok');
      }
      if (users.some((u) => u.name.toLowerCase() === clean.toLowerCase())) {
        await call(env, 'sendMessage', { chat_id: chatId, text: 'there is already a user called ' + clean });
        return new Response('ok');
      }
      const uuid = crypto.randomUUID();
      await call(env, 'sendMessage', { chat_id: chatId, text: 'adding ' + clean + ' and redeploying, this takes a minute...' });
      const ok = await writeUsers(env, usersLine(users, { add: { name: clean, uuid } }));
      if (ok) {
        const subs = subLinkHosts(env, hosts)
          .map((h) => 'https://' + h + '/' + env.SUB_PATH + '?u=' + uuid)
          .join('\n\n');
        await call(env, 'sendMessage', {
          chat_id: chatId,
          text: clean + ' is being added. In about a minute their links work:\n\n' + subs +
            '\n\nuuid: ' + uuid + '\n\nGive them at least two of the links.',
          disable_web_page_preview: true,
        });
      } else {
        await call(env, 'sendMessage', { chat_id: chatId, text: "couldn't kick off the deploy, check the worker's GH settings" });
      }
    } else if (cmd === '/deluser' || cmd === '/removeuser' || cmd === '/revoke') {
      if (!ghConfigured(env)) {
        await call(env, 'sendMessage', { chat_id: chatId, text: 'removing users needs GH_TOKEN, GH_REPO and GH_WORKFLOW set on the worker.' });
        return new Response('ok');
      }
      // No default here on purpose: a bare /deluser must never pick someone.
      const target = arg ? findUser(users, arg) : null;
      if (!arg) {
        await call(env, 'sendMessage', {
          chat_id: chatId,
          text: 'send: /deluser <name>   e.g. /deluser ali\n\n' +
            users.filter((u) => u.name !== 'main').map((u) => '/deluser ' + u.name).join('\n'),
        });
      } else if (!target) {
        await call(env, 'sendMessage', { chat_id: chatId, text: 'no user called ' + arg + ', see /users' });
      } else if (target.name === 'main') {
        await call(env, 'sendMessage', { chat_id: chatId, text: "main is the deployment's own uuid and can't be removed from here" });
      } else {
        await call(env, 'sendMessage', { chat_id: chatId, text: 'removing ' + target.name + ' and redeploying, this takes a minute...' });
        const ok = await writeUsers(env, usersLine(users, { remove: target }));
        await call(env, 'sendMessage', {
          chat_id: chatId,
          text: ok
            ? target.name + ' is being removed. In about a minute their uuid stops working on every host and their subscription links return nothing.\n\nCheck with /users once it is done.'
            : "couldn't kick off the deploy, check the worker's GH settings",
        });
      }
    } else if (cmd === '/users') {
      await call(env, 'sendMessage', {
        chat_id: chatId,
        text: users.map((u, i) => (i + 1) + '. ' + u.name + '\n   ' + u.uuid).join('\n'),
      });
    } else if (cmd === '/config') {
      for (const h of hosts) {
        await sendDocument(
          env,
          chatId,
          'kemkite-' + who.name + '-' + h.split('.')[0] + '.json',
          JSON.stringify(clientConfig(env, h, who.uuid), null, 2),
          who.name + ' - ' + h + ' (ws)'
        );
        if (grpcEnabled(env, h)) {
          await sendDocument(
            env,
            chatId,
            'kemkite-' + who.name + '-' + h.split('.')[0] + '-grpc.json',
            JSON.stringify(clientConfig(env, h, who.uuid, 'grpc'), null, 2),
            who.name + ' - ' + h + ' (grpc)'
          );
        }
      }
    } else if (cmd === '/multi') {
      await sendDocument(
        env,
        chatId,
        'kemkite-multi.json',
        JSON.stringify(multiConfig(env, hosts, who.uuid), null, 2),
        who.name + ' - ' + hosts.length + ' hosts, lowest ping wins'
      );
    } else if (cmd === '/sub') {
      if (!env.SUB_PATH) {
        await call(env, 'sendMessage', { chat_id: chatId, text: 'no subscription path is set' });
      } else {
        await call(env, 'sendMessage', {
          chat_id: chatId,
          text:
            who.name +
            '\n\n' +
            subLinkHosts(env, hosts)
              .map((h) => 'https://' + h + '/' + env.SUB_PATH + '?u=' + who.uuid)
              .join('\n\n') +
            (env.SUB_HOSTS
              ? '\n\nAdd all of them. Each one is on a different account, and they stay the same when the proxy hostnames rotate.'
              : ''),
          disable_web_page_preview: true,
        });
      }
    } else if (cmd === '/hosts') {
      await call(env, 'sendMessage', {
        chat_id: chatId,
        text: hosts.map((h, i) => (i + 1) + '. ' + h).join('\n'),
      });
    } else if (cmd === '/show') {
      const json = JSON.stringify(clientConfig(env, host, who.uuid), null, 2);
      await call(env, 'sendMessage', {
        chat_id: chatId,
        text: '```json\n' + json + '\n```',
        parse_mode: 'Markdown',
      });
    } else if (cmd === '/host') {
      await call(env, 'sendMessage', { chat_id: chatId, text: host });
    } else {
      await call(env, 'sendMessage', { chat_id: chatId, text: HELP });
    }
  } catch {
    await call(env, 'sendMessage', {
      chat_id: chatId,
      text: 'something went wrong handling that',
    }).catch(() => {});
  }

  return new Response('ok');
}
