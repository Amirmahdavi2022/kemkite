// Optional personal Telegram bot. Only wakes up when TG_TOKEN, TG_OWNER and
// TG_SECRET are all set. Anything that does not carry Telegram's secret
// header gets the same 404 as any other stray request, so the endpoint does
// not stand out from the outside.

import { parseDecryption, publicFromPrivate, b64encode } from './keys.js';

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

function outbound(env, host, tag) {
  return {
    tag,
    protocol: 'vless',
    settings: {
      vnext: [
        {
          address: host,
          port: 443,
          users: [
            { id: env.UUID, encryption: clientEncryption(env.DECRYPTION), level: 0 },
          ],
        },
      ],
    },
    streamSettings: {
      network: 'ws',
      security: 'tls',
      tlsSettings: { serverName: host, allowInsecure: false, fingerprint: 'chrome' },
      wsSettings: { path: '/', headers: { Host: host } },
    },
  };
}

/**
 * All hosts in one config, with an observatory probing them and a balancer
 * picking whichever is alive. If one account or zone gets blocked the client
 * moves on by itself instead of waiting for you to notice.
 */
export function multiConfig(env, hosts) {
  const tags = hosts.map((_, i) => 'w' + (i + 1));
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
      ...hosts.map((h, i) => outbound(env, h, tags[i])),
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

export function clientConfig(env, host) {
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
      {
        tag: 'proxy',
        protocol: 'vless',
        settings: {
          vnext: [
            {
              address: host,
              port: 443,
              users: [
                {
                  id: env.UUID,
                  encryption: clientEncryption(env.DECRYPTION),
                  level: 0,
                },
              ],
            },
          ],
        },
        streamSettings: {
          network: 'ws',
          security: 'tls',
          tlsSettings: { serverName: host, allowInsecure: false },
          wsSettings: { path: '/', headers: { Host: host } },
        },
      },
      { tag: 'direct', protocol: 'freedom' },
    ],
  };
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
  '/config  one file per host, pick whichever you like',
  '/multi   all hosts in one config, auto failover',
  '/show    primary config as text',
  '/hosts   list every hostname in service',
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

  try {
    if (cmd === '/config') {
      for (const h of hosts) {
        await sendDocument(
          env,
          chatId,
          'kemkite-' + h.split('.')[0] + '.json',
          JSON.stringify(clientConfig(env, h), null, 2),
          h
        );
      }
    } else if (cmd === '/multi') {
      await sendDocument(
        env,
        chatId,
        'kemkite-multi.json',
        JSON.stringify(multiConfig(env, hosts), null, 2),
        hosts.length + ' hosts, lowest ping wins'
      );
    } else if (cmd === '/hosts') {
      await call(env, 'sendMessage', {
        chat_id: chatId,
        text: hosts.map((h, i) => (i + 1) + '. ' + h).join('\n'),
      });
    } else if (cmd === '/show') {
      const json = JSON.stringify(clientConfig(env, host), null, 2);
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
