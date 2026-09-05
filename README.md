# kemkite

A VLESS server for Cloudflare Workers that speaks **VLESS Encryption** — the post-quantum layer Xray added in 2025 (`mlkem768x25519plus`).

Every other VLESS-on-Workers project I could find still runs `encryption=none`. That's fine when your TLS ends at your own box, but on Workers it doesn't: TLS terminates at Cloudflare's edge, so the VLESS header, your UUID and every destination you visit are plaintext to the CDN sitting in the middle. kemkite closes that gap. The tunnel is encrypted between your client and the Worker itself, and Cloudflare only sees bytes it can't read.

Written from scratch in JavaScript against the Go reference in `Xray-core/proxy/vless/encryption`, and tested against the real Xray client, not a mock.

---

## What it does

```
client  ──TLS──►  Cloudflare edge  ──►  your Worker  ──►  internet
        └──────── VLESS Encryption ────┘
                  (CF can't read this part)
```

Two key exchanges are stacked. The long-term one is the key in your config, and the ephemeral one is fresh per connection, so a recorded session stays unreadable even if the config leaks later. The ephemeral half is ML-KEM-768 + X25519 both, so "harvest now, decrypt later" doesn't work on it.

Supported:

| | |
|---|---|
| Auth | ML-KEM-768 (post-quantum) or X25519 |
| Appearance | `native`, `xorpub`, `random` |
| Resume | 1-RTT, and 0-RTT tickets |
| Ciphers | AES-256-GCM and ChaCha20-Poly1305, picked by the client |
| Transport | WebSocket |
| Traffic | TCP, plus UDP/53 over DoH so VPN-mode DNS works |
| Extras | multiple users, a subscription endpoint, an optional Telegram bot |

## Quick start

```bash
git clone https://github.com/Amirmahdavi2022/kemkite
cd kemkite && npm install

# generate a matching pair
npm run keys -- mlkem768 random 600
```

Put the `DECRYPTION` value and a UUID in `wrangler.toml`:

```toml
[vars]
UUID = "your-uuid-here"
DECRYPTION = "mlkem768x25519plus.random.600s.…"
```

Deploy with `npx wrangler deploy`, then point a client at it:

```json
{
  "protocol": "vless",
  "settings": { "vnext": [{
    "address": "your-worker.workers.dev",
    "port": 443,
    "users": [{ "id": "your-uuid-here", "encryption": "mlkem768x25519plus.random.0rtt.…" }]
  }]},
  "streamSettings": {
    "network": "ws",
    "security": "tls",
    "wsSettings": { "path": "/" }
  }
}
```

Requires Xray-core 25.x or newer on the client. **The `encryption` value cannot travel in a `vless://` share link** — it's not one of the URL fields, so clients silently drop it and you get a connection that imports fine and then does nothing. Import full JSON. In v2rayNG that means `+` then Custom Config, not the link import.

## Which mode should I pick

- `native` — records look like TLS 1.3 application data (`17 03 03 …`). Reasonable if you're already behind real TLS.
- `xorpub` — same, but the public keys in the handshake are masked so they don't stand out as key material.
- `random` — the record headers are masked too, so the stream is uniformly random from the first byte. This is the one to use if you care about a DPI box that fingerprints nested TLS.

`random` costs nothing measurable. It's the default in `npm run keys`.

## How resistant is this, honestly

What it fixes: Cloudflare, or anyone who compromises the edge, can no longer read your traffic or see where it's going. Recorded traffic can't be decrypted later, including by a quantum computer. Replayed handshakes are rejected.

What it does **not** fix:

- Your hostname still travels in cleartext SNI on every connection. If the domain gets listed, this changes nothing.
- REALITY is impossible on Workers, because the TLS handshake isn't yours. The best you can look like is an ordinary Cloudflare customer.
- Running a proxy on Workers is against Cloudflare's terms and accounts have been suspended for it.
So it's a real improvement to one specific layer, and it isn't a magic bullet. Encryption and blocking are different problems, and this one only solves the first. Pick your domain strategy separately.

## More than one person

Set `USERS` to `name:uuid,name:uuid`. `UUID` on its own still works and becomes the user called `main`, so upgrading a single-user deployment changes nothing.

```toml
USERS = "ali:0f8d…,reza:6b21…"
```

Each person gets their own UUID and their own subscription link, which means you can hand one out, watch it turn up, and revoke it later without disturbing anyone else. Be clear about what that is and isn't: everyone shares the same server key, nothing is metered, and one user's traffic is not isolated from another's. It's revocable identity, not a billing system.

## Subscription

Set `SUB_PATH` to something unguessable and the Worker serves a subscription at `https://host/<SUB_PATH>?u=<name-or-uuid>`.

It returns the JSON form, an array of complete configs, which is what Happ and v2rayN read. A base64 link list can't work here for the reason above. Ten entries by default, spread across every hostname you've deployed, the Cloudflare TLS ports (443, 8443, 2053, 2083, 2087, 2096) and a few paths, some with early data. They're ten genuinely different routes, not ten copies. `?n=` changes the count.

The response carries `Subscription-Userinfo`, `Profile-Title` and `Profile-Update-Interval`, so the entry renders with a name, a traffic bar and an expiry date like any other subscription. **Those numbers are cosmetic.** Nothing is counted. They exist so the entry doesn't look out of place next to the others, and `SUB_TOTAL_GB` and `SUB_DAYS` control what they say.

## Optional Telegram bot

Set `TG_TOKEN`, `TG_OWNER` and `TG_SECRET` and the same Worker also serves a webhook, so you can pull configs onto a phone without sitting at a desk.

```
/config [user]   one importable file per host
/multi  [user]   every host in one config with automatic failover
/sub    [user]   subscription links
/users           who has a uuid here
/hosts           every hostname in service
```

`/multi` is worth explaining: it writes an observatory that probes each host every five minutes and a `leastPing` balancer that picks between them. Deploy the same Worker to several accounts and a blocked domain or a suspended account stops being an outage, because the client moves on by itself.

Only the owner id is answered. A POST without Telegram's secret header gets the same 404 as any other stray request, so the endpoint doesn't stand out. Leave the three settings unset and none of this code runs.

## Tests

```bash
npm test     # 50 offline tests
```

The interop testing that matters was done against the actual `xray` binary (v26.3.27) driving a SOCKS inbound through the tunnel, 400 KB checked byte-for-byte on every combination:

| auth | mode | resume | |
|---|---|---|---|
| mlkem768 | native | 1-RTT | pass |
| x25519 | native | 1-RTT | pass |
| mlkem768 | xorpub | 1-RTT | pass |
| mlkem768 | random | 1-RTT | pass |
| x25519 | random | 1-RTT | pass |
| mlkem768 | native | 0-RTT | pass |
| x25519 | xorpub | 0-RTT | pass |

Same thing again over WebSocket inside the real Workers runtime via `wrangler dev`, and then on a deployed Worker behind a real hostname.

One bug worth mentioning, since it's the kind of thing that only shows up in interop: `random` mode was completely dead at first because the AES-CTR helper rounded its keystream to 16-byte blocks. Record headers are 5 bytes, so everything after the first one desynced. Unit tests were perfectly happy. The real client was not.

## A note on 0-RTT

The server keeps resumption tickets in memory. On Workers that memory belongs to one isolate, and a later connection often lands on a different one, so most tickets won't be found and the client quietly falls back to a full handshake. It works, it just doesn't save you anything. Until there's a Durable Object behind it, generate keys with `0` seconds and stay on 1-RTT.

## Layout

```
src/framing.js       record header, lengths, nonce
src/aead.js          blake3 derive_key, AES-GCM / ChaCha20, AES-CTR
src/stream.js        byte stream over any transport
src/conn.js          record layer, chunking and rekey
src/keys.js          key strings and generation
src/server.js        the handshake
src/vless.js         inner VLESS request
src/users.js         the uuid set
src/subscription.js  subscription endpoint
src/bot.js           optional telegram webhook
src/worker.js        the Worker
```

## Credit

The protocol is RPRX's work in [Xray-core](https://github.com/XTLS/Xray-core) ([PR #5067](https://github.com/XTLS/Xray-core/pull/5067)). This is an independent server-side implementation of it. Crypto primitives come from [@noble](https://github.com/paulmillr/noble-hashes).

MIT.
