// Several people on one deployment.
//
// USERS is "name:uuid,name:uuid". UUID on its own still works and becomes
// the user called "main", so an existing single-user deployment keeps
// running untouched after an upgrade.
//
// Every user shares the same server key. What they get is a separate UUID,
// which means you can hand one out, see it turn up, and revoke it later
// without touching anybody else. It is not metering and it is not isolation.

import { parseUUID, uuidEquals } from './vless.js';

export function parseUsers(env) {
  const users = [];
  const seen = new Set();

  const add = (name, uuid) => {
    const clean = uuid.trim();
    if (!clean || seen.has(clean.toLowerCase())) return;
    let bytes;
    try {
      bytes = parseUUID(clean);
    } catch {
      return; // a malformed entry should not take the whole list down
    }
    seen.add(clean.toLowerCase());
    users.push({ name: name.trim() || 'user' + (users.length + 1), uuid: clean, bytes });
  };

  if (env.UUID) add('main', env.UUID);
  for (const entry of (env.USERS || '').split(',')) {
    if (!entry.trim()) continue;
    const i = entry.indexOf(':');
    if (i === -1) add('user' + (users.length + 1), entry);
    else add(entry.slice(0, i), entry.slice(i + 1));
  }
  return users;
}

/** The user this uuid belongs to, or null if nobody owns it. */
export function findByUUID(users, bytes) {
  for (const u of users) if (uuidEquals(u.bytes, bytes)) return u;
  return null;
}

/** Looks a user up by name or by full uuid, case-insensitively. */
export function findUser(users, key) {
  if (!key) return users[0] || null;
  const k = String(key).trim().toLowerCase();
  return (
    users.find((u) => u.name.toLowerCase() === k) ||
    users.find((u) => u.uuid.toLowerCase() === k) ||
    null
  );
}
