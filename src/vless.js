// The inner VLESS request, unchanged by the encryption layer:
//
//   version(1) uuid(16) addonsLen(1) addons cmd(1) port(2) atyp(1) addr payload
//
// The response is just version(1) 00 followed by the stream.

export const CMD_TCP = 1;
export const CMD_UDP = 2;
export const CMD_MUX = 3;

export function parseUUID(s) {
  const hex = s.replace(/-/g, '');
  if (hex.length !== 32) throw new Error('bad uuid');
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

/**
 * @param {Uint8Array} buf - the accumulated head of the decrypted stream
 * @returns {{version,uuid,command,port,address,addressType,offset}|null}
 *          null means "not enough bytes yet, call again with more"
 */
export function parseRequest(buf) {
  if (buf.length < 24) return null;
  const version = buf[0];
  const uuid = buf.subarray(1, 17);
  const addonsLen = buf[17];
  let i = 18 + addonsLen;
  if (buf.length < i + 4) return null;

  const command = buf[i++];
  const port = (buf[i] << 8) | buf[i + 1];
  i += 2;
  const addressType = buf[i++];

  let address;
  if (addressType === 1) {
    if (buf.length < i + 4) return null;
    address = Array.from(buf.subarray(i, i + 4)).join('.');
    i += 4;
  } else if (addressType === 2) {
    if (buf.length < i + 1) return null;
    const n = buf[i++];
    if (buf.length < i + n) return null;
    address = new TextDecoder().decode(buf.subarray(i, i + n));
    i += n;
  } else if (addressType === 3) {
    if (buf.length < i + 16) return null;
    const parts = [];
    for (let j = 0; j < 8; j++) {
      parts.push(((buf[i + j * 2] << 8) | buf[i + j * 2 + 1]).toString(16));
    }
    address = parts.join(':');
    i += 16;
  } else {
    throw new Error('unknown address type: ' + addressType);
  }

  return { version, uuid, command, port, address, addressType, offset: i };
}

export function responseHeader(version) {
  return new Uint8Array([version, 0]);
}

export function uuidEquals(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
