/** A local QR transport representation, not a new handshake or trust decision.
 * Restore the original v2 JSON link before passing it to the Rust worker.
 * Nothing is fetched, stored or logged here. */
export const MAX_INVITATION_LINK_LENGTH = 2300;
export const LINK_PREFIX = "kotopizdelka://invite#";
const COMPACT_PREFIX = `${LINK_PREFIX}C2`;
const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const FIXED_BYTES = 202;
const QUICK_PROTOCOL = "KotoPizdelka.quick-invitation.v2";
const OFFER_PROTOCOL = "KotoPizdelka.invitation.v1";
const BUNDLE_PROTOCOL = "private-messenger.olm-v1.spike-1";
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

function object(value: unknown, keys: string[]): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Invalid QR structure");
  const record = value as Record<string, unknown>;
  if (Object.keys(record).length !== keys.length || keys.some(key => !Object.hasOwn(record, key))) throw new Error("Invalid QR fields");
  return record;
}

function hexBytes(value: unknown, length: number): Uint8Array {
  if (typeof value !== "string" || value.length !== length * 2 || !/^[0-9a-f]+$/.test(value)) throw new Error("Invalid QR bytes");
  return Uint8Array.from(value.match(/../g)!, pair => parseInt(pair, 16));
}

function base64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

function keyBytes(value: unknown): Uint8Array {
  if (typeof value !== "string" || !/^[A-Za-z0-9+/]{43}$/.test(value)) throw new Error("Invalid QR key");
  const bytes = Uint8Array.from(atob(value), char => char.charCodeAt(0));
  if (bytes.length !== 32 || base64(bytes).replace(/=+$/, "") !== value) throw new Error("Invalid QR key encoding");
  return bytes;
}

function base32(bytes: Uint8Array): string {
  let buffer = 0, bits = 0, result = "";
  for (const byte of bytes) {
    buffer = buffer * 256 + byte;
    bits += 8;
    while (bits >= 5) { bits -= 5; result += ALPHABET[(buffer >>> bits) & 31]; }
    buffer &= (1 << bits) - 1;
  }
  if (bits) result += ALPHABET[(buffer << (5 - bits)) & 31];
  return result;
}

function unbase32(text: string): Uint8Array {
  if (!text || !/^[A-Z2-7]+$/.test(text) || text.length > MAX_INVITATION_LINK_LENGTH) throw new Error("Invalid QR encoding");
  const result = new Uint8Array(Math.floor(text.length * 5 / 8));
  let buffer = 0, bits = 0, offset = 0;
  for (const char of text) {
    buffer = buffer * 32 + ALPHABET.indexOf(char);
    bits += 5;
    if (bits >= 8) { bits -= 8; result[offset++] = (buffer >>> bits) & 255; }
    buffer &= (1 << bits) - 1;
  }
  if (buffer !== 0 || base32(result) !== text) throw new Error("Noncanonical QR encoding");
  return result;
}

/** Existing links remain unchanged; malformed compact input fails locally. */
export function restoreQrLink(link: string): string {
  if (!link.startsWith(COMPACT_PREFIX)) return link;
  if (link.length > MAX_INVITATION_LINK_LENGTH) throw new Error("QR is too large");
  const bytes = unbase32(link.slice(COMPACT_PREFIX.length));
  if (bytes.length < FIXED_BYTES + 1) throw new Error("Truncated QR");
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const expires = view.getBigUint64(0);
  if (expires === 0n || expires > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error("Invalid QR expiry");
  const urlLength = view.getUint16(FIXED_BYTES - 2);
  if (!urlLength || bytes.length !== FIXED_BYTES + urlLength) throw new Error("Invalid QR length");
  let offset = 8;
  const take = (length: number) => { const value = bytes.subarray(offset, offset + length); offset += length; return value; };
  const hex = (length: number) => Array.from(take(length), value => value.toString(16).padStart(2, "0")).join("");
  const nonce = hex(16);
  const identity_key = base64(take(32)).replace(/=+$/, "");
  const one_time_key = base64(take(32)).replace(/=+$/, "");
  const queue_id = hex(16), token = hex(32), secret = hex(32), recipient_ticket = hex(32);
  const relay_url = decoder.decode(bytes.subarray(FIXED_BYTES));
  const value = {
    protocol: QUICK_PROTOCOL,
    offer: { protocol: OFFER_PROTOCOL, kind: "offer", nonce,
      bundle: { protocol: BUNDLE_PROTOCOL, identity_key, one_time_key },
      write: { relay_url, queue_id, token } },
    secret, recipient_ticket, expires_at: Number(expires),
  };
  const restored = LINK_PREFIX + base64(encoder.encode(JSON.stringify(value))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  if (restored.length > MAX_INVITATION_LINK_LENGTH) throw new Error("Restored QR is too large");
  return restored;
}

/** Pack only known, exactly reversible native exports. Other valid opaque
 * links retain the old QR representation, including future protocols. */
export function compactQrLink(link: string): string {
  try {
    if (!link.startsWith(LINK_PREFIX) || link.length > MAX_INVITATION_LINK_LENGTH) return link;
    const json = decoder.decode(Uint8Array.from(atob(link.slice(LINK_PREFIX.length).replace(/-/g, "+").replace(/_/g, "/")), char => char.charCodeAt(0)));
    const value = object(JSON.parse(json), ["protocol", "offer", "secret", "recipient_ticket", "expires_at"]);
    const offer = object(value.offer, ["protocol", "kind", "nonce", "bundle", "write"]);
    const bundle = object(offer.bundle, ["protocol", "identity_key", "one_time_key"]);
    const write = object(offer.write, ["relay_url", "queue_id", "token"]);
    if (value.protocol !== QUICK_PROTOCOL || offer.protocol !== OFFER_PROTOCOL || offer.kind !== "offer" || bundle.protocol !== BUNDLE_PROTOCOL || typeof write.relay_url !== "string" || typeof value.expires_at !== "number" || !Number.isSafeInteger(value.expires_at) || value.expires_at <= 0) return link;
    const url = encoder.encode(write.relay_url);
    if (!url.length || url.length > MAX_INVITATION_LINK_LENGTH) return link;
    const bytes = new Uint8Array(FIXED_BYTES + url.length);
    const view = new DataView(bytes.buffer);
    view.setBigUint64(0, BigInt(value.expires_at));
    let offset = 8;
    for (const part of [hexBytes(offer.nonce, 16), keyBytes(bundle.identity_key), keyBytes(bundle.one_time_key), hexBytes(write.queue_id, 16), hexBytes(write.token, 32), hexBytes(value.secret, 32), hexBytes(value.recipient_ticket, 32)]) {
      bytes.set(part, offset); offset += part.length;
    }
    view.setUint16(FIXED_BYTES - 2, url.length);
    bytes.set(url, FIXED_BYTES);
    const compact = COMPACT_PREFIX + base32(bytes);
    return compact.length < link.length && restoreQrLink(compact) === link ? compact : link;
  } catch { return link; }
}
