import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";
import { transform } from "esbuild";
import jsQR from "jsqr";
import { createHash } from "node:crypto";

const require = createRequire(import.meta.url);
const compactSource = await readFile(new URL("../src/compactInvitation.ts", import.meta.url), "utf8");
const compactCompiled = await transform(compactSource, { loader: "ts", format: "esm", target: "es2022" });
const compactModule = `data:text/javascript;base64,${Buffer.from(compactCompiled.code).toString("base64")}`;
const { compactQrLink, restoreQrLink } = await import(compactModule);
const input = (await readFile(new URL("../src/invitationLink.ts", import.meta.url), "utf8"))
  .replaceAll('from "./compactInvitation"', `from ${JSON.stringify(compactModule)}`)
  .replace('from "qrcode"', `from ${JSON.stringify(pathToFileURL(require.resolve("qrcode")).href)}`);
const compiled = await transform(input, { loader: "ts", format: "esm", target: "es2022" });
const { normalizeInvitationLink, invitationQr, invitationQrDisplaySize, MAX_INVITATION_LINK_LENGTH } = await import(`data:text/javascript;base64,${Buffer.from(compiled.code).toString("base64")}`);
const link = `kotopizdelka://invite#${Buffer.from(JSON.stringify({ v: 2, secret: "test-only-secret", relay: "https://relay.example" })).toString("base64url")}`;

test("invitation fragment stays opaque and preserves base64url case after surrounding whitespace", () => {
  assert.equal(normalizeInvitationLink(` \n${link}\t `), link);
  assert.equal(normalizeInvitationLink("kotopizdelka://invite#AbCd_ef-123"), "kotopizdelka://invite#AbCd_ef-123");
});

test("invitation links reject other origins, query strings, percent escapes, controls and empty/oversized fragments", () => {
  for (const invalid of ["javascript:alert(1)", "https://relay.example/invite#AbCd", "kotopizdelka://evil#AbCd", "kotopizdelka://invite/#AbCd", "kotopizdelka://invite?secret=AbCd", "kotopizdelka://invite#", "kotopizdelka://invite#%41", "kotopizdelka://invite#Ab\nCd", "kotopizdelka://invite#кот", "kotopizdelka://invite#<svg>", "kotopizdelka://invite#AbCd/123", `kotopizdelka://invite#${"a".repeat(MAX_INVITATION_LINK_LENGTH)}`]) {
    assert.throws(() => normalizeInvitationLink(invalid));
  }
});

function decodeRenderedPath(qr, scale = 5) {
  assert.match(qr.path, /^(?:M\d+ \d+h1v1h-1z)+$/);
  const width = qr.size * scale;
  const pixels = new Uint8ClampedArray(width * width * 4).fill(255);
  for (const cell of qr.path.matchAll(/M(\d+) (\d+)h1v1h-1z/g)) {
    const x = Number(cell[1]), y = Number(cell[2]);
    assert.ok(x >= 4 && y >= 4 && x < qr.size - 4 && y < qr.size - 4);
    for (let dy = 0; dy < scale; dy++) for (let dx = 0; dx < scale; dx++) {
      const at = ((y * scale + dy) * width + x * scale + dx) * 4;
      pixels[at] = pixels[at + 1] = pixels[at + 2] = 0;
    }
  }
  const decoded = jsQR(pixels, width, width, { inversionAttempts: "dontInvert" })?.data;
  return decoded === undefined ? undefined : normalizeInvitationLink(decoded);
}

test("independent QR decoder recovers exact invitation from rendered SVG coordinates", () => {
  assert.equal(decodeRenderedPath(invitationQr(link)), link);
  const large = `kotopizdelka://invite#${Buffer.from("0123456789abcdef".repeat(65)).toString("base64url")}`;
  assert.equal(decodeRenderedPath(invitationQr(large)), large);
});

test("maximum valid invitation fits QR M capacity while oversized input is rejected before QR work", () => {
  const maximum = `kotopizdelka://invite#${"a".repeat(MAX_INVITATION_LINK_LENGTH - "kotopizdelka://invite#".length)}`;
  assert.equal(normalizeInvitationLink(maximum), maximum);
  assert.equal(decodeRenderedPath(invitationQr(maximum)), maximum);
  assert.throws(() => invitationQr(`${maximum}a`));
});

function realShapeLink(seed) {
  const bytes = name => createHash("sha256").update(`QR fixture ${seed} ${name}`).digest();
  const hex = name => bytes(name).toString("hex");
  const key = name => bytes(name).toString("base64").replace(/=+$/, "");
  const invitation = {
    protocol: "KotoPizdelka.quick-invitation.v2",
    offer: {
      protocol: "KotoPizdelka.invitation.v1", kind: "offer", nonce: hex("nonce").slice(0, 32),
      bundle: { protocol: "private-messenger.olm-v1.spike-1", identity_key: key("identity"), one_time_key: key("one-time") },
      write: { relay_url: "https://relay.000000000000.example.invalid", queue_id: hex("queue").slice(0, 32), token: hex("write") },
    },
    secret: hex("secret"), recipient_ticket: hex("ticket"), expires_at: 1791208800,
  };
  return `kotopizdelka://invite#${Buffer.from(JSON.stringify(invitation)).toString("base64url")}`;
}

test("full invitation QR uses whole screen pixels per module at display scaling and viewport bounds", () => {
  const fixtures = [realShapeLink("one"), realShapeLink("two"), realShapeLink("three"), `kotopizdelka://invite#${"a".repeat(MAX_INVITATION_LINK_LENGTH - "kotopizdelka://invite#".length)}`];
  const boxes = [{ width: 764, height: 700 }, { width: 764, height: 520 }, { width: 306, height: 700 }, { width: 306, height: 320 }];
  for (const value of fixtures) {
    const qr = invitationQr(value);
    assert.ok(value.length >= 966, "fixture contains the full invitation structure");
    for (const box of boxes) for (const ratio of [1, 1.25, 1.5, 3]) for (const enlarged of [false, true]) {
      const width = invitationQrDisplaySize(qr.size, box.width, box.height, ratio, enlarged);
      const pitch = width * ratio / qr.size;
      assert.ok(Math.abs(pitch - Math.round(pitch)) < 1e-6);
      assert.ok(width > 0 && width <= box.width + 1e-6 && width <= box.height + 1e-6);
      assert.ok(width <= (enlarged ? 750 : 500) + 1e-6);
      assert.equal(decodeRenderedPath(qr, Math.round(pitch)), value);
    }
  }
});

test("compact full invitation preserves the exact exported URI while reducing QR density", () => {
  for (const seed of ["one", "two", "three"]) {
    const original = realShapeLink(seed);
    const packed = compactQrLink(original);
    assert.equal(original.length, 966);
    assert.equal(packed.length, 415);
    assert.match(packed, /^kotopizdelka:\/\/invite#C2[A-Z2-7]+$/);
    assert.equal(restoreQrLink(packed), original);
    assert.equal(normalizeInvitationLink(packed), original);
    assert.equal(invitationQr(original).size, 77); // Version 13 plus quiet zone.
    assert.equal(decodeRenderedPath(invitationQr(original), 3), original);
  }
});

test("compact QR rejects invalid lengths, expiry, UTF-8 and noncanonical Base32", () => {
  const packed = compactQrLink(realShapeLink("one"));
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const encode = bytes => {
    let value = 0n, bits = 0, out = "";
    for (const byte of bytes) {
      value = value * 256n + BigInt(byte); bits += 8;
      while (bits >= 5) { bits -= 5; out += alphabet[Number((value >> BigInt(bits)) & 31n)]; }
      value &= (1n << BigInt(bits)) - 1n;
    }
    if (bits) out += alphabet[Number(value << BigInt(5 - bits))];
    return `kotopizdelka://invite#C2${out}`;
  };
  const read = text => {
    let value = 0n, bits = 0; const out = [];
    for (const char of text.slice("kotopizdelka://invite#C2".length)) {
      value = value * 32n + BigInt(alphabet.indexOf(char)); bits += 5;
      if (bits >= 8) { bits -= 8; out.push(Number((value >> BigInt(bits)) & 255n)); }
      value &= (1n << BigInt(bits)) - 1n;
    }
    return Buffer.from(out);
  };
  const lowercaseBody = "kotopizdelka://invite#C2" + packed.slice("kotopizdelka://invite#C2".length).toLowerCase();
  for (const bad of [packed.slice(0, -1), `${packed}A`, lowercaseBody, "kotopizdelka://invite#C2A", "kotopizdelka://invite#C2="]) assert.throws(() => normalizeInvitationLink(bad));
  const bytes = read(packed);
  for (const mutation of [
    copy => copy.fill(0, 0, 8),
    copy => copy.fill(255, 0, 8),
    copy => copy.writeUInt16BE(1, 200),
    copy => { copy[202] = 255; },
  ]) { const copy = Buffer.from(bytes); mutation(copy); assert.throws(() => restoreQrLink(encode(copy))); }
  assert.throws(() => restoreQrLink(encode(Buffer.concat([bytes, Buffer.from([0])]))));
});

test("unknown, noncanonical and nonpackable exports retain their original QR payload", () => {
  const original = realShapeLink("one");
  const value = JSON.parse(Buffer.from(original.split("#")[1], "base64url").toString());
  const uri = object => `kotopizdelka://invite#${Buffer.from(JSON.stringify(object)).toString("base64url")}`;
  assert.equal(compactQrLink(link), link);
  for (const change of [
    object => { object.protocol = "future.protocol"; },
    object => { object.offer.extra = "unknown"; },
    object => { object.expires_at = Number.MAX_SAFE_INTEGER + 1; },
    object => { object.offer.bundle.identity_key += "="; },
  ]) { const copy = structuredClone(value); change(copy); const text = uri(copy); assert.equal(compactQrLink(text), text); }
  const reordered = uri({ expires_at: value.expires_at, secret: value.secret, recipient_ticket: value.recipient_ticket, offer: value.offer, protocol: value.protocol });
  assert.equal(compactQrLink(reordered), reordered);
});

test("QR display sizing does not force a larger or fractional code into a tiny or invalid viewport", () => {
  assert.equal(invitationQrDisplaySize(125, 100, 100, 1), 0);
  for (const invalid of [0, -1, Number.NaN, Number.POSITIVE_INFINITY]) {
    assert.equal(invitationQrDisplaySize(125, invalid, 600, 1), 0);
    assert.equal(invitationQrDisplaySize(125, 600, invalid, 1), 0);
    assert.equal(invitationQrDisplaySize(125, 600, 600, invalid), 0);
  }
  assert.equal(invitationQrDisplaySize(125, 750, 700, 1), 500);
  assert.equal(invitationQrDisplaySize(125, 750, 700, 1, true), 625);
});
