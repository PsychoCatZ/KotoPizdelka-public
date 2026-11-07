// Synthetic, expired invitation for the ZXing rotation regression test.
// No real server, tickets, identity or private keys are used.
const QRCode = require('qrcode');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const seed = 26;
const key = byte => Buffer.alloc(32, byte).toString('base64').replace(/=+$/, '');
const value = {
  protocol: 'KotoPizdelka.quick-invitation.v2',
  offer: {
    protocol: 'KotoPizdelka.invitation.v1', kind: 'offer', nonce: crypto.createHash('sha256').update(`PUBLIC QR FIXTURE ${seed} nonce`).digest('hex').slice(0, 32),
    bundle: { protocol: 'private-messenger.olm-v1.spike-1', identity_key: key(1), one_time_key: key(2) },
    write: { relay_url: 'https://relay.000000000000.example.invalid', queue_id: '02'.repeat(16), token: '03'.repeat(32) },
  },
  secret: '04'.repeat(32), recipient_ticket: '05'.repeat(32), expires_at: 1791208800,
};
const link = 'kotopizdelka://invite#' + Buffer.from(JSON.stringify(value)).toString('base64url');
const qr = QRCode.create(link, { errorCorrectionLevel: 'M', version: 25, maskPattern: 3 });
const size = qr.modules.size + 8;
const rows = Array.from({ length: size }, (_, y) => Array.from({ length: size }, (_, x) =>
  y >= 4 && x >= 4 && y < size - 4 && x < size - 4 && qr.modules.get(y - 4, x - 4) ? '#' : '.').join(''));
const folder = path.resolve(__dirname, '../../src-tauri/gen/android/app/src/test/resources');
for (const [name, content] of [['invitation-false-finder-link.txt', link + '\n'], ['invitation-false-finder-matrix.txt', rows.join('\n') + '\n']]) {
  const target = path.join(folder, name);
  if (process.argv.includes('--write')) fs.writeFileSync(target, content);
  else assert.equal(fs.readFileSync(target, 'utf8'), content, name);
}
console.log('PASS: synthetic QR fixture and matrix are reproducible');
