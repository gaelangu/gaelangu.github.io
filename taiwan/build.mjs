#!/usr/bin/env node
/*
 * taiwan/build.mjs — encrypts the plaintext trip data and injects the
 * ciphertext into taiwan/index.html.
 *
 * Two-factor scheme (v2):
 *   secret = <link key> ":" <PIN>
 *   - link key: 128-bit random value carried in the share URL fragment
 *     (https://gaelangu.com/taiwan/#k=...). Fragments never reach the server.
 *     Persisted in taiwan/linkkey.txt (gitignored) so rebuilds keep old links valid.
 *   - PIN: short numeric code people type on the page.
 *   A leaked link is useless without the PIN; the PIN is useless without the link.
 *
 * Usage:
 *   PIN=09032019 node taiwan/build.mjs     # encrypt with a PIN
 *   node taiwan/build.mjs                  # uses DEFAULT_PIN below
 *
 * To CHANGE THE PIN: run again with the new PIN.
 * To REVOKE A LEAKED LINK: delete taiwan/linkkey.txt and rebuild — a new link
 * is generated and every old link stops working.
 *
 * Files:
 *   taiwan/data.json    plaintext trip data (gitignored — holds passport PII)
 *   taiwan/linkkey.txt  secret link-key half (gitignored)
 *   taiwan/index.html   gets the encrypted blob injected between markers
 *
 * Crypto (must stay identical to the browser decrypt in index.html):
 *   key  = PBKDF2(linkKey + ":" + pin, salt, 250000, SHA-256) -> AES-GCM 256
 *   blob = AES-GCM(iv, key, utf8(JSON))
 */

import { readFile, writeFile } from 'node:fs/promises';
import { webcrypto as crypto } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const DEFAULT_PIN = '09032019';
const ITERATIONS = 250000;

const HERE = dirname(fileURLToPath(import.meta.url));
const DATA_PATH = join(HERE, 'data.json');
const KEY_PATH = join(HERE, 'linkkey.txt');
const HTML_PATH = join(HERE, 'index.html');
const START = '/* __ENC_START__ */';
const END = '/* __ENC_END__ */';

function b64(buf) {
  return Buffer.from(buf).toString('base64');
}
function b64url(buf) {
  return Buffer.from(buf).toString('base64url');
}

async function loadOrCreateLinkKey() {
  try {
    const k = (await readFile(KEY_PATH, 'utf8')).trim();
    if (/^[A-Za-z0-9_-]{16,}$/.test(k)) return k;
    console.error('linkkey.txt exists but looks malformed; refusing to guess. Delete it to regenerate.');
    process.exit(1);
  } catch {
    const k = b64url(crypto.getRandomValues(new Uint8Array(16)));
    await writeFile(KEY_PATH, k + '\n', 'utf8');
    console.log('Generated new link key -> taiwan/linkkey.txt (gitignored). Old links (if any) are now invalid.');
    return k;
  }
}

async function main() {
  const pin = String(process.env.PIN || DEFAULT_PIN).trim();
  if (!/^\d{6,12}$/.test(pin)) {
    console.error(`PIN must be 6-12 digits. Got: "${pin}"`);
    process.exit(1);
  }

  const linkKey = await loadOrCreateLinkKey();
  const secret = linkKey + ':' + pin;

  const dataRaw = await readFile(DATA_PATH, 'utf8');
  // Validate JSON early so we never inject a broken payload.
  JSON.parse(dataRaw);
  const plaintext = new TextEncoder().encode(dataRaw);

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const keyMaterial = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret), 'PBKDF2', false, ['deriveKey'],
  );
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: ITERATIONS, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false, ['encrypt'],
  );
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext);

  const payload = {
    v: 2,
    iter: ITERATIONS,
    pinlen: pin.length,
    salt: b64(salt),
    iv: b64(iv),
    ct: b64(ct),
  };

  const html = await readFile(HTML_PATH, 'utf8');
  const s = html.indexOf(START);
  const e = html.indexOf(END);
  if (s === -1 || e === -1 || e < s) {
    console.error('Could not find injection markers in index.html.');
    process.exit(1);
  }
  const before = html.slice(0, s + START.length);
  const after = html.slice(e);
  const injected = `\n    const ENC = ${JSON.stringify(payload)};\n    `;
  await writeFile(HTML_PATH, before + injected + after, 'utf8');

  const kb = (payload.ct.length / 1024).toFixed(1);
  console.log(`Encrypted ${dataRaw.length} bytes of trip data -> ${kb}KB ciphertext.`);
  console.log(`PIN: ${pin.replace(/\d/g, '•')} (${pin.length} digits).`);
  console.log('');
  console.log('Share THIS link (the #k= part is required to unlock):');
  console.log(`  https://gaelangu.com/taiwan/#k=${linkKey}`);
  console.log(`  local test: http://localhost:3456/taiwan/#k=${linkKey}`);
}

main().catch((err) => { console.error(err); process.exit(1); });
