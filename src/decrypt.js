/**
 * Happ deep-link decryptor — pure JavaScript, client-side only.
 *
 * Supports:  happ://crypt/…   happ://crypt2/…  happ://crypt3/…
 *            happ://crypt4/…  happ://crypt5/…
 *
 * Dependencies (npm, bundled by Vite):
 *   node-forge  → RSA PKCS1v15 decrypt
 *   @noble/ciphers → ChaCha20-Poly1305 decrypt
 *
 * Runtime data (served from /public/data/, fetched on first call):
 *   data/selectors.json          – [[starts, mid, ends], …] for crypt5 key selection
 *   data/expanded_rsa_keys.json  – { "selector": "base64-PKCS8-key", … }
 */

import { chacha20poly1305 } from '@noble/ciphers/chacha.js';
import forge from 'node-forge';

// ---------------------------------------------------------------------------
// Embedded PKCS1 RSA private keys for crypt1–crypt4 (base64, no headers)
// ---------------------------------------------------------------------------
const PKCS1_KEYS_B64 = [
  // key[0] — happ://crypt/  (RSA-1024)
  "MIICXwIBAAKBgQCxsS7PUq1biQlVD92rf6eXKr9oG1/SrYx3qWahZP+Jq35m4Wb/Z+mB6eBWrPzJ/zZpZLWLQorcvOKt+sLaCHyH1HLNkti4jlaEQX6x97XgBm8GK08+lLLWquFDhWRNxsrfzJyNdpVopzBRmCJKTc8ObYyPbrv9T35a8Kd5WqjnUwIDAQABAoGBAJoqe85skPPF5U7jwRM2YhUJhZ+xgGWtJR3834pPslWjcLuZ/F7DrRiF7ZnF5FztDCxMsCXuycPSLWl9EulQS5mrL/fnwpK2jVE8O1Em9RsBOOrWwzuZnAuooRIb/8zC0fvH2oGkk60zSKycMe69uvYUDjhvULX2Spjmf9CS9/HhAkEA3I797En/DrpAZz6NM4GqZ1mkH0kEX/kAHLP1lBgYL1kVK455EG/ecJkMJmtK7A+fWw0N0IcxrpYAbbOAo19vjwJBAM4+0MAZ8TIZUk6Rs2gYUo04A6mYUy5MWtRa9pyFIgD71oHDR+1jrnPLqQyCj0tfbZBc1iVgsisJBpocC8sKaf0CQQDRNd3Mxb/nY2p1xJLBmaxezlvsxSEePB4MG/PFXzmJqBF5uHJD0imIWtR4mOt/ka4R+wbwl1zcAzMy28MYtQ0nAkEAuUILWML0uL+uAw01TeerH1aVU52T+h5z6BPdOTMNHD0arWywCzhi13i03JvaAyYw0F/Tq7dz0txEpeFTZopwMQJBANnHbzB87/xTjDQA4/L8sSU8m0vM1nRWmJIaAC94pcM+KDGLnbBhWrvZGy8Zg8vQwNvdvCLvylk0jVTTFqW3ibM=",
  // key[1] — happ://crypt2/  (RSA-4096)
  "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",
  // key[2] — happ://crypt3/  (RSA-4096)
  "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",
  // key[3] — happ://crypt4/  (RSA-4096)
  "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",
];

// ---------------------------------------------------------------------------
// Runtime data (fetched once on first crypt5 call)
// ---------------------------------------------------------------------------
let _selectors = null;
let _expandedKeys = null;

async function loadData() {
  if (_selectors && _expandedKeys) return;
  const base = import.meta.env.BASE_URL;
  [_selectors, _expandedKeys] = await Promise.all([
    fetch(`${base}data/selectors.json`).then((r) => {
      if (!r.ok) throw new Error(`Failed to fetch selectors.json: ${r.status}`);
      return r.json();
    }),
    fetch(`${base}data/expanded_rsa_keys.json`).then((r) => {
      if (!r.ok) throw new Error(`Failed to fetch expanded_rsa_keys.json: ${r.status}`);
      return r.json();
    }),
  ]);
}

// ---------------------------------------------------------------------------
// String / byte helpers
// ---------------------------------------------------------------------------

/** Swap adjacent character pairs: ABCD → BADC */
function swapPairs(s) {
  const arr = [...s];
  for (let i = 0; i + 1 < arr.length; i += 2) [arr[i], arr[i + 1]] = [arr[i + 1], arr[i]];
  return arr.join('');
}

/** URL-safe base64 → Uint8Array */
function b64DecodeUrlSafe(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
}

/** Uint8Array → Latin-1 string (needed for node-forge byte buffers) */
function uint8ToLatinStr(arr) {
  let s = '';
  for (let i = 0; i < arr.length; i++) s += String.fromCharCode(arr[i]);
  return s;
}

/** Latin-1 byte string from node-forge → Uint8Array */
function latinStrToUint8(str) {
  const out = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) out[i] = str.charCodeAt(i) & 0xff;
  return out;
}

function concatUint8Arrays(chunks) {
  const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Crypt5 payload parsing
// ---------------------------------------------------------------------------

/**
 * Block-pair swap permutation.
 * For each output position j (1-indexed):
 *   k = (j-1) ÷ 4,  p = (j-1) mod 4
 *   source = 4k + (p+2) mod 4
 * Net effect: every 4-char block ABCD → CDAB (two 2-char pairs swapped).
 */
function blockPairSwap(region, length) {
  const result = [];
  for (let j = 1; j <= length; j++) {
    const k = Math.floor((j - 1) / 4);
    const p = (j - 1) % 4;
    result.push(region[4 * k + ((p + 2) % 4)]);
  }
  return result.join('');
}

function extractNonce(payload) {
  const n = payload.slice(4, 16);
  return n[2] + n[3] + n[0] + n[1] + n[6] + n[7] + n[4] + n[5] + n[10] + n[11] + n[8] + n[9];
}

function extractUrlB64(payload, N) {
  return payload[17] + blockPairSwap(payload.slice(20, 20 + N), N - 1);
}

function extractEncStr(payload, N) {
  const urlRegion = payload.slice(20, 20 + N);
  const encRegion = payload.slice(20 + N, 20 + N + 684);
  const skip = Math.floor((N - 1) / 4) * 4 + 1;
  return urlRegion[skip] + blockPairSwap(encRegion, 683);
}

// ---------------------------------------------------------------------------
// Selector derivation
// ---------------------------------------------------------------------------
// crypt5 key selection is driven by the payload itself.
// The selector is assembled from the reordered 4-char prefix and the trailing
// 4 characters around the encoded suffix marker.
function deriveSelector(payload) {
  return (
    payload[2] +
    payload[3] +
    payload[0] +
    payload[1] +
    payload[761] +
    payload[764] +
    payload[765] +
    payload[766]
  );
}

async function getExpandedRsaKey(selector) {
  await loadData();
  if (_expandedKeys[selector]) return _expandedKeys[selector];
  for (const [starts, mid, ends] of _selectors) {
    if (selector.startsWith(starts) && selector.slice(2, 6) === mid && selector.endsWith(ends)) {
      const key = _expandedKeys[starts + mid + ends];
      if (key) return key;
    }
  }
  throw new Error(`No RSA key found for selector: ${selector}`);
}

// ---------------------------------------------------------------------------
// RSA helpers (node-forge)
// ---------------------------------------------------------------------------

function loadForgePkcs8Key(pkcs8B64) {
  const lines = pkcs8B64.replace(/\s/g, '').match(/.{1,64}/g).join('\n');
  const pem = `-----BEGIN PRIVATE KEY-----\n${lines}\n-----END PRIVATE KEY-----`;
  return forge.pki.privateKeyFromPem(pem);
}

function loadForgePkcs1Key(pkcs1B64) {
  const lines = pkcs1B64.replace(/\s/g, '').match(/.{1,64}/g).join('\n');
  const pem = `-----BEGIN RSA PRIVATE KEY-----\n${lines}\n-----END RSA PRIVATE KEY-----`;
  return forge.pki.privateKeyFromPem(pem);
}

function forgeRsaDecrypt(privateKey, cipherBytes) {
  return privateKey.decrypt(uint8ToLatinStr(cipherBytes), 'RSAES-PKCS1-V1_5');
}

// ---------------------------------------------------------------------------
// Crypt5 pipeline
// ---------------------------------------------------------------------------
async function decryptCrypt5(payload) {
  const N = parseInt(payload.slice(18, 20), 10);
  const nonceStr = extractNonce(payload);
  const urlB64 = extractUrlB64(payload, N);
  const encStr = extractEncStr(payload, N);

  // Locate the non-trailing '=' in enc_str — it separates the RSA ciphertext
  const trailingStart = encStr.replace(/=+$/, '').length;
  const eqIdx = encStr.indexOf('=');
  const cipherB64 =
    eqIdx >= 0 && eqIdx < trailingStart ? encStr.slice(eqIdx + 1) : encStr;
  const cb = cipherB64.replace(/=+$/, '');
  const cbPadded = cb + '='.repeat((4 - (cb.length % 4)) % 4);
  const cipherBytes = Uint8Array.from(atob(cbPadded), (c) => c.charCodeAt(0));

  // RSA-PKCS1v15 decrypt → 44-char base64 string
  const selector = deriveSelector(payload);
  const rsaKeyB64 = await getExpandedRsaKey(selector);
  const privateKey = loadForgePkcs8Key(rsaKeyB64);
  const rsaPlainStr = forgeRsaDecrypt(privateKey, cipherBytes);

  // swapPairs(rsa_plain) → base64-decode → 32-byte ChaCha20 key
  const chachaKey = b64DecodeUrlSafe(swapPairs(rsaPlainStr));

  // ChaCha20-Poly1305 decrypt
  const nonce = new TextEncoder().encode(nonceStr);
  const ciphertext = b64DecodeUrlSafe(urlB64);
  const chacha = chacha20poly1305(chachaKey, nonce);
  const intermediate = chacha.decrypt(ciphertext);

  // swapPairs(intermediate) → base64-decode → final URL
  const intermediateStr = new TextDecoder().decode(intermediate);
  return new TextDecoder().decode(b64DecodeUrlSafe(swapPairs(intermediateStr)));
}

// ---------------------------------------------------------------------------
// Crypt1–4 pipeline
// ---------------------------------------------------------------------------
async function decryptCrypt1to4(ordinal, payload) {
  const privateKey = loadForgePkcs1Key(PKCS1_KEYS_B64[ordinal]);
  const keySize = Math.ceil(privateKey.n.bitLength() / 8);
  const cipherBytes = b64DecodeUrlSafe(payload);

  const plaintextChunks = [];
  for (let i = 0; i < cipherBytes.length; i += keySize) {
    const decrypted = forgeRsaDecrypt(privateKey, cipherBytes.slice(i, i + keySize));
    plaintextChunks.push(latinStrToUint8(decrypted));
  }
  return new TextDecoder().decode(concatUint8Arrays(plaintextChunks));
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------
export async function decryptLink(link) {
  const path = link.startsWith('happ://') ? link.slice(7) : link;

  if (path.startsWith('crypt5/')) return decryptCrypt5(path.slice(7));
  if (path.startsWith('crypt4/')) return decryptCrypt1to4(3, path.slice(7));
  if (path.startsWith('crypt3/')) return decryptCrypt1to4(2, path.slice(7));
  if (path.startsWith('crypt2/')) return decryptCrypt1to4(1, path.slice(7));
  if (path.startsWith('crypt/')) return decryptCrypt1to4(0, path.slice(6));

  throw new Error(`Unknown link format: ${link}`);
}
