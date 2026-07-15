import forge from 'node-forge';
import { chacha20poly1305 } from '@noble/ciphers/chacha.js';

const keyCache = new Map();
const textDecoder = new TextDecoder();
const textEncoder = new TextEncoder();

function decodeBase64(value) {
  let clean = value
    .replace(/\s/g, '')
    .replace(/-/g, '+')
    .replace(/_/g, '/')
    .replace(/=+$/, '');
  while (clean.length % 4) clean += '=';

  try {
    return Uint8Array.from(atob(clean), (char) => char.charCodeAt(0));
  } catch {
    throw new Error('invalid crypt5 base64');
  }
}

function bytesToLatinString(bytes) {
  let value = '';
  for (let i = 0; i < bytes.length; i++) value += String.fromCharCode(bytes[i]);
  return value;
}

function latinStringToBytes(value) {
  return Uint8Array.from(value, (char) => char.charCodeAt(0) & 0xff);
}

function swapAdjacent(bytes) {
  const result = bytes.slice();
  for (let i = 0; i + 1 < result.length; i += 2) {
    [result[i], result[i + 1]] = [result[i + 1], result[i]];
  }
  return result;
}

// ABCD -> CDAB for every complete four-byte block. This transform is its own inverse.
function swapBlockHalves(bytes) {
  const result = bytes.slice();
  const fullLength = result.length - (result.length % 4);
  for (let i = 0; i < fullLength; i += 4) {
    [result[i], result[i + 2]] = [result[i + 2], result[i]];
    [result[i + 1], result[i + 3]] = [result[i + 3], result[i + 1]];
  }
  return result;
}

function loadPrivateKey(marker, keytable) {
  const keyBase64 = keytable[marker];
  if (!keyBase64) throw new Error(`unknown crypt5 marker: ${marker}`);

  let privateKey = keyCache.get(marker);
  if (!privateKey) {
    const lines = keyBase64.match(/.{1,64}/g);
    if (!lines) throw new Error(`invalid crypt5 key: ${marker}`);
    const pem = `-----BEGIN PRIVATE KEY-----\n${lines.join('\n')}\n-----END PRIVATE KEY-----`;
    privateKey = forge.pki.privateKeyFromPem(pem);
    keyCache.set(marker, privateKey);
  }
  return privateKey;
}

function decryptBody(body, privateKey, salted) {
  if (body.length < 13) throw new Error('crypt5 body is too short');

  const nonce = body.subarray(0, 12);
  let salt = null;
  let lengthStart = 12;
  if (salted) {
    if (body.length < 22) throw new Error('crypt5 salted header is too short');
    salt = body.subarray(14, 22);
    lengthStart = 22;
  }

  let lengthEnd = lengthStart;
  while (lengthEnd < body.length && body[lengthEnd] >= 48 && body[lengthEnd] <= 57) {
    lengthEnd += 1;
  }
  if (lengthEnd === lengthStart) throw new Error('crypt5 segment length is missing');

  const segmentLength = Number(textDecoder.decode(body.subarray(lengthStart, lengthEnd)));
  const packed = body.subarray(lengthEnd);
  if (!Number.isSafeInteger(segmentLength) || packed.length === 0 || segmentLength > packed.length - 1) {
    throw new Error('crypt5 segment is truncated');
  }

  const encryptedUrl = textDecoder.decode(packed.subarray(1, segmentLength + 1));
  const rsaCiphertext = decodeBase64(textDecoder.decode(packed.subarray(segmentLength + 1)));
  const rsaPlaintext = privateKey.decrypt(bytesToLatinString(rsaCiphertext));
  const rsaValue = decodeBase64(textDecoder.decode(swapAdjacent(latinStringToBytes(rsaPlaintext))));
  if (rsaValue.length !== 32) throw new Error(`unexpected crypt5 key length: ${rsaValue.length}`);

  const chachaKey = rsaValue.slice();
  if (salt) {
    for (let i = 0; i < chachaKey.length; i++) chachaKey[i] ^= salt[i % salt.length];
  }

  const ciphertext = decodeBase64(encryptedUrl);
  let intermediate;
  try {
    intermediate = chacha20poly1305(chachaKey, nonce).decrypt(ciphertext);
  } catch {
    throw new Error('crypt5 authentication failed');
  }

  const plaintext = decodeBase64(textDecoder.decode(swapAdjacent(intermediate)));
  return textDecoder.decode(plaintext);
}

/**
 * Decrypt crypt5 directly with its RSA + ChaCha20-Poly1305 format.
 * Supports both the legacy layout and the newer salted/XOR layout.
 */
export function decryptCrypt5Direct(payload, keytable) {
  const shuffled = swapBlockHalves(textEncoder.encode(payload));
  if (shuffled.length < 8) throw new Error('crypt5 payload is too short');

  const markerBytes = new Uint8Array(8);
  markerBytes.set(shuffled.subarray(0, 4));
  markerBytes.set(shuffled.subarray(shuffled.length - 4), 4);
  const marker = textDecoder.decode(markerBytes);
  const privateKey = loadPrivateKey(marker, keytable);
  const body = shuffled.subarray(4, shuffled.length - 4);
  const preferSalted = body.length > 12 && !(body[12] >= 48 && body[12] <= 57);

  let firstError;
  for (const salted of [preferSalted, !preferSalted]) {
    try {
      return decryptBody(body, privateKey, salted);
    } catch (error) {
      firstError ??= error;
    }
  }
  throw firstError;
}

/** Try direct decryption first and invoke the native-compatible path only on failure. */
export async function decryptCrypt5WithFallback(payload, loadKeys, fallback) {
  try {
    return decryptCrypt5Direct(payload, await loadKeys());
  } catch {
    return fallback(payload);
  }
}
