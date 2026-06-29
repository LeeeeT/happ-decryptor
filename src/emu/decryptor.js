/**
 * Client-side loader for the native-emulation crypt5 decryptor.
 *
 * Loads the prebuilt unicorn.js (Unicorn 2.1.4, AArch64) CPU emulator + its
 * wrapper, the extracted `liberror-code.so`, and the marker→key table, then
 * runs the native decrypt routine fully in-browser (no server). See
 * ANALYSIS/FINDINGS.md for how this was reverse-engineered.
 *
 * Assets are served from /public/emu/ and /public/data/ and fetched once.
 */
import { createDecryptor } from './emu_core.js';

let _decryptorPromise = null;

// Evaluate a UMD/CommonJS bundle's text and return its module.exports.
function evalCjs(src) {
  const shim = { exports: {} };
  // eslint-disable-next-line no-new-func
  new Function('module', 'exports', src)(shim, shim.exports);
  return shim.exports.default || shim.exports;
}

async function buildDecryptor() {
  const base = import.meta.env.BASE_URL;
  const [unicornSrc, wrapperSrc, soBuf, keytable] = await Promise.all([
    fetch(`${base}emu/unicorn_aarch64.js`).then((r) => r.text()),
    fetch(`${base}emu/unicorn-wrapper.js`).then((r) => r.text()),
    fetch(`${base}emu/liberror-code.so`).then((r) => r.arrayBuffer()),
    fetch(`${base}data/keytable.json`).then((r) => r.json()),
  ]);
  const MUnicorn = evalCjs(unicornSrc);
  return createDecryptor({
    MUnicorn,
    wrapperSrc,
    soBytes: new Uint8Array(soBuf),
    keytable,
    verbose: 0,
  });
}

/** Returns a cached `{ decrypt(inBytes: Uint8Array) -> Uint8Array }`. */
export function getNativeDecryptor() {
  if (!_decryptorPromise) _decryptorPromise = buildDecryptor();
  return _decryptorPromise;
}
