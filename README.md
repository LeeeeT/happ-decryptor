# Happ Link Decryptor

Browser-based decryptor for supported `happ://` deep links.

The app runs entirely client-side and supports all currently bundled formats:
`crypt`, `crypt2`, `crypt3`, `crypt4`, and `crypt5`.

## Highlights

- Decryption happens locally in the browser — no server, no APK processing
- Legacy RSA-wrapped links (`crypt`–`crypt4`) decrypt directly in JavaScript
- `crypt5` runs the original native library (`liberror-code.so`) in-browser via
  CPU emulation, so the obfuscated key derivation stays correct across app versions
- An RSA-modexp fast path (JS `BigInt`) brings a `crypt5` decrypt down to ~2 s
- 36 bundled `crypt5` marker keys + the emulation assets are committed under `public/`

## Development

```bash
npm install
npm run dev
npm run build
npm run preview
```

## How it works

- `src/decrypt.js` — top-level decode for every generation.
- `src/emu/` — loads `liberror-code.so` onto [unicorn.js](https://github.com/AlexAltea/unicorn.js)
  (Unicorn 2.1.4, asm.js) with a mock JNI/libc host, and runs the native `crypt5`
  decrypt. Includes the `BN_mod_exp_mont` interception that does the RSA modular
  exponentiation in JavaScript `BigInt`; if the bundled `.so` is ever replaced and
  the interception target no longer matches, the library runs unmodified instead.
- `public/emu/` — the native library + emulator; `public/data/keytable.json` — the
  36 marker→key entries injected into the library exactly as the app does on-device.

The detailed reverse-engineering write-up is in the in-page dossier
([`index.html`](./index.html)).

## Runtime Dependencies

- [`node-forge`](https://github.com/digitalbazaar/forge) — RSA PKCS#1 v1.5
  decryption for the legacy `crypt`–`crypt4` formats.

## Privacy

Decryption happens locally in the browser tab. The app does not upload links or
decrypted results to a server.
