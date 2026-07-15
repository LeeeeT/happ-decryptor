# Happ Link Decryptor

Browser-based decryptor for supported `happ://` deep links.

The app runs entirely client-side and supports all currently bundled formats:
`crypt`, `crypt2`, `crypt3`, `crypt4`, and `crypt5`.

## Highlights

- Decryption happens locally in the browser — no server
- Legacy RSA-wrapped links (`crypt`–`crypt4`) decrypt directly in JavaScript
- `crypt5` decrypts directly with RSA + ChaCha20-Poly1305, including both the
  legacy and newer salted/XOR layouts
- The original native-library CPU emulator remains as an automatic fallback
- 36 bundled `crypt5` marker keys + the fallback emulation assets are committed under `public/`

## Development

```bash
npm install
npm run dev
npm test
npm run build
npm run preview
```

## How it works

- `src/decrypt.js` — top-level decode for every generation.
- `src/crypt5.js` — lightweight direct `crypt5` parsing, RSA key recovery, salt/XOR
  handling, and authenticated ChaCha20-Poly1305 decryption.
- `src/emu/` — fallback that loads `liberror-code.so` onto
  [unicorn.js](https://github.com/AlexAltea/unicorn.js) (Unicorn 2.1.4, asm.js) with
  a mock JNI/libc host and its existing JavaScript `BigInt` RSA fast path.
- `public/data/crypt5-keys.json` — PKCS#8 keys for direct decryption;
  `public/data/keytable.json` — key strings used by the native fallback.

The detailed reverse-engineering write-up is in the in-page dossier
([`index.html`](./index.html)).

## Runtime Dependencies

- [`node-forge`](https://github.com/digitalbazaar/forge) — RSA PKCS#1 v1.5
  decryption.
- [`@noble/ciphers`](https://github.com/paulmillr/noble-ciphers) — audited
  ChaCha20-Poly1305 implementation for direct `crypt5` decryption.

## Privacy

Decryption happens locally in the browser tab. The app does not upload links or
decrypted results to a server.
