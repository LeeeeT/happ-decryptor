# Happ Link Decryptor

Browser-based decryptor for supported `happ://` deep links.

The app runs entirely client-side and supports all currently bundled formats:
`crypt`, `crypt2`, `crypt3`, `crypt4`, and `crypt5`.

## Highlights

- Local decryption in the browser
- Support for legacy RSA-wrapped links and current `crypt5` links
- 34 bundled crypt5 RSA keys generated from the current APK snapshot
- Static compatibility data committed in `public/data/`
- No APK processing, native emulation, or external services required at runtime

## Development

```bash
npm install
npm run dev
npm run build
npm run preview
```

## Reverse Engineering Notes

The detailed reverse-engineering log lives in the in-page write-up in [`index.html`](./index.html).

## Runtime Dependencies

- [`node-forge`](https://github.com/digitalbazaar/forge) for RSA PKCS#1 v1.5 decryption
- [`@noble/ciphers`](https://github.com/paulmillr/noble-ciphers) for ChaCha20-Poly1305

## Privacy

Decryption happens locally in the browser tab. The app does not upload links or decrypted results to a server.
