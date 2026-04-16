# Happ Link Decryptor

A browser-based tool that decrypts `happ://` deep links (all five generations: `crypt` through `crypt5`) entirely client-side. No data is sent to any server.

## Live site

Deployed via GitHub Pages — see the Actions tab for the latest build.

## Development

```bash
npm install
npm run dev       # dev server at http://localhost:5173
npm run build     # production build → dist/
npm run preview   # preview the production build locally
```

## How it works

See the in-page write-up for a detailed explanation of the `happ://` encryption scheme and how each generation was analysed and reimplemented.

The two cryptographic dependencies are:
- [node-forge](https://github.com/digitalbazaar/forge) — RSA-PKCS1v15 decryption (Web Crypto API does not support PKCS1v15)
- [@noble/ciphers](https://github.com/paulmillr/noble-ciphers) — ChaCha20-Poly1305

Both are bundled by Vite at build time.
