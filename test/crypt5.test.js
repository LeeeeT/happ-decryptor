import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import { decryptCrypt5Direct, decryptCrypt5WithFallback } from '../src/crypt5.js';

const CRYPT5_PREFIX = 'happ://crypt5/';
const EXAMPLE_LINK = 'happ://crypt5/fzvdO4bMOfTWNaB3taWRhRaF64soexaE9dm3ZlLK0Rke9Rz3BG1f9gmj4tSDpjRSWWdX5G6oaaQK9Gs+fdJPWNXIF08BsaeifWtfTlCvC/nSWDv0ZrofgJXkQ8MlUk63CoJkt7RvXAfablYXb/cYWEZJQkDMyMaE5/1KegAbWVWVI60MPqDylUyYoLtOeOOX9amvELecOZ4kKz1QVqgE9uCBz3py+3Ghr1iVGKOhFwb98OFP+j0tGvDo/3d609DVq3RwBGXu1ogZ7PTc3/A5IlaA3Hff5IlVujozQ3ywmQBsTGd+l3AHJAX1oDbPkRSSwg7Y7hl3AKXKpZsEhMzPbJY8UxZ7GmVsxeROLopVx85ACqakzg+ZZwdZslfKgdRzUmL9Mv895HDOHE3tbh6qnDhE9Ew/Epx1iBCb2HjorOLDBluH8ztdL9mdUX+turjC4GLN0YR55P3H23A0W5zl0di5YfrI2nUBKxh30lUVG9NbqYKlwxgmhxAUZrQ6cnFGF2VuZ9VJLQ3sQ8rqXTtfau8ySbu770Hd6vVEun8aSJm4W4M0DagKbORL4A4M6Cuf1v/jj7EWhA9yhhcSuxkc6WUWMGYRraWBM9vSrSbjeT1U69a3n9T56M/TOJWf4z8fXrHRnCR1tfzwrjHiOJfZGiKvbAd4k6f+VADYpLdCq+ornEElv7V0sByfwPTgep+Q33Qkl67ArHpmbZDcCyWkGz0BoUzGJFe58YiS/oNFVdufbuDnFd1ArAVMztJJJbxlo4Is48+Iof=ff';

const keytable = JSON.parse(
  await readFile(new URL('../public/data/crypt5-keys.json', import.meta.url), 'utf8'),
);

test('decrypts the supplied salted crypt5 link directly', () => {
  const plaintext = decryptCrypt5Direct(EXAMPLE_LINK.slice(CRYPT5_PREFIX.length), keytable);
  assert.equal(plaintext, 'https://example.com/sub');
});

test('rejects a crypt5 payload that fails authentication', () => {
  const payload = EXAMPLE_LINK.slice(CRYPT5_PREFIX.length);
  const tampered = `${payload.slice(0, 200)}A${payload.slice(201)}`;
  assert.throws(() => decryptCrypt5Direct(tampered, keytable));
});

test('uses the fallback when direct decryption fails', async () => {
  const payload = EXAMPLE_LINK.slice(CRYPT5_PREFIX.length);
  let fallbackPayload;
  const plaintext = await decryptCrypt5WithFallback(
    payload,
    async () => ({}),
    async (receivedPayload) => {
      fallbackPayload = receivedPayload;
      return 'fallback result';
    },
  );

  assert.equal(fallbackPayload, payload);
  assert.equal(plaintext, 'fallback result');
});
