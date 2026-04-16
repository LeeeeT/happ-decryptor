import { defineConfig } from 'vite';

export default defineConfig({
  // When deploying to GitHub Pages the base must be /<repo-name>/.
  // Pass it via the BASE_URL environment variable in CI; falls back to '/' locally.
  base: process.env.BASE_URL ?? '/',
});
