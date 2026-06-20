#!/usr/bin/env node
/**
 * Bundles the Service Worker (src/sw/sw.ts) into public/sw.js so it ships as a
 * single self-contained file — with the SigV4, S3, and crypto code bundled in
 * from the canonical modules (no duplication). Run by `npm run build:sw`, which
 * the dev and build scripts invoke automatically.
 */
import { build } from 'esbuild';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

await build({
  entryPoints: [join(root, 'src/sw/sw.ts')],
  outfile: join(root, 'public/sw.js'),
  bundle: true,
  format: 'iife',
  target: 'es2022',
  platform: 'browser',
  minify: true,
  legalComments: 'none',
});

console.log('built public/sw.js');
