// @ts-check
import { defineConfig } from 'astro/config';
import cloudflare from '@astrojs/cloudflare';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  output: 'server',
  // v13 reads wrangler.jsonc automatically; in `astro dev` the D1/KV bindings
  // are served by a LOCAL Miniflare emulator — no Cloudflare account or network.
  adapter: cloudflare({
    imageService: 'passthrough', // we serve our own static assets; no Images binding needed
    sessionKVBindingName: 'KV', // reuse our KV; no separate SESSION namespace needed
  }),
  devToolbar: {
    enabled: false,
  },
  security: {
    checkOrigin: true,
  },
  vite: {
    plugins: [tailwindcss()],
  },
});
