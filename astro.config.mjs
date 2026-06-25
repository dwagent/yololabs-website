// @ts-check
import { defineConfig } from 'astro/config';
import sitemap from '@astrojs/sitemap';

export default defineConfig({
  site: 'https://blue-glacier-04dc8260f.7.azurestaticapps.net',
  integrations: [sitemap()],
});
