import adapter from '@sveltejs/adapter-static';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

/** @type {import('@sveltejs/kit').Config} */
const config = {
	preprocess: vitePreprocess(),
	kit: {
		// SPA mode — `ssr=false` is set in +layout.ts so every route
		// renders client-side. `fallback: 'index.html'` makes Cloudflare
		// Pages serve the SPA shell for any unmatched path, then the
		// client router takes over.
		adapter: adapter({
			pages: 'build',
			assets: 'build',
			fallback: 'index.html',
			precompress: false,
			strict: false
		})
	}
};

export default config;
