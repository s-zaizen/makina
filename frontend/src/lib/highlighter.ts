import type { HighlighterCore } from 'shiki/core';

let instance: HighlighterCore | null = null;
let loading: Promise<HighlighterCore> | null = null;

async function getInstance(): Promise<HighlighterCore> {
	if (instance) return instance;
	if (!loading) {
		loading = (async () => {
			const { createHighlighterCore } = await import('shiki/core');
			const { createOnigurumaEngine } = await import('shiki/engine/oniguruma');
			const h = await createHighlighterCore({
				themes: [import('shiki/themes/vitesse-dark.mjs')],
				langs: [
					import('shiki/langs/python.mjs'),
					import('shiki/langs/javascript.mjs'),
					import('shiki/langs/typescript.mjs'),
					import('shiki/langs/rust.mjs'),
					import('shiki/langs/go.mjs'),
					import('shiki/langs/java.mjs'),
					import('shiki/langs/ruby.mjs'),
					import('shiki/langs/c.mjs'),
					import('shiki/langs/cpp.mjs')
				],
				engine: createOnigurumaEngine(import('shiki/wasm'))
			});
			instance = h;
			return h;
		})();
	}
	return loading;
}

const SEV_BG: Record<string, string> = {
	critical: 'rgba(239,68,68,0.12)',
	high: 'rgba(249,115,22,0.10)',
	medium: 'rgba(234,179,8,0.10)',
	low: 'rgba(96,165,250,0.10)'
};

export async function preloadHighlighter(): Promise<void> {
	await getInstance();
}

export async function highlightSnippet(
	code: string,
	lang: string,
	lineStart: number,
	lineEnd: number,
	severity: string
): Promise<string> {
	const h = await getInstance();
	const bg = SEV_BG[severity] ?? 'transparent';
	const safeLang = lang === 'auto' ? 'text' : lang;

	return h.codeToHtml(code, {
		lang: safeLang,
		theme: 'vitesse-dark',
		transformers: [
			{
				line(node, line) {
					const actualLine = line + lineStart - 1;
					if (actualLine >= lineStart && actualLine <= lineEnd) {
						this.addClassToHast(node, 'highlighted-line');
						node.properties['style'] =
							(node.properties['style'] ?? '') + `background:${bg};`;
					}
				}
			}
		]
	});
}
