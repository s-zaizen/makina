<script lang="ts">
	import type { Language } from '$lib/types';

	const LANGUAGES: { value: Language; label: string }[] = [
		{ value: 'auto', label: 'Auto-detect' },
		{ value: 'python', label: 'Python' },
		{ value: 'rust', label: 'Rust' },
		{ value: 'javascript', label: 'JavaScript' },
		{ value: 'typescript', label: 'TypeScript' },
		{ value: 'go', label: 'Go' },
		{ value: 'java', label: 'Java' },
		{ value: 'ruby', label: 'Ruby' },
		{ value: 'c', label: 'C' },
		{ value: 'cpp', label: 'C++' }
	];

	let {
		language,
		onlanguagechange,
		onscan,
		scanning,
		hasFindings,
		onsubmittoverify
	}: {
		language: Language;
		onlanguagechange: (lang: Language) => void;
		onscan: () => void;
		scanning: boolean;
		hasFindings: boolean;
		onsubmittoverify: () => void;
	} = $props();
</script>

<div class="flex items-center gap-2">
	<select
		value={language}
		onchange={(e) => onlanguagechange((e.currentTarget as HTMLSelectElement).value as Language)}
		class="px-2.5 py-1 text-xs font-medium bg-gray-800 text-gray-300 border border-gray-700 rounded focus:outline-none focus:border-indigo-500 cursor-pointer"
	>
		{#each LANGUAGES as l}
			<option value={l.value}>{l.label}</option>
		{/each}
	</select>

	<button
		onclick={onscan}
		disabled={scanning}
		class={[
			'flex items-center gap-1.5 px-3.5 py-1 rounded text-xs font-semibold transition-colors',
			scanning
				? 'bg-green-800 text-green-300 cursor-not-allowed'
				: 'bg-green-600 hover:bg-green-500 text-white cursor-pointer'
		].join(' ')}
	>
		{#if scanning}
			<svg class="w-3.5 h-3.5 animate-spin" fill="none" viewBox="0 0 24 24">
				<circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" />
				<path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
			</svg>
			Scanning…
		{:else}
			Scan
		{/if}
	</button>

	<div class="w-px h-3.5 bg-gray-700"></div>

	<button
		onclick={onsubmittoverify}
		disabled={!hasFindings || scanning}
		class={[
			'flex items-center gap-1 px-3.5 py-1 rounded text-xs font-semibold border transition-colors',
			hasFindings && !scanning
				? 'border-indigo-600 text-indigo-300 hover:bg-indigo-900/40 cursor-pointer'
				: 'border-gray-800 text-gray-700 cursor-not-allowed'
		].join(' ')}
	>
		Submit →
	</button>
</div>
