<script lang="ts">
	import { onMount } from 'svelte';
	import { highlightSnippet } from '$lib/highlighter';
	import type { Finding, Label, Language, Severity } from '$lib/types';

	let {
		finding,
		language,
		onlabel,
		onfocus,
		focused = false,
		readonly = false,
		existingLabel = null
	}: {
		finding: Finding;
		language: Language;
		onlabel?: (id: string, label: Label) => Promise<void>;
		onfocus?: () => void;
		focused?: boolean;
		readonly?: boolean;
		existingLabel?: Label | null;
	} = $props();

	const severityStyles: Record<Severity, string> = {
		critical: 'text-red-400 bg-red-950 border-red-800',
		high: 'text-orange-400 bg-orange-950 border-orange-800',
		medium: 'text-yellow-400 bg-yellow-950 border-yellow-800',
		low: 'text-blue-400 bg-blue-950 border-blue-800'
	};
	const severityBorderLeft: Record<Severity, string> = {
		critical: 'border-l-red-600',
		high: 'border-l-orange-500',
		medium: 'border-l-yellow-500',
		low: 'border-l-blue-400'
	};
	const severityBarColor: Record<Severity, string> = {
		critical: 'bg-red-600',
		high: 'bg-orange-500',
		medium: 'bg-yellow-500',
		low: 'bg-blue-400'
	};

	let interactiveLabel = $state<Label | null>(null);
	const labeled = $derived<Label | null>(readonly ? (existingLabel ?? null) : interactiveLabel);
	let loading = $state(false);
	let highlightedHtml = $state('');

	const borderColor = $derived(severityBorderLeft[finding.severity]);
	const barColor = $derived(severityBarColor[finding.severity]);
	const confidencePct = $derived(Math.round(finding.confidence * 100));
	const lineRange = $derived(
		finding.line_end > finding.line_start
			? `Lines ${finding.line_start}–${finding.line_end}`
			: `Line ${finding.line_start}`
	);
	const isSemgrep = $derived(finding.source === 'semgrep');
	const isManual = $derived(finding.source === 'manual');

	onMount(async () => {
		if (finding.code_snippet) {
			try {
				highlightedHtml = await highlightSnippet(
					finding.code_snippet,
					language,
					finding.line_start,
					finding.line_end,
					finding.severity
				);
			} catch {
				highlightedHtml = `<pre class="text-gray-300 text-xs p-2">${finding.code_snippet}</pre>`;
			}
		}
	});

	async function handleLabel(label: Label, e: MouseEvent) {
		e.stopPropagation();
		if (!onlabel) return;
		loading = true;
		try {
			await onlabel(finding.id, label);
			interactiveLabel = label;
		} finally {
			loading = false;
		}
	}
</script>

<div
	role="button"
	tabindex="0"
	onclick={onfocus}
	onkeydown={(e) => e.key === 'Enter' && onfocus?.()}
	class={[
		'rounded border bg-gray-900 border-l-4 p-3 flex flex-col gap-2 transition-all',
		borderColor,
		focused
			? 'border-gray-600 ring-1 ring-indigo-500/50 cursor-default'
			: 'border-gray-700 cursor-pointer hover:border-gray-600 hover:bg-gray-900/80'
	].join(' ')}
>
	<!-- Header -->
	<div class="flex flex-wrap items-center gap-2">
		<span
			class={`text-xs font-semibold px-2 py-0.5 rounded-full border ${severityStyles[finding.severity]} uppercase tracking-wide`}
		>
			{finding.severity}
		</span>
		<span class="font-mono text-xs text-gray-300">{finding.rule_id}</span>
		{#if finding.cwe}
			<span class="text-xs px-1.5 py-0.5 rounded bg-gray-700 text-gray-400 border border-gray-600">
				{finding.cwe}
			</span>
		{/if}
		<span
			class={`text-xs px-1.5 py-0.5 rounded font-mono border ${
				isSemgrep
					? 'bg-blue-950 text-blue-400 border-blue-800'
					: isManual
						? 'bg-teal-950 text-teal-400 border-teal-800'
						: 'bg-purple-950 text-purple-400 border-purple-800'
			}`}
		>
			{finding.source.toUpperCase()}
		</span>
		{#if finding.is_uncertain}
			<span class="text-xs px-1.5 py-0.5 rounded bg-yellow-900 text-yellow-400 border border-yellow-700">
				Uncertain
			</span>
		{/if}
		{#if focused}
			<span class="ml-auto text-xs text-indigo-400/70">↑ in editor</span>
		{/if}
	</div>

	<!-- Message -->
	<p class="text-sm text-gray-200 leading-snug">{finding.message}</p>

	<!-- Code snippet -->
	{#if finding.code_snippet}
		<div class="rounded border border-gray-800 overflow-hidden">
			<div class="flex items-center justify-between px-3 py-1 bg-gray-800/60 border-b border-gray-800">
				<span class="text-xs font-mono text-gray-500">{lineRange}</span>
			</div>
			{#if highlightedHtml}
				<div
					class="shiki-snippet"
					style="max-height:10rem; overflow-y:auto; font-size:0.72rem; line-height:1.55;"
				>
					{@html highlightedHtml}
				</div>
			{:else}
				<pre class="text-gray-300 text-xs p-2 overflow-x-auto">{finding.code_snippet}</pre>
			{/if}
		</div>
	{/if}

	<!-- Confidence bar -->
	<div class="flex items-center gap-2">
		<span class="text-xs text-gray-500 w-20 shrink-0">Confidence {confidencePct}%</span>
		<div class="flex-1 h-1.5 bg-gray-800 rounded-full overflow-hidden">
			<div class={`h-full rounded-full ${barColor}`} style="width:{confidencePct}%"></div>
		</div>
	</div>

	<!-- TP / FP buttons or readonly label badge -->
	{#if readonly}
		{#if labeled}
			<div class="flex items-center gap-2 mt-1">
				<span class={[
					'text-xs font-semibold px-3 py-1 rounded border',
					labeled === 'tp'
						? 'bg-green-700 border-green-600 text-white'
						: 'bg-red-700 border-red-600 text-white'
				].join(' ')}>
					{labeled === 'tp' ? '✓ True Positive' : '✗ False Positive'}
				</span>
			</div>
		{/if}
	{:else}
		<div class="flex gap-2 mt-1">
			<button
				onclick={(e) => handleLabel('tp', e)}
				disabled={loading || labeled !== null}
				class={[
					'flex-1 flex items-center justify-center gap-1.5 text-xs font-medium px-3 py-1.5 rounded border transition-colors',
					labeled === 'tp'
						? 'bg-green-700 border-green-600 text-white'
						: labeled === 'fp'
							? 'bg-gray-800 border-gray-700 text-gray-500 cursor-not-allowed'
							: 'bg-green-900/40 border-green-700 text-green-400 hover:bg-green-900/70 cursor-pointer'
				].join(' ')}
			>
				{#if labeled === 'tp'}
					<svg class="w-3.5 h-3.5" viewBox="0 0 20 20" fill="currentColor">
						<path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd" />
					</svg>
				{:else}
					<span>&#10003;</span>
				{/if}
				True Positive
			</button>

			<button
				onclick={(e) => handleLabel('fp', e)}
				disabled={loading || labeled !== null}
				class={[
					'flex-1 flex items-center justify-center gap-1.5 text-xs font-medium px-3 py-1.5 rounded border transition-colors',
					labeled === 'fp'
						? 'bg-red-700 border-red-600 text-white'
						: labeled === 'tp'
							? 'bg-gray-800 border-gray-700 text-gray-500 cursor-not-allowed'
							: 'bg-red-900/40 border-red-700 text-red-400 hover:bg-red-900/70 cursor-pointer'
				].join(' ')}
			>
				{#if labeled === 'fp'}
					<svg class="w-3.5 h-3.5" viewBox="0 0 20 20" fill="currentColor">
						<path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd" />
					</svg>
				{:else}
					<span>&#10007;</span>
				{/if}
				False Positive
			</button>
		</div>
	{/if}
</div>
