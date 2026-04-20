<script lang="ts">
	import { untrack } from 'svelte';
	import { highlightSnippet } from '$lib/highlighter';
	import type { Label, VerifyCase } from '$lib/types';

	let {
		cases,
		onlabel,
		onsubmit
	}: {
		cases: VerifyCase[];
		onlabel: (caseNo: number, findingId: string, label: Label) => void;
		onsubmit: (caseNo: number) => Promise<void>;
	} = $props();

	const langColor: Record<string, string> = {
		python: 'text-blue-400 bg-blue-950 border-blue-800',
		javascript: 'text-yellow-400 bg-yellow-950 border-yellow-800',
		typescript: 'text-sky-400 bg-sky-950 border-sky-800',
		rust: 'text-orange-400 bg-orange-950 border-orange-800',
		go: 'text-cyan-400 bg-cyan-950 border-cyan-800',
		java: 'text-red-400 bg-red-950 border-red-800',
		ruby: 'text-rose-400 bg-rose-950 border-rose-800',
		c: 'text-gray-400 bg-gray-800 border-gray-600',
		cpp: 'text-purple-400 bg-purple-950 border-purple-800'
	};
	const sevColor: Record<string, string> = {
		critical: 'text-red-400',
		high: 'text-orange-400',
		medium: 'text-yellow-400',
		low: 'text-blue-400'
	};

	function formatDate(iso: string) {
		const d = new Date(iso);
		const date = d.toLocaleDateString('ja-JP', { year: 'numeric', month: '2-digit', day: '2-digit' });
		const time = d.toLocaleTimeString('ja-JP', { hour: '2-digit', minute: '2-digit' });
		return `${date} ${time}`;
	}

	// Per-case expand state and submitting state
	let expandedCases = $state<Record<number, boolean>>({});
	let submittingCases = $state<Record<number, boolean>>({});

	// Highlighted code cache: keyed by findingId
	let codeCache = $state<Record<string, string>>({});

	async function highlightAllCases(cs: typeof cases) {
		const promises: Promise<void>[] = [];
		for (const vc of cs) {
			for (const f of vc.findings) {
				if (f.code_snippet && !codeCache[f.id]) {
					codeCache[f.id] = ''; // sentinel: in-progress
					const { id, code_snippet, line_start, line_end, severity } = f;
					const lang = vc.language;
					promises.push(
						highlightSnippet(code_snippet, lang, line_start, line_end, severity)
							.then((html) => { codeCache[id] = html; })
							.catch(() => { /* keep sentinel, falls back to plain <pre> */ })
					);
				}
			}
		}
		await Promise.all(promises);
	}

	$effect(() => {
		const cs = cases; // track cases changes
		untrack(() => { void highlightAllCases(cs); });
	});

	function isExpanded(caseNo: number) {
		return expandedCases[caseNo] !== false;
	}

	function toggleExpand(caseNo: number) {
		expandedCases[caseNo] = !isExpanded(caseNo);
	}

	async function handleSubmit(caseNo: number) {
		submittingCases[caseNo] = true;
		try {
			await onsubmit(caseNo);
		} finally {
			submittingCases[caseNo] = false;
		}
	}


</script>

{#if cases.length === 0}
	<div class="flex-1 flex items-center justify-center bg-gray-950">
		<div class="text-center">
			<div class="w-12 h-12 mx-auto mb-4 rounded-full bg-gray-800/60 border border-gray-700 flex items-center justify-center">
				<svg class="w-5 h-5 text-gray-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
					<path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5"
						d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01" />
				</svg>
			</div>
			<p class="text-sm text-gray-600">No cases pending.</p>
			<p class="text-xs text-gray-700 mt-1">
				Scan code and click <span class="text-indigo-500 font-medium">Submit →</span> to queue a case.
			</p>
		</div>
	</div>
{:else}
	<div class="flex-1 overflow-y-auto px-6 py-5 bg-gray-950">
		<div class="max-w-2xl mx-auto space-y-3">
			<p class="text-xs text-gray-600 mb-2">
				{cases.length} case{cases.length !== 1 ? 's' : ''} pending verification
			</p>

			{#each cases as vc (vc.caseNo)}
				{@const labeledCount = Object.keys(vc.labels).length}
				{@const tpCount = Object.values(vc.labels).filter((l) => l === 'tp').length}
				{@const fpCount = Object.values(vc.labels).filter((l) => l === 'fp').length}
				{@const expanded = isExpanded(vc.caseNo)}
				{@const submitting = submittingCases[vc.caseNo] ?? false}

				<div class="rounded-xl border border-gray-800 bg-gray-900 overflow-hidden">
					<!-- Header -->
					<button
						onclick={() => toggleExpand(vc.caseNo)}
						class="w-full flex items-center gap-2.5 px-4 py-3 hover:bg-gray-800/50 transition-colors text-left"
					>
						<span class="font-mono text-sm font-bold text-indigo-400 shrink-0">
							#{String(vc.caseNo).padStart(4, '0')}
						</span>
						{#if vc.cveId}
							<span class="font-mono text-xs text-amber-400 shrink-0">{vc.cveId}</span>
						{/if}
						<span class="text-xs text-gray-500 shrink-0">{formatDate(vc.submittedAt)}</span>
						<span class={`text-xs px-1.5 py-0.5 rounded border font-mono shrink-0 ${langColor[vc.language] ?? 'text-gray-400 bg-gray-800 border-gray-600'}`}>
							{vc.language}
						</span>
						<span class="text-xs text-gray-500 shrink-0">{vc.findings.length} findings</span>
						{#if labeledCount > 0}
							<span class="text-xs text-gray-600 shrink-0">
								{#if tpCount > 0}<span class="text-emerald-600">TP:{tpCount}</span>{/if}
								{#if tpCount > 0 && fpCount > 0}<span class="text-gray-700 mx-1">·</span>{/if}
								{#if fpCount > 0}<span class="text-red-700">FP:{fpCount}</span>{/if}
							</span>
						{/if}
						<svg
							class={`ml-auto w-4 h-4 text-gray-600 transition-transform shrink-0 ${expanded ? 'rotate-180' : ''}`}
							fill="none" viewBox="0 0 24 24" stroke="currentColor"
						>
							<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
						</svg>
					</button>

					<!-- Body -->
					{#if expanded}
						<div class="border-t border-gray-800 divide-y divide-gray-800/60">
							{#each vc.findings as f (f.id)}
								{@const labeled = vc.labels[f.id] ?? null}

								<div class="px-4 py-3 flex gap-3">
									<div class="flex-1 min-w-0 space-y-2">
										<!-- Finding meta -->
										<div class="flex flex-wrap items-center gap-2">
											<span class={`text-xs font-bold uppercase ${sevColor[f.severity] ?? 'text-gray-400'}`}>
												{f.severity}
											</span>
											<span class="font-mono text-xs text-gray-500">{f.rule_id}</span>
											{#if f.cwe}
												<span class="text-xs text-gray-600 font-mono px-1 bg-gray-800 rounded border border-gray-700">
													{f.cwe}
												</span>
											{/if}
											<span class="text-xs text-gray-700 font-mono">
												{f.line_end > f.line_start ? `L${f.line_start}–${f.line_end}` : `L${f.line_start}`}
											</span>
										</div>

										<!-- Message -->
										<p class="text-xs text-gray-300 leading-snug">{f.message}</p>

										<!-- Code snippet -->
										{#if f.code_snippet}
											<div class="rounded border border-gray-800 overflow-hidden">
												{#if codeCache[f.id]}
													<div
														class="shiki-snippet"
														style="max-height:8rem; overflow-y:auto; font-size:0.68rem; line-height:1.5;"
													>
														{@html codeCache[f.id]}
													</div>
												{:else}
													<pre class="text-gray-300 text-xs p-2 overflow-x-auto max-h-32">{f.code_snippet}</pre>
												{/if}
											</div>
										{/if}
									</div>

									<!-- TP / FP buttons -->
									<div class="flex flex-col gap-1.5 shrink-0 pt-0.5">
										<button
											onclick={() => onlabel(vc.caseNo, f.id, 'tp')}
											disabled={labeled !== null}
											class={[
												'text-xs px-3 py-1 rounded border font-medium transition-colors',
												labeled === 'tp'
													? 'bg-emerald-700 border-emerald-600 text-white'
													: labeled === 'fp'
														? 'bg-gray-800 border-gray-700 text-gray-600 cursor-not-allowed'
														: 'bg-emerald-900/30 border-emerald-700/60 text-emerald-400 hover:bg-emerald-900/60 cursor-pointer'
											].join(' ')}
										>
											TP
										</button>
										<button
											onclick={() => onlabel(vc.caseNo, f.id, 'fp')}
											disabled={labeled !== null}
											class={[
												'text-xs px-3 py-1 rounded border font-medium transition-colors',
												labeled === 'fp'
													? 'bg-red-700 border-red-600 text-white'
													: labeled === 'tp'
														? 'bg-gray-800 border-gray-700 text-gray-600 cursor-not-allowed'
														: 'bg-red-900/30 border-red-700/60 text-red-400 hover:bg-red-900/60 cursor-pointer'
											].join(' ')}
										>
											FP
										</button>
									</div>
								</div>
							{/each}

							<!-- Submit footer -->
							<div class="px-4 py-3 bg-gray-900/60 flex items-center justify-between gap-3">
								<span class="text-xs text-gray-600">
									{labeledCount}/{vc.findings.length} labeled
									{#if labeledCount > 0}
										&nbsp;·&nbsp;<span class="text-emerald-600">{tpCount} TP</span>
										&nbsp;·&nbsp;<span class="text-red-600">{fpCount} FP</span>
									{/if}
								</span>
								<button
									onclick={() => handleSubmit(vc.caseNo)}
									disabled={submitting || labeledCount === 0}
									class={[
										'px-5 py-1.5 rounded text-sm font-semibold transition-colors',
										submitting || labeledCount === 0
											? 'bg-gray-800 text-gray-600 cursor-not-allowed'
											: 'bg-indigo-600 hover:bg-indigo-500 text-white cursor-pointer'
									].join(' ')}
								>
									{submitting ? 'Submitting…' : 'Submit to Knowledge'}
								</button>
							</div>
						</div>
					{/if}
				</div>
			{/each}
		</div>
	</div>
{/if}
