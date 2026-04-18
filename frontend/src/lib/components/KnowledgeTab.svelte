<script lang="ts">
	import type { Stats, VerifiedEntry } from '$lib/types';

	let { stats, history }: { stats: Stats | null; history: VerifiedEntry[] } = $props();

	const STAGES = [
		{ key: 'bootstrapping', label: 'Bootstrapping', min: 0 },
		{ key: 'learning', label: 'Learning', min: 1 },
		{ key: 'refining', label: 'Refining', min: 50 },
		{ key: 'mature', label: 'Mature', min: 500 }
	];

	const sevColor: Record<string, string> = {
		critical: 'text-red-400 bg-red-950/60 border-red-800',
		high: 'text-orange-400 bg-orange-950/60 border-orange-800',
		medium: 'text-yellow-400 bg-yellow-950/60 border-yellow-800',
		low: 'text-blue-400 bg-blue-950/60 border-blue-800'
	};
	const sevDot: Record<string, string> = {
		critical: 'bg-red-500',
		high: 'bg-orange-500',
		medium: 'bg-yellow-500',
		low: 'bg-blue-500'
	};
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
	const stageColor: Record<string, string> = {
		bootstrapping: 'text-gray-500',
		learning: 'text-blue-400',
		refining: 'text-indigo-400',
		mature: 'text-emerald-400'
	};

	function formatDate(iso: string) {
		const d = new Date(iso);
		return (
			d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }) +
			'  ' +
			d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false })
		);
	}

	const total = $derived(stats?.total_labels ?? 0);
	const tp = $derived(stats?.tp_count ?? 0);
	const fp = $derived(stats?.fp_count ?? 0);
	const tpRatio = $derived(total > 0 ? tp / total : 0);

	const stageIdx = $derived(
		Math.max(0, STAGES.findIndex((s) => s.key === stats?.model_stage))
	);
	const curMin = $derived(STAGES[stageIdx].min);
	const nextStage = $derived(STAGES[stageIdx + 1] ?? null);
	const bandPct = $derived(
		nextStage !== null
			? Math.min(100, Math.round(((total - curMin) / (nextStage.min - curMin)) * 100))
			: 100
	);
</script>

<div class="flex flex-1 min-h-0">
	<!-- Left: Case History -->
	<div class="flex-1 min-w-0 overflow-y-auto px-5 py-4 border-r border-gray-800">
		<div class="max-w-2xl">
			<div class="flex items-center gap-2 mb-4">
				<h2 class="text-xs font-semibold text-gray-500 uppercase tracking-widest">
					Verified Cases
				</h2>
				{#if history.length > 0}
					<span class="text-[10px] bg-gray-800 text-gray-500 rounded-full px-1.5 py-0.5">
						{history.length}
					</span>
				{/if}
			</div>

			{#if history.length === 0}
				<div class="flex flex-col items-center justify-center py-20 gap-3">
					<div class="w-12 h-12 rounded-full bg-gray-800/60 border border-gray-700 flex items-center justify-center">
						<svg class="w-5 h-5 text-gray-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
							<path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5"
								d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
						</svg>
					</div>
					<p class="text-sm text-gray-600">No verified cases yet.</p>
					<p class="text-xs text-gray-700">Submit cases from the Verify tab to build the knowledge base.</p>
				</div>
			{:else}
				<div class="space-y-3">
					{#each history as entry (entry.caseNo)}
						<article class="rounded-xl border border-gray-800 bg-gray-900 overflow-hidden hover:border-gray-700 transition-colors">
							<!-- Header bar -->
							<div class="flex items-center gap-2.5 px-4 py-2.5 border-b border-gray-800/60 bg-gray-900/80">
								<span class="font-mono text-sm font-bold text-indigo-400 shrink-0">
									#{String(entry.caseNo).padStart(4, '0')}
								</span>
								<span class={`text-[10px] px-1.5 py-0.5 rounded border font-mono shrink-0 ${langColor[entry.language] ?? 'text-gray-400 bg-gray-800 border-gray-600'}`}>
									{entry.language}
								</span>
								{#if entry.maxSeverity}
									<span class={`ml-auto text-[10px] font-bold uppercase px-2 py-0.5 rounded border shrink-0 ${sevColor[entry.maxSeverity]}`}>
										{entry.maxSeverity}
									</span>
								{/if}
							</div>

							<!-- Findings list -->
							{#if entry.findingCount > 0}
								<div class="px-4 pt-3 pb-2 space-y-2">
									{#each entry.ruleIds.slice(0, 4) as rid, i}
										<div class="flex items-start gap-2">
											<div class={`w-1.5 h-1.5 rounded-full mt-1.5 shrink-0 ${sevDot[entry.maxSeverity ?? 'low'] ?? 'bg-gray-600'}`}></div>
											<div class="min-w-0">
												<span class="font-mono text-xs text-gray-300 truncate block">{rid}</span>
												{#if entry.cwes[i]}
													<span class="text-[10px] text-gray-600 font-mono">{entry.cwes[i]}</span>
												{/if}
											</div>
										</div>
									{/each}
									{#if entry.ruleIds.length > 4}
										<p class="text-[10px] text-gray-700 pl-3.5">+{entry.ruleIds.length - 4} more</p>
									{/if}
								</div>
							{:else}
								<div class="px-4 py-2.5">
									<span class="text-xs text-gray-700 italic">No findings detected</span>
								</div>
							{/if}

							<!-- Footer -->
							<div class="flex items-center gap-3 px-4 py-2 border-t border-gray-800/40 bg-gray-950/30">
								<span class="text-[10px] text-gray-600 tabular-nums">
									{entry.findingCount} finding{entry.findingCount !== 1 ? 's' : ''}
								</span>
								{#if entry.tpCount > 0}
									<span class="text-[10px] text-emerald-600 font-medium">TP:{entry.tpCount}</span>
								{/if}
								{#if entry.fpCount > 0}
									<span class="text-[10px] text-red-700 font-medium">FP:{entry.fpCount}</span>
								{/if}
								{#if entry.findingCount > 0}
									<span class="text-[10px] text-gray-700 tabular-nums">
										conf:{Math.round(entry.avgConfidence * 100)}%
									</span>
								{/if}
								<span class="ml-auto text-[10px] text-gray-700 tabular-nums shrink-0">
									{formatDate(entry.verifiedAt)}
								</span>
							</div>
						</article>
					{/each}
				</div>
			{/if}
		</div>
	</div>

	<!-- Right: Learning Status -->
	<div class="w-64 xl:w-72 shrink-0 overflow-y-auto px-4 py-4 bg-gray-950">
		<h2 class="text-[10px] font-semibold text-gray-600 uppercase tracking-widest mb-4">
			Learning Status
		</h2>

		<div class="space-y-4">
			<!-- Stage -->
			<section class="rounded-xl border border-gray-800 bg-gray-900 p-4">
				<h3 class="text-[10px] font-semibold text-gray-600 uppercase tracking-widest mb-3">
					Model Status
				</h3>
				<div class="flex items-baseline gap-2 mb-3">
					<span class={`text-lg font-bold capitalize ${stageColor[stats?.model_stage ?? 'bootstrapping']}`}>
						{stats?.model_stage ?? 'bootstrapping'}
					</span>
					<span class="text-xs text-gray-600">stage</span>
				</div>

				<!-- Stage stepper -->
				<div class="flex items-center gap-1 mb-3">
					{#each STAGES as s, i}
						{@const done = i < stageIdx}
						{@const active = i === stageIdx}
						<div class="flex items-center flex-1 last:flex-none">
							<div class={['h-1.5 flex-1 rounded-full', done ? 'bg-emerald-500' : active ? 'bg-indigo-500/60' : 'bg-gray-800'].join(' ')}></div>
							{#if i === STAGES.length - 1}
								<div class={['w-2 h-2 rounded-full shrink-0 ml-1', done ? 'bg-emerald-500' : active ? 'bg-indigo-400' : 'bg-gray-800'].join(' ')}></div>
							{/if}
						</div>
					{/each}
				</div>

				<div class="text-[10px] text-gray-700">
					{#each STAGES as s, i}
						<span class={i <= stageIdx ? 'text-gray-500' : 'text-gray-700'}>
							{s.label}{i < STAGES.length - 1 ? ' → ' : ''}
						</span>
					{/each}
				</div>

				{#if nextStage !== null}
					<div class="mt-3">
						<div class="flex justify-between text-[10px] text-gray-700 mb-1">
							<span>{nextStage.label}</span>
							<span class="text-indigo-500">{total} / {nextStage.min}</span>
						</div>
						<div class="h-1.5 bg-gray-800 rounded-full overflow-hidden">
							<div
								class="h-full bg-gradient-to-r from-indigo-700 to-indigo-400 transition-all duration-700"
								style="width:{bandPct}%"
							></div>
						</div>
					</div>
				{/if}

				<p class="text-[10px] text-gray-700 italic mt-2">Retrains on every Verify Submit</p>
			</section>

			<!-- Label stats -->
			<section class="rounded-xl border border-gray-800 bg-gray-900 p-4">
				<h3 class="text-[10px] font-semibold text-gray-600 uppercase tracking-widest mb-3">
					Accumulated Labels
				</h3>

				<div class="grid grid-cols-3 gap-2 mb-3">
					{#each [{ label: 'Total', value: total, color: 'text-gray-100' }, { label: 'TP', value: tp, color: 'text-emerald-400' }, { label: 'FP', value: fp, color: 'text-red-400' }] as item}
						<div class="bg-gray-800/50 rounded-lg p-2.5 text-center border border-gray-700/30">
							<div class={`text-xl font-bold tabular-nums ${item.color}`}>{item.value}</div>
							<div class="text-[10px] text-gray-600 mt-0.5">{item.label}</div>
						</div>
					{/each}
				</div>

				{#if total > 0}
					<div class="flex justify-between text-[10px] text-gray-600 mb-1">
						<span>TP / FP ratio</span>
						<span>
							<span class="text-emerald-500">{Math.round(tpRatio * 100)}%</span>
							{' / '}
							<span class="text-red-500">{Math.round((1 - tpRatio) * 100)}%</span>
						</span>
					</div>
					<div class="h-2 bg-gray-800 rounded-full overflow-hidden flex">
						<div class="h-full bg-emerald-500 transition-all duration-700" style="width:{tpRatio * 100}%"></div>
						<div class="h-full bg-red-500/60 transition-all duration-700" style="width:{(1 - tpRatio) * 100}%"></div>
					</div>
				{:else}
					<p class="text-[10px] text-gray-700 text-center py-1">
						No labels yet — verify cases to accumulate knowledge.
					</p>
				{/if}
			</section>

			<!-- Summary -->
			<section class="rounded-xl border border-gray-800 bg-gray-900 p-4">
				<h3 class="text-[10px] font-semibold text-gray-600 uppercase tracking-widest mb-3">Summary</h3>
				<div class="space-y-1.5">
					{#each [{ label: 'Cases verified', value: history.length }, { label: 'Findings labeled', value: total }, { label: 'True positives', value: tp }, { label: 'False positives', value: fp }] as r}
						<div class="flex justify-between text-xs">
							<span class="text-gray-600">{r.label}</span>
							<span class="text-gray-300 tabular-nums font-medium">{r.value}</span>
						</div>
					{/each}
				</div>
			</section>
		</div>
	</div>
</div>
