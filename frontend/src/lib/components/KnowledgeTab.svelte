<script lang="ts">
	import type { Stats, KnowledgeCase, Label, Language } from '$lib/types';
	import CodeEditor from '$lib/components/CodeEditor.svelte';
	import FindingCard from '$lib/components/FindingCard.svelte';

	let { stats, history }: { stats: Stats | null; history: KnowledgeCase[] } = $props();

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

	// Filter state
	let searchQuery = $state('');
	let filterLang = $state<string | null>(null);
	let filterLabel = $state<'tp' | 'fp' | null>(null);

	const availableLangs = $derived([...new Set(history.map((c) => c.language))]);

	const filteredHistory = $derived(
		history.filter((kc) => {
			if (filterLang && kc.language !== filterLang) return false;
			if (filterLabel) {
				const vals = Object.values(kc.labels);
				if (!vals.includes(filterLabel)) return false;
			}
			if (searchQuery.trim()) {
				const q = searchQuery.toLowerCase();
				if (
					!kc.cveId?.toLowerCase().includes(q) &&
					!kc.findings.some(
						(f) =>
							f.rule_id.toLowerCase().includes(q) ||
							(f.cwe?.toLowerCase().includes(q) ?? false) ||
							f.message.toLowerCase().includes(q)
					)
				)
					return false;
			}
			return true;
		})
	);

	// Center panel selection — always derived from full history so viewer stays put while filtering
	let selectedCaseNo = $state<number | null>(null);
	let focusedFindingId = $state<string | null>(null);

	const selectedCase = $derived(history.find((c) => c.caseNo === selectedCaseNo) ?? null);
	const focusedLine = $derived(
		selectedCase?.findings.find((f) => f.id === focusedFindingId)?.line_start ?? null
	);

	function selectCase(caseNo: number) {
		selectedCaseNo = caseNo;
		focusedFindingId = null;
	}

	function getSeverityCounts(kc: KnowledgeCase) {
		const ruleIds = Array.from(new Set(kc.findings.map((f) => f.rule_id)));
		const cwes = Array.from(
			new Set(kc.findings.map((f) => f.cwe).filter((c): c is string => c !== null))
		);
		const tpCount = Object.values(kc.labels).filter((l) => l === 'tp').length;
		const fpCount = Object.values(kc.labels).filter((l) => l === 'fp').length;
		const maxSev = kc.findings.reduce<string | null>((acc, f) => {
			const order: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
			if (!acc || (order[f.severity] ?? 0) > (order[acc] ?? 0)) return f.severity;
			return acc;
		}, null);
		return { ruleIds, cwes, tpCount, fpCount, maxSev };
	}
</script>

<div class="flex flex-1 min-h-0">
	<!-- Left: Case list -->
	<div class="w-60 xl:w-72 shrink-0 flex flex-col border-r border-gray-800 bg-gray-950">
		<!-- Header + search -->
		<div class="shrink-0 border-b border-gray-800/60">
			<div class="flex items-center gap-2 px-4 py-2.5">
				<h2 class="text-[10px] font-semibold text-gray-500 uppercase tracking-widest">
					Verified Cases
				</h2>
				{#if history.length > 0}
					<span class="text-[10px] bg-gray-800 text-gray-500 rounded-full px-1.5 py-0.5">
						{filteredHistory.length}{filteredHistory.length !== history.length ? `/${history.length}` : ''}
					</span>
				{/if}
			</div>

			{#if history.length > 0}
				<div class="px-3 pb-2">
					<input
						bind:value={searchQuery}
						type="text"
						placeholder="Search CVE, rule, CWE…"
						class="w-full bg-gray-800/60 border border-gray-700 rounded-md px-2.5 py-1.5 text-xs text-gray-200 placeholder-gray-600 focus:outline-none focus:border-indigo-600/60 transition-colors"
					/>
				</div>
				<div class="px-3 pb-2.5 flex flex-wrap gap-1">
					{#each [['ALL', null], ['TP', 'tp'], ['FP', 'fp']] as [chipLabel, chipVal]}
						<button
							onclick={() => { filterLabel = chipVal as 'tp' | 'fp' | null; }}
							class={[
								'text-[10px] px-2 py-0.5 rounded border transition-colors',
								filterLabel === chipVal
									? chipVal === 'tp' ? 'bg-emerald-700 border-emerald-600 text-white' : chipVal === 'fp' ? 'bg-red-700 border-red-600 text-white' : 'bg-indigo-700 border-indigo-600 text-white'
									: 'bg-gray-800 border-gray-700 text-gray-500 hover:text-gray-300 cursor-pointer'
							].join(' ')}
						>{chipLabel}</button>
					{/each}
					{#if availableLangs.length > 1}
						{#each availableLangs as lang}
							<button
								onclick={() => { filterLang = filterLang === lang ? null : lang; }}
								class={[
									'text-[10px] px-2 py-0.5 rounded border font-mono transition-colors',
									filterLang === lang
										? 'bg-indigo-700 border-indigo-600 text-white'
										: 'bg-gray-800 border-gray-700 text-gray-500 hover:text-gray-300 cursor-pointer'
								].join(' ')}
							>{lang.toUpperCase()}</button>
						{/each}
					{/if}
				</div>
			{/if}
		</div>

		{#if history.length === 0}
			<div class="flex flex-col items-center justify-center flex-1 gap-3 px-4">
				<div class="w-10 h-10 rounded-full bg-gray-800/60 border border-gray-700 flex items-center justify-center">
					<svg class="w-4 h-4 text-gray-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
						<path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5"
							d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
					</svg>
				</div>
				<p class="text-xs text-gray-600 text-center">No verified cases yet.</p>
			</div>
		{:else if filteredHistory.length === 0}
			<div class="flex flex-col items-center justify-center flex-1 gap-2 px-4">
				<p class="text-xs text-gray-600 text-center">No cases match the current filter.</p>
				<button
					onclick={() => { searchQuery = ''; filterLang = null; filterLabel = null; }}
					class="text-[10px] text-indigo-500 hover:text-indigo-400 transition-colors cursor-pointer"
				>Clear filters</button>
			</div>
		{:else}
			<div class="flex-1 overflow-y-auto py-2">
				{#each filteredHistory as kc (kc.caseNo)}
					{@const { maxSev, tpCount, fpCount } = getSeverityCounts(kc)}
					<button
						onclick={() => selectCase(kc.caseNo)}
						class={[
							'w-full text-left px-3 py-2.5 flex flex-col gap-1 transition-colors',
							selectedCaseNo === kc.caseNo
								? 'bg-indigo-600/20 border-r-2 border-indigo-500'
								: 'hover:bg-gray-800/50 border-r-2 border-transparent'
						].join(' ')}
					>
						<div class="flex items-center gap-2">
							<span class="font-mono text-xs font-bold text-indigo-400 shrink-0">
								#{String(kc.caseNo).padStart(4, '0')}
							</span>
							<span class={`text-[10px] px-1 py-0.5 rounded border font-mono shrink-0 ${langColor[kc.language] ?? 'text-gray-400 bg-gray-800 border-gray-600'}`}>
								{kc.language.toUpperCase()}
							</span>
							{#if maxSev}
								<span class={`ml-auto text-[10px] font-bold uppercase px-1.5 py-0.5 rounded border shrink-0 ${sevColor[maxSev]}`}>
									{maxSev}
								</span>
							{/if}
						</div>
						<div class="flex items-center gap-2 text-[10px] text-gray-600">
							<span>{kc.findings.length} findings</span>
							{#if tpCount > 0}<span class="text-emerald-600">TP:{tpCount}</span>{/if}
							{#if fpCount > 0}<span class="text-red-700">FP:{fpCount}</span>{/if}
							<span class="ml-auto truncate">{formatDate(kc.verifiedAt)}</span>
						</div>
					</button>
				{/each}
			</div>
		{/if}
	</div>

	<!-- Center: Code viewer + findings -->
	<div class="flex-1 min-w-0 flex flex-col min-h-0 border-r border-gray-800/60">
		{#if selectedCase}
			<div class="flex flex-1 min-h-0">
				<!-- Code editor (readonly) -->
				<div class="flex-1 min-w-0 flex flex-col min-h-0">
					<CodeEditor
						value={selectedCase.code}
						onchange={() => {}}
						language={selectedCase.language as Language}
						findings={selectedCase.findings}
						focusedLine={focusedLine}
						readonly={true}
						filename={`case-${String(selectedCase.caseNo).padStart(4, '0')}.${selectedCase.language}`}
					/>
				</div>

				<!-- Finding cards -->
				<div class="w-80 xl:w-96 shrink-0 overflow-y-auto p-3 flex flex-col gap-2 bg-gray-950 border-l border-gray-800/60">
					<div class="flex items-center gap-2 mb-1">
						<span class="text-[10px] font-semibold text-gray-600 uppercase tracking-widest">
							Findings
						</span>
						<span class="text-[10px] bg-gray-800 text-gray-500 rounded-full px-1.5 py-0.5">
							{selectedCase.findings.length}
						</span>
					</div>
					{#each selectedCase.findings as f (f.id)}
						<FindingCard
							finding={f}
							language={selectedCase.language as Language}
							onlabel={async () => {}}
							onfocus={() => (focusedFindingId = f.id)}
							focused={f.id === focusedFindingId}
							readonly={true}
							existingLabel={(selectedCase.labels[f.id] as Label | undefined) ?? null}
						/>
					{/each}
				</div>
			</div>
		{:else}
			<div class="flex-1 flex flex-col items-center justify-center gap-3 text-center px-6">
				<div class="w-12 h-12 rounded-full bg-gray-800/60 border border-gray-700 flex items-center justify-center">
					<svg class="w-5 h-5 text-gray-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
						<path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5"
							d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
					</svg>
				</div>
				<p class="text-sm text-gray-600">Select a case to view code</p>
				<p class="text-xs text-gray-700">Click any case in the left panel</p>
			</div>
		{/if}
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
