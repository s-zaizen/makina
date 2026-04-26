<script lang="ts">
	import type { KnowledgeCase, Label, Language } from '$lib/types';
	import CodeEditor from '$lib/components/CodeEditor.svelte';
	import FindingCard from '$lib/components/FindingCard.svelte';

	let { history }: { history: KnowledgeCase[] } = $props();

	const sevColor: Record<string, string> = {
		critical: 'text-red-400 bg-red-950/60 border-red-800',
		high: 'text-orange-400 bg-orange-950/60 border-orange-800',
		medium: 'text-yellow-400 bg-yellow-950/60 border-yellow-800',
		low: 'text-blue-400 bg-blue-950/60 border-blue-800'
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

	function formatDate(iso: string) {
		const d = new Date(iso);
		return (
			d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }) +
			'  ' +
			d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false })
		);
	}

	// Filter state
	let searchQuery = $state('');
	let filterLang = $state<string | null>(null);
	let filterLabel = $state<'tp' | 'fp' | null>(null);

	// Virtualized list: render only the first N matches by default.
	// With 10k+ cases, rendering every row DOM at once freezes the tab.
	const PAGE_SIZE = 150;
	let displayLimit = $state(PAGE_SIZE);

	// Reset page limit whenever a filter changes.
	$effect(() => {
		void searchQuery;
		void filterLang;
		void filterLabel;
		displayLimit = PAGE_SIZE;
	});

	function onListScroll(e: Event) {
		const el = e.currentTarget as HTMLElement;
		if (el.scrollHeight - el.scrollTop - el.clientHeight < 200) {
			// Near bottom — load next page
			displayLimit += PAGE_SIZE;
		}
	}

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
	<div class="w-56 md:w-60 lg:w-64 xl:w-72 shrink-0 flex flex-col border-r border-gray-800 bg-gray-950/70">
		<!-- Header + search -->
		<div class="shrink-0 border-b border-gray-800/60">
			<div class="flex items-center gap-2 px-4 py-2.5">
				<h2 class="text-xs font-semibold text-gray-500 uppercase tracking-widest">
					Verified Cases
				</h2>
				{#if history.length > 0}
					<span class="text-xs bg-gray-800 text-gray-500 rounded-full px-1.5 py-0.5">
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
				<!-- Label filters: equal-width grid -->
				<div class="px-3 pb-2 grid grid-cols-3 gap-1">
					{#each [['ALL', null], ['TP', 'tp'], ['FP', 'fp']] as [chipLabel, chipVal]}
						<button
							onclick={() => { filterLabel = chipVal as 'tp' | 'fp' | null; }}
							class={[
								'text-xs px-2 py-1 rounded border text-center transition-colors',
								filterLabel === chipVal
									? chipVal === 'tp' ? 'bg-emerald-700 border-emerald-600 text-white' : chipVal === 'fp' ? 'bg-red-700 border-red-600 text-white' : 'bg-indigo-700 border-indigo-600 text-white'
									: 'bg-gray-800 border-gray-700 text-gray-500 hover:text-gray-300 cursor-pointer'
							].join(' ')}
						>{chipLabel}</button>
					{/each}
				</div>

				<!-- Language filters: equal-width grid, 3 per row -->
				{#if availableLangs.length > 1}
					<div class="px-3 pb-2.5 grid grid-cols-3 gap-1">
						{#each availableLangs as lang}
							<button
								onclick={() => { filterLang = filterLang === lang ? null : lang; }}
								class={[
									'text-xs px-1 py-1 rounded border font-mono text-center truncate transition-colors',
									filterLang === lang
										? 'bg-indigo-700 border-indigo-600 text-white'
										: 'bg-gray-800 border-gray-700 text-gray-500 hover:text-gray-300 cursor-pointer'
								].join(' ')}
								title={lang.toUpperCase()}
							>{lang.toUpperCase()}</button>
						{/each}
					</div>
				{/if}
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
					class="text-xs text-indigo-500 hover:text-indigo-400 transition-colors cursor-pointer"
				>Clear filters</button>
			</div>
		{:else}
			<div class="flex-1 overflow-y-auto py-2" onscroll={onListScroll}>
				{#each filteredHistory.slice(0, displayLimit) as kc (kc.caseNo)}
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
							<span class={`text-xs px-1 py-0.5 rounded border font-mono shrink-0 ${langColor[kc.language] ?? 'text-gray-400 bg-gray-800 border-gray-600'}`}>
								{kc.language.toUpperCase()}
							</span>
							{#if maxSev}
								<span class={`ml-auto text-xs font-bold uppercase px-1.5 py-0.5 rounded border shrink-0 ${sevColor[maxSev]}`}>
									{maxSev}
								</span>
							{/if}
						</div>
						<div class="flex items-center gap-2 text-xs text-gray-600">
							<span>{kc.findings.length} findings</span>
							{#if tpCount > 0}<span class="text-emerald-600">TP:{tpCount}</span>{/if}
							{#if fpCount > 0}<span class="text-red-700">FP:{fpCount}</span>{/if}
							<span class="ml-auto truncate">{formatDate(kc.verifiedAt)}</span>
						</div>
					</button>
				{/each}
				{#if filteredHistory.length > displayLimit}
					<div class="px-3 py-3 text-center text-xs text-gray-600">
						Showing {displayLimit} of {filteredHistory.length}
						<button
							class="ml-2 text-indigo-400 hover:text-indigo-300 cursor-pointer"
							onclick={() => (displayLimit += PAGE_SIZE)}
						>load more</button>
					</div>
				{/if}
			</div>
		{/if}
	</div>

	<!-- Center: Code viewer + findings -->
	<div class="flex-1 min-w-0 flex flex-col min-h-0">
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
				<div class="hidden md:flex w-64 lg:w-72 xl:w-80 shrink-0 overflow-y-auto p-3 flex-col gap-2 bg-gray-950/70 border-l border-gray-800/60">
					<div class="flex items-center gap-2 mb-1">
						<span class="text-xs font-semibold text-gray-500 uppercase tracking-wider">
							Findings
						</span>
						<span class="text-xs bg-gray-800 text-gray-500 rounded-full px-1.5 py-0.5">
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
			<div class="flex-1 bg-gray-950/70"></div>
			<div class="pointer-events-none fixed top-12 bottom-9 left-0 right-0 z-20 flex flex-col items-center justify-center gap-3 text-center px-6">
				<div class="w-12 h-12 rounded-full bg-gray-800/60 border border-gray-700 flex items-center justify-center">
					<svg class="w-5 h-5 text-gray-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
						<path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5"
							d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
					</svg>
				</div>
				<p class="text-lg text-gray-600">Select a case to view code</p>
				<p class="text-base text-gray-700">Click any case in the left panel</p>
			</div>
		{/if}
	</div>
</div>
