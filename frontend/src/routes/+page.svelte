<script lang="ts">
	import { onMount } from 'svelte';
	import { SvelteSet } from 'svelte/reactivity';
	import CodeEditor from '$lib/components/CodeEditor.svelte';
	import FileTree from '$lib/components/FileTree.svelte';
	import FindingCard from '$lib/components/FindingCard.svelte';
	import KnowledgeTab from '$lib/components/KnowledgeTab.svelte';
	import ModelTab from '$lib/components/ModelTab.svelte';
	import ScanPanel from '$lib/components/ScanPanel.svelte';
	import StatusBar from '$lib/components/StatusBar.svelte';
	import VerifyTab from '$lib/components/VerifyTab.svelte';
	import {
		scanCode,
		submitFeedback,
		getStats,
		getVerifyQueue,
		addToVerifyQueue,
		getKnowledgeHistory,
		submitToKnowledge
	} from '$lib/api';
	import { preloadHighlighter } from '$lib/highlighter';
	import { readFolder, flatFiles } from '$lib/folder';
	import { PLACEHOLDERS } from '$lib/placeholders';
	import { PUBLIC_MODE } from '$lib/flags';
	import type { Finding, Language, Label, Stats, VerifyCase, KnowledgeCase, FileNode } from '$lib/types';

	type Tab = 'scan' | 'verify' | 'knowledge' | 'model';

	// Tabs that mutate the learning corpus are hidden in public deployments
	// (the model is frozen, so Verify Submit / Model retrain have no effect).
	const VISIBLE_TABS: readonly Tab[] = PUBLIC_MODE
		? (['scan', 'knowledge'] as const)
		: (['scan', 'verify', 'knowledge', 'model'] as const);

	// ── State ────────────────────────────────────────────────────────────────────

	let activeTab = $state<Tab>('scan');
	let language = $state<Language>('python');
	let code = $state(PLACEHOLDERS.python);
	let findings = $state<Finding[]>([]);
	let scanning = $state(false);
	let stats = $state<Stats | null>(null);
	let error = $state<string | null>(null);
	let focusedFindingId = $state<string | null>(null);

	let verifyCases = $state<VerifyCase[]>([]);
	let knowledgeHistory = $state<KnowledgeCase[]>([]);

	let folderRoot = $state<FileNode | null>(null);
	let selectedFile = $state<FileNode | null>(null);
	let scannedPaths = new SvelteSet<string>();
	let scanProgress = $state<{ current: number; total: number } | null>(null);

	const focusedFinding = $derived(findings.find((f) => f.id === focusedFindingId));
	const focusedLine = $derived(focusedFinding?.line_start ?? null);
	const currentFilename = $derived(selectedFile?.name);

	// ── Init ─────────────────────────────────────────────────────────────────────

	// Live counter for stats (cheap, 2s poll) + throttled refresh of the
	// heavy queue/knowledge endpoints only when the label count actually
	// moved. Keeps the header ticking during bulk imports without hammering
	// the backend with full list fetches every interval.
	const HEAVY_REFRESH_INTERVAL_MS = 3_000;
	let lastSeenTotalLabels = 0;
	let lastHeavyRefreshAt = 0;

	async function refreshHeavy() {
		try {
			verifyCases = await getVerifyQueue();
		} catch { /* backend not running */ }
		try {
			knowledgeHistory = await getKnowledgeHistory();
		} catch { /* backend not running */ }
		lastHeavyRefreshAt = Date.now();
	}

	async function pollTick() {
		try {
			const s = await getStats();
			stats = s;
			const moved = s.total_labels !== lastSeenTotalLabels;
			lastSeenTotalLabels = s.total_labels;
			if (moved && Date.now() - lastHeavyRefreshAt >= HEAVY_REFRESH_INTERVAL_MS) {
				await refreshHeavy();
			}
		} catch { /* backend not running */ }
	}

	onMount(() => {
		void preloadHighlighter();
		void refreshHeavy();
		void pollTick();
		const tick = setInterval(() => void pollTick(), 2000);
		return () => clearInterval(tick);
	});

	// ── Helpers ──────────────────────────────────────────────────────────────────

	async function refreshStats() {
		try {
			stats = await getStats();
		} catch { /* backend not running */ }
	}

	// ── Handlers ─────────────────────────────────────────────────────────────────

	function handleLanguageChange(lang: Language) {
		language = lang;
		code = PLACEHOLDERS[lang];
		findings = [];
		focusedFindingId = null;
	}

	async function handleScan() {
		scanning = true;
		error = null;
		focusedFindingId = null;
		try {
			const result = await scanCode(code, language);
			findings = result.findings;
		} catch {
			error = 'Cannot connect to makina server. Run: docker compose up -d';
		} finally {
			scanning = false;
		}
	}

	async function handleSubmitToVerify() {
		if (findings.length === 0) return;
		try {
			const newCase = await addToVerifyQueue(null, code, language, findings);
			verifyCases = [...verifyCases, newCase];
		} catch {
			const localCase: VerifyCase = {
				caseNo: Date.now(),
				code,
				language,
				findings: [...findings],
				submittedAt: new Date().toISOString(),
				labels: {}
			};
			verifyCases = [...verifyCases, localCase];
		}
		findings = [];
		focusedFindingId = null;
		activeTab = 'verify';
	}

	function handleCaseLabel(caseNo: number, findingId: string, label: Label) {
		verifyCases = verifyCases.map((vc) =>
			vc.caseNo === caseNo
				? { ...vc, labels: { ...vc.labels, [findingId]: label } }
				: vc
		);
	}

	async function handleCaseSubmit(caseNo: number) {
		const vc = verifyCases.find((c) => c.caseNo === caseNo);
		if (!vc) return;

		await submitToKnowledge(caseNo, vc.labels);

		const knowledgeCase: KnowledgeCase = {
			caseNo: vc.caseNo,
			cveId: vc.cveId,
			code: vc.code,
			language: vc.language,
			findings: vc.findings,
			labels: { ...vc.labels },
			submittedAt: vc.submittedAt,
			verifiedAt: new Date().toISOString()
		};
		knowledgeHistory = [knowledgeCase, ...knowledgeHistory];
		verifyCases = verifyCases.filter((c) => c.caseNo !== caseNo);
		await refreshStats();
	}

	function handleFocusFinding(id: string) {
		focusedFindingId = id;
		activeTab = 'scan';
	}

	async function handleFolderDrop(item: DataTransferItem) {
		const root = await readFolder(item);
		if (!root) return;
		folderRoot = root;
		scannedPaths.clear();
		scanProgress = null;
		const files = flatFiles(root);
		if (files.length > 0) handleSelectFile(files[0]);
	}

	function handleSelectFile(node: FileNode) {
		if (!node.content || !node.language) return;
		selectedFile = node;
		code = node.content;
		language = node.language;
		findings = [];
		focusedFindingId = null;
	}

	async function handleScanAll() {
		if (!folderRoot) return;
		const files = flatFiles(folderRoot);
		scanProgress = { current: 0, total: files.length };
		for (let i = 0; i < files.length; i++) {
			const f = files[i];
			if (!f.content || !f.language) continue;
			try {
				const result = await scanCode(f.content, f.language);
				if (result.findings.length > 0) {
					await addToVerifyQueue(null, f.content, f.language, result.findings)
						.then((c) => (verifyCases = [...verifyCases, c]))
						.catch(() => {});
				}
				scannedPaths.add(f.path);
			} catch { /* continue */ }
			scanProgress = { current: i + 1, total: files.length };
		}
		scanProgress = null;
	}

	function handleClearFolder() {
		folderRoot = null;
		selectedFile = null;
		scannedPaths.clear();
		scanProgress = null;
	}
</script>

<div class="relative flex flex-col h-screen text-gray-100 overflow-hidden" style="background:#060a12;">

	<!-- Background eye (watching you). Sits at z-0 on the page root; content
	     panels are rendered above this but many (editor / sidebars) use their
	     own opaque background, so the eye mainly peeks through gaps and empty
	     states. Opacity is tuned to be ambient, not distracting. -->
	<div
		class="pointer-events-none fixed inset-0 flex items-center justify-center z-0"
		aria-hidden="true"
	>
		<img
			src="/eye-bg.svg"
			alt=""
			class="w-[135vmin] h-[135vmin] opacity-[0.18] select-none"
			style="filter: blur(0.5px);"
			draggable="false"
		/>
	</div>

	<!-- Header -->
	<div class="relative z-10 flex items-center gap-3 h-12 px-4 bg-gray-900/90 border-b border-gray-800 shrink-0 backdrop-blur-sm">
		<span class="text-base font-bold text-gray-100 tracking-tight">makina</span>
		<div class="w-px h-5 bg-gray-700 mx-1"></div>

		<!-- Tabs -->
		<nav class="flex items-center gap-1">
			{#each VISIBLE_TABS as tab}
				<button
					onclick={() => (activeTab = tab)}
					class={[
						'flex items-center px-3.5 py-1.5 rounded text-sm font-medium capitalize transition-all',
						activeTab === tab
							? 'bg-indigo-600/30 text-indigo-300 border border-indigo-700/60'
							: 'text-gray-500 hover:text-gray-300 hover:bg-gray-800 border border-transparent'
					].join(' ')}
				>
					{tab}
					{#if tab === 'verify' && verifyCases.length > 0}
						<span class="ml-1.5 text-xs font-bold bg-indigo-600/50 text-indigo-200 rounded-full px-1.5 py-0.5">
							{verifyCases.length}
						</span>
					{/if}
				</button>
			{/each}
		</nav>

		<!-- Scan controls -->
		{#if activeTab === 'scan'}
			<div class="ml-auto">
				<ScanPanel
					{language}
					onlanguagechange={handleLanguageChange}
					onscan={handleScan}
					{scanning}
					hasFindings={findings.length > 0}
					onsubmittoverify={handleSubmitToVerify}
				/>
			</div>
		{/if}
	</div>

	<!-- Content -->
	<div class="relative z-10 flex flex-col flex-1 min-h-0">
	{#if activeTab === 'scan'}
		<div class="flex flex-1 min-h-0">
			<!-- File tree sidebar — always present; shows an empty-state
			     placeholder until a folder is loaded so users see the
			     workspace layout from the first paint. -->
			<div class="hidden lg:flex w-52 xl:w-60 shrink-0 flex-col">
				{#if folderRoot}
					<FileTree
						root={folderRoot}
						selectedPath={selectedFile?.path ?? null}
						{scannedPaths}
						{scanProgress}
						onselect={handleSelectFile}
						onscanall={handleScanAll}
						onclear={handleClearFolder}
					/>
				{:else}
					<div class="flex h-full flex-col bg-gray-950/70 border-r border-gray-800/60">
						<div class="flex items-center gap-2 px-3 py-2 border-b shrink-0" style="border-color:#1a2035;">
							<span class="text-xs font-mono text-gray-600 truncate flex-1">
								(no folder)
							</span>
						</div>
						<div class="flex flex-1 flex-col items-center justify-center gap-3 px-4 text-center">
							<svg
								class="w-8 h-8 text-gray-700"
								fill="none"
								viewBox="0 0 24 24"
								stroke="currentColor"
								stroke-width="1.4"
							>
								<path
									stroke-linecap="round"
									stroke-linejoin="round"
									d="M3 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2V7z"
								/>
							</svg>
							<p class="text-xs text-gray-500 leading-relaxed">
								Drop a folder<br />on the editor
							</p>
							<p class="text-[10px] text-gray-700 italic leading-relaxed">
								or paste code into the editor for a one-off scan
							</p>
						</div>
					</div>
				{/if}
			</div>

			<!-- Editor -->
			<div class="flex flex-1 flex-col min-h-0 border-r border-gray-800/60">
				<CodeEditor
					value={code}
					onchange={(v) => (code = v)}
					{language}
					{findings}
					{focusedLine}
					onFolderDrop={folderRoot ? undefined : handleFolderDrop}
					filename={currentFilename}
				/>
			</div>

			<!-- Findings panel -->
			<div class="hidden lg:flex w-72 xl:w-80 shrink-0 overflow-y-auto p-3 flex-col gap-2 bg-gray-950/70">
				{#if error}
					<div class="bg-red-900/40 border border-red-800 rounded p-3 text-sm text-red-300">
						{error}
					</div>
				{/if}
				{#if findings.length === 0 && !error}
					<div class="text-gray-500 text-lg text-center mt-10 space-y-1.5">
						<p>{scanning ? 'Scanning…' : 'Paste code and click Scan'}</p>
						{#if !folderRoot}
							<p class="text-gray-600 text-base">or drop a folder on the editor</p>
						{/if}
					</div>
				{/if}
				{#each findings as f (f.id)}
					<FindingCard
						finding={f}
						{language}
						onlabel={async (id, label) => {
							await submitFeedback(id, label);
							await refreshStats();
						}}
						onfocus={() => handleFocusFinding(f.id)}
						focused={f.id === focusedFindingId}
					/>
				{/each}
			</div>
		</div>
	{:else if activeTab === 'verify'}
		<VerifyTab
			cases={verifyCases}
			onlabel={handleCaseLabel}
			onsubmit={handleCaseSubmit}
		/>
	{:else if activeTab === 'knowledge'}
		<KnowledgeTab history={knowledgeHistory} />
	{:else if activeTab === 'model'}
		<ModelTab {stats} historyCount={knowledgeHistory.length} />
	{/if}

	<!-- Status bar -->
	<StatusBar {stats} />
	</div>
</div>
