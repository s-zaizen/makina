<script lang="ts">
	import type { FileNode } from '$lib/types';
	import TreeNode from './TreeNode.svelte';

	let {
		root,
		selectedPath,
		scannedPaths,
		scanProgress,
		onselect,
		onscanall,
		onclear
	}: {
		root: FileNode;
		selectedPath: string | null;
		scannedPaths: Set<string>;
		scanProgress: { current: number; total: number } | null;
		onselect: (node: FileNode) => void;
		onscanall: () => void;
		onclear: () => void;
	} = $props();

	function countFiles(node: FileNode): number {
		if (node.type === 'file') return 1;
		return (node.children ?? []).reduce((a, c) => a + countFiles(c), 0);
	}

	const totalFiles = $derived(
		root.type === 'dir' ? (root.children ?? []).reduce((a, c) => a + countFiles(c), 0) : 1
	);
	const scanning = $derived(scanProgress !== null);
</script>

<div class="flex flex-col h-full bg-gray-950/70 border-r border-gray-800/60">
	<!-- Header -->
	<div class="flex items-center gap-2 px-3 py-2 border-b shrink-0" style="border-color:#1a2035;">
		<span class="text-xs font-mono text-gray-500 truncate flex-1">{root.name}</span>
		<button
			onclick={onclear}
			class="text-gray-700 hover:text-gray-400 transition-colors shrink-0"
			title="Close folder"
		>
			<svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
				<path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" />
			</svg>
		</button>
	</div>

	<!-- File list -->
	<div class="flex-1 overflow-y-auto py-1">
		{#if root.type === 'dir'}
			{#each root.children ?? [] as child (child.path)}
				<TreeNode node={child} depth={0} {selectedPath} {scannedPaths} {onselect} />
			{/each}
		{:else}
			<TreeNode node={root} depth={0} {selectedPath} {scannedPaths} {onselect} />
		{/if}
	</div>

	<!-- Footer: Scan All -->
	<div class="shrink-0 px-3 py-2 border-t" style="border-color:#1a2035;">
		{#if scanning}
			<div class="space-y-1.5">
				<div class="flex justify-between text-[10px] text-gray-600">
					<span>Scanning…</span>
					<span>{scanProgress!.current}/{scanProgress!.total}</span>
				</div>
				<div class="w-full rounded-full overflow-hidden" style="height:3px; background:#1a2035;">
					<div
						class="h-full bg-indigo-600 transition-all"
						style="width:{(scanProgress!.current / scanProgress!.total) * 100}%"
					></div>
				</div>
			</div>
		{:else}
			<button
				onclick={onscanall}
				disabled={totalFiles === 0}
				class={[
					'w-full py-1.5 rounded text-xs font-semibold transition-colors',
					totalFiles > 0
						? 'bg-indigo-600/80 hover:bg-indigo-600 text-white cursor-pointer'
						: 'bg-gray-800 text-gray-600 cursor-not-allowed'
				].join(' ')}
			>
				Scan All ({totalFiles} files)
			</button>
		{/if}
	</div>
</div>
