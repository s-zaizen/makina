<script lang="ts">
	import type { FileNode } from '$lib/types';
	import TreeNode from './TreeNode.svelte';

	let {
		node,
		depth,
		selectedPath,
		scannedPaths,
		onselect
	}: {
		node: FileNode;
		depth: number;
		selectedPath: string | null;
		scannedPaths: Set<string>;
		onselect: (node: FileNode) => void;
	} = $props();

	const langColor: Record<string, string> = {
		python: 'text-blue-400',
		javascript: 'text-yellow-400',
		typescript: 'text-sky-400',
		rust: 'text-orange-400',
		go: 'text-cyan-400',
		java: 'text-red-400',
		ruby: 'text-rose-400',
		c: 'text-gray-400',
		cpp: 'text-purple-400'
	};
	const langExt: Record<string, string> = {
		python: 'py', javascript: 'js', typescript: 'ts', rust: 'rs',
		go: 'go', java: 'java', ruby: 'rb', c: 'c', cpp: 'cpp'
	};

	// depth is fixed at creation time — intentional snapshot
	// eslint-disable-next-line svelte/state-referenced-locally
	let open = $state(depth < 2);

	const isSelected = $derived(node.path === selectedPath);
	const isScanned = $derived(scannedPaths.has(node.path));
	const indent = $derived(`${8 + depth * 12}px`);
</script>

{#if node.type === 'file'}
	<button
		onclick={() => onselect(node)}
		class={[
			'w-full flex items-center gap-1.5 px-2 py-0.5 rounded text-left transition-colors group',
			isSelected
				? 'bg-indigo-900/50 text-gray-100'
				: 'text-gray-400 hover:text-gray-200 hover:bg-gray-800/60'
		].join(' ')}
		style="padding-left:{indent};"
	>
		<!-- File icon -->
		<svg class={`w-3.5 h-3.5 shrink-0 ${node.language ? langColor[node.language] ?? 'text-gray-600' : 'text-gray-600'}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.5">
			<path stroke-linecap="round" stroke-linejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
		</svg>
		<span class="text-xs font-mono truncate flex-1">{node.name}</span>
		{#if isScanned}
			<span class="text-[9px] text-emerald-600 shrink-0">✓</span>
		{/if}
		{#if node.language}
			<span class={`text-[9px] font-mono shrink-0 ${langColor[node.language] ?? 'text-gray-600'}`}>
				.{langExt[node.language] ?? node.language}
			</span>
		{/if}
	</button>
{:else}
	<div>
		<button
			onclick={() => (open = !open)}
			class="w-full flex items-center gap-1.5 px-2 py-0.5 rounded text-left hover:bg-gray-800/40 transition-colors text-gray-500 hover:text-gray-300"
			style="padding-left:{indent};"
		>
			<svg
				class={`w-2.5 h-2.5 shrink-0 text-gray-600 transition-transform ${open ? 'rotate-90' : ''}`}
				fill="currentColor" viewBox="0 0 6 10"
			>
				<path d="M1 1l4 4-4 4" stroke="currentColor" stroke-width="1.5" fill="none" stroke-linecap="round" stroke-linejoin="round" />
			</svg>
			<!-- Dir icon -->
			<svg class="w-3.5 h-3.5 shrink-0 text-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.5">
				{#if open}
					<path stroke-linecap="round" stroke-linejoin="round" d="M5 19a2 2 0 01-2-2V7a2 2 0 012-2h4l2 2h4a2 2 0 012 2v1M5 19h14a2 2 0 002-2v-5a2 2 0 00-2-2H9a2 2 0 00-2 2v5a2 2 0 01-2 2z" />
				{:else}
					<path stroke-linecap="round" stroke-linejoin="round" d="M3 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2V7z" />
				{/if}
			</svg>
			<span class="text-xs font-mono truncate">{node.name}</span>
			<span class="text-[9px] text-gray-700 shrink-0 ml-auto">
				{node.children?.filter((c) => c.type === 'file').length ?? 0}f
			</span>
		</button>
		{#if open}
			{#each node.children ?? [] as child (child.path)}
				<TreeNode
					node={child}
					depth={depth + 1}
					{selectedPath}
					{scannedPaths}
					{onselect}
				/>
			{/each}
		{/if}
	</div>
{/if}
