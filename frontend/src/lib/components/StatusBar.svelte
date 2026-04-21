<script lang="ts">
	import type { Stats } from '$lib/types';

	let { stats }: { stats: Stats | null } = $props();

	const stageColors: Record<string, string> = {
		bootstrapping: 'text-gray-500',
		learning: 'text-blue-400',
		refining: 'text-indigo-400',
		mature: 'text-emerald-400'
	};

	const stageColor = $derived(stageColors[stats?.model_stage ?? ''] ?? 'text-gray-400');
</script>

{#if !stats}
	<div class="h-9 bg-gray-900 border-t border-gray-700"></div>
{:else}
	<div class="h-9 bg-gray-900 border-t border-gray-700 flex items-center px-4 gap-5 text-sm text-gray-400">
		<span>Labels: <span class="text-gray-200 font-medium tabular-nums">{stats.total_labels}</span></span>
		<span class="text-gray-600">|</span>
		<span>
			TP: <span class="text-green-400 font-medium tabular-nums">{stats.tp_count}</span>
			{' '}FP: <span class="text-red-400 font-medium tabular-nums">{stats.fp_count}</span>
		</span>
		<span class="text-gray-600">|</span>
		<span>Model: <span class="font-medium {stageColor}">{stats.model_stage}</span></span>
		<span class="text-gray-600">|</span>
		<span class="text-gray-600 italic text-xs">retrains on every submit</span>
	</div>
{/if}
