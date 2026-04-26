<script lang="ts">
	import { onMount } from 'svelte';
	import type { Stats, ModelMetrics } from '$lib/types';
	import { getModelMetrics } from '$lib/api';

	let { stats, historyCount }: { stats: Stats | null; historyCount: number } = $props();

	let metrics = $state<ModelMetrics | null>(null);
	let nowTick = $state(Date.now());

	// Refetch whenever the label count changes (i.e. a retrain has fired).
	$effect(() => {
		void stats?.total_labels;
		getModelMetrics().then((m) => (metrics = m)).catch(() => {});
	});

	onMount(() => {
		getModelMetrics().then((m) => (metrics = m)).catch(() => {});
		// Tick every 30 s so the "trained X ago" label stays live without
		// polling the backend (the metrics only change on retrain).
		const tick = setInterval(() => { nowTick = Date.now(); }, 30_000);
		return () => clearInterval(tick);
	});

	function formatRelative(iso: string, now: number): string {
		const d = new Date(iso);
		const s = Math.round((now - d.getTime()) / 1000);
		if (s < 60) return `${s}s ago`;
		if (s < 3600) return `${Math.round(s / 60)}m ago`;
		if (s < 86400) {
			const h = Math.floor(s / 3600);
			const m = Math.round((s % 3600) / 60);
			return m > 0 ? `${h}h ${m}m ago` : `${h}h ago`;
		}
		return `${Math.round(s / 86400)}d ago`;
	}

	function pct(x: number | undefined): string {
		if (x === undefined || x === null) return '–';
		return `${(x * 100).toFixed(1)}%`;
	}

	function accColor(acc: number | undefined): string {
		if (acc === undefined) return 'text-gray-500';
		if (acc >= 0.85) return 'text-emerald-400';
		if (acc >= 0.7) return 'text-indigo-400';
		if (acc >= 0.55) return 'text-amber-400';
		return 'text-red-400';
	}

	function compact(n: number): string {
		if (n < 1000) return n.toString();
		if (n < 10000) return (n / 1000).toFixed(1).replace(/\.0$/, '') + 'K';
		if (n < 1_000_000) return Math.round(n / 1000) + 'K';
		return (n / 1_000_000).toFixed(1).replace(/\.0$/, '') + 'M';
	}

	const STAGES = [
		{ key: 'bootstrapping', label: 'Bootstrapping', min: 0 },
		{ key: 'learning', label: 'Learning', min: 1 },
		{ key: 'refining', label: 'Refining', min: 50 },
		{ key: 'mature', label: 'Mature', min: 500 }
	];

	const stageColor: Record<string, string> = {
		bootstrapping: 'text-gray-500',
		learning: 'text-blue-400',
		refining: 'text-indigo-400',
		mature: 'text-emerald-400'
	};

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

<div class="flex-1 overflow-y-auto bg-gray-950/70 px-6 py-6">
	<div class="mx-auto max-w-5xl">
		<h2 class="mb-5 text-xs font-semibold uppercase tracking-widest text-gray-500">
			Learning Status
		</h2>

		<div class="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-2">
			<!-- Model Status -->
			<section class="rounded-xl border border-gray-800 bg-gray-900 p-4">
				<h3 class="mb-3 text-xs font-semibold uppercase tracking-wider text-gray-500">
					Model Status
				</h3>
				<div class="mb-3 flex items-baseline gap-2">
					<span
						class={`text-2xl font-bold capitalize ${stageColor[stats?.model_stage ?? 'bootstrapping']}`}
					>
						{stats?.model_stage ?? 'bootstrapping'}
					</span>
					<span class="text-xs text-gray-600">stage</span>
				</div>

				<div class="mb-3 flex items-center gap-1">
					{#each STAGES as s, i}
						{@const done = i < stageIdx}
						{@const active = i === stageIdx}
						<div class="flex flex-1 items-center last:flex-none">
							<div
								class={[
									'h-1.5 flex-1 rounded-full',
									done ? 'bg-emerald-500' : active ? 'bg-indigo-500/60' : 'bg-gray-800'
								].join(' ')}
							></div>
							{#if i === STAGES.length - 1}
								<div
									class={[
										'ml-1 h-2 w-2 shrink-0 rounded-full',
										done ? 'bg-emerald-500' : active ? 'bg-indigo-400' : 'bg-gray-800'
									].join(' ')}
								></div>
							{/if}
						</div>
					{/each}
				</div>

				<div class="text-xs text-gray-700">
					{#each STAGES as s, i}
						<span class={i <= stageIdx ? 'text-gray-500' : 'text-gray-700'}>
							{s.label}{i < STAGES.length - 1 ? ' → ' : ''}
						</span>
					{/each}
				</div>

				{#if nextStage !== null}
					<div class="mt-3">
						<div class="mb-1 flex justify-between text-xs text-gray-700">
							<span>{nextStage.label}</span>
							<span class="text-indigo-500">{total} / {nextStage.min}</span>
						</div>
						<div class="h-1.5 overflow-hidden rounded-full bg-gray-800">
							<div
								class="h-full bg-gradient-to-r from-indigo-700 to-indigo-400 transition-all duration-700"
								style="width:{bandPct}%"
							></div>
						</div>
					</div>
				{/if}

				<p class="mt-2 text-xs italic text-gray-700">Retrains on every Verify Submit</p>
			</section>

			<!-- Accumulated Labels -->
			<section class="rounded-xl border border-gray-800 bg-gray-900 p-4">
				<h3 class="mb-3 text-xs font-semibold uppercase tracking-wider text-gray-500">
					Accumulated Labels
				</h3>

				<div class="mb-3 grid grid-cols-3 gap-1.5">
					{#each [{ label: 'Total', value: total, color: 'text-gray-100' }, { label: 'TP', value: tp, color: 'text-emerald-400' }, { label: 'FP', value: fp, color: 'text-red-400' }] as item}
						<div
							class="min-w-0 rounded-lg border border-gray-700/30 bg-gray-800/50 px-1.5 py-2 text-center"
							title={item.value.toLocaleString()}
						>
							<div class={`text-xl font-bold tabular-nums lg:text-2xl ${item.color}`}>
								{compact(item.value)}
							</div>
							<div class="mt-0.5 text-xs text-gray-600">{item.label}</div>
						</div>
					{/each}
				</div>

				{#if total > 0}
					<div class="mb-1 flex justify-between text-xs text-gray-600">
						<span>TP / FP ratio</span>
						<span>
							<span class="text-emerald-500">{Math.round(tpRatio * 100)}%</span>
							{' / '}
							<span class="text-red-500">{Math.round((1 - tpRatio) * 100)}%</span>
						</span>
					</div>
					<div class="flex h-2 overflow-hidden rounded-full bg-gray-800">
						<div class="h-full bg-emerald-500 transition-all duration-700" style="width:{tpRatio * 100}%"></div>
						<div class="h-full bg-red-500/60 transition-all duration-700" style="width:{(1 - tpRatio) * 100}%"></div>
					</div>
				{:else}
					<p class="py-1 text-center text-xs text-gray-700">
						No labels yet — verify cases to accumulate knowledge.
					</p>
				{/if}
			</section>

			<!-- Model Quality (validation metrics) -->
			<section class="rounded-xl border border-gray-800 bg-gray-900 p-4 md:col-span-2 xl:col-span-1">
				<div class="mb-3 flex items-center justify-between">
					<h3 class="text-xs font-semibold uppercase tracking-wider text-gray-500">Model Quality</h3>
					{#if metrics?.trained_at}
						<span class="font-mono text-[11px] text-gray-600">
							{formatRelative(metrics.trained_at, nowTick)}
						</span>
					{/if}
				</div>

				{#if !metrics}
					<p class="py-2 text-center text-xs text-gray-700">
						No training run yet. Submit a labeled case or run bulk import to train.
					</p>
				{:else if metrics.val_accuracy === undefined}
					<p class="py-2 text-center text-xs text-gray-700">
						Insufficient samples for train/val split (need ≥ 5 per class).
						<br />
						<span class="text-gray-600">Trained on {metrics.samples} samples.</span>
					</p>
				{:else}
					<div class="mb-3 flex items-baseline gap-2">
						<span class={`text-xl font-bold tabular-nums lg:text-2xl ${accColor(metrics.val_accuracy)}`}>
							{pct(metrics.val_accuracy)}
						</span>
						<span class="text-xs text-gray-600">val accuracy</span>
					</div>

					<div class="mb-3 h-1.5 overflow-hidden rounded-full bg-gray-800">
						<div
							class={`h-full transition-all duration-700 ${
								metrics.val_accuracy >= 0.85
									? 'bg-emerald-500'
									: metrics.val_accuracy >= 0.7
										? 'bg-indigo-500'
										: metrics.val_accuracy >= 0.55
											? 'bg-amber-500'
											: 'bg-red-500'
							}`}
							style="width:{(metrics.val_accuracy * 100).toFixed(1)}%"
						></div>
					</div>

					<div class="mb-3 grid grid-cols-2 gap-2">
						<div class="rounded-lg border border-gray-700/30 bg-gray-800/50 p-2 text-center">
							<div class="text-xs font-bold tabular-nums text-gray-200">{pct(metrics.val_precision)}</div>
							<div class="mt-0.5 text-[11px] text-gray-600">Precision</div>
						</div>
						<div class="rounded-lg border border-gray-700/30 bg-gray-800/50 p-2 text-center">
							<div class="text-xs font-bold tabular-nums text-gray-200">{pct(metrics.val_recall)}</div>
							<div class="mt-0.5 text-[11px] text-gray-600">Recall</div>
						</div>
					</div>

					<div class="space-y-1 text-xs">
						<div class="flex justify-between">
							<span class="text-gray-600">Split</span>
							<span class="font-mono text-gray-400">{metrics.split}</span>
						</div>
						<div class="flex justify-between">
							<span class="text-gray-600">Val samples</span>
							<span class="tabular-nums text-gray-400">{metrics.val_samples}</span>
						</div>
						{#if metrics.val_prob_mean_tp !== undefined && metrics.val_prob_mean_tp !== null}
							<div class="flex justify-between">
								<span class="text-gray-600">Mean p(TP) on TPs</span>
								<span class="tabular-nums text-emerald-500">{metrics.val_prob_mean_tp.toFixed(2)}</span>
							</div>
						{/if}
						{#if metrics.val_prob_mean_fp !== undefined && metrics.val_prob_mean_fp !== null}
							<div class="flex justify-between">
								<span class="text-gray-600">Mean p(TP) on FPs</span>
								<span class="tabular-nums text-red-500">{metrics.val_prob_mean_fp.toFixed(2)}</span>
							</div>
						{/if}
						<div class="flex justify-between">
							<span class="text-gray-600">Train time</span>
							<span class="tabular-nums text-gray-400">{(metrics.elapsed_ms / 1000).toFixed(1)}s</span>
						</div>
					</div>

					{#if metrics.val_prob_mean_tp !== undefined && metrics.val_prob_mean_fp !== undefined && metrics.val_prob_mean_tp !== null && metrics.val_prob_mean_fp !== null}
						{@const gap = metrics.val_prob_mean_tp - metrics.val_prob_mean_fp}
						<div class="mt-2 border-t border-gray-800/60 pt-2">
							<div class="flex justify-between text-xs">
								<span class="text-gray-600">TP/FP separation</span>
								<span
									class={`tabular-nums ${gap >= 0.3 ? 'text-emerald-500' : gap >= 0.15 ? 'text-amber-500' : 'text-red-400'}`}
								>
									Δ {gap.toFixed(2)}
								</span>
							</div>
							<p class="mt-1 text-[11px] italic text-gray-700">
								{gap >= 0.3
									? 'Clear separation — model discriminates well.'
									: gap >= 0.15
										? 'Weak separation — confidences cluster near 0.5.'
										: 'Near zero separation — GBDT adds little signal; collect more diverse labels.'}
							</p>
						</div>
					{/if}
				{/if}
			</section>

			<!-- Summary -->
			<section class="rounded-xl border border-gray-800 bg-gray-900 p-4 md:col-span-2 xl:col-span-1">
				<h3 class="mb-3 text-xs font-semibold uppercase tracking-wider text-gray-500">Summary</h3>
				<div class="space-y-1.5">
					{#each [{ label: 'Cases verified', value: historyCount }, { label: 'Findings labeled', value: total }, { label: 'True positives', value: tp }, { label: 'False positives', value: fp }] as r}
						<div class="flex justify-between text-xs">
							<span class="text-gray-600">{r.label}</span>
							<span class="font-medium tabular-nums text-gray-300">{r.value}</span>
						</div>
					{/each}
				</div>
			</section>
		</div>
	</div>
</div>
