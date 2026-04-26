<script lang="ts">
	import { onMount } from 'svelte';
	import EditorWorker from 'monaco-editor/esm/vs/editor/editor.worker?worker';
	import type * as MonacoType from 'monaco-editor';
	import type { Finding, Language } from '$lib/types';

	let {
		value,
		onchange,
		language,
		findings = [],
		focusedLine = null,
		onFolderDrop,
		filename,
		readonly = false
	}: {
		value: string;
		onchange: (v: string) => void;
		language: Language;
		findings?: Finding[];
		focusedLine?: number | null;
		onFolderDrop?: (item: DataTransferItem) => void;
		filename?: string;
		readonly?: boolean;
	} = $props();

	const LANG_MAP: Record<Language, string> = {
		auto: 'plaintext', python: 'python', rust: 'rust',
		javascript: 'javascript', typescript: 'typescript', go: 'go',
		java: 'java', ruby: 'ruby', c: 'c', cpp: 'cpp'
	};
	const EXT_MAP: Record<Language, string> = {
		auto: 'txt', python: 'py', rust: 'rs', javascript: 'js',
		typescript: 'ts', go: 'go', java: 'java', ruby: 'rb', c: 'c', cpp: 'cpp'
	};
	const SEV_RULER: Record<string, string> = {
		critical: '#dc2626', high: '#ea580c', medium: '#ca8a04', low: '#2563eb'
	};

	let containerEl: HTMLDivElement;
	let dragging = $state(false);
	let editor = $state<MonacoType.editor.IStandaloneCodeEditor | null>(null);
	let monacoRef: typeof MonacoType | null = null;
	let findingDecs: MonacoType.editor.IEditorDecorationsCollection | null = null;
	let focusDecs: MonacoType.editor.IEditorDecorationsCollection | null = null;
	let updating = false;

	const lineCount = $derived(value.split('\n').length);

	function setupTheme(monaco: typeof MonacoType) {
		monaco.editor.defineTheme('makina-dark', {
			base: 'vs-dark',
			inherit: true,
			rules: [
				{ token: 'keyword', foreground: '93c5fd' },
				{ token: 'keyword.control', foreground: 'c084fc' },
				{ token: 'storage.type', foreground: 'c084fc' },
				{ token: 'string', foreground: '86efac' },
				{ token: 'string.escape', foreground: '6ee7b7' },
				{ token: 'comment', foreground: '4b5563', fontStyle: 'italic' },
				{ token: 'number', foreground: 'fb923c' },
				{ token: 'regexp', foreground: 'f9a8d4' },
				{ token: 'operator', foreground: '94a3b8' },
				{ token: 'type', foreground: '67e8f9' },
				{ token: 'type.identifier', foreground: '67e8f9' },
				{ token: 'entity.name.type', foreground: '67e8f9' },
				{ token: 'entity.name.function', foreground: 'fde68a' },
				{ token: 'support.function', foreground: 'fde68a' },
				{ token: 'variable', foreground: 'e2e8f0' },
				{ token: 'variable.predefined', foreground: 'f87171' },
				{ token: 'constant', foreground: 'fb923c' },
				{ token: 'constant.language', foreground: 'c084fc' },
				{ token: 'delimiter', foreground: '64748b' },
				{ token: 'delimiter.bracket', foreground: '94a3b8' },
				{ token: 'namespace', foreground: '67e8f9' },
				{ token: 'tag', foreground: '93c5fd' },
				{ token: 'attribute.name', foreground: 'fde68a' },
				{ token: 'attribute.value', foreground: '86efac' }
			],
			colors: {
				'editor.background': '#00000000',
				'editor.foreground': '#e2e8f0',
				'editor.lineHighlightBackground': '#0f1828',
				'editor.lineHighlightBorder': '#1a2540',
				'editor.selectionBackground': '#1e40af55',
				'editor.selectionHighlightBackground': '#1e40af25',
				'editor.inactiveSelectionBackground': '#1e40af20',
				'editorCursor.foreground': '#34d399',
				'editorLineNumber.foreground': '#2d3748',
				'editorLineNumber.activeForeground': '#6b7280',
				'editorGutter.background': '#060a12',
				'editorRuler.foreground': '#1f2937',
				'editorIndentGuide.background1': '#1a2035',
				'editorIndentGuide.activeBackground1': '#2d3f5f',
				'editorBracketMatch.background': '#0ea5e920',
				'editorBracketMatch.border': '#0ea5e9',
				'editorError.foreground': '#f87171',
				'editorWarning.foreground': '#fb923c',
				'editorInfo.foreground': '#60a5fa',
				'editorOverviewRuler.border': '#00000000',
				'editorOverviewRuler.background': '#060a12',
				'scrollbarSlider.background': '#1e293766',
				'scrollbarSlider.hoverBackground': '#334155aa',
				'scrollbarSlider.activeBackground': '#475569',
				'minimap.background': '#060a12',
				'editorWidget.background': '#0d1117',
				'editorWidget.border': '#1f2937',
				'focusBorder': '#3b82f680'
			}
		});
	}

	onMount(() => {
		let disposeEditor: (() => void) | null = null;

		void (async () => {
			// Set up Monaco worker BEFORE importing the module
			(window as Window & { MonacoEnvironment?: unknown }).MonacoEnvironment = {
				getWorker: () => new EditorWorker()
			};

			const monaco = await import('monaco-editor');
			monacoRef = monaco;

			setupTheme(monaco);
			monaco.editor.setTheme('makina-dark');

			const instance = monaco.editor.create(containerEl, {
				value,
				language: LANG_MAP[language],
				theme: 'makina-dark',
				readOnly: readonly,
				fontSize: 13,
				fontFamily: "'Cascadia Code', 'JetBrains Mono', 'Fira Code', ui-monospace, monospace",
				fontLigatures: true,
				lineHeight: 1.75,
				letterSpacing: 0.3,
				lineNumbers: 'on',
				glyphMargin: true,
				minimap: { enabled: true, scale: 1, renderCharacters: false, maxColumn: 80 },
				scrollBeyondLastLine: false,
				wordWrap: 'on',
				padding: { top: 14, bottom: 14 },
				renderLineHighlight: 'all',
				cursorBlinking: 'smooth',
				cursorSmoothCaretAnimation: 'on',
				smoothScrolling: true,
				overviewRulerBorder: false,
				hideCursorInOverviewRuler: false,
				folding: true,
				foldingHighlight: false,
				scrollbar: { verticalScrollbarSize: 5, horizontalScrollbarSize: 5, useShadows: false },
				bracketPairColorization: { enabled: true },
				guides: { bracketPairs: 'active', indentation: true },
				suggest: { showWords: false, showSnippets: false },
				quickSuggestions: false,
				parameterHints: { enabled: false },
				codeLens: false,
				contextmenu: false,
				links: false,
				renderWhitespace: 'none',
				occurrencesHighlight: 'off',
				selectionHighlight: true
			});

			instance.onDidChangeModelContent(() => {
				if (!updating) onchange(instance.getValue());
			});

			editor = instance;
			disposeEditor = () => instance.dispose();
		})();

		return () => {
			disposeEditor?.();
		};
	});

	// Sync value → editor
	$effect(() => {
		if (!editor) return;
		if (editor.getValue() !== value) {
			updating = true;
			editor.setValue(value);
			updating = false;
		}
	});

	// Sync language → editor
	$effect(() => {
		if (!editor || !monacoRef) return;
		const model = editor.getModel();
		if (model) monacoRef.editor.setModelLanguage(model, LANG_MAP[language]);
	});

	// Update finding decorations
	$effect(() => {
		if (!editor || !monacoRef) return;
		findingDecs?.clear();
		if (findings.length === 0) return;

		const monaco = monacoRef;
		const decs: MonacoType.editor.IModelDeltaDecoration[] = findings.map((f) => {
			const sev = f.severity;
			const isMl = f.source === 'ml';
			return {
				range: new monaco.Range(f.line_start, 1, f.line_end, 1),
				options: {
					isWholeLine: true,
					className: isMl ? 'finding-line-ml' : `finding-line-${sev}`,
					linesDecorationsClassName: isMl ? 'finding-border-ml' : undefined,
					glyphMarginClassName: isMl ? 'finding-glyph-ml' : `finding-glyph-${sev}`,
					overviewRulerColor: isMl ? '#8b5cf6' : (SEV_RULER[sev] ?? SEV_RULER.low),
					overviewRulerLane: monaco.editor.OverviewRulerLane.Right
				}
			};
		});
		findingDecs = editor.createDecorationsCollection(decs);
	});

	// Scroll to focused line
	$effect(() => {
		if (!editor || !monacoRef || !focusedLine) return;
		const monaco = monacoRef;
		editor.revealLineInCenter(focusedLine, monaco.editor.ScrollType.Smooth);
		editor.setPosition({ lineNumber: focusedLine, column: 1 });

		focusDecs?.clear();
		focusDecs = editor.createDecorationsCollection([{
			range: new monaco.Range(focusedLine, 1, focusedLine, 1),
			options: {
				isWholeLine: true,
				className: 'finding-line-focused',
				glyphMarginClassName: 'finding-glyph-focused'
			}
		}]);
	});

	function handleDragOver(e: DragEvent) {
		if (!onFolderDrop) return;
		e.preventDefault();
		dragging = true;
	}
	function handleDragLeave() { dragging = false; }
	function handleDrop(e: DragEvent) {
		e.preventDefault();
		dragging = false;
		if (!onFolderDrop) return;
		const item = e.dataTransfer?.items[0];
		if (item) onFolderDrop(item);
	}
</script>

<div
	class="flex flex-col h-full relative"
	style="background:rgba(3,7,18,0.70);"
	ondragover={handleDragOver}
	ondragleave={handleDragLeave}
	ondrop={handleDrop}
	role="region"
	aria-label="Code editor"
>
	<!-- Drag overlay -->
	{#if dragging}
		<div
			class="absolute inset-0 z-10 flex flex-col items-center justify-center gap-3 rounded"
			style="background:rgba(3,7,18,0.92); border:2px dashed #4f46e5;"
		>
			<svg class="w-10 h-10 text-indigo-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.5">
				<path stroke-linecap="round" stroke-linejoin="round" d="M3 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2V7z" />
			</svg>
			<span class="text-sm text-indigo-300 font-medium">Drop folder or file</span>
		</div>
	{/if}

	<!-- Title bar -->
	<div
		class="flex items-center gap-3 px-4 shrink-0 border-b"
		style="height:40px; border-color:#1a2035;"
	>
		<div class="flex items-center gap-1.5">
			<div class="w-2.5 h-2.5 rounded-full" style="background:#374151;"></div>
			<div class="w-2.5 h-2.5 rounded-full" style="background:#374151;"></div>
			<div class="w-2.5 h-2.5 rounded-full" style="background:#374151;"></div>
		</div>
		<span class="font-mono text-sm" style="color:#6b7280;">
			{filename ?? `source.${EXT_MAP[language]}`}
		</span>
		<div class="ml-auto flex items-center gap-3 text-sm" style="color:#4b5563;">
			<span>{lineCount} lines</span>
			{#if findings.length > 0}
				<span style="color:#c2670b;">{findings.length} finding{findings.length !== 1 ? 's' : ''}</span>
			{/if}
		</div>
	</div>

	<!-- Monaco container -->
	<div class="flex-1 min-h-0" bind:this={containerEl}></div>
</div>

<style>
	:global(.finding-line-critical) { background: rgba(239,68,68,0.12) !important; }
	:global(.finding-line-high)     { background: rgba(249,115,22,0.10) !important; }
	:global(.finding-line-medium)   { background: rgba(234,179,8,0.10) !important; }
	:global(.finding-line-low)      { background: rgba(96,165,250,0.10) !important; }
	:global(.finding-line-ml)       { background: rgba(139,92,246,0.18) !important; }
	:global(.finding-line-focused)  { background: rgba(79,70,229,0.15) !important; }

	:global(.finding-border-ml) { box-shadow: inset 2px 0 0 #8b5cf6; }

	:global(.finding-glyph-critical)::before { content: '●'; color: #dc2626; font-size: 10px; }
	:global(.finding-glyph-high)::before     { content: '●'; color: #ea580c; font-size: 10px; }
	:global(.finding-glyph-medium)::before   { content: '●'; color: #ca8a04; font-size: 10px; }
	:global(.finding-glyph-low)::before      { content: '●'; color: #2563eb; font-size: 10px; }
	:global(.finding-glyph-ml)::before       { content: '◆'; color: #a78bfa; font-size: 10px; }
	:global(.finding-glyph-focused)::before  { content: '▶'; color: #818cf8; font-size: 10px; }

	:global(.shiki-snippet pre) {
		margin: 0;
		padding: 0.5rem;
		background: transparent !important;
		overflow-x: auto;
	}
	:global(.shiki-snippet code) {
		font-family: ui-monospace, 'SFMono-Regular', Menlo, monospace;
		counter-reset: line;
	}
</style>
