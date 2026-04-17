"use client";
import { useEffect, useRef, useState } from "react";
import dynamic from "next/dynamic";
import type { OnMount } from "@monaco-editor/react";
import type * as MonacoType from "monaco-editor";
import type { Finding, Language } from "../lib/types";

const MonacoEditor = dynamic(() => import("@monaco-editor/react"), { ssr: false });

const LANG_MAP: Record<Language, string> = {
  auto: "plaintext",
  python: "python",
  rust: "rust",
  javascript: "javascript",
  typescript: "typescript",
  go: "go",
  java: "java",
  ruby: "ruby",
  c: "c",
  cpp: "cpp",
};

const EXT_MAP: Record<Language, string> = {
  auto: "txt", python: "py", rust: "rs", javascript: "js",
  typescript: "ts", go: "go", java: "java", ruby: "rb", c: "c", cpp: "cpp",
};

const SEV_CLASS: Record<string, { line: string; glyph: string }> = {
  critical: { line: "finding-line-critical", glyph: "finding-glyph-critical" },
  high:     { line: "finding-line-high",     glyph: "finding-glyph-high"     },
  medium:   { line: "finding-line-medium",   glyph: "finding-glyph-medium"   },
  low:      { line: "finding-line-low",      glyph: "finding-glyph-low"      },
};

const SEV_RULER: Record<string, string> = {
  critical: "#dc2626", high: "#ea580c", medium: "#ca8a04", low: "#2563eb",
};

function setupTheme(monaco: typeof MonacoType) {
  monaco.editor.defineTheme("deus-dark", {
    base: "vs-dark",
    inherit: true,
    rules: [
      { token: "keyword",              foreground: "93c5fd" },
      { token: "keyword.control",      foreground: "c084fc" },
      { token: "storage.type",         foreground: "c084fc" },
      { token: "string",               foreground: "86efac" },
      { token: "string.escape",        foreground: "6ee7b7" },
      { token: "comment",              foreground: "4b5563", fontStyle: "italic" },
      { token: "comment.block",        foreground: "4b5563", fontStyle: "italic" },
      { token: "number",               foreground: "fb923c" },
      { token: "regexp",               foreground: "f9a8d4" },
      { token: "operator",             foreground: "94a3b8" },
      { token: "type",                 foreground: "67e8f9" },
      { token: "type.identifier",      foreground: "67e8f9" },
      { token: "entity.name.type",     foreground: "67e8f9" },
      { token: "entity.name.class",    foreground: "67e8f9" },
      { token: "entity.name.function", foreground: "fde68a" },
      { token: "support.function",     foreground: "fde68a" },
      { token: "variable",             foreground: "e2e8f0" },
      { token: "variable.predefined",  foreground: "f87171" },
      { token: "constant",             foreground: "fb923c" },
      { token: "constant.language",    foreground: "c084fc" },
      { token: "delimiter",            foreground: "64748b" },
      { token: "delimiter.bracket",    foreground: "94a3b8" },
      { token: "namespace",            foreground: "67e8f9" },
      { token: "tag",                  foreground: "93c5fd" },
      { token: "attribute.name",       foreground: "fde68a" },
      { token: "attribute.value",      foreground: "86efac" },
      { token: "metatag",              foreground: "f87171" },
    ],
    colors: {
      "editor.background":                    "#080c15",
      "editor.foreground":                    "#e2e8f0",
      "editor.lineHighlightBackground":       "#0f1828",
      "editor.lineHighlightBorder":           "#1a2540",
      "editor.selectionBackground":           "#1e40af55",
      "editor.selectionHighlightBackground":  "#1e40af25",
      "editor.inactiveSelectionBackground":   "#1e40af20",
      "editor.wordHighlightBackground":       "#0ea5e925",
      "editor.wordHighlightStrongBackground": "#0ea5e940",
      "editorCursor.foreground":              "#34d399",
      "editorLineNumber.foreground":          "#2d3748",
      "editorLineNumber.activeForeground":    "#6b7280",
      "editorGutter.background":              "#060a12",
      "editorRuler.foreground":               "#1f2937",
      "editorIndentGuide.background":         "#1a2035",
      "editorIndentGuide.activeBackground":   "#2d3f5f",
      "editorBracketMatch.background":        "#0ea5e920",
      "editorBracketMatch.border":            "#0ea5e9",
      "editorError.foreground":               "#f87171",
      "editorWarning.foreground":             "#fb923c",
      "editorInfo.foreground":                "#60a5fa",
      "editorOverviewRuler.border":           "#00000000",
      "editorOverviewRuler.background":       "#060a12",
      "scrollbarSlider.background":           "#1e293766",
      "scrollbarSlider.hoverBackground":      "#334155aa",
      "scrollbarSlider.activeBackground":     "#475569",
      "scrollbar.shadow":                     "#00000000",
      "minimap.background":                   "#060a12",
      "minimap.selectionHighlight":           "#1e40af66",
      "editorWidget.background":              "#0d1117",
      "editorWidget.border":                  "#1f2937",
      "focusBorder":                          "#3b82f680",
    },
  });
}

interface CodeEditorProps {
  value: string;
  onChange: (value: string) => void;
  language: Language;
  findings?: Finding[];
  focusedLine?: number | null;
  onFolderDrop?: (item: DataTransferItem) => void;
  filename?: string;
}

export function CodeEditor({
  value,
  onChange,
  language,
  findings = [],
  focusedLine,
  onFolderDrop,
  filename,
}: CodeEditorProps) {
  const [dragging, setDragging] = useState(false);
  const [editor, setEditor] = useState<MonacoType.editor.IStandaloneCodeEditor | null>(null);
  const [monaco, setMonaco] = useState<typeof MonacoType | null>(null);
  const findingDecsRef = useRef<MonacoType.editor.IEditorDecorationsCollection | null>(null);
  const focusDecsRef = useRef<MonacoType.editor.IEditorDecorationsCollection | null>(null);

  const handleMount: OnMount = (editorInstance, monacoInstance) => {
    setupTheme(monacoInstance);
    monacoInstance.editor.setTheme("deus-dark");
    setEditor(editorInstance);
    setMonaco(monacoInstance);
  };

  // Per-severity finding decorations
  useEffect(() => {
    if (!editor || !monaco) return;
    findingDecsRef.current?.clear();
    if (findings.length === 0) return;

    const decs: MonacoType.editor.IModelDeltaDecoration[] = findings.map((f) => {
      const cls = SEV_CLASS[f.severity] ?? SEV_CLASS.low;
      return {
        range: new monaco.Range(f.line_start, 1, f.line_end, 1),
        options: {
          isWholeLine: true,
          className: cls.line,
          glyphMarginClassName: cls.glyph,
          overviewRulerColor: SEV_RULER[f.severity] ?? SEV_RULER.low,
          overviewRulerLane: monaco.editor.OverviewRulerLane.Right,
        },
      };
    });

    findingDecsRef.current = editor.createDecorationsCollection(decs);
  }, [findings, editor, monaco]);

  // Scroll to focused line + highlight
  useEffect(() => {
    if (!editor || !monaco || !focusedLine) return;
    editor.revealLineInCenter(focusedLine, monaco.editor.ScrollType.Smooth);
    editor.setPosition({ lineNumber: focusedLine, column: 1 });

    focusDecsRef.current?.clear();
    focusDecsRef.current = editor.createDecorationsCollection([{
      range: new monaco.Range(focusedLine, 1, focusedLine, 1),
      options: {
        isWholeLine: true,
        className: "finding-line-focused",
        glyphMarginClassName: "finding-glyph-focused",
      },
    }]);
  }, [focusedLine, editor, monaco]);

  const lineCount = value.split("\n").length;

  const handleDragOver = (e: React.DragEvent) => {
    if (!onFolderDrop) return;
    e.preventDefault();
    setDragging(true);
  };

  const handleDragLeave = () => setDragging(false);

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragging(false);
    if (!onFolderDrop) return;
    const item = e.dataTransfer.items[0];
    if (item) onFolderDrop(item);
  };

  return (
    <div
      className="flex flex-col h-full relative"
      style={{ background: "#060a12" }}
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
    >
      {/* Drag overlay */}
      {dragging && (
        <div
          className="absolute inset-0 z-10 flex flex-col items-center justify-center gap-3 rounded"
          style={{ background: "rgba(6,10,18,0.92)", border: "2px dashed #4f46e5" }}
        >
          <svg className="w-10 h-10 text-indigo-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M3 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2V7z" />
          </svg>
          <span className="text-sm text-indigo-300 font-medium">Drop folder or file</span>
        </div>
      )}

      {/* Editor title bar */}
      <div
        className="flex items-center gap-3 px-4 shrink-0 border-b"
        style={{ height: 36, background: "#040710", borderColor: "#1a2035" }}
      >
        <div className="flex items-center gap-1.5">
          <div className="w-2.5 h-2.5 rounded-full" style={{ background: "#374151" }} />
          <div className="w-2.5 h-2.5 rounded-full" style={{ background: "#374151" }} />
          <div className="w-2.5 h-2.5 rounded-full" style={{ background: "#374151" }} />
        </div>
        <span className="font-mono text-xs" style={{ color: "#4b5563" }}>
          {filename ?? `source.${EXT_MAP[language]}`}
        </span>
        <div className="ml-auto flex items-center gap-3 text-xs" style={{ color: "#374151" }}>
          <span>{lineCount} lines</span>
          {findings.length > 0 && (
            <span style={{ color: "#c2670b" }}>
              {findings.length} finding{findings.length !== 1 ? "s" : ""}
            </span>
          )}
        </div>
      </div>

      <div className="flex-1 min-h-0">
        <MonacoEditor
          height="100%"
          language={LANG_MAP[language]}
          value={value}
          theme="deus-dark"
          onChange={(val) => onChange(val ?? "")}
          onMount={handleMount}
          options={{
            fontSize: 13,
            fontFamily: "'Cascadia Code', 'JetBrains Mono', 'Fira Code', ui-monospace, monospace",
            fontLigatures: true,
            lineHeight: 1.75,
            letterSpacing: 0.3,
            lineNumbers: "on",
            glyphMargin: true,
            minimap: {
              enabled: true,
              scale: 1,
              renderCharacters: false,
              maxColumn: 80,
            },
            scrollBeyondLastLine: false,
            wordWrap: "on",
            padding: { top: 14, bottom: 14 },
            renderLineHighlight: "all",
            cursorBlinking: "smooth",
            cursorSmoothCaretAnimation: "on",
            smoothScrolling: true,
            overviewRulerBorder: false,
            hideCursorInOverviewRuler: false,
            folding: true,
            foldingHighlight: false,
            scrollbar: {
              verticalScrollbarSize: 5,
              horizontalScrollbarSize: 5,
              useShadows: false,
            },
            bracketPairColorization: { enabled: true },
            guides: { bracketPairs: "active", indentation: true },
            suggest: { showWords: false, showSnippets: false },
            quickSuggestions: false,
            parameterHints: { enabled: false },
            codeLens: false,
            contextmenu: false,
            links: false,
            renderWhitespace: "none",
            occurrencesHighlight: "off",
            selectionHighlight: true,
          }}
        />
      </div>
    </div>
  );
}
