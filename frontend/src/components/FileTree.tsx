"use client";
import { useState } from "react";
import type { FileNode } from "../lib/types";

const langColor: Record<string, string> = {
  python:     "text-blue-400",
  javascript: "text-yellow-400",
  typescript: "text-sky-400",
  rust:       "text-orange-400",
  go:         "text-cyan-400",
  java:       "text-red-400",
  ruby:       "text-rose-400",
  c:          "text-gray-400",
  cpp:        "text-purple-400",
};

const langExt: Record<string, string> = {
  python: "py", javascript: "js", typescript: "ts", rust: "rs",
  go: "go", java: "java", ruby: "rb", c: "c", cpp: "cpp",
};

function FileIcon({ lang }: { lang?: string }) {
  const color = lang ? langColor[lang] : "text-gray-600";
  return (
    <svg className={`w-3.5 h-3.5 shrink-0 ${color}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
    </svg>
  );
}

function DirIcon({ open }: { open: boolean }) {
  return (
    <svg className="w-3.5 h-3.5 shrink-0 text-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      {open
        ? <path strokeLinecap="round" strokeLinejoin="round" d="M5 19a2 2 0 01-2-2V7a2 2 0 012-2h4l2 2h4a2 2 0 012 2v1M5 19h14a2 2 0 002-2v-5a2 2 0 00-2-2H9a2 2 0 00-2 2v5a2 2 0 01-2 2z" />
        : <path strokeLinecap="round" strokeLinejoin="round" d="M3 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2V7z" />
      }
    </svg>
  );
}

interface TreeNodeProps {
  node: FileNode;
  depth: number;
  selectedPath: string | null;
  scannedPaths: Set<string>;
  onSelect: (node: FileNode) => void;
}

function TreeNode({ node, depth, selectedPath, scannedPaths, onSelect }: TreeNodeProps) {
  const [open, setOpen] = useState(depth < 2);

  if (node.type === "file") {
    const isSelected = node.path === selectedPath;
    const isScanned = scannedPaths.has(node.path);
    return (
      <button
        onClick={() => onSelect(node)}
        className={[
          "w-full flex items-center gap-1.5 px-2 py-0.5 rounded text-left transition-colors group",
          isSelected
            ? "bg-indigo-900/50 text-gray-100"
            : "text-gray-400 hover:text-gray-200 hover:bg-gray-800/60",
        ].join(" ")}
        style={{ paddingLeft: `${8 + depth * 12}px` }}
      >
        <FileIcon lang={node.language} />
        <span className="text-xs font-mono truncate flex-1">{node.name}</span>
        {isScanned && (
          <span className="text-[9px] text-emerald-600 shrink-0">✓</span>
        )}
        {node.language && (
          <span className={`text-[9px] font-mono shrink-0 ${langColor[node.language] ?? "text-gray-600"}`}>
            .{langExt[node.language] ?? node.language}
          </span>
        )}
      </button>
    );
  }

  return (
    <div>
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center gap-1.5 px-2 py-0.5 rounded text-left hover:bg-gray-800/40 transition-colors text-gray-500 hover:text-gray-300"
        style={{ paddingLeft: `${8 + depth * 12}px` }}
      >
        <svg
          className={`w-2.5 h-2.5 shrink-0 text-gray-600 transition-transform ${open ? "rotate-90" : ""}`}
          fill="currentColor" viewBox="0 0 6 10"
        >
          <path d="M1 1l4 4-4 4" stroke="currentColor" strokeWidth="1.5" fill="none" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
        <DirIcon open={open} />
        <span className="text-xs font-mono truncate">{node.name}</span>
        <span className="text-[9px] text-gray-700 shrink-0 ml-auto">
          {node.children?.filter(c => c.type === "file").length ?? 0}f
        </span>
      </button>
      {open && node.children?.map((child) => (
        <TreeNode
          key={child.path}
          node={child}
          depth={depth + 1}
          selectedPath={selectedPath}
          scannedPaths={scannedPaths}
          onSelect={onSelect}
        />
      ))}
    </div>
  );
}

interface FileTreeProps {
  root: FileNode;
  selectedPath: string | null;
  scannedPaths: Set<string>;
  scanProgress: { current: number; total: number } | null;
  onSelect: (node: FileNode) => void;
  onScanAll: () => void;
  onClear: () => void;
}

export function FileTree({ root, selectedPath, scannedPaths, scanProgress, onSelect, onScanAll, onClear }: FileTreeProps) {
  const totalFiles = root.children?.reduce((acc, c) => {
    const count = (n: FileNode): number => n.type === "file" ? 1 : (n.children ?? []).reduce((a, ch) => a + count(ch), 0);
    return acc + count(c);
  }, 0) ?? 0;

  const scanning = scanProgress !== null;

  return (
    <div className="flex flex-col h-full" style={{ background: "#040710", borderRight: "1px solid #1a2035" }}>
      {/* Header */}
      <div className="flex items-center gap-2 px-3 py-2 border-b shrink-0" style={{ borderColor: "#1a2035" }}>
        <span className="text-xs font-mono text-gray-500 truncate flex-1">{root.name}</span>
        <button
          onClick={onClear}
          className="text-gray-700 hover:text-gray-400 transition-colors shrink-0"
          title="Close folder"
        >
          <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
      </div>

      {/* File list */}
      <div className="flex-1 overflow-y-auto py-1">
        {root.type === "dir"
          ? root.children?.map((child) => (
              <TreeNode
                key={child.path}
                node={child}
                depth={0}
                selectedPath={selectedPath}
                scannedPaths={scannedPaths}
                onSelect={onSelect}
              />
            ))
          : <TreeNode
              node={root}
              depth={0}
              selectedPath={selectedPath}
              scannedPaths={scannedPaths}
              onSelect={onSelect}
            />
        }
      </div>

      {/* Footer: Scan All */}
      <div className="shrink-0 px-3 py-2 border-t" style={{ borderColor: "#1a2035" }}>
        {scanning ? (
          <div className="space-y-1.5">
            <div className="flex justify-between text-[10px] text-gray-600">
              <span>Scanning…</span>
              <span>{scanProgress!.current}/{scanProgress!.total}</span>
            </div>
            <div className="w-full rounded-full overflow-hidden" style={{ height: 3, background: "#1a2035" }}>
              <div
                className="h-full bg-indigo-600 transition-all"
                style={{ width: `${(scanProgress!.current / scanProgress!.total) * 100}%` }}
              />
            </div>
          </div>
        ) : (
          <button
            onClick={onScanAll}
            disabled={totalFiles === 0}
            className={[
              "w-full py-1.5 rounded text-xs font-semibold transition-colors",
              totalFiles > 0
                ? "bg-indigo-600/80 hover:bg-indigo-600 text-white cursor-pointer"
                : "bg-gray-800 text-gray-600 cursor-not-allowed",
            ].join(" ")}
          >
            Scan All ({totalFiles} files)
          </button>
        )}
      </div>
    </div>
  );
}
