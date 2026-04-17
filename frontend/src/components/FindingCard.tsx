"use client";
import { useState } from "react";
import { Prism as SyntaxHighlighter } from "react-syntax-highlighter";
import { vscDarkPlus } from "react-syntax-highlighter/dist/esm/styles/prism";
import type { Finding, Label, Language, Severity } from "../lib/types";

const severityStyles: Record<Severity, string> = {
  critical: "text-red-400 bg-red-950 border-red-800",
  high:     "text-orange-400 bg-orange-950 border-orange-800",
  medium:   "text-yellow-400 bg-yellow-950 border-yellow-800",
  low:      "text-blue-400 bg-blue-950 border-blue-800",
};

const severityBorderLeft: Record<Severity, string> = {
  critical: "border-l-red-600",
  high:     "border-l-orange-500",
  medium:   "border-l-yellow-500",
  low:      "border-l-blue-400",
};

const severityBarColor: Record<Severity, string> = {
  critical: "bg-red-600",
  high:     "bg-orange-500",
  medium:   "bg-yellow-500",
  low:      "bg-blue-400",
};

const severityHighlight: Record<Severity, string> = {
  critical: "rgba(239,68,68,0.12)",
  high:     "rgba(249,115,22,0.10)",
  medium:   "rgba(234,179,8,0.10)",
  low:      "rgba(96,165,250,0.10)",
};

function toSyntaxLang(lang: Language): string {
  if (lang === "auto") return "text";
  return lang;
}

interface FindingCardProps {
  finding: Finding;
  language: Language;
  onLabel: (id: string, label: Label) => Promise<void>;
  onFocus?: () => void;
  focused?: boolean;
}

export function FindingCard({
  finding,
  language,
  onLabel,
  onFocus,
  focused = false,
}: FindingCardProps) {
  const [labeled, setLabeled] = useState<Label | null>(null);
  const [loading, setLoading] = useState(false);

  const handleLabel = async (label: Label, e: React.MouseEvent) => {
    e.stopPropagation();
    setLoading(true);
    try {
      await onLabel(finding.id, label);
      setLabeled(label);
    } finally {
      setLoading(false);
    }
  };

  const borderColor = severityBorderLeft[finding.severity];
  const barColor    = severityBarColor[finding.severity];
  const lineHighlight = severityHighlight[finding.severity];
  const confidencePct = Math.round(finding.confidence * 100);
  const lineRange = finding.line_end > finding.line_start
    ? `Lines ${finding.line_start}–${finding.line_end}`
    : `Line ${finding.line_start}`;
  const isSemgrep = finding.source === "semgrep";
  const isManual  = finding.source === "manual";

  return (
    <div
      onClick={onFocus}
      className={[
        "rounded border bg-gray-900 border-l-4 p-3 flex flex-col gap-2 transition-all",
        borderColor,
        focused
          ? "border-gray-600 ring-1 ring-indigo-500/50 cursor-default"
          : "border-gray-700 cursor-pointer hover:border-gray-600 hover:bg-gray-900/80",
      ].join(" ")}
    >
      {/* Header */}
      <div className="flex flex-wrap items-center gap-2">
        <span className={`text-xs font-semibold px-2 py-0.5 rounded-full border ${severityStyles[finding.severity]} uppercase tracking-wide`}>
          {finding.severity}
        </span>
        <span className="font-mono text-xs text-gray-300">{finding.rule_id}</span>
        {finding.cwe && (
          <span className="text-xs px-1.5 py-0.5 rounded bg-gray-700 text-gray-400 border border-gray-600">
            {finding.cwe}
          </span>
        )}
        <span className={`text-xs px-1.5 py-0.5 rounded font-mono border ${
          isSemgrep
            ? "bg-blue-950 text-blue-400 border-blue-800"
            : isManual
            ? "bg-teal-950 text-teal-400 border-teal-800"
            : "bg-purple-950 text-purple-400 border-purple-800"
        }`}>
          {finding.source}
        </span>
        {finding.is_uncertain && (
          <span className="text-xs px-1.5 py-0.5 rounded bg-yellow-900 text-yellow-400 border border-yellow-700">
            Uncertain
          </span>
        )}
        {focused && (
          <span className="ml-auto text-xs text-indigo-400/70">↑ in editor</span>
        )}
      </div>

      {/* Message */}
      <p className="text-sm text-gray-200 leading-snug">{finding.message}</p>

      {/* Code snippet */}
      {finding.code_snippet && (
        <div className="rounded border border-gray-800 overflow-hidden">
          <div className="flex items-center justify-between px-3 py-1 bg-gray-800/60 border-b border-gray-800">
            <span className="text-xs font-mono text-gray-500">{lineRange}</span>
          </div>
          <SyntaxHighlighter
            language={toSyntaxLang(language)}
            style={vscDarkPlus}
            showLineNumbers
            startingLineNumber={finding.line_start}
            wrapLines
            lineProps={(lineNumber) => {
              const inRange = lineNumber >= finding.line_start && lineNumber <= finding.line_end;
              return inRange
                ? { style: { backgroundColor: lineHighlight, display: "block" } }
                : {};
            }}
            customStyle={{
              margin: 0,
              padding: "0.5rem",
              background: "transparent",
              fontSize: "0.72rem",
              lineHeight: "1.55",
              maxHeight: "10rem",
              overflowY: "auto",
            }}
            lineNumberStyle={{
              minWidth: "2.2em",
              paddingRight: "1em",
              color: "#4b5563",
              userSelect: "none",
              fontSize: "0.68rem",
            }}
            codeTagProps={{
              style: { fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace" },
            }}
          >
            {finding.code_snippet}
          </SyntaxHighlighter>
        </div>
      )}

      {/* Confidence bar */}
      <div className="flex items-center gap-2">
        <span className="text-xs text-gray-500 w-20 shrink-0">
          Confidence {confidencePct}%
        </span>
        <div className="flex-1 h-1.5 bg-gray-800 rounded-full overflow-hidden">
          <div className={`h-full rounded-full ${barColor}`} style={{ width: `${confidencePct}%` }} />
        </div>
      </div>

      {/* TP / FP buttons */}
      <div className="flex gap-2 mt-1">
        <button
          onClick={(e) => handleLabel("tp", e)}
          disabled={loading || labeled !== null}
          className={[
            "flex-1 flex items-center justify-center gap-1.5 text-xs font-medium px-3 py-1.5 rounded border transition-colors",
            labeled === "tp"
              ? "bg-green-700 border-green-600 text-white"
              : labeled === "fp"
              ? "bg-gray-800 border-gray-700 text-gray-500 cursor-not-allowed"
              : "bg-green-900/40 border-green-700 text-green-400 hover:bg-green-900/70 cursor-pointer",
          ].join(" ")}
        >
          {labeled === "tp" ? (
            <svg className="w-3.5 h-3.5" viewBox="0 0 20 20" fill="currentColor">
              <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
            </svg>
          ) : <span>&#10003;</span>}
          True Positive
        </button>

        <button
          onClick={(e) => handleLabel("fp", e)}
          disabled={loading || labeled !== null}
          className={[
            "flex-1 flex items-center justify-center gap-1.5 text-xs font-medium px-3 py-1.5 rounded border transition-colors",
            labeled === "fp"
              ? "bg-red-700 border-red-600 text-white"
              : labeled === "tp"
              ? "bg-gray-800 border-gray-700 text-gray-500 cursor-not-allowed"
              : "bg-red-900/40 border-red-700 text-red-400 hover:bg-red-900/70 cursor-pointer",
          ].join(" ")}
        >
          {labeled === "fp" ? (
            <svg className="w-3.5 h-3.5" viewBox="0 0 20 20" fill="currentColor">
              <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
            </svg>
          ) : <span>&#10007;</span>}
          False Positive
        </button>
      </div>
    </div>
  );
}
