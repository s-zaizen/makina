"use client";
import { useState } from "react";
import { Prism as SyntaxHighlighter } from "react-syntax-highlighter";
import { vscDarkPlus } from "react-syntax-highlighter/dist/esm/styles/prism";
import type { Label, VerifyCase } from "../lib/types";

const langColor: Record<string, string> = {
  python:     "text-blue-400 bg-blue-950 border-blue-800",
  javascript: "text-yellow-400 bg-yellow-950 border-yellow-800",
  typescript: "text-sky-400 bg-sky-950 border-sky-800",
  rust:       "text-orange-400 bg-orange-950 border-orange-800",
  go:         "text-cyan-400 bg-cyan-950 border-cyan-800",
  java:       "text-red-400 bg-red-950 border-red-800",
  ruby:       "text-rose-400 bg-rose-950 border-rose-800",
  c:          "text-gray-400 bg-gray-800 border-gray-600",
  cpp:        "text-purple-400 bg-purple-950 border-purple-800",
};

const sevColor: Record<string, string> = {
  critical: "text-red-400",
  high:     "text-orange-400",
  medium:   "text-yellow-400",
  low:      "text-blue-400",
};

const sevHighlight: Record<string, string> = {
  critical: "rgba(239,68,68,0.10)",
  high:     "rgba(249,115,22,0.08)",
  medium:   "rgba(234,179,8,0.08)",
  low:      "rgba(96,165,250,0.08)",
};

function formatDate(iso: string) {
  const d = new Date(iso);
  const date = d.toLocaleDateString("ja-JP", { year: "numeric", month: "2-digit", day: "2-digit" });
  const time = d.toLocaleTimeString("ja-JP", { hour: "2-digit", minute: "2-digit" });
  return `${date} ${time}`;
}

interface CaseCardProps {
  vc: VerifyCase;
  onLabel: (findingId: string, label: Label) => void;
  onSubmit: () => Promise<void>;
}

function CaseCard({ vc, onLabel, onSubmit }: CaseCardProps) {
  const [expanded, setExpanded] = useState(true);
  const [submitting, setSubmitting] = useState(false);

  const labeledCount = Object.keys(vc.labels).length;
  const tpCount = Object.values(vc.labels).filter((l) => l === "tp").length;
  const fpCount = Object.values(vc.labels).filter((l) => l === "fp").length;

  const handleSubmit = async () => {
    setSubmitting(true);
    try { await onSubmit(); } finally { setSubmitting(false); }
  };

  return (
    <div className="rounded-xl border border-gray-800 bg-gray-900 overflow-hidden">
      {/* Header */}
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center gap-2.5 px-4 py-3 hover:bg-gray-800/50 transition-colors text-left"
      >
        <span className="font-mono text-sm font-bold text-indigo-400 shrink-0">
          #{String(vc.caseNo).padStart(4, "0")}
        </span>
        {vc.cveId && (
          <span className="font-mono text-xs text-amber-400 shrink-0">{vc.cveId}</span>
        )}
        <span className="text-xs text-gray-500 shrink-0">{formatDate(vc.submittedAt)}</span>
        <span className={`text-xs px-1.5 py-0.5 rounded border font-mono shrink-0 ${langColor[vc.language] ?? "text-gray-400 bg-gray-800 border-gray-600"}`}>
          {vc.language}
        </span>
        <span className="text-xs text-gray-500 shrink-0">{vc.findings.length} findings</span>
        {labeledCount > 0 && (
          <span className="text-xs text-gray-600 shrink-0">
            {tpCount > 0 && <span className="text-emerald-600">TP:{tpCount}</span>}
            {tpCount > 0 && fpCount > 0 && <span className="text-gray-700 mx-1">·</span>}
            {fpCount > 0 && <span className="text-red-700">FP:{fpCount}</span>}
          </span>
        )}
        <svg
          className={`ml-auto w-4 h-4 text-gray-600 transition-transform shrink-0 ${expanded ? "rotate-180" : ""}`}
          fill="none" viewBox="0 0 24 24" stroke="currentColor"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {/* Body */}
      {expanded && (
        <div className="border-t border-gray-800 divide-y divide-gray-800/60">
          {vc.findings.map((f) => {
            const labeled = vc.labels[f.id] ?? null;
            return (
              <div key={f.id} className="px-4 py-3 flex gap-3">
                <div className="flex-1 min-w-0 space-y-2">
                  {/* Finding meta */}
                  <div className="flex flex-wrap items-center gap-2">
                    <span className={`text-xs font-bold uppercase ${sevColor[f.severity] ?? "text-gray-400"}`}>
                      {f.severity}
                    </span>
                    <span className="font-mono text-xs text-gray-500">{f.rule_id}</span>
                    {f.cwe && (
                      <span className="text-xs text-gray-600 font-mono px-1 bg-gray-800 rounded border border-gray-700">
                        {f.cwe}
                      </span>
                    )}
                    <span className="text-xs text-gray-700 font-mono">
                      {f.line_end > f.line_start ? `L${f.line_start}–${f.line_end}` : `L${f.line_start}`}
                    </span>
                  </div>

                  {/* Message */}
                  <p className="text-xs text-gray-300 leading-snug">{f.message}</p>

                  {/* Code snippet */}
                  {f.code_snippet && (
                    <div className="rounded border border-gray-800 overflow-hidden">
                      <SyntaxHighlighter
                        language={vc.language === "auto" ? "text" : vc.language}
                        style={vscDarkPlus}
                        showLineNumbers
                        startingLineNumber={f.line_start}
                        wrapLines
                        lineProps={(ln) => {
                          const inRange = ln >= f.line_start && ln <= f.line_end;
                          return inRange ? { style: { backgroundColor: sevHighlight[f.severity], display: "block" } } : {};
                        }}
                        customStyle={{
                          margin: 0,
                          padding: "0.4rem",
                          background: "transparent",
                          fontSize: "0.68rem",
                          lineHeight: "1.5",
                          maxHeight: "8rem",
                          overflowY: "auto",
                        }}
                        lineNumberStyle={{
                          minWidth: "2em",
                          paddingRight: "0.75em",
                          color: "#374151",
                          userSelect: "none",
                          fontSize: "0.62rem",
                        }}
                        codeTagProps={{ style: { fontFamily: "ui-monospace, monospace" } }}
                      >
                        {f.code_snippet}
                      </SyntaxHighlighter>
                    </div>
                  )}
                </div>

                {/* TP / FP buttons */}
                <div className="flex flex-col gap-1.5 shrink-0 pt-0.5">
                  <button
                    onClick={() => onLabel(f.id, "tp")}
                    disabled={labeled !== null}
                    className={[
                      "text-xs px-3 py-1 rounded border font-medium transition-colors",
                      labeled === "tp"
                        ? "bg-emerald-700 border-emerald-600 text-white"
                        : labeled === "fp"
                        ? "bg-gray-800 border-gray-700 text-gray-600 cursor-not-allowed"
                        : "bg-emerald-900/30 border-emerald-700/60 text-emerald-400 hover:bg-emerald-900/60 cursor-pointer",
                    ].join(" ")}
                  >
                    TP
                  </button>
                  <button
                    onClick={() => onLabel(f.id, "fp")}
                    disabled={labeled !== null}
                    className={[
                      "text-xs px-3 py-1 rounded border font-medium transition-colors",
                      labeled === "fp"
                        ? "bg-red-700 border-red-600 text-white"
                        : labeled === "tp"
                        ? "bg-gray-800 border-gray-700 text-gray-600 cursor-not-allowed"
                        : "bg-red-900/30 border-red-700/60 text-red-400 hover:bg-red-900/60 cursor-pointer",
                    ].join(" ")}
                  >
                    FP
                  </button>
                </div>
              </div>
            );
          })}

          {/* Submit footer */}
          <div className="px-4 py-3 bg-gray-900/60 flex items-center justify-between gap-3">
            <span className="text-xs text-gray-600">
              {labeledCount}/{vc.findings.length} labeled
              {labeledCount > 0 && (
                <> · <span className="text-emerald-600">{tpCount} TP</span> · <span className="text-red-600">{fpCount} FP</span></>
              )}
            </span>
            <button
              onClick={handleSubmit}
              disabled={submitting || labeledCount === 0}
              className={[
                "px-5 py-1.5 rounded text-sm font-semibold transition-colors",
                submitting || labeledCount === 0
                  ? "bg-gray-800 text-gray-600 cursor-not-allowed"
                  : "bg-indigo-600 hover:bg-indigo-500 text-white cursor-pointer",
              ].join(" ")}
            >
              {submitting ? "Submitting…" : "Submit to Knowledge"}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

interface VerifyTabProps {
  cases: VerifyCase[];
  onLabel: (caseNo: number, findingId: string, label: Label) => void;
  onSubmit: (caseNo: number) => Promise<void>;
}

export function VerifyTab({ cases, onLabel, onSubmit }: VerifyTabProps) {
  if (cases.length === 0) {
    return (
      <div className="flex-1 flex items-center justify-center bg-gray-950">
        <div className="text-center">
          <div className="w-12 h-12 mx-auto mb-4 rounded-full bg-gray-800/60 border border-gray-700 flex items-center justify-center">
            <svg className="w-5 h-5 text-gray-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5}
                d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01" />
            </svg>
          </div>
          <p className="text-sm text-gray-600">No cases pending.</p>
          <p className="text-xs text-gray-700 mt-1">
            Scan code and click <span className="text-indigo-500 font-medium">Submit →</span> to queue a case.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex-1 overflow-y-auto px-6 py-5 bg-gray-950">
      <div className="max-w-2xl mx-auto space-y-3">
        <p className="text-xs text-gray-600 mb-2">
          {cases.length} case{cases.length !== 1 ? "s" : ""} pending verification
        </p>
        {cases.map((vc) => (
          <CaseCard
            key={vc.caseNo}
            vc={vc}
            onLabel={(findingId, label) => onLabel(vc.caseNo, findingId, label)}
            onSubmit={() => onSubmit(vc.caseNo)}
          />
        ))}
      </div>
    </div>
  );
}
