"use client";
import type { Stats, VerifiedEntry } from "../lib/types";

// ── constants ────────────────────────────────────────────────────────────────

const STAGES = [
  { key: "bootstrapping", label: "Bootstrapping", min: 0   },
  { key: "learning",      label: "Learning",      min: 1   },
  { key: "refining",      label: "Refining",      min: 50  },
  { key: "mature",        label: "Mature",        min: 500 },
];

const sevColor: Record<string, string> = {
  critical: "text-red-400 bg-red-950/60 border-red-800",
  high:     "text-orange-400 bg-orange-950/60 border-orange-800",
  medium:   "text-yellow-400 bg-yellow-950/60 border-yellow-800",
  low:      "text-blue-400 bg-blue-950/60 border-blue-800",
};

const sevDot: Record<string, string> = {
  critical: "bg-red-500",
  high:     "bg-orange-500",
  medium:   "bg-yellow-500",
  low:      "bg-blue-500",
};

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

const stageColor: Record<string, string> = {
  bootstrapping: "text-gray-500",
  learning:      "text-blue-400",
  refining:      "text-indigo-400",
  mature:        "text-emerald-400",
};

// ── helpers ──────────────────────────────────────────────────────────────────

function formatDate(iso: string) {
  const d = new Date(iso);
  return d.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" })
    + "  " + d.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", hour12: false });
}

// ── CaseCard ─────────────────────────────────────────────────────────────────

function CaseCard({ entry }: { entry: VerifiedEntry }) {
  const hasFindings = entry.findingCount > 0;

  return (
    <article className="rounded-xl border border-gray-800 bg-gray-900 overflow-hidden hover:border-gray-700 transition-colors">
      {/* Header bar */}
      <div className="flex items-center gap-2.5 px-4 py-2.5 border-b border-gray-800/60 bg-gray-900/80">
        <span className="font-mono text-sm font-bold text-indigo-400 shrink-0">
          #{String(entry.caseNo).padStart(4, "0")}
        </span>
        <span
          className={`text-[10px] px-1.5 py-0.5 rounded border font-mono shrink-0 ${langColor[entry.language] ?? "text-gray-400 bg-gray-800 border-gray-600"}`}
        >
          {entry.language}
        </span>
        {entry.maxSeverity && (
          <span className={`ml-auto text-[10px] font-bold uppercase px-2 py-0.5 rounded border shrink-0 ${sevColor[entry.maxSeverity]}`}>
            {entry.maxSeverity}
          </span>
        )}
      </div>

      {/* Findings list */}
      {hasFindings ? (
        <div className="px-4 pt-3 pb-2 space-y-2">
          {entry.ruleIds.slice(0, 4).map((rid, i) => (
            <div key={rid} className="flex items-start gap-2">
              <div className={`w-1.5 h-1.5 rounded-full mt-1.5 shrink-0 ${sevDot[entry.maxSeverity ?? "low"] ?? "bg-gray-600"}`} />
              <div className="min-w-0">
                <span className="font-mono text-xs text-gray-300 truncate block">{rid}</span>
                {entry.cwes[i] && (
                  <span className="text-[10px] text-gray-600 font-mono">{entry.cwes[i]}</span>
                )}
              </div>
            </div>
          ))}
          {entry.ruleIds.length > 4 && (
            <p className="text-[10px] text-gray-700 pl-3.5">
              +{entry.ruleIds.length - 4} more
            </p>
          )}
        </div>
      ) : (
        <div className="px-4 py-2.5">
          <span className="text-xs text-gray-700 italic">No findings detected</span>
        </div>
      )}

      {/* Footer */}
      <div className="flex items-center gap-3 px-4 py-2 border-t border-gray-800/40 bg-gray-950/30">
        <span className="text-[10px] text-gray-600 tabular-nums">
          {entry.findingCount} finding{entry.findingCount !== 1 ? "s" : ""}
        </span>
        {entry.tpCount > 0 && (
          <span className="text-[10px] text-emerald-600 font-medium">TP:{entry.tpCount}</span>
        )}
        {entry.fpCount > 0 && (
          <span className="text-[10px] text-red-700 font-medium">FP:{entry.fpCount}</span>
        )}
        {entry.findingCount > 0 && (
          <span className="text-[10px] text-gray-700 tabular-nums">
            conf:{Math.round(entry.avgConfidence * 100)}%
          </span>
        )}
        <span className="ml-auto text-[10px] text-gray-700 tabular-nums shrink-0">
          {formatDate(entry.verifiedAt)}
        </span>
      </div>
    </article>
  );
}

// ── LearningPanel ─────────────────────────────────────────────────────────────

interface LearningPanelProps {
  stats: Stats | null;
  totalCases: number;
}

function LearningPanel({ stats, totalCases }: LearningPanelProps) {
  const total   = stats?.total_labels ?? 0;
  const tp      = stats?.tp_count ?? 0;
  const fp      = stats?.fp_count ?? 0;
  const tpRatio = total > 0 ? tp / total : 0;

  const stageIdx  = Math.max(0, STAGES.findIndex((s) => s.key === stats?.model_stage));
  const curMin    = STAGES[stageIdx].min;
  const nextMin   = STAGES[stageIdx + 1]?.min ?? null;
  const bandPct   = nextMin !== null
    ? Math.min(100, Math.round(((total - curMin) / (nextMin - curMin)) * 100))
    : 100;

  return (
    <div className="space-y-4">
      {/* Stage */}
      <section className="rounded-xl border border-gray-800 bg-gray-900 p-4">
        <h3 className="text-[10px] font-semibold text-gray-600 uppercase tracking-widest mb-3">
          Model Status
        </h3>
        <div className="flex items-baseline gap-2 mb-3">
          <span className={`text-lg font-bold capitalize ${stageColor[stats?.model_stage ?? "bootstrapping"]}`}>
            {stats?.model_stage ?? "bootstrapping"}
          </span>
          <span className="text-xs text-gray-600">stage</span>
        </div>

        {/* Stage stepper */}
        <div className="flex items-center gap-1 mb-3">
          {STAGES.map((s, i) => {
            const done   = i < stageIdx;
            const active = i === stageIdx;
            return (
              <div key={s.key} className="flex items-center flex-1 last:flex-none">
                <div className={[
                  "h-1.5 flex-1 rounded-full",
                  done   ? "bg-emerald-500"
                         : active ? "bg-indigo-500/60"
                         : "bg-gray-800",
                ].join(" ")} />
                {i === STAGES.length - 1 && (
                  <div className={[
                    "w-2 h-2 rounded-full shrink-0 ml-1",
                    done ? "bg-emerald-500" : active ? "bg-indigo-400" : "bg-gray-800",
                  ].join(" ")} />
                )}
              </div>
            );
          })}
        </div>

        <div className="text-[10px] text-gray-700">
          {STAGES.map((s, i) => (
            <span key={s.key} className={i <= stageIdx ? "text-gray-500" : "text-gray-700"}>
              {s.label}{i < STAGES.length - 1 ? " → " : ""}
            </span>
          ))}
        </div>

        {nextMin !== null && (
          <div className="mt-3">
            <div className="flex justify-between text-[10px] text-gray-700 mb-1">
              <span>{STAGES[stageIdx + 1]?.label}</span>
              <span className="text-indigo-500">{total} / {nextMin}</span>
            </div>
            <div className="h-1.5 bg-gray-800 rounded-full overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-indigo-700 to-indigo-400 transition-all duration-700"
                style={{ width: `${bandPct}%` }}
              />
            </div>
          </div>
        )}

        <p className="text-[10px] text-gray-700 italic mt-2">
          Retrains on every Verify Submit
        </p>
      </section>

      {/* Label stats */}
      <section className="rounded-xl border border-gray-800 bg-gray-900 p-4">
        <h3 className="text-[10px] font-semibold text-gray-600 uppercase tracking-widest mb-3">
          Accumulated Labels
        </h3>

        <div className="grid grid-cols-3 gap-2 mb-3">
          {[
            { label: "Total",  value: total, color: "text-gray-100"    },
            { label: "TP",     value: tp,    color: "text-emerald-400" },
            { label: "FP",     value: fp,    color: "text-red-400"     },
          ].map((item) => (
            <div key={item.label} className="bg-gray-800/50 rounded-lg p-2.5 text-center border border-gray-700/30">
              <div className={`text-xl font-bold tabular-nums ${item.color}`}>{item.value}</div>
              <div className="text-[10px] text-gray-600 mt-0.5">{item.label}</div>
            </div>
          ))}
        </div>

        {total > 0 ? (
          <>
            <div className="flex justify-between text-[10px] text-gray-600 mb-1">
              <span>TP / FP ratio</span>
              <span>
                <span className="text-emerald-500">{Math.round(tpRatio * 100)}%</span>
                {" / "}
                <span className="text-red-500">{Math.round((1 - tpRatio) * 100)}%</span>
              </span>
            </div>
            <div className="h-2 bg-gray-800 rounded-full overflow-hidden flex">
              <div className="h-full bg-emerald-500 transition-all duration-700" style={{ width: `${tpRatio * 100}%` }} />
              <div className="h-full bg-red-500/60 transition-all duration-700" style={{ width: `${(1 - tpRatio) * 100}%` }} />
            </div>
          </>
        ) : (
          <p className="text-[10px] text-gray-700 text-center py-1">
            No labels yet — verify cases to accumulate knowledge.
          </p>
        )}
      </section>

      {/* Summary */}
      <section className="rounded-xl border border-gray-800 bg-gray-900 p-4">
        <h3 className="text-[10px] font-semibold text-gray-600 uppercase tracking-widest mb-3">
          Summary
        </h3>
        <div className="space-y-1.5">
          {[
            { label: "Cases verified",  value: totalCases },
            { label: "Findings labeled", value: total },
            { label: "True positives",  value: tp },
            { label: "False positives", value: fp },
          ].map((r) => (
            <div key={r.label} className="flex justify-between text-xs">
              <span className="text-gray-600">{r.label}</span>
              <span className="text-gray-300 tabular-nums font-medium">{r.value}</span>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}

// ── KnowledgeTab ─────────────────────────────────────────────────────────────

interface KnowledgeTabProps {
  stats: Stats | null;
  history: VerifiedEntry[];
}

export function KnowledgeTab({ stats, history }: KnowledgeTabProps) {
  return (
    <div className="flex flex-1 min-h-0">

      {/* ── Left: Case History ────────────────────────────────────────────── */}
      <div className="flex-1 min-w-0 overflow-y-auto px-5 py-4 border-r border-gray-800">
        <div className="max-w-2xl">
          <div className="flex items-center gap-2 mb-4">
            <h2 className="text-xs font-semibold text-gray-500 uppercase tracking-widest">
              Verified Cases
            </h2>
            {history.length > 0 && (
              <span className="text-[10px] bg-gray-800 text-gray-500 rounded-full px-1.5 py-0.5">
                {history.length}
              </span>
            )}
          </div>

          {history.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-20 gap-3">
              <div className="w-12 h-12 rounded-full bg-gray-800/60 border border-gray-700 flex items-center justify-center">
                <svg className="w-5 h-5 text-gray-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5}
                    d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
              </div>
              <p className="text-sm text-gray-600">No verified cases yet.</p>
              <p className="text-xs text-gray-700">Submit cases from the Verify tab to build the knowledge base.</p>
            </div>
          ) : (
            <div className="space-y-3">
              {history.map((entry) => (
                <CaseCard key={entry.caseNo} entry={entry} />
              ))}
            </div>
          )}
        </div>
      </div>

      {/* ── Right: Learning Status ───────────────────────────────────────── */}
      <div className="w-64 xl:w-72 shrink-0 overflow-y-auto px-4 py-4 bg-gray-950">
        <h2 className="text-[10px] font-semibold text-gray-600 uppercase tracking-widest mb-4">
          Learning Status
        </h2>
        <LearningPanel stats={stats} totalCases={history.length} />
      </div>

    </div>
  );
}
