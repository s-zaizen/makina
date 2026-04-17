"use client";
import type { Stats, VerifiedEntry } from "../lib/types";

// Maturity bands — descriptive only, not capability gates.
// The model trains from the first label; stages reflect confidence level.
const STAGES = [
  { key: "bootstrapping", label: "Bootstrapping", sub: "0 labels",    min: 0   },
  { key: "learning",      label: "Learning",      sub: "1–49 labels", min: 1   },
  { key: "refining",      label: "Refining",      sub: "50–499",      min: 50  },
  { key: "mature",        label: "Mature",        sub: "500+",        min: 500 },
];

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

interface KnowledgeTabProps {
  stats: Stats | null;
  history: VerifiedEntry[];
}

function Bar({ pct, color }: { pct: number; color: string }) {
  return (
    <div className="flex-1 h-2 bg-gray-800 rounded-full overflow-hidden">
      <div
        className={`h-full rounded-full transition-all duration-700 ${color}`}
        style={{ width: `${Math.max(2, pct)}%` }}
      />
    </div>
  );
}

function formatDate(iso: string) {
  const d = new Date(iso);
  return d.toLocaleDateString("ja-JP", { year: "numeric", month: "2-digit", day: "2-digit" })
    + " " + d.toLocaleTimeString("ja-JP", { hour: "2-digit", minute: "2-digit" });
}

export function KnowledgeTab({ stats, history }: KnowledgeTabProps) {
  const total     = stats?.total_labels ?? 0;
  const tpCount   = stats?.tp_count ?? 0;
  const fpCount   = stats?.fp_count ?? 0;
  const tpRatio   = total > 0 ? tpCount / total : 0;

  const stageIdx = Math.max(0, STAGES.findIndex((s) => s.key === stats?.model_stage));
  // Continuous progress: show how far through the current maturity band we are
  const currentMin = STAGES[stageIdx].min;
  const nextMin    = STAGES[stageIdx + 1]?.min ?? null;
  const bandProgress = nextMin !== null
    ? Math.min(1, (total - currentMin) / (nextMin - currentMin))
    : 1;

  return (
    <div className="flex-1 overflow-y-auto px-6 py-5 bg-gray-950">
      <div className="max-w-2xl mx-auto space-y-5">

        {/* ── Model Pipeline ─────────────────────────────────────────── */}
        <section className="rounded-xl border border-gray-800 bg-gray-900 p-5">
          <h2 className="text-xs font-semibold text-gray-500 uppercase tracking-widest mb-5">
            Model Pipeline
          </h2>

          <div className="flex items-start">
            {STAGES.map((stage, i) => {
              const done   = i < stageIdx;
              const active = i === stageIdx;
              return (
                <div key={stage.key} className="flex items-start flex-1 last:flex-none">
                  <div className="flex flex-col items-center gap-1.5 min-w-0">
                    <div className={[
                      "w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold border-2 transition-all shrink-0",
                      done   ? "bg-emerald-500/20 border-emerald-500 text-emerald-400"
                             : active
                             ? "bg-indigo-500/20 border-indigo-500 text-indigo-300 ring-4 ring-indigo-500/15"
                             : "bg-gray-800 border-gray-700 text-gray-600",
                    ].join(" ")}>
                      {done ? "✓" : i + 1}
                    </div>
                    <span className={[
                      "text-xs font-medium text-center",
                      done ? "text-emerald-400" : active ? "text-indigo-300" : "text-gray-600",
                    ].join(" ")}>{stage.label}</span>
                    <span className="text-[10px] text-gray-700 text-center leading-tight">{stage.sub}</span>
                  </div>
                  {i < STAGES.length - 1 && (
                    <div className={[
                      "flex-1 h-0.5 mt-4 mx-1",
                      done ? "bg-emerald-500" : "bg-gray-800",
                    ].join(" ")} />
                  )}
                </div>
              );
            })}
          </div>

          <div className="mt-5">
            <div className="flex justify-between text-xs text-gray-600 mb-2">
              <span className="text-gray-500">
                Continuously learning · retrained on every Verify Submit
              </span>
              <span className="text-indigo-400 tabular-nums font-medium">{total} labels</span>
            </div>
            <div className="h-2 bg-gray-800 rounded-full overflow-hidden">
              <div
                className="h-full rounded-full bg-gradient-to-r from-indigo-700 to-indigo-400 transition-all duration-700"
                style={{ width: `${bandProgress * 100}%` }}
              />
            </div>
            {nextMin !== null && (
              <p className="text-xs text-gray-700 mt-1.5">
                {nextMin - total} more labels to reach{" "}
                <span className="text-gray-500">{STAGES[stageIdx + 1]?.label}</span>
              </p>
            )}
          </div>
        </section>

        {/* ── Label Statistics ───────────────────────────────────────── */}
        <section className="rounded-xl border border-gray-800 bg-gray-900 p-5">
          <h2 className="text-xs font-semibold text-gray-500 uppercase tracking-widest mb-4">
            Accumulated Labels
          </h2>

          <div className="grid grid-cols-3 gap-3 mb-4">
            {[
              { label: "Total",          value: total,   color: "text-gray-100"    },
              { label: "True Positive",  value: tpCount, color: "text-emerald-400" },
              { label: "False Positive", value: fpCount, color: "text-red-400"     },
            ].map((item) => (
              <div
                key={item.label}
                className="bg-gray-800/50 border border-gray-700/40 rounded-lg p-3 text-center"
              >
                <div className={`text-2xl font-bold tabular-nums ${item.color}`}>{item.value}</div>
                <div className="text-xs text-gray-600 mt-1">{item.label}</div>
              </div>
            ))}
          </div>

          {total > 0 ? (
            <div>
              <div className="flex justify-between text-xs text-gray-600 mb-1.5">
                <span>TP / FP Ratio</span>
                <span>
                  <span className="text-emerald-400">{Math.round(tpRatio * 100)}% TP</span>
                  <span className="text-gray-700 mx-1">·</span>
                  <span className="text-red-400">{Math.round((1 - tpRatio) * 100)}% FP</span>
                </span>
              </div>
              <div className="h-2.5 bg-gray-800 rounded-full overflow-hidden flex">
                <div
                  className="h-full bg-emerald-500 transition-all duration-700"
                  style={{ width: `${tpRatio * 100}%` }}
                />
                <div
                  className="h-full bg-red-500/70 transition-all duration-700"
                  style={{ width: `${(1 - tpRatio) * 100}%` }}
                />
              </div>
            </div>
          ) : (
            <p className="text-xs text-gray-700 text-center py-1">
              No labels yet — verify cases to accumulate knowledge.
            </p>
          )}
        </section>

        {/* ── Verified Cases History ─────────────────────────────────── */}
        <section className="rounded-xl border border-gray-800 bg-gray-900 p-5">
          <h2 className="text-xs font-semibold text-gray-500 uppercase tracking-widest mb-4">
            Verified Cases
          </h2>

          {history.length === 0 ? (
            <p className="text-xs text-gray-700 text-center py-2">
              No verified cases yet.
            </p>
          ) : (
            <div className="space-y-2">
              {history.map((entry) => (
                <div
                  key={entry.caseNo}
                  className="flex items-center gap-3 py-2 border-b border-gray-800/60 last:border-0"
                >
                  <span className="font-mono text-xs font-bold text-indigo-400 w-14 shrink-0">
                    #{String(entry.caseNo).padStart(4, "0")}
                  </span>
                  <span className="text-xs text-gray-600 w-32 shrink-0 tabular-nums">
                    {formatDate(entry.verifiedAt)}
                  </span>
                  <span className={`text-xs font-mono w-16 shrink-0 ${langColor[entry.language] ?? "text-gray-500"}`}>
                    {entry.language}
                  </span>
                  <div className="flex gap-3 text-xs">
                    <span className="text-gray-500">{entry.findingCount} findings</span>
                    {entry.tpCount > 0 && (
                      <span className="text-emerald-600">TP:{entry.tpCount}</span>
                    )}
                    {entry.fpCount > 0 && (
                      <span className="text-red-700">FP:{entry.fpCount}</span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>

      </div>
    </div>
  );
}
