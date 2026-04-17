"use client";
import type { Stats } from "../lib/types";

interface StatusBarProps {
  stats: Stats | null;
}

const stageColors: Record<string, string> = {
  "bootstrapping": "text-gray-500",
  "learning":      "text-blue-400",
  "refining":      "text-indigo-400",
  "mature":        "text-emerald-400",
};

export function StatusBar({ stats }: StatusBarProps) {
  if (!stats) {
    return <div className="h-8 bg-gray-900 border-t border-gray-700" />;
  }

  const stageColor = stageColors[stats.model_stage] ?? "text-gray-400";

  return (
    <div className="h-8 bg-gray-900 border-t border-gray-700 flex items-center px-4 gap-5 text-xs text-gray-400">
      <span>
        Labels:{" "}
        <span className="text-gray-200 font-medium">{stats.total_labels}</span>
      </span>

      <span className="text-gray-600">|</span>

      <span>
        TP:{" "}
        <span className="text-green-400 font-medium">{stats.tp_count}</span>
        {" "}FP:{" "}
        <span className="text-red-400 font-medium">{stats.fp_count}</span>
      </span>

      <span className="text-gray-600">|</span>

      <span>
        Model:{" "}
        <span className={`font-medium ${stageColor}`}>{stats.model_stage}</span>
      </span>

      <span className="text-gray-600">|</span>
      <span className="text-gray-600 italic text-[10px]">retrains on every submit</span>
    </div>
  );
}
