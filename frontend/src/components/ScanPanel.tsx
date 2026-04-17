"use client";

import type { Language } from "../lib/types";

const LANGUAGES: { value: Language; label: string }[] = [
  { value: "auto", label: "Auto-detect" },
  { value: "python", label: "Python" },
  { value: "rust", label: "Rust" },
  { value: "javascript", label: "JavaScript" },
  { value: "typescript", label: "TypeScript" },
  { value: "go", label: "Go" },
  { value: "java", label: "Java" },
  { value: "ruby", label: "Ruby" },
  { value: "c", label: "C" },
  { value: "cpp", label: "C++" },
];

interface ScanPanelProps {
  language: Language;
  onLanguageChange: (lang: Language) => void;
  onScan: () => void;
  scanning: boolean;
  hasFindings: boolean;
  onSubmitToVerify: () => void;
}

export function ScanPanel({ language, onLanguageChange, onScan, scanning, hasFindings, onSubmitToVerify }: ScanPanelProps) {
  return (
    <div className="flex items-center gap-2">
      <select
        value={language}
        onChange={(e) => onLanguageChange(e.target.value as Language)}
        className="px-2.5 py-1 text-xs font-medium bg-gray-800 text-gray-300 border border-gray-700 rounded focus:outline-none focus:border-indigo-500 cursor-pointer"
      >
        {LANGUAGES.map((l) => (
          <option key={l.value} value={l.value}>
            {l.label}
          </option>
        ))}
      </select>

      <button
        onClick={onScan}
        disabled={scanning}
        className={[
          "flex items-center gap-1.5 px-3.5 py-1 rounded text-xs font-semibold transition-colors",
          scanning
            ? "bg-green-800 text-green-300 cursor-not-allowed"
            : "bg-green-600 hover:bg-green-500 text-white cursor-pointer",
        ].join(" ")}
      >
        {scanning ? (
          <>
            <svg className="w-3.5 h-3.5 animate-spin" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
            </svg>
            Scanning…
          </>
        ) : "Scan"}
      </button>

      <div className="w-px h-3.5 bg-gray-700" />

      <button
        onClick={onSubmitToVerify}
        disabled={!hasFindings || scanning}
        className={[
          "flex items-center gap-1 px-3.5 py-1 rounded text-xs font-semibold border transition-colors",
          hasFindings && !scanning
            ? "border-indigo-600 text-indigo-300 hover:bg-indigo-900/40 cursor-pointer"
            : "border-gray-800 text-gray-700 cursor-not-allowed",
        ].join(" ")}
      >
        Submit →
      </button>
    </div>
  );
}
