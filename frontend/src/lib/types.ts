export type Language =
  | "auto"
  | "python"
  | "rust"
  | "javascript"
  | "typescript"
  | "go"
  | "java"
  | "ruby"
  | "c"
  | "cpp";

export type Severity = "critical" | "high" | "medium" | "low";
export type Label = "tp" | "fp";

export interface Finding {
  id: string;
  rule_id: string;
  message: string;
  severity: Severity;
  line_start: number;
  line_end: number;
  code_snippet: string;
  confidence: number;
  is_uncertain: boolean;
  cwe: string | null;
  source: string;
}

export interface ScanResponse {
  scan_id: string;
  findings: Finding[];
  language: string;
  lines_scanned: number;
}

export interface Stats {
  total_labels: number;
  tp_count: number;
  fp_count: number;
  model_stage: string;
  labels_until_next_stage: number;
}

export interface VerifyCase {
  caseNo: number;
  cveId?: string | null;
  code: string;
  language: Language;
  findings: Finding[];
  submittedAt: string;
  labels: Record<string, Label>;
}

export interface FileNode {
  name: string;
  path: string;
  type: "file" | "dir";
  language?: Language;
  content?: string;
  children?: FileNode[];
}

export interface KnowledgeCase {
  caseNo: number;
  cveId?: string | null;
  code: string;
  language: Language;
  findings: Finding[];
  labels: Record<string, string>;
  submittedAt: string;
  verifiedAt: string;
}
