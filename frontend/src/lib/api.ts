import type { Finding, ScanResponse, Stats, Language, Label, VerifyCase } from "./types";

const BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:7373";

export async function scanCode(code: string, language: Language): Promise<ScanResponse> {
  const res = await fetch(`${BASE}/api/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ code, language }),
  });
  if (!res.ok) throw new Error(`Scan failed: ${res.status}`);
  return res.json();
}

export async function submitFeedback(findingId: string, label: Label): Promise<{ total_labels: number }> {
  const res = await fetch(`${BASE}/api/feedback`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ finding_id: findingId, label }),
  });
  if (!res.ok) throw new Error(`Feedback failed: ${res.status}`);
  return res.json();
}

export async function getStats(): Promise<Stats> {
  const res = await fetch(`${BASE}/api/stats`);
  if (!res.ok) throw new Error(`Stats failed: ${res.status}`);
  return res.json();
}

export async function addManualFinding(
  code: string,
  language: Language,
  lineStart: number,
  lineEnd: number,
  severity: string,
  cwe: string | null,
  message: string,
): Promise<Finding> {
  const res = await fetch(`${BASE}/api/findings/manual`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      code,
      language,
      line_start: lineStart,
      line_end: lineEnd,
      severity,
      cwe: cwe || null,
      message,
    }),
  });
  if (!res.ok) throw new Error(`Manual finding failed: ${res.status}`);
  return res.json();
}

// ── Verify queue ──────────────────────────────────────────────────────────────

interface BackendVerifyCase {
  case_no: number;
  cve_id: string | null;
  code: string;
  language: string;
  findings: Finding[];
  submitted_at: string;
}

function mapCase(b: BackendVerifyCase): VerifyCase {
  return {
    caseNo: b.case_no,
    cveId: b.cve_id,
    code: b.code,
    language: b.language as Language,
    findings: b.findings,
    submittedAt: b.submitted_at,
    labels: {},
  };
}

export async function getVerifyQueue(): Promise<VerifyCase[]> {
  const res = await fetch(`${BASE}/api/verify/queue`);
  if (!res.ok) throw new Error(`Queue fetch failed: ${res.status}`);
  const items: BackendVerifyCase[] = await res.json();
  return items.map(mapCase);
}

export async function addToVerifyQueue(
  cveId: string | null,
  code: string,
  language: Language,
  findings: Finding[],
): Promise<VerifyCase> {
  const res = await fetch(`${BASE}/api/verify/queue`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ cve_id: cveId, code, language, findings }),
  });
  if (!res.ok) throw new Error(`Queue add failed: ${res.status}`);
  const item: BackendVerifyCase = await res.json();
  return mapCase(item);
}

export async function removeFromVerifyQueue(caseNo: number): Promise<void> {
  const res = await fetch(`${BASE}/api/verify/queue/${caseNo}`, { method: "DELETE" });
  if (!res.ok) throw new Error(`Queue remove failed: ${res.status}`);
}

export async function getVerifiedHistory(): Promise<VerifyCase[]> {
  const res = await fetch(`${BASE}/api/verify/done`);
  if (!res.ok) throw new Error(`Verified history failed: ${res.status}`);
  const items: BackendVerifyCase[] = await res.json();
  return items.map(mapCase);
}
