# /vuln-add-verify-with-claude

Automatically research a CVE, extract vulnerable code, queue it, and verify it — end-to-end.

## Usage

```
/vuln-add-verify-with-claude
```

No arguments. Claude selects a CVE to process, or the user can specify one inline:

```
/vuln-add-verify-with-claude CVE-2024-XXXXX
```

## Pipeline

### Step 1 — Source selection

If no CVE is specified, choose one that:
- Has a public PoC or disclosed vulnerable code (NVD, GitHub advisories, project changelogs, security blogs)
- Has a clear taint flow (source → sink) that deus can learn from
- Is NOT already in the verify queue (check `GET /api/verify/queue` first)

### Step 2 — Research

Search for:
1. The **official NVD entry** (severity, CWE, affected versions)
2. A **public PoC or vulnerable code snippet** — prefer:
   - GitHub commit diffs showing the vulnerable line(s)
   - CVE PoC repos (e.g. github.com/trickest/cve, github.com/nomi-sec/PoC-in-GitHub)
   - Security advisories with code examples
   - Blog posts with reproduction code

**Quality bar** — only proceed if you find code that:
- Is ≥ 10 lines of real source (not a one-liner, not config-only)
- Shows the vulnerability in context (not just a patch diff)
- Has a clear taint source (user input) → dangerous sink

If no suitable code is found after 2 search attempts, report the failure and stop.

### Step 3 — Extract & clean

Extract a self-contained snippet (20–80 lines preferred):
- Keep enough context to show the vulnerability flow
- Remove unrelated code that obscures the finding
- Add a single comment on the vulnerable line: `# CVE-YYYY-NNNNN: <vuln type>`

### Step 4 — vuln-add

Run `/vuln-add` on the extracted snippet (follow that command's full pipeline):
- Detect language
- Validate
- Scan via `POST /api/scan`
- Queue via `POST /api/verify/queue` with `cve_id` set to the CVE ID

### Step 5 — vuln-verify

Run `/vuln-verify` on the resulting `case_no` (follow that command's full pipeline):
- Review each finding against the CVE description
- Label TP/FP with justification
- Submit via `DELETE /api/verify/queue/{case_no}`

### Step 6 — Report

Output a summary:
```
CVE: CVE-YYYY-NNNNN
Title: <short description>
Language: <lang>
Severity: <CVSS / HIGH / CRITICAL>
CWE: <CWE-N>
Source: <URL where code was found>

case_no: #N
findings: X tp, Y fp
retrain: triggered

Vulnerability summary:
<2-3 sentences explaining the taint flow and why the findings are TP>
```

## Notes

- Never fabricate code — only use code found in public sources.
- If the CVE is in a language not supported by deus, say so and stop.
- If the scanner finds 0 findings, still queue and submit (0 findings is valid training signal for FP-heavy CVEs). Label the case with 0 findings and note "no scanner findings — submitted as negative example".
