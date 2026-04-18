# /vuln-add

Add a vulnerable code snippet to the deus verify queue.

## Usage

```
/vuln-add {code}
```

`{code}` is a block of vulnerable source code (any language supported by deus).

## What to do

1. **Detect language** — infer from syntax/keywords (python / javascript / typescript / java / go / ruby / c / cpp / rust). Default to `python` if ambiguous.

2. **Validate** — reject and explain if the snippet:
   - Is fewer than 5 lines
   - Contains no recognisable vulnerability pattern (no taint source, no dangerous sink, no obvious CWE)
   - Is clearly configuration-only or a placeholder (`TODO`, `...`, `pass` body only)

3. **Scan** — POST to the deus scan API:
   ```
   POST http://localhost:7373/api/scan
   {"code": "<snippet>", "language": "<lang>"}
   ```

4. **Queue** — POST the scan result to the verify queue:
   ```
   POST http://localhost:7373/api/verify/queue
   {"cve_id": null, "code": "<snippet>", "language": "<lang>", "findings": [...]}
   ```

5. **Report** — output:
   - `case_no` assigned
   - language detected
   - number of findings the scanner returned
   - one-line description of the primary vulnerability (CWE / rule_id)

## Example output

```
✓ Queued as case #42
  language:  python
  findings:  3  (CWE-89 SQL Injection, CWE-78 OS Command Injection, CWE-22 Path Traversal)
```
