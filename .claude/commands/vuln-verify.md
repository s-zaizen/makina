# /vuln-verify

Label and submit a pending case in the deus verify queue.

## Usage

```
/vuln-verify {case_id}
```

`{case_id}` is the integer `case_no` returned by `/vuln-add` or visible in the Verify tab.

## What to do

1. **Fetch the case** — GET the pending queue and locate `case_no == {case_id}`:
   ```
   GET http://localhost:7373/api/verify/queue
   ```
   If not found, report "case #{case_id} not found in pending queue" and stop.

2. **Review findings** — read `findings_json` for the case. For each finding:
   - Assess whether it is a true positive (TP) or false positive (FP) based on the code and the rule/CWE reported.
   - Default to **TP** for obvious vulnerability patterns; FP only when the scanner clearly misfired.

3. **Submit labels and case in one call** — POST to knowledge (triggers GBDT retrain):
   ```
   POST http://localhost:7373/api/knowledge
   {
     "case_no": {case_id},
     "labels": {
       "<finding_id_1>": "tp",
       "<finding_id_2>": "fp",
       ...
     }
   }
   ```

4. **Report** — output:
   - `case_no` submitted
   - per-finding label summary (`N tp, M fp`)
   - confirmation that retrain was triggered

## Example output

```
✓ Submitted case #42
  findings:  3 tp, 0 fp
  retrain:   triggered
```
