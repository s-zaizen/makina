"""Language-agnostic vulnerability analyzer using code embeddings.

Detection layers (cheap → expensive):

  1. Sink-pattern regex (per CWE): pinpoints the exact line of a known
     dangerous call (eval, system, pickle.loads, …) regardless of
     semantic similarity. Very fast, high precision when a known sink
     is present.

  2. kNN against labeled CVEfixes / user-verified TP embeddings stored
     in `feedback.db`. Built once at startup, grouped by CWE. Scanned
     code windows are compared to each CWE's cluster of real-world TP
     examples, not to hardcoded Python exec/eval strings.

  3. Hardcoded CWE prototypes (VULN_PATTERNS below). Used as a fallback
     when the labeled index is empty or the embedder is not ready.
"""
from __future__ import annotations

import logging
import os
import re
import sqlite3
import threading
from pathlib import Path
from typing import Optional

import numpy as np

from . import embedder

logger = logging.getLogger("makina_ml.analyzer")

DB_PATH = Path(os.environ.get("MAKINA_DB", "/root/.makina/feedback.db"))
MODEL_PATH = Path(os.environ.get("MAKINA_MODEL", "/root/.makina/model.json"))

# ── CWE metadata + hardcoded-prototype fallback ─────────────────────────────

VULN_PATTERNS: dict = {
    "CWE-89": {
        "name": "SQL Injection",
        "severity": "critical",
        "patterns": [
            'cursor.execute("SELECT * FROM users WHERE name=\'" + name + "\'")',
            'db.query(f"INSERT INTO logs VALUES (\'{user_input}\')")',
            'db.query("SELECT * FROM users WHERE id=" + userId)',
            'connection.query(`DELETE FROM ${table} WHERE id=${id}`)',
            'stmt.executeQuery("SELECT * FROM users WHERE user=\'" + user + "\'")',
            'User.where("name = \'#{params[:name]}\'")',
            'db.Query("SELECT * FROM users WHERE name=\'" + name + "\'")',
        ],
    },
    "CWE-78": {
        "name": "Command Injection",
        "severity": "critical",
        "patterns": [
            "os.system(user_input)",
            "subprocess.call(cmd, shell=True)",
            'os.popen("cat " + filename)',
            "child_process.exec(cmd)",
            'system("ping " + host)',
            'exec.Command("sh", "-c", userInput)',
            "Runtime.getRuntime().exec(userInput)",
        ],
    },
    "CWE-94": {
        "name": "Code Injection",
        "severity": "critical",
        "patterns": [
            "exec(user_input)",
            "eval(request.args.get('code'))",
            "exec(compile(code, '<string>', 'exec'))",
            "eval(f'result = {formula}')",
            "exec(code_obj)",
            "eval(untrusted_code)",
            "exec(ast.Module(body=[node], type_ignores=[]))",
            "exec(compile(ast.Module(body=[node], type_ignores=[]), '<string>', 'exec'))",
        ],
    },
    "CWE-22": {
        "name": "Path Traversal",
        "severity": "high",
        "patterns": [
            'open("/var/data/" + filename)',
            "file = open(base_path + user_path)",
            'fs.readFile("uploads/" + req.params.file)',
            "new FileInputStream(new File(baseDir + userInput))",
            "path.join(uploadDir, req.body.filename)",
        ],
    },
    "CWE-502": {
        "name": "Unsafe Deserialization",
        "severity": "high",
        "patterns": [
            "pickle.loads(data)",
            "pickle.load(file)",
            "yaml.load(stream)",
            "Marshal.load(data)",
            "new ObjectInputStream(new FileInputStream(file))",
        ],
    },
    "CWE-327": {
        "name": "Weak Cryptography",
        "severity": "medium",
        "patterns": [
            "hashlib.md5(password.encode())",
            "hashlib.sha1(data)",
            "DES.new(key)",
            'Cipher.getInstance("DES")',
            'MessageDigest.getInstance("MD5")',
        ],
    },
    "CWE-918": {
        "name": "Server-Side Request Forgery",
        "severity": "high",
        "patterns": [
            "requests.get(user_url)",
            "urllib.request.urlopen(url)",
            "fetch(req.body.url)",
            "http.Get(userURL)",
            "HttpClient.Get(untrustedUrl)",
        ],
    },
    "CWE-79": {
        "name": "Cross-Site Scripting",
        "severity": "high",
        "patterns": [
            "element.innerHTML = userInput",
            "document.write(req.body.content)",
            'res.send("<html>" + userContent + "</html>")',
            "dangerouslySetInnerHTML={{ __html: userHtml }}",
        ],
    },
    "CWE-798": {
        "name": "Hardcoded Credentials",
        "severity": "high",
        "patterns": [
            'password = "admin123"',
            'API_KEY = "sk-prod-abcdef123456"',
            'db_password = "P@ssw0rd!"',
            'secret_key = "hardcoded-jwt-secret-do-not-use"',
        ],
    },
    "CWE-611": {
        "name": "XML External Entity Injection",
        "severity": "high",
        "patterns": [
            "ET.parse(user_xml)",
            "lxml.etree.fromstring(xml_input)",
            "DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(userInput)",
        ],
    },
}

# ── Sink regex table (C) ────────────────────────────────────────────────────
# Per-CWE regex of known dangerous call-sites. Matching a sink pinpoints the
# exact line, which beats embedding similarity for precision.

SINK_REGEX: dict[str, re.Pattern] = {
    "CWE-94": re.compile(
        r"\b(exec|eval|Function|compile|r_core_call_str_at|vm\.runInNewContext|"
        r"setTimeout\s*\(\s*['\"]|new\s+Function)\s*\(",
    ),
    "CWE-78": re.compile(
        r"\b(os\.system|subprocess\.(?:call|run|Popen|check_output)|os\.popen|"
        r"child_process\.(?:exec|execSync|spawn)|Runtime\.getRuntime\(\)\.exec|"
        r"exec\.Command|shell_exec|passthru|pcntl_exec|popen|execve|execvp)\s*\("
        r"|shell\s*=\s*True",
    ),
    "CWE-89": re.compile(
        r"\.(?:execute|executemany|query|prepare|raw)\s*\(|"
        r"\b(?:executeQuery|executeUpdate)\s*\(",
    ),
    "CWE-22": re.compile(
        r"\b(?:open|fopen|readFile|readFileSync|writeFile|writeFileSync|"
        r"FileInputStream|FileReader|ifstream|ofstream|path\.join)\s*\(",
    ),
    "CWE-502": re.compile(
        r"\b(?:pickle\.loads?|cPickle\.loads?|yaml\.load|Marshal\.load|"
        r"ObjectInputStream|unserialize|jsonpickle\.decode)\s*\(",
    ),
    "CWE-327": re.compile(
        r"\bhashlib\.(?:md5|sha1)\s*\(|\bDES\.(?:new|Cipher)|"
        r"MessageDigest\.getInstance\s*\(\s*['\"](?:MD5|SHA-?1)['\"]",
    ),
    "CWE-918": re.compile(
        r"\b(?:requests\.(?:get|post|put|delete)|urllib\.request\.urlopen|"
        r"urlopen|fetch|http\.Get|HttpClient\.Get|axios\.(?:get|post))\s*\(",
    ),
    "CWE-79": re.compile(
        r"\binnerHTML\s*=|document\.write\s*\(|dangerouslySetInnerHTML|"
        r"\$\(\s*[^)]+\)\.html\s*\(",
    ),
    "CWE-611": re.compile(
        r"\b(?:ET\.parse|lxml\.etree\.(?:parse|fromstring)|"
        r"DocumentBuilderFactory|XMLReader)\s*\(",
    ),
}


def _find_sink_line(cwe: str, lines: list[str], win_start: int, win_end: int) -> Optional[int]:
    """Return 1-indexed line of the first regex sink match inside the window,
    or None. window bounds are 1-indexed inclusive."""
    pat = SINK_REGEX.get(cwe)
    if pat is None:
        return None
    lo = max(0, win_start - 1)
    hi = min(len(lines), win_end)
    for i in range(lo, hi):
        if pat.search(lines[i]):
            return i + 1
    return None


# ── Prototype / labeled index ───────────────────────────────────────────────

THRESHOLD_HARDCODED = 0.80
# Retained for reference / future use when we have line-level CVEfixes
# embeddings. The kNN path currently biases every C function to sim≈0.99.
THRESHOLD_LABELED = 0.96
# Hybrid detection gate:
#   - A window is ALWAYS emitted if a known dangerous sink (per-CWE regex)
#     matches inside it — this is the high-precision signal we trust most.
#   - The similarity path is deliberately strict: CodeBERT max-sim alone
#     flooded Java files with CWE-94 FPs, so we require both very high
#     similarity to a curated prototype AND the GBDT to agree strongly.
GBDT_GATE_THRESHOLD = 0.70
CWE_CLASSIFY_THRESHOLD = 0.95
MIN_LINES_BETWEEN_SAME_CWE = 15
REFINE_CONTEXT = 1
REFINE_SPAN = 2
MAX_LABELED_PER_CWE = 200

_index_lock = threading.Lock()
_pattern_index: "list[dict] | None" = None
_index_source: str = "none"  # "labeled" | "hardcoded" | "none"
_gbdt_model = None
_gbdt_lock = threading.Lock()


def _build_hardcoded_index() -> list:
    index = []
    for cwe, info in VULN_PATTERNS.items():
        vecs = embedder.embed_batch(info["patterns"])
        if vecs is None:
            continue
        normed = []
        for v in vecs:
            n = np.linalg.norm(v)
            if n > 0:
                normed.append(v / n)
        if not normed:
            continue
        index.append({
            "cwe": cwe,
            "name": info["name"],
            "severity": info["severity"],
            "pattern_vecs": np.asarray(normed, dtype=np.float32),
        })
    return index


def _build_labeled_index() -> list:
    """Load TP embeddings from feedback.db, group by rule_id (== CWE when
    available). Returns [] if DB is missing or has no usable samples."""
    if not DB_PATH.exists():
        return []
    try:
        conn = sqlite3.connect(str(DB_PATH))
        rows = conn.execute(
            "SELECT rule_id, feature_vector FROM findings "
            "WHERE label = 'tp' AND feature_vector IS NOT NULL AND rule_id LIKE 'CWE-%'"
        ).fetchall()
        conn.close()
    except Exception as e:
        logger.warning("failed to load labeled index: %s", e)
        return []

    buckets: dict[str, list[np.ndarray]] = {}
    for rule_id, fv_bytes in rows:
        if not fv_bytes:
            continue
        fv = np.frombuffer(fv_bytes, dtype="<f4")
        if fv.shape[0] != 768:
            continue
        n = np.linalg.norm(fv)
        if n == 0:
            continue
        buckets.setdefault(rule_id, []).append(fv / n)

    index = []
    for cwe, vecs in buckets.items():
        if len(vecs) < 2:  # need at least a couple to be meaningful
            continue
        if len(vecs) > MAX_LABELED_PER_CWE:
            # Deterministic subsample to keep matrix size bounded
            step = len(vecs) // MAX_LABELED_PER_CWE
            vecs = vecs[::step][:MAX_LABELED_PER_CWE]
        meta = VULN_PATTERNS.get(cwe, {})
        index.append({
            "cwe": cwe,
            "name": meta.get("name", cwe),
            "severity": meta.get("severity", "medium"),
            "pattern_vecs": np.asarray(vecs, dtype=np.float32),
        })
    return index


def _get_index() -> "list[dict] | None":
    """Primary pattern index for CWE detection. We deliberately use the
    hardcoded, line-level prototypes here rather than the labeled kNN index:
    CVEfixes stores whole-method embeddings, which makes any C function look
    "similar" to any vulnerable C function, producing noisy sim≈0.99 matches
    across unrelated CWEs. The labeled data is better used for GBDT scoring
    (method-level TP vs FP), not for initial CWE categorisation."""
    global _pattern_index, _index_source
    with _index_lock:
        if _pattern_index is not None:
            return _pattern_index
        if not embedder.is_ready():
            return None
        _pattern_index = _build_hardcoded_index()
        _index_source = "hardcoded"
        logger.info(
            "pattern index built",
            extra={"cwes": len(_pattern_index), "source": "hardcoded"},
        )
        return _pattern_index


def reset_index() -> None:
    """Force rebuild next call to _get_index(). Hook for /train completion."""
    global _pattern_index, _index_source
    with _index_lock:
        _pattern_index = None
        _index_source = "none"
    reset_gbdt()


def index_source() -> str:
    return _index_source


def _load_gbdt():
    """Lazy-load the GBDT model used to gate detections. Returns None if
    the model hasn't been trained yet."""
    global _gbdt_model
    with _gbdt_lock:
        if _gbdt_model is not None:
            return _gbdt_model
        if not MODEL_PATH.exists():
            return None
        try:
            import xgboost as xgb
            m = xgb.XGBClassifier()
            m.load_model(str(MODEL_PATH))
            _gbdt_model = m
            logger.info("GBDT loaded for analyzer gating")
            return m
        except Exception as e:
            logger.warning("failed to load GBDT: %s", e)
            return None


def reset_gbdt() -> None:
    global _gbdt_model
    with _gbdt_lock:
        _gbdt_model = None


def _get_cwe_index() -> "list[dict] | None":
    """Index used for CWE classification of windows. We stick with the
    hardcoded curated prototypes (~10 CWEs) rather than the labeled
    CVEfixes index: labeled has 40+ CWE buckets with whole-function
    embeddings, and any C-ish function finds a high-similarity nearest
    bucket regardless of actual vulnerability — producing CWE-347/79/etc
    FPs across unrelated code."""
    return _get_index()


# ── Language detection + chunking ───────────────────────────────────────────

def _detect_language(code: str, hint: Optional[str]) -> str:
    if hint and hint.lower() not in ("auto", "unknown", ""):
        return hint.lower()
    if "def " in code and ("import " in code or "from " in code):
        return "python"
    if "fn " in code and ("let " in code or "pub " in code or "use " in code):
        return "rust"
    if "func " in code and "package " in code:
        return "go"
    if "public class " in code or "import java." in code:
        return "java"
    if "function " in code or "const " in code or "=>" in code:
        return "javascript"
    return "unknown"


def _chunks(lines: list, window: int = 20, stride: int = 10):
    n = len(lines)
    for start in range(0, n, stride):
        end = min(start + window, n)
        yield start + 1, end, "\n".join(lines[start:end])


def _embed_lines(lines: list[str]) -> "np.ndarray | None":
    snippets = []
    for i in range(len(lines)):
        s = max(0, i - REFINE_CONTEXT)
        e = min(len(lines), i + REFINE_CONTEXT + 1)
        snippets.append("\n".join(lines[s:e]))
    vecs = embedder.embed_batch(snippets)
    if vecs is None or len(vecs) == 0:
        return None
    vecs = np.asarray(vecs, dtype=np.float32)
    norms = np.linalg.norm(vecs, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    return vecs / norms


def _refine_range(
    line_vecs: "np.ndarray | None",
    pattern_vecs: np.ndarray,
    window_start: int,
    window_end: int,
    cwe: str,
    lines: list[str],
) -> tuple[int, int, float, str]:
    """Narrow a window-level match to a tight range. Returns
    (start, end, peak_score, refinement_method).

    Preference order:
      1. Regex sink match inside the window → exact line ± REFINE_SPAN
      2. Embedding peak line ± REFINE_SPAN
      3. Whole window (last resort when neither signal is available)
    """
    sink_line = _find_sink_line(cwe, lines, window_start, window_end)
    if sink_line is not None:
        s = max(window_start, sink_line - REFINE_SPAN)
        e = min(window_end, sink_line + REFINE_SPAN)
        return s, e, 1.0, "sink_regex"

    if line_vecs is not None:
        lo = window_start - 1
        hi = min(window_end, len(line_vecs))
        if lo < hi:
            window = line_vecs[lo:hi]
            sims = (pattern_vecs @ window.T).max(axis=0)
            peak_idx = int(sims.argmax())
            peak = float(sims[peak_idx])
            s = max(0, peak_idx - REFINE_SPAN)
            e = min(len(sims) - 1, peak_idx + REFINE_SPAN)
            return window_start + s, window_start + e, peak, "embedding_peak"

    return window_start, window_end, 0.0, "window"


# ── Public entry point ──────────────────────────────────────────────────────

def _classify_cwe(
    unit_vec: np.ndarray, index: "list[dict] | None"
) -> "tuple[dict | None, float]":
    """Among the CWE clusters in `index`, pick the one whose pattern set is
    most similar to `unit_vec`. Returns (entry, similarity)."""
    if not index:
        return None, 0.0
    best_entry, best_sim = None, 0.0
    for entry in index:
        sims = entry["pattern_vecs"] @ unit_vec
        sim = float(sims.max())
        if sim > best_sim:
            best_entry, best_sim = entry, sim
    return best_entry, best_sim


def _any_sink_hit(lines: list[str], win_start: int, win_end: int) -> Optional[tuple[str, int]]:
    """Return (cwe, line_no) of the first sink regex hit in the window,
    across every CWE we track — or None."""
    for cwe in SINK_REGEX:
        line_no = _find_sink_line(cwe, lines, win_start, win_end)
        if line_no is not None:
            return cwe, line_no
    return None


def _analyze_gbdt_first(
    code: str, lang: str, gbdt, cwe_index: list[dict]
) -> dict:
    """Hybrid detection:
      • a window is emitted if any CWE sink regex matches inside it
        (ground truth — GBDT not consulted);
      • otherwise the window must pass CWE_CLASSIFY_THRESHOLD on similarity
        AND GBDT_GATE_THRESHOLD on the trained model."""
    lines = code.splitlines()
    if not lines:
        return {"status": "ready", "language_detected": lang, "findings": [], "mode": "gbdt-first"}

    line_vecs = _embed_lines(lines)

    windows: list[tuple[int, int, str]] = []
    chunks_list: list[str] = []
    for line_start, line_end, chunk in _chunks(lines):
        if len(chunk.strip()) < 30:
            continue
        windows.append((line_start, line_end, chunk))
        chunks_list.append(chunk)

    if not chunks_list:
        return {"status": "ready", "language_detected": lang, "findings": [], "mode": "gbdt-first"}

    embs = embedder.embed_batch(chunks_list)
    if embs is None or len(embs) == 0:
        return {"status": "ready", "language_detected": lang, "findings": [], "mode": "gbdt-first"}
    embs = np.asarray(embs, dtype=np.float32)

    try:
        probs = gbdt.predict_proba(embs)[:, 1]
    except Exception as e:
        logger.warning("GBDT predict failed, falling back: %s", e)
        return _analyze_legacy(code, lang)

    findings = []
    last_reported: dict[str, int] = {}

    for (line_start, line_end, _chunk), emb, prob in zip(windows, embs, probs):
        prob = float(prob)
        norm = float(np.linalg.norm(emb))
        if norm == 0:
            continue
        unit_vec = emb / norm

        sink_hit = _any_sink_hit(lines, line_start, line_end)
        gate_reason: str

        if sink_hit is not None:
            cwe, _sink_line = sink_hit
            best_entry = next(
                (e for e in cwe_index if e["cwe"] == cwe),
                VULN_PATTERNS.get(cwe) and {
                    "cwe": cwe,
                    "name": VULN_PATTERNS[cwe]["name"],
                    "severity": VULN_PATTERNS[cwe]["severity"],
                    # No pattern_vecs needed — sink regex drives the refine.
                    "pattern_vecs": np.zeros((1, 768), dtype=np.float32),
                },
            )
            if best_entry is None:
                continue
            cwe_sim = 1.0  # sink match is ground truth
            gate_reason = "sink"
        else:
            best_entry, cwe_sim = _classify_cwe(unit_vec, cwe_index)
            if best_entry is None or cwe_sim < CWE_CLASSIFY_THRESHOLD:
                continue
            if prob < GBDT_GATE_THRESHOLD:
                continue
            cwe = best_entry["cwe"]
            gate_reason = "sim+gbdt"

        if line_start - last_reported.get(cwe, -999) < MIN_LINES_BETWEEN_SAME_CWE:
            continue

        refined_start, refined_end, _peak, method = _refine_range(
            line_vecs, best_entry["pattern_vecs"],
            line_start, line_end, cwe, lines,
        )

        last_reported[cwe] = refined_start
        snippet_lines = lines[refined_start - 1 : refined_end]
        findings.append({
            "rule_id": f"ML-{cwe.replace('-', '')}",
            "message": (
                f"{best_entry.get('name', cwe)} "
                f"(gate={gate_reason}, gbdt={prob:.2f}, cwe_sim={cwe_sim:.2f}, via {method})"
            ),
            "severity": best_entry.get("severity", "medium"),
            "line_start": refined_start,
            "line_end": refined_end,
            "code_snippet": "\n".join(snippet_lines)[:400],
            "confidence": round(prob if gate_reason != "sink" else max(prob, 0.75), 3),
            "cwe": cwe,
            "refined_by": method,
            "gate": gate_reason,
        })

    return {
        "status": "ready",
        "language_detected": lang,
        "findings": findings,
        "mode": "hybrid-gbdt-first",
    }


def _analyze_legacy(code: str, lang: str) -> dict:
    """Similarity-first detection — used as a fallback when the GBDT model
    is not yet trained. This was the previous default behaviour."""
    index = _get_index()
    if not index:
        return {"status": "loading", "language_detected": lang, "findings": []}

    threshold = THRESHOLD_HARDCODED
    lines = code.splitlines()
    line_vecs = _embed_lines(lines) if lines else None
    findings = []
    last_reported: dict[str, int] = {}

    for line_start, line_end, chunk in _chunks(lines):
        if len(chunk.strip()) < 30:
            continue
        vec = embedder.embed(chunk)
        if vec is None:
            continue
        norm = np.linalg.norm(vec)
        if norm == 0:
            continue
        vec = vec / norm

        best_entry, best_sim = _classify_cwe(vec, index)
        if best_entry is None or best_sim < threshold:
            continue

        cwe = best_entry["cwe"]
        if line_start - last_reported.get(cwe, -999) < MIN_LINES_BETWEEN_SAME_CWE:
            continue

        refined_start, refined_end, _peak, method = _refine_range(
            line_vecs, best_entry["pattern_vecs"],
            line_start, line_end, cwe, lines,
        )
        last_reported[cwe] = refined_start
        snippet_lines = lines[refined_start - 1 : refined_end]
        findings.append({
            "rule_id": f"ML-{cwe.replace('-', '')}",
            "message": f"{best_entry['name']} (semantic match, sim={best_sim:.2f}, via {method})",
            "severity": best_entry["severity"],
            "line_start": refined_start,
            "line_end": refined_end,
            "code_snippet": "\n".join(snippet_lines)[:400],
            "confidence": round(best_sim, 3),
            "cwe": cwe,
            "refined_by": method,
        })

    return {
        "status": "ready",
        "language_detected": lang,
        "findings": findings,
        "mode": "similarity-first",
    }


def analyze(code: str, language: Optional[str] = None) -> dict:
    lang = _detect_language(code, language)

    if not embedder.is_ready():
        return {"status": embedder.status(), "language_detected": lang, "findings": []}

    gbdt = _load_gbdt()
    if gbdt is None:
        # No trained model yet — fall back to hardcoded-prototype similarity.
        return _analyze_legacy(code, lang)

    cwe_index = _get_cwe_index()
    if not cwe_index:
        return {"status": "loading", "language_detected": lang, "findings": []}

    return _analyze_gbdt_first(code, lang, gbdt, cwe_index)
