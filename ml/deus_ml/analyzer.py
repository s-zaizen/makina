"""Language-agnostic vulnerability analyzer using code embeddings."""
from typing import Optional
import numpy as np
from . import embedder

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

THRESHOLD = 0.80
MIN_LINES_BETWEEN_SAME_CWE = 15
# After a window matches, re-score each line inside it and return a tight
# range around the hottest line. This narrows "Lines 1-20" to ~5 lines
# pointing at the actual sink.
REFINE_CONTEXT = 1  # lines of context used per-line during refinement embedding
REFINE_SPAN = 2     # lines to keep on either side of the peak line

_pattern_index: "list[dict] | None" = None


def _build_index() -> list:
    index = []
    for cwe, info in VULN_PATTERNS.items():
        vecs = embedder.embed_batch(info["patterns"])
        if vecs is None:
            continue
        # Normalize each pattern vector individually (per-pattern matching)
        normed = []
        for v in vecs:
            n = np.linalg.norm(v)
            if n > 0:
                normed.append(v / n)
        if not normed:
            continue
        index.append(
            {
                "cwe": cwe,
                "name": info["name"],
                "severity": info["severity"],
                "pattern_vecs": np.array(normed),  # shape (N, 768)
            }
        )
    return index


def _get_index() -> "list[dict] | None":
    global _pattern_index
    if _pattern_index is not None:
        return _pattern_index
    if not embedder.is_ready():
        return None
    _pattern_index = _build_index()
    return _pattern_index


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


def _cosine(a: np.ndarray, b: np.ndarray) -> float:
    na, nb = np.linalg.norm(a), np.linalg.norm(b)
    if na == 0 or nb == 0:
        return 0.0
    return float(np.dot(a, b) / (na * nb))


def _embed_lines(lines: list[str]) -> "np.ndarray | None":
    """Embed each line (with ±REFINE_CONTEXT context) and return a normalized
    (N, 768) matrix — one row per source line. Returns None if the embedder
    fails or yields no vectors."""
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
) -> tuple[int, int, float]:
    """Within [window_start, window_end], locate the line with the highest
    similarity to the matched CWE patterns and return a REFINE_SPAN-wide
    range centered on it (clipped to the window)."""
    if line_vecs is None:
        return window_start, window_end, 0.0
    lo, hi = window_start - 1, min(window_end, len(line_vecs))
    if lo >= hi:
        return window_start, window_end, 0.0
    window = line_vecs[lo:hi]
    sims = (pattern_vecs @ window.T).max(axis=0)
    peak_idx = int(sims.argmax())
    peak = float(sims[peak_idx])
    s = max(0, peak_idx - REFINE_SPAN)
    e = min(len(sims) - 1, peak_idx + REFINE_SPAN)
    return window_start + s, window_start + e, peak


def analyze(code: str, language: Optional[str] = None) -> dict:
    lang = _detect_language(code, language)

    if not embedder.is_ready():
        return {"status": embedder.status(), "language_detected": lang, "findings": []}

    index = _get_index()
    if not index:
        return {"status": "loading", "language_detected": lang, "findings": []}

    lines = code.splitlines()
    line_vecs = _embed_lines(lines) if lines else None
    findings = []
    last_reported: dict[str, int] = {}

    for line_start, line_end, chunk in _chunks(lines):
        if len(chunk.strip()) < 30:  # skip near-empty tail chunks
            continue
        vec = embedder.embed(chunk)
        if vec is None:
            continue
        norm = np.linalg.norm(vec)
        if norm == 0:
            continue
        vec = vec / norm

        best_sim, best_entry = 0.0, None
        for entry in index:
            sims = entry["pattern_vecs"] @ vec
            sim = float(sims.max())
            if sim > best_sim:
                best_sim, best_entry = sim, entry

        if best_entry is None or best_sim < THRESHOLD:
            continue

        cwe = best_entry["cwe"]
        if line_start - last_reported.get(cwe, -999) < MIN_LINES_BETWEEN_SAME_CWE:
            continue

        refined_start, refined_end, _peak = _refine_range(
            line_vecs, best_entry["pattern_vecs"], line_start, line_end
        )

        last_reported[cwe] = refined_start
        snippet_lines = lines[refined_start - 1 : refined_end]
        findings.append(
            {
                "rule_id": f"ML-{cwe.replace('-', '')}",
                "message": f"{best_entry['name']} (semantic match, sim={best_sim:.2f})",
                "severity": best_entry["severity"],
                "line_start": refined_start,
                "line_end": refined_end,
                "code_snippet": "\n".join(snippet_lines)[:400],
                "confidence": round(best_sim, 3),
                "cwe": cwe,
            }
        )

    return {"status": "ready", "language_detected": lang, "findings": findings}
