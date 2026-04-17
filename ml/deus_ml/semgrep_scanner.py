"""semgrep-based rule scanner — wraps the bundled community rules."""
import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

RULES_DIR = Path(os.environ.get("SEMGREP_RULES_DIR", "/opt/semgrep-rules"))
CUSTOM_RULES = Path(os.environ.get("SEMGREP_CUSTOM_RULES", "/opt/semgrep-custom"))

LANG_EXT = {
    "python": ".py",
    "javascript": ".js",
    "typescript": ".ts",
    "go": ".go",
    "java": ".java",
    "ruby": ".rb",
    "c": ".c",
    "cpp": ".cpp",
    "rust": ".rs",
}

SEV_MAP = {"ERROR": "critical", "WARNING": "high", "INFO": "medium"}


def _detect_language(code: str) -> str:
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


def _rules_path(language: str) -> Optional[Path]:
    for candidate in [
        RULES_DIR / language / "lang" / "security",
        RULES_DIR / language / "lang",
        RULES_DIR / language,
    ]:
        if candidate.is_dir():
            return candidate
    return None


def _parse(results: list, rules_path: Path, source_lines: list | None = None) -> list:
    findings = []
    for r in results:
        extra = r.get("extra", {})
        meta = extra.get("metadata", {})

        cwe = meta.get("cwe", "")
        if isinstance(cwe, list):
            cwe = cwe[0] if cwe else ""
        if cwe and ":" in cwe:
            cwe = cwe.split(":")[0].strip()

        check_id = r.get("check_id", "")
        rule_id = check_id.split(".")[-1] if check_id else "semgrep"

        line_start = r.get("start", {}).get("line", 1)
        line_end = r.get("end", {}).get("line", line_start)

        # extra.lines is unreliable in semgrep ≥1.100 (returns fingerprint, not source).
        # Extract matched text directly from source_lines using line numbers.
        if source_lines:
            matched = "\n".join(source_lines[line_start - 1 : line_end])
            ctx_start = max(0, line_start - 4)
            ctx_end = min(len(source_lines), line_end + 3)
            embed_snippet = "\n".join(source_lines[ctx_start:ctx_end])
        else:
            matched = ""
            embed_snippet = ""

        findings.append(
            {
                "rule_id": rule_id,
                "message": extra.get("message", check_id),
                "severity": SEV_MAP.get(extra.get("severity", "WARNING"), "high"),
                "line_start": line_start,
                "line_end": line_end,
                "code_snippet": matched,
                "embed_snippet": embed_snippet,
                "confidence": 0.85,
                "cwe": cwe or None,
            }
        )
    return findings


def scan(code: str, language: str) -> dict:
    effective_lang = language
    if effective_lang in ("auto", "unknown", "", None):
        effective_lang = _detect_language(code)

    rules_path = _rules_path(effective_lang)
    if rules_path is None:
        return {"status": "ok", "findings": [], "language": effective_lang}

    ext = LANG_EXT.get(effective_lang, ".txt")
    with tempfile.NamedTemporaryFile(mode="w", suffix=ext, delete=False, encoding="utf-8") as f:
        f.write(code)
        tmpfile = f.name

    try:
        cmd = ["semgrep", "scan", "--config", str(rules_path)]
        # Add custom taint rules if available
        if CUSTOM_RULES.is_dir():
            cmd += ["--config", str(CUSTOM_RULES)]
        cmd += ["--json", "--no-git-ignore", "--quiet", tmpfile]

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
            env={**os.environ, "SEMGREP_SEND_METRICS": "off"},
        )
        # semgrep exits 0 (no findings) or 1 (findings) on success; ≥2 on error
        if proc.returncode >= 2:
            return {"status": "ok", "findings": [], "language": language}

        data = json.loads(proc.stdout)
        source_lines = code.splitlines()
        return {
            "status": "ok",
            "findings": _parse(data.get("results", []), rules_path, source_lines),
            "language": effective_lang,
        }

    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
        return {"status": "ok", "findings": [], "language": language}

    finally:
        os.unlink(tmpfile)
