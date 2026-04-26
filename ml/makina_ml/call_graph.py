"""
Call graph extraction for call-graph-aware embeddings.

For Python we use the stdlib `ast` module for reliable parsing.
For other languages we fall back to regex-based heuristics.
The goal is not perfect analysis but richer embedding context
so CodeBERT can learn cross-function vulnerability patterns.
"""
import ast
import re
from typing import Optional


def extract_functions(code: str, language: str) -> dict:
    """
    Returns {func_name: {"source": str, "callees": list[str],
                          "line_start": int, "line_end": int}}
    """
    if language == "python":
        return _python_functions(code)
    if language in ("javascript", "typescript"):
        return _js_functions(code)
    if language == "go":
        return _go_functions(code)
    if language in ("java", "ruby", "rust", "c", "cpp"):
        return _generic_functions(code, language)
    return {}


def build_augmented_context(
    functions: dict,
    code: str,
    line_start: int,
    line_end: int,
    max_depth: int = 1,
) -> str:
    """
    Return embedding context = enclosing function source +
    source of called functions (up to max_depth hops).
    Falls back to ±4 lines if call graph is unavailable.
    """
    func = _find_enclosing(functions, line_start)
    if func is None:
        lines = code.splitlines()
        ctx_s = max(0, line_start - 4)
        ctx_e = min(len(lines), line_end + 3)
        return "\n".join(lines[ctx_s:ctx_e])

    parts = [func["source"]]
    seen = {func["name"]}
    queue = list(func["callees"])

    for _ in range(max_depth):
        next_q = []
        for callee in queue:
            if callee in seen or callee not in functions:
                continue
            seen.add(callee)
            callee_info = functions[callee]
            parts.append(f"\n# → {callee}:")
            parts.append(callee_info["source"])
            next_q.extend(callee_info["callees"])
        queue = next_q
        if not queue:
            break

    return "\n".join(parts)


def _find_enclosing(functions: dict, line: int) -> Optional[dict]:
    for name, info in functions.items():
        if info["line_start"] <= line <= info["line_end"]:
            return {**info, "name": name}
    return None


# ─── Python ──────────────────────────────────────────────────────────────────

def _python_functions(code: str) -> dict:
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return {}

    lines = code.splitlines()
    result = {}

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        callees: list[str] = []
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Name):
                    callees.append(child.func.id)
                elif isinstance(child.func, ast.Attribute):
                    callees.append(child.func.attr)

        src = "\n".join(lines[node.lineno - 1 : node.end_lineno])
        result[node.name] = {
            "source": src,
            "callees": list(dict.fromkeys(callees)),  # dedup, preserve order
            "line_start": node.lineno,
            "line_end": node.end_lineno,
        }

    return result


# ─── JavaScript / TypeScript ─────────────────────────────────────────────────

_JS_FUNC_RE = re.compile(
    r"(?:function\s+(\w+)\s*\(|"          # function foo(
    r"(?:const|let|var)\s+(\w+)\s*=\s*"   # const foo =
    r"(?:async\s+)?(?:function\s*\(|"     #   function( or
    r"\(.*?\)\s*=>))",                     #   (...) =>
)
_CALL_RE = re.compile(r"\b(\w+)\s*\(")


def _js_functions(code: str) -> dict:
    lines = code.splitlines()
    result: dict = {}
    i = 0
    while i < len(lines):
        m = _JS_FUNC_RE.match(lines[i].strip())
        if m:
            name = m.group(1) or m.group(2) or f"_anon_{i}"
            body_lines, depth = [lines[i]], lines[i].count("{") - lines[i].count("}")
            j = i + 1
            while j < len(lines) and (depth > 0 or j == i + 1):
                body_lines.append(lines[j])
                depth += lines[j].count("{") - lines[j].count("}")
                j += 1
            src = "\n".join(body_lines)
            callees = list(dict.fromkeys(
                c for c in _CALL_RE.findall(src)
                if c not in ("if", "for", "while", "switch", "catch")
            ))
            result[name] = {
                "source": src,
                "callees": callees,
                "line_start": i + 1,
                "line_end": j,
            }
            i = j
            continue
        i += 1
    return result


# ─── Go ──────────────────────────────────────────────────────────────────────

_GO_FUNC_RE = re.compile(r"^func\s+(?:\(\w+\s+\*?\w+\)\s+)?(\w+)\s*\(")


def _go_functions(code: str) -> dict:
    lines = code.splitlines()
    result: dict = {}
    i = 0
    while i < len(lines):
        m = _GO_FUNC_RE.match(lines[i])
        if m:
            name = m.group(1)
            body_lines = [lines[i]]
            depth = lines[i].count("{") - lines[i].count("}")
            j = i + 1
            while j < len(lines) and (depth > 0 or j == i + 1):
                body_lines.append(lines[j])
                depth += lines[j].count("{") - lines[j].count("}")
                j += 1
            src = "\n".join(body_lines)
            callees = list(dict.fromkeys(
                c for c in _CALL_RE.findall(src)
                if c not in ("if", "for", "range", "make", "len", "append")
            ))
            result[name] = {
                "source": src,
                "callees": callees,
                "line_start": i + 1,
                "line_end": j,
            }
            i = j
            continue
        i += 1
    return result


# ─── Generic (Java, Ruby, Rust, C, C++) ──────────────────────────────────────

_GENERIC_FUNC_RE = {
    "java":   re.compile(r"(?:public|private|protected|static|\s)+[\w<>\[\]]+\s+(\w+)\s*\("),
    "ruby":   re.compile(r"^\s*def\s+(\w+)"),
    "rust":   re.compile(r"^\s*(?:pub\s+)?fn\s+(\w+)"),
    "c":      re.compile(r"^(?:[\w\s\*]+)\s+(\w+)\s*\([^;]*\)\s*\{"),
    "cpp":    re.compile(r"^(?:[\w\s\*:~<>]+)\s+(\w+)\s*\([^;]*\)\s*(?:const\s*)?\{"),
}


def _generic_functions(code: str, language: str) -> dict:
    pat = _GENERIC_FUNC_RE.get(language)
    if not pat:
        return {}
    lines = code.splitlines()
    result: dict = {}
    i = 0
    end_marker = "end" if language == "ruby" else None

    while i < len(lines):
        m = pat.match(lines[i])
        if m:
            name = m.group(1)
            body_lines = [lines[i]]
            if end_marker:
                j = i + 1
                depth = 1
                while j < len(lines):
                    body_lines.append(lines[j])
                    if re.match(r"^\s*def\s+", lines[j]):
                        depth += 1
                    if re.match(r"^\s*end\b", lines[j]):
                        depth -= 1
                        if depth == 0:
                            j += 1
                            break
                    j += 1
            else:
                depth = lines[i].count("{") - lines[i].count("}")
                j = i + 1
                while j < len(lines) and (depth > 0 or j == i + 1):
                    body_lines.append(lines[j])
                    depth += lines[j].count("{") - lines[j].count("}")
                    j += 1
            src = "\n".join(body_lines)
            callees = list(dict.fromkeys(
                c for c in _CALL_RE.findall(src)
                if len(c) > 2
            ))
            result[name] = {
                "source": src,
                "callees": callees,
                "line_start": i + 1,
                "line_end": j,
            }
            i = j
            continue
        i += 1
    return result
