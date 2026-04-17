"""
Interprocedural taint engine using tree-sitter for function boundary detection.
Detects cross-function flows: source reads tainted input → calls func → sink executes it.

Two detection strategies:
1. BFS from source functions through their callees to find sinks.
2. Broker pattern: a function calls both a source function and a sink function.
"""
from __future__ import annotations
import re
from dataclasses import dataclass
from collections import deque

_CALL_RE = re.compile(r'\b([a-zA-Z_]\w*)\s*\(')

_KEYWORDS = frozenset({
    'if', 'for', 'while', 'switch', 'return', 'print', 'len', 'range',
    'isinstance', 'str', 'int', 'float', 'bool', 'list', 'dict', 'set',
    'tuple', 'True', 'False', 'None', 'type', 'repr', 'super', 'object',
    'map', 'filter', 'zip', 'sorted', 'reversed', 'enumerate',
    'hasattr', 'getattr', 'setattr', 'delattr', 'callable',
    'new', 'delete', 'typeof', 'instanceof',
    'make', 'append', 'copy', 'panic', 'recover', 'defer',
    'println', 'printf', 'sprintf', 'Println', 'Printf', 'Sprintf',
    'assert', 'raise', 'except', 'finally', 'with', 'lambda',
    'yield', 'async', 'await',
})

_TS_LANG_MAP = {
    "python": "python",
    "javascript": "javascript",
    "typescript": "typescript",
    "go": "go",
    "java": "java",
    "ruby": "ruby",
    "rust": "rust",
    "c": "c",
    "cpp": "cpp",
}

_FUNC_NODE_TYPES: dict[str, frozenset[str]] = {
    "python":     frozenset({"function_definition"}),
    "javascript": frozenset({"function_declaration", "function_expression", "method_definition"}),
    "typescript": frozenset({"function_declaration", "function_expression", "method_definition"}),
    "go":         frozenset({"function_declaration", "method_declaration"}),
    "java":       frozenset({"method_declaration", "constructor_declaration"}),
    "ruby":       frozenset({"method", "singleton_method"}),
    "rust":       frozenset({"function_item"}),
    "c":          frozenset({"function_definition"}),
    "cpp":        frozenset({"function_definition"}),
}


@dataclass
class SinkPattern:
    pattern: re.Pattern
    cwe: str
    message: str


@dataclass
class SourceConfig:
    patterns: list[re.Pattern]
    sinks: list[SinkPattern]


def _src(pats: list[str]) -> list[re.Pattern]:
    return [re.compile(p) for p in pats]


def _sinks(items: list[tuple[str, str, str]]) -> list[SinkPattern]:
    return [SinkPattern(re.compile(p), cwe, msg) for p, cwe, msg in items]


TAINT_CONFIGS: dict[str, SourceConfig] = {
    "python": SourceConfig(
        patterns=_src([
            r'\brequest\.args\b', r'\brequest\.form\b', r'\brequest\.json\b',
            r'\brequest\.data\b', r'\brequest\.get_json\s*\(',
            r'\binput\s*\(', r'\bsys\.stdin\b',
        ]),
        sinks=_sinks([
            (r'\.execute\s*\(',     "CWE-89",  "SQL Injection: tainted input flows into DB execute"),
            (r'\.executemany\s*\(', "CWE-89",  "SQL Injection: tainted input flows into DB executemany"),
            (r'\bos\.system\s*\(',  "CWE-78",  "Command Injection: tainted input flows into os.system"),
            (r'\bos\.popen\s*\(',   "CWE-78",  "Command Injection: tainted input flows into os.popen"),
            (r'\bsubprocess\.(run|call|Popen|check_output)\s*\(', "CWE-78",
             "Command Injection: tainted input flows into subprocess"),
            (r'\beval\s*\(',        "CWE-94",  "Code Injection: tainted input flows into eval"),
            (r'\bexec\s*\(',        "CWE-94",  "Code Injection: tainted input flows into exec"),
            (r'\bopen\s*\(',        "CWE-22",  "Path Traversal: tainted input flows into open"),
        ]),
    ),
    "javascript": SourceConfig(
        patterns=_src([
            r'\breq\.query\b', r'\breq\.body\b', r'\breq\.params\b',
            r'\brequest\.query\b', r'\brequest\.body\b',
        ]),
        sinks=_sinks([
            (r'\.query\s*\(',          "CWE-89", "SQL Injection: tainted input flows into DB query"),
            (r'\.execute\s*\(',        "CWE-89", "SQL Injection: tainted input flows into DB execute"),
            (r'\bexec\s*\(',           "CWE-78", "Command Injection: tainted input flows into exec"),
            (r'\bexecSync\s*\(',       "CWE-78", "Command Injection: tainted input flows into execSync"),
            (r'\beval\s*\(',           "CWE-94", "Code Injection: tainted input flows into eval"),
            (r'\.innerHTML\s*=',       "CWE-79", "XSS: tainted input assigned to innerHTML"),
            (r'\bdocument\.write\s*\(', "CWE-79", "XSS: tainted input written to document"),
        ]),
    ),
    "go": SourceConfig(
        patterns=_src([
            r'\bFormValue\s*\(', r'\bPostFormValue\s*\(',
            r'\.Query\(\)\.Get\s*\(', r'\.Header\.Get\s*\(',
        ]),
        sinks=_sinks([
            (r'\.Query\s*\(',        "CWE-89", "SQL Injection: tainted input flows into DB Query"),
            (r'\.QueryRow\s*\(',     "CWE-89", "SQL Injection: tainted input flows into DB QueryRow"),
            (r'\.Exec\s*\(',         "CWE-89", "SQL Injection: tainted input flows into DB Exec"),
            (r'\bexec\.Command\s*\(', "CWE-78", "Command Injection: tainted input flows into exec.Command"),
        ]),
    ),
}

TAINT_CONFIGS["typescript"] = TAINT_CONFIGS["javascript"]


# ─── Function extraction via tree-sitter ─────────────────────────────────────

def _extract_functions(code: str, language: str) -> dict:
    ts_lang = _TS_LANG_MAP.get(language)
    if not ts_lang:
        return {}

    try:
        from tree_sitter_languages import get_parser
        parser = get_parser(ts_lang)
    except Exception:
        return {}

    try:
        tree = parser.parse(code.encode('utf-8'))
    except Exception:
        return {}

    lines = code.splitlines()
    target_types = _FUNC_NODE_TYPES.get(language, frozenset())
    result: dict = {}

    stack = [tree.root_node]
    while stack:
        node = stack.pop()

        if node.type in target_types:
            name_node = node.child_by_field_name('name')
            if name_node is None:
                for child in node.children:
                    if child.type in ('identifier', 'property_identifier'):
                        name_node = child
                        break

            if name_node:
                name = name_node.text.decode('utf-8', errors='replace')
                start_line = node.start_point[0] + 1
                end_line = node.end_point[0] + 1
                src = '\n'.join(lines[start_line - 1 : end_line])

                callees = list(dict.fromkeys(
                    c for c in _CALL_RE.findall(src)
                    if c not in _KEYWORDS and len(c) > 2 and c != name
                ))

                result[name] = {
                    'source': src,
                    'callees': callees,
                    'line_start': start_line,
                    'line_end': end_line,
                }

        for child in reversed(node.children):
            stack.append(child)

    return result


# ─── Taint flow detection ─────────────────────────────────────────────────────

def _has_source(src: str, config: SourceConfig) -> bool:
    return any(p.search(src) for p in config.patterns)


def _matching_sinks(src: str, config: SourceConfig) -> list[SinkPattern]:
    return [s for s in config.sinks if s.pattern.search(src)]


def _find_taint_flows(functions: dict, config: SourceConfig) -> list[dict]:
    if not functions:
        return []

    func_has_source = {n: _has_source(i['source'], config) for n, i in functions.items()}
    func_sinks = {n: _matching_sinks(i['source'], config) for n, i in functions.items()}

    source_func_names = {n for n, v in func_has_source.items() if v}
    sink_func_names = {n for n, sinks in func_sinks.items() if sinks}

    findings = []
    seen_keys: set[tuple] = set()

    def record(source_name: str, sink_name: str, sink: SinkPattern, path: list[str]) -> None:
        key = (source_name, sink_name, sink.cwe)
        if key in seen_keys:
            return
        seen_keys.add(key)
        src_info = functions[source_name]
        snk_info = functions[sink_name]
        path_str = ' → '.join(dict.fromkeys(path))
        findings.append({
            'rule_id': f'taint-interproc-{sink.cwe.lower().replace("-", "")}',
            'message': f"{sink.message}. Taint path: {path_str}",
            'severity': 'high',
            'line_start': src_info['line_start'],
            'line_end': snk_info['line_end'],
            'code_snippet': (
                f"# Source in: {source_name}\n{src_info['source'][:400]}"
                f"\n# Sink in: {sink_name}\n{snk_info['source'][:400]}"
            ),
            'confidence': 0.75,
            'cwe': sink.cwe,
        })

    # Strategy 1: BFS from source functions through callees to find sinks.
    # Catches: source_func itself (or its callees) eventually calls a sink function.
    for start_name in source_func_names:
        q: deque[tuple[str, list[str]]] = deque([(start_name, [start_name])])
        visited: set[str] = {start_name}
        while q:
            cur_name, path = q.popleft()
            for callee in functions[cur_name]['callees']:
                if callee not in functions or callee in visited:
                    continue
                new_path = path + [callee]
                for sink in func_sinks[callee]:
                    record(start_name, callee, sink, new_path)
                visited.add(callee)
                q.append((callee, new_path))

    # Strategy 2: Broker pattern — a function calls both a source function and a sink function.
    # Catches: handle() calls get_user_input() [source func] and run_query() [sink func].
    for broker_name, broker_info in functions.items():
        callees_in_scope = [c for c in broker_info['callees'] if c in functions]
        src_callees = [c for c in callees_in_scope if c in source_func_names]
        snk_callees = [c for c in callees_in_scope if c in sink_func_names]
        if not src_callees or not snk_callees:
            continue
        for sc in src_callees:
            for sk in snk_callees:
                if sc == sk:
                    continue
                for sink in func_sinks[sk]:
                    record(sc, sk, sink, [sc, broker_name, sk])

    return findings


# ─── Public API ───────────────────────────────────────────────────────────────

def analyze(code: str, language: str) -> dict:
    config = TAINT_CONFIGS.get(language)
    if not config:
        return {"status": "ok", "findings": [], "language": language}

    functions = _extract_functions(code, language)
    findings = _find_taint_flows(functions, config)
    return {"status": "ok", "findings": findings, "language": language}
