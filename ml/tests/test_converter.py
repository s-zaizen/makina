"""Tests for the CVEfixes converter's pure helpers.

The converter lives under `ml/scripts/converters/` so it isn't part of
the `makina_ml` package; we import it via path.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

CONVERTER_PATH = Path(__file__).resolve().parents[1] / "scripts" / "converters" / "cvefixes.py"


@pytest.fixture(scope="module")
def cvefixes():
    # bulk_import.py is imported at the top of cvefixes.py; ensure
    # `ml/scripts/` is on sys.path before loading.
    scripts_root = CONVERTER_PATH.parent.parent
    if str(scripts_root) not in sys.path:
        sys.path.insert(0, str(scripts_root))
    spec = importlib.util.spec_from_file_location("cvefixes_under_test", CONVERTER_PATH)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ── _is_noise — drop trivial diff lines ──────────────────────────────────────


@pytest.mark.parametrize(
    "line,expected",
    [
        # Brace / blank / comment
        ("", True),
        ("   ", True),
        ("}", True),
        ("// foo", True),
        ("/* block */", True),
        ("# python comment", True),
        ("-- sql comment", True),
        # Trivial constant inits
        ("  unsigned int buffer_index = 0;", True),
        ("  i = 0;", True),
        ("  ptr = NULL;", True),
        ("  flag = false;", True),
        ("  count = 0L;", True),
        ("  bool done = false;", True),
        # Pure control flow
        ("  break;", True),
        ("  continue;", True),
        ("  goto out;", True),
        ("  return;", True),
        ("  return 0;", True),
        ("  return -1;", True),
        ("\treturn res;", True),
        ("  return ptr->next;", True),
        ("  return r, nil", True),
        # Substantive lines that must NOT be dropped
        ("  return execute(req);", False),
        ("  return foo(bar);", False),
        ("  if (sk_filter(sk, skb))", False),
        ("  result = compute(x, y);", False),
        ("  fields.appendChild(document.createTextNode(label));", False),
        ("  break_pipe(fd);", False),
        ("  std::string s = something();", False),
        ("  fd = -1;", False),
    ],
)
def test_is_noise(cvefixes, line: str, expected: bool):
    assert cvefixes._is_noise(line) is expected


# ── _should_skip_commit — keyword include/exclude gating ─────────────────────


@pytest.mark.parametrize(
    "msg,expected",
    [
        # Excluded — refactor / cleanup language dominates (exclude wins
        # over include even if a security keyword is also present).
        ("refactor: rename foo to bar", True),
        ("cleanup: remove unused imports", True),
        ("Bump version to 1.2.3", True),
        ("Merge branch 'feature'", True),
        ("typo in docs", True),
        ("Patch use-after-free in hash table cleanup", True),  # cleanup → drop
        # Kept — has security signal, no excluded keyword
        ("fix CVE-2024-1234: SQL injection in user lookup", False),
        ("Prevent buffer overflow when parsing input", False),
        ("Validate user input to escape XSS in render", False),
        ("Resolve auth bypass via crafted token", False),
        # No signal at all — drop (no security keyword)
        ("update README", True),
        ("", False),  # empty / None → keep (no signal to reject on)
        (None, False),
    ],
)
def test_should_skip_commit(cvefixes, msg, expected: bool):
    assert cvefixes._should_skip_commit(msg) is expected


# ── _should_skip_file — drop test/doc paths ──────────────────────────────────


@pytest.mark.parametrize(
    "filename,expected",
    [
        ("src/foo/bar.c", False),
        ("src/foo/test_something.py", True),
        ("tests/auth_test.go", True),
        ("docs/CHANGELOG.md", True),
        ("README.md", True),
        ("app/examples/demo.py", True),
        ("src/fixtures/input.json", True),
        ("kernel/auth.c", False),
        (None, False),
    ],
)
def test_should_skip_file(cvefixes, filename, expected: bool):
    assert cvefixes._should_skip_file(filename) is expected


# ── _to_method_ranges — projection + clustering ──────────────────────────────


def test_to_method_ranges_projects_and_clusters(cvefixes):
    # Method spans file lines 100..120. Diff touched file lines
    # 102, 103, 104 (one cluster) and 115 (another cluster). They project
    # onto method-relative coords 3..5 and 16.
    diff = [
        [102, "  vulnerable code"],
        [103, "  more vulnerable code"],
        [104, "  even more"],
        [115, "  another spot"],
        [200, "  outside the method — must be dropped"],
    ]
    ranges = cvefixes._to_method_ranges(
        diff, method_start=100, method_end=120, gap=2, drop_noise=False
    )
    assert ranges == [(3, 5), (16, 16)]


def test_to_method_ranges_drops_noise_when_flag_set(cvefixes):
    diff = [
        [10, "  real_call(x);"],
        [11, "  return 0;"],  # trivial flow → dropped under drop_noise
        [12, "}"],  # brace-only → dropped
    ]
    ranges = cvefixes._to_method_ranges(
        diff, method_start=10, method_end=20, gap=1, drop_noise=True
    )
    # Only line 10 (method-relative 1) remains.
    assert ranges == [(1, 1)]
