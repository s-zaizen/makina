"""Regression tests for the interprocedural taint engine.

Skipped when tree_sitter_languages isn't available (lightweight host
runs); inside the `ml` container the parser binaries are pre-bundled.
"""

from __future__ import annotations

import pytest

pytest.importorskip("tree_sitter_languages")

from makina_ml import taint_engine  # noqa: E402


def _findings(code: str, language: str) -> list[dict]:
    return taint_engine.analyze(code, language)["findings"]


# ── Python interprocedural source → wrapper → sink ───────────────────────────


def test_python_interprocedural_command_injection():
    code = """\
from flask import request
import os

def get_user_cmd():
    return request.args.get('cmd')

def run_command(cmd):
    os.system(cmd)

def handle_request():
    user_input = get_user_cmd()
    run_command(user_input)
    return "ok"
"""
    findings = _findings(code, "python")
    cwes = {f["cwe"] for f in findings}
    assert "CWE-78" in cwes, f"taint engine missed os.system sink: {findings}"


# ── JS arrow-function broker — regression for the recent fix ─────────────────


def test_javascript_arrow_function_broker_detected():
    code = """\
const { execSync } = require('child_process');

function readInput(req) {
  return req.query.cmd;
}

function shellRun(c) {
  execSync(c);
}

app.get('/run', (req, res) => {
  const c = readInput(req);
  shellRun(c);
});
"""
    findings = _findings(code, "javascript")
    assert any(f["cwe"] == "CWE-78" for f in findings), (
        f"arrow-function broker should be tracked: {findings}"
    )


# ── JS named-function regression baseline ────────────────────────────────────


def test_javascript_named_function_broker_detected():
    code = """\
const { execSync } = require('child_process');

function readInput(req) {
  return req.query.cmd;
}

function shellRun(c) {
  execSync(c);
}

function handler(req, res) {
  const c = readInput(req);
  shellRun(c);
}
"""
    findings = _findings(code, "javascript")
    assert any(f["cwe"] == "CWE-78" for f in findings)


# ── Go interprocedural ───────────────────────────────────────────────────────


def test_go_interprocedural_command_injection():
    code = """\
package main

import (
    "net/http"
    "os/exec"
)

func getCmd(r *http.Request) string {
    return r.FormValue("cmd")
}

func run(c string) {
    exec.Command("sh", "-c", c).Run()
}

func handler(w http.ResponseWriter, r *http.Request) {
    c := getCmd(r)
    run(c)
}
"""
    findings = _findings(code, "go")
    assert any(f["cwe"] == "CWE-78" for f in findings)


# ── Negative case: no source → no taint finding ─────────────────────────────


def test_no_source_means_no_taint_finding():
    code = """\
import os

def static_run():
    os.system("echo hello")
"""
    findings = _findings(code, "python")
    # Static commands are NOT tainted — taint engine must stay quiet.
    # (semgrep / analyzer may still flag them; that's not our concern here.)
    assert findings == []


# ── Unknown language is a no-op ──────────────────────────────────────────────


def test_unsupported_language_returns_empty():
    out = taint_engine.analyze("anything", "ada")
    assert out["findings"] == []
