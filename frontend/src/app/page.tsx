"use client";
import { useState, useCallback, useEffect } from "react";
import { CodeEditor } from "../components/CodeEditor";
import { FileTree } from "../components/FileTree";
import { FindingCard } from "../components/FindingCard";
import { KnowledgeTab } from "../components/KnowledgeTab";
import { ScanPanel } from "../components/ScanPanel";
import { StatusBar } from "../components/StatusBar";
import { VerifyTab } from "../components/VerifyTab";
import { scanCode, submitFeedback, getStats, getVerifyQueue, addToVerifyQueue, removeFromVerifyQueue } from "../lib/api";
import { readFolder, flatFiles } from "../lib/folder";
import type { Finding, Language, Label, Stats, Severity, VerifyCase, VerifiedEntry, FileNode } from "../lib/types";

type Tab = "scan" | "verify" | "knowledge";

const PLACEHOLDERS: Record<Language, string> = {
  auto: `# Paste any code here — deus will auto-detect the language
import os
def run(cmd):
    os.system(cmd)
`,
  python: `import os
import pickle
import hashlib

def login(username, password):
    pw_hash = hashlib.md5(password.encode()).hexdigest()
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{pw_hash}'"
    cursor.execute(query)
    return cursor.fetchone()

def run_command(user_input):
    os.system(f"echo {user_input}")

def load_data(filename):
    with open(f"/data/{filename}", "rb") as f:
        return pickle.loads(f.read())
`,
  rust: `use std::process::Command;

fn run_user_command(user_input: &str) {
    Command::new("sh")
        .arg("-c")
        .arg(user_input)
        .output()
        .unwrap();
}

fn parse_number(s: &str) -> i32 {
    s.parse().unwrap()
}

unsafe fn raw_operations(ptr: *mut u8) {
    *ptr = 42;
}
`,
  javascript: `const express = require('express');
const { exec } = require('child_process');
const db = require('./db');

app.get('/user', (req, res) => {
    const id = req.query.id;
    db.query("SELECT * FROM users WHERE id=" + id, (err, rows) => {
        res.json(rows);
    });
});

app.post('/ping', (req, res) => {
    exec("ping " + req.body.host, (err, stdout) => {
        res.send(stdout);
    });
});

app.get('/file', (req, res) => {
    res.sendFile('/uploads/' + req.query.name);
});
`,
  typescript: `import express from 'express';
import fetch from 'node-fetch';

const app = express();

app.post('/proxy', async (req, res) => {
    const url = req.body.url;
    const result = await fetch(url);
    res.json(await result.json());
});

app.get('/render', (req, res) => {
    const content = req.query.content as string;
    res.send(\`<html><body>\${content}</body></html>\`);
});
`,
  go: `package main

import (
    "database/sql"
    "net/http"
    "os/exec"
)

func getUser(db *sql.DB, name string) {
    rows, _ := db.Query("SELECT * FROM users WHERE name='" + name + "'")
    defer rows.Close()
}

func runCmd(w http.ResponseWriter, r *http.Request) {
    cmd := r.URL.Query().Get("cmd")
    out, _ := exec.Command("sh", "-c", cmd).Output()
    w.Write(out)
}
`,
  java: `import java.sql.*;
import java.io.*;

public class UserService {
    public User getUser(String name) throws SQLException {
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(
            "SELECT * FROM users WHERE name='" + name + "'"
        );
        return mapUser(rs);
    }

    public void runCommand(String input) throws IOException {
        Runtime.getRuntime().exec("sh -c " + input);
    }
}
`,
  ruby: `require 'sqlite3'
require 'open3'

class UserController
  def find_user(name)
    db = SQLite3::Database.new 'app.db'
    db.execute("SELECT * FROM users WHERE name = '\#{name}'")
  end

  def run_report(host)
    Open3.capture2("ping \#{host}")
  end

  def load_session(data)
    Marshal.load(data)
  end
end
`,
  c: `#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void run_command(char *user_input) {
    char cmd[256];
    sprintf(cmd, "echo %s", user_input);
    system(cmd);
}

void read_file(char *filename) {
    char path[128];
    strcpy(path, "/data/");
    strcat(path, filename);
    FILE *f = fopen(path, "r");
}
`,
  cpp: `#include <iostream>
#include <cstdlib>
#include <string>

void execute(const std::string& userInput) {
    std::string cmd = "ls " + userInput;
    system(cmd.c_str());
}

char* getBuffer(int size) {
    char* buf = new char[size];
    return buf;
}
`,
};

export default function Home() {
  const [activeTab, setActiveTab]   = useState<Tab>("scan");
  const [language, setLanguage]     = useState<Language>("python");
  const [code, setCode]             = useState(PLACEHOLDERS.python);
  const [findings, setFindings]     = useState<Finding[]>([]);
  const [scanning, setScanning]     = useState(false);
  const [stats, setStats]           = useState<Stats | null>(null);
  const [error, setError]           = useState<string | null>(null);
  const [focusedFindingId, setFocusedFindingId] = useState<string | null>(null);

  const [verifyCases, setVerifyCases]           = useState<VerifyCase[]>([]);
  const [knowledgeHistory, setKnowledgeHistory] = useState<VerifiedEntry[]>([]);

  // Folder mode
  const [folderRoot, setFolderRoot]           = useState<FileNode | null>(null);
  const [selectedFile, setSelectedFile]       = useState<FileNode | null>(null);
  const [scannedPaths, setScannedPaths]       = useState<Set<string>>(new Set());
  const [scanProgress, setScanProgress]       = useState<{ current: number; total: number } | null>(null);

  const focusedFinding = findings.find((f) => f.id === focusedFindingId);
  const focusedLine = focusedFinding?.line_start ?? null;

  const refreshStats = useCallback(async () => {
    try { setStats(await getStats()); } catch { /* backend not running */ }
  }, []);

  useEffect(() => {
    refreshStats();
    getVerifyQueue().then(setVerifyCases).catch(() => {});
  }, [refreshStats]);

  const handleLanguageChange = (lang: Language) => {
    setLanguage(lang);
    setCode(PLACEHOLDERS[lang]);
    setFindings([]);
    setFocusedFindingId(null);
  };

  const handleScan = async () => {
    setScanning(true);
    setError(null);
    setFocusedFindingId(null);
    try {
      const result = await scanCode(code, language);
      setFindings(result.findings);
    } catch {
      setError("Cannot connect to deus server. Run: ./compose up");
    } finally {
      setScanning(false);
    }
  };

  const handleSubmitToVerify = async () => {
    if (findings.length === 0) return;
    try {
      const newCase = await addToVerifyQueue(null, code, language, findings);
      setVerifyCases((prev) => [...prev, newCase]);
    } catch {
      const localCase: VerifyCase = {
        caseNo: Date.now(),
        code,
        language,
        findings: [...findings],
        submittedAt: new Date().toISOString(),
        labels: {},
      };
      setVerifyCases((prev) => [...prev, localCase]);
    }
    setFindings([]);
    setFocusedFindingId(null);
    setActiveTab("verify");
  };

  const handleCaseLabel = (caseNo: number, findingId: string, label: Label) => {
    setVerifyCases((prev) =>
      prev.map((vc) =>
        vc.caseNo === caseNo
          ? { ...vc, labels: { ...vc.labels, [findingId]: label } }
          : vc,
      ),
    );
  };

  const handleCaseSubmit = async (caseNo: number) => {
    const vc = verifyCases.find((c) => c.caseNo === caseNo);
    if (!vc) return;

    const labeledEntries = Object.entries(vc.labels);
    await Promise.all(labeledEntries.map(([id, lbl]) => submitFeedback(id, lbl)));

    const tpCount = labeledEntries.filter(([, l]) => l === "tp").length;
    const fpCount = labeledEntries.filter(([, l]) => l === "fp").length;
    const entry: VerifiedEntry = {
      caseNo: vc.caseNo,
      verifiedAt: new Date().toISOString(),
      language: vc.language,
      findingCount: vc.findings.length,
      tpCount,
      fpCount,
    };
    setKnowledgeHistory((prev) => [entry, ...prev]);
    setVerifyCases((prev) => prev.filter((c) => c.caseNo !== caseNo));
    try { await removeFromVerifyQueue(caseNo); } catch { /* non-critical */ }
    await refreshStats();
  };

  const handleFocusFinding = (id: string) => {
    setFocusedFindingId(id);
    setActiveTab("scan");
  };

  // Folder drop
  const handleFolderDrop = async (item: DataTransferItem) => {
    const root = await readFolder(item);
    if (!root) return;
    setFolderRoot(root);
    setScannedPaths(new Set());
    setScanProgress(null);
    // Auto-select first file
    const files = flatFiles(root);
    if (files.length > 0) handleSelectFile(files[0]);
  };

  const handleSelectFile = (node: FileNode) => {
    if (!node.content || !node.language) return;
    setSelectedFile(node);
    setCode(node.content);
    setLanguage(node.language);
    setFindings([]);
    setFocusedFindingId(null);
  };

  const handleScanAll = async () => {
    if (!folderRoot) return;
    const files = flatFiles(folderRoot);
    setScanProgress({ current: 0, total: files.length });
    const newScanned = new Set(scannedPaths);
    for (let i = 0; i < files.length; i++) {
      const f = files[i];
      if (!f.content || !f.language) continue;
      try {
        const result = await scanCode(f.content, f.language);
        if (result.findings.length > 0) {
          await addToVerifyQueue(null, f.content, f.language, result.findings)
            .then((c) => setVerifyCases((prev) => [...prev, c]))
            .catch(() => {});
        }
        newScanned.add(f.path);
        setScannedPaths(new Set(newScanned));
      } catch { /* continue */ }
      setScanProgress({ current: i + 1, total: files.length });
    }
    setScanProgress(null);
  };

  const handleClearFolder = () => {
    setFolderRoot(null);
    setSelectedFile(null);
    setScannedPaths(new Set());
    setScanProgress(null);
  };

  const verifyBadge = verifyCases.length > 0
    ? <span className="ml-1 text-[10px] font-bold bg-indigo-600/50 text-indigo-200 rounded-full px-1.5 py-0.5">{verifyCases.length}</span>
    : null;

  const currentFilename = selectedFile?.name;

  return (
    <div className="flex flex-col h-screen bg-gray-950 text-gray-100">

      {/* ── Header ─────────────────────────────────────────────────── */}
      <div className="flex items-center gap-3 h-11 px-4 bg-gray-900 border-b border-gray-800 shrink-0">
        <span className="text-sm font-bold text-gray-100 tracking-tight">deus</span>

        <div className="w-px h-4 bg-gray-700 mx-1" />

        {/* Tabs */}
        <nav className="flex items-center gap-1">
          {(["scan", "verify", "knowledge"] as Tab[]).map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={[
                "flex items-center px-3 py-1 rounded text-xs font-medium capitalize transition-all",
                activeTab === tab
                  ? "bg-indigo-600/30 text-indigo-300 border border-indigo-700/60"
                  : "text-gray-500 hover:text-gray-300 hover:bg-gray-800 border border-transparent",
              ].join(" ")}
            >
              {tab}
              {tab === "verify" && verifyBadge}
            </button>
          ))}
        </nav>

        {/* Scan controls — only on Scan tab */}
        {activeTab === "scan" && (
          <div className="ml-auto">
            <ScanPanel
              language={language}
              onLanguageChange={handleLanguageChange}
              onScan={handleScan}
              scanning={scanning}
              hasFindings={findings.length > 0}
              onSubmitToVerify={handleSubmitToVerify}
            />
          </div>
        )}
      </div>

      {/* ── Content ────────────────────────────────────────────────── */}
      {activeTab === "scan" && (
        <div className="flex flex-1 min-h-0">
          {/* File tree sidebar — only when folder is loaded */}
          {folderRoot && (
            <div className="hidden lg:flex w-52 xl:w-60 shrink-0 flex-col">
              <FileTree
                root={folderRoot}
                selectedPath={selectedFile?.path ?? null}
                scannedPaths={scannedPaths}
                scanProgress={scanProgress}
                onSelect={handleSelectFile}
                onScanAll={handleScanAll}
                onClear={handleClearFolder}
              />
            </div>
          )}

          {/* Editor */}
          <div className={`flex flex-col min-h-0 border-r border-gray-800/60 ${folderRoot ? "flex-1" : "w-full lg:w-3/5"}`}>
            <CodeEditor
              value={code}
              onChange={setCode}
              language={language}
              findings={findings}
              focusedLine={focusedLine}
              onFolderDrop={handleFolderDrop}
              filename={currentFilename}
            />
          </div>

          {/* Findings panel — hidden on small screens when no findings */}
          <div className={[
            "overflow-y-auto p-3 flex flex-col gap-2 bg-gray-950",
            folderRoot ? "hidden lg:flex w-72 xl:w-80 shrink-0" : "hidden lg:flex w-2/5",
          ].join(" ")}>
            {error && (
              <div className="bg-red-900/40 border border-red-800 rounded p-3 text-sm text-red-300">
                {error}
              </div>
            )}
            {findings.length === 0 && !error && (
              <div className="text-gray-600 text-xs text-center mt-10 space-y-1">
                <p>{scanning ? "Scanning…" : "Paste code and click Scan"}</p>
                {!folderRoot && (
                  <p className="text-gray-700">or drop a folder on the editor</p>
                )}
              </div>
            )}
            {findings.map((f) => (
              <FindingCard
                key={f.id}
                finding={f}
                language={language}
                onLabel={async (id, label) => { await submitFeedback(id, label); await refreshStats(); }}
                onFocus={() => handleFocusFinding(f.id)}
                focused={f.id === focusedFindingId}
              />
            ))}
          </div>
        </div>
      )}

      {activeTab === "verify" && (
        <VerifyTab
          cases={verifyCases}
          onLabel={handleCaseLabel}
          onSubmit={handleCaseSubmit}
        />
      )}

      {activeTab === "knowledge" && (
        <KnowledgeTab stats={stats} history={knowledgeHistory} />
      )}

      {/* ── Status bar ─────────────────────────────────────────────── */}
      <StatusBar stats={stats} />
    </div>
  );
}
