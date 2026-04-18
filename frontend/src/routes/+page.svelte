<script lang="ts">
	import { onMount } from 'svelte';
	import { SvelteSet } from 'svelte/reactivity';
	import CodeEditor from '$lib/components/CodeEditor.svelte';
	import FileTree from '$lib/components/FileTree.svelte';
	import FindingCard from '$lib/components/FindingCard.svelte';
	import KnowledgeTab from '$lib/components/KnowledgeTab.svelte';
	import ScanPanel from '$lib/components/ScanPanel.svelte';
	import StatusBar from '$lib/components/StatusBar.svelte';
	import VerifyTab from '$lib/components/VerifyTab.svelte';
	import {
		scanCode,
		submitFeedback,
		getStats,
		getVerifyQueue,
		addToVerifyQueue,
		getKnowledgeHistory,
		submitToKnowledge
	} from '$lib/api';
	import { readFolder, flatFiles } from '$lib/folder';
	import type { Finding, Language, Label, Stats, VerifyCase, KnowledgeCase, FileNode } from '$lib/types';

	type Tab = 'scan' | 'verify' | 'knowledge';

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
		typescript: `${'import'} express from 'express';
${'import'} fetch from 'node-fetch';

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
`
	};

	// ── State ────────────────────────────────────────────────────────────────────

	let activeTab = $state<Tab>('scan');
	let language = $state<Language>('python');
	let code = $state(PLACEHOLDERS.python);
	let findings = $state<Finding[]>([]);
	let scanning = $state(false);
	let stats = $state<Stats | null>(null);
	let error = $state<string | null>(null);
	let focusedFindingId = $state<string | null>(null);

	let verifyCases = $state<VerifyCase[]>([]);
	let knowledgeHistory = $state<KnowledgeCase[]>([]);

	let folderRoot = $state<FileNode | null>(null);
	let selectedFile = $state<FileNode | null>(null);
	let scannedPaths = new SvelteSet<string>();
	let scanProgress = $state<{ current: number; total: number } | null>(null);

	const focusedFinding = $derived(findings.find((f) => f.id === focusedFindingId));
	const focusedLine = $derived(focusedFinding?.line_start ?? null);
	const currentFilename = $derived(selectedFile?.name);

	// ── Init ─────────────────────────────────────────────────────────────────────

	onMount(() => {
		refreshStats();
		getVerifyQueue()
			.then((q) => (verifyCases = q))
			.catch(() => {});
		getKnowledgeHistory()
			.then((cases) => (knowledgeHistory = cases))
			.catch(() => {});
	});

	// ── Helpers ──────────────────────────────────────────────────────────────────

	async function refreshStats() {
		try {
			stats = await getStats();
		} catch { /* backend not running */ }
	}

	// ── Handlers ─────────────────────────────────────────────────────────────────

	function handleLanguageChange(lang: Language) {
		language = lang;
		code = PLACEHOLDERS[lang];
		findings = [];
		focusedFindingId = null;
	}

	async function handleScan() {
		scanning = true;
		error = null;
		focusedFindingId = null;
		try {
			const result = await scanCode(code, language);
			findings = result.findings;
		} catch {
			error = 'Cannot connect to deus server. Run: docker compose up -d';
		} finally {
			scanning = false;
		}
	}

	async function handleSubmitToVerify() {
		if (findings.length === 0) return;
		try {
			const newCase = await addToVerifyQueue(null, code, language, findings);
			verifyCases = [...verifyCases, newCase];
		} catch {
			const localCase: VerifyCase = {
				caseNo: Date.now(),
				code,
				language,
				findings: [...findings],
				submittedAt: new Date().toISOString(),
				labels: {}
			};
			verifyCases = [...verifyCases, localCase];
		}
		findings = [];
		focusedFindingId = null;
		activeTab = 'verify';
	}

	function handleCaseLabel(caseNo: number, findingId: string, label: Label) {
		verifyCases = verifyCases.map((vc) =>
			vc.caseNo === caseNo
				? { ...vc, labels: { ...vc.labels, [findingId]: label } }
				: vc
		);
	}

	async function handleCaseSubmit(caseNo: number) {
		const vc = verifyCases.find((c) => c.caseNo === caseNo);
		if (!vc) return;

		await submitToKnowledge(caseNo, vc.labels);

		const knowledgeCase: KnowledgeCase = {
			caseNo: vc.caseNo,
			cveId: vc.cveId,
			code: vc.code,
			language: vc.language,
			findings: vc.findings,
			labels: { ...vc.labels },
			submittedAt: vc.submittedAt,
			verifiedAt: new Date().toISOString()
		};
		knowledgeHistory = [knowledgeCase, ...knowledgeHistory];
		verifyCases = verifyCases.filter((c) => c.caseNo !== caseNo);
		await refreshStats();
	}

	function handleFocusFinding(id: string) {
		focusedFindingId = id;
		activeTab = 'scan';
	}

	async function handleFolderDrop(item: DataTransferItem) {
		const root = await readFolder(item);
		if (!root) return;
		folderRoot = root;
		scannedPaths.clear();
		scanProgress = null;
		const files = flatFiles(root);
		if (files.length > 0) handleSelectFile(files[0]);
	}

	function handleSelectFile(node: FileNode) {
		if (!node.content || !node.language) return;
		selectedFile = node;
		code = node.content;
		language = node.language;
		findings = [];
		focusedFindingId = null;
	}

	async function handleScanAll() {
		if (!folderRoot) return;
		const files = flatFiles(folderRoot);
		scanProgress = { current: 0, total: files.length };
		for (let i = 0; i < files.length; i++) {
			const f = files[i];
			if (!f.content || !f.language) continue;
			try {
				const result = await scanCode(f.content, f.language);
				if (result.findings.length > 0) {
					await addToVerifyQueue(null, f.content, f.language, result.findings)
						.then((c) => (verifyCases = [...verifyCases, c]))
						.catch(() => {});
				}
				scannedPaths.add(f.path);
			} catch { /* continue */ }
			scanProgress = { current: i + 1, total: files.length };
		}
		scanProgress = null;
	}

	function handleClearFolder() {
		folderRoot = null;
		selectedFile = null;
		scannedPaths.clear();
		scanProgress = null;
	}
</script>

<div class="flex flex-col h-screen bg-gray-950 text-gray-100">

	<!-- Header -->
	<div class="flex items-center gap-3 h-11 px-4 bg-gray-900 border-b border-gray-800 shrink-0">
		<img src="/favicon.svg" alt="deus" class="w-5 h-5" />
		<span class="text-sm font-bold text-gray-100 tracking-tight">deus</span>
		<div class="w-px h-4 bg-gray-700 mx-1"></div>

		<!-- Tabs -->
		<nav class="flex items-center gap-1">
			{#each (['scan', 'verify', 'knowledge'] as Tab[]) as tab}
				<button
					onclick={() => (activeTab = tab)}
					class={[
						'flex items-center px-3 py-1 rounded text-xs font-medium capitalize transition-all',
						activeTab === tab
							? 'bg-indigo-600/30 text-indigo-300 border border-indigo-700/60'
							: 'text-gray-500 hover:text-gray-300 hover:bg-gray-800 border border-transparent'
					].join(' ')}
				>
					{tab}
					{#if tab === 'verify' && verifyCases.length > 0}
						<span class="ml-1 text-[10px] font-bold bg-indigo-600/50 text-indigo-200 rounded-full px-1.5 py-0.5">
							{verifyCases.length}
						</span>
					{/if}
				</button>
			{/each}
		</nav>

		<!-- Scan controls -->
		{#if activeTab === 'scan'}
			<div class="ml-auto">
				<ScanPanel
					{language}
					onlanguagechange={handleLanguageChange}
					onscan={handleScan}
					{scanning}
					hasFindings={findings.length > 0}
					onsubmittoverify={handleSubmitToVerify}
				/>
			</div>
		{/if}
	</div>

	<!-- Content -->
	{#if activeTab === 'scan'}
		<div class="flex flex-1 min-h-0">
			<!-- File tree sidebar -->
			{#if folderRoot}
				<div class="hidden lg:flex w-52 xl:w-60 shrink-0 flex-col">
					<FileTree
						root={folderRoot}
						selectedPath={selectedFile?.path ?? null}
						{scannedPaths}
						{scanProgress}
						onselect={handleSelectFile}
						onscanall={handleScanAll}
						onclear={handleClearFolder}
					/>
				</div>
			{/if}

			<!-- Editor -->
			<div class={`flex flex-col min-h-0 border-r border-gray-800/60 ${folderRoot ? 'flex-1' : 'w-full lg:w-3/5'}`}>
				<CodeEditor
					value={code}
					onchange={(v) => (code = v)}
					{language}
					{findings}
					{focusedLine}
					onFolderDrop={folderRoot ? undefined : handleFolderDrop}
					filename={currentFilename}
				/>
			</div>

			<!-- Findings panel -->
			<div class={[
				'overflow-y-auto p-3 flex flex-col gap-2 bg-gray-950',
				folderRoot ? 'hidden lg:flex w-72 xl:w-80 shrink-0' : 'hidden lg:flex w-2/5'
			].join(' ')}>
				{#if error}
					<div class="bg-red-900/40 border border-red-800 rounded p-3 text-sm text-red-300">
						{error}
					</div>
				{/if}
				{#if findings.length === 0 && !error}
					<div class="text-gray-600 text-xs text-center mt-10 space-y-1">
						<p>{scanning ? 'Scanning…' : 'Paste code and click Scan'}</p>
						{#if !folderRoot}
							<p class="text-gray-700">or drop a folder on the editor</p>
						{/if}
					</div>
				{/if}
				{#each findings as f (f.id)}
					<FindingCard
						finding={f}
						{language}
						onlabel={async (id, label) => {
							await submitFeedback(id, label);
							await refreshStats();
						}}
						onfocus={() => handleFocusFinding(f.id)}
						focused={f.id === focusedFindingId}
					/>
				{/each}
			</div>
		</div>
	{:else if activeTab === 'verify'}
		<VerifyTab
			cases={verifyCases}
			onlabel={handleCaseLabel}
			onsubmit={handleCaseSubmit}
		/>
	{:else if activeTab === 'knowledge'}
		<KnowledgeTab {stats} history={knowledgeHistory} />
	{/if}

	<!-- Status bar -->
	<StatusBar {stats} />
</div>
