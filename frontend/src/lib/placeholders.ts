// Per-language sample snippets shown in the Scan tab editor.
// Each snippet contains a few intentional vulnerabilities so the
// scan output is interesting on first load.

import type { Language } from './types';

export const PLACEHOLDERS: Record<Language, string> = {
	auto: `# Paste any code here — makina will auto-detect the language
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
