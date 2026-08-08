'use strict';

/**
 * Vulnerable Express.js app — intentional SAST findings for CodeQL.
 * DO NOT deploy to production.
 *
 * Vulnerabilities:
 *   1. SQL Injection          — user input in raw SQL query
 *   2. Command Injection      — user input passed to exec()
 *   3. Path Traversal         — user-controlled file path
 *   4. Hardcoded Credentials  — API key in source
 *   5. Prototype Pollution    — unsafe merge of user input
 *   6. ReDoS                  — catastrophic backtracking regex
 */

const express = require('express');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(express.json());

// VULNERABILITY 1: Hardcoded credentials
// CodeQL: js/hardcoded-credentials
const DB_PASSWORD = 'supersecret123';
const API_KEY = 'sk-prod-abc123xyz';

app.get('/', (req, res) => {
  res.json({ status: 'ok', message: 'JavaScript DevSecOps demo app' });
});

app.get('/health', (req, res) => {
  res.json({ status: 'healthy' });
});

// VULNERABILITY 2: SQL Injection
// CodeQL: js/sql-injection
app.get('/user', (req, res) => {
  const username = req.query.username;
  // BAD: string interpolation directly into SQL
  const query = `SELECT * FROM users WHERE username = '${username}'`;
  res.json({ query });
});

// VULNERABILITY 3: Command Injection
// CodeQL: js/command-line-injection
app.get('/ping', (req, res) => {
  const host = req.query.host;
  // BAD: user input passed directly to shell
  exec(`ping -c 1 ${host}`, (err, stdout) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ output: stdout });
  });
});

// VULNERABILITY 4: Path Traversal
// CodeQL: js/path-injection
app.get('/file', (req, res) => {
  const filename = req.query.filename;
  // BAD: user controls the file path
  const content = fs.readFileSync(filename, 'utf8');
  res.json({ content });
});

// VULNERABILITY 5: Prototype Pollution
// CodeQL: js/prototype-pollution
app.post('/merge', (req, res) => {
  const target = {};
  const source = req.body;
  // BAD: recursive merge without prototype check
  function merge(target, source) {
    for (const key in source) {
      if (typeof source[key] === 'object') {
        target[key] = {};
        merge(target[key], source[key]);
      } else {
        // BAD: allows __proto__ pollution
        target[key] = source[key];
      }
    }
  }
  merge(target, source);
  res.json({ result: target });
});

// VULNERABILITY 6: ReDoS
// CodeQL: js/redos
app.get('/validate', (req, res) => {
  const input = req.query.input;
  // BAD: catastrophic backtracking on malicious input
  const vulnerable = /^(a+)+$/.test(input);
  res.json({ valid: vulnerable });
});

app.listen(9002, () => console.log('Server running on :9002'));
