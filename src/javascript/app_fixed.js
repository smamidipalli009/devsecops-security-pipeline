'use strict';

/**
 * Hardened Express.js app — all SAST findings from app.js fixed.
 *
 * Fixes:
 *   1. Hardcoded Credentials → environment variables
 *   2. SQL Injection         → parameterised queries
 *   3. Command Injection     → execFile with args array
 *   4. Path Traversal        → path.basename() + safe directory
 *   5. Prototype Pollution   → Object.hasOwn() check + Object.create(null)
 *   6. ReDoS                 → safe regex without catastrophic backtracking
 */

const express = require('express');
const { execFile } = require('child_process');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(express.json());

// FIX 1: Credentials from environment variables
const DB_PASSWORD = process.env.DB_PASSWORD;
const API_KEY = process.env.API_KEY;
const SAFE_DIR = '/app/safe_files';

app.get('/', (req, res) => {
  res.json({ status: 'ok', message: 'JavaScript DevSecOps demo app (hardened)' });
});

app.get('/health', (req, res) => {
  res.json({ status: 'healthy' });
});

// FIX 2: Parameterised query placeholder
app.get('/user', (req, res) => {
  const username = req.query.username;
  // Safe: using ? placeholder (shown as pattern — real DB would use prepared stmt)
  const query = 'SELECT * FROM users WHERE username = ?';
  res.json({ query, params: [username] });
});

// FIX 3: execFile with args array — no shell interpolation
app.get('/ping', (req, res) => {
  const host = req.query.host;
  execFile('ping', ['-c', '1', host], (err, stdout) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ output: stdout });
  });
});

// FIX 4: Path sanitisation + safe directory check
app.get('/file', (req, res) => {
  const filename = req.query.filename;
  const safePath = path.join(SAFE_DIR, path.basename(filename));
  if (!safePath.startsWith(SAFE_DIR)) {
    return res.status(403).json({ error: 'access denied' });
  }
  const content = fs.readFileSync(safePath, 'utf8');
  res.json({ content });
});

// FIX 5: Prototype pollution prevented
app.post('/merge', (req, res) => {
  const target = Object.create(null);
  const source = req.body;
  function safeMerge(target, source) {
    for (const key of Object.keys(source)) {
      // Object.hasOwn prevents __proto__ pollution
      if (!Object.hasOwn(source, key)) continue;
      if (key === '__proto__' || key === 'constructor') continue;
      if (typeof source[key] === 'object' && source[key] !== null) {
        target[key] = Object.create(null);
        safeMerge(target[key], source[key]);
      } else {
        target[key] = source[key];
      }
    }
  }
  safeMerge(target, source);
  res.json({ result: target });
});

// FIX 6: Safe regex without catastrophic backtracking
app.get('/validate', (req, res) => {
  const input = req.query.input;
  // Safe: linear time regex
  const safe = /^a+$/.test(input);
  res.json({ valid: safe });
});

app.listen(9002, () => console.log('Server running on :9002'));
