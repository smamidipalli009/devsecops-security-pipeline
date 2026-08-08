import express, { Request, Response } from 'express';
import { exec } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';

/**
 * Vulnerable TypeScript Express app — intentional SAST findings for CodeQL.
 * DO NOT deploy to production.
 *
 * Vulnerabilities:
 *   1. Hardcoded Credentials      — API key in source
 *   2. SQL Injection               — user input in raw SQL
 *   3. Command Injection           — user input passed to exec()
 *   4. Path Traversal              — user-controlled file path
 *   5. Unsafe Deserialization      — JSON.parse on untrusted input without validation
 *   6. Type Assertion Abuse        — casting unknown to any bypasses type safety
 */

const app = express();
app.use(express.json());

// VULNERABILITY 1: Hardcoded credentials
const DB_PASSWORD: string = 'supersecret123';
const API_KEY: string = 'sk-prod-abc123xyz';

app.get('/', (req: Request, res: Response) => {
  res.json({ status: 'ok', message: 'TypeScript DevSecOps demo app' });
});

app.get('/health', (req: Request, res: Response) => {
  res.json({ status: 'healthy' });
});

// VULNERABILITY 2: SQL Injection
app.get('/user', (req: Request, res: Response) => {
  const username = req.query.username as string;
  // BAD: string interpolation directly into SQL
  const query = `SELECT * FROM users WHERE username = '${username}'`;
  res.json({ query });
});

// VULNERABILITY 3: Command Injection
app.get('/ping', (req: Request, res: Response) => {
  const host = req.query.host as string;
  // BAD: user input passed directly to shell
  exec(`ping -c 1 ${host}`, (err, stdout) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ output: stdout });
  });
});

// VULNERABILITY 4: Path Traversal
app.get('/file', (req: Request, res: Response) => {
  const filename = req.query.filename as string;
  // BAD: user controls the file path
  const content = fs.readFileSync(filename, 'utf8');
  res.json({ content });
});

// VULNERABILITY 5: Unsafe Deserialization
app.post('/deserialize', (req: Request, res: Response) => {
  const data = req.body.payload as string;
  // BAD: parsing untrusted JSON without schema validation
  const parsed = JSON.parse(data);
  res.json({ result: parsed });
});

// VULNERABILITY 6: Type assertion abuse — bypasses TypeScript type safety
app.post('/process', (req: Request, res: Response) => {
  // BAD: casting unknown input to any loses all type safety
  const input = req.body as any;
  const result = input.value * 2;
  res.json({ result });
});

app.listen(9003, () => console.log('Server running on :9003'));
