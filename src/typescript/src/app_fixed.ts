import express, { Request, Response } from 'express';
import { execFile } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';

/**
 * Hardened TypeScript app — all findings from app.ts fixed.
 *
 * Fixes:
 *   1. Hardcoded Credentials  → environment variables
 *   2. SQL Injection           → parameterised query pattern
 *   3. Command Injection       → execFile with args array
 *   4. Path Traversal          → path.basename() + safe directory
 *   5. Unsafe Deserialization  → JSON schema validation
 *   6. Type assertion abuse    → proper type guards
 */

const app = express();
app.use(express.json());

// FIX 1: Credentials from environment variables
const DB_PASSWORD: string = process.env.DB_PASSWORD ?? '';
const API_KEY: string = process.env.API_KEY ?? '';
const SAFE_DIR: string = '/app/safe_files';

app.get('/', (req: Request, res: Response) => {
  res.json({ status: 'ok', message: 'TypeScript DevSecOps demo app (hardened)' });
});

app.get('/health', (req: Request, res: Response) => {
  res.json({ status: 'healthy' });
});

// FIX 2: Parameterised query
app.get('/user', (req: Request, res: Response) => {
  const username = req.query.username as string;
  const query = 'SELECT * FROM users WHERE username = ?';
  res.json({ query, params: [username] });
});

// FIX 3: execFile with args array
app.get('/ping', (req: Request, res: Response) => {
  const host = req.query.host as string;
  execFile('ping', ['-c', '1', host], (err, stdout) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ output: stdout });
  });
});

// FIX 4: Path sanitisation
app.get('/file', (req: Request, res: Response) => {
  const filename = req.query.filename as string;
  const safePath = path.join(SAFE_DIR, path.basename(filename));
  if (!safePath.startsWith(SAFE_DIR)) {
    return res.status(403).json({ error: 'access denied' });
  }
  const content = fs.readFileSync(safePath, 'utf8');
  res.json({ content });
});

// FIX 5: Schema validation before parse
interface Payload { value: number; label: string; }
function isPayload(obj: unknown): obj is Payload {
  return (
    typeof obj === 'object' && obj !== null &&
    typeof (obj as Payload).value === 'number' &&
    typeof (obj as Payload).label === 'string'
  );
}
app.post('/deserialize', (req: Request, res: Response) => {
  const data = req.body.payload as string;
  const parsed: unknown = JSON.parse(data);
  if (!isPayload(parsed)) {
    return res.status(400).json({ error: 'invalid payload schema' });
  }
  res.json({ result: parsed });
});

// FIX 6: Proper type guard instead of any cast
app.post('/process', (req: Request, res: Response) => {
  const body: unknown = req.body;
  if (typeof body !== 'object' || body === null || !('value' in body)) {
    return res.status(400).json({ error: 'missing value' });
  }
  const value = (body as { value: unknown }).value;
  if (typeof value !== 'number') {
    return res.status(400).json({ error: 'value must be a number' });
  }
  res.json({ result: value * 2 });
});

app.listen(9003, () => console.log('Server running on :9003'));
