/*
 * Glyph Animator — Repository server (hardened + optional UPnP)
 *
 * HTTPS-native, Node.js built-ins: http/https/fs/path/zlib/crypto/sqlite.
 * UPnP via nat-upnp-2 (optional) if installed; feature-flagged.
 *
 * Endpoints:
 *   GET    /api/health
 *   GET    /api/animations
 *   POST   /api/animations  (gzip JSON document)
 *   GET    /api/animations/:id
 *   PUT    /api/animations/:id
 *   DELETE /api/animations/:id
 */
'use strict';

const http = require('node:http');
const https = require('node:https');
const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

// ----------------------------------------------------------------- config
const HOST = process.env.HOST || '0.0.0.0';
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'data', 'repository.db');
const TLS_CERT = process.env.TLS_CERT || path.join(__dirname, 'certs', 'fullchain.pem');
const TLS_KEY = process.env.TLS_KEY || path.join(__dirname, 'certs', 'privkey.pem');
const HTTP_REDIRECT_PORT = process.env.HTTP_REDIRECT_PORT ? parseInt(process.env.HTTP_REDIRECT_PORT, 10) : null;
const MAX_MIB = parseInt(process.env.MAX_BYTES || process.env.MAX_MIB || '8', 10);
const MAX_BYTES = MAX_MIB * 1024 * 1024;
const TLS_AVAILABLE = fs.existsSync(TLS_CERT) && fs.existsSync(TLS_KEY);
const PORT = parseInt(process.env.PORT || (TLS_AVAILABLE ? '8443' : '3000'), 10);
const ENABLE_UPNP = (process.env.ENABLE_UPNP || 'false').toLowerCase() === 'true';
const UPNP_EXTERNAL_PORT = process.env.UPNP_EXTERNAL_PORT ? parseInt(process.env.UPNP_EXTERNAL_PORT, 10) : PORT;
const RATE_LIMIT_MAX = parseInt(process.env.RATE_LIMIT_MAX || '60', 10); // reqs
const RATE_LIMIT_WINDOW_MS = parseInt(process.env.RATE_LIMIT_WINDOW_MS || '60000', 10); // 1m
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
const TRUST_XFF = (process.env.TRUST_XFF || 'false').toLowerCase() === 'true';

// ----------------------------------------------------------------- db
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
const db = new DatabaseSync(DB_PATH);
db.exec(`
  CREATE TABLE IF NOT EXISTS animations (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    author TEXT NOT NULL DEFAULT '',
    data BLOB NOT NULL,
    size_bytes INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_animations_updated ON animations(updated_at DESC);
`);
const insertStmt = db.prepare('INSERT INTO animations(id,name,author,data,size_bytes,updated_at) VALUES(?,?,?,?,?,?)');
const updateStmt = db.prepare('UPDATE animations SET name=?, author=?, data=?, size_bytes=?, updated_at=? WHERE id=?');
const listStmt = db.prepare('SELECT id,name,author,size_bytes,updated_at FROM animations ORDER BY updated_at DESC');
const getStmt = db.prepare('SELECT data FROM animations WHERE id=?');
const existsStmt = db.prepare('SELECT 1 FROM animations WHERE id=?');
const deleteStmt = db.prepare('DELETE FROM animations WHERE id=?');

// ----------------------------------------------------------------- rate limit
const buckets = new Map();
function getClientKey(req) {
  let ip = req.socket.remoteAddress || 'unknown';
  if (TRUST_XFF && req.headers['x-forwarded-for']) {
    const xf = String(req.headers['x-forwarded-for']).split(',')[0].trim();
    if (xf) ip = xf;
  }
  return ip + '|' + req.url.split('?')[0];
}
function isRateLimited(key) {
  const now = Date.now();
  const b = buckets.get(key) || { count: 0, start: now };
  if (now - b.start > RATE_LIMIT_WINDOW_MS) { b.count = 0; b.start = now; }
  b.count++;
  buckets.set(key, b);
  return b.count > RATE_LIMIT_MAX;
}
// Prune stale rate-limit buckets so the map cannot grow without bound.
const pruneTimer = setInterval(() => {
  const cutoff = Date.now() - RATE_LIMIT_WINDOW_MS;
  for (const [k, b] of buckets) if (b.start < cutoff) buckets.delete(k);
}, Math.max(1000, RATE_LIMIT_WINDOW_MS));
if (pruneTimer.unref) pruneTimer.unref();

// ----------------------------------------------------------------- helpers
const ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
function isGzip(buf){ return buf && buf.length >= 2 && buf[0] === 0x1f && buf[1] === 0x8b; }
// Cap decompression output to guard against gzip-bomb denial of service. We only
// need the document header (name/author/updatedAt), so a few MB is plenty.
const MAX_DECOMPRESS = 4 * 1024 * 1024;
function decodeMetadata(buf){
  try {
    const raw = isGzip(buf) ? zlib.gunzipSync(buf, { maxOutputLength: MAX_DECOMPRESS }) : buf;
    const o = JSON.parse(raw.toString('utf8'));
    return {
      name: typeof o.name === 'string' && o.name.trim() ? o.name.trim().slice(0, 120) : 'Untitled',
      author: typeof o.author === 'string' ? o.author.slice(0, 120) : '',
      updatedAt: typeof o.updatedAt === 'number' && o.updatedAt > 0 ? o.updatedAt : Date.now(),
    };
  } catch { return { name: 'Untitled', author: '', updatedAt: Date.now() }; }
}
function readBody(req){
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    req.on('data', c => {
      total += c.length;
      if (total > MAX_BYTES) { reject(new Error('Payload too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}
function corsHeaders(origin){
  const base = { 'Access-Control-Allow-Origin': origin || '*', 'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS', 'Access-Control-Allow-Headers': '*', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer' };
  return base;
}
function sendJson(res, code, obj, origin){
  const body = Buffer.from(JSON.stringify(obj));
  const h = Object.assign({ 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': body.length }, corsHeaders(origin));
  res.writeHead(code, h);
  res.end(body);
}
function getOrigin(req){ return ALLOWED_ORIGINS.length ? (ALLOWED_ORIGINS[0]) : (req.headers.origin || '*'); } // permissive if not configured

async function handle(req, res){
  const origin = getOrigin(req);
  const url = new URL(req.url, 'http://localhost');
  const parts = url.pathname.split('/').filter(Boolean);

  if (req.method === 'OPTIONS') {
    res.writeHead(204, corsHeaders(origin));
    return res.end();
  }

  // simple path traversal guard
  if (url.pathname.includes('..')) return sendJson(res, 400, { error: 'Bad path' }, origin);

  const key = getClientKey(req);
  if (isRateLimited(key)) return sendJson(res, 429, { error: 'Rate limit exceeded' }, origin);

  if (parts[0] !== 'api') return sendJson(res, 404, { error: 'Not found' }, origin);
  if (parts[1] === 'health' && req.method === 'GET') return sendJson(res, 200, { ok: true, name: 'glyph-animator-repository', storage: 'sqlite', tls: TLS_AVAILABLE }, origin);

  if (parts[1] === 'animations') {
    // Reject obviously oversized bodies up-front when the client declares a size.
    if (req.method === 'POST' || req.method === 'PUT') {
      const declared = parseInt(req.headers['content-length'] || '0', 10);
      if (Number.isFinite(declared) && declared > MAX_BYTES) {
        return sendJson(res, 413, { error: 'Payload too large' }, origin);
      }
    }
    if (parts.length === 2) {
      if (req.method === 'GET') {
        const rows = listStmt.all().map(r => ({ id: r.id, name: r.name, author: r.author, sizeBytes: r.size_bytes, updatedAt: r.updated_at }));
        return sendJson(res, 200, rows, origin);
      }
      if (req.method === 'POST') {
        const body = await readBody(req);
        if (body.length < 4) return sendJson(res, 400, { error: 'Empty body' }, origin);
        const id = crypto.randomUUID();
        const meta = decodeMetadata(body);
        insertStmt.run(id, meta.name, meta.author, body, body.length, meta.updatedAt);
        return sendJson(res, 201, { id, name: meta.name, sizeBytes: body.length }, origin);
      }
      return sendJson(res, 405, { error: 'Method not allowed' }, origin);
    }
    if (parts.length === 3) {
      const id = parts[2];
      if (!ID_RE.test(id)) return sendJson(res, 400, { error: 'Bad id' }, origin);
      if (req.method === 'GET') {
        const row = getStmt.get(id);
        if (!row) return sendJson(res, 404, { error: 'Not found' }, origin);
        const data = Buffer.from(row.data);
        res.writeHead(200, Object.assign({ 'Content-Type': 'application/octet-stream', 'Content-Length': data.length }, corsHeaders(origin), { 'X-Content-Type-Options': 'nosniff' }));
        return res.end(data);
      }
      if (req.method === 'PUT') {
        const body = await readBody(req);
        if (body.length < 4) return sendJson(res, 400, { error: 'Empty body' }, origin);
        const meta = decodeMetadata(body);
        if (existsStmt.get(id)) updateStmt.run(meta.name, meta.author, body, body.length, meta.updatedAt, id);
        else insertStmt.run(id, meta.name, meta.author, body, body.length, meta.updatedAt);
        return sendJson(res, 200, { id, name: meta.name, sizeBytes: body.length }, origin);
      }
      if (req.method === 'DELETE') {
        const info = deleteStmt.run(id);
        if (info.changes === 0) return sendJson(res, 404, { error: 'Not found' }, origin);
        return sendJson(res, 200, { ok: true }, origin);
      }
      return sendJson(res, 405, { error: 'Method not allowed' }, origin);
    }
  }
  return sendJson(res, 404, { error: 'Not found' }, origin);
}

function listener(req, res){
  handle(req, res).catch(err => {
    if (!res.headersSent) {
      const origin = getOrigin(req);
      const tooLarge = err && /payload too large/i.test(err.message || '');
      sendJson(res, tooLarge ? 413 : 500, { error: err && err.message ? err.message : 'Internal error' }, origin);
    }
  });
}

// ----------------------------------------------------------------- upnp (optional)
async function setupUpnp(){
  if (!ENABLE_UPNP) return;
  try {
    const nat = require('nat-upnp-2');
    const client = nat.createClient();
    const gw = await new Promise((resolve, reject) => client.getGateway((e,g)=>e?reject(e):resolve(g)));
    if (!gw) return;
    const publicPort = UPNP_EXTERNAL_PORT;
    const privatePort = PORT;
    await new Promise((resolve,reject)=>client.portMapping({ public: publicPort, private: privatePort, ttl: 0, description: 'glyph-animator-repo', protocol: 'TCP' }, (e)=>e?reject(e):resolve()));
    console.log(`[repository] UPnP: mapped ${publicPort}->${privatePort} TCP`);
  } catch (e) {
    console.warn('[repository] UPnP not enabled or failed:', e.message);
  }
}

// ----------------------------------------------------------------- start
if (TLS_AVAILABLE) {
  const options = { cert: fs.readFileSync(TLS_CERT), key: fs.readFileSync(TLS_KEY) };
  https.createServer(options, listener).listen(PORT, HOST, async () => {
    console.log(`[repository] HTTPS listening on https://${HOST}:${PORT}`);
    console.log(`[repository] SQLite database at ${DB_PATH}`);
    await setupUpnp();
  });
  if (HTTP_REDIRECT_PORT) {
    http.createServer((req,res)=>{
      const host = (req.headers.host || '').split(':')[0];
      res.writeHead(308, { Location: `https://${host}:${PORT}${req.url}` });
      res.end();
    }).listen(HTTP_REDIRECT_PORT, HOST, ()=>{ console.log(`[repository] HTTP->HTTPS redirect on port ${HTTP_REDIRECT_PORT}`); });
  }
} else {
  http.createServer(listener).listen(PORT, HOST, async () => {
    console.warn('[repository] WARNING: no TLS certificate found, serving plain HTTP.');
    console.warn(`[repository] Put a certificate at ${TLS_CERT} and key at ${TLS_KEY} or set env vars.`);
    console.log(`[repository] HTTP listening on http://${HOST}:${PORT}`);
    console.log(`[repository] SQLite database at ${DB_PATH}`);
    await setupUpnp();
  });
}
process.on('SIGINT', ()=>{ try{ db.close(); }catch{} process.exit(0); });
