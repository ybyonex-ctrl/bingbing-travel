import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { body, validationResult } from 'express-validator';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import initSqlJs from 'sql.js';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'bbtravel_jwt_secret_2026_change_in_prod';
const DB_PATH = path.join(__dirname, 'data', 'bbuser.db');

// ── Database Setup ──────────────────────────────────
let db;
async function initDB() {
  const SQL = await initSqlJs();
  const dbDir = path.dirname(DB_PATH);
  if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir, { recursive: true });

  if (fs.existsSync(DB_PATH)) {
    const buf = fs.readFileSync(DB_PATH);
    db = new SQL.Database(buf);
  } else {
    db = new SQL.Database();
  }

  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    qq_email TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
  )`);
  saveDB();
}

function saveDB() {
  const data = db.export();
  const buffer = Buffer.from(data);
  fs.writeFileSync(DB_PATH, buffer);
}

function dbGet(sql, params = []) {
  const stmt = db.prepare(sql);
  if (params.length > 0) stmt.bind(params);
  if (stmt.step()) {
    const row = stmt.getAsObject();
    stmt.free();
    return row;
  }
  stmt.free();
  return undefined;
}

function dbRun(sql, params = []) {
  db.run(sql, params);
  saveDB();
}

function dbAll(sql, params = []) {
  const stmt = db.prepare(sql);
  if (params.length > 0) stmt.bind(params);
  const rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

// ── Express App ─────────────────────────────────────
const app = express();
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '1mb' }));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  message: { error: '请求过于频繁，请15分钟后重试' }
});

// ── Middleware ───────────────────────────────────────
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: '未登录' });
  }
  try {
    const decoded = jwt.verify(header.slice(7), JWT_SECRET);
    req.userId = decoded.id;
    req.username = decoded.username;
    next();
  } catch {
    return res.status(401).json({ error: '登录已过期，请重新登录' });
  }
}

// Safe string equals — compare length then each char
function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

// Sanitize input — strip SQL-injection vectors and XSS chars
function sanitize(str) {
  if (typeof str !== 'string') return '';
  return str.replace(/[<>"'%;()&\/\\]/g, '').trim();
}

// ── Routes ──────────────────────────────────────────

// Register
app.post('/api/auth/register', authLimiter, [
  body('username').isString().isLength({ min: 3, max: 30 }),
  body('password').isString().isLength({ min: 6, max: 100 }),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ error: '用户名3-30字符，密码至少6字符' });
  }
  try {
    const username = sanitize(req.body.username);
    const password = req.body.password;

    // Check existing — parameterized query
    const existing = dbGet('SELECT id FROM users WHERE username = ?', [username]);
    if (existing) {
      if (safeEqual(String(existing.id), String(existing.id))) {
        return res.status(409).json({ error: '用户名已存在' });
      }
    }

    const hashed = await bcrypt.hash(password, 10);
    dbRun('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashed]);

    const user = dbGet('SELECT id FROM users WHERE username = ?', [username]);
    const token = jwt.sign({ id: user.id, username }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, username, userId: user.id });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: '服务器错误' });
  }
});

// Login
app.post('/api/auth/login', authLimiter, [
  body('username').isString().isLength({ min: 1 }),
  body('password').isString().isLength({ min: 1 }),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ error: '请输入用户名和密码' });
  }
  try {
    const username = sanitize(req.body.username);
    const password = req.body.password;

    const user = dbGet('SELECT * FROM users WHERE username = ?', [username]);
    if (!user) {
      return res.status(401).json({ error: '用户名或密码错误' });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ error: '用户名或密码错误' });
    }

    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, username: user.username, userId: user.id, qqEmail: user.qq_email || '' });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: '服务器错误' });
  }
});

// Get profile
app.get('/api/user/profile', auth, (req, res) => {
  try {
    const user = dbGet('SELECT id, username, qq_email, created_at FROM users WHERE id = ?', [req.userId]);
    if (!user) return res.status(404).json({ error: '用户不存在' });
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: '服务器错误' });
  }
});

// Bind QQ email
app.post('/api/user/bind-qq', auth, [
  body('qqEmail').isString().matches(/^\d{5,12}@qq\.com$/),
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ error: '请输入正确的QQ邮箱格式' });
  }
  try {
    const qqEmail = sanitize(req.body.qqEmail);
    dbRun("UPDATE users SET qq_email = ?, updated_at = datetime('now') WHERE id = ?", [qqEmail, req.userId]);
    res.json({ qqEmail, message: '绑定成功' });
  } catch (err) {
    res.status(500).json({ error: '服务器错误' });
  }
});

// Change password
app.post('/api/auth/change-password', auth, [
  body('oldPassword').isString().isLength({ min: 1 }),
  body('newPassword').isString().isLength({ min: 6, max: 100 }),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ error: '新密码至少6个字符' });
  }
  try {
    const user = dbGet('SELECT * FROM users WHERE id = ?', [req.userId]);
    if (!user) return res.status(404).json({ error: '用户不存在' });

    const match = await bcrypt.compare(req.body.oldPassword, user.password);
    if (!match) return res.status(401).json({ error: '原密码错误' });

    const hashed = await bcrypt.hash(req.body.newPassword, 10);
    dbRun("UPDATE users SET password = ?, updated_at = datetime('now') WHERE id = ?", [hashed, req.userId]);
    res.json({ message: '密码已修改' });
  } catch (err) {
    res.status(500).json({ error: '服务器错误' });
  }
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', uptime: process.uptime() });
});

// Static files — only in local dev (skip on Render — frontend is on Netlify)
if (!process.env.RENDER) {
  app.use(express.static(path.join(__dirname, '..', 'cloudflare-deploy')));
  app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'cloudflare-deploy', 'index.html'));
  });
}

// ── Start ───────────────────────────────────────────
await initDB();
app.listen(PORT, '0.0.0.0', () => {
  console.log(`冰出行服务器运行中 http://0.0.0.0:${PORT}`);
});
