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
import crypto from 'crypto';
import net from 'net';
import tls from 'tls';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 3001;
const DEFAULT_DEV_JWT_SECRET = 'bbtravel_jwt_secret_2026_change_in_prod';
const isProduction = process.env.NODE_ENV === 'production' || Boolean(process.env.RAILWAY_ENVIRONMENT || process.env.RENDER || process.env.FLY_APP_NAME);
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || '';
const DB_PATH = path.resolve(process.env.DB_PATH || path.join(process.env.DATA_DIR || path.join(__dirname, 'data'), 'bbuser.db'));
const USERNAME_RE = /^[\p{L}\p{N}_-]{3,30}$/u;
const QQ_EMAIL_RE = /^\d{5,12}@qq\.com$/;
const DEEPSEEK_KEY_RE = /^sk-[A-Za-z0-9_-]{20,200}$/;
const ALLOWED_MODELS = new Set(['deepseek-chat', 'deepseek-reasoner', 'deepseek-v4-pro']);
const DEFAULT_ALLOWED_ORIGINS = [
  'http://localhost:8787',
  'http://127.0.0.1:8787',
  'http://localhost:3001',
  'http://127.0.0.1:3001',
];
const configuredOrigins = new Set([
  ...DEFAULT_ALLOWED_ORIGINS,
  ...String(process.env.ALLOWED_ORIGINS || '')
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean),
]);
const netlifyOriginPattern = /^https:\/\/[a-z0-9-]+\.netlify\.app$/i;
const cloudflareOriginPattern = /^https:\/\/([a-z0-9-]+\.)*[a-z0-9-]+\.(pages|workers)\.dev$/i;

function resolveJwtSecret() {
  const configuredSecret = process.env.JWT_SECRET || '';
  if (!isProduction) return configuredSecret || DEFAULT_DEV_JWT_SECRET;

  if (configuredSecret && configuredSecret !== DEFAULT_DEV_JWT_SECRET && configuredSecret.length >= 32) {
    return configuredSecret;
  }

  console.warn('JWT_SECRET is missing or weak; using an ephemeral random secret for this process.');
  return crypto.randomBytes(48).toString('hex');
}

const JWT_SECRET = resolveJwtSecret();

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
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({
  credentials: true,
  origin(origin, callback) {
    if (!origin) return callback(null, true);
    if (configuredOrigins.has(origin) || netlifyOriginPattern.test(origin) || cloudflareOriginPattern.test(origin)) {
      return callback(null, true);
    }
    return callback(new Error('CORS origin blocked'));
  },
}));
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: '请求过于频繁，请稍后重试' },
}));
app.use(express.json({ limit: '1mb' }));
app.use((err, req, res, next) => {
  if (err?.type === 'entity.too.large') {
    return res.status(413).json({ error: '请求体过大' });
  }
  if (err instanceof SyntaxError && 'body' in err) {
    return res.status(400).json({ error: 'JSON格式错误' });
  }
  if (err?.message === 'CORS origin blocked') {
    return res.status(403).json({ error: '来源不允许' });
  }
  return next(err);
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: '请求过于频繁，请15分钟后重试' }
});

const aiLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 40,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'AI请求过于频繁，请稍后重试' }
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

function timingSafeStringEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

function normalizeString(str, max = 100) {
  if (typeof str !== 'string') return '';
  return str.trim().slice(0, max);
}

function normalizeUsername(username) {
  return normalizeString(username, 30);
}

function normalizeQQEmail(email) {
  return normalizeString(email, 40).toLowerCase();
}

function validateRequest(req, res) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    res.status(400).json({ error: errors.array()[0]?.msg || '请求参数不正确' });
    return false;
  }
  return true;
}

function requireAdminToken(req, res, next) {
  if (!ADMIN_TOKEN) return res.status(404).json({ error: 'Not found' });
  const header = req.headers.authorization || '';
  const bearer = header.startsWith('Bearer ') ? header.slice(7) : '';
  const token = req.get('x-admin-token') || bearer;
  if (!timingSafeStringEqual(token, ADMIN_TOKEN)) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  next();
}

function validateDeepSeekKey(apiKey) {
  return DEEPSEEK_KEY_RE.test(apiKey);
}

function clampNumber(value, fallback, min, max) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, n));
}

function normalizeMessages(messages) {
  if (!Array.isArray(messages) || messages.length === 0 || messages.length > 20) return null;
  const roles = new Set(['system', 'user', 'assistant']);
  const clean = [];
  for (const msg of messages) {
    if (!msg || typeof msg !== 'object') return null;
    const role = String(msg.role || '').trim();
    const content = typeof msg.content === 'string' ? msg.content : '';
    if (!roles.has(role) || content.length < 1 || content.length > 16000) return null;
    clean.push({ role, content });
  }
  return clean;
}

async function fetchWithTimeout(url, options, timeoutMs = 30000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

// ── Routes ──────────────────────────────────────────

// Register
app.post('/api/auth/register', authLimiter, [
  body('username').isString().trim().matches(USERNAME_RE).withMessage('用户名仅支持中英文、数字、下划线和短横线，长度3-30字符'),
  body('password').isString().isLength({ min: 8, max: 100 }).withMessage('密码至少8字符'),
], async (req, res) => {
  if (!validateRequest(req, res)) return;
  try {
    const username = normalizeUsername(req.body.username);
    const password = req.body.password;

    const existing = dbGet('SELECT id FROM users WHERE username = ?', [username]);
    if (existing) {
      return res.status(409).json({ error: '用户名已存在' });
    }

    const hashed = await bcrypt.hash(password, 12);
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
  body('username').isString().trim().matches(USERNAME_RE).withMessage('用户名格式不正确'),
  body('password').isString().isLength({ min: 1, max: 100 }).withMessage('请输入密码'),
], async (req, res) => {
  if (!validateRequest(req, res)) return;
  try {
    const username = normalizeUsername(req.body.username);
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
  body('qqEmail').isString().trim().matches(QQ_EMAIL_RE).withMessage('请输入正确的QQ邮箱格式'),
], (req, res) => {
  if (!validateRequest(req, res)) return;
  try {
    const qqEmail = normalizeQQEmail(req.body.qqEmail);

    // Check: is this QQ email already bound to another user?
    const existing = dbGet('SELECT id, username FROM users WHERE qq_email = ? AND id != ?', [qqEmail, req.userId]);
    if (existing) {
      return res.status(409).json({ error: '此QQ邮箱已被用户 ' + existing.username + ' 绑定' });
    }

    dbRun("UPDATE users SET qq_email = ?, updated_at = datetime('now') WHERE id = ?", [qqEmail, req.userId]);
    res.json({ qqEmail, message: '绑定成功' });
  } catch (err) {
    res.status(500).json({ error: '服务器错误' });
  }
});

// Store verification codes in memory (with expiry)
const verificationCodes = new Map(); // username -> {code, expires, requests, failures}

// Generate 6-digit code
function generateCode() {
  return String(crypto.randomInt(100000, 1000000));
}

function hasSmtpConfig() {
  return Boolean(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS);
}

async function sendVerificationEmail(to, code) {
  const port = Number(process.env.SMTP_PORT || 465);
  const host = process.env.SMTP_HOST;
  const secure = String(process.env.SMTP_SECURE || '').toLowerCase() === 'false' ? false : port === 465;
  const from = process.env.SMTP_FROM || process.env.SMTP_USER;
  const fromAddress = extractEmailAddress(from);
  const socket = await connectSmtp({ host, port, secure });
  try {
    await expectSmtp(socket, [220]);
    await smtpCommand(socket, `EHLO ${process.env.SMTP_EHLO_HOST || 'bingbing-travel.local'}`, [250]);
    await smtpCommand(socket, 'AUTH LOGIN', [334]);
    await smtpCommand(socket, Buffer.from(process.env.SMTP_USER).toString('base64'), [334]);
    await smtpCommand(socket, Buffer.from(process.env.SMTP_PASS).toString('base64'), [235]);
    await smtpCommand(socket, `MAIL FROM:<${fromAddress}>`, [250]);
    await smtpCommand(socket, `RCPT TO:<${to}>`, [250, 251]);
    await smtpCommand(socket, 'DATA', [354]);
    await smtpCommand(socket, buildVerificationEmail({ from, to, code }), [250], true);
    await smtpCommand(socket, 'QUIT', [221]);
  } finally {
    socket.end();
  }
}

function extractEmailAddress(value) {
  const match = String(value || '').match(/<([^>]+)>/);
  return (match ? match[1] : value || '').trim();
}

function encodeHeader(value) {
  return '=?UTF-8?B?' + Buffer.from(String(value), 'utf8').toString('base64') + '?=';
}

function buildVerificationEmail({ from, to, code }) {
  const boundary = 'bb-' + crypto.randomBytes(8).toString('hex');
  const subject = encodeHeader('冰冰出行密码重置验证码');
  const text = `你的冰冰出行验证码是：${code}。验证码10分钟内有效。如非本人操作，请忽略本邮件。`;
  const html = `<div style="font-family:Arial,'Microsoft YaHei',sans-serif;line-height:1.7;color:#253246"><h2>冰冰出行验证码</h2><p>你的验证码是：</p><p style="font-size:28px;font-weight:700;letter-spacing:4px;color:#6C8BF5">${code}</p><p>验证码10分钟内有效。如非本人操作，请忽略本邮件。</p></div>`;
  return [
    `From: ${from}`,
    `To: ${to}`,
    `Subject: ${subject}`,
    'MIME-Version: 1.0',
    `Content-Type: multipart/alternative; boundary="${boundary}"`,
    '',
    `--${boundary}`,
    'Content-Type: text/plain; charset=UTF-8',
    'Content-Transfer-Encoding: 8bit',
    '',
    text,
    `--${boundary}`,
    'Content-Type: text/html; charset=UTF-8',
    'Content-Transfer-Encoding: 8bit',
    '',
    html,
    `--${boundary}--`,
    '.',
  ].join('\r\n');
}

function connectSmtp({ host, port, secure }) {
  return new Promise((resolve, reject) => {
    const socket = secure
      ? tls.connect({ host, port, servername: host, rejectUnauthorized: process.env.SMTP_REJECT_UNAUTHORIZED !== 'false' })
      : net.connect({ host, port });
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error('SMTP connection timed out'));
    }, 15000);
    socket.once('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
    socket.once(secure ? 'secureConnect' : 'connect', () => {
      clearTimeout(timer);
      socket.setEncoding('utf8');
      resolve(socket);
    });
  });
}

function expectSmtp(socket, expectedCodes) {
  return new Promise((resolve, reject) => {
    let data = '';
    const timer = setTimeout(() => {
      cleanup();
      reject(new Error('SMTP response timed out'));
    }, 15000);
    const onData = (chunk) => {
      data += chunk;
      const lines = data.split(/\r?\n/).filter(Boolean);
      const last = lines[lines.length - 1] || '';
      if (!/^\d{3} /.test(last)) return;
      const code = Number(last.slice(0, 3));
      cleanup();
      if (expectedCodes.includes(code)) resolve(data);
      else reject(new Error('Unexpected SMTP response ' + data.trim()));
    };
    const onError = (err) => {
      cleanup();
      reject(err);
    };
    const cleanup = () => {
      clearTimeout(timer);
      socket.off('data', onData);
      socket.off('error', onError);
    };
    socket.on('data', onData);
    socket.once('error', onError);
  });
}

function smtpCommand(socket, command, expectedCodes, raw = false) {
  socket.write(raw ? command + '\r\n' : command + '\r\n');
  return expectSmtp(socket, expectedCodes);
}

// Clean expired codes every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of verificationCodes) {
    if (now > v.expires) verificationCodes.delete(k);
  }
}, 300000);

// Forgot password — send verification code to QQ email
app.post('/api/auth/forgot-password', authLimiter, [
  body('username').isString().trim().matches(USERNAME_RE).withMessage('用户名格式不正确'),
  body('qqEmail').isString().trim().matches(QQ_EMAIL_RE).withMessage('请输入正确的QQ邮箱'),
], async (req, res) => {
  if (!validateRequest(req, res)) return;
  try {
    const username = normalizeUsername(req.body.username);
    const qqEmail = normalizeQQEmail(req.body.qqEmail);

    const user = dbGet('SELECT id, qq_email FROM users WHERE username = ?', [username]);
    if (!user) {
      return res.status(404).json({ error: '用户名不存在' });
    }
    if (!user.qq_email || user.qq_email !== qqEmail) {
      return res.status(400).json({ error: 'QQ邮箱与绑定的邮箱不匹配' });
    }

    // Check rate limit for this username
    const existing = verificationCodes.get(username);
    if (existing && existing.requests >= 3 && Date.now() < existing.expires) {
      return res.status(429).json({ error: '请求过于频繁，请10分钟后重试' });
    }

    const code = generateCode();
    verificationCodes.set(username, { code, expires: Date.now() + 600000, requests: (existing?.requests || 0) + 1, failures: 0 });

    if (hasSmtpConfig()) {
      try {
        await sendVerificationEmail(qqEmail, code);
        return res.json({ message: '验证码已发送到QQ邮箱', ...(isProduction ? {} : { devCode: code }) });
      } catch (mailErr) {
        verificationCodes.delete(username);
        console.error('Verification email error:', mailErr);
        return res.status(502).json({ error: '验证码邮件发送失败，请稍后重试或检查邮箱服务配置' });
      }
    }

    if (isProduction) {
      verificationCodes.delete(username);
      return res.status(503).json({ error: '验证码邮件服务未配置，请联系管理员' });
    }

    res.json({ message: '验证码已生成', devCode: code, note: 'SMTP未配置，验证码直接显示' });
  } catch (err) {
    console.error('Forgot password error:', err);
    res.status(500).json({ error: '服务器错误' });
  }
});

// Reset password — verify code and set new password


// ── Admin: Clean up duplicate QQ email bindings (one-time) ──
app.post('/api/admin/cleanup-dup-qq', requireAdminToken, (req, res) => {
  try {
    // Find all users with QQ emails that appear more than once
    const dups = dbAll('SELECT qq_email, COUNT(*) as cnt FROM users WHERE qq_email != \'\' GROUP BY qq_email HAVING cnt > 1');
    let cleaned = 0;
    for (const row of dups) {
      // Keep the first user's binding, clear the rest
      const users = dbAll('SELECT id FROM users WHERE qq_email = ? ORDER BY id ASC', [row.qq_email]);
      for (let i = 1; i < users.length; i++) {
        dbRun("UPDATE users SET qq_email = '', updated_at = datetime('now') WHERE id = ?", [users[i].id]);
        cleaned++;
      }
    }
    res.json({ message: '清理完成', removedDuplicates: cleaned, duplicateEmails: dups.length });
  } catch (err) {
    res.status(500).json({ error: '清理失败' });
  }
});
app.post('/api/auth/reset-password', authLimiter, [
  body('username').isString().trim().matches(USERNAME_RE).withMessage('用户名格式不正确'),
  body('code').isString().trim().matches(/^\d{6}$/).withMessage('请输入6位验证码'),
  body('newPassword').isString().isLength({ min: 8, max: 100 }).withMessage('新密码至少8字符'),
], async (req, res) => {
  if (!validateRequest(req, res)) return;
  try {
    const username = normalizeUsername(req.body.username);
    const code = normalizeString(req.body.code, 6);
    const newPassword = req.body.newPassword;

    const stored = verificationCodes.get(username);
    if (!stored || Date.now() > stored.expires) {
      return res.status(400).json({ error: '验证码已过期，请重新获取' });
    }
    if ((stored.failures || 0) >= 5) {
      verificationCodes.delete(username);
      return res.status(429).json({ error: '验证码错误次数过多，请重新获取' });
    }
    if (!timingSafeStringEqual(stored.code, code)) {
      stored.failures = (stored.failures || 0) + 1;
      return res.status(400).json({ error: '验证码错误' });
    }

    const hashed = await bcrypt.hash(newPassword, 12);
    dbRun("UPDATE users SET password = ?, updated_at = datetime('now') WHERE username = ?", [hashed, username]);
    
    verificationCodes.delete(username);
    res.json({ message: '密码已重置，请使用新密码登录' });
  } catch (err) {
    console.error('Reset password error:', err);
    res.status(500).json({ error: '服务器错误' });
  }
});
app.post('/api/auth/change-password', auth, [
  body('oldPassword').isString().isLength({ min: 1 }),
  body('newPassword').isString().isLength({ min: 8, max: 100 }).withMessage('新密码至少8个字符'),
], async (req, res) => {
  if (!validateRequest(req, res)) return;
  try {
    const user = dbGet('SELECT * FROM users WHERE id = ?', [req.userId]);
    if (!user) return res.status(404).json({ error: '用户不存在' });

    const match = await bcrypt.compare(req.body.oldPassword, user.password);
    if (!match) return res.status(401).json({ error: '原密码错误' });

    const hashed = await bcrypt.hash(req.body.newPassword, 12);
    dbRun("UPDATE users SET password = ?, updated_at = datetime('now') WHERE id = ?", [hashed, req.userId]);
    res.json({ message: '密码已修改' });
  } catch (err) {
    res.status(500).json({ error: '服务器错误' });
  }
});

// DeepSeek proxy — avoids browser CORS failures on Netlify static frontend.
app.post('/api/ai/models', aiLimiter, [
  body('apiKey').isString().trim().matches(DEEPSEEK_KEY_RE).withMessage('请填写有效的 DeepSeek API Key'),
], async (req, res) => {
  if (!validateRequest(req, res)) return;
  const apiKey = String(req.body?.apiKey || '').trim();
  if (!validateDeepSeekKey(apiKey)) return res.status(400).json({ error: '请填写有效的 DeepSeek API Key' });

  try {
    const upstream = await fetchWithTimeout('https://api.deepseek.com/v1/models', {
      headers: { Authorization: `Bearer ${apiKey}` },
    }, 15000);
    const text = await upstream.text();
    res.status(upstream.status).type(upstream.headers.get('content-type') || 'application/json').send(text);
  } catch (err) {
    console.error('DeepSeek models proxy error:', err);
    res.status(502).json({ error: '无法连接 DeepSeek，请稍后重试或检查服务器网络' });
  }
});

app.post('/api/ai/chat', auth, aiLimiter, [
  body('apiKey').isString().trim().matches(DEEPSEEK_KEY_RE).withMessage('请先配置有效的 DeepSeek API Key'),
  body('model').optional().isString().trim().isLength({ min: 1, max: 60 }).withMessage('模型名称不正确'),
  body('messages').isArray({ min: 1, max: 20 }).withMessage('对话内容不正确'),
], async (req, res) => {
  if (!validateRequest(req, res)) return;
  const apiKey = String(req.body?.apiKey || '').trim();
  const model = String(req.body?.model || 'deepseek-chat').trim();
  const messages = normalizeMessages(req.body?.messages);
  const temperature = clampNumber(req.body?.temperature, 0.7, 0, 2);
  const max_tokens = Math.round(clampNumber(req.body?.max_tokens, 4096, 1, 8192));

  if (!validateDeepSeekKey(apiKey)) return res.status(400).json({ error: '请先配置有效的 DeepSeek API Key' });
  if (!ALLOWED_MODELS.has(model)) return res.status(400).json({ error: '模型不在允许列表内' });
  if (!messages) return res.status(400).json({ error: '对话内容过长或格式不正确' });

  try {
    const upstream = await fetchWithTimeout('https://api.deepseek.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify({ model, messages, temperature, max_tokens }),
    }, 60000);
    const text = await upstream.text();
    res.status(upstream.status).type(upstream.headers.get('content-type') || 'application/json').send(text);
  } catch (err) {
    console.error('DeepSeek chat proxy error:', err);
    res.status(502).json({ error: 'AI 服务暂时不可达，请检查后端部署网络或稍后重试' });
  }
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', uptime: process.uptime() });
});

app.use('/api', (req, res) => {
  res.status(404).json({ error: '接口不存在' });
});

// Static files — local dev only unless explicitly enabled.
if (!isProduction || process.env.SERVE_STATIC === 'true') {
  app.use(express.static(path.join(__dirname, '..', 'cloudflare-deploy')));
  app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'cloudflare-deploy', 'index.html'));
  });
}

app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: '服务器错误' });
});

// ── Start ───────────────────────────────────────────
await initDB();
app.listen(PORT, '0.0.0.0', () => {
  console.log(`冰出行服务器运行中 http://0.0.0.0:${PORT}`);
});
