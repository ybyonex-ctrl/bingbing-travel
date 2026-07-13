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
const DB_PATH = path.resolve(process.env.DB_PATH || path.join(process.env.DATA_DIR || path.join(__dirname, 'data'), 'bbuser.db'));
const STATIC_DIR = path.resolve(process.env.STATIC_DIR || path.join(__dirname, 'netlify-deploy'));
const USERNAME_RE = /^[\p{L}\p{N}_-]{3,30}$/u;
const QQ_EMAIL_RE = /^\d{5,12}@qq\.com$/;
const DEEPSEEK_KEY_RE = /^sk-[A-Za-z0-9_-]{20,200}$/;
const DEEPSEEK_API_BASE = String(process.env.DEEPSEEK_API_BASE || 'https://api.deepseek.com').replace(/\/+$/, '');
const DEEPSEEK_MODELS_URL = `${DEEPSEEK_API_BASE}/models`;
const DEEPSEEK_CHAT_URL = `${DEEPSEEK_API_BASE}/chat/completions`;
const ALLOWED_MODELS = new Set(['deepseek-v4-flash', 'deepseek-v4-pro', 'deepseek-chat', 'deepseek-reasoner']);
const DEEPSEEK_MODELS_TIMEOUT_MS = parseDurationMs(process.env.DEEPSEEK_MODELS_TIMEOUT_MS, 20000, 5000, 60000);
const DEEPSEEK_CHAT_TIMEOUT_MS = parseDurationMs(process.env.DEEPSEEK_CHAT_TIMEOUT_MS, 180000, 60000, 300000);
const UPSTREAM_RESPONSE_LIMIT_BYTES = parseInteger(process.env.UPSTREAM_RESPONSE_LIMIT_BYTES, 2 * 1024 * 1024, 64 * 1024, 8 * 1024 * 1024);
const TRUST_PROXY_HOPS = parseInteger(process.env.TRUST_PROXY_HOPS, 1, 0, 10);
const GLOBAL_RATE_LIMIT_MAX = parseInteger(process.env.GLOBAL_RATE_LIMIT_MAX, 240, 30, 5000);
const AUTH_RATE_LIMIT_MAX = parseInteger(process.env.AUTH_RATE_LIMIT_MAX, 15, 3, 200);
const PASSWORD_RESET_RATE_LIMIT_MAX = parseInteger(process.env.PASSWORD_RESET_RATE_LIMIT_MAX, 6, 2, 100);
const ADMIN_RATE_LIMIT_MAX = parseInteger(process.env.ADMIN_RATE_LIMIT_MAX, 5, 1, 50);
const AI_IP_RATE_LIMIT_MAX = parseInteger(process.env.AI_IP_RATE_LIMIT_MAX, 24, 2, 500);
const AI_USER_RATE_LIMIT_MAX = parseInteger(process.env.AI_USER_RATE_LIMIT_MAX, 16, 1, 500);
const AI_DAILY_QUOTA = parseInteger(process.env.AI_DAILY_QUOTA, 60, 1, 10000);
const AI_USER_CONCURRENCY = parseInteger(process.env.AI_USER_CONCURRENCY, 1, 1, 10);
const AI_GLOBAL_CONCURRENCY = parseInteger(process.env.AI_GLOBAL_CONCURRENCY, 8, 1, 100);
const AI_MAX_TOKENS = parseInteger(process.env.AI_MAX_TOKENS, 4096, 512, 8192);
const REQUEST_BODY_LIMIT = parseBodyLimit(process.env.REQUEST_BODY_LIMIT || '256kb');
const truthyValues = new Set(['1', 'true', 'yes', 'on']);
const GEO_BLOCK_ENABLED = truthyValues.has(String(process.env.GEO_BLOCK_ENABLED || '').trim().toLowerCase());
const GEO_REQUIRE_COUNTRY_HEADER_FOR_ADMIN = truthyValues.has(String(process.env.GEO_REQUIRE_COUNTRY_HEADER_FOR_ADMIN || '').trim().toLowerCase());
const ALLOWED_COUNTRIES = parseCountrySet(process.env.ALLOWED_COUNTRIES);
const BLOCKED_COUNTRIES = parseCountrySet(process.env.BLOCKED_COUNTRIES);
const ADMIN_IP_ALLOWLIST = new Set(String(process.env.ADMIN_IP_ALLOWLIST || '').split(',').map(normalizeIp).filter(Boolean));
const DEFAULT_DEV_ALLOWED_ORIGINS = [
  'http://localhost:8787',
  'http://127.0.0.1:8787',
  'http://localhost:3001',
  'http://127.0.0.1:3001',
  'http://localhost:5173',
  'http://127.0.0.1:5173',
  'http://localhost:4173',
  'http://127.0.0.1:4173',
  'http://localhost:5500',
  'http://127.0.0.1:5500',
  'http://localhost:8338',
  'http://127.0.0.1:8338',
  'http://localhost:8339',
  'http://127.0.0.1:8339',
];
const ALLOW_FILE_ORIGIN = truthyValues.has(String(process.env.ALLOW_FILE_ORIGIN || '').trim().toLowerCase());
const configuredOrigins = new Set([
  // Production callers must be explicitly listed in ALLOWED_ORIGINS. Do not
  // trust every Netlify/Cloudflare subdomain: those domains host third-party
  // sites too.
  ...(!isProduction ? DEFAULT_DEV_ALLOWED_ORIGINS : []),
  ...String(process.env.ALLOWED_ORIGINS || '')
    .split(',')
    .map(normalizeConfiguredOrigin)
    .filter(Boolean),
]);

function parseInteger(value, fallback, min, max) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, Math.round(n)));
}

function parseDurationMs(value, fallback, min, max) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, Math.round(n)));
}

function parseBodyLimit(value) {
  const match = String(value || '').trim().toLowerCase().match(/^(\d{1,4})(kb|mb)$/);
  if (!match) return '256kb';
  const bytes = Number(match[1]) * (match[2] === 'mb' ? 1024 * 1024 : 1024);
  return `${Math.max(32, Math.min(1024, Math.round(bytes / 1024)))}kb`;
}

function parseCountrySet(value) {
  return new Set(String(value || '')
    .split(',')
    .map((country) => country.trim().toUpperCase())
    .filter((country) => /^[A-Z]{2}$/.test(country)));
}

function normalizeConfiguredOrigin(value) {
  const raw = String(value || '').trim();
  if (!raw || raw === '*') return '';
  try {
    const url = new URL(raw);
    return (url.protocol === 'http:' || url.protocol === 'https:') ? url.origin : '';
  } catch {
    return '';
  }
}

function normalizeIp(value) {
  const raw = String(value || '').trim().toLowerCase();
  if (!raw) return '';
  const withoutMappedPrefix = raw.startsWith('::ffff:') ? raw.slice(7) : raw;
  return withoutMappedPrefix.replace(/^\[|\]$/g, '').split('%')[0];
}

function isAllowedOrigin(origin) {
  if (!origin) return true;
  if (origin === 'null') return !isProduction && ALLOW_FILE_ORIGIN;
  if (!isProduction) {
    try {
      const url = new URL(origin);
      if ((url.protocol === 'http:' || url.protocol === 'https:') && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)) return true;
    } catch {
      return false;
    }
  }
  return configuredOrigins.has(origin);
}

function resolveJwtSecret() {
  const configuredSecret = process.env.JWT_SECRET || '';
  if (!isProduction) return configuredSecret || DEFAULT_DEV_JWT_SECRET;

  const uniqueChars = new Set(configuredSecret).size;
  if (configuredSecret && configuredSecret !== DEFAULT_DEV_JWT_SECRET && configuredSecret.length >= 48 && uniqueChars >= 12) {
    return configuredSecret;
  }

  throw new Error('Production startup blocked: JWT_SECRET must be a unique random secret with at least 48 characters.');
}

const JWT_SECRET = resolveJwtSecret();
const SECURITY_LOG_SALT = process.env.SECURITY_LOG_SALT || (isProduction ? JWT_SECRET : crypto.randomBytes(32).toString('hex'));

function resolveAdminToken() {
  const token = String(process.env.ADMIN_TOKEN || '');
  if (!token) return '';
  if (token.length >= 32 && new Set(token).size >= 10) return token;
  console.warn(JSON.stringify({ level: 'warn', event: 'admin_token_disabled', reason: 'missing_entropy_or_length' }));
  return '';
}

const ADMIN_TOKEN = resolveAdminToken();

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
    token_version INTEGER NOT NULL DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
  )`);
  // Lightweight migration for databases created before token invalidation was
  // introduced. Existing users start at version 0 and are signed out once.
  const userColumns = dbAll('PRAGMA table_info(users)').map((column) => column.name);
  if (!userColumns.includes('token_version')) {
    db.run('ALTER TABLE users ADD COLUMN token_version INTEGER NOT NULL DEFAULT 0');
  }
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

function fingerprint(value) {
  return crypto.createHmac('sha256', SECURITY_LOG_SALT).update(String(value || 'unknown')).digest('hex').slice(0, 12);
}

function clientIp(req) {
  return normalizeIp(req.ip || req.socket?.remoteAddress || 'unknown');
}

function requestCountry(req) {
  const value = req.get('cf-ipcountry') || req.get('x-vercel-ip-country') || req.get('cloudfront-viewer-country') || '';
  const country = String(value).trim().toUpperCase();
  return /^[A-Z]{2}$/.test(country) ? country : '';
}

function redactLogText(value) {
  return String(value ?? '')
    .replace(/sk-[A-Za-z0-9_-]{20,200}/gi, '[REDACTED_DEEPSEEK_KEY]')
    .replace(/Bearer\s+[A-Za-z0-9._~-]+/gi, 'Bearer [REDACTED]')
    .replace(/eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g, '[REDACTED_JWT]');
}

function sanitizeLogDetails(details) {
  const sanitized = {};
  for (const [key, value] of Object.entries(details || {})) {
    if (/(authorization|api.?key|token|secret|password|cookie)/i.test(key)) {
      sanitized[key] = '[REDACTED]';
    } else if (typeof value === 'string') {
      sanitized[key] = redactLogText(value).slice(0, 240);
    } else if (typeof value === 'number' || typeof value === 'boolean' || value == null) {
      sanitized[key] = value;
    }
  }
  return sanitized;
}

function securityLog(event, req, details = {}) {
  console.warn(JSON.stringify({
    level: 'warn',
    event,
    requestId: req?.requestId || '-',
    route: String(req?.originalUrl || '').split('?')[0].slice(0, 160),
    ipHash: fingerprint(clientIp(req)),
    userId: Number.isInteger(req?.userId) ? req.userId : undefined,
    country: requestCountry(req) || undefined,
    ...sanitizeLogDetails(details),
  }));
}

function logError(event, err, req) {
  console.error(JSON.stringify({
    level: 'error',
    event,
    requestId: req?.requestId || '-',
    route: String(req?.originalUrl || '').split('?')[0].slice(0, 160),
    ipHash: req ? fingerprint(clientIp(req)) : undefined,
    errorName: redactLogText(err?.name || 'Error').slice(0, 80),
    errorCode: redactLogText(err?.code || '').slice(0, 80) || undefined,
    ...(!isProduction ? { message: redactLogText(err?.message || err || '').slice(0, 240) } : {}),
  }));
}

function geoRiskGuard(req, res, next) {
  if (!GEO_BLOCK_ENABLED) return next();
  const country = requestCountry(req);
  const isAdminRoute = req.baseUrl.startsWith('/api/admin') || req.originalUrl.startsWith('/api/admin/');
  if (!country) {
    if (isAdminRoute && GEO_REQUIRE_COUNTRY_HEADER_FOR_ADMIN) {
      securityLog('geo_country_missing', req);
      return res.status(403).json({ error: '当前网络无法完成安全校验，请联系管理员' });
    }
    return next();
  }
  const blocked = BLOCKED_COUNTRIES.has(country) || (ALLOWED_COUNTRIES.size > 0 && !ALLOWED_COUNTRIES.has(country));
  if (!blocked) return next();
  securityLog('geo_request_blocked', req, { policy: ALLOWED_COUNTRIES.size > 0 ? 'allowlist' : 'blocklist' });
  return res.status(403).json({ error: '当前地区暂不支持此敏感操作' });
}

function rateLimitHandler(event, message) {
  return (req, res) => {
    securityLog(event, req);
    res.status(429).json({ error: message });
  };
}

// ── Express App ─────────────────────────────────────
const app = express();
app.disable('x-powered-by');
app.set('trust proxy', TRUST_PROXY_HOPS);
app.use((req, res, next) => {
  const incomingId = String(req.get('x-request-id') || '').trim();
  req.requestId = /^[A-Za-z0-9._:-]{8,80}$/.test(incomingId) ? incomingId : crypto.randomUUID();
  res.set('X-Request-ID', req.requestId);
  next();
});
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      baseUri: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      formAction: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", 'https://unpkg.com'],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com', 'https://unpkg.com'],
      fontSrc: ["'self'", 'data:', 'https://fonts.gstatic.com'],
      imgSrc: ["'self'", 'data:', 'blob:', 'https:'],
      connectSrc: ["'self'", 'https://bingbing-travel-production.up.railway.app'],
      frameSrc: ["'self'", 'blob:'],
      workerSrc: ["'self'", 'blob:'],
      upgradeInsecureRequests: isProduction ? [] : null,
    },
  },
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: { policy: 'cross-origin' },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
}));
app.use(cors({
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-DeepSeek-API-Key'],
  origin(origin, callback) {
    if (isAllowedOrigin(origin)) {
      return callback(null, true);
    }
    return callback(new Error(origin === 'null' ? 'CORS null origin blocked' : 'CORS origin blocked'));
  },
}));
// Capture the user's BYOK credential, then remove the raw header before any
// downstream application logging can accidentally serialize request headers.
app.use('/api/ai', (req, res, next) => {
  const apiKey = String(req.get('x-deepseek-api-key') || '').trim();
  Object.defineProperty(req, 'deepSeekApiKey', {
    value: apiKey,
    enumerable: false,
    writable: false,
  });
  delete req.headers['x-deepseek-api-key'];
  res.set({
    'Cache-Control': 'no-store, max-age=0',
    Pragma: 'no-cache',
  });
  next();
});
app.use(['/api/auth', '/api/ai', '/api/admin'], geoRiskGuard);
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: GLOBAL_RATE_LIMIT_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  handler: rateLimitHandler('global_rate_limited', '访问过于频繁，请稍后再试'),
}));
app.use(express.json({ limit: REQUEST_BODY_LIMIT, strict: true, type: 'application/json' }));
// Reject the legacy body credential path by removing it before validation and
// proxying. DeepSeek keys are accepted only through the short-lived BYOK header.
app.use('/api/ai', (req, res, next) => {
  if (req.body && Object.prototype.hasOwnProperty.call(req.body, 'apiKey')) {
    delete req.body.apiKey;
  }
  next();
});
app.use((err, req, res, next) => {
  if (err?.type === 'entity.too.large') {
    securityLog('request_body_too_large', req);
    return res.status(413).json({ error: `请求内容过大，请精简后重试（上限 ${REQUEST_BODY_LIMIT}）` });
  }
  if (err instanceof SyntaxError && 'body' in err) {
    return res.status(400).json({ error: '请求内容格式不正确，请检查后重试' });
  }
  if (err?.message === 'CORS origin blocked' || err?.message === 'CORS null origin blocked') {
    const origin = req.headers.origin || '';
    securityLog('cors_origin_blocked', req, { originHash: fingerprint(origin) });
    const message = origin === 'null'
      ? '本地 file:// 页面来源未被允许。请用本地 HTTP 服务打开页面，或在后端设置 ALLOW_FILE_ORIGIN=true 后重新部署。'
      : '来源不允许';
    return res.status(403).json({ error: message });
  }
  return next(err);
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: AUTH_RATE_LIMIT_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  handler: rateLimitHandler('auth_ip_rate_limited', '尝试次数过多，请15分钟后再试'),
});

const authAccountLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: AUTH_RATE_LIMIT_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => `account:${fingerprint(normalizeUsername(req.body?.username))}`,
  handler: rateLimitHandler('auth_account_rate_limited', '此账户尝试次数过多，请15分钟后再试'),
});

const passwordResetLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: PASSWORD_RESET_RATE_LIMIT_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  handler: rateLimitHandler('password_reset_ip_rate_limited', '密码找回请求过多，请15分钟后再试'),
});

const passwordResetAccountLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: PASSWORD_RESET_RATE_LIMIT_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => `reset:${fingerprint(normalizeUsername(req.body?.username))}`,
  handler: rateLimitHandler('password_reset_account_rate_limited', '此账户的密码找回请求过多，请15分钟后再试'),
});

const adminLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: ADMIN_RATE_LIMIT_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  handler: rateLimitHandler('admin_rate_limited', 'Too many requests'),
});

const aiIpLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: AI_IP_RATE_LIMIT_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  handler: rateLimitHandler('ai_ip_rate_limited', 'AI 请求过于频繁，请稍后再试'),
});

const aiUserLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: AI_USER_RATE_LIMIT_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => `user:${req.userId}`,
  handler: rateLimitHandler('ai_user_rate_limited', '你的 AI 请求过于频繁，请稍后再试'),
});

const aiDailyUsage = new Map();
const aiConcurrencyByUser = new Map();
let aiGlobalConcurrency = 0;

function aiDailyQuota(req, res, next) {
  const userKey = String(req.userId);
  const day = new Date().toISOString().slice(0, 10);
  const current = aiDailyUsage.get(userKey);
  const bucket = current?.day === day ? current : { day, count: 0 };
  if (bucket.count >= AI_DAILY_QUOTA) {
    const nextDay = Date.parse(`${day}T00:00:00.000Z`) + 24 * 60 * 60 * 1000;
    res.set('Retry-After', String(Math.max(1, Math.ceil((nextDay - Date.now()) / 1000))));
    securityLog('ai_daily_quota_exceeded', req);
    return res.status(429).json({ error: '今天的 AI 生成额度已用完，请明天再试' });
  }
  bucket.count += 1;
  aiDailyUsage.set(userKey, bucket);
  res.set('X-AI-Quota-Remaining', String(Math.max(0, AI_DAILY_QUOTA - bucket.count)));
  next();
}

function aiConcurrencyGuard(req, res, next) {
  const userKey = String(req.userId);
  const userCount = aiConcurrencyByUser.get(userKey) || 0;
  if (aiGlobalConcurrency >= AI_GLOBAL_CONCURRENCY || userCount >= AI_USER_CONCURRENCY) {
    securityLog('ai_concurrency_rejected', req, { scope: aiGlobalConcurrency >= AI_GLOBAL_CONCURRENCY ? 'global' : 'user' });
    res.set('Retry-After', '15');
    return res.status(429).json({ error: '已有行程正在生成，请等待完成或取消后再试' });
  }

  aiGlobalConcurrency += 1;
  aiConcurrencyByUser.set(userKey, userCount + 1);
  let released = false;
  const release = () => {
    if (released) return;
    released = true;
    aiGlobalConcurrency = Math.max(0, aiGlobalConcurrency - 1);
    const nextCount = Math.max(0, (aiConcurrencyByUser.get(userKey) || 1) - 1);
    if (nextCount === 0) aiConcurrencyByUser.delete(userKey);
    else aiConcurrencyByUser.set(userKey, nextCount);
  };
  res.once('finish', release);
  res.once('close', release);
  next();
}

// ── Middleware ───────────────────────────────────────
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: '未登录' });
  }
  try {
    const decoded = jwt.verify(header.slice(7), JWT_SECRET);
    if (!Number.isInteger(decoded.id) || !Number.isInteger(decoded.tokenVersion)) {
      return res.status(401).json({ error: '登录已过期，请重新登录' });
    }
    const user = dbGet('SELECT id, username, token_version FROM users WHERE id = ?', [decoded.id]);
    if (!user || decoded.tokenVersion !== user.token_version) {
      return res.status(401).json({ error: '登录已过期，请重新登录' });
    }
    req.userId = user.id;
    req.username = user.username;
    next();
  } catch {
    return res.status(401).json({ error: '登录已过期，请重新登录' });
  }
}

function issueAuthToken(user) {
  return jwt.sign({
    id: user.id,
    username: user.username,
    tokenVersion: Number(user.token_version) || 0,
  }, JWT_SECRET, { expiresIn: '7d' });
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
  if (ADMIN_IP_ALLOWLIST.size > 0 && !ADMIN_IP_ALLOWLIST.has(clientIp(req))) {
    securityLog('admin_ip_blocked', req);
    return res.status(404).json({ error: 'Not found' });
  }
  const header = req.headers.authorization || '';
  const bearer = header.startsWith('Bearer ') ? header.slice(7) : '';
  const token = req.get('x-admin-token') || bearer;
  if (!timingSafeStringEqual(token, ADMIN_TOKEN)) {
    securityLog('admin_auth_failed', req);
    return res.status(isProduction ? 404 : 403).json({ error: isProduction ? 'Not found' : 'Forbidden' });
  }
  next();
}

function validateDeepSeekKey(apiKey) {
  return DEEPSEEK_KEY_RE.test(apiKey);
}

function readDeepSeekKey(req) {
  return String(req.deepSeekApiKey || '').trim();
}

function requireDeepSeekKey(req, res, next) {
  if (!validateDeepSeekKey(readDeepSeekKey(req))) {
    return res.status(400).json({ error: '请填写你自己的有效 DeepSeek API Key' });
  }
  next();
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
  let totalLength = 0;
  let systemMessages = 0;
  for (let index = 0; index < messages.length; index += 1) {
    const msg = messages[index];
    if (!msg || typeof msg !== 'object' || Array.isArray(msg)) return null;
    const role = String(msg.role || '').trim();
    const content = typeof msg.content === 'string' ? msg.content.trim() : '';
    if (!roles.has(role) || content.length < 1 || content.length > 12000) return null;
    totalLength += content.length;
    if (totalLength > 32000) return null;
    if (role === 'system') {
      systemMessages += 1;
      if (systemMessages > 1 || index !== 0) return null;
    }
    clean.push({ role, content });
  }
  return clean;
}

async function readResponseText(response, maxBytes, controller) {
  if (!response.body) return '';
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      controller.abort();
      const err = new Error('Upstream response exceeded the configured limit');
      err.code = 'UPSTREAM_RESPONSE_TOO_LARGE';
      throw err;
    }
    chunks.push(Buffer.from(value));
  }
  return Buffer.concat(chunks).toString('utf8');
}

async function fetchTextWithTimeout(url, options, timeoutMs = 30000, req, res) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const onAborted = () => controller.abort();
  const onClosed = () => {
    if (!res?.writableEnded) controller.abort();
  };
  req?.once('aborted', onAborted);
  res?.once('close', onClosed);
  try {
    const response = await fetch(url, { ...options, signal: controller.signal });
    const text = await readResponseText(response, UPSTREAM_RESPONSE_LIMIT_BYTES, controller);
    return { response, text };
  } finally {
    clearTimeout(timer);
    req?.off('aborted', onAborted);
    res?.off('close', onClosed);
  }
}

function normalizeDeepSeekModel(model) {
  if (model === 'deepseek-chat') {
    return { model: 'deepseek-v4-flash', thinking: { type: 'disabled' } };
  }
  if (model === 'deepseek-reasoner') {
    return { model: 'deepseek-v4-flash', thinking: { type: 'enabled' }, reasoning_effort: 'high' };
  }
  return { model, thinking: { type: 'disabled' } };
}

function deepSeekErrorMessage(status, text) {
  let payload;
  try {
    payload = JSON.parse(text);
  } catch {
    payload = null;
  }
  const raw = payload?.error;
  const upstreamMessage = typeof raw === 'string'
    ? raw
    : raw?.message || raw?.code || (typeof payload?.message === 'string' ? payload.message : '');

  if (status === 400) return upstreamMessage || 'DeepSeek 请求参数不被接受，请检查模型、JSON 输出或 token 限制。';
  if (status === 401 || status === 403) return 'DeepSeek API Key 无效、权限不足或账户未开通该模型。';
  if (status === 402) return 'DeepSeek 账户余额不足或额度不可用，请检查控制台余额。';
  if (status === 404) return 'DeepSeek 模型或接口不存在，请切换模型后重试。';
  if (status === 429) return 'DeepSeek 请求过于频繁或并发受限，请稍后再试。';
  if (status >= 500) return 'DeepSeek 服务暂时不可用，请稍后重试。';
  return upstreamMessage || `DeepSeek 请求失败 HTTP ${status}`;
}

function sendDeepSeekResponse(res, upstream, text) {
  const contentType = upstream.headers.get('content-type') || 'application/json; charset=utf-8';
  if (!upstream.ok) {
    return res.status(upstream.status).json({ error: deepSeekErrorMessage(upstream.status, text) });
  }
  return res.status(upstream.status).type(contentType).send(text);
}

// ── Routes ──────────────────────────────────────────

// Register
app.post('/api/auth/register', authLimiter, authAccountLimiter, [
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

    const user = dbGet('SELECT id, username, token_version FROM users WHERE username = ?', [username]);
    const token = issueAuthToken(user);
    res.json({ token, username, userId: user.id });
  } catch (err) {
    logError('register_failed', err, req);
    res.status(500).json({ error: '服务器暂时无法完成注册，请稍后重试' });
  }
});

// Login
app.post('/api/auth/login', authLimiter, authAccountLimiter, [
  body('username').isString().trim().matches(USERNAME_RE).withMessage('用户名格式不正确'),
  body('password').isString().isLength({ min: 1, max: 100 }).withMessage('请输入密码'),
], async (req, res) => {
  if (!validateRequest(req, res)) return;
  try {
    const username = normalizeUsername(req.body.username);
    const password = req.body.password;

    const user = dbGet('SELECT * FROM users WHERE username = ?', [username]);
    if (!user) {
      securityLog('auth_login_failed', req, { accountHash: fingerprint(username) });
      return res.status(401).json({ error: '用户名或密码错误' });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      securityLog('auth_login_failed', req, { accountHash: fingerprint(username) });
      return res.status(401).json({ error: '用户名或密码错误' });
    }

    const token = issueAuthToken(user);
    res.json({ token, username: user.username, userId: user.id, qqEmail: user.qq_email || '' });
  } catch (err) {
    logError('login_failed', err, req);
    res.status(500).json({ error: '服务器暂时无法登录，请稍后重试' });
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
app.post('/api/user/bind-qq', auth, authLimiter, [
  body('qqEmail').isString().trim().matches(QQ_EMAIL_RE).withMessage('请输入正确的QQ邮箱格式'),
], (req, res) => {
  if (!validateRequest(req, res)) return;
  try {
    const qqEmail = normalizeQQEmail(req.body.qqEmail);

    // Check: is this QQ email already bound to another user?
    const existing = dbGet('SELECT id, username FROM users WHERE qq_email = ? AND id != ?', [qqEmail, req.userId]);
    if (existing) {
      return res.status(409).json({ error: '此 QQ 邮箱已被其他账户绑定，请检查后重试' });
    }

    dbRun("UPDATE users SET qq_email = ?, updated_at = datetime('now') WHERE id = ?", [qqEmail, req.userId]);
    res.json({ qqEmail, message: '绑定成功' });
  } catch (err) {
    res.status(500).json({ error: '服务器错误' });
  }
});

// Store verification codes in memory (with expiry)
const verificationCodes = new Map(); // username -> {code, expires, requests, failures}
const MAX_VERIFICATION_ENTRIES = 10000;

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
  const today = new Date().toISOString().slice(0, 10);
  for (const [key, bucket] of aiDailyUsage) {
    if (bucket.day !== today) aiDailyUsage.delete(key);
  }
}, 300000);

// Forgot password — send verification code to QQ email
app.post('/api/auth/forgot-password', passwordResetLimiter, passwordResetAccountLimiter, [
  body('username').isString().trim().matches(USERNAME_RE).withMessage('用户名格式不正确'),
  body('qqEmail').isString().trim().matches(QQ_EMAIL_RE).withMessage('请输入正确的QQ邮箱'),
], async (req, res) => {
  if (!validateRequest(req, res)) return;
  try {
    const username = normalizeUsername(req.body.username);
    const qqEmail = normalizeQQEmail(req.body.qqEmail);
    const genericMessage = '若账户信息匹配，验证码会发送到绑定的 QQ 邮箱';

    if (isProduction && !hasSmtpConfig()) {
      return res.status(503).json({ error: '密码找回服务暂不可用，请稍后再试' });
    }

    const user = dbGet('SELECT id, qq_email FROM users WHERE username = ?', [username]);
    if (!user || !user.qq_email || user.qq_email !== qqEmail) {
      return res.status(202).json({ message: genericMessage });
    }

    // Check rate limit for this username
    const existing = verificationCodes.get(username);
    if (existing && existing.requests >= 3 && Date.now() < existing.expires) {
      return res.status(429).json({ error: '请求过于频繁，请10分钟后重试' });
    }

    const code = generateCode();
    if (verificationCodes.size >= MAX_VERIFICATION_ENTRIES && !verificationCodes.has(username)) {
      const oldestKey = verificationCodes.keys().next().value;
      if (oldestKey) verificationCodes.delete(oldestKey);
    }
    verificationCodes.set(username, { code, expires: Date.now() + 600000, requests: (existing?.requests || 0) + 1, failures: 0 });

    if (hasSmtpConfig()) {
      try {
        await sendVerificationEmail(qqEmail, code);
        return res.status(202).json({ message: genericMessage, ...(isProduction ? {} : { devCode: code }) });
      } catch (mailErr) {
        verificationCodes.delete(username);
        logError('verification_email_failed', mailErr, req);
        if (isProduction) return res.status(202).json({ message: genericMessage });
        return res.status(502).json({ error: '验证码邮件发送失败，请稍后重试或检查邮箱服务配置' });
      }
    }

    if (isProduction) {
      verificationCodes.delete(username);
      return res.status(503).json({ error: '验证码邮件服务未配置，请联系管理员' });
    }

    res.json({ message: '验证码已生成', devCode: code, note: 'SMTP未配置，验证码直接显示' });
  } catch (err) {
    logError('forgot_password_failed', err, req);
    res.status(500).json({ error: '密码找回服务暂不可用，请稍后再试' });
  }
});

// Reset password — verify code and set new password


// ── Admin: Clean up duplicate QQ email bindings (one-time) ──
app.post('/api/admin/cleanup-dup-qq', adminLimiter, requireAdminToken, (req, res) => {
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
    logError('admin_cleanup_failed', err, req);
    res.status(500).json({ error: '清理失败' });
  }
});
app.post('/api/auth/reset-password', passwordResetLimiter, passwordResetAccountLimiter, [
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
    dbRun("UPDATE users SET password = ?, token_version = token_version + 1, updated_at = datetime('now') WHERE username = ?", [hashed, username]);
    
    verificationCodes.delete(username);
    res.json({ message: '密码已重置，请使用新密码登录' });
  } catch (err) {
    logError('reset_password_failed', err, req);
    res.status(500).json({ error: '密码重置失败，请稍后重试' });
  }
});
app.post('/api/auth/change-password', auth, authLimiter, [
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
    dbRun("UPDATE users SET password = ?, token_version = token_version + 1, updated_at = datetime('now') WHERE id = ?", [hashed, req.userId]);
    res.json({ message: '密码已修改' });
  } catch (err) {
    logError('change_password_failed', err, req);
    res.status(500).json({ error: '密码修改失败，请稍后重试' });
  }
});

// DeepSeek BYOK proxy: each user supplies their own key. The server never stores
// the key and deliberately keeps it out of request bodies and application logs.
app.post('/api/ai/models', auth, aiIpLimiter, aiUserLimiter, requireDeepSeekKey, async (req, res) => {
  const apiKey = readDeepSeekKey(req);

  try {
    const { response: upstream, text } = await fetchTextWithTimeout(DEEPSEEK_MODELS_URL, {
      headers: { Authorization: `Bearer ${apiKey}` },
    }, DEEPSEEK_MODELS_TIMEOUT_MS, req, res);
    sendDeepSeekResponse(res, upstream, text);
  } catch (err) {
    logError('deepseek_models_failed', err, req);
    const status = err?.name === 'AbortError' ? 504 : 502;
    const message = err?.code === 'UPSTREAM_RESPONSE_TOO_LARGE'
      ? 'DeepSeek 返回内容过大，请稍后重试'
      : '无法连接 DeepSeek，请稍后重试或检查服务器网络';
    res.status(status).json({ error: message });
  }
});

app.post('/api/ai/chat', auth, aiIpLimiter, aiUserLimiter, requireDeepSeekKey, aiDailyQuota, aiConcurrencyGuard, [
  body('model').optional().isString().trim().isLength({ min: 1, max: 60 }).withMessage('模型名称不正确'),
  body('messages').isArray({ min: 1, max: 20 }).withMessage('对话内容不正确'),
], async (req, res) => {
  if (!validateRequest(req, res)) return;
  const apiKey = readDeepSeekKey(req);
  const model = String(req.body?.model || 'deepseek-chat').trim();
  const messages = normalizeMessages(req.body?.messages);
  const temperature = clampNumber(req.body?.temperature, 0.7, 0, 2);
  const max_tokens = Math.round(clampNumber(req.body?.max_tokens, AI_MAX_TOKENS, 1, AI_MAX_TOKENS));

  if (!ALLOWED_MODELS.has(model)) return res.status(400).json({ error: '模型不在允许列表内' });
  if (!messages) return res.status(400).json({ error: '对话内容过长或格式不正确' });

  try {
    const modelPayload = normalizeDeepSeekModel(model);
    const requestBody = {
      ...modelPayload,
      messages,
      temperature,
      max_tokens,
      stream: false,
      response_format: { type: 'json_object' },
    };
    const { response: upstream, text } = await fetchTextWithTimeout(DEEPSEEK_CHAT_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify(requestBody),
    }, DEEPSEEK_CHAT_TIMEOUT_MS, req, res);
    sendDeepSeekResponse(res, upstream, text);
  } catch (err) {
    logError('deepseek_chat_failed', err, req);
    const status = err?.name === 'AbortError' ? 504 : 502;
    const seconds = Math.round(DEEPSEEK_CHAT_TIMEOUT_MS / 1000);
    const message = err?.code === 'UPSTREAM_RESPONSE_TOO_LARGE'
      ? 'AI 返回内容过大，请减少行程天数或需求长度后重试'
      : status === 504
      ? `AI 生成超过 ${seconds} 秒仍未完成，请切换极速模型、减少天数或稍后重试。`
      : 'AI 服务暂时不可达，请检查后端部署网络或稍后重试';
    res.status(status).json({ error: message });
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
const shouldServeStatic = !isProduction || truthyValues.has(String(process.env.SERVE_STATIC || '').trim().toLowerCase());
if (shouldServeStatic) {
  const staticIndex = path.join(STATIC_DIR, 'index.html');
  if (!fs.existsSync(staticIndex)) {
    throw new Error(`Static frontend entrypoint not found: ${staticIndex}`);
  }
  app.use(express.static(STATIC_DIR));
  app.get('*', (req, res) => {
    res.sendFile(staticIndex);
  });
}

app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  logError('unhandled_request_error', err, req);
  res.status(500).json({ error: '服务暂时不可用，请稍后重试' });
});

// ── Start ───────────────────────────────────────────
if (isProduction && configuredOrigins.size === 0) {
  console.warn(JSON.stringify({ level: 'warn', event: 'allowed_origins_empty', effect: 'browser_cross_origin_requests_blocked' }));
}
if (GEO_BLOCK_ENABLED && ALLOWED_COUNTRIES.size === 0 && BLOCKED_COUNTRIES.size === 0) {
  console.warn(JSON.stringify({ level: 'warn', event: 'geo_policy_empty', effect: 'geo_filter_has_no_country_rules' }));
}
await initDB();
app.listen(PORT, '0.0.0.0', () => {
  console.log(`冰冰出行服务器运行中 http://0.0.0.0:${PORT}`);
});
