import { createServer } from 'node:http';
import { createReadStream, mkdirSync, readFileSync } from 'node:fs';
import { createHash, randomBytes, scryptSync, timingSafeEqual, createCipheriv, createDecipheriv } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { dirname, extname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = dirname(fileURLToPath(import.meta.url));
const DATA_DIR = resolve(process.env.NAMU_DATA_DIR || join(ROOT, 'data'));
const PORT = Number(process.env.NAMU_PORT || 4173);
const SESSION_MS = 8 * 60 * 60 * 1000;
const MAX_BODY = 25 * 1024 * 1024;
mkdirSync(DATA_DIR, { recursive: true });
const db = new DatabaseSync(join(DATA_DIR, 'namu.sqlite'));
db.exec(`PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, display_name TEXT NOT NULL,
  password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('owner','staff')),
  active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS app_state (id INTEGER PRIMARY KEY CHECK(id=1), data TEXT NOT NULL, updated_at TEXT NOT NULL, updated_by TEXT);
CREATE TABLE IF NOT EXISTS audit_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL,
  user_id TEXT, user_name TEXT NOT NULL, action TEXT NOT NULL,
  entity TEXT NOT NULL, entity_id TEXT, summary TEXT NOT NULL,
  before_json TEXT, after_json TEXT
);
CREATE INDEX IF NOT EXISTS audit_created_at_idx ON audit_events(created_at DESC);`);

const sessions = new Map();
const failedLogins = new Map();
const entityLabels = { students: '수강생', payments: '수납', ledger: '가계부', consultations: '상담' };
const entityNames = { students: 'name', payments: 'studentId', ledger: 'description', consultations: 'name' };
const emptyData = () => ({ students: [], payments: [], ledger: [], consultations: [], activity: [] });
const now = () => new Date().toISOString();
const id = prefix => `${prefix}${randomBytes(8).toString('hex')}`;

function hashPassword(password, salt = randomBytes(16)) {
  const derived = scryptSync(password, salt, 64);
  return `scrypt$${salt.toString('hex')}$${derived.toString('hex')}`;
}
function verifyPassword(password, saved) {
  const [scheme, saltHex, hashHex] = String(saved).split('$');
  if (scheme !== 'scrypt' || !saltHex || !hashHex) return false;
  const salt = Buffer.from(saltHex, 'hex');
  const expected = Buffer.from(hashHex, 'hex');
  const actual = scryptSync(password, salt, expected.length);
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}
function userPublic(user) {
  return { id: user.id, username: user.username, displayName: user.display_name, role: user.role };
}
function currentUser(req) {
  const match = /(?:^|;\s*)namu_session=([a-f0-9]+)/.exec(req.headers.cookie || '');
  if (!match) return null;
  const session = sessions.get(match[1]);
  if (!session || session.expiresAt < Date.now()) { sessions.delete(match[1]); return null; }
  const user = db.prepare('SELECT * FROM users WHERE id=? AND active=1').get(session.userId);
  if (!user) { sessions.delete(match[1]); return null; }
  session.expiresAt = Date.now() + SESSION_MS;
  return user;
}
function cookieHeader(token, maxAge = 28800) {
  return `namu_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAge}`;
}
function send(res, status, payload, headers = {}) {
  const body = payload === null ? '' : JSON.stringify(payload);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers });
  res.end(body);
}
function readBody(req) {
  return new Promise((resolveBody, reject) => {
    let size = 0; const chunks = [];
    req.on('data', chunk => { size += chunk.length; if (size > MAX_BODY) { reject(Object.assign(new Error('요청 파일이 너무 큽니다.'), { status: 413 })); req.destroy(); } else chunks.push(chunk); });
    req.on('end', () => { try { resolveBody(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')); } catch { reject(Object.assign(new Error('요청 형식이 올바르지 않습니다.'), { status: 400 })); } });
    req.on('error', reject);
  });
}
async function requireJson(req) { return readBody(req); }
function requireOwner(user, res) {
  if (user?.role === 'owner') return true;
  send(res, 403, { error: '원장 계정만 사용할 수 있는 기능입니다.' });
  return false;
}
function getData() {
  const row = db.prepare('SELECT data FROM app_state WHERE id=1').get();
  return row ? JSON.parse(row.data) : emptyData();
}
function getAudit(limit = 100) {
  return db.prepare('SELECT id, created_at AS createdAt, user_name AS userName, action, entity, entity_id AS entityId, summary, before_json AS beforeJson, after_json AS afterJson FROM audit_events ORDER BY id DESC LIMIT ?').all(limit);
}
function addAudit(user, action, entity, entityId, summary, before, after) {
  db.prepare('INSERT INTO audit_events(created_at,user_id,user_name,action,entity,entity_id,summary,before_json,after_json) VALUES(?,?,?,?,?,?,?,?,?)')
    .run(now(), user?.id || null, user?.display_name || 'NAMU', action, entity, entityId || null, summary, before ? JSON.stringify(before) : null, after ? JSON.stringify(after) : null);
}
function validateData(data) {
  if (!data || typeof data !== 'object') return false;
  return ['students', 'payments', 'ledger', 'consultations', 'activity'].every(key => Array.isArray(data[key]));
}
function saveData(data, user) {
  if (!validateData(data)) throw Object.assign(new Error('저장할 데이터 구조가 올바르지 않습니다.'), { status: 400 });
  if (Buffer.byteLength(JSON.stringify(data)) > 10 * 1024 * 1024) throw Object.assign(new Error('저장 데이터가 너무 큽니다.'), { status: 413 });
  const before = getData();
  db.exec('BEGIN IMMEDIATE');
  try {
    db.prepare('INSERT INTO app_state(id,data,updated_at,updated_by) VALUES(1,?,?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data,updated_at=excluded.updated_at,updated_by=excluded.updated_by')
      .run(JSON.stringify(data), now(), user.id);
    for (const collection of ['students', 'payments', 'ledger', 'consultations']) {
      const oldMap = new Map((before[collection] || []).map(item => [String(item.id), item]));
      const newMap = new Map((data[collection] || []).map(item => [String(item.id), item]));
      for (const key of new Set([...oldMap.keys(), ...newMap.keys()])) {
        const oldItem = oldMap.get(key), newItem = newMap.get(key);
        if (JSON.stringify(oldItem) === JSON.stringify(newItem)) continue;
        const action = !oldItem ? '추가' : !newItem ? '삭제' : '수정';
        const label = entityLabels[collection];
        const human = newItem || oldItem;
        const name = String(human?.[entityNames[collection]] || key).slice(0, 80);
        addAudit(user, action, label, key, `${label} ${action}: ${name}`, oldItem, newItem);
      }
    }
    db.exec('COMMIT');
  } catch (error) { db.exec('ROLLBACK'); throw error; }
}
function makeBackup(passphrase) {
  if (typeof passphrase !== 'string' || passphrase.length < 12) throw Object.assign(new Error('백업 암호는 12자 이상으로 설정해 주세요.'), { status: 400 });
  const salt = randomBytes(16), iv = randomBytes(12), key = scryptSync(passphrase, salt, 32);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const clear = Buffer.from(JSON.stringify({ format: 'NAMU-BACKUP', version: 1, createdAt: now(), data: getData(), audit: getAudit(10000) }));
  const ciphertext = Buffer.concat([cipher.update(clear), cipher.final()]);
  return { format: 'NAMU-ENCRYPTED-BACKUP', version: 1, salt: salt.toString('base64'), iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), ciphertext: ciphertext.toString('base64') };
}
function openBackup(passphrase, backup) {
  if (!backup || backup.format !== 'NAMU-ENCRYPTED-BACKUP' || backup.version !== 1) throw Object.assign(new Error('NAMU 백업 파일 형식이 아닙니다.'), { status: 400 });
  try {
    const key = scryptSync(passphrase, Buffer.from(backup.salt, 'base64'), 32);
    const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(backup.iv, 'base64'));
    decipher.setAuthTag(Buffer.from(backup.tag, 'base64'));
    const clear = Buffer.concat([decipher.update(Buffer.from(backup.ciphertext, 'base64')), decipher.final()]);
    const payload = JSON.parse(clear.toString('utf8'));
    if (payload.format !== 'NAMU-BACKUP' || payload.version !== 1 || !validateData(payload.data) || !Array.isArray(payload.audit)) throw new Error('invalid backup');
    return payload;
  } catch { throw Object.assign(new Error('암호가 틀렸거나 백업 파일이 손상되었습니다.'), { status: 400 }); }
}
function checkOrigin(req) {
  const origin = req.headers.origin;
  if (!origin) return true;
  try { const parsed = new URL(origin); return ['localhost', '127.0.0.1'].includes(parsed.hostname) && parsed.port === String(PORT); } catch { return false; }
}
const MIME = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.json': 'application/json; charset=utf-8' };
function serveFile(pathname, res) {
  const safe = pathname === '/' ? '/index.html' : pathname;
  if (!['/index.html', '/styles.css', '/auth.css', '/app.js'].includes(safe)) { res.writeHead(404); res.end('Not found'); return; }
  const file = join(ROOT, safe.slice(1));
  try {
    res.writeHead(200, { 'Content-Type': MIME[extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer' });
    createReadStream(file).pipe(res);
  } catch { res.writeHead(404); res.end('Not found'); }
}

async function handle(req, res) {
  const host = String(req.headers.host || '').split(':')[0].toLowerCase();
  if (!['localhost', '127.0.0.1'].includes(host)) return send(res, 403, { error: '이 시험판은 이 컴퓨터에서만 접속할 수 있습니다.' });
  const url = new URL(req.url, 'http://localhost');
  if (req.method !== 'GET' && !checkOrigin(req)) return send(res, 403, { error: '요청 출처를 확인할 수 없습니다.' });
  const usersCount = Number(db.prepare('SELECT COUNT(*) AS count FROM users').get().count);

  if (url.pathname === '/api/status' && req.method === 'GET') return send(res, 200, { setupRequired: usersCount === 0 });
  if (url.pathname === '/api/setup' && req.method === 'POST') {
    if (usersCount) return send(res, 409, { error: '초기 원장 계정이 이미 만들어졌습니다.' });
    const body = await requireJson(req);
    const username = String(body.username || '').trim().toLowerCase();
    const displayName = String(body.displayName || '').trim();
    const password = String(body.password || '');
    if (!/^[a-z0-9._-]{3,40}$/.test(username)) return send(res, 400, { error: '아이디는 영문 소문자, 숫자, 점, 밑줄, 하이픈으로 3~40자여야 합니다.' });
    if (!displayName || displayName.length > 60) return send(res, 400, { error: '표시 이름을 입력해 주세요.' });
    if (password.length < 12 || password.length > 200) return send(res, 400, { error: '비밀번호는 12자 이상으로 설정해 주세요.' });
    const initial = validateData(body.initialData) ? body.initialData : emptyData();
    const owner = { id: id('U'), username, display_name: displayName, password_hash: hashPassword(password), role: 'owner', active: 1, created_at: now() };
    db.exec('BEGIN IMMEDIATE');
    try {
      db.prepare('INSERT INTO users(id,username,display_name,password_hash,role,active,created_at) VALUES(?,?,?,?,?,?,?)').run(owner.id, owner.username, owner.display_name, owner.password_hash, owner.role, owner.active, owner.created_at);
      db.prepare('INSERT INTO app_state(id,data,updated_at,updated_by) VALUES(1,?,?,?)').run(JSON.stringify(initial), now(), owner.id);
      addAudit(owner, '설정', '계정', owner.id, '원장 계정을 만들고 NAMU를 시작함', null, { username, displayName });
      db.exec('COMMIT');
    } catch (error) { db.exec('ROLLBACK'); throw error; }
    const token = randomBytes(32).toString('hex'); sessions.set(token, { userId: owner.id, expiresAt: Date.now() + SESSION_MS });
    return send(res, 201, { user: userPublic(owner), data: initial }, { 'Set-Cookie': cookieHeader(token) });
  }
  if (url.pathname === '/api/login' && req.method === 'POST') {
    const ip = req.socket.remoteAddress || 'local';
    const throttle = failedLogins.get(ip) || { count: 0, until: 0 };
    if (throttle.until > Date.now()) return send(res, 429, { error: '로그인 시도가 많습니다. 잠시 후 다시 시도해 주세요.' });
    const body = await requireJson(req);
    const username = String(body.username || '').trim().toLowerCase(), password = String(body.password || '');
    if (password.length > 200) return send(res, 401, { error: '아이디 또는 비밀번호를 확인해 주세요.' });
    const user = db.prepare('SELECT * FROM users WHERE username=? AND active=1').get(username);
    if (!user || !verifyPassword(password, user.password_hash)) {
      throttle.count++;
      if (throttle.count >= 5) { throttle.count = 0; throttle.until = Date.now() + 5 * 60 * 1000; }
      failedLogins.set(ip, throttle);
      return send(res, 401, { error: '아이디 또는 비밀번호를 확인해 주세요.' });
    }
    failedLogins.delete(ip);
    const token = randomBytes(32).toString('hex'); sessions.set(token, { userId: user.id, expiresAt: Date.now() + SESSION_MS });
    addAudit(user, '로그인', '계정', user.id, '로그인 성공', null, null);
    return send(res, 200, { user: userPublic(user) }, { 'Set-Cookie': cookieHeader(token) });
  }
  const user = currentUser(req);
  if (url.pathname.startsWith('/api/') && url.pathname !== '/api/logout' && !user) return send(res, 401, { error: '로그인이 필요합니다.' });
  if (url.pathname === '/api/me' && req.method === 'GET') return send(res, 200, { user: userPublic(user) });
  if (url.pathname === '/api/logout' && req.method === 'POST') {
    const match = /(?:^|;\s*)namu_session=([a-f0-9]+)/.exec(req.headers.cookie || '');
    if (match) sessions.delete(match[1]);
    if (user) addAudit(user, '로그아웃', '계정', user.id, '로그아웃', null, null);
    return send(res, 200, { ok: true }, { 'Set-Cookie': cookieHeader('', 0) });
  }
  if (url.pathname === '/api/data' && req.method === 'GET') return send(res, 200, getData());
  if (url.pathname === '/api/data' && req.method === 'PUT') {
    const body = await requireJson(req); saveData(body.data, user); return send(res, 200, { ok: true, updatedAt: now() });
  }
  if (url.pathname === '/api/audit' && req.method === 'GET') {
    if (!requireOwner(user, res)) return;
    return send(res, 200, { events: getAudit(Math.min(250, Math.max(1, Number(url.searchParams.get('limit') || 100)))) });
  }
  if (url.pathname === '/api/users' && req.method === 'GET') {
    if (!requireOwner(user, res)) return;
    const users = db.prepare('SELECT id,username,display_name AS displayName,role,active,created_at AS createdAt FROM users ORDER BY role,display_name').all();
    return send(res, 200, { users });
  }
  if (url.pathname === '/api/users' && req.method === 'POST') {
    if (!requireOwner(user, res)) return;
    const body = await requireJson(req), username = String(body.username || '').trim().toLowerCase(), displayName = String(body.displayName || '').trim(), password = String(body.password || '');
    if (!/^[a-z0-9._-]{3,40}$/.test(username)) return send(res, 400, { error: '아이디 형식을 확인해 주세요.' });
    if (!displayName || displayName.length > 60) return send(res, 400, { error: '이름을 입력해 주세요.' });
    if (password.length < 12 || password.length > 200) return send(res, 400, { error: '초기 비밀번호는 12자 이상이어야 합니다.' });
    const newUser = { id: id('U'), username, display_name: displayName, password_hash: hashPassword(password), role: body.role === 'manager' ? 'manager' : 'staff', active: 1, created_at: now() };
    try { db.prepare('INSERT INTO users(id,username,display_name,password_hash,role,active,created_at) VALUES(?,?,?,?,?,?,?)').run(newUser.id, newUser.username, newUser.display_name, newUser.password_hash, newUser.role, 1, newUser.created_at); }
    catch { return send(res, 409, { error: '이미 사용 중인 아이디입니다.' }); }
    addAudit(user, '추가', '직원 계정', newUser.id, `직원 계정 추가: ${displayName}`, null, { username, displayName, role: newUser.role });
    return send(res, 201, { user: userPublic(newUser) });
  }
  const userStatus = url.pathname.match(/^\/api\/users\/(U[a-f0-9]+)\/status$/);
  if (userStatus && req.method === 'PATCH') {
    if (!requireOwner(user, res)) return;
    const target = db.prepare('SELECT * FROM users WHERE id=?').get(userStatus[1]);
    if (!target) return send(res, 404, { error: '계정을 찾을 수 없습니다.' });
    if (target.id === user.id || target.role === 'owner') return send(res, 400, { error: '원장 계정은 이 화면에서 비활성화할 수 없습니다.' });
    const body = await requireJson(req), active = body.active === true ? 1 : 0;
    db.prepare('UPDATE users SET active=? WHERE id=?').run(active, target.id);
    addAudit(user, active ? '활성화' : '비활성화', '직원 계정', target.id, `직원 계정 ${active ? '활성화' : '비활성화'}: ${target.display_name}`, { active: target.active === 1 }, { active: active === 1 });
    if (!active) for (const [token, session] of sessions) if (session.userId === target.id) sessions.delete(token);
    return send(res, 200, { ok: true });
  }
  const userPassword = url.pathname.match(/^\/api\/users\/(U[a-f0-9]+)\/password$/);
  if (userPassword && req.method === 'POST') {
    if (!requireOwner(user, res)) return;
    const target = db.prepare('SELECT * FROM users WHERE id=? AND active=1').get(userPassword[1]);
    if (!target || target.role === 'owner') return send(res, 404, { error: '활성 직원 계정을 찾을 수 없습니다.' });
    const body = await requireJson(req), password = String(body.password || '');
    if (password.length < 12 || password.length > 200) return send(res, 400, { error: '초기 비밀번호는 12자 이상이어야 합니다.' });
    db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(hashPassword(password), target.id);
    addAudit(user, '초기화', '직원 계정', target.id, `직원 비밀번호 초기화: ${target.display_name}`, null, null);
    for (const [token, session] of sessions) if (session.userId === target.id) sessions.delete(token);
    return send(res, 200, { ok: true });
  }
  if (url.pathname === '/api/auth/password' && req.method === 'POST') {
    const body = await requireJson(req), oldPassword = String(body.oldPassword || ''), newPassword = String(body.newPassword || '');
    const fullUser = db.prepare('SELECT * FROM users WHERE id=?').get(user.id);
    if (!verifyPassword(oldPassword, fullUser.password_hash)) return send(res, 400, { error: '현재 비밀번호를 확인해 주세요.' });
    if (newPassword.length < 12 || newPassword.length > 200) return send(res, 400, { error: '새 비밀번호는 12자 이상이어야 합니다.' });
    db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(hashPassword(newPassword), user.id);
    addAudit(user, '변경', '계정', user.id, '비밀번호 변경', null, null);
    for (const [token, session] of sessions) if (session.userId === user.id) sessions.delete(token);
    const token = randomBytes(32).toString('hex'); sessions.set(token, { userId: user.id, expiresAt: Date.now() + SESSION_MS });
    return send(res, 200, { ok: true }, { 'Set-Cookie': cookieHeader(token) });
  }
  if (url.pathname === '/api/backup/export' && req.method === 'POST') {
    if (!requireOwner(user, res)) return;
    const body = await requireJson(req); return send(res, 200, makeBackup(body.passphrase));
  }
  if (url.pathname === '/api/backup/restore' && req.method === 'POST') {
    if (!requireOwner(user, res)) return;
    const body = await requireJson(req), backup = openBackup(String(body.passphrase || ''), body.backup);
    db.exec('BEGIN IMMEDIATE');
    try {
      db.prepare('INSERT INTO app_state(id,data,updated_at,updated_by) VALUES(1,?,?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data,updated_at=excluded.updated_at,updated_by=excluded.updated_by').run(JSON.stringify(backup.data), now(), user.id);
      db.exec('DELETE FROM audit_events');
      const insert = db.prepare('INSERT INTO audit_events(id,created_at,user_id,user_name,action,entity,entity_id,summary,before_json,after_json) VALUES(?,?,?,?,?,?,?,?,?,?)');
      for (const e of backup.audit.slice(-10000)) insert.run(e.id, e.createdAt, null, e.userName, e.action, e.entity, e.entityId || null, e.summary, e.beforeJson || null, e.afterJson || null);
      db.exec('COMMIT');
    } catch (error) { db.exec('ROLLBACK'); throw error; }
    addAudit(user, '복구', '데이터', 'all', '암호화 백업에서 데이터 복구', null, { backupCreatedAt: backup.createdAt });
    return send(res, 200, { ok: true, restoredAt: now() });
  }

  if (url.pathname.startsWith('/api/')) return send(res, 404, { error: '요청한 기능을 찾을 수 없습니다.' });
  if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405); res.end('Method not allowed'); return; }
  serveFile(url.pathname, res);
}

const server = createServer((req, res) => {
  handle(req, res).catch(error => {
    if (!res.headersSent) send(res, error.status || 500, { error: error.status ? error.message : '처리 중 문제가 생겼습니다.' });
    else res.destroy();
  });
});
server.listen(PORT, '127.0.0.1', () => {
  console.log(`NAMU is running at http://localhost:${PORT}`);
  console.log(`Data file: ${join(DATA_DIR, 'namu.sqlite')}`);
  console.log('This pilot listens only on this computer. Press Ctrl+C to stop.');
});
