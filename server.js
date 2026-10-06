import { createServer } from 'node:http';
import { createReadStream, mkdirSync, readFileSync } from 'node:fs';
import { createHash, randomBytes, scryptSync, timingSafeEqual, createCipheriv, createDecipheriv } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { dirname, extname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = dirname(fileURLToPath(import.meta.url));
const DATA_DIR = resolve(process.env.NAMU_DATA_DIR || join(ROOT, 'data'));
const PORT = Number(process.env.NAMU_PORT || 4173);
const HOST = process.env.NAMU_HOST || '127.0.0.1';
const ALLOWED_HOSTS = new Set((process.env.NAMU_ALLOWED_HOSTS || 'localhost,127.0.0.1').split(',').map(value => value.trim().toLowerCase()).filter(Boolean));
const SECURE_COOKIES = process.env.NODE_ENV === 'production';
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
CREATE TABLE IF NOT EXISTS branches (id TEXT PRIMARY KEY, name TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS user_branches (user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, branch_id TEXT NOT NULL REFERENCES branches(id) ON DELETE CASCADE, PRIMARY KEY(user_id,branch_id));
CREATE TABLE IF NOT EXISTS branch_state (branch_id TEXT PRIMARY KEY REFERENCES branches(id), data TEXT NOT NULL, updated_at TEXT NOT NULL, updated_by TEXT, version INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS audit_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL,
  user_id TEXT, user_name TEXT NOT NULL, action TEXT NOT NULL,
  entity TEXT NOT NULL, entity_id TEXT, summary TEXT NOT NULL,
  before_json TEXT, after_json TEXT, branch_id TEXT
);
CREATE TABLE IF NOT EXISTS access_requests (
  id TEXT PRIMARY KEY, kind TEXT NOT NULL CHECK(kind IN ('signup','password','id')),
  username TEXT, display_name TEXT NOT NULL, password_hash TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_created_at_idx ON audit_events(created_at DESC);`);
if (!db.prepare('PRAGMA table_info(audit_events)').all().some(column => column.name === 'branch_id')) db.exec('ALTER TABLE audit_events ADD COLUMN branch_id TEXT');

const sessions = new Map();
const failedLogins = new Map();
const accessRequestAttempts = new Map();
const entityLabels = { students: '수강생', payments: '수납', ledger: '가계부', consultations: '상담' };
const entityNames = { students: 'name', payments: 'studentId', ledger: 'description', consultations: 'name' };
const emptyData = () => ({ students: [], payments: [], ledger: [], consultations: [], activity: [] });
const now = () => new Date().toISOString();
const id = prefix => `${prefix}${randomBytes(8).toString('hex')}`;

// Preserve the existing single-branch database by moving its data into a first branch once.
if (Number(db.prepare('SELECT COUNT(*) AS n FROM branches').get().n) === 0 && Number(db.prepare('SELECT COUNT(*) AS n FROM users').get().n) > 0) {
  const branchId = id('B'), legacy = db.prepare('SELECT data,updated_at,updated_by FROM app_state WHERE id=1').get();
  db.exec('BEGIN IMMEDIATE');
  try {
    db.prepare('INSERT INTO branches(id,name,active,created_at) VALUES(?,?,1,?)').run(branchId, '본점', now());
    db.prepare('INSERT INTO branch_state(branch_id,data,updated_at,updated_by) VALUES(?,?,?,?)').run(branchId, legacy?.data || JSON.stringify(emptyData()), legacy?.updated_at || now(), legacy?.updated_by || null);
    for (const staff of db.prepare("SELECT id FROM users WHERE role='staff'").all()) db.prepare('INSERT OR IGNORE INTO user_branches(user_id,branch_id) VALUES(?,?)').run(staff.id, branchId);
    db.prepare('DELETE FROM app_state WHERE id=1').run();
    db.exec('COMMIT');
  } catch (error) { db.exec('ROLLBACK'); throw error; }
}

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
function getBranches(user) {
  return user?.role === 'owner'
    ? db.prepare('SELECT id,name,active FROM branches WHERE active=1 ORDER BY created_at,id').all()
    : db.prepare('SELECT b.id,b.name,b.active FROM branches b JOIN user_branches ub ON ub.branch_id=b.id WHERE ub.user_id=? AND b.active=1 ORDER BY b.created_at,b.id').all(user?.id || '');
}
function allowedBranch(user, branchId) {
  if (!branchId) return null;
  if (user?.role === 'owner') return db.prepare('SELECT id FROM branches WHERE id=? AND active=1').get(branchId) || null;
  return db.prepare('SELECT b.id FROM branches b JOIN user_branches ub ON ub.branch_id=b.id WHERE b.id=? AND ub.user_id=? AND b.active=1').get(branchId,user?.id || '') || null;
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
  return `namu_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAge}${SECURE_COOKIES ? '; Secure' : ''}`;
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
function getData(branchId) {
  const row = db.prepare('SELECT data,version FROM branch_state WHERE branch_id=?').get(branchId);
  return row ? { data: JSON.parse(row.data), revision: row.version } : { data: emptyData(), revision: 0 };
}
function getAudit(limit = 100) {
  return db.prepare('SELECT id, created_at AS createdAt, user_name AS userName, action, entity, entity_id AS entityId, summary, before_json AS beforeJson, after_json AS afterJson, branch_id AS branchId FROM audit_events ORDER BY id DESC LIMIT ?').all(limit);
}
function addAudit(user, action, entity, entityId, summary, before, after, branchId = null) {
  db.prepare('INSERT INTO audit_events(created_at,user_id,user_name,action,entity,entity_id,summary,before_json,after_json,branch_id) VALUES(?,?,?,?,?,?,?,?,?,?)')
    .run(now(), user?.id || null, user?.display_name || 'NAMU', action, entity, entityId || null, summary, before ? JSON.stringify(before) : null, after ? JSON.stringify(after) : null, branchId);
}
function validateData(data) {
  if (!data || typeof data !== 'object') return false;
  return ['students', 'payments', 'ledger', 'consultations', 'activity'].every(key => Array.isArray(data[key]));
}
function saveData(data, user, branchId, expectedRevision) {
  if (!validateData(data)) throw Object.assign(new Error('저장할 데이터 구조가 올바르지 않습니다.'), { status: 400 });
  if (Buffer.byteLength(JSON.stringify(data)) > 10 * 1024 * 1024) throw Object.assign(new Error('저장 데이터가 너무 큽니다.'), { status: 413 });
  const row = db.prepare('SELECT data,version FROM branch_state WHERE branch_id=?').get(branchId);
  if (!row) throw Object.assign(new Error('지점 데이터를 찾을 수 없습니다.'), { status: 404 });
  if (Number(expectedRevision) !== row.version) throw Object.assign(new Error('다른 직원이 먼저 변경했습니다. 화면을 새로고침해 최신 내용을 확인한 뒤 다시 입력해 주세요.'), { status: 409 });
  const before = JSON.parse(row.data);
  db.exec('BEGIN IMMEDIATE');
  try {
    const changed = db.prepare('UPDATE branch_state SET data=?,updated_at=?,updated_by=?,version=version+1 WHERE branch_id=? AND version=?').run(JSON.stringify(data), now(), user.id, branchId, row.version);
    if (changed.changes !== 1) throw Object.assign(new Error('다른 직원이 먼저 변경했습니다. 화면을 새로고침한 뒤 다시 입력해 주세요.'), { status: 409 });
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
        addAudit(user, action, label, key, `${label} ${action}: ${name}`, oldItem, newItem, branchId);
      }
    }
    db.exec('COMMIT');
    return row.version + 1;
  } catch (error) { db.exec('ROLLBACK'); throw error; }
}
function makeBackup(passphrase) {
  if (typeof passphrase !== 'string' || passphrase.length < 12) throw Object.assign(new Error('백업 암호는 12자 이상으로 설정해 주세요.'), { status: 400 });
  const salt = randomBytes(16), iv = randomBytes(12), key = scryptSync(passphrase, salt, 32);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const branches = db.prepare('SELECT id,name,active FROM branches ORDER BY created_at,id').all().map(branch => ({ ...branch, ...getData(branch.id) }));
  const clear = Buffer.from(JSON.stringify({ format: 'NAMU-BACKUP', version: 2, createdAt: now(), branches, audit: getAudit(10000) }));
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
    if (payload.format !== 'NAMU-BACKUP' || ![1,2].includes(payload.version) || !Array.isArray(payload.audit)) throw new Error('invalid backup');
    if (payload.version === 1 && !validateData(payload.data)) throw new Error('invalid backup');
    if (payload.version === 2 && (!Array.isArray(payload.branches) || payload.branches.some(branch => !branch.id || !validateData(branch.data)))) throw new Error('invalid backup');
    return payload;
  } catch { throw Object.assign(new Error('암호가 틀렸거나 백업 파일이 손상되었습니다.'), { status: 400 }); }
}
function checkOrigin(req) {
  const origin = req.headers.origin;
  if (!origin) return true;
  try {
    const parsed = new URL(origin), requestHost = String(req.headers.host || '').toLowerCase();
    const forwardedProto = String(req.headers['x-forwarded-proto'] || 'http').split(',')[0].trim().toLowerCase();
    return ALLOWED_HOSTS.has(parsed.hostname.toLowerCase()) && parsed.host.toLowerCase() === requestHost && parsed.protocol === `${forwardedProto}:` && (!SECURE_COOKIES || forwardedProto === 'https');
  } catch { return false; }
}
const MIME = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.json': 'application/json; charset=utf-8' };
function serveFile(pathname, res) {
  const safe = pathname === '/' ? '/index.html' : pathname;
  if (!['/index.html', '/styles.css', '/auth.css', '/app.js'].includes(safe)) { res.writeHead(404); res.end('Not found'); return; }
  const file = join(ROOT, safe.slice(1));
  try {
    res.writeHead(200, { 'Content-Type': MIME[extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'" });
    createReadStream(file).pipe(res);
  } catch { res.writeHead(404); res.end('Not found'); }
}

async function handle(req, res) {
  const host = String(req.headers.host || '').split(':')[0].toLowerCase();
  if (!ALLOWED_HOSTS.has(host)) return send(res, 403, { error: '허용되지 않은 NAMU 접속 주소입니다.' });
  const url = new URL(req.url, 'http://localhost');
  if (url.pathname === '/healthz' && req.method === 'GET') return send(res, 200, { ok: true });
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
      const branchId = id('B');
      db.prepare('INSERT INTO branches(id,name,active,created_at) VALUES(?,?,1,?)').run(branchId, '본점', now());
      db.prepare('INSERT INTO branch_state(branch_id,data,updated_at,updated_by) VALUES(?,?,?,?)').run(branchId, JSON.stringify(initial), now(), owner.id);
      addAudit(owner, '설정', '계정', owner.id, '원장 계정을 만들고 NAMU를 시작함', null, { username, displayName }, branchId);
      db.exec('COMMIT');
    } catch (error) { db.exec('ROLLBACK'); throw error; }
    const token = randomBytes(32).toString('hex'); sessions.set(token, { userId: owner.id, expiresAt: Date.now() + SESSION_MS });
    return send(res, 201, { user: userPublic(owner), data: initial }, { 'Set-Cookie': cookieHeader(token) });
  }
  if (url.pathname === '/api/login' && req.method === 'POST') {
    const ip = (String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || 'local');
    const body = await requireJson(req);
    const username = String(body.username || '').trim().toLowerCase(), password = String(body.password || '');
    const throttleKey = `${ip}:${username}`, throttle = failedLogins.get(throttleKey) || { count: 0, until: 0 };
    if (throttle.until > Date.now()) return send(res, 429, { error: '로그인 시도가 많습니다. 잠시 후 다시 시도해 주세요.' });
    if (password.length > 200) return send(res, 401, { error: '아이디 또는 비밀번호를 확인해 주세요.' });
    const user = db.prepare('SELECT * FROM users WHERE username=? AND active=1').get(username);
    if (!user || !verifyPassword(password, user.password_hash)) {
      throttle.count++;
      if (throttle.count >= 5) { throttle.count = 0; throttle.until = Date.now() + 5 * 60 * 1000; }
      failedLogins.set(throttleKey, throttle);
      return send(res, 401, { error: '아이디 또는 비밀번호를 확인해 주세요.' });
    }
    failedLogins.delete(throttleKey);
    const token = randomBytes(32).toString('hex'); sessions.set(token, { userId: user.id, expiresAt: Date.now() + SESSION_MS });
    addAudit(user, '로그인', '계정', user.id, '로그인 성공', null, null);
    return send(res, 200, { user: userPublic(user) }, { 'Set-Cookie': cookieHeader(token) });
  }
  if (url.pathname === '/api/access-requests' && req.method === 'POST') {
    const ip = (String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || 'local');
    const recent = (accessRequestAttempts.get(ip) || []).filter(at => Date.now() - at < 60_000);
    if (recent.length >= 5) return send(res, 429, { error: '요청이 많습니다. 잠시 후 다시 시도해 주세요.' });
    recent.push(Date.now()); accessRequestAttempts.set(ip, recent);
    const body = await requireJson(req);
    const kind = String(body.kind || ''), displayName = String(body.displayName || '').trim();
    const username = String(body.username || '').trim().toLowerCase();
    const password = String(body.password || '');
    if (!['signup','password','id'].includes(kind)) return send(res, 400, { error: '요청 종류를 확인해 주세요.' });
    if (!displayName || displayName.length > 60) return send(res, 400, { error: '이름을 입력해 주세요.' });
    if (kind !== 'id' && !/^[a-z0-9._-]{3,40}$/.test(username)) return send(res, 400, { error: '아이디 형식을 확인해 주세요.' });
    if (kind === 'signup') {
      if (password.length < 12 || password.length > 200) return send(res, 400, { error: '비밀번호는 12자 이상이어야 합니다.' });
      const used = db.prepare('SELECT 1 FROM users WHERE username=? UNION SELECT 1 FROM access_requests WHERE username=? AND kind=\'signup\'').get(username, username);
      if (used) return send(res, 409, { error: '이 아이디는 이미 사용 중이거나 가입 승인 대기 중입니다.' });
    }
    const duplicate = kind !== 'id' && db.prepare('SELECT 1 FROM access_requests WHERE kind=? AND username=?').get(kind, username);
    if (duplicate) return send(res, 409, { error: '이미 같은 요청이 접수되어 원장 확인을 기다리고 있습니다.' });
    db.prepare('INSERT INTO access_requests(id,kind,username,display_name,password_hash,created_at) VALUES(?,?,?,?,?,?)')
      .run(id('R'), kind, kind === 'id' ? null : username, displayName, kind === 'signup' ? hashPassword(password) : null, now());
    return send(res, 201, { ok: true, message: kind === 'signup' ? '가입 요청을 보냈습니다. 원장 승인 후 로그인이 가능합니다.' : '요청을 보냈습니다. 원장에게 확인해 주세요.' });
  }
  const user = currentUser(req);
  if (url.pathname.startsWith('/api/') && url.pathname !== '/api/logout' && !user) return send(res, 401, { error: '로그인이 필요합니다.' });
  if (url.pathname === '/api/me' && req.method === 'GET') return send(res, 200, { user: userPublic(user), branches: getBranches(user) });
  if (url.pathname === '/api/logout' && req.method === 'POST') {
    const match = /(?:^|;\s*)namu_session=([a-f0-9]+)/.exec(req.headers.cookie || '');
    if (match) sessions.delete(match[1]);
    if (user) addAudit(user, '로그아웃', '계정', user.id, '로그아웃', null, null);
    return send(res, 200, { ok: true }, { 'Set-Cookie': cookieHeader('', 0) });
  }
  if (url.pathname === '/api/branches' && req.method === 'GET') return send(res, 200, { branches: getBranches(user) });
  if (url.pathname === '/api/branches' && req.method === 'POST') {
    if (!requireOwner(user, res)) return;
    const body = await requireJson(req), name = String(body.name || '').trim();
    if (!name || name.length > 80) return send(res, 400, { error: '지점 이름을 1~80자로 입력해 주세요.' });
    const branchId = id('B');
    db.exec('BEGIN IMMEDIATE');
    try {
      db.prepare('INSERT INTO branches(id,name,active,created_at) VALUES(?,?,1,?)').run(branchId, name, now());
      db.prepare('INSERT INTO branch_state(branch_id,data,updated_at,updated_by) VALUES(?,?,?,?)').run(branchId, JSON.stringify(emptyData()), now(), user.id);
      addAudit(user, '추가', '지점', branchId, `지점 추가: ${name}`, null, { name });
      db.exec('COMMIT');
    } catch (error) { db.exec('ROLLBACK'); throw error; }
    return send(res, 201, { branch: { id: branchId, name, active: 1 } });
  }
  const branchStatus = url.pathname.match(/^\/api\/branches\/([A-Za-z0-9]+)\/status$/);
  if (branchStatus && req.method === 'PATCH') {
    if (!requireOwner(user, res)) return;
    const branch = db.prepare('SELECT * FROM branches WHERE id=?').get(branchStatus[1]);
    if (!branch) return send(res, 404, { error: '지점을 찾을 수 없습니다.' });
    const body = await requireJson(req), active = body.active === true ? 1 : 0;
    if (!active && Number(db.prepare('SELECT COUNT(*) AS n FROM branches WHERE active=1').get().n) < 2) return send(res, 400, { error: '마지막 사용 지점은 중지할 수 없습니다.' });
    db.prepare('UPDATE branches SET active=? WHERE id=?').run(active, branch.id);
    addAudit(user, active ? '활성화' : '비활성화', '지점', branch.id, `지점 ${active?'활성화':'비활성화'}: ${branch.name}`, { active: !!branch.active }, { active: !!active });
    return send(res, 200, { ok: true });
  }
  if (url.pathname === '/api/data' && req.method === 'GET') {
    const branchId = url.searchParams.get('branchId') || getBranches(user)[0]?.id;
    if (!allowedBranch(user, branchId)) return send(res, 403, { error: '이 지점에 접근할 권한이 없습니다.' });
    return send(res, 200, getData(branchId));
  }
  if (url.pathname === '/api/data' && req.method === 'PUT') {
    const body = await requireJson(req), branchId = String(body.branchId || '');
    if (!allowedBranch(user, branchId)) return send(res, 403, { error: '이 지점에 접근할 권한이 없습니다.' });
    const revision = saveData(body.data, user, branchId, body.revision); return send(res, 200, { ok: true, revision, updatedAt: now() });
  }
  if (url.pathname === '/api/audit' && req.method === 'GET') {
    if (!requireOwner(user, res)) return;
    return send(res, 200, { events: getAudit(Math.min(250, Math.max(1, Number(url.searchParams.get('limit') || 100)))) });
  }
  if (url.pathname === '/api/access-requests' && req.method === 'GET') {
    if (!requireOwner(user, res)) return;
    const requests = db.prepare('SELECT id,kind,username,display_name AS displayName,created_at AS createdAt FROM access_requests ORDER BY created_at').all();
    return send(res, 200, { requests });
  }
  const accessRequest = url.pathname.match(/^\/api\/access-requests\/([A-Za-z0-9]+)\/resolve$/);
  if (accessRequest && req.method === 'POST') {
    if (!requireOwner(user, res)) return;
    const request = db.prepare('SELECT * FROM access_requests WHERE id=?').get(accessRequest[1]);
    if (!request) return send(res, 404, { error: '요청을 찾을 수 없습니다.' });
    const body = await requireJson(req), decision = String(body.decision || '');
    if (decision === 'approve' && request.kind === 'signup') {
      const userId = id('U'), branchId = db.prepare('SELECT id FROM branches WHERE active=1 ORDER BY created_at,id LIMIT 1').get()?.id;
      if (!branchId) return send(res, 400, { error: '먼저 사용할 지점을 등록해 주세요.' });
      try {
        db.prepare('INSERT INTO users(id,username,display_name,password_hash,role,active,created_at) VALUES(?,?,?,?,?,?,?)').run(userId, request.username, request.display_name, request.password_hash, 'staff', 1, now());
        db.prepare('INSERT INTO user_branches(user_id,branch_id) VALUES(?,?)').run(userId, branchId);
      }
      catch { return send(res, 409, { error: '해당 아이디가 이미 등록되어 있습니다.' }); }
      addAudit(user, '승인', '직원 계정', request.id, `가입 요청 승인: ${request.display_name}`, null, { username: request.username });
    } else if (decision === 'approve' && request.kind === 'password') {
      const password = String(body.password || ''), target = db.prepare('SELECT * FROM users WHERE username=? AND display_name=? AND active=1 AND role=\'staff\'').get(request.username, request.display_name);
      if (!target) return send(res, 400, { error: '직원 아이디와 이름이 계정 정보와 일치하지 않습니다. 요청자 정보를 확인해 주세요.' });
      if (password.length < 12 || password.length > 200) return send(res, 400, { error: '임시 비밀번호는 12자 이상이어야 합니다.' });
      db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(hashPassword(password), target.id);
      for (const [token, session] of sessions) if (session.userId === target.id) sessions.delete(token);
      addAudit(user, '초기화', '직원 계정', target.id, `직원 비밀번호 초기화: ${target.display_name}`, null, null);
    } else if (decision !== 'reviewed' && decision !== 'reject') return send(res, 400, { error: '처리 방법을 확인해 주세요.' });
    db.prepare('DELETE FROM access_requests WHERE id=?').run(request.id);
    return send(res, 200, { ok: true });
  }
  if (url.pathname === '/api/users' && req.method === 'GET') {
    if (!requireOwner(user, res)) return;
    const users = db.prepare('SELECT id,username,display_name AS displayName,role,active,created_at AS createdAt FROM users ORDER BY role,display_name').all().map(account => ({ ...account, branchIds: db.prepare('SELECT branch_id AS id FROM user_branches WHERE user_id=?').all(account.id).map(row => row.id) }));
    return send(res, 200, { users });
  }
  if (url.pathname === '/api/users' && req.method === 'POST') {
    if (!requireOwner(user, res)) return;
    const body = await requireJson(req), username = String(body.username || '').trim().toLowerCase(), displayName = String(body.displayName || '').trim(), password = String(body.password || '');
    if (!/^[a-z0-9._-]{3,40}$/.test(username)) return send(res, 400, { error: '아이디 형식을 확인해 주세요.' });
    if (!displayName || displayName.length > 60) return send(res, 400, { error: '이름을 입력해 주세요.' });
    if (password.length < 12 || password.length > 200) return send(res, 400, { error: '초기 비밀번호는 12자 이상이어야 합니다.' });
    const branchIds = [...new Set(Array.isArray(body.branchIds) ? body.branchIds.map(String) : [])];
    if (branchIds.length !== 1 || branchIds.some(branchId => !db.prepare('SELECT 1 FROM branches WHERE id=? AND active=1').get(branchId))) return send(res, 400, { error: '직원 한 명에게 사용 중인 지점 한 곳을 배정해 주세요.' });
    const newUser = { id: id('U'), username, display_name: displayName, password_hash: hashPassword(password), role: 'staff', active: 1, created_at: now() };
    try {
      db.prepare('INSERT INTO users(id,username,display_name,password_hash,role,active,created_at) VALUES(?,?,?,?,?,?,?)').run(newUser.id, newUser.username, newUser.display_name, newUser.password_hash, newUser.role, 1, newUser.created_at);
      const assign = db.prepare('INSERT INTO user_branches(user_id,branch_id) VALUES(?,?)');
      for (const branchId of branchIds) assign.run(newUser.id, branchId);
    }
    catch { return send(res, 409, { error: '이미 사용 중인 아이디입니다.' }); }
    addAudit(user, '추가', '직원 계정', newUser.id, `직원 계정 추가: ${displayName}`, null, { username, displayName, role: newUser.role });
    return send(res, 201, { user: userPublic(newUser) });
  }
  const userBranches = url.pathname.match(/^\/api\/users\/(U[a-f0-9]+)\/branches$/);
  if (userBranches && req.method === 'PUT') {
    if (!requireOwner(user, res)) return;
    const target = db.prepare("SELECT * FROM users WHERE id=? AND role='staff'").get(userBranches[1]);
    if (!target) return send(res, 404, { error: '직원 계정을 찾을 수 없습니다.' });
    const body = await requireJson(req), branchIds = [...new Set(Array.isArray(body.branchIds) ? body.branchIds.map(String) : [])];
    if (branchIds.length !== 1 || branchIds.some(branchId => !db.prepare('SELECT 1 FROM branches WHERE id=? AND active=1').get(branchId))) return send(res, 400, { error: '직원 한 명에게 사용 중인 지점 한 곳을 배정해 주세요.' });
    db.exec('BEGIN IMMEDIATE');
    try {
      db.prepare('DELETE FROM user_branches WHERE user_id=?').run(target.id);
      const assign = db.prepare('INSERT INTO user_branches(user_id,branch_id) VALUES(?,?)');
      for (const branchId of branchIds) assign.run(target.id, branchId);
      db.exec('COMMIT');
    } catch (error) { db.exec('ROLLBACK'); throw error; }
    addAudit(user, '변경', '직원 지점 권한', target.id, `직원 지점 권한 변경: ${target.display_name}`, null, { branchIds });
    return send(res, 200, { ok: true });
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
      if (backup.version === 1) {
        const branchId = db.prepare('SELECT id FROM branches ORDER BY created_at,id LIMIT 1').get()?.id;
        if (!branchId) throw new Error('restore branch missing');
        db.prepare('INSERT INTO branch_state(branch_id,data,updated_at,updated_by) VALUES(?,?,?,?) ON CONFLICT(branch_id) DO UPDATE SET data=excluded.data,updated_at=excluded.updated_at,updated_by=excluded.updated_by,version=branch_state.version+1').run(branchId, JSON.stringify(backup.data), now(), user.id);
      } else {
        for (const branch of backup.branches) {
          const exists = db.prepare('SELECT 1 FROM branches WHERE id=?').get(branch.id);
          if (!exists) db.prepare('INSERT INTO branches(id,name,active,created_at) VALUES(?,?,1,?)').run(branch.id, branch.name, now());
          db.prepare('INSERT INTO branch_state(branch_id,data,updated_at,updated_by) VALUES(?,?,?,?) ON CONFLICT(branch_id) DO UPDATE SET data=excluded.data,updated_at=excluded.updated_at,updated_by=excluded.updated_by,version=branch_state.version+1').run(branch.id, JSON.stringify(branch.data), now(), user.id);
        }
      }
      db.exec('DELETE FROM audit_events');
      const insert = db.prepare('INSERT INTO audit_events(id,created_at,user_id,user_name,action,entity,entity_id,summary,before_json,after_json,branch_id) VALUES(?,?,?,?,?,?,?,?,?,?,?)');
      for (const e of backup.audit.slice(-10000)) insert.run(e.id, e.createdAt, null, e.userName, e.action, e.entity, e.entityId || null, e.summary, e.beforeJson || null, e.afterJson || null, e.branchId || null);
      db.exec('COMMIT');
    } catch (error) { db.exec('ROLLBACK'); throw error; }
    addAudit(user, '복구', '데이터', 'all', '암호화 백업에서 데이터 복구', null, { backupCreatedAt: backup.createdAt });
    return send(res, 200, { ok: true, restoredAt: now() });
  }

  if (url.pathname.startsWith('/api/')) return send(res, 404, { error: '요청한 기능을 찾을 수 없습니다.' });
  if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405); res.end('Method not allowed'); return; }
  serveFile(url.pathname, res);
}

const handleRequest = (req, res) => {
  handle(req, res).catch(error => {
    if (!res.headersSent) send(res, error.status || 500, { error: error.status ? error.message : '처리 중 문제가 생겼습니다.' });
    else res.destroy();
  });
};
const server = createServer(handleRequest);
server.listen(PORT, HOST, () => {
  console.log(`NAMU is listening on ${HOST}:${PORT}`);
  console.log(`Data file: ${join(DATA_DIR, 'namu.sqlite')}`);
  console.log(`Allowed web hosts: ${[...ALLOWED_HOSTS].join(', ')}`);
});
// Browsers commonly resolve "localhost" to IPv6 (::1) before IPv4. Keep both
// listeners loopback-only so the local app works without exposing the LAN.
if (HOST === '127.0.0.1') {
  const ipv6LoopbackServer = createServer(handleRequest);
  ipv6LoopbackServer.on('error', error => console.error(`IPv6 localhost listener: ${error.message}`));
  ipv6LoopbackServer.listen(PORT, '::1', () => console.log(`NAMU is also listening on [::1]:${PORT}`));
}
