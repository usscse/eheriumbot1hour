const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');

const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const LOG_FILE = path.join(DATA_DIR, 'log.json');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, '[]');
if (!fs.existsSync(LOG_FILE)) fs.writeFileSync(LOG_FILE, '[]');
if (!fs.existsSync(USERS_FILE)) {
  const admin = [{ id: 1, username: 'admin', passwordHash: hashPassword('admin'), role: 'admin', mustChangePassword: true }];
  fs.writeFileSync(USERS_FILE, JSON.stringify(admin, null, 2));
}

const sessions = new Map(); // token -> {id, username, role, createdAt}
const sseClients = new Set();
const locks = new Map(); // recordId -> { userId, username, expiresAt }
const LOCK_TTL_MS = 30 * 60 * 1000;

function hashPassword(password) {
  return crypto.createHash('sha256').update(String(password || '')).digest('hex');
}

function readJSON(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return fallback;
  }
}

function writeJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

function nowISO() {
  return new Date().toISOString();
}

function addLog(entry) {
  const logs = readJSON(LOG_FILE, []);
  logs.unshift({ at: nowISO(), ...entry });
  writeJSON(LOG_FILE, logs.slice(0, 5000));
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk;
      if (body.length > 2 * 1024 * 1024) {
        reject(new Error('Payload too large'));
        req.destroy();
      }
    });
    req.on('end', () => {
      if (!body) return resolve({});
      try {
        resolve(JSON.parse(body));
      } catch {
        reject(new Error('Invalid JSON'));
      }
    });
    req.on('error', reject);
  });
}

function sendJSON(res, status, data) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store'
  });
  res.end(JSON.stringify(data));
}

function sendText(res, status, text, contentType = 'text/plain; charset=utf-8') {
  res.writeHead(status, { 'Content-Type': contentType, 'Cache-Control': 'no-store' });
  res.end(text);
}

function bearerToken(req) {
  const auth = req.headers.authorization || '';
  if (auth.startsWith('Bearer ')) return auth.slice(7).trim();
  return req.headers['x-token'] || '';
}

function getSession(req) {
  const token = bearerToken(req);
  if (!token) return null;
  return sessions.get(token) || null;
}

function requireAuth(req, res) {
  const user = getSession(req);
  if (!user) {
    sendJSON(res, 401, { error: 'Unauthorized' });
    return null;
  }
  return user;
}

function requireAdmin(req, res) {
  const user = requireAuth(req, res);
  if (!user) return null;
  if (user.role !== 'admin') {
    sendJSON(res, 403, { error: 'Admin only' });
    return null;
  }
  return user;
}

function cleanLocks() {
  const now = Date.now();
  for (const [id, lock] of locks.entries()) {
    if (lock.expiresAt <= now) locks.delete(id);
  }
}

function broadcastSSE(event, data) {
  const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const res of sseClients) {
    try {
      res.write(payload);
    } catch {
      sseClients.delete(res);
    }
  }
}

function listOnlineDeduped() {
  const seen = new Set();
  return [...sessions.values()]
    .filter(s => {
      if (seen.has(s.username)) return false;
      seen.add(s.username);
      return true;
    })
    .map(s => ({ id: s.id, username: s.username, role: s.role }));
}

function route(req, res) {
  cleanLocks();
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const { pathname } = url;

  if (req.method === 'GET' && pathname === '/') {
    const p = path.join(__dirname, 'client.html');
    if (!fs.existsSync(p)) return sendText(res, 404, 'client.html not found');
    return sendText(res, 200, fs.readFileSync(p, 'utf8'), 'text/html; charset=utf-8');
  }

  if (req.method === 'GET' && pathname === '/health') {
    return sendJSON(res, 200, { ok: true, host: os.hostname(), time: nowISO() });
  }

  if (req.method === 'GET' && pathname === '/api/events') {
    const sseToken = url.searchParams.get('token');
    const user = sseToken ? sessions.get(sseToken) : getSession(req);
    if (!user) {
      sendJSON(res, 401, { error: 'Unauthorized' });
      return;
    }
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive'
    });
    res.write(`event: hello\ndata: ${JSON.stringify({ ok: true })}\n\n`);
    sseClients.add(res);
    req.on('close', () => sseClients.delete(res));
    return;
  }

  if (req.method === 'POST' && pathname === '/api/login') {
    return parseBody(req)
      .then(body => {
        const username = String(body.username || '').trim();
        const password = String(body.password || '');
        const users = readJSON(USERS_FILE, []);
        const found = users.find(u => u.username === username);
        if (!found || found.passwordHash !== hashPassword(password)) {
          return sendJSON(res, 401, { error: 'Invalid username or password.' });
        }

        for (const s of sessions.values()) {
          if (s.username === username) {
            return sendJSON(res, 409, { error: 'User already logged in on another device. Please logout from the other device first.' });
          }
        }

        const token = crypto.randomBytes(24).toString('hex');
        const session = { id: found.id, username: found.username, role: found.role, createdAt: nowISO() };
        sessions.set(token, session);
        addLog({ action: 'login', by: found.username, userId: found.id });
        broadcastSSE('online', { online: listOnlineDeduped() });
        return sendJSON(res, 200, { ok: true, token, user: session, mustChangePassword: !!found.mustChangePassword });
      })
      .catch(err => sendJSON(res, 400, { error: err.message }));
  }

  if (req.method === 'POST' && pathname === '/api/logout') {
    const token = bearerToken(req);
    const user = sessions.get(token);
    if (token) sessions.delete(token);
    if (user) {
      addLog({ action: 'logout', by: user.username, userId: user.id });
      broadcastSSE('online', { online: listOnlineDeduped() });
    }
    return sendJSON(res, 200, { ok: true });
  }

  if (req.method === 'GET' && pathname === '/api/me') {
    const user = requireAuth(req, res);
    if (!user) return;
    return sendJSON(res, 200, { user });
  }

  if (req.method === 'GET' && pathname === '/api/db') {
    if (!requireAuth(req, res)) return;
    return sendJSON(res, 200, readJSON(DB_FILE, []));
  }

  if (req.method === 'POST' && pathname === '/api/db') {
    const user = requireAuth(req, res);
    if (!user) return;
    return parseBody(req)
      .then(body => {
        if (!Array.isArray(body)) return sendJSON(res, 400, { error: 'Expected array' });
        writeJSON(DB_FILE, body);
        addLog({ action: 'db_replace', by: user.username, count: body.length });
        broadcastSSE('db_changed', { by: user.username, count: body.length });
        sendJSON(res, 200, { ok: true });
      })
      .catch(err => sendJSON(res, 400, { error: err.message }));
  }

  if (req.method === 'GET' && pathname === '/api/records') {
    if (!requireAuth(req, res)) return;
    return sendJSON(res, 200, readJSON(DB_FILE, []));
  }

  if (req.method === 'POST' && pathname === '/api/records') {
    const user = requireAuth(req, res);
    if (!user) return;
    return parseBody(req)
      .then(body => {
        const db = readJSON(DB_FILE, []);
        const maxId = db.reduce((m, x) => Math.max(m, Number(x.id) || 0), 0);
        const rec = {
          id: maxId + 1,
          created_at: nowISO(),
          updated_at: nowISO(),
          ...body
        };
        db.unshift(rec);
        writeJSON(DB_FILE, db);
        addLog({ action: 'record_create', by: user.username, recordId: rec.id });
        broadcastSSE('record_created', { record: rec });
        sendJSON(res, 201, rec);
      })
      .catch(err => sendJSON(res, 400, { error: err.message }));
  }

  const recMatch = pathname.match(/^\/api\/records\/(\d+)$/);
  if (recMatch && req.method === 'PUT') {
    const user = requireAuth(req, res);
    if (!user) return;
    const id = Number(recMatch[1]);
    return parseBody(req)
      .then(body => {
        const db = readJSON(DB_FILE, []);
        const i = db.findIndex(r => Number(r.id) === id);
        if (i < 0) return sendJSON(res, 404, { error: 'Record not found' });
        db[i] = { ...db[i], ...body, id, updated_at: nowISO() };
        writeJSON(DB_FILE, db);
        addLog({ action: 'record_update', by: user.username, recordId: id });
        broadcastSSE('record_updated', { record: db[i] });
        sendJSON(res, 200, db[i]);
      })
      .catch(err => sendJSON(res, 400, { error: err.message }));
  }

  if (recMatch && req.method === 'DELETE') {
    const user = requireAuth(req, res);
    if (!user) return;
    const id = Number(recMatch[1]);
    const db = readJSON(DB_FILE, []);
    const i = db.findIndex(r => Number(r.id) === id);
    if (i < 0) return sendJSON(res, 404, { error: 'Record not found' });
    db.splice(i, 1);
    writeJSON(DB_FILE, db);
    locks.delete(String(id));
    addLog({ action: 'record_delete', by: user.username, recordId: id });
    broadcastSSE('record_deleted', { id });
    return sendJSON(res, 200, { ok: true });
  }

  const lockMatch = pathname.match(/^\/api\/lock\/(\d+)$/);
  if (lockMatch && req.method === 'POST') {
    const user = requireAuth(req, res);
    if (!user) return;
    const id = lockMatch[1];
    const ex = locks.get(id);
    if (ex && ex.userId !== user.id && ex.expiresAt > Date.now()) {
      return sendJSON(res, 409, { error: `Record locked by ${ex.username}` });
    }
    locks.set(id, { userId: user.id, username: user.username, expiresAt: Date.now() + LOCK_TTL_MS });
    broadcastSSE('lock_changed', { id: Number(id), lock: locks.get(id) });
    return sendJSON(res, 200, { ok: true });
  }

  if (lockMatch && req.method === 'DELETE') {
    const user = requireAuth(req, res);
    if (!user) return;
    const id = lockMatch[1];
    const ex = locks.get(id);
    if (!ex) return sendJSON(res, 200, { ok: true });
    if (ex.userId !== user.id && user.role !== 'admin') {
      return sendJSON(res, 403, { error: 'Cannot unlock this record' });
    }
    locks.delete(id);
    broadcastSSE('lock_changed', { id: Number(id), lock: null });
    return sendJSON(res, 200, { ok: true });
  }

  if (req.method === 'GET' && pathname === '/api/locks') {
    if (!requireAuth(req, res)) return;
    const out = [];
    for (const [id, l] of locks.entries()) out.push({ id: Number(id), ...l });
    return sendJSON(res, 200, out);
  }

  if (req.method === 'GET' && pathname === '/api/users') {
    if (!requireAdmin(req, res)) return;
    const users = readJSON(USERS_FILE, []).map(u => ({ id: u.id, username: u.username, role: u.role, mustChangePassword: !!u.mustChangePassword }));
    return sendJSON(res, 200, users);
  }

  if (req.method === 'POST' && pathname === '/api/users') {
    const admin = requireAdmin(req, res);
    if (!admin) return;
    return parseBody(req)
      .then(body => {
        const username = String(body.username || '').trim();
        const password = String(body.password || '').trim();
        const role = body.role === 'admin' ? 'admin' : 'user';
        if (!username || !password) return sendJSON(res, 400, { error: 'Username and password are required' });
        const users = readJSON(USERS_FILE, []);
        if (users.some(u => u.username === username)) return sendJSON(res, 409, { error: 'Username already exists' });
        const id = users.reduce((m, u) => Math.max(m, Number(u.id) || 0), 0) + 1;
        users.push({ id, username, passwordHash: hashPassword(password), role, mustChangePassword: false });
        writeJSON(USERS_FILE, users);
        addLog({ action: 'user_create', by: admin.username, userId: id });
        broadcastSSE('users_changed', { by: admin.username });
        sendJSON(res, 201, { id, username, role });
      })
      .catch(err => sendJSON(res, 400, { error: err.message }));
  }

  const userPwMatch = pathname.match(/^\/api\/users\/(\d+)\/password$/);
  if (userPwMatch && req.method === 'POST') {
    const admin = requireAdmin(req, res);
    if (!admin) return;
    return parseBody(req)
      .then(body => {
        const id = Number(userPwMatch[1]);
        const password = String(body.password || '').trim();
        if (!password) return sendJSON(res, 400, { error: 'Password is required' });
        const users = readJSON(USERS_FILE, []);
        const u = users.find(x => Number(x.id) === id);
        if (!u) return sendJSON(res, 404, { error: 'User not found' });
        u.passwordHash = hashPassword(password);
        u.mustChangePassword = false;
        writeJSON(USERS_FILE, users);
        addLog({ action: 'user_reset_password', by: admin.username, userId: id });
        sendJSON(res, 200, { ok: true });
      })
      .catch(err => sendJSON(res, 400, { error: err.message }));
  }

  const userForceMatch = pathname.match(/^\/api\/users\/(\d+)\/force-logout$/);
  if (userForceMatch && req.method === 'POST') {
    const admin = requireAdmin(req, res);
    if (!admin) return;
    const id = parseInt(userForceMatch[1], 10);
    for (const [token, session] of sessions.entries()) {
      if (session.id === id) sessions.delete(token);
    }
    broadcastSSE('force_logout', { userId: id });
    broadcastSSE('online', { online: listOnlineDeduped() });
    addLog({ action: 'user_force_logout', by: admin.username, userId: id });
    return sendJSON(res, 200, { ok: true });
  }

  const userMatch = pathname.match(/^\/api\/users\/(\d+)$/);
  if (userMatch && req.method === 'DELETE') {
    const admin = requireAdmin(req, res);
    if (!admin) return;
    const id = Number(userMatch[1]);
    const users = readJSON(USERS_FILE, []);
    const idx = users.findIndex(u => Number(u.id) === id);
    if (idx < 0) return sendJSON(res, 404, { error: 'User not found' });
    if (users[idx].username === 'admin') return sendJSON(res, 400, { error: 'Cannot delete default admin' });
    users.splice(idx, 1);
    writeJSON(USERS_FILE, users);
    for (const [token, session] of sessions.entries()) {
      if (session.id === id) sessions.delete(token);
    }
    addLog({ action: 'user_delete', by: admin.username, userId: id });
    broadcastSSE('users_changed', { by: admin.username });
    broadcastSSE('online', { online: listOnlineDeduped() });
    return sendJSON(res, 200, { ok: true });
  }

  if (req.method === 'POST' && pathname === '/api/change-password') {
    const user = requireAuth(req, res);
    if (!user) return;
    return parseBody(req)
      .then(body => {
        const oldPassword = String(body.oldPassword || '');
        const newPassword = String(body.newPassword || '').trim();
        if (!newPassword) return sendJSON(res, 400, { error: 'New password is required' });
        const users = readJSON(USERS_FILE, []);
        const u = users.find(x => x.id === user.id);
        if (!u) return sendJSON(res, 404, { error: 'User not found' });
        if (u.passwordHash !== hashPassword(oldPassword)) {
          return sendJSON(res, 401, { error: 'Current password is incorrect' });
        }
        u.passwordHash = hashPassword(newPassword);
        u.mustChangePassword = false;
        writeJSON(USERS_FILE, users);
        addLog({ action: 'password_change', by: user.username, userId: user.id });
        sendJSON(res, 200, { ok: true });
      })
      .catch(err => sendJSON(res, 400, { error: err.message }));
  }

  if (req.method === 'GET' && pathname === '/api/log') {
    if (!requireAdmin(req, res)) return;
    return sendJSON(res, 200, readJSON(LOG_FILE, []));
  }

  if (req.method === 'GET' && pathname === '/api/online') {
    if (!requireAuth(req, res)) return;
    const seen = new Set();
    const online = [...sessions.values()]
      .filter(s => {
        if (seen.has(s.username)) return false;
        seen.add(s.username);
        return true;
      })
      .map(s => ({ id: s.id, username: s.username, role: s.role }));
    return sendJSON(res, 200, online);
  }

  sendJSON(res, 404, { error: 'Not found' });
}

const server = http.createServer((req, res) => {
  try {
    route(req, res);
  } catch (err) {
    sendJSON(res, 500, { error: 'Internal server error', detail: err.message });
  }
});

server.listen(PORT, () => {
  console.log(`TSR Data Manager v1.0 Final server running on http://localhost:${PORT}`);
});
