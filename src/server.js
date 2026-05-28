const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');
const { db, dynamicPoints, CHALLENGES } = require('./db');

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'g4ram-skill-secret-2026';
const PORT = process.env.PORT || 3000;

// ============================================================
// WAF — blocks common attack patterns on the platform itself
// (separate from CTF challenge vulns which run on their own infra)
// ============================================================
const WAF_RULES = [
  // SQL Injection
  { name: 'SQLi', pattern: /(\b(union|select|insert|update|delete|drop|truncate|exec|execute|xp_|sp_)\b[\s\S]{0,30}\b(from|into|table|where|set)\b)/i },
  { name: 'SQLi', pattern: /('|")\s*(or|and)\s*('|"|\d|true|false)/i },
  { name: 'SQLi', pattern: /;\s*(drop|delete|insert|update|create)\s/i },
  // XSS
  { name: 'XSS', pattern: /<\s*(script|iframe|object|embed|svg|img[^>]+onerror)[^>]*>/i },
  { name: 'XSS', pattern: /javascript\s*:/i },
  { name: 'XSS', pattern: /on(load|error|click|mouseover|focus|blur)\s*=/i },
  // Path Traversal
  { name: 'PathTraversal', pattern: /(\.\.[\/\\]){2,}/  },
  { name: 'PathTraversal', pattern: /(\/etc\/passwd|\/etc\/shadow|\/proc\/self|\/windows\/system32)/i },
  // SSTI
  { name: 'SSTI', pattern: /\{\{.*\}\}|\{%.*%\}|\$\{.*\}/  },
  // XXE
  { name: 'XXE', pattern: /<!ENTITY\s/i },
  { name: 'XXE', pattern: /SYSTEM\s+["'](file|http|ftp|expect|php)/i },
  // Command Injection
  { name: 'CMDi', pattern: /[;&|`]\s*(ls|cat|wget|curl|bash|sh|nc|ncat|python|perl|ruby|php)\b/i },
  { name: 'CMDi', pattern: /\$\([^)]+\)/ },
  // SSRF — block requests trying to hit internal IPs
  { name: 'SSRF', pattern: /(127\.0\.0\.1|localhost|169\.254\.|10\.\d+\.\d+\.\d+|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/i },
];

const RATE_LIMIT = new Map(); // ip -> { count, resetAt }
const RATE_WINDOW = 60 * 1000; // 1 min
const RATE_MAX = 120;           // requests per window (normal browsing)
const SUBMIT_RATE = new Map();  // ip -> { count, resetAt } for flag submits
const SUBMIT_MAX = 30;          // max flag submits per minute

function getRateKey(req) {
  return req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || 'unknown';
}

function checkRate(map, key, max) {
  const now = Date.now();
  let entry = map.get(key);
  if (!entry || now > entry.resetAt) {
    entry = { count: 0, resetAt: now + RATE_WINDOW };
    map.set(key, entry);
  }
  entry.count++;
  return entry.count <= max;
}

function waf(req, res, next) {
  // Skip static assets
  if (req.path.startsWith('/public') || req.path.match(/\.(js|css|html|png|ico|woff2?)$/)) return next();

  const ip = getRateKey(req);

  // Global rate limit
  if (!checkRate(RATE_LIMIT, ip, RATE_MAX)) {
    return res.status(429).json({ error: 'Too many requests. Slow down.' });
  }

  // Stricter rate on submit
  if (req.path === '/api/submit' && !checkRate(SUBMIT_RATE, ip, SUBMIT_MAX)) {
    return res.status(429).json({ error: 'Flag submission rate limit exceeded.' });
  }

  // Scan all input sources
  const targets = [
    JSON.stringify(req.body || {}),
    JSON.stringify(req.query || {}),
    JSON.stringify(req.params || {}),
    req.headers['user-agent'] || '',
    req.headers['referer'] || '',
  ].join(' ');

  for (const rule of WAF_RULES) {
    if (rule.pattern.test(targets)) {
      console.warn(`[WAF] Blocked ${rule.name} from ${ip} on ${req.method} ${req.path}`);
      return res.status(403).json({ error: `Request blocked by WAF: ${rule.name} pattern detected.` });
    }
  }

  // Block oversized payloads
  const contentLength = parseInt(req.headers['content-length'] || '0');
  if (contentLength > 50 * 1024) { // 50KB max
    return res.status(413).json({ error: 'Payload too large.' });
  }

  next();
}

app.use(express.json({ limit: '50kb' }));
app.use(cookieParser());
app.use(waf);
app.use(express.static(path.join(__dirname, '../public')));

function auth(req, res, next) {
  const token = req.cookies.token || (req.headers.authorization || '').replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Invalid token' }); }
}

// === AUTH ===
app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body || {};
  if (!username || !email || !password) return res.status(400).json({ error: 'All fields required' });
  if (username.length < 3 || username.length > 20) return res.status(400).json({ error: 'Username must be 3–20 characters' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Invalid email address' });
  if (db.getUserByUsername(username)) return res.status(400).json({ error: 'Username already taken' });
  if (db.getUserByEmail(email)) return res.status(400).json({ error: 'Email already registered' });
  const hash = await bcrypt.hash(password, 10);
  const user = db.createUser(username, email, hash);
  const token = jwt.sign({ id: user.id, username }, JWT_SECRET, { expiresIn: '7d' });
  res.cookie('token', token, { httpOnly: true, maxAge: 7*24*3600*1000, sameSite: 'lax' });
  res.json({ ok: true, username });
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'All fields required' });
  const user = db.getUserByUsername(username);
  if (!user || !await bcrypt.compare(password, user.password_hash))
    return res.status(401).json({ error: 'Invalid username or password' });
  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
  res.cookie('token', token, { httpOnly: true, maxAge: 7*24*3600*1000, sameSite: 'lax' });
  res.json({ ok: true, username: user.username });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ ok: true });
});

app.get('/api/me', auth, (req, res) => {
  const user = db.getUserById(req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const { password_hash, ...safe } = user;
  const solves = db.getUserSolves(req.user.id).map(s => {
    const ch = CHALLENGES.find(c => c.id === s.challenge_id);
    return ch ? ch.slug : null;
  }).filter(Boolean);
  const hints = db.getUserHints(req.user.id).map(h => {
    const ch = CHALLENGES.find(c => c.id === h.challenge_id);
    return ch ? ch.slug : null;
  }).filter(Boolean);
  res.json({ ...safe, solves, hints });
});

// === CHALLENGES ===
app.get('/api/challenges', auth, (req, res) => {
  const userSolves = db.getUserSolves(req.user.id).map(s => s.challenge_id);
  const userHints  = db.getUserHints(req.user.id).map(h => h.challenge_id);
  const result = CHALLENGES.map(c => ({
    id: c.id, slug: c.slug, category: c.category, title: c.title,
    description: c.description, difficulty: c.difficulty,
    base_points: c.base_points,
    current_points: dynamicPoints(c.base_points, c.solve_count),
    hint_cost: c.hint_cost,
    solve_count: c.solve_count,
    author: c.author,
    solved: userSolves.includes(c.id),
    hint_unlocked: userHints.includes(c.id),
    hint: userHints.includes(c.id) ? c.hint : null,
  }));
  res.json(result);
});

// === HINT UNLOCK ===
app.post('/api/hint', auth, (req, res) => {
  const { slug } = req.body || {};
  if (!slug) return res.status(400).json({ error: 'Missing slug' });
  const ch = CHALLENGES.find(c => c.slug === slug);
  if (!ch) return res.status(404).json({ error: 'Challenge not found' });

  if (db.hasHint(req.user.id, ch.id))
    return res.json({ ok: true, hint: ch.hint, cost: 0, already: true });

  const solved = db.hasSolved(req.user.id, ch.id);
  const cost = solved ? 0 : ch.hint_cost;
  const user = db.getUserById(req.user.id);

  if (!solved && user.points < cost)
    return res.status(400).json({ error: `Not enough points. Hint costs ${cost} pts, you have ${user.points}.` });

  db.addHint(req.user.id, ch.id, cost);
  const updated = db.getUserById(req.user.id);
  res.json({ ok: true, hint: ch.hint, cost, new_points: updated.points });
});

// === FLAG SUBMIT ===
app.post('/api/submit', auth, (req, res) => {
  const { slug, flag } = req.body || {};
  if (!slug || !flag) return res.status(400).json({ error: 'Missing fields' });
  const ch = CHALLENGES.find(c => c.slug === slug);
  if (!ch) return res.status(404).json({ error: 'Challenge not found' });

  if (db.hasSolved(req.user.id, ch.id))
    return res.json({ ok: false, msg: 'Already solved!' });

  if (flag.trim() !== ch.flag.trim())
    return res.json({ ok: false, msg: 'Incorrect flag. Keep digging!' });

  const awarded = dynamicPoints(ch.base_points, ch.solve_count);
  db.addSolve(req.user.id, ch.id, awarded);
  const updated = db.getUserById(req.user.id);
  res.json({ ok: true, msg: `Flag captured! +${awarded} pts`, points: awarded, new_points: updated.points });
});

// === SCOREBOARD ===
app.get('/api/scoreboard', (req, res) => {
  const users = db.getUsers().map(u => {
    const solves = db.getUserSolves(u.id);
    const last = solves.length ? solves[solves.length - 1].solved_at : null;
    return { id: u.id, username: u.username, avatar_color: u.avatar_color, points: u.points, solve_count: solves.length, last_solve: last };
  });
  users.sort((a, b) => b.points - a.points || (a.last_solve || '').localeCompare(b.last_solve || ''));
  res.json(users.slice(0, 100));
});

// === STATS (public) ===
app.get('/api/stats', (req, res) => {
  const users = db.getUsers();
  const solves = db.getSolves();
  res.json({ players: users.length, total_solves: solves.length, challenges: CHALLENGES.length });
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, '../public/index.html')));
app.listen(PORT, () => console.log(`G4ram Skill Assessment running on :${PORT}`));
