const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');
const { db, dynamicPoints, CHALLENGES } = require('./db');

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'g4ram-skill-secret-2026';
const PORT = process.env.PORT || 3000;
const IS_PROD = process.env.NODE_ENV === 'production';

// ── Security headers ────────────────────────────────────────────────────────
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; " +
    "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com; " +
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com; " +
    "font-src 'self' https://fonts.gstatic.com; " +
    "connect-src 'self'; " +
    "img-src 'self' data:; " +
    "frame-ancestors 'none';"
  );
  next();
});

// ── WAF ─────────────────────────────────────────────────────────────────────
const WAF_RULES = [
  { name:'SQLi',          re: /(\b(union|select|insert|update|delete|drop|truncate|exec|execute)\b[\s\S]{0,40}\b(from|into|table|where|set)\b)/i },
  { name:'SQLi',          re: /('|")\s*(or|and)\s*('|"|\d|true|false)/i },
  { name:'SQLi',          re: /;\s*(drop|delete|insert|update|create)\s/i },
  { name:'XSS',           re: /<\s*(script|iframe|object|embed)[^>]*>/i },
  { name:'XSS',           re: /javascript\s*:/i },
  { name:'XSS',           re: /on(load|error|click|mouseover|focus|blur)\s*=/i },
  { name:'PathTraversal', re: /(\.\.[\/\\]){2,}/ },
  { name:'PathTraversal', re: /(\/etc\/passwd|\/etc\/shadow|\/proc\/self|\/windows\/system32)/i },
  { name:'SSTI',          re: /\{\{[\s\S]+\}\}|\{%[\s\S]+%\}/ },
  { name:'XXE',           re: /<!ENTITY\s/i },
  { name:'CMDi',          re: /[;&|`]\s*(wget|curl|bash|sh|nc|ncat|python3?|perl|ruby)\b/i },
  { name:'SSRF',          re: /(169\.254\.|10\.\d+\.\d+\.\d+|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/i },
];

// Rate limit maps
const RL_GLOBAL  = new Map();
const RL_SUBMIT   = new Map();
const RL_LOGIN    = new Map();
const RL_REGISTER = new Map();

function rlCheck(map, key, max, windowMs) {
  const now = Date.now();
  let e = map.get(key);
  if (!e || now > e.r) { e = { c: 0, r: now + windowMs }; map.set(key, e); }
  e.c++;
  return e.c <= max;
}

function getIP(req) {
  return (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || 'unknown';
}

app.use(express.json({ limit: '20kb' }));
app.use(cookieParser());

app.use((req, res, next) => {
  // Skip static files
  if (/\.(js|css|html|png|ico|woff2?|svg|map)$/.test(req.path)) return next();

  const ip = getIP(req);

  // Global: 150 req/min
  if (!rlCheck(RL_GLOBAL, ip, 150, 60000))
    return res.status(429).json({ error: 'Too many requests. Slow down.' });

  // Login: 10 attempts/min per IP (brute-force protection)
  if (req.path === '/api/login' && !rlCheck(RL_LOGIN, ip, 10, 60000))
    return res.status(429).json({ error: 'Too many login attempts. Try again in a minute.' });
  // Register: 5 per hour per IP (prevent spam accounts)
  if (req.path === '/api/register' && !rlCheck(RL_REGISTER, ip, 5, 3600000))
    return res.status(429).json({ error: 'Too many registration attempts. Try again later.' });

  // Submit: 20 submits/min
  if (req.path === '/api/submit' && !rlCheck(RL_SUBMIT, ip, 20, 60000))
    return res.status(429).json({ error: 'Flag submission rate limit exceeded.' });

  // WAF scan
  const body = JSON.stringify(req.body || {});
  const query = new URLSearchParams(req.query || {}).toString();
  const ua = req.headers['user-agent'] || '';
  const target = [body, query, ua].join(' ');

  for (const rule of WAF_RULES) {
    if (rule.re.test(target)) {
      console.warn(`[WAF] ${rule.name} from ${ip} ${req.method} ${req.path}`);
      return res.status(403).json({ error: `Blocked: ${rule.name}` });
    }
  }

  next();
});

app.use(express.static(path.join(__dirname, '../public')));

// ── Auth middleware ──────────────────────────────────────────────────────────
function auth(req, res, next) {
  const token = req.cookies.token || (req.headers.authorization || '').replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { return res.status(401).json({ error: 'Invalid or expired token' }); }
}

// ── Input sanitize helper ────────────────────────────────────────────────────
function sanitize(str, maxLen = 200) {
  if (typeof str !== 'string') return '';
  return str.trim().slice(0, maxLen);
}

// ── REGISTER ────────────────────────────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  try {
    const username = sanitize(req.body?.username || '', 20);
    const email    = sanitize(req.body?.email    || '', 100);
    const password = sanitize(req.body?.password || '', 128);

    if (!username || !email || !password)
      return res.status(400).json({ error: 'All fields required' });
    if (username.length < 3)
      return res.status(400).json({ error: 'Username must be at least 3 characters' });
    if (!/^[a-zA-Z0-9_\-]+$/.test(username))
      return res.status(400).json({ error: 'Username may only contain letters, numbers, _ and -' });
    if (password.length < 6)
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
      return res.status(400).json({ error: 'Invalid email address' });

    const hash = await bcrypt.hash(password, 12);
    const user = await db.createUser(username, email, hash);
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
    res.cookie('token', token, {
      httpOnly: true, maxAge: 7*24*3600*1000,
      sameSite: 'lax', secure: IS_PROD
    });
    res.json({ ok: true, username: user.username });
  } catch (e) {
    if (e.message === 'USERNAME_TAKEN') return res.status(400).json({ error: 'Username already taken' });
    if (e.message === 'EMAIL_TAKEN')    return res.status(400).json({ error: 'Email already registered' });
    console.error('[register]', e.message);
    res.status(500).json({ error: 'Registration failed. Please try again.' });
  }
});

// ── LOGIN ────────────────────────────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
  try {
    const username = sanitize(req.body?.username || '', 20);
    const password = sanitize(req.body?.password || '', 128);
    if (!username || !password)
      return res.status(400).json({ error: 'All fields required' });

    const user = db.getUserByUsername(username);
    // Always run bcrypt to prevent timing attacks on username enumeration
    const valid = user ? await bcrypt.compare(password, user.password_hash) : await bcrypt.compare(password, '$2a$12$invaliddummyhashfortimingXXXXXXXXXXXXXXXXXXXXXXXXXX');
    if (!user || !valid)
      return res.status(401).json({ error: 'Invalid username or password' });

    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
    res.cookie('token', token, {
      httpOnly: true, maxAge: 7*24*3600*1000,
      sameSite: 'lax', secure: IS_PROD
    });
    res.json({ ok: true, username: user.username });
  } catch (e) {
    console.error('[login]', e.message);
    res.status(500).json({ error: 'Login failed. Please try again.' });
  }
});

// ── LOGOUT ───────────────────────────────────────────────────────────────────
app.post('/api/logout', (req, res) => {
  res.clearCookie('token', { sameSite: 'lax', secure: IS_PROD });
  res.json({ ok: true });
});

// ── ME ───────────────────────────────────────────────────────────────────────
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

// ── CHALLENGES ───────────────────────────────────────────────────────────────
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

// ── HINT UNLOCK ──────────────────────────────────────────────────────────────
app.post('/api/hint', auth, async (req, res) => {
  try {
    const slug = sanitize(req.body?.slug || '', 100);
    if (!slug) return res.status(400).json({ error: 'Missing slug' });

    const ch = CHALLENGES.find(c => c.slug === slug);
    if (!ch) return res.status(404).json({ error: 'Challenge not found' });

    // Already unlocked?
    if (db.hasHint(req.user.id, ch.id)) {
      return res.json({ ok: true, hint: ch.hint, cost: 0, already: true });
    }

    const solved = db.hasSolved(req.user.id, ch.id);
    const cost = solved ? 0 : ch.hint_cost;
    const user = db.getUserById(req.user.id);

    if (!solved && user.points < cost)
      return res.status(400).json({ error: `Not enough points. Hint costs ${cost} pts, you have ${user.points}.` });

    const result = await db.addHint(req.user.id, ch.id, cost);
    if (result.duplicate) return res.json({ ok: true, hint: ch.hint, cost: 0, already: true });
    if (result.insufficient) return res.status(400).json({ error: 'Not enough points.' });

    const updated = db.getUserById(req.user.id);
    res.json({ ok: true, hint: ch.hint, cost, new_points: updated.points });
  } catch (e) {
    console.error('[hint]', e.message);
    res.status(500).json({ error: 'Failed to unlock hint.' });
  }
});

// ── FLAG SUBMIT ───────────────────────────────────────────────────────────────
app.post('/api/submit', auth, async (req, res) => {
  try {
    const slug = sanitize(req.body?.slug || '', 100);
    const flag = sanitize(req.body?.flag || '', 300);
    if (!slug || !flag) return res.status(400).json({ error: 'Missing fields' });

    const ch = CHALLENGES.find(c => c.slug === slug);
    if (!ch) return res.status(404).json({ error: 'Challenge not found' });

    if (db.hasSolved(req.user.id, ch.id))
      return res.json({ ok: false, msg: 'Already solved!' });

    // Constant-time flag comparison to prevent timing attacks
    const expected = Buffer.from(ch.flag.trim());
    const submitted = Buffer.from(flag.trim());
    const match = expected.length === submitted.length &&
      require('crypto').timingSafeEqual(expected, submitted);

    if (!match)
      return res.json({ ok: false, msg: 'Incorrect flag. Keep digging!' });

    const awarded = dynamicPoints(ch.base_points, ch.solve_count);
    const result = await db.addSolve(req.user.id, ch.id, awarded);
    if (result.duplicate) return res.json({ ok: false, msg: 'Already solved!' });

    const updated = db.getUserById(req.user.id);
    res.json({ ok: true, msg: `Flag captured! +${awarded} pts`, points: awarded, new_points: updated.points });
  } catch (e) {
    console.error('[submit]', e.message);
    res.status(500).json({ error: 'Submission failed.' });
  }
});

// ── SCOREBOARD ───────────────────────────────────────────────────────────────
app.get('/api/scoreboard', auth, (req, res) => {
  const users = db.getUsers().map(u => {
    const solves = db.getUserSolves(u.id);
    const last = solves.length ? solves[solves.length - 1].solved_at : null;
    return {
      id: u.id, username: u.username, avatar_color: u.avatar_color,
      points: u.points, solve_count: solves.length, last_solve: last
    };
  });
  users.sort((a, b) => b.points - a.points || (a.last_solve || '').localeCompare(b.last_solve || ''));
  res.json(users.slice(0, 100));
});

// ── STATS ─────────────────────────────────────────────────────────────────────
app.get('/api/stats', (req, res) => {
  res.json({
    players: db.getUsers().length,
    total_solves: db.getSolves().length,
    challenges: CHALLENGES.length
  });
});

// ── SPA fallback ──────────────────────────────────────────────────────────────
app.get('*', (req, res) => res.sendFile(path.join(__dirname, '../public/index.html')));

app.listen(PORT, () => console.log(`G4ram Skill Assessment running on :${PORT}`));
