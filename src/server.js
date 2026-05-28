const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');
const { db, dynamicPoints, CHALLENGES } = require('./db');

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'g4ram-skill-secret-2026';
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(cookieParser());
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
