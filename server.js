require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { Pool } = require('pg');

const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
const SECRET = process.env.JWT_SECRET;
const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(express.static('public'));

const scrypt = (pw, salt) => new Promise((res, rej) =>
  crypto.scrypt(pw, salt, 64, { N: 2 ** 17, r: 8, p: 1, maxmem: 256 * 1024 * 1024 },
    (e, k) => (e ? rej(e) : res(k))));
const hashStored = async (pw) => {
  const salt = crypto.randomBytes(16);
  return salt.toString('hex') + ':' + (await scrypt(pw, salt)).toString('hex');
};
const verifyStored = async (pw, stored) => {
  const [s, h] = stored.split(':');
  const a = await scrypt(pw, Buffer.from(s, 'hex'));
  return crypto.timingSafeEqual(a, Buffer.from(h, 'hex'));
};

const setSession = (res, u) =>
  res.cookie('session', jwt.sign({ id: u.id, role: u.role_name, name: u.name }, SECRET, { expiresIn: '2h' }),
    { httpOnly: true, sameSite: 'strict', secure: process.env.NODE_ENV === 'production' });

app.post('/api/register', async (req, res) => {
  const { username, name, password } = req.body || {};
  if (!/^[a-z0-9_]{3,32}$/.test(username || '') || !name ||
      typeof password !== 'string' || password.length < 12 || password.length > 128)
    return res.status(400).json({ error: 'Username must be 3-32 characters (a-z, 0-9, _). Password must be 12-128 characters.' });
  try {
    const { rows } = await pool.query(
      `INSERT INTO users (username, name, hashed_password, role_id)
       VALUES ($1, $2, $3, (SELECT id FROM roles WHERE role_name = 'operator'))
       RETURNING id, name, 'operator' AS role_name`,
      [username, name, await hashStored(password)]);
    setSession(res, rows[0]);
    res.json({ ok: true });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'Username already taken.' });
    console.error(e);
    res.status(500).json({ error: 'Server error.' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (typeof password !== 'string' || password.length > 128)
      return res.status(401).json({ error: 'Wrong username or password.' });
    const { rows } = await pool.query(
      `SELECT u.id, u.name, u.hashed_password, r.role_name
       FROM users u JOIN roles r ON r.id = u.role_id WHERE u.username = $1`, [username || '']);
    // Same error for unknown user and bad password.
    if (!rows[0] || !(await verifyStored(password, rows[0].hashed_password)))
      return res.status(401).json({ error: 'Wrong username or password.' });
    setSession(res, rows[0]);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error.' });
  }
});

app.post('/api/logout', (req, res) => res.clearCookie('session').json({ ok: true }));

const auth = async (req, res, next) => {
  try {
    const p = jwt.verify(req.cookies.session, SECRET);
    const { rows } = await pool.query(
      `SELECT u.id, u.name, r.role_name AS role
       FROM users u JOIN roles r ON r.id = u.role_id WHERE u.id = $1`, [p.id]);
    if (!rows[0]) return res.status(401).json({ error: 'Not signed in.' });
    req.user = rows[0];
    next();
  } catch { res.status(401).json({ error: 'Not signed in.' }); }
};

const adminOnly = (req, res, next) =>
  req.user.role === 'admin' ? next() : res.status(403).json({ error: 'Admins only.' });

// Placeholder data per role; swap in real queries later. Enforcement is server-side.
const DASH = {
  operator: { title: 'Machine operations', stats: [['Active machines', 12], ['Fuel used today (gal)', 184], ['Open alerts', 3]],
    rows: [['Tractor 8R-210', 'Field 14', 'Working'], ['Sprayer R4045', 'Field 9', 'Idle'], ['Combine S780', 'Field 2', 'Service due']] },
  agronomist: { title: 'Field conditions', stats: [['Fields monitored', 27], ['Avg soil moisture', '23%'], ['Irrigation flags', 4]],
    rows: [['Field 14', 'Moisture 19%', 'Irrigate'], ['Field 9', 'Moisture 26%', 'OK'], ['Field 2', 'Moisture 21%', 'Watch']] },
  admin: { title: 'Fleet administration', stats: [['Registered users', null], ['Machines enrolled', 34], ['Open alerts', 7]],
    rows: [] },
};

app.get('/api/dashboard', auth, async (req, res) => {
  const d = structuredClone(DASH[req.user.role]);
  if (req.user.role === 'admin') {
    const { rows } = await pool.query(
      `SELECT u.id, u.username, u.name, r.role_name
      FROM users u JOIN roles r ON r.id = u.role_id ORDER BY u.id`);
    d.stats[0][1] = rows.length;
    d.rows = rows.map((r) => [r.username, r.name, r.role_name]);
    d.users = rows;
    d.roles = (await pool.query('SELECT role_name FROM roles ORDER BY id')).rows.map((r) => r.role_name);
  }
  res.json({ user: req.user, ...d });
});

app.patch('/api/users/:id/role', auth, adminOnly, async (req, res) => {
  if (String(req.user.id) === req.params.id)
    return res.status(400).json({ error: "You can't change your own role." });
  try {
    const { rowCount } = await pool.query(
      'UPDATE users SET role_id = (SELECT id FROM roles WHERE role_name = $1) WHERE id = $2',
      [req.body?.role, req.params.id]);
    if (!rowCount) return res.status(404).json({ error: 'User not found.' });
    res.json({ ok: true });
  } catch (e) {
    // 23502: role name matched nothing; 22P02: id wasn't a number
    if (e.code === '23502' || e.code === '22P02') return res.status(400).json({ error: 'Unknown role or user.' });
    console.error(e);
    res.status(500).json({ error: 'Server error.' });
  }
});

app.listen(process.env.PORT || 3000, () => console.log('Field Ops on http://localhost:' + (process.env.PORT || 3000)));