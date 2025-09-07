import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import Database from 'better-sqlite3';

const app = express();
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';
const UPLOAD_ROOT = path.join(process.cwd(), 'uploads');

// ensure upload dir exists
fs.mkdirSync(UPLOAD_ROOT, { recursive: true });

// DB init
const db = new Database('granduer.db');
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  name TEXT,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS rooms (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  client_type TEXT NOT NULL CHECK (client_type IN ('student','visitor','worker')),
  owner_id INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (owner_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS memberships (
  user_id INTEGER NOT NULL,
  room_id INTEGER NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin','client')),
  PRIMARY KEY (user_id, room_id),
  FOREIGN KEY (user_id) REFERENCES users(id),
  FOREIGN KEY (room_id) REFERENCES rooms(id)
);
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  room_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  text TEXT,
  file_url TEXT,
  file_name TEXT,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (room_id) REFERENCES rooms(id),
  FOREIGN KEY (user_id) REFERENCES users(id)
);
`);

// middleware
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(UPLOAD_ROOT)); // serve files

// auth helpers
function signToken(user) {
  return jwt.sign({ uid: user.id, email: user.email, name: user.name }, JWT_SECRET, { expiresIn: '7d' });
}
function requireAuth(req, res, next) {
  const hdr = req.headers.authorization || '';
  const token = hdr.startsWith('Bearer ') ? hdr.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Missing token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// storage per room: /uploads/<roomId>/
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const roomId = req.params.id;
    const dir = path.join(UPLOAD_ROOT, String(roomId));
    fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (_req, file, cb) => {
    const ts = Date.now();
    const safe = file.originalname.replace(/[^\w.\-]+/g, '_');
    cb(null, `${ts}-${safe}`);
  }
});
const upload = multer({ storage });

// AUTH
app.post('/auth/signup', (req, res) => {
  const { email, password, name } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email & password required' });
  const hash = bcrypt.hashSync(password, 10);
  try {
    const stmt = db.prepare('INSERT INTO users (email, password_hash, name, created_at) VALUES (?, ?, ?, ?)');
    const info = stmt.run(email.toLowerCase(), hash, name || null, Date.now());
    const user = { id: info.lastInsertRowid, email, name };
    const token = signToken(user);
    res.json({ token, user });
  } catch (e) {
    if (String(e).includes('UNIQUE')) return res.status(409).json({ error: 'Email already exists' });
    res.status(500).json({ error: 'Signup failed' });
  }
});

app.post('/auth/login', (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email & password required' });
  const row = db.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase());
  if (!row) return res.status(401).json({ error: 'Invalid credentials' });
  const ok = bcrypt.compareSync(password, row.password_hash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
  const token = signToken(row);
  res.json({ token, user: { id: row.id, email: row.email, name: row.name } });
});

app.get('/me', requireAuth, (req, res) => {
  res.json({ user: req.user });
});

// ROOMS
app.post('/rooms', requireAuth, (req, res) => {
  const { name, clientType } = req.body || {};
  if (!name || !clientType) return res.status(400).json({ error: 'name & clientType required' });
  const stmt = db.prepare('INSERT INTO rooms (name, client_type, owner_id, created_at) VALUES (?, ?, ?, ?)');
  const info = stmt.run(name, clientType, req.user.uid, Date.now());
  // make creator a member (admin)
  db.prepare('INSERT INTO memberships (user_id, room_id, role) VALUES (?, ?, ?)').run(req.user.uid, info.lastInsertRowid, 'admin');
  res.json({ id: info.lastInsertRowid, name, clientType });
});

app.get('/rooms', requireAuth, (req, res) => {
  const rows = db.prepare(`
    SELECT r.id, r.name, r.client_type as clientType, r.created_at as createdAt, m.role
    FROM rooms r
    JOIN memberships m ON m.room_id = r.id
    WHERE m.user_id = ?
    ORDER BY r.created_at DESC
  `).all(req.user.uid);
  res.json(rows);
});

// Add or invite a user to a room (when your client signs up)
app.post('/rooms/:id/members', requireAuth, (req, res) => {
  const { userEmail, role } = req.body || {};
  if (!userEmail || !role) return res.status(400).json({ error: 'userEmail & role required' });
  const roomId = Number(req.params.id);
  const room = db.prepare('SELECT * FROM rooms WHERE id = ?').get(roomId);
  if (!room) return res.status(404).json({ error: 'Room not found' });

  const me = db.prepare('SELECT role FROM memberships WHERE user_id = ? AND room_id = ?').get(req.user.uid, roomId);
  if (!me || me.role !== 'admin') return res.status(403).json({ error: 'Admin only' });

  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(userEmail.toLowerCase());
  if (!user) return res.status(404).json({ error: 'User must sign up first' });
  try {
    db.prepare('INSERT INTO memberships (user_id, room_id, role) VALUES (?, ?, ?)').run(user.id, roomId, role);
  } catch (_) {} // ignore if already a member
  res.json({ ok: true });
});

// MESSAGES
app.get('/rooms/:id/messages', requireAuth, (req, res) => {
  const roomId = Number(req.params.id);
  const member = db.prepare('SELECT 1 FROM memberships WHERE user_id = ? AND room_id = ?').get(req.user.uid, roomId);
  if (!member) return res.status(403).json({ error: 'Not a member' });
  const rows = db.prepare(`
    SELECT m.id, m.text, m.file_url as fileUrl, m.file_name as fileName, m.created_at as createdAt,
           u.name as displayName, u.email
    FROM messages m
    JOIN users u ON u.id = m.user_id
    WHERE m.room_id = ?
    ORDER BY m.created_at ASC
  `).all(roomId);
  res.json(rows);
});

app.post('/rooms/:id/messages', requireAuth, (req, res) => {
  const roomId = Number(req.params.id);
  const member = db.prepare('SELECT 1 FROM memberships WHERE user_id = ? AND room_id = ?').get(req.user.uid, roomId);
  if (!member) return res.status(403).json({ error: 'Not a member' });
  const { text } = req.body || {};
  if (!text || !text.trim()) return res.status(400).json({ error: 'text required' });
  const stmt = db.prepare('INSERT INTO messages (room_id, user_id, text, created_at) VALUES (?, ?, ?, ?)');
  const info = stmt.run(roomId, req.user.uid, text.trim(), Date.now());
  res.json({ id: info.lastInsertRowid, text: text.trim() });
});

// FILE UPLOADS
app.post('/rooms/:id/upload', requireAuth, upload.single('file'), (req, res) => {
  const roomId = Number(req.params.id);
  const member = db.prepare('SELECT 1 FROM memberships WHERE user_id = ? AND room_id = ?').get(req.user.uid, roomId);
  if (!member) return res.status(403).json({ error: 'Not a member' });
  if (!req.file) return res.status(400).json({ error: 'file required' });
  const fileUrl = `/uploads/${roomId}/${req.file.filename}`;
  db.prepare('INSERT INTO messages (room_id, user_id, file_url, file_name, created_at) VALUES (?, ?, ?, ?, ?)')
    .run(roomId, req.user.uid, fileUrl, req.file.originalname, Date.now());
  res.json({ fileUrl: `${process.env.BASE_URL || ''}${fileUrl}`, fileName: req.file.originalname });
});

app.listen(PORT, () => {
  console.log(`Granduer server running on http://localhost:${PORT}`);
});
