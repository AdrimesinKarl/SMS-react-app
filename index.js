const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const port = 5000;
const SECRET_KEY = 'secret123';  // Change this later

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Open database
const db = new sqlite3.Database('./students.db');

// Create users table
db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  password TEXT
)`);

// Create students table (updated with yearLevel)
db.run(`CREATE TABLE IF NOT EXISTS students (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT,
  age INTEGER,
  yearLevel TEXT
)`);

// Add admin user if not exists
const adminUsername = 'admin';
const adminPasswordHash = bcrypt.hashSync('admin123', 10);
db.get('SELECT * FROM users WHERE username = ?', [adminUsername], (err, row) => {
  if (!row) {
    db.run('INSERT INTO users (username, password) VALUES (?, ?)', [adminUsername, adminPasswordHash]);
    console.log('Admin user created');
  }
});

// Register
app.post('/api/register', (req, res) => {
  const { username, password } = req.body;
  const hashed = bcrypt.hashSync(password, 10);
  db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashed], function(err) {
    if (err) return res.status(400).json({ error: 'User exists' });
    res.json({ message: 'Registered!' });
  });
});

// Login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (!user) return res.status(400).json({ error: 'Invalid' });
    const valid = bcrypt.compareSync(password, user.password);
    if (!valid) return res.status(400).json({ error: 'Invalid' });
    const token = jwt.sign({ id: user.id, username: user.username }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ token });
  });
});

// Auth middleware
function auth(req, res, next) {
  const token = req.headers.authorization;
  if (!token) return res.status(401).json({ error: 'No token' });
  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) return res.status(401).json({ error: 'Invalid token' });
    req.user = decoded;
    next();
  });
}

// CRUD for students
app.get('/api/students', auth, (req, res) => {
  db.all('SELECT * FROM students', [], (err, rows) => {
    res.json(rows);
  });
});
app.post('/api/students', auth, (req, res) => {
  const { name, age, yearLevel } = req.body;
  db.run('INSERT INTO students (name, age, yearLevel) VALUES (?, ?, ?)', [name, age, yearLevel], function(err) {
    res.json({ id: this.lastID });
  });
});
app.put('/api/students/:id', auth, (req, res) => {
  const { name, age, yearLevel } = req.body;
  db.run('UPDATE students SET name = ?, age = ?, yearLevel = ? WHERE id = ?', [name, age, yearLevel, req.params.id], function(err) {
    res.json({ updated: true });
  });
});
app.delete('/api/students/:id', auth, (req, res) => {
  db.run('DELETE FROM students WHERE id = ?', [req.params.id], function(err) {
    res.json({ deleted: true });
  });
});

app.listen(port, () => {
  console.log(`Server started on http://localhost:${port}`);
});
