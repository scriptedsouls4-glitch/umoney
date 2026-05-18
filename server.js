require('dotenv').config();
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const twilio = require('twilio');
const session = require('express-session');
const crypto = require('crypto');

const app = express();
app.use(express.json());
app.use(express.static('public'));
app.use(session({ secret: 'otp_secret_key', resave: false, saveUninitialized: true }));

// Database setup
const db = new sqlite3.Database('./database.sqlite');
db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  phone TEXT UNIQUE,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`);
db.run(`CREATE TABLE IF NOT EXISTS otps (
  phone TEXT,
  otp TEXT,
  expires_at DATETIME,
  PRIMARY KEY (phone)
)`);

// Twilio client
const client = twilio(process.env.TWILIO_SID, process.env.TWILIO_AUTH_TOKEN);

// Generate 6-digit OTP
function generateOTP() {
  return crypto.randomInt(100000, 999999).toString();
}

// Send OTP via SMS
async function sendOTP(phone, otp) {
  await client.messages.create({
    body: `Your OTP is: ${otp}. Valid for 5 minutes.`,
    from: process.env.TWILIO_PHONE,
    to: phone
  });
}

// API: Request OTP
app.post('/api/send-otp', async (req, res) => {
  const { phone } = req.body;
  if (!phone) return res.status(400).json({ error: 'Phone required' });

  const otp = generateOTP();
  const expires = new Date(Date.now() + 5 * 60 * 1000).toISOString();

  db.run(`INSERT OR REPLACE INTO otps (phone, otp, expires_at) VALUES (?, ?, ?)`,
    [phone, otp, expires], async (err) => {
      if (err) return res.status(500).json({ error: 'DB error' });
      try {
        await sendOTP(phone, otp);
        res.json({ message: 'OTP sent' });
      } catch (err) {
        res.status(500).json({ error: 'SMS failed' });
      }
    });
});

// API: Verify OTP & create/login account
app.post('/api/verify-otp', (req, res) => {
  const { phone, otp } = req.body;
  if (!phone || !otp) return res.status(400).json({ error: 'Phone and OTP required' });

  db.get(`SELECT otp, expires_at FROM otps WHERE phone = ?`, [phone], (err, row) => {
    if (err || !row) return res.status(400).json({ error: 'No OTP request found' });
    if (new Date(row.expires_at) < new Date()) return res.status(400).json({ error: 'OTP expired' });
    if (row.otp !== otp) return res.status(400).json({ error: 'Invalid OTP' });

    // OTP valid → create or fetch user
    db.run(`INSERT OR IGNORE INTO users (phone) VALUES (?)`, [phone], function(err) {
      if (err) return res.status(500).json({ error: 'User creation failed' });
      db.get(`SELECT id, phone, created_at FROM users WHERE phone = ?`, [phone], (err, user) => {
        if (err) return res.status(500).json({ error: 'DB error' });
        req.session.userId = user.id;
        res.json({ success: true, user, isNew: this.changes === 1 });
      });
    });
  });
});

// Protected route example
app.get('/api/me', (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Unauthorized' });
  db.get(`SELECT id, phone, created_at FROM users WHERE id = ?`, [req.session.userId], (err, user) => {
    res.json(user);
  });
});

app.listen(3000, () => console.log('Server running on http://localhost:3000'));