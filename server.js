require('dotenv').config();
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const twilio = require('twilio');
const session = require('express-session');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(session({
    secret: 'xero_premium_secure_key_2024',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, maxAge: 3600000 }
}));

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
let client = null;
if (process.env.TWILIO_SID && process.env.TWILIO_SID !== 'your_account_sid_here') {
    try {
        client = twilio(process.env.TWILIO_SID, process.env.TWILIO_AUTH_TOKEN);
        console.log('✅ Twilio client ready');
    } catch (err) {
        console.log('⚠️ Twilio error:', err.message);
    }
} else {
    console.log('⚠️ Twilio not configured - using demo mode');
}

// Generate OTP
function generateOTP() {
    return crypto.randomInt(100000, 999999).toString();
}

// Send OTP
async function sendOTP(phone, otp) {
    const cleanPhone = phone.replace(/\s/g, '');
    
    if (client) {
        try {
            await client.messages.create({
                body: `Your Xero OTP is: ${otp}. Valid for 5 minutes.`,
                from: process.env.TWILIO_PHONE,
                to: cleanPhone
            });
            console.log(`✅ OTP sent to ${cleanPhone}`);
        } catch (err) {
            console.log(`❌ SMS failed:`, err.message);
            throw new Error('SMS sending failed');
        }
    } else {
        console.log(`📱 [DEMO MODE] OTP for ${cleanPhone}: ${otp}`);
        // In demo mode, we don't throw error
    }
}

// API: Send OTP
app.post('/api/send-otp', async (req, res) => {
    const { phone } = req.body;
    
    if (!phone) {
        return res.status(400).json({ error: 'Phone number required' });
    }
    
    const cleanPhone = phone.replace(/\s/g, '');
    const otp = generateOTP();
    const expires = new Date(Date.now() + 5 * 60 * 1000).toISOString();
    
    db.run(`INSERT OR REPLACE INTO otps (phone, otp, expires_at) VALUES (?, ?, ?)`,
        [cleanPhone, otp, expires], async (err) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }
            
            try {
                await sendOTP(cleanPhone, otp);
                res.json({ success: true, message: 'OTP sent successfully', demoMode: !client });
            } catch (err) {
                res.status(500).json({ error: 'Failed to send OTP. Check Twilio credentials.' });
            }
        });
});

// API: Verify OTP
app.post('/api/verify-otp', (req, res) => {
    const { phone, otp } = req.body;
    
    if (!phone || !otp) {
        return res.status(400).json({ error: 'Phone and OTP required' });
    }
    
    const cleanPhone = phone.replace(/\s/g, '');
    
    db.get(`SELECT otp, expires_at FROM otps WHERE phone = ?`, [cleanPhone], (err, row) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        
        if (!row) {
            return res.status(400).json({ error: 'No OTP found. Request new OTP.' });
        }
        
        if (new Date(row.expires_at) < new Date()) {
            return res.status(400).json({ error: 'OTP expired. Request new one.' });
        }
        
        if (row.otp !== otp) {
            return res.status(400).json({ error: 'Invalid OTP. Try again.' });
        }
        
        // Create or get user
        db.run(`INSERT OR IGNORE INTO users (phone) VALUES (?)`, [cleanPhone], function(err) {
            if (err) {
                return res.status(500).json({ error: 'User creation failed' });
            }
            
            db.get(`SELECT id, phone, created_at FROM users WHERE phone = ?`, [cleanPhone], (err, user) => {
                if (err || !user) {
                    return res.status(500).json({ error: 'User not found' });
                }
                
                req.session.userId = user.id;
                req.session.save();
                
                res.json({
                    success: true,
                    user: {
                        id: user.id,
                        phone: user.phone,
                        created_at: user.created_at
                    },
                    isNew: this.changes === 1
                });
            });
        });
    });
});

// API: Logout
app.post('/api/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

// API: Get current user
app.get('/api/me', (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    
    db.get(`SELECT id, phone, created_at FROM users WHERE id = ?`, [req.session.userId], (err, user) => {
        if (err || !user) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.json(user);
    });
});

// Serve HTML
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
    console.log(`\n🚀 Server running on http://localhost:${PORT}`);
    console.log(`📱 Open this URL in browser\n`);
});
