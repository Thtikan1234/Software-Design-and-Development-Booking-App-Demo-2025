const express    = require('express');
const cors       = require('cors');
const jwt        = require('jsonwebtoken');
const bcrypt     = require('bcryptjs');
const db         = require('./database');

const app        = express();
const PORT       = 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

app.use(cors());
app.use(express.json());

// Middleware: ตรวจสอบ JWT Token ก่อนเข้าถึง protected routes
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'กรุณาเข้าสู่ระบบก่อน' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Token ไม่ถูกต้องหรือหมดอายุ' });
    }
    req.user = user;
    next();
  });
};

// POST /api/login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'กรุณากรอก username และ password' });
  }

  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (err)   return res.status(500).json({ error: err.message });
    if (!user) return res.status(401).json({ error: 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง' });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง' });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      token,
      user: { id: user.id, username: user.username, role: user.role }
    });
  });
});

// POST /api/register
app.post('/api/register', async (req, res) => {
  const { username, password, role } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'กรุณากรอก username และ password' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const sql = `INSERT INTO users (username, password, role) VALUES (?, ?, ?)`;
    
    db.run(sql, [username, hashedPassword, role || 'user'], function(err) {
      if (err) {
        if (err.message.includes('UNIQUE')) {
          return res.status(400).json({ error: 'ชื่อผู้ใช้นี้มีอยู่แล้ว' });
        }
        return res.status(400).json({ error: err.message });
      }
      res.status(201).json({ id: this.lastID, username, role: role || 'user' });
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// POST /api/bookings — สร้างการจองใหม่
app.post('/api/bookings', (req, res) => {
  const { fullname, email, phone, checkin, checkout, roomtype, guests } = req.body;
  
  // ตรวจสอบข้อมูลที่บังคับ
  if (!fullname || !email || !phone || !checkin || !checkout || !roomtype || guests === undefined) {
    return res.status(400).json({ 
      error: 'กรุณากรอกข้อมูลให้ครบถ้วน',
      required: { fullname, email, phone, checkin, checkout, roomtype, guests }
    });
  }

  const sql = `INSERT INTO bookings (fullname, email, phone, checkin, checkout, roomtype, guests)
               VALUES (?, ?, ?, ?, ?, ?, ?)`;

  db.run(sql, [fullname, email, phone, checkin, checkout, roomtype, guests], function(err) {
    if (err) return res.status(400).json({ error: err.message });
    db.get('SELECT * FROM bookings WHERE id = ?', [this.lastID], (err, row) => {
      if (err) return res.status(400).json({ error: err.message });
      res.status(201).json(row);
    });
  });
});

// GET /api/bookings
app.get('/api/bookings', (req, res) => {
  db.all('SELECT * FROM bookings ORDER BY created_at DESC', [], (err, rows) => {
    if (err) return res.status(400).json({ error: err.message });
    res.json(rows);
  });
});

// GET /api/bookings/:id
app.get('/api/bookings/:id', (req, res) => {
  db.get('SELECT * FROM bookings WHERE id = ?', [req.params.id], (err, row) => {
    if (err)  return res.status(400).json({ error: err.message });
    if (!row) return res.status(404).json({ error: 'ไม่พบข้อมูลการจอง' });
    res.json(row);
  });
});

// PUT /api/bookings/:id — อัปเดตการจอง (ต้อง login)
app.put('/api/bookings/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  const { fullname, email, phone, checkin, checkout, roomtype, guests, comment } = req.body;

  console.log('PUT /api/bookings/:id - ID:', id, 'By user:', req.user.username, 'Received:', req.body);

  if (isNaN(id)) {
    return res.status(400).json({ error: 'ID ต้องเป็นตัวเลข' });
  }

  // Validation
  if (!fullname || !email || !phone || !checkin || !checkout || !roomtype || guests === undefined) {
    return res.status(400).json({ 
      error: 'กรุณากรอกข้อมูลให้ครบถ้วน (fullname, email, phone, checkin, checkout, roomtype, guests)',
      received: { fullname, email, phone, checkin, checkout, roomtype, guests }
    });
  }

  // Email validation
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ error: 'Email ไม่ถูกต้อง' });
  }

  // Guests validation
  if (isNaN(guests) || guests < 1) {
    return res.status(400).json({ error: 'จำนวนแขกต้องเป็นตัวเลขมากกว่า 0' });
  }

  // Check if booking exists first
  db.get('SELECT * FROM bookings WHERE id = ?', [id], (err, existing) => {
    if (err) {
      return res.status(400).json({ error: 'Database error: ' + err.message });
    }

    if (!existing) {
      return res.status(404).json({ error: 'ไม่พบข้อมูลการจองที่ต้องการอัปเดต' });
    }

    const sql = `UPDATE bookings
                 SET fullname=?, email=?, phone=?, checkin=?, checkout=?,
                     roomtype=?, guests=?, comment=?, updated_at=CURRENT_TIMESTAMP
                 WHERE id=?`;

    db.run(sql, [fullname, email, phone, checkin, checkout, roomtype, guests, comment || null, id],
      function(err) {
        if (err) {
          return res.status(400).json({ error: 'Database error: ' + err.message });
        }

        if (this.changes === 0) {
          return res.status(404).json({ error: 'ไม่พบข้อมูลการจองที่ต้องการอัปเดต' });
        }

        db.get('SELECT * FROM bookings WHERE id = ?', [id], (err, row) => {
          if (err) {
            return res.status(400).json({ error: 'Database error: ' + err.message });
          }

          res.json({
            status: 'success',
            message: `อัปเดตการจองสำเร็จโดย ${req.user.username}`,
            updatedBy: req.user.username,
            data: row
          });
        });
      }
    );
  });
});

// DELETE /api/bookings/:id
app.delete('/api/bookings/:id', (req, res) => {
  db.run('DELETE FROM bookings WHERE id = ?', [req.params.id], function(err) {
    if (err) return res.status(400).json({ error: err.message });
    if (this.changes === 0) {
      return res.status(404).json({ error: 'ไม่พบข้อมูล' });
    }

    res.json({
      status: 'ลบข้อมูลสำเร็จ'
    });
  });
});

// GET /api/users
app.get('/api/users', authenticateToken, (req, res) => {
  const sql = `SELECT id, username, role FROM users`;

  db.all(sql, [], (err, rows) => {
    if (err) return res.status(400).json({ error: err.message });
    res.json(rows);
  });
});

// Create tables
db.run(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'user'
  )
`);

db.run(`
  CREATE TABLE IF NOT EXISTS bookings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fullname TEXT NOT NULL,
    email TEXT NOT NULL,
    phone TEXT NOT NULL,
    checkin TEXT NOT NULL,
    checkout TEXT NOT NULL,
    roomtype TEXT NOT NULL,
    guests INTEGER NOT NULL,
    comment TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));