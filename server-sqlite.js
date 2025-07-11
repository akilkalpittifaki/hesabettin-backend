const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'hesabettin-secret-key-2024';

// Middleware
app.use(cors());
app.use(express.json());

// SQLite Database
const dbPath = path.join(__dirname, 'hesabettin.db');
const db = new sqlite3.Database(dbPath);

// Test endpoint
app.get('/api/test', (req, res) => {
  res.json({ 
    message: 'Backend çalışıyor! (SQLite)', 
    timestamp: new Date().toISOString(),
    database: 'SQLite - hesabettin.db' 
  });
});

// Initialize Database
function initDatabase() {
  db.serialize(() => {
    // Users table
    db.run(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Hesaplar table
    db.run(`
      CREATE TABLE IF NOT EXISTS hesaplar (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        ad TEXT NOT NULL,
        tur TEXT NOT NULL,
        bakiye REAL NOT NULL DEFAULT 0,
        kesimTarihi TEXT NULL,
        olusturulmaTarihi DATETIME DEFAULT CURRENT_TIMESTAMP,
        ekstreLimit REAL NULL,
        minOdemeOrani REAL NULL,
        faizOrani REAL NULL,
        ekstreAktif BOOLEAN DEFAULT FALSE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    // İşlemler table
    db.run(`
      CREATE TABLE IF NOT EXISTS islemler (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        tur TEXT NOT NULL,
        tarih INTEGER NOT NULL,
        hesapId INTEGER NOT NULL,
        hedefHesapId INTEGER NULL,
        kategori TEXT NULL,
        tutar REAL NOT NULL,
        notlar TEXT NULL,
        olusturulmaTarihi INTEGER NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (hesapId) REFERENCES hesaplar(id) ON DELETE CASCADE,
        FOREIGN KEY (hedefHesapId) REFERENCES hesaplar(id) ON DELETE CASCADE
      )
    `);

    console.log('✅ SQLite Database initialized');
  });
}

// JWT Middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Token gerekli' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Geçersiz token' });
    }
    req.user = user;
    next();
  });
}

// ==================== AUTH ROUTES ====================

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Tüm alanları doldurun' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Şifre en az 6 karakter olmalı' });
    }

    // Check if email exists
    db.get('SELECT id FROM users WHERE email = ?', [email], async (err, row) => {
      if (err) {
        return res.status(500).json({ error: 'Veritabanı hatası' });
      }

      if (row) {
        return res.status(400).json({ error: 'Bu e-posta zaten kayıtlı' });
      }

      // Hash password
      const saltRounds = 10;
      const passwordHash = await bcrypt.hash(password, saltRounds);

      // Insert user
      db.run('INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)', 
        [name, email, passwordHash], 
        function(err) {
          if (err) {
            return res.status(500).json({ error: 'Kullanıcı oluşturulamadı' });
          }

          const userId = this.lastID;

          // Create JWT token
          const token = jwt.sign(
            { userId, email, name },
            JWT_SECRET,
            { expiresIn: '7d' }
          );

          res.status(201).json({
            message: 'Kullanıcı başarıyla kaydedildi',
            token,
            user: { id: userId, name, email }
          });
        }
      );
    });

  } catch (error) {
    console.error('Register hatası:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'E-posta ve şifre gerekli' });
    }

    // Find user
    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
      if (err) {
        return res.status(500).json({ error: 'Veritabanı hatası' });
      }

      if (!user) {
        return res.status(401).json({ error: 'Geçersiz e-posta veya şifre' });
      }

      // Check password
      const isValidPassword = await bcrypt.compare(password, user.password_hash);
      if (!isValidPassword) {
        return res.status(401).json({ error: 'Geçersiz e-posta veya şifre' });
      }

      // Create JWT token
      const token = jwt.sign(
        { userId: user.id, email: user.email, name: user.name },
        JWT_SECRET,
        { expiresIn: '7d' }
      );

      res.json({
        message: 'Giriş başarılı',
        token,
        user: { id: user.id, name: user.name, email: user.email }
      });
    });

  } catch (error) {
    console.error('Login hatası:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// ==================== HESAPLAR ROUTES ====================

// Get all hesaplar
app.get('/api/hesaplar', authenticateToken, (req, res) => {
  db.all('SELECT * FROM hesaplar WHERE user_id = ?', [req.user.userId], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Hesaplar getirilemedi' });
    }
    res.json(rows);
  });
});

// Add hesap
app.post('/api/hesaplar', authenticateToken, (req, res) => {
  const { ad, tur, bakiye, kesimTarihi, ekstreLimit, minOdemeOrani, faizOrani, ekstreAktif } = req.body;

  db.run(
    `INSERT INTO hesaplar (user_id, ad, tur, bakiye, kesimTarihi, ekstreLimit, minOdemeOrani, faizOrani, ekstreAktif) 
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [req.user.userId, ad, tur, bakiye || 0, kesimTarihi, ekstreLimit, minOdemeOrani, faizOrani, ekstreAktif || false],
    function(err) {
      if (err) {
        return res.status(500).json({ error: 'Hesap eklenemedi' });
      }
      res.status(201).json({ id: this.lastID, message: 'Hesap eklendi' });
    }
  );
});

// ==================== İŞLEMLER ROUTES ====================

// Get all işlemler
app.get('/api/islemler', authenticateToken, (req, res) => {
  db.all('SELECT * FROM islemler WHERE user_id = ? ORDER BY tarih DESC', [req.user.userId], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'İşlemler getirilemedi' });
    }
    res.json(rows);
  });
});

// Add işlem
app.post('/api/islemler', authenticateToken, (req, res) => {
  const { tur, tarih, hesapId, hedefHesapId, kategori, tutar, notlar } = req.body;
  const olusturulmaTarihi = Date.now();

  db.run(
    `INSERT INTO islemler (user_id, tur, tarih, hesapId, hedefHesapId, kategori, tutar, notlar, olusturulmaTarihi) 
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [req.user.userId, tur, tarih, hesapId, hedefHesapId, kategori, tutar, notlar, olusturulmaTarihi],
    function(err) {
      if (err) {
        return res.status(500).json({ error: 'İşlem eklenemedi' });
      }
      res.status(201).json({ id: this.lastID, message: 'İşlem eklendi' });
    }
  );
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Server çalışıyor: http://localhost:${PORT}`);
  console.log(`📊 Test endpoint: http://localhost:${PORT}/api/test`);
  initDatabase();
});

process.on('SIGINT', () => {
  console.log('\n📦 Database bağlantısı kapatılıyor...');
  db.close((err) => {
    if (err) {
      console.error('Database kapatma hatası:', err.message);
    } else {
      console.log('✅ Database bağlantısı kapatıldı');
    }
    process.exit(0);
  });
}); 