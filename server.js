const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// CORS ve middleware
app.use(cors());
app.use(express.json());

// Railway MySQL Connection
const dbConfig = {
  host: process.env.MYSQLHOST || 'crossover.proxy.rlwy.net',
  port: process.env.MYSQLPORT || 20810,
  user: process.env.MYSQLUSER || 'root',
  password: process.env.MYSQLPASSWORD,
  database: process.env.MYSQLDATABASE || 'railway',
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
};

console.log('🔗 MySQL Bağlantı ayarları:', {
  host: dbConfig.host,
  port: dbConfig.port,
  user: dbConfig.user,
  database: dbConfig.database
});

let db;

// MySQL Connection Pool
async function connectDB() {
  try {
    db = await mysql.createPool({
      ...dbConfig,
      waitForConnections: true,
      connectionLimit: 10,
      queueLimit: 0,
      acquireTimeout: 60000,
      timeout: 60000
    });
    
    console.log('✅ MySQL bağlantısı başarılı!');
    
    // Test connection
    const [rows] = await db.execute('SELECT 1 as test');
    console.log('✅ MySQL test sorgusu başarılı:', rows[0]);
    
    // Create tables if not exist
    await createTables();
    
  } catch (error) {
    console.error('❌ MySQL bağlantı hatası:', error);
    process.exit(1);
  }
}

// Create tables function
async function createTables() {
  try {
    console.log('📋 Tablolar oluşturuluyor...');
    
    // Users table
    await db.execute(`
      CREATE TABLE IF NOT EXISTS users (
        id int(11) NOT NULL AUTO_INCREMENT,
        name varchar(255) NOT NULL,
        email varchar(255) NOT NULL,
        password_hash varchar(255) NOT NULL,
        created_at timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        UNIQUE KEY email (email)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);
    
    // Hesaplar table
    await db.execute(`
      CREATE TABLE IF NOT EXISTS hesaplar (
        id int(11) NOT NULL AUTO_INCREMENT,
        user_id int(11) NOT NULL,
        hesap_adi varchar(255) NOT NULL,
        bakiye decimal(15,2) DEFAULT 0.00,
        created_at timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        KEY user_id (user_id),
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);
    
    // Islemler table
    await db.execute(`
      CREATE TABLE IF NOT EXISTS islemler (
        id int(11) NOT NULL AUTO_INCREMENT,
        user_id int(11) NOT NULL,
        hesap_id int(11) NOT NULL,
        kategori varchar(100) NOT NULL,
        tutar decimal(15,2) NOT NULL,
        aciklama text DEFAULT NULL,
        tarih date NOT NULL,
        tip enum('gelir','gider') NOT NULL,
        created_at timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        KEY user_id (user_id),
        KEY hesap_id (hesap_id),
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
        FOREIGN KEY (hesap_id) REFERENCES hesaplar (id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);
    
    // Hedefler table
    await db.execute(`
      CREATE TABLE IF NOT EXISTS hedefler (
        id int(11) NOT NULL AUTO_INCREMENT,
        user_id int(11) NOT NULL,
        baslik varchar(255) NOT NULL,
        aciklama text DEFAULT NULL,
        hedef_tutar decimal(15,2) NOT NULL,
        mevcut_tutar decimal(15,2) DEFAULT 0.00,
        baslangic_tarihi date NOT NULL,
        bitis_tarihi date NOT NULL,
        ceza text DEFAULT NULL,
        durum enum('aktif','tamamlandi','basarisiz') DEFAULT 'aktif',
        created_at timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        KEY user_id (user_id),
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);
    
    // Hatirlaticilar table
    await db.execute(`
      CREATE TABLE IF NOT EXISTS hatirlaticilar (
        id int(11) NOT NULL AUTO_INCREMENT,
        user_id int(11) NOT NULL,
        baslik varchar(255) NOT NULL,
        aciklama text DEFAULT NULL,
        tarih date NOT NULL,
        saat time NOT NULL,
        aktif tinyint(1) DEFAULT 1,
        created_at timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        KEY user_id (user_id),
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);
    
    console.log('✅ Tüm tablolar başarıyla oluşturuldu!');
    
  } catch (error) {
    console.error('❌ Tablo oluşturma hatası:', error);
  }
}

// Middleware: JWT token doğrulama
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Token gerekli' });
  }

  jwt.verify(token, 'secret_key', (err, user) => {
    if (err) return res.status(403).json({ message: 'Geçersiz token' });
    req.user = user;
    next();
  });
};

// Test endpoint
app.get('/api/test', (req, res) => {
  res.json({
    message: 'Hesabettin Backend çalışıyor! 🚀',
    timestamp: new Date().toISOString(),
    database: 'Railway MySQL',
    status: 'OK'
  });
});

// User Registration
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    
    if (!name || !email || !password) {
      return res.status(400).json({ message: 'Tüm alanlar gerekli' });
    }

    // Check if user exists
    const [existingUsers] = await db.execute(
      'SELECT id FROM users WHERE email = ?',
      [email]
    );

    if (existingUsers.length > 0) {
      return res.status(409).json({ message: 'Bu email zaten kayıtlı' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert user
    const [result] = await db.execute(
      'INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)',
      [name, email, hashedPassword]
    );

    const userId = result.insertId;

    // Generate JWT token
    const token = jwt.sign({ userId, email }, 'secret_key', { expiresIn: '24h' });

    res.status(201).json({
      message: 'Kullanıcı başarıyla oluşturuldu',
      token,
      user: { id: userId, name, email }
    });

  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ message: 'Sunucu hatası' });
  }
});

// User Login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'Email ve şifre gerekli' });
    }

    // Find user
    const [users] = await db.execute(
      'SELECT id, name, email, password_hash FROM users WHERE email = ?',
      [email]
    );

    if (users.length === 0) {
      return res.status(401).json({ message: 'Geçersiz email veya şifre' });
    }

    const user = users[0];

    // Check password
    const isValidPassword = await bcrypt.compare(password, user.password_hash);
    if (!isValidPassword) {
      return res.status(401).json({ message: 'Geçersiz email veya şifre' });
    }

    // Generate JWT token
    const token = jwt.sign({ userId: user.id, email: user.email }, 'secret_key', { expiresIn: '24h' });

    res.json({
      message: 'Giriş başarılı',
      token,
      user: { id: user.id, name: user.name, email: user.email }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Sunucu hatası' });
  }
});

// Get Hesaplar (Accounts)
app.get('/api/hesaplar', authenticateToken, async (req, res) => {
  try {
    const [hesaplar] = await db.execute(
      'SELECT * FROM hesaplar WHERE user_id = ? ORDER BY created_at DESC',
      [req.user.userId]
    );
    res.json(hesaplar);
  } catch (error) {
    console.error('Get hesaplar error:', error);
    res.status(500).json({ message: 'Sunucu hatası' });
  }
});

// Add Hesap (Account)
app.post('/api/hesaplar', authenticateToken, async (req, res) => {
  try {
    const { hesap_adi, bakiye = 0 } = req.body;

    if (!hesap_adi) {
      return res.status(400).json({ message: 'Hesap adı gerekli' });
    }

    const [result] = await db.execute(
      'INSERT INTO hesaplar (user_id, hesap_adi, bakiye) VALUES (?, ?, ?)',
      [req.user.userId, hesap_adi, bakiye]
    );

    res.status(201).json({
      message: 'Hesap başarıyla eklendi',
      hesap: { id: result.insertId, hesap_adi, bakiye }
    });

  } catch (error) {
    console.error('Add hesap error:', error);
    res.status(500).json({ message: 'Sunucu hatası' });
  }
});

// Get Islemler (Transactions)
app.get('/api/islemler', authenticateToken, async (req, res) => {
  try {
    const [islemler] = await db.execute(
      `SELECT i.*, h.hesap_adi 
       FROM islemler i 
       JOIN hesaplar h ON i.hesap_id = h.id 
       WHERE i.user_id = ? 
       ORDER BY i.tarih DESC, i.created_at DESC`,
      [req.user.userId]
    );
    res.json(islemler);
  } catch (error) {
    console.error('Get islemler error:', error);
    res.status(500).json({ message: 'Sunucu hatası' });
  }
});

// Add Islem (Transaction)
app.post('/api/islemler', authenticateToken, async (req, res) => {
  try {
    const { hesap_id, kategori, tutar, aciklama, tarih, tip } = req.body;

    if (!hesap_id || !kategori || !tutar || !tarih || !tip) {
      return res.status(400).json({ message: 'Tüm zorunlu alanlar gerekli' });
    }

    // Start transaction
    const connection = await db.getConnection();
    await connection.beginTransaction();

    try {
      // Add islem
      const [result] = await connection.execute(
        'INSERT INTO islemler (user_id, hesap_id, kategori, tutar, aciklama, tarih, tip) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [req.user.userId, hesap_id, kategori, tutar, aciklama, tarih, tip]
      );

      // Update hesap bakiye
      const tutarChange = tip === 'gelir' ? tutar : -tutar;
      await connection.execute(
        'UPDATE hesaplar SET bakiye = bakiye + ? WHERE id = ? AND user_id = ?',
        [tutarChange, hesap_id, req.user.userId]
      );

      await connection.commit();
      connection.release();

      res.status(201).json({
        message: 'İşlem başarıyla eklendi',
        islem: { id: result.insertId, hesap_id, kategori, tutar, aciklama, tarih, tip }
      });

    } catch (error) {
      await connection.rollback();
      connection.release();
      throw error;
    }

  } catch (error) {
    console.error('Add islem error:', error);
    res.status(500).json({ message: 'Sunucu hatası' });
  }
});

// Start server
connectDB().then(() => {
  app.listen(PORT, () => {
    console.log(`🚀 Hesabettin Backend Server çalışıyor: Port ${PORT}`);
    console.log(`📍 Railway URL: https://hesabettin-backend.up.railway.app`);
  });
});

module.exports = app; 