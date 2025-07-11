const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Character encoding for Turkish support
app.use((req, res, next) => {
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  next();
});

// Test endpoint
app.get('/api/test', (req, res) => {
  res.json({ 
    message: 'Backend çalışıyor!', 
    timestamp: new Date().toISOString(),
    database: 'hesabettin2' 
  });
});

// MySQL Bağlantısı - Production/Development
const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root', 
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'hesabettin2',
  port: process.env.DB_PORT || 3307,
  charset: 'utf8mb4',
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
};

let db;

// Database bağlantısını başlat
async function initDatabase() {
  try {
    db = await mysql.createConnection(dbConfig);
    console.log('✅ MySQL bağlantısı başarılı');
    
    // Tabloları oluştur
    await createTables();
  } catch (error) {
    console.error('❌ MySQL bağlantı hatası:', error.message);
    console.log('📝 MySQL kurulumu ve veritabanı oluşturma talimatları:');
    console.log('1. MySQL yükleyin: https://dev.mysql.com/downloads/installer/');
    console.log('2. MySQL çalıştırın');
    console.log('3. Veritabanı oluşturun: CREATE DATABASE hesabettin_db;');
    console.log('4. .env dosyasındaki DB bilgilerini kontrol edin');
  }
}

// Tabloları oluştur
async function createTables() {
  try {
    // Users tablosu
    await db.execute(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Hesaplar tablosu - mevcut yapıya uyumlu
    await db.execute(`
      CREATE TABLE IF NOT EXISTS hesaplar (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        hesap_adi VARCHAR(255) NOT NULL,
        bakiye DECIMAL(15,2) DEFAULT 0.00,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    // İşlemler tablosu - mevcut yapıya uyumlu
    await db.execute(`
      CREATE TABLE IF NOT EXISTS islemler (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        hesap_id INT NOT NULL,
        kategori VARCHAR(100) NOT NULL,
        tutar DECIMAL(15,2) NOT NULL,
        aciklama TEXT DEFAULT NULL,
        tarih DATE NOT NULL,
        tip ENUM('gelir','gider') NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (hesap_id) REFERENCES hesaplar(id) ON DELETE CASCADE
      )
    `);

    // Hedefler tablosu
    await db.execute(`
      CREATE TABLE IF NOT EXISTS hedefler (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        baslik VARCHAR(255) NOT NULL,
        aciklama TEXT DEFAULT NULL,
        hedef_tutar DECIMAL(15,2) NOT NULL,
        mevcut_tutar DECIMAL(15,2) DEFAULT 0.00,
        baslangic_tarihi DATE NOT NULL,
        bitis_tarihi DATE NOT NULL,
        ceza TEXT DEFAULT NULL,
        durum ENUM('aktif','tamamlandi','basarisiz') DEFAULT 'aktif',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    // Hatırlatıcılar tablosu
    await db.execute(`
      CREATE TABLE IF NOT EXISTS hatirlaticilar (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        baslik VARCHAR(255) NOT NULL,
        aciklama TEXT DEFAULT NULL,
        tarih DATE NOT NULL,
        saat TIME NOT NULL,
        aktif BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    console.log('✅ Veritabanı tabloları hazır');
  } catch (error) {
    console.error('❌ Tablo oluşturma hatası:', error.message);
  }
}

// JWT Middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Token gerekli' });
  }

  jwt.verify(token, 'hesabettin_super_secret_key_2024', (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Geçersiz token' });
    }
    req.user = user;
    next();
  });
}

// ==================== AUTH ROUTES ====================

// Debug: Tüm kullanıcıları listele (geliştirme için)
app.get('/api/debug/users', async (req, res) => {
  try {
    const [users] = await db.execute('SELECT id, name, email, created_at FROM users');
    console.log('👥 Kayıtlı kullanıcılar:', users);
    res.json(users);
  } catch (error) {
    console.error('❌ Kullanıcıları listeleme hatası:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// Kayıt ol
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Tüm alanları doldurun' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Şifre en az 6 karakter olmalı' });
    }

    // Email kontrolü
    const [existingUsers] = await db.execute(
      'SELECT id FROM users WHERE email = ?',
      [email]
    );

    if (existingUsers.length > 0) {
      return res.status(400).json({ error: 'Bu e-posta zaten kayıtlı' });
    }

    // Şifreyi hash'le
    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // Kullanıcıyı kaydet
    const [result] = await db.execute(
      'INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)',
      [name, email, passwordHash]
    );

    const userId = result.insertId;

    // JWT token oluştur
    const token = jwt.sign(
      { userId, email, name },
      'hesabettin_super_secret_key_2024',
      { expiresIn: '7d' }
    );

    res.status(201).json({
      message: 'Kullanıcı başarıyla kaydedildi',
      token,
      user: { id: userId, name, email }
    });

  } catch (error) {
    console.error('Register hatası:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// Giriş yap
app.post('/api/auth/login', async (req, res) => {
  try {
    console.log('🔄 Login isteği alındı');
    const { email, password } = req.body;
    console.log('📧 Email:', email);

    if (!email || !password) {
      console.log('❌ Email veya şifre eksik');
      return res.status(400).json({ error: 'E-posta ve şifre gerekli' });
    }

    // Kullanıcıyı bul
    console.log('🔍 Kullanıcı aranıyor...');
    const [users] = await db.execute(
      'SELECT * FROM users WHERE email = ?',
      [email]
    );
    console.log('👥 Bulunan kullanıcı sayısı:', users.length);

    if (users.length === 0) {
      console.log('❌ Kullanıcı bulunamadı');
      return res.status(401).json({ error: 'Geçersiz e-posta veya şifre' });
    }

    const user = users[0];
    console.log('👤 Kullanıcı bulundu:', { id: user.id, email: user.email, name: user.name });

    // Şifre kontrolü
    console.log('🔐 Şifre kontrol ediliyor...');
    const isValidPassword = await bcrypt.compare(password, user.password_hash);
    console.log('✅ Şifre doğruluğu:', isValidPassword);
    
    if (!isValidPassword) {
      console.log('❌ Şifre hatalı');
      return res.status(401).json({ error: 'Geçersiz e-posta veya şifre' });
    }

    // JWT token oluştur
    console.log('🎫 JWT token oluşturuluyor...');
    const token = jwt.sign(
      { userId: user.id, email: user.email, name: user.name },
      'hesabettin_super_secret_key_2024',
      { expiresIn: '7d' }
    );

    console.log('✅ Login başarılı!');
    res.json({
      message: 'Giriş başarılı',
      token,
      user: { id: user.id, name: user.name, email: user.email }
    });

  } catch (error) {
    console.error('🚨 Login hatası:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// Google ile giriş/kayıt
app.post('/api/auth/google', async (req, res) => {
  try {
    const { email, name, idToken } = req.body;

    if (!email || !name || !idToken) {
      return res.status(400).json({ error: 'Google bilgileri eksik' });
    }

    // Kullanıcı var mı kontrol et
    const [users] = await db.execute(
      'SELECT * FROM users WHERE email = ?',
      [email]
    );

    let user;
    if (users.length > 0) {
      // Mevcut kullanıcı
      user = users[0];
    } else {
      // Yeni kullanıcı oluştur
      const [result] = await db.execute(
        'INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)',
        [name, email, 'GOOGLE_OAUTH'] // OAuth kullanıcıları için özel işaret
      );
      user = { id: result.insertId, name, email };
    }

    // JWT token oluştur
    const token = jwt.sign(
      { userId: user.id, email: user.email, name: user.name },
      'hesabettin_super_secret_key_2024',
      { expiresIn: '7d' }
    );

    res.json({
      message: 'Google ile giriş başarılı',
      token,
      user: { id: user.id, name: user.name, email: user.email }
    });

  } catch (error) {
    console.error('Google auth hatası:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// Apple ile giriş/kayıt
app.post('/api/auth/apple', async (req, res) => {
  try {
    const { email, name, identityToken } = req.body;

    if (!identityToken) {
      return res.status(400).json({ error: 'Apple identity token gerekli' });
    }

    // Email yoksa unique bir email oluştur
    const userEmail = email || `apple_user_${Date.now()}@hesabettin.app`;

    // Kullanıcı var mı kontrol et
    const [users] = await db.execute(
      'SELECT * FROM users WHERE email = ?',
      [userEmail]
    );

    let user;
    if (users.length > 0) {
      // Mevcut kullanıcı
      user = users[0];
    } else {
      // Yeni kullanıcı oluştur
      const [result] = await db.execute(
        'INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)',
        [name || 'Apple User', userEmail, 'APPLE_OAUTH'] // OAuth kullanıcıları için özel işaret
      );
      user = { id: result.insertId, name: name || 'Apple User', email: userEmail };
    }

    // JWT token oluştur
    const token = jwt.sign(
      { userId: user.id, email: user.email, name: user.name },
      'hesabettin_super_secret_key_2024',
      { expiresIn: '7d' }
    );

    res.json({
      message: 'Apple ile giriş başarılı',
      token,
      user: { id: user.id, name: user.name, email: user.email }
    });

  } catch (error) {
    console.error('Apple auth hatası:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// ==================== HESAP ROUTES ====================

// Tüm hesapları getir - mevcut veritabanı yapısına uyumlu
app.get('/api/hesaplar', authenticateToken, async (req, res) => {
  try {
    console.log('🔍 Hesapları getiriyor, user_id:', req.user.userId);
    
    const [hesaplar] = await db.execute(
      `SELECT id, hesap_adi as ad, bakiye, created_at, updated_at 
       FROM hesaplar WHERE user_id = ?`,
      [req.user.userId]
    );

    console.log('📊 Bulunan hesaplar:', hesaplar.length);

    // Flutter uyumlu format'a çevir
    const formattedHesaplar = hesaplar.map(hesap => ({
      id: hesap.id,
      ad: hesap.ad,
      tur: 'Banka', // Varsayılan değer
      bakiye: Number(hesap.bakiye || 0), // Number olarak gönder
      olusturulmaTarihi: new Date(hesap.created_at).getTime()
    }));

    console.log('✅ Formatlanmış hesaplar:', formattedHesaplar);
    res.json(formattedHesaplar);
  } catch (error) {
    console.error('❌ Hesapları getirme hatası:', error);
    res.status(500).json({ error: 'Sunucu hatası: ' + error.message });
  }
});

// Hesap ekle - mevcut veritabanı yapısına uyumlu
app.post('/api/hesaplar', authenticateToken, async (req, res) => {
  try {
    const { ad, tur, bakiye } = req.body;
    
    // Gelen datayı logla
    console.log('📥 Gelen hesap data:', req.body);

    if (!ad) {
      return res.status(400).json({ error: 'Hesap adı gerekli' });
    }

    const hesapAdi = ad; // ad -> hesap_adi mapping
    const hesapBakiye = bakiye || 0.00;

    console.log('💾 Veritabanına yazılacak: hesap_adi=', hesapAdi, 'bakiye=', hesapBakiye);

    // Gerçek veritabanında tur kolonu yok, o yüzden sadece hesap_adi ve bakiye kaydediyoruz
    const [result] = await db.execute(
      `INSERT INTO hesaplar (user_id, hesap_adi, bakiye) VALUES (?, ?, ?)`,
      [req.user.userId, hesapAdi, hesapBakiye]
    );

    console.log('✅ Hesap eklendi, ID:', result.insertId);
    res.status(201).json({ id: result.insertId, message: 'Hesap eklendi' });
  } catch (error) {
    console.error('❌ Hesap ekleme hatası:', error);
    res.status(500).json({ error: 'Sunucu hatası: ' + error.message });
  }
});

// Hesap güncelle
app.put('/api/hesaplar/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { ad, bakiye } = req.body;

    // Gerçek veritabanında sadece hesap_adi ve bakiye güncellenebilir
    await db.execute(
      `UPDATE hesaplar SET hesap_adi = ?, bakiye = ? WHERE id = ? AND user_id = ?`,
      [ad, bakiye, id, req.user.userId]
    );

    res.json({ message: 'Hesap güncellendi' });
  } catch (error) {
    console.error('Hesap güncelleme hatası:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// Hesap sil
app.delete('/api/hesaplar/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    await db.execute(
      'DELETE FROM hesaplar WHERE id = ? AND user_id = ?',
      [id, req.user.userId]
    );

    res.json({ message: 'Hesap silindi' });
  } catch (error) {
    console.error('Hesap silme hatası:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// ==================== İŞLEM ROUTES ====================

// İşlemler listele - tüm işlemler veya filtrelenmiş
app.get('/api/islemler', authenticateToken, async (req, res) => {
  try {
    console.log('📋 İşlemler getiriliyor, query params:', req.query);
    
    let query = `
      SELECT id, user_id, hesap_id, kategori, tutar, aciklama, tarih, tip, created_at
      FROM islemler 
      WHERE user_id = ?
    `;
    let params = [req.user.userId];

    // Tarih aralığı filtresi varsa ekle
    if (req.query.baslangic && req.query.bitis) {
      const baslangicDate = new Date(parseInt(req.query.baslangic)).toISOString().split('T')[0];
      const bitisDate = new Date(parseInt(req.query.bitis)).toISOString().split('T')[0];
      
      query += ' AND tarih BETWEEN ? AND ?';
      params.push(baslangicDate, bitisDate);
      
      console.log('📅 Tarih aralığı filtresi:', { baslangicDate, bitisDate });
    }

    // Hesap filtresi varsa ekle
    if (req.query.hesapId) {
      query += ' AND hesap_id = ?';
      params.push(req.query.hesapId);
      console.log('🏦 Hesap filtresi:', req.query.hesapId);
    }

    query += ' ORDER BY tarih DESC, created_at DESC';

    const [islemler] = await db.execute(query, params);
    console.log('📊 Bulunan işlem sayısı:', islemler.length);

    // Frontend formatına çevir
    const formattedIslemler = islemler.map(islem => ({
      id: islem.id,
      tur: islem.tip, // tip -> tur mapping
      tarih: new Date(islem.tarih).getTime(), // DATE'i timestamp'e çevir
      hesapId: islem.hesap_id, // hesap_id -> hesapId mapping
      kategori: islem.kategori,
      tutar: Number(islem.tutar),
      notlar: islem.aciklama, // aciklama -> notlar mapping
      olusturulmaTarihi: new Date(islem.created_at).getTime()
    }));

    res.json(formattedIslemler);
  } catch (error) {
    console.error('❌ İşlemleri getirme hatası:', error);
    res.status(500).json({ error: 'Sunucu hatası: ' + error.message });
  }
});

// İşlem ekle - gerçek veritabanı yapısına uyumlu
app.post('/api/islemler', authenticateToken, async (req, res) => {
  try {
    console.log('📥 Gelen işlem data:', req.body);
    
    const { tur, tarih, hesapId, kategori, tutar, notlar } = req.body;

    if (!tur || !tarih || !hesapId || tutar === undefined) {
      console.log('❌ Gerekli alanlar eksik:', { tur, tarih, hesapId, tutar });
      return res.status(400).json({ error: 'Gerekli alanlar eksik' });
    }

    // Frontend'den gelen timestamp'i DATE formatına çevir
    const tarihDate = new Date(tarih).toISOString().split('T')[0]; // YYYY-MM-DD formatı
    
    console.log('💾 Veritabanına yazılacak:', {
      user_id: req.user.userId,
      hesap_id: hesapId,
      kategori,
      tutar,
      aciklama: notlar,
      tarih: tarihDate,
      tip: tur
    });

    const [result] = await db.execute(
      `INSERT INTO islemler (user_id, hesap_id, kategori, tutar, aciklama, tarih, tip) 
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [req.user.userId, hesapId, kategori, tutar, notlar || null, tarihDate, tur]
    );

    console.log('✅ İşlem eklendi, ID:', result.insertId);

    // Bakiye güncelle
    await updateBalance(tur, hesapId, null, tutar, req.user.userId);

    res.status(201).json({ id: result.insertId, message: 'İşlem eklendi' });
  } catch (error) {
    console.error('❌ İşlem ekleme hatası:', error);
    res.status(500).json({ error: 'Sunucu hatası: ' + error.message });
  }
});

// İşlem güncelle - gerçek veritabanı yapısına uyumlu
app.put('/api/islemler/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { eskiIslem, yeniIslem } = req.body;

    // Eski işlemin etkisini geri al
    await reverseBalance(eskiIslem.tur, eskiIslem.hesapId, null, eskiIslem.tutar, req.user.userId);

    // Yeni işlemi güncelle
    const tarihDate = new Date(yeniIslem.tarih).toISOString().split('T')[0];
    
    await db.execute(
      `UPDATE islemler SET hesap_id = ?, kategori = ?, tutar = ?, aciklama = ?, tarih = ?, tip = ?
       WHERE id = ? AND user_id = ?`,
      [yeniIslem.hesapId, yeniIslem.kategori, yeniIslem.tutar, yeniIslem.notlar, tarihDate, yeniIslem.tur, id, req.user.userId]
    );

    // Yeni işlemin etkisini uygula
    await updateBalance(yeniIslem.tur, yeniIslem.hesapId, null, yeniIslem.tutar, req.user.userId);

    res.json({ message: 'İşlem güncellendi' });
  } catch (error) {
    console.error('İşlem güncelleme hatası:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// İşlem sil - gerçek veritabanı yapısına uyumlu
app.delete('/api/islemler/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const islem = req.body;

    // Bakiye etkisini geri al
    await reverseBalance(islem.tur, islem.hesapId, null, islem.tutar, req.user.userId);

    // İşlemi sil
    await db.execute(
      'DELETE FROM islemler WHERE id = ? AND user_id = ?',
      [id, req.user.userId]
    );

    res.json({ message: 'İşlem silindi' });
  } catch (error) {
    console.error('İşlem silme hatası:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// ==================== BAKIYE YÖNETİMİ ====================

async function updateBalance(tur, hesapId, hedefHesapId, tutar, userId) {
  console.log('💰 Bakiye güncelleniyor:', { tur, hesapId, tutar });
  
  if (tur === 'gelir') {
    await db.execute(
      'UPDATE hesaplar SET bakiye = bakiye + ? WHERE id = ? AND user_id = ?',
      [tutar, hesapId, userId]
    );
    console.log('✅ Gelir işlemi: +', tutar);
  } else if (tur === 'gider') {
    await db.execute(
      'UPDATE hesaplar SET bakiye = bakiye - ? WHERE id = ? AND user_id = ?',
      [tutar, hesapId, userId]
    );
    console.log('✅ Gider işlemi: -', tutar);
  }
}

async function reverseBalance(tur, hesapId, hedefHesapId, tutar, userId) {
  console.log('🔄 Bakiye geri alınıyor:', { tur, hesapId, tutar });
  
  if (tur === 'gelir') {
    await db.execute(
      'UPDATE hesaplar SET bakiye = bakiye - ? WHERE id = ? AND user_id = ?',
      [tutar, hesapId, userId]
    );
  } else if (tur === 'gider') {
    await db.execute(
      'UPDATE hesaplar SET bakiye = bakiye + ? WHERE id = ? AND user_id = ?',
      [tutar, hesapId, userId]
    );
  }
}

// ==================== EKSTRE ENDPOINTS ====================

app.get('/api/ekstre/mevcut-tutar/:hesapId', authenticateToken, async (req, res) => {
  try {
    // Basit implementasyon - gerçek ekstre sistemi backend'de implement edilecek
    res.json({ tutar: 0.0 });
  } catch (error) {
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

app.get('/api/ekstre/gecmis/:hesapId', authenticateToken, async (req, res) => {
  try {
    // Basit implementasyon
    res.json([]);
  } catch (error) {
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

app.get('/api/ekstre/donem-islemler', authenticateToken, async (req, res) => {
  try {
    // Basit implementasyon
    res.json([]);
  } catch (error) {
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// ==================== İSTATİSTİK ENDPOINTS ====================

app.get('/api/istatistikler/kategori', authenticateToken, async (req, res) => {
  try {
    const { tur, baslangic, bitis } = req.query;
    console.log('📊 Kategori istatistikleri:', { tur, baslangic, bitis });

    if (!tur) {
      return res.status(400).json({ error: 'İşlem türü (tur) gerekli' });
    }

    let query = `
      SELECT kategori, SUM(tutar) as toplam
      FROM islemler 
      WHERE user_id = ? AND tip = ?
    `;
    let params = [req.user.userId, tur];

    // Tarih aralığı filtresi
    if (baslangic && bitis) {
      const baslangicDate = new Date(parseInt(baslangic)).toISOString().split('T')[0];
      const bitisDate = new Date(parseInt(bitis)).toISOString().split('T')[0];
      
      query += ' AND tarih BETWEEN ? AND ?';
      params.push(baslangicDate, bitisDate);
    }

    query += ' GROUP BY kategori ORDER BY toplam DESC';

    const [results] = await db.execute(query, params);
    console.log('📈 Kategori sonuçları:', results);

    // Key-value formatına çevir
    const kategoriData = {};
    results.forEach(row => {
      kategoriData[row.kategori] = Number(row.toplam);
    });

    res.json(kategoriData);
  } catch (error) {
    console.error('❌ Kategori istatistikleri hatası:', error);
    res.status(500).json({ error: 'Sunucu hatası: ' + error.message });
  }
});

app.get('/api/istatistikler/aylik', authenticateToken, async (req, res) => {
  try {
    const { yil } = req.query;
    const selectedYear = yil || new Date().getFullYear();
    
    console.log('📅 Aylık istatistikler:', { yil: selectedYear });

    const query = `
      SELECT 
        MONTH(tarih) as ay,
        tip,
        SUM(tutar) as toplam
      FROM islemler 
      WHERE user_id = ? AND YEAR(tarih) = ?
      GROUP BY MONTH(tarih), tip
      ORDER BY ay
    `;

    const [results] = await db.execute(query, [req.user.userId, selectedYear]);
    console.log('📊 Aylık sonuçlar:', results);

    // Ay bazında veriyi organize et
    const aylikData = {};
    for (let ay = 1; ay <= 12; ay++) {
      const ayStr = ay.toString().padStart(2, '0');
      aylikData[ayStr] = { gelir: 0, gider: 0 };
    }

    results.forEach(row => {
      const ayStr = row.ay.toString().padStart(2, '0');
      if (row.tip === 'gelir') {
        aylikData[ayStr].gelir = Number(row.toplam);
      } else if (row.tip === 'gider') {
        aylikData[ayStr].gider = Number(row.toplam);
      }
    });

    res.json(aylikData);
  } catch (error) {
    console.error('❌ Aylık istatistikler hatası:', error);
    res.status(500).json({ error: 'Sunucu hatası: ' + error.message });
  }
});

// ==================== HEDEFLER ENDPOINTS ====================

// Kullanıcının hedeflerini getir
app.get('/api/hedefler', authenticateToken, async (req, res) => {
  try {
    const [rows] = await db.execute(
      'SELECT * FROM hedefler WHERE user_id = ? ORDER BY created_at DESC',
      [req.user.userId]
    );
    res.json(rows);
  } catch (error) {
    console.error('Hedefler getirme hatası:', error);
    res.status(500).json({ error: 'Hedefler getirilemedi' });
  }
});

// Yeni hedef ekle
app.post('/api/hedefler', authenticateToken, async (req, res) => {
  try {
    const { baslik, aciklama, hedef_tutar, bitis_tarihi, ceza } = req.body;

    if (!baslik || !hedef_tutar || !bitis_tarihi) {
      return res.status(400).json({ error: 'Gerekli alanlar eksik' });
    }

    const [result] = await db.execute(
      `INSERT INTO hedefler (user_id, baslik, aciklama, hedef_tutar, baslangic_tarihi, bitis_tarihi, ceza) 
       VALUES (?, ?, ?, ?, CURDATE(), ?, ?)`,
      [req.user.userId, baslik, aciklama, hedef_tutar, bitis_tarihi, ceza]
    );

    res.status(201).json({ 
      message: 'Hedef başarıyla eklendi',
      id: result.insertId 
    });
  } catch (error) {
    console.error('Hedef ekleme hatası:', error);
    res.status(500).json({ error: 'Hedef eklenemedi' });
  }
});

// Hedef güncelle (mevcut tutar artır, durum değiştir)
app.put('/api/hedefler/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { mevcut_tutar, durum } = req.body;

    const updateFields = [];
    const values = [];

    if (mevcut_tutar !== undefined) {
      updateFields.push('mevcut_tutar = ?');
      values.push(mevcut_tutar);
    }

    if (durum !== undefined) {
      updateFields.push('durum = ?');
      values.push(durum);
    }

    if (updateFields.length === 0) {
      return res.status(400).json({ error: 'Güncellenecek alan belirtilmedi' });
    }

    values.push(req.user.userId, id);

    await db.execute(
      `UPDATE hedefler SET ${updateFields.join(', ')} WHERE user_id = ? AND id = ?`,
      values
    );

    res.json({ message: 'Hedef güncellendi' });
  } catch (error) {
    console.error('Hedef güncelleme hatası:', error);
    res.status(500).json({ error: 'Hedef güncellenemedi' });
  }
});

// Hedef sil
app.delete('/api/hedefler/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    await db.execute(
      'DELETE FROM hedefler WHERE user_id = ? AND id = ?',
      [req.user.userId, id]
    );

    res.json({ message: 'Hedef silindi' });
  } catch (error) {
    console.error('Hedef silme hatası:', error);
    res.status(500).json({ error: 'Hedef silinemedi' });
  }
});

// ==================== HATIRLATICILAR ENDPOINTS ====================

// Kullanıcının hatırlatıcılarını getir
app.get('/api/hatirlaticilar', authenticateToken, async (req, res) => {
  try {
    const [rows] = await db.execute(
      'SELECT * FROM hatirlaticilar WHERE user_id = ? ORDER BY tarih ASC, saat ASC',
      [req.user.userId]
    );
    res.json(rows);
  } catch (error) {
    console.error('Hatırlatıcılar getirme hatası:', error);
    res.status(500).json({ error: 'Hatırlatıcılar getirilemedi' });
  }
});

// Yeni hatırlatıcı ekle
app.post('/api/hatirlaticilar', authenticateToken, async (req, res) => {
  try {
    const { baslik, aciklama, tarih, saat } = req.body;

    if (!baslik || !tarih || !saat) {
      return res.status(400).json({ error: 'Gerekli alanlar eksik' });
    }

    const [result] = await db.execute(
      'INSERT INTO hatirlaticilar (user_id, baslik, aciklama, tarih, saat) VALUES (?, ?, ?, ?, ?)',
      [req.user.userId, baslik, aciklama, tarih, saat]
    );

    res.status(201).json({ 
      message: 'Hatırlatıcı başarıyla eklendi',
      id: result.insertId 
    });
  } catch (error) {
    console.error('Hatırlatıcı ekleme hatası:', error);
    res.status(500).json({ error: 'Hatırlatıcı eklenemedi' });
  }
});

// Hatırlatıcı güncelle (aktif/pasif)
app.put('/api/hatirlaticilar/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { aktif } = req.body;

    await db.execute(
      'UPDATE hatirlaticilar SET aktif = ? WHERE user_id = ? AND id = ?',
      [aktif, req.user.userId, id]
    );

    res.json({ message: 'Hatırlatıcı güncellendi' });
  } catch (error) {
    console.error('Hatırlatıcı güncelleme hatası:', error);
    res.status(500).json({ error: 'Hatırlatıcı güncellenemedi' });
  }
});

// Hatırlatıcı sil
app.delete('/api/hatirlaticilar/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    await db.execute(
      'DELETE FROM hatirlaticilar WHERE user_id = ? AND id = ?',
      [req.user.userId, id]
    );

    res.json({ message: 'Hatırlatıcı silindi' });
  } catch (error) {
    console.error('Hatırlatıcı silme hatası:', error);
    res.status(500).json({ error: 'Hatırlatıcı silinemedi' });
  }
});

// Test endpoint
app.get('/api/test', (req, res) => {
  res.json({ message: 'Hesabettin Backend API çalışıyor! 🚀' });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Endpoint bulunamadı' });
});

// Error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Sunucu hatası' });
});

// Sunucuyu başlat
async function startServer() {
  await initDatabase();
  
  app.listen(PORT, () => {
    console.log(`🚀 Hesabettin Backend API çalışıyor:`);
    console.log(`   http://localhost:${PORT}`);
    console.log(`   Test: http://localhost:${PORT}/api/test`);
    console.log('');
    console.log('📱 Flutter uygulamanızdan bağlanabilirsiniz!');
  });
}

startServer(); 