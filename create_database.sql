-- Hesabettin2 veritabanını oluştur ve kullan
CREATE DATABASE IF NOT EXISTS hesabettin2;
USE hesabettin2;

-- Kullanıcılar tablosu
CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Hesaplar tablosu
CREATE TABLE IF NOT EXISTS hesaplar (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  hesap_adi VARCHAR(255) NOT NULL,
  bakiye DECIMAL(15,2) DEFAULT 0.00,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- İşlemler tablosu
CREATE TABLE IF NOT EXISTS islemler (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  hesap_id INT NOT NULL,
  kategori VARCHAR(100) NOT NULL,
  tutar DECIMAL(15,2) NOT NULL,
  aciklama TEXT,
  tarih DATE NOT NULL,
  tip ENUM('gelir', 'gider') NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (hesap_id) REFERENCES hesaplar(id) ON DELETE CASCADE
);

-- Test verisi ekle (isteğe bağlı)
-- INSERT INTO users (name, email, password_hash) VALUES 
-- ('Test User', 'test@example.com', '$2a$10$test_hash_for_password_123');

SHOW TABLES; 