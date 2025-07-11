-- Hesabettin App MySQL Database Setup
-- Bu dosyayı MySQL'de çalıştırarak veritabanını manuel kurabilirsiniz

-- Veritabanı oluştur
CREATE DATABASE IF NOT EXISTS hesabettin_db;
USE hesabettin_db;

-- Users tablosu
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Hesaplar tablosu
CREATE TABLE IF NOT EXISTS hesaplar (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    ad VARCHAR(255) NOT NULL,
    tur VARCHAR(100) NOT NULL,
    bakiye DECIMAL(15,2) NOT NULL DEFAULT 0,
    kesimTarihi DATE NULL,
    olusturulmaTarihi TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ekstreLimit DECIMAL(15,2) NULL,
    minOdemeOrani DECIMAL(5,4) NULL,
    faizOrani DECIMAL(5,4) NULL,
    ekstreAktif BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- İşlemler tablosu
CREATE TABLE IF NOT EXISTS islemler (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    tur VARCHAR(50) NOT NULL,
    tarih BIGINT NOT NULL,
    hesapId INT NOT NULL,
    hedefHesapId INT NULL,
    kategori VARCHAR(255) NULL,
    tutar DECIMAL(15,2) NOT NULL,
    notlar TEXT NULL,
    olusturulmaTarihi BIGINT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (hesapId) REFERENCES hesaplar(id) ON DELETE CASCADE,
    FOREIGN KEY (hedefHesapId) REFERENCES hesaplar(id) ON DELETE CASCADE
);

-- Index'ler (performans için)
CREATE INDEX idx_hesaplar_user_id ON hesaplar(user_id);
CREATE INDEX idx_islemler_user_id ON islemler(user_id);
CREATE INDEX idx_islemler_hesap_id ON islemler(hesapId);
CREATE INDEX idx_islemler_tarih ON islemler(tarih);

-- Test kullanıcısı (isteğe bağlı)
-- INSERT INTO users (name, email, password_hash) VALUES 
-- ('Test User', 'test@example.com', '$2a$10$rZ5gNl6h5k8pWJMzP4x2dOhOWzL1wL1yC5fK1n2o3p4q5r6s7t8u9v');
-- Şifre: 123456

SHOW TABLES; 