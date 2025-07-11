# Hesabettin Backend API

Flutter uygulaması için MySQL tabanlı Node.js backend API.

## 🚀 Hızlı Başlangıç

### 1. MySQL Kurulumu
```bash
# MySQL'i indirin ve kurun:
# https://dev.mysql.com/downloads/installer/

# MySQL'i başlatın ve bağlanın
mysql -u root -p

# Veritabanı oluşturun
CREATE DATABASE hesabettin_db;
```

### 2. Backend Kurulumu
```bash
# Backend dizinine gidin
cd backend

# Dependencies'i yükleyin
npm install

# Sunucuyu başlatın
npm start

# Veya development modunda
npm run dev
```

### 3. Konfigürasyon
`.env` dosyasını MySQL bilgilerinize göre düzenleyin:
```env
PORT=3000
JWT_SECRET=hesabettin_super_secret_key_2024

DB_HOST=localhost
DB_USER=root
DB_PASSWORD=your_mysql_password
DB_NAME=hesabettin_db
DB_PORT=3306
```

## 📡 API Endpoints

### Authentication
- `POST /api/auth/register` - Kullanıcı kaydı
- `POST /api/auth/login` - Giriş yapma

### Hesaplar
- `GET /api/hesaplar` - Tüm hesapları getir
- `POST /api/hesaplar` - Yeni hesap ekle
- `PUT /api/hesaplar/:id` - Hesap güncelle
- `DELETE /api/hesaplar/:id` - Hesap sil

### İşlemler
- `GET /api/islemler` - Tüm işlemleri getir
- `POST /api/islemler` - Yeni işlem ekle
- `PUT /api/islemler/:id` - İşlem güncelle
- `DELETE /api/islemler/:id` - İşlem sil

### Test
- `GET /api/test` - API durumu kontrolü

## 🔧 Özellikler

✅ JWT Authentication  
✅ MySQL Veritabanı  
✅ CORS Desteği  
✅ Şifre Hash'leme  
✅ Kullanıcı Bazlı Veri İzolasyonu  
✅ Otomatik Bakiye Hesaplama  
✅ Error Handling  

## 📱 Flutter Uygulaması

Backend çalıştıktan sonra Flutter uygulamanızı başlatın:
```bash
flutter run
```

Uygulama `http://localhost:3000` adresine bağlanacak.

## 🛠️ Geliştirme

- `npm run dev` - Nodemon ile otomatik restart
- `database.sql` - Manuel veritabanı kurulumu
- Loglar konsola yazdırılır

## 📦 Dependencies

- **express** - Web framework
- **mysql2** - MySQL client
- **jsonwebtoken** - JWT auth
- **bcryptjs** - Password hashing
- **cors** - Cross-origin requests
- **dotenv** - Environment variables 