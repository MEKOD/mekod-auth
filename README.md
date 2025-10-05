mekod-auth

Express + Prisma tabanlı, e-posta doğrulamalı, şifre sıfırlamalı, TOTP 2FA’lı, refresh-rotate oturum yönetimli ve HttpOnly/Secure cookie’li kimlik doğrulama sunucusu.
Stack: Node.js, TypeScript, Express, Prisma, SQLite (dev), JWT.

Özellikler

E-posta ile kayıt ve doğrulama linki

Şifre sıfırlama (token TTL’li)

Login / Refresh / Logout (refresh token rotasyonu + session kaydı)

TOTP 2FA (kurulum, doğrulama, devre dışı bırakma)

Google OAuth (state + PKCE)

/auth/me ile korumalı profil uç noktası

HttpOnly + SameSite + Secure cookie akışı

CORS kontrollü; proxy arkasında trust proxy hazır

Temiz service ayrımı, test edilebilir mimari

Hızlı Başlangıç (Geliştirme)
# 1) Bağımlılıklar
npm ci

# 2) Prisma client
npx prisma generate

# 3) DB şemasını uygula (migration yoksa push)
npx prisma migrate deploy || npx prisma db push

# 4) Build ve çalıştır
npm run build
node dist/server.js
# -> http://localhost:4000/health


Geliştirme sırasında istersen:
npx ts-node src/server.ts

Dizinyapısı
.
├─ prisma/
│  ├─ schema.prisma
│  └─ dev.db                 # (gitignore)
├─ src/
│  ├─ auth/
│  │  ├─ routes.ts          # REST uçları
│  │  ├─ service.ts         # iş mantığı
│  │  ├─ tokens.ts          # JWT + cookie set/clear
│  │  ├─ email.ts           # SMTP
│  │  ├─ password.ts        # reset akışı
│  │  ├─ totp.ts            # 2FA
│  │  └─ oauth.ts           # Google OAuth
│  └─ server.ts             # Express + middleware
├─ .env.example             # örnek env (sırlar yok)
├─ .gitignore
├─ package.json
└─ tsconfig.json

Ortam Değişkenleri

.env.example dosyasını .env olarak kopyalayıp düzenle:

Ad	Açıklama	Örnek
DATABASE_URL	Prisma bağlantısı	file:./prisma/dev.db
JWT_ACCESS_SECRET	Access token için sır	change-me
JWT_REFRESH_SECRET	Refresh token için sır	change-me
NODE_ENV	development / production	development
PORT	Sunucu portu	4000
COOKIE_DOMAIN	Prod’da üst alan adı	.example.com
COOKIE_SECURE	true → sadece HTTPS	false (dev)
APP_NAME	E-posta başlığı vb.	auth-server
FRONTEND_URL	Redirect’ler için	http://localhost:3000
CORS_ORIGINS	Virgülle çoklu origin	http://localhost:3000
SMTP_*	Mail sunucusu bilgileri	…
GOOGLE_*	OAuth istemci bilgileri	…

Not: Localhost’ta cookie’ler için domain set edilmez (tarayıcı uyumu). Prod’da COOKIE_DOMAIN=.example.com ve HTTPS altında COOKIE_SECURE=true.

Uç Noktalar (özet)

POST /auth/register — { email, password } → 201

POST /auth/login — { email, password, totp? } → 200 + Set-Cookie

POST /auth/refresh — cookie’den refresh alır → yeni cookie’ler

POST /auth/logout — refresh revoke + cookie temizliği

GET /auth/me — korumalı; kullanıcı bilgisi

E-posta doğrulama

POST /auth/verify-email/request (auth) → mail gönderir

POST /auth/verify-email/confirm { token }

GET /auth/verify-email/confirm?token=... → redirect

Şifre sıfırlama

POST /auth/forgot-password { email }

POST /auth/reset-password { token, password }

2FA (TOTP)

POST /auth/2fa/setup (auth)

POST /auth/2fa/verify { token } (auth)

POST /auth/2fa/disable (auth)

Google OAuth

GET /auth/google → Google’a yönlendirir

GET /auth/google/callback → cookie set + redirect

Hızlı Test (cURL)
# Kayıt
EMAIL="test+$RANDOM@example.com"
curl -i -X POST http://localhost:4000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"'"$EMAIL"'","password":"S3cure!pass"}'

# (dev) E-postayı doğrulanmışa çekmek istersen:
# sqlite3 prisma/dev.db "UPDATE User SET emailVerifiedAt = datetime('now') WHERE email='$EMAIL';"

# Login (cookie’leri kaydet)
curl -i -c cj -X POST http://localhost:4000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"'"$EMAIL"'","password":"S3cure!pass"}'

# Korumalı uç
curl -i -b cj http://localhost:4000/auth/me

# Refresh & Logout
curl -i -c cj -b cj -X POST http://localhost:4000/auth/refresh
curl -i -c cj -b cj -X POST http://localhost:4000/auth/logout

Güvenlik Notları

Cookie’ler: HttpOnly, SameSite=Lax, prod’da Secure + trust proxy

CORS: CORS_ORIGINS ile sadece izinli origin’ler

Token rotasyonu: her refresh’te yeni refresh + eski revoke

TTL’ler: access 15m, refresh 7d (kolayca değiştirilebilir)

E-posta & reset tokenları: hash’li saklanır, süreli, tek kullanımlık

(Opsiyonel) /auth/* için temel rate-limit ekleyebilirsin:

import rateLimit from "express-rate-limit";
app.use("/auth", rateLimit({ windowMs: 15*60*1000, max: 20 }));

Üretim (kısa rehber)

.env (örnek):

NODE_ENV=production
PORT=4000
COOKIE_DOMAIN=.example.com
COOKIE_SECURE=true
FRONTEND_URL=https://app.example.com
CORS_ORIGINS=https://app.example.com


Reverse proxy (Nginx örneği):

server {
  server_name api.example.com;
  location / {
    proxy_pass         http://127.0.0.1:4000;
    proxy_set_header   Host $host;
    proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header   X-Forwarded-Proto $scheme;
  }
}


Process manager (PM2):

pm2 start "node dist/server.js" --name mekod-auth --update-env
pm2 save

Geliştirme İpuçları

tokens.ts tek noktadan cookie bayraklarını yönetir.

Localhost’ta cookie domain yok; prod’da .example.com.

server.ts içinde app.set("trust proxy", 1) aktif (Cloudflare/Nginx).

Prisma loglarını görmek için:

const prisma = new PrismaClient({ log: ['query','error'] });

Lisans

MIT © 2025 Mert Turkoglu

İstersen mini logo / badge, veya OpenAPI (Swagger) ekleyen bir PR checklist’i de yazabilirim; ama şu haliyle “kur → çalıştır → test et → deploy” akışı tam.
