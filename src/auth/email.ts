// backend/src/auth/email.ts
import crypto from "crypto";
import nodemailer from "nodemailer";
import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

/* ---------- ENV ---------- */
const SMTP_HOST = process.env.SMTP_HOST || "smtp.example.com";
const SMTP_PORT = Number(process.env.SMTP_PORT || 587);
const SMTP_USER = process.env.SMTP_USER || "user@example.com";
const SMTP_PASS = process.env.SMTP_PASS || "password";
const FROM_EMAIL = process.env.FROM_EMAIL || "no-reply@myworld.com";
const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:3000";

/* ---------- MAILER ---------- */
const transporter = nodemailer.createTransport({
  host: SMTP_HOST,
  port: SMTP_PORT,
  secure: SMTP_PORT === 465, // 465 → SSL
  auth: { user: SMTP_USER, pass: SMTP_PASS },
});

export async function sendEmail(to: string, subject: string, html: string) {
  await transporter.sendMail({ from: FROM_EMAIL, to, subject, html });
}

/* ---------- HELPERS ---------- */
function hashToken(raw: string) {
  return crypto.createHash("sha256").update(raw).digest("hex");
}

function appUrl(path: string) {
  // path: "/verify-email.html?token=..."
  return `${FRONTEND_URL.replace(/\/$/, "")}${path}`;
}

/* ========================================================================== */
/*                          E-POSTA DOĞRULAMA AKIŞI                           */
/* ========================================================================== */

/**
 * Kullanıcıya doğrulama e-postası yollar.
 * - DB'ye EmailVerificationToken kaydı atar (hash + son kullanma)
 * - Kullanıcıya FRONTEND_URL üzerinde doğrulama linki gönderir
 */
export async function createEmailVerification(userId: string, email: string) {
  // 32-byte rastgele token üret
  const token = crypto.randomBytes(32).toString("hex");
  const tokenHash = hashToken(token);
  const expiresAt = new Date(Date.now() + 1000 * 60 * 60); // 1 saat

  // Eski tokenları temizle (isteğe bağlı)
  await prisma.emailVerificationToken.deleteMany({
    where: { userId },
  });

  await prisma.emailVerificationToken.create({
    data: { userId, tokenHash, expiresAt },
  });

  const link = appUrl(`/verify-email.html?token=${token}`);
  const html = `
    <div style="font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;line-height:1.4">
      <h2>myworld • E-posta Doğrulama</h2>
      <p>Merhaba, hesabını doğrulamak için aşağıdaki butona tıkla.</p>
      <p>
        <a href="${link}" style="display:inline-block;background:#7c5cff;color:#fff;
           padding:10px 14px;border-radius:10px;text-decoration:none">
           E-postamı Doğrula
        </a>
      </p>
      <p>Buton çalışmazsa bu bağlantıyı kopyala:</p>
      <code style="word-break:break-all">${link}</code>
      <p style="color:#667085">Bu bağlantı 1 saat geçerlidir.</p>
    </div>
  `;

  await sendEmail(email, "E-posta Doğrulama", html);
}

/**
 * Doğrulama tokenını onaylar.
 * - Token geçerliyse User.emailVerifiedAt alanını set eder
 * - Tokenı tüketir (siler)
 */
export async function confirmEmail(token: string) {
  const tokenHash = hashToken(token);

  const rec = await prisma.emailVerificationToken.findFirst({
    where: {
      tokenHash,
      expiresAt: { gt: new Date() },
    },
  });

  if (!rec) throw new Error("InvalidOrExpired");

  await prisma.user.update({
    where: { id: rec.userId },
    data: { emailVerifiedAt: new Date() },
  });

  await prisma.emailVerificationToken.delete({ where: { id: rec.id } });
}

/**
 * Kullanıcının mevcut e-postasına yeniden doğrulama maili yollar.
 * (Örn. login sırasında doğrulanmamışsa tetiklemek için.)
 */
export async function requestEmailVerification(userId: string) {
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: { email: true },
  });
  if (!user) throw new Error("UserNotFound");
  await createEmailVerification(userId, user.email);
}
