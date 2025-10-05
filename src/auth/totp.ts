// src/auth/totp.ts
import { PrismaClient } from "@prisma/client";
import { authenticator } from "otplib";
import QRCode from "qrcode";

const prisma = new PrismaClient();

const APP_NAME = process.env.APP_NAME || "myworld";

/**
 * Kullanıcı için TOTP kurulum secret'ı üretir, DB'ye kaydeder,
 * otpauth URL ve QR kodu (data URL) döndürür.
 *
 * GEREKEN ŞEMA ALANLARI (User modeline eklenecek):
 *   twoFactorSecret String?
 *   twoFactorEnabled Boolean @default(false)
 */
export async function setupTOTP(userId: string) {
  const user = await prisma.user.findUnique({ where: { id: userId } });
  if (!user) throw new Error("UserNotFound");

  const secret = authenticator.generateSecret();
  const label = `${APP_NAME}:${user.email}`;
  const otpauthUrl = authenticator.keyuri(user.email, APP_NAME, secret);
  const qrDataUrl = await QRCode.toDataURL(otpauthUrl);

  await prisma.user.update({
    where: { id: userId },
    data: { twoFactorSecret: secret, twoFactorEnabled: false },
  });

  return { otpauthUrl, qrDataUrl };
}

/**
 * Kullanıcının girdiği TOTP kodunu doğrular ve 2FA’yı etkinleştirir.
 */
export async function verifyTOTP(userId: string, token: string) {
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: { twoFactorSecret: true },
  });
  if (!user || !user.twoFactorSecret) throw new Error("NoTOTPSetup");

  const ok = authenticator.check(token, user.twoFactorSecret);
  if (!ok) throw new Error("InvalidTOTP");

  await prisma.user.update({
    where: { id: userId },
    data: { twoFactorEnabled: true },
  });

  return { ok: true };
}

/**
 * 2FA’yı tamamen kapatır (secret’ı temizler).
 */
export async function disableTOTP(userId: string) {
  await prisma.user.update({
    where: { id: userId },
    data: { twoFactorSecret: null, twoFactorEnabled: false },
  });
  return { ok: true };
}

/**
 * Giriş sırasında, kullanıcı 2FA aktifse token’ı doğrulamak için yardımcı.
 */
export async function requireTOTPIfEnabled(userId: string, token?: string) {
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: { twoFactorEnabled: true, twoFactorSecret: true },
  });
  if (!user) throw new Error("UserNotFound");
  if (!user.twoFactorEnabled) return { required: false, ok: true };

  if (!token) return { required: true, ok: false };
  const ok = authenticator.check(token, user.twoFactorSecret!);
  if (!ok) throw new Error("InvalidTOTP");
  return { required: false, ok: true };
}
