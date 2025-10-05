import crypto from "crypto";
import { PrismaClient } from "@prisma/client";
import { sendEmail } from "./email";

const prisma = new PrismaClient();

/** Reset token üret ve mail gönder */
export async function createPasswordReset(email: string) {
  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) throw new Error("UserNotFound");

  // Rastgele token üret
  const token = crypto.randomBytes(32).toString("hex");
  const expiresAt = new Date(Date.now() + 1000 * 60 * 15); // 15 dk geçerli

  // DB’ye kaydet (PasswordResetToken tablosuna, schema.prisma’da ekleyeceğiz)
  await prisma.passwordResetToken.create({
    data: {
      userId: user.id,
      tokenHash: crypto.createHash("sha256").update(token).digest("hex"),
      expiresAt,
    },
  });

  // Kullanıcıya e-posta at
  const link = `http://localhost:3000/reset-password?token=${token}`;
  await sendEmail(
    user.email,
    "Şifre Sıfırlama",
    `<p>Şifreni sıfırlamak için linke tıkla:</p><a href="${link}">${link}</a>`
  );
}

/** Token doğrula ve yeni şifre ata */
export async function resetPassword(token: string, newPassword: string) {
  const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
  const record = await prisma.passwordResetToken.findFirst({
    where: { tokenHash, expiresAt: { gt: new Date() } },
    include: { user: true },
  });

  if (!record) throw new Error("InvalidOrExpired");

  const bcrypt = await import("bcryptjs");
  const passwordHash = bcrypt.hashSync(newPassword, 12);

  // Şifreyi güncelle
  await prisma.user.update({
    where: { id: record.userId },
    data: { passwordHash },
  });

  // Token’ı kullanıldı diye sil
  await prisma.passwordResetToken.delete({ where: { id: record.id } });
}
