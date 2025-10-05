import bcrypt from "bcryptjs";
import { PrismaClient } from "@prisma/client";
import { signAccess, signRefresh } from "./tokens";

const prisma = new PrismaClient();

/** Yardımcı: Cihaz kaydı/izleme (opsiyonel) */
async function upsertDevice(userId: string, userAgent?: string, ip?: string) {
  try {
    // Basit bir kural: aynı userId + userAgent + ip kombinasyonunu tek cihaz say.
    const existing = await prisma.device.findFirst({
      where: { userId, userAgent: userAgent || undefined, ip: ip || undefined },
    });
    if (existing) {
      await prisma.device.update({
        where: { id: existing.id },
        data: { lastSeenAt: new Date() },
      });
    } else {
      await prisma.device.create({
        data: {
          userId,
          name: undefined,
          userAgent,
          ip,
        },
      });
    }
  } catch {
    // cihaz takibi opsiyonel; hata olsa da auth akışını bozma
  }
}

/** Register */
export async function register(email: string, password: string) {
  const exists = await prisma.user.findUnique({ where: { email } });
  if (exists) throw new Error("EmailInUse");

  const passwordHash = bcrypt.hashSync(password, 12);
  const user = await prisma.user.create({ data: { email, passwordHash } });

  return { id: user.id, email: user.email };
}

/** Login: şifre doğrula + session oluştur + token üret */
export async function login(
  email: string,
  password: string,
  userAgent?: string,
  ip?: string
) {
  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) throw new Error("InvalidCredentials");

  const ok = bcrypt.compareSync(password, user.passwordHash);
  if (!ok) throw new Error("InvalidCredentials");

  const access = signAccess(user.id);
  const refresh = signRefresh(user.id);

  const refreshHash = bcrypt.hashSync(refresh, 12);
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

  await prisma.session.create({
    data: {
      userId: user.id,
      refreshTokenHash: refreshHash,
      userAgent,
      ip,
      expiresAt,
    },
  });

  // cihaz kaydı (opsiyonel)
  await upsertDevice(user.id, userAgent, ip);

  return {
    user: { id: user.id, email: user.email },
    access,
    refresh,
    expiresAt,
  };
}

/** Refresh rotate: eski session’ı revoke et, yenisini oluştur (routes içinde userId doğrulanır) */
export async function rotateRefreshForUser(
  userId: string,
  oldRefreshToken: string,
  userAgent?: string,
  ip?: string
) {
  const sessions = await prisma.session.findMany({
    where: { userId, revokedAt: null },
    orderBy: { createdAt: "desc" },
  });

  const match = sessions.find((s) =>
    bcrypt.compareSync(oldRefreshToken, s.refreshTokenHash)
  );
  if (!match) throw new Error("InvalidRefresh");

  // Eskiyi revoke et
  await prisma.session.update({
    where: { id: match.id },
    data: { revokedAt: new Date() },
  });

  // Yeni üret
  const access = signAccess(userId);
  const refresh = signRefresh(userId);
  const refreshHash = bcrypt.hashSync(refresh, 12);
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

  await prisma.session.create({
    data: {
      userId,
      refreshTokenHash: refreshHash,
      userAgent,
      ip,
      expiresAt,
    },
  });

  // cihaz güncelle (opsiyonel)
  await upsertDevice(userId, userAgent, ip);

  return { access, refresh, expiresAt };
}

/** Logout: refresh’i bul ve revoke et */
export async function logout(userId: string, refreshToken: string) {
  const sessions = await prisma.session.findMany({
    where: { userId, revokedAt: null },
  });
  const match = sessions.find((s) =>
    bcrypt.compareSync(refreshToken, s.refreshTokenHash)
  );
  if (match) {
    await prisma.session.update({
      where: { id: match.id },
      data: { revokedAt: new Date() },
    });
  }
}

/** (Opsiyonel) Kullanıcının oturumlarını listele */
export async function listSessions(userId: string) {
  return prisma.session.findMany({
    where: { userId },
    orderBy: [{ revokedAt: "asc" }, { createdAt: "desc" }],
    select: { id: true, createdAt: true, expiresAt: true, revokedAt: true, userAgent: true, ip: true },
  });
}

/** (Opsiyonel) Belirli oturumu revoke et */
export async function revokeSession(userId: string, sessionId: string) {
  const s = await prisma.session.findUnique({ where: { id: sessionId } });
  if (!s || s.userId !== userId) throw new Error("NotFound");
  if (s.revokedAt) return { ok: true };
  await prisma.session.update({ where: { id: sessionId }, data: { revokedAt: new Date() } });
  return { ok: true };
}
