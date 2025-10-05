// src/auth/routes.ts
import { Router, type Request, type Response, type NextFunction } from "express";
import { PrismaClient } from "@prisma/client";
import {
  verifyAccess,
  verifyRefresh,
  setAuthCookies,
  clearAuthCookies,
} from "./tokens";
import { login, logout, register, rotateRefreshForUser } from "./service";
import { createPasswordReset, resetPassword } from "./password";
import { setupTOTP, verifyTOTP, disableTOTP, requireTOTPIfEnabled } from "./totp";
import { getGoogleAuthUrl, handleGoogleCallback } from "./oauth";
import { sendEmail } from "./email";
import crypto from "crypto";

const prisma = new PrismaClient();
const r = Router();

const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:3000";
const BACKEND_URL  = process.env.BACKEND_URL  || "http://localhost:4000";
const APP_NAME = process.env.APP_NAME || "myworld";

/* ========== Helpers ========== */

function requireBody<T extends string[]>(keys: T) {
  return (req: Request, res: Response, next: NextFunction) => {
    for (const k of keys) {
      if (typeof (req.body as any)[k] !== "string") {
        return res.status(400).json({ error: "Validation" });
      }
    }
    next();
  };
}

// Cookie öncelikli; yoksa Authorization: Bearer <token> kabul eder
export function requireAuth(req: Request, res: Response, next: NextFunction) {
  try {
    let token = req.cookies?.access_token as string | undefined;

    if (!token) {
      const auth = req.header("authorization") || req.header("Authorization");
      if (auth && auth.startsWith("Bearer ")) token = auth.slice(7).trim();
    }

    if (!token) return res.status(401).json({ error: "Unauthorized" });

    const payload = verifyAccess(token);
    (req as any).userId = payload.sub;
    next();
  } catch {
    return res.status(401).json({ error: "Unauthorized" });
  }
}

async function sendVerificationEmailForUser(userId: string, email: string) {
  const token = crypto.randomBytes(32).toString("hex");
  const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);

  await prisma.emailVerificationToken.deleteMany({ where: { userId } });
  await prisma.emailVerificationToken.create({
    data: { userId, tokenHash, expiresAt },
  });

  const link = `${BACKEND_URL}/auth/verify-email/confirm?token=${encodeURIComponent(token)}`;

  // mail hatası kayıt/giriş akışını düşürmesin
  try {
    await sendEmail(
      email,
      `${APP_NAME} • E-posta Doğrulama`,
      `<p>E-postanı doğrulamak için tıkla:</p><a href="${link}">${link}</a>`
    );
  } catch (err: any) {
    console.error("sendEmail failed:", err?.message || err);
  }
}

/* ========== Health ========== */

r.get("/health", (_req, res) => res.json({ ok: true }));

/* ========== Auth Core ========== */

r.post("/register", requireBody(["email", "password"]), async (req, res) => {
  try {
    const { email, password } = req.body;
    if (password.length < 8) return res.status(400).json({ error: "Validation" });

    const user = await register(email, password);
    await sendVerificationEmailForUser(user.id, user.email);

    return res.status(201).json({ ok: true, user });
  } catch (e: any) {
    // prisma unique hatası veya kendi "EmailInUse" mesajın
    if (e?.code === "P2002" || e?.message === "EmailInUse") {
      return res.status(409).json({ error: "EmailInUse" });
    }
    console.error("REGISTER ERROR:", e);
    return res.status(500).json({ error: "Internal" });
  }
});

r.post("/login", requireBody(["email", "password"]), async (req, res) => {
  try {
    const ua = (req.headers["user-agent"] as string) ?? undefined;
    const ip =
      (req.headers["x-forwarded-for"] as string) ||
      req.socket.remoteAddress ||
      undefined;

    const existing = await prisma.user.findUnique({
      where: { email: req.body.email },
      select: {
        id: true,
        email: true,
        emailVerifiedAt: true,
        twoFactorEnabled: true,
      },
    });

    if (existing && !existing.emailVerifiedAt) {
      // yeniden doğrulama maili göndermeye çalış, hata verse bile 403 dön
      try { await sendVerificationEmailForUser(existing.id, existing.email); }
      catch (err) { console.error("resend verify email failed:", err); }
      return res.status(403).json({ error: "EmailNotVerified", resent: true });
    }

    if (existing?.twoFactorEnabled) {
      const totp = (req.body as any).totp as string | undefined;
      const check = await requireTOTPIfEnabled(existing.id, totp);
      if (check.required) return res.status(400).json({ error: "TOTPRequired" });
    }

    const { user, access, refresh, expiresAt } = await login(
      req.body.email,
      req.body.password,
      ua,
      ip
    );

    // Cookie set (bayraklar tokens.ts içindeki setAuthCookies'te yönetiliyor)
    setAuthCookies(res, access, refresh);
    return res.json({ ok: true, user, sessionExpiresAt: expiresAt });
  } catch (e: any) {
    if (e?.message === "InvalidTOTP") return res.status(400).json({ error: "InvalidTOTP" });
    if (e?.message === "InvalidCredentials") return res.status(400).json({ error: "InvalidCredentials" });
    console.error("LOGIN ERROR:", e);
    return res.status(500).json({ error: "Internal" });
  }
});

r.post("/refresh", async (req, res) => {
  try {
    const token = req.cookies?.refresh_token as string | undefined;
    if (!token) return res.status(401).json({ error: "NoRefresh" });

    const payload = verifyRefresh(token);

    const ua = (req.headers["user-agent"] as string) ?? undefined;
    const ip =
      (req.headers["x-forwarded-for"] as string) ||
      req.socket.remoteAddress ||
      undefined;

    const { access, refresh, expiresAt } = await rotateRefreshForUser(
      payload.sub,
      token,
      ua,
      ip
    );

    setAuthCookies(res, access, refresh);
    return res.json({ ok: true, sessionExpiresAt: expiresAt });
  } catch {
    return res.status(401).json({ error: "InvalidRefresh" });
  }
});

r.post("/logout", async (req, res) => {
  try {
    const token = req.cookies?.refresh_token as string | undefined;
    if (token) {
      try {
        const payload = verifyRefresh(token);
        await logout(payload.sub, token);
      } catch {}
    }
    clearAuthCookies(res);
    return res.json({ ok: true });
  } catch {
    clearAuthCookies(res);
    return res.json({ ok: true });
  }
});

r.get("/me", requireAuth, async (req, res) => {
  const userId = (req as any).userId as string;
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: {
      id: true,
      email: true,
      createdAt: true,
      emailVerifiedAt: true,
      twoFactorEnabled: true,
    },
  });
  return res.json({ ok: true, user });
});

/* ========== Password Reset ========== */

r.post("/forgot-password", requireBody(["email"]), async (req, res) => {
  try {
    await createPasswordReset(req.body.email);
    return res.json({ ok: true });
  } catch (e: any) {
    if (e?.message === "UserNotFound") return res.json({ ok: true });
    return res.status(500).json({ error: "Internal" });
  }
});

r.post("/reset-password", requireBody(["token", "password"]), async (req, res) => {
  try {
    const { token, password } = req.body;
    if (password.length < 8) return res.status(400).json({ error: "Validation" });
    await resetPassword(token, password);
    return res.json({ ok: true });
  } catch (e: any) {
    if (e?.message === "InvalidOrExpired") return res.status(400).json({ error: "InvalidOrExpired" });
    return res.status(500).json({ error: "Internal" });
  }
});

/* ========== Email Verification ========== */

r.post("/verify-email/request", requireAuth, async (req, res) => {
  try {
    const userId = (req as any).userId as string;
    const user = await prisma.user.findUnique({ where: { id: userId }, select: { email: true } });
    if (!user) return res.status(404).json({ error: "NotFound" });
    await sendVerificationEmailForUser(userId, user.email);
    return res.json({ ok: true });
  } catch {
    return res.status(500).json({ error: "Internal" });
  }
});

// API POST confirm (JSON)
r.post("/verify-email/confirm", requireBody(["token"]), async (req, res) => {
  try {
    const tokenHash = crypto.createHash("sha256").update(req.body.token).digest("hex");

    const record = await prisma.emailVerificationToken.findFirst({
      where: { tokenHash, expiresAt: { gt: new Date() } },
    });
    if (!record) return res.status(400).json({ error: "InvalidOrExpired" });

    await prisma.user.update({
      where: { id: record.userId },
      data: { emailVerifiedAt: new Date() },
    });

    await prisma.emailVerificationToken.deleteMany({ where: { userId: record.userId } });
    return res.json({ ok: true });
  } catch {
    return res.status(500).json({ error: "Internal" });
  }
});

// E-postadaki link için GET confirm (redirect)
r.get("/verify-email/confirm", async (req, res) => {
  try {
    const token = (req.query.token as string) || "";
    if (!token) {
      return res.redirect(`${FRONTEND_URL}/verify.html?status=missing`);
    }

    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
    const record = await prisma.emailVerificationToken.findFirst({
      where: { tokenHash, expiresAt: { gt: new Date() } },
    });

    if (!record) {
      return res.redirect(`${FRONTEND_URL}/verify.html?status=invalid`);
    }

    await prisma.user.update({
      where: { id: record.userId },
      data: { emailVerifiedAt: new Date() },
    });

    await prisma.emailVerificationToken.deleteMany({ where: { userId: record.userId } });
    return res.redirect(`${FRONTEND_URL}/verify.html?status=ok`);
  } catch {
    return res.redirect(`${FRONTEND_URL}/verify.html?status=error`);
  }
});

/* ========== Sessions Management ========== */

r.get("/sessions", requireAuth, async (req, res) => {
  const userId = (req as any).userId as string;
  const sessions = await prisma.session.findMany({
    where: { userId },
    orderBy: [{ revokedAt: "asc" }, { createdAt: "desc" }],
    select: {
      id: true,
      createdAt: true,
      expiresAt: true,
      revokedAt: true,
      userAgent: true,
      ip: true,
    },
  });
  return res.json({ ok: true, sessions });
});

r.post("/sessions/:id/revoke", requireAuth, async (req, res) => {
  const userId = (req as any).userId as string;
  const { id } = req.params;
  const s = await prisma.session.findUnique({ where: { id } });
  if (!s || s.userId !== userId) return res.status(404).json({ error: "NotFound" });
  if (s.revokedAt) return res.json({ ok: true });
  await prisma.session.update({ where: { id }, data: { revokedAt: new Date() } });
  return res.json({ ok: true });
});

/* ========== TOTP / 2FA ========== */

r.post("/2fa/setup", requireAuth, async (req, res) => {
  try {
    const userId = (req as any).userId as string;
    const data = await setupTOTP(userId);
    return res.json({ ok: true, ...data });
  } catch (e: any) {
    if (e?.message === "UserNotFound") return res.status(404).json({ error: "NotFound" });
    return res.status(500).json({ error: "Internal" });
  }
});

r.post("/2fa/verify", requireAuth, requireBody(["token"]), async (req, res) => {
  try {
    const userId = (req as any).userId as string;
    await verifyTOTP(userId, req.body.token);
    return res.json({ ok: true });
  } catch (e: any) {
    if (e?.message === "InvalidTOTP") return res.status(400).json({ error: "InvalidTOTP" });
    if (e?.message === "NoTOTPSetup") return res.status(400).json({ error: "NoTOTPSetup" });
    return res.status(500).json({ error: "Internal" });
  }
});

r.post("/2fa/disable", requireAuth, async (req, res) => {
  try {
    const userId = (req as any).userId as string;
    await disableTOTP(userId);
    return res.json({ ok: true });
  } catch {
    return res.status(500).json({ error: "Internal" });
  }
});

/* ========== Google OAuth (state + PKCE) ========== */

r.get("/google", (req, res) => {
  const url = getGoogleAuthUrl(req, res);
  return res.redirect(url);
});

r.get("/google/callback", async (req, res) => {
  try {
    const ua = (req.headers["user-agent"] as string) ?? undefined;
    const ip =
      (req.headers["x-forwarded-for"] as string) ||
      req.socket.remoteAddress ||
      undefined;

    const { user, access, refresh, redirectTo } = await handleGoogleCallback(
      req,
      res,
      ua,
      ip
    );

    if (redirectTo) return res.redirect(redirectTo);

    // access/refresh kesin var (redirectTo yoksa)
    setAuthCookies(res, access!, refresh!);

    if (FRONTEND_URL) return res.redirect(`${FRONTEND_URL}/me`);
    return res.json({ ok: true, user });
  } catch (e) {
    console.error("GOOGLE CALLBACK ERROR:", e);
    return res.status(400).json({ error: "GoogleAuthFailed" });
  }
});

export default r;
