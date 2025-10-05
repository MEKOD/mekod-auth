// src/auth/oauth.ts
import type { CodeChallengeMethod } from "google-auth-library/build/src/auth/oauth2client";
import type { Request, Response } from "express";
import { OAuth2Client } from "google-auth-library";
import { PrismaClient } from "@prisma/client";
import { signAccess, signRefresh } from "./tokens";
import bcrypt from "bcryptjs";
import crypto from "crypto";

const prisma = new PrismaClient();

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID!;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET!;
const GOOGLE_REDIRECT_URI =
  process.env.GOOGLE_REDIRECT_URI || "http://localhost:4000/auth/google/callback";

const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:3000";
const IS_PROD = process.env.NODE_ENV === "production";

const oauth2 = new OAuth2Client({
  clientId: GOOGLE_CLIENT_ID,
  clientSecret: GOOGLE_CLIENT_SECRET,
  redirectUri: GOOGLE_REDIRECT_URI,
});

const GOOGLE_SCOPES = ["openid", "email", "profile"];

/* ---------- Helpers ---------- */
function base64url(buf: Buffer) {
  return buf
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}
function sha256(input: string) {
  return crypto.createHash("sha256").update(input).digest();
}
function setTemp(res: Response, name: string, value: string, sec = 600) {
  res.cookie(name, value, {
    httpOnly: true,
    sameSite: "lax",
    secure: IS_PROD,
    maxAge: sec * 1000,
    path: "/",
  });
}
function clearTemp(res: Response, name: string) {
  res.clearCookie(name, { path: "/" });
}

/* ---------- Google URL ---------- */
export function getGoogleAuthUrl(req?: Request, res?: Response) {
  if (req && res) {
    const state = crypto.randomBytes(32).toString("hex");
    const codeVerifier = base64url(crypto.randomBytes(32));
    const codeChallenge = base64url(sha256(codeVerifier));

    setTemp(res, "oauth_state", state, 600);
    setTemp(res, "oauth_code_verifier", codeVerifier, 600);

    return oauth2.generateAuthUrl({
      access_type: "offline",
      prompt: "consent",
      scope: GOOGLE_SCOPES,
      state,
      code_challenge: codeChallenge,
    code_challenge_method: "S256" as unknown as CodeChallengeMethod,

    });
  }

  // fallback
  return oauth2.generateAuthUrl({
    access_type: "offline",
    prompt: "consent",
    scope: GOOGLE_SCOPES,
  });
}

/* ---------- Google Callback ---------- */
export async function handleGoogleCallback(
  req: Request,
  res: Response,
  userAgent?: string,
  ip?: string
): Promise<{
  user?: { id: string; email: string };
  access?: string;
  refresh?: string;
  expiresAt?: Date;
  redirectTo?: string;
}> {
  const code = req.query.code as string | undefined;
  const state = req.query.state as string | undefined;
  if (!code || !state) throw new Error("MissingCodeOrState");

  const stateCookie = req.cookies?.["oauth_state"];
  const codeVerifier = req.cookies?.["oauth_code_verifier"];
  if (!stateCookie || stateCookie !== state || !codeVerifier) {
    throw new Error("InvalidOAuthState");
  }

  // Token takası (PKCE ile)
  const { tokens } = await oauth2.getToken({
    code,
    codeVerifier,
    redirect_uri: GOOGLE_REDIRECT_URI,
  } as any);
  oauth2.setCredentials(tokens);

  clearTemp(res, "oauth_state");
  clearTemp(res, "oauth_code_verifier");

  // ID token doğrulama
  if (!tokens.id_token) throw new Error("NoIdToken");
  const ticket = await oauth2.verifyIdToken({
    idToken: tokens.id_token,
    audience: GOOGLE_CLIENT_ID,
  });
  const payload = ticket.getPayload();
  if (!payload || !payload.sub || !payload.email) {
    throw new Error("GoogleProfileError");
  }

  const googleId = payload.sub;
  const email = payload.email;

  // Kullanıcıyı bul/oluştur
  let user = await prisma.user.findFirst({
    where: { OR: [{ googleId }, { email }] },
  });

  if (!user) {
    const placeholder = bcrypt.hashSync(`google:${googleId}`, 12);
    user = await prisma.user.create({
      data: {
        email,
        googleId,
        passwordHash: placeholder,
        emailVerifiedAt: new Date(),
      },
    });
  } else if (!user.googleId) {
    user = await prisma.user.update({
      where: { id: user.id },
      data: { googleId, emailVerifiedAt: user.emailVerifiedAt ?? new Date() },
    });
  }

  // Eğer 2FA açıksa redirectTo döndür
  if ((user as any).twoFactorEnabled) {
    setTemp(res, "pending_totp_user", user.id, 300);
    return {
      user: { id: user.id, email: user.email },
      redirectTo: `${FRONTEND_URL}/totp-challenge`,
    };
  }

  // Normal akış
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

  return {
    user: { id: user.id, email: user.email },
    access,
    refresh,
    expiresAt,
  };
}
