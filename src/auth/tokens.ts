// src/auth/tokens.ts
import type { Response } from "express";
import jwt from "jsonwebtoken";

// ---- env assert (fail-fast) ----
function mustGetEnv(key: string): string {
  const v = process.env[key];
  if (!v) throw new Error(`Missing env: ${key}`);
  return v;
}
const ACCESS_SECRET = mustGetEnv("JWT_ACCESS_SECRET");
const REFRESH_SECRET = mustGetEnv("JWT_REFRESH_SECRET");

// ---- cookie bayrakları ----
const IS_PROD = process.env.NODE_ENV === "production";
const SECURE = IS_PROD || (process.env.COOKIE_SECURE ?? "false") === "true";
const RAW_DOMAIN = process.env.COOKIE_DOMAIN ?? "localhost";
// localhost'ta domain verme (tarayıcı uyumu)
const DOMAIN: string | undefined =
  RAW_DOMAIN && RAW_DOMAIN !== "localhost" ? RAW_DOMAIN : undefined;

// ÇAKIŞMAYI ÖNLEMEK İÇİN YENİ İSİM
export type AuthJwtPayload = { sub: string; type: "access" | "refresh" };

export function signAccess(userId: string) {
  const payload: AuthJwtPayload = { sub: userId, type: "access" };
  return jwt.sign(payload, ACCESS_SECRET, { expiresIn: "15m" });
}

export function signRefresh(userId: string) {
  const payload: AuthJwtPayload = { sub: userId, type: "refresh" };
  return jwt.sign(payload, REFRESH_SECRET, { expiresIn: "7d" });
}

export function verifyAccess(token: string): AuthJwtPayload {
  return jwt.verify(token, ACCESS_SECRET) as AuthJwtPayload;
  // alternatif: return jwt.verify<AuthJwtPayload>(token, ACCESS_SECRET);
}

export function verifyRefresh(token: string): AuthJwtPayload {
  return jwt.verify(token, REFRESH_SECRET) as AuthJwtPayload;
}

/** HttpOnly cookie’leri set et */
export function setAuthCookies(res: Response, access: string, refresh: string) {
  const base = {
    httpOnly: true,
    sameSite: "lax" as const,
    secure: SECURE,
    path: "/" as const,
    ...(DOMAIN ? { domain: DOMAIN } : {}),
  };
  res.cookie("access_token", access, { ...base, maxAge: 15 * 60 * 1000 });
  res.cookie("refresh_token", refresh, { ...base, maxAge: 7 * 24 * 60 * 60 * 1000 });
}

export function clearAuthCookies(res: Response) {
  const opts = { path: "/" as const, ...(DOMAIN ? { domain: DOMAIN } : {}) };
  res.clearCookie("access_token", opts);
  res.clearCookie("refresh_token", opts);
}
