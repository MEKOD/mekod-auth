// backend/src/server.ts
import "dotenv/config";
import express from "express";
import helmet from "helmet";
import cors, { CorsOptions } from "cors";
import cookieParser from "cookie-parser";

import authRoutes from "./auth/routes";

const app = express();

const PORT = Number(process.env.PORT ?? 4000);
const NODE_ENV = process.env.NODE_ENV || "development";

// Çoklu origin desteği: CORS_ORIGINS virgülle ayır (prod + localhost)
const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:3000";
const ORIGINS = (process.env.CORS_ORIGINS ?? FRONTEND_URL)
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

// Proxy arkasında isen Secure cookie/SameSite için şart
app.set("trust proxy", 1);

// Güvenlik + parsers
app.use(
  helmet({
    // SPA çağrıları için minimal, gerekirse CSP eklenir
    crossOriginResourcePolicy: { policy: "cross-origin" },
  })
);
app.use(express.json({ limit: "1mb" }));
app.use(cookieParser());

// CORS (credentials:true, sadece listedeki origin'lere izin)
const corsOptions: CorsOptions = {
  origin(origin, cb) {
    // Origin header yoksa (curl/health) izin ver
    if (!origin) return cb(null, true);
    // Listedeki origin'ler + localhost varyasyonları
    const ok =
      ORIGINS.includes(origin) ||
      /^https?:\/\/localhost(:\d+)?$/.test(origin) ||
      /^https?:\/\/127\.0\.0\.1(:\d+)?$/.test(origin);
    cb(ok ? null : new Error("CORS blocked"), ok);
  },
  credentials: true,
};
app.use(cors(corsOptions));
// Preflight
app.options("*", cors(corsOptions));

// Health
app.get("/health", (_req, res) => res.json({ ok: true, env: NODE_ENV }));

// Auth endpointleri
app.use("/auth", authRoutes);

// Basit hata yakalayıcı (5xx yerine kontrollü cevap)
app.use((err: any, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  const status = Number(err?.status || err?.statusCode || 500);
  const message =
    status >= 500 ? "Internal server error" : String(err?.message || "Bad request");
  if (status >= 500) {
    // prod’da hassas içeriği logla ama kullanıcıya göstermeyelim
    // eslint-disable-next-line no-console
    console.error(err);
  }
  res.status(status).json({ error: message });
});

// Dinle
app.listen(PORT, () => {
  console.log(`API listening on http://localhost:${PORT}`);
  console.log(`NODE_ENV: ${NODE_ENV}`);
  console.log(`CORS origins: ${ORIGINS.join(", ") || "(none)"}`);
});
