import express, { type Express } from "express";
import cors from "cors";
import pinoHttp from "pino-http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import router from "./routes/index.js";
import ssrRouter from "./routes/ssr.js";
import { logger } from "./lib/logger.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const LUMINA_DIR = path.resolve(__dirname, "../../lumina-villa");

const app: Express = express();

app.use(
  pinoHttp({
    logger,
    serializers: {
      req(req) {
        return { id: req.id, method: req.method, url: req.url?.split("?")[0] };
      },
      res(res) {
        return { statusCode: res.statusCode };
      },
    },
  }),
);
app.use(cors());
app.use(express.json({ limit: "20mb" }));
app.use(express.urlencoded({ extended: true, limit: "20mb" }));

// ── API routes ────────────────────────────────────────────────────
app.use("/api", router);

// ── Static assets from lumina-villa (admin dashboard, fonts, etc.)
// Serves /admin/*, /assets/*, etc. but NOT index.html at root (SSR handles that)
app.use(
  express.static(LUMINA_DIR, {
    index: false,   // don't auto-serve index.html — SSR handles /
    dotfiles: "ignore",
  }),
);

// ── Admin dashboard: serve admin/index.html at /admin and /admin/ ─
app.get(["/admin", "/admin/"], (_req, res) => {
  res.sendFile(path.resolve(LUMINA_DIR, "admin", "index.html"));
});

// ── SSR routes: / and /villa/:slug ───────────────────────────────
app.use(ssrRouter);

// ── 404 fallback ─────────────────────────────────────────────────
app.use((_req, res) => {
  res.status(404).type("html").send(`<!DOCTYPE html>
<html lang="id"><head><meta charset="utf-8"/><title>404</title>
<style>body{font-family:sans-serif;text-align:center;padding:80px;color:#191d1a;}</style></head>
<body><h1 style="font-size:4rem;margin-bottom:8px">404</h1>
<p>Halaman tidak ditemukan.</p><a href="/" style="color:#1e3a2f;">← Kembali ke beranda</a></body></html>`);
});

export default app;
