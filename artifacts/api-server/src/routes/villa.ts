import { Router } from "express";
import { createHmac, createHash, randomBytes, pbkdf2 } from "node:crypto";
import { promisify } from "node:util";
import multer from "multer";

const pbkdf2Async = promisify(pbkdf2);
const router = Router();
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } });

// ── Config from env ───────────────────────────────────────────────
function getConfig() {
  const SUPABASE_URL = process.env.SUPABASE_URL;
  const SUPABASE_KEY = process.env.SUPABASE_KEY;
  const JWT_SECRET = process.env.JWT_SECRET;
  const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
  const GITHUB_REPO = process.env.GITHUB_REPO;
  const GITHUB_BRANCH = process.env.GITHUB_BRANCH || "main";
  const GITHUB_IMG_PATH = process.env.GITHUB_IMG_PATH || "images/villas";
  return { SUPABASE_URL, SUPABASE_KEY, JWT_SECRET, GITHUB_TOKEN, GITHUB_REPO, GITHUB_BRANCH, GITHUB_IMG_PATH };
}

// ── Supabase REST helper ──────────────────────────────────────────
async function sb(table: string, method = "GET", query = "", body: unknown = null) {
  const { SUPABASE_URL, SUPABASE_KEY } = getConfig();
  if (!SUPABASE_URL || !SUPABASE_KEY) throw { status: 500, message: "Supabase belum dikonfigurasi" };

  const url = `${SUPABASE_URL}/rest/v1/${table}${query ? "?" + query : ""}`;
  const headers: Record<string, string> = {
    apikey: SUPABASE_KEY,
    Authorization: `Bearer ${SUPABASE_KEY}`,
    "Content-Type": "application/json",
  };
  if (method !== "DELETE") headers["Prefer"] = "return=representation";
  const opts: RequestInit = { method, headers };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(url, opts);
  if (method === "DELETE" && res.status < 300) return [];
  const text = await res.text();
  if (!res.ok) throw new Error(`Supabase ${method} ${table} ${res.status}: ${text}`);
  return text ? JSON.parse(text) : [];
}

// ── JWT ───────────────────────────────────────────────────────────
function b64url(input: string | Buffer): string {
  const str = typeof input === "string" ? input : input.toString("binary");
  return Buffer.from(str, "binary").toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function signJWT(payload: Record<string, unknown>): string {
  const { JWT_SECRET } = getConfig();
  if (!JWT_SECRET) throw { status: 500, message: "JWT_SECRET belum dikonfigurasi" };
  const header = b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body = b64url(JSON.stringify({ ...payload, iat: Math.floor(Date.now() / 1000) }));
  const data = `${header}.${body}`;
  const sig = createHmac("sha256", JWT_SECRET).update(data).digest("base64url");
  return `${data}.${sig}`;
}

function verifyJWT(token: string): Record<string, unknown> | null {
  try {
    const { JWT_SECRET } = getConfig();
    if (!JWT_SECRET) return null;
    const [header, body, sig] = token.split(".");
    if (!header || !body || !sig) return null;
    const data = `${header}.${body}`;
    const expected = createHmac("sha256", JWT_SECRET).update(data).digest("base64url");
    if (expected !== sig) return null;
    const payload = JSON.parse(Buffer.from(body.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString());
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch { return null; }
}

// ── Password ──────────────────────────────────────────────────────
async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16);
  const saltHex = salt.toString("hex");
  const derived = await pbkdf2Async(password, salt, 100000, 32, "sha256");
  const hash = derived.toString("hex");
  return `${saltHex}:${hash}`;
}

async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const [saltHex, storedHash] = stored.split(":");
  const salt = Buffer.from(saltHex, "hex");
  const derived = await pbkdf2Async(password, salt, 100000, 32, "sha256");
  return derived.toString("hex") === storedHash;
}

// ── Auth helpers ──────────────────────────────────────────────────
type User = Record<string, unknown>;

function getUser(req: Express.Request): User | null {
  const auth = (req as any).headers.authorization || "";
  if (!auth.startsWith("Bearer ")) return null;
  return verifyJWT(auth.slice(7));
}

function requireAuth(req: Express.Request): User {
  const u = getUser(req);
  if (!u) throw { status: 401, message: "Unauthorized" };
  return u;
}

function requireSA(req: Express.Request): User {
  const u = requireAuth(req);
  if (u.role !== "superadmin") throw { status: 403, message: "Superadmin only" };
  return u;
}

function canAccessVilla(user: User, villaId: string): boolean {
  return user.role === "superadmin" || user.villa_id === villaId;
}

// ── Error wrapper ─────────────────────────────────────────────────
function handle(fn: (req: any, res: any) => Promise<void>) {
  return async (req: any, res: any) => {
    try {
      await fn(req, res);
    } catch (e: any) {
      if (e.status) return res.status(e.status).json({ error: e.message });
      console.error(e);
      res.status(500).json({ error: "Internal server error" });
    }
  };
}

// ── Routes ────────────────────────────────────────────────────────

// POST /setup
router.post("/setup", handle(async (req, res) => {
  const count = await sb("v_users", "GET", "select=id&limit=1");
  if ((count as any[]).length > 0) return res.status(403).json({ error: "Setup sudah dilakukan." });
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "username dan password wajib diisi" });
  const password_hash = await hashPassword(password);
  const user = await sb("v_users", "POST", "", { username, password_hash, role: "superadmin", status: "active" }) as any[];
  res.status(201).json({ message: "Superadmin berhasil dibuat", user: { id: user[0]?.id, username } });
}));

// POST /auth/login
router.post("/auth/login", handle(async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "username dan password wajib diisi" });
  const rows = await sb("v_users", "GET", `username=eq.${encodeURIComponent(username)}&select=*&limit=1`) as any[];
  const user = rows[0];
  if (!user) return res.status(401).json({ error: "Username atau password salah" });
  if (user.status === "pending") return res.status(403).json({ error: "Akun menunggu persetujuan superadmin" });
  if (user.status === "suspended") return res.status(403).json({ error: "Akun disuspend" });
  if (!await verifyPassword(password, user.password_hash)) return res.status(401).json({ error: "Username atau password salah" });
  const exp = Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 7;
  const token = signJWT({ sub: user.id, username: user.username, role: user.role, villa_id: user.villa_id, exp });
  res.json({ token, user: { id: user.id, username: user.username, role: user.role, villa_id: user.villa_id } });
}));

// POST /auth/register
router.post("/auth/register", handle(async (req, res) => {
  const { username, password, email, villa_id } = req.body;
  if (!username || !password) return res.status(400).json({ error: "username dan password wajib diisi" });
  if (password.length < 6) return res.status(400).json({ error: "Password minimal 6 karakter" });
  const existing = await sb("v_users", "GET", `username=eq.${encodeURIComponent(username)}&limit=1`) as any[];
  if (existing.length) return res.status(409).json({ error: "Username sudah dipakai" });
  const password_hash = await hashPassword(password);
  await sb("v_users", "POST", "", { username, password_hash, email: email || null, villa_id: villa_id || null, role: "admin", status: "pending" });
  res.status(201).json({ message: "Pendaftaran berhasil. Tunggu persetujuan superadmin." });
}));

// GET /auth/me
router.get("/auth/me", handle(async (req, res) => {
  const u = requireAuth(req);
  const rows = await sb("v_users", "GET", `id=eq.${u.sub}&select=id,username,email,role,villa_id,status,created_at&limit=1`) as any[];
  res.json(rows[0] || null);
}));

// GET /villas
router.get("/villas", handle(async (req, res) => {
  const u = requireAuth(req);
  let q = "select=*&order=created_at.asc";
  if (u.role !== "superadmin" && u.villa_id) q += `&id=eq.${u.villa_id}`;
  res.json(await sb("villa_info", "GET", q));
}));

// POST /villas
router.post("/villas", handle(async (req, res) => {
  const u = requireAuth(req);
  const b = req.body;
  if (!b.name || !b.slug) return res.status(400).json({ error: "name dan slug wajib diisi" });
  const ex = await sb("villa_info", "GET", `slug=eq.${encodeURIComponent(b.slug)}&limit=1`) as any[];
  if (ex.length) return res.status(409).json({ error: "Slug sudah dipakai" });
  const r = await sb("villa_info", "POST", "", {
    name: b.name, slug: b.slug, tagline: b.tagline || null,
    description: b.description || null, address: b.address || null,
    city: b.city || null, province: b.province || null,
    max_guests: b.max_guests || null, max_guests_note: b.max_guests_note || null,
    extra_bed_price: b.extra_bed_price || null, extra_bed_note: b.extra_bed_note || null,
    checkin_time: b.checkin_time || "14.00 WIB", checkout_time: b.checkout_time || "12.00 WIB",
  }) as any[];
  const villa = r[0] || r;
  if (u.role === "admin") await sb("v_users", "PATCH", `id=eq.${u.sub}`, { villa_id: villa.id });
  res.status(201).json(villa);
}));

// GET /villas/:id
router.get("/villas/:id", handle(async (req, res) => {
  const u = requireAuth(req);
  const { id } = req.params;
  if (!canAccessVilla(u, id)) return res.status(403).json({ error: "Forbidden" });
  const r = await sb("villa_info", "GET", `id=eq.${id}&select=*&limit=1`) as any[];
  if (!r.length) return res.status(404).json({ error: "Villa tidak ditemukan" });
  res.json(r[0]);
}));

// PATCH /villas/:id
router.patch("/villas/:id", handle(async (req, res) => {
  const u = requireAuth(req);
  const { id } = req.params;
  if (!canAccessVilla(u, id)) return res.status(403).json({ error: "Forbidden" });
  const b = req.body;
  const allowed = ["name","slug","tagline","description","address","city","province",
    "max_guests","max_guests_note","extra_bed_price","extra_bed_note","checkin_time","checkout_time"];
  const upd: Record<string, unknown> = { updated_at: new Date().toISOString() };
  for (const k of allowed) if (k in b) upd[k] = b[k];
  const r = await sb("villa_info", "PATCH", `id=eq.${id}`, upd) as any[];
  res.json(r[0] || r);
}));

// DELETE /villas/:id
router.delete("/villas/:id", handle(async (req, res) => {
  requireSA(req);
  const { id } = req.params;
  const ex = await sb("villa_info", "GET", `id=eq.${id}&select=id&limit=1`) as any[];
  if (!ex.length) return res.status(404).json({ error: "Villa tidak ditemukan" });
  await sb("facilities", "DELETE", `villa_id=eq.${id}`);
  await sb("policies", "DELETE", `villa_id=eq.${id}`);
  await sb("contacts", "DELETE", `villa_id=eq.${id}`);
  await sb("gallery", "DELETE", `villa_id=eq.${id}`);
  await sb("inquiries", "DELETE", `villa_id=eq.${id}`);
  await sb("villa_info", "DELETE", `id=eq.${id}`);
  res.json({ message: "Villa berhasil dihapus" });
}));

// GET /villas/:villaId/facilities
router.get("/villas/:villaId/facilities", handle(async (req, res) => {
  requireAuth(req);
  const { villaId } = req.params;
  res.json(await sb("facilities", "GET", `villa_id=eq.${villaId}&order=sort_order.asc`));
}));

// POST /villas/:villaId/facilities
router.post("/villas/:villaId/facilities", handle(async (req, res) => {
  const u = requireAuth(req);
  const { villaId } = req.params;
  if (!canAccessVilla(u, villaId)) return res.status(403).json({ error: "Forbidden" });
  const b = req.body;
  if (!b.name) return res.status(400).json({ error: "name wajib diisi" });
  const r = await sb("facilities", "POST", "", {
    villa_id: villaId, icon: b.icon || "star", name: b.name,
    description: b.description || null, sort_order: b.sort_order ?? 0, is_active: true,
  }) as any[];
  res.status(201).json(r[0] || r);
}));

// PATCH /facilities/:id
router.patch("/facilities/:id", handle(async (req, res) => {
  const u = requireAuth(req);
  const { id } = req.params;
  const fac = await sb("facilities", "GET", `id=eq.${id}&limit=1`) as any[];
  if (!fac.length) return res.status(404).json({ error: "Tidak ditemukan" });
  if (!canAccessVilla(u, fac[0].villa_id)) return res.status(403).json({ error: "Forbidden" });
  const r = await sb("facilities", "PATCH", `id=eq.${id}`, req.body) as any[];
  res.json(r[0] || r);
}));

// DELETE /facilities/:id
router.delete("/facilities/:id", handle(async (req, res) => {
  const u = requireAuth(req);
  const { id } = req.params;
  const fac = await sb("facilities", "GET", `id=eq.${id}&limit=1`) as any[];
  if (!fac.length) return res.status(404).json({ error: "Tidak ditemukan" });
  if (!canAccessVilla(u, fac[0].villa_id)) return res.status(403).json({ error: "Forbidden" });
  await sb("facilities", "DELETE", `id=eq.${id}`);
  res.json({ success: true });
}));

// GET /villas/:villaId/policies
router.get("/villas/:villaId/policies", handle(async (req, res) => {
  requireAuth(req);
  const { villaId } = req.params;
  res.json(await sb("policies", "GET", `villa_id=eq.${villaId}&order=sort_order.asc`));
}));

// POST /villas/:villaId/policies
router.post("/villas/:villaId/policies", handle(async (req, res) => {
  const u = requireAuth(req);
  const { villaId } = req.params;
  if (!canAccessVilla(u, villaId)) return res.status(403).json({ error: "Forbidden" });
  const b = req.body;
  if (!b.content || !b.type) return res.status(400).json({ error: "content dan type wajib diisi" });
  const r = await sb("policies", "POST", "", {
    villa_id: villaId, type: b.type, content: b.content, sort_order: b.sort_order ?? 0,
  }) as any[];
  res.status(201).json(r[0] || r);
}));

// PATCH /policies/:id
router.patch("/policies/:id", handle(async (req, res) => {
  const u = requireAuth(req);
  const { id } = req.params;
  const item = await sb("policies", "GET", `id=eq.${id}&limit=1`) as any[];
  if (!item.length) return res.status(404).json({ error: "Tidak ditemukan" });
  if (!canAccessVilla(u, item[0].villa_id)) return res.status(403).json({ error: "Forbidden" });
  const r = await sb("policies", "PATCH", `id=eq.${id}`, req.body) as any[];
  res.json(r[0] || r);
}));

// DELETE /policies/:id
router.delete("/policies/:id", handle(async (req, res) => {
  const u = requireAuth(req);
  const { id } = req.params;
  const item = await sb("policies", "GET", `id=eq.${id}&limit=1`) as any[];
  if (!item.length) return res.status(404).json({ error: "Tidak ditemukan" });
  if (!canAccessVilla(u, item[0].villa_id)) return res.status(403).json({ error: "Forbidden" });
  await sb("policies", "DELETE", `id=eq.${id}`);
  res.json({ success: true });
}));

// GET /villas/:villaId/contacts
router.get("/villas/:villaId/contacts", handle(async (req, res) => {
  requireAuth(req);
  const { villaId } = req.params;
  res.json(await sb("contacts", "GET", `villa_id=eq.${villaId}`));
}));

// POST /villas/:villaId/contacts
router.post("/villas/:villaId/contacts", handle(async (req, res) => {
  const u = requireAuth(req);
  const { villaId } = req.params;
  if (!canAccessVilla(u, villaId)) return res.status(403).json({ error: "Forbidden" });
  const b = req.body;
  if (!b.value || !b.type) return res.status(400).json({ error: "type dan value wajib diisi" });
  const r = await sb("contacts", "POST", "", {
    villa_id: villaId, type: b.type, label: b.label || null, value: b.value, is_primary: b.is_primary ?? false,
  }) as any[];
  res.status(201).json(r[0] || r);
}));

// DELETE /contacts/:id
router.delete("/contacts/:id", handle(async (req, res) => {
  const u = requireAuth(req);
  const { id } = req.params;
  const item = await sb("contacts", "GET", `id=eq.${id}&limit=1`) as any[];
  if (!item.length) return res.status(404).json({ error: "Tidak ditemukan" });
  if (!canAccessVilla(u, item[0].villa_id)) return res.status(403).json({ error: "Forbidden" });
  await sb("contacts", "DELETE", `id=eq.${id}`);
  res.json({ success: true });
}));

// GET /contacts/global
router.get("/contacts/global", handle(async (req, res) => {
  requireAuth(req);
  res.json(await sb("contacts", "GET", "villa_id=is.null&order=created_at.asc"));
}));

// POST /contacts/global
router.post("/contacts/global", handle(async (req, res) => {
  requireAuth(req);
  const b = req.body;
  if (!b.value || !b.type) return res.status(400).json({ error: "type dan value wajib diisi" });
  const r = await sb("contacts", "POST", "", {
    villa_id: null, type: b.type, label: b.label || null, value: b.value, is_primary: b.is_primary ?? false,
  }) as any[];
  res.status(201).json(r[0] || r);
}));

// PATCH /contacts/global/:id
router.patch("/contacts/global/:id", handle(async (req, res) => {
  requireAuth(req);
  const { id } = req.params;
  const item = await sb("contacts", "GET", `id=eq.${id}&villa_id=is.null&limit=1`) as any[];
  if (!item.length) return res.status(404).json({ error: "Kontak global tidak ditemukan" });
  const b = req.body;
  const r = await sb("contacts", "PATCH", `id=eq.${id}&villa_id=is.null`, {
    type: b.type, label: b.label ?? null, value: b.value, is_primary: b.is_primary ?? false,
  }) as any[];
  res.json(r[0] || r);
}));

// DELETE /contacts/global/:id
router.delete("/contacts/global/:id", handle(async (req, res) => {
  requireAuth(req);
  const { id } = req.params;
  const item = await sb("contacts", "GET", `id=eq.${id}&villa_id=is.null&limit=1`) as any[];
  if (!item.length) return res.status(404).json({ error: "Kontak global tidak ditemukan" });
  await sb("contacts", "DELETE", `id=eq.${id}&villa_id=is.null`);
  res.json({ success: true });
}));

// GET /villas/:villaId/gallery
router.get("/villas/:villaId/gallery", handle(async (req, res) => {
  requireAuth(req);
  const { villaId } = req.params;
  res.json(await sb("gallery", "GET", `villa_id=eq.${villaId}&is_active=eq.true&order=sort_order.asc`));
}));

// DELETE /gallery/:id
router.delete("/gallery/:id", handle(async (req, res) => {
  const u = requireAuth(req);
  const { id } = req.params;
  const item = await sb("gallery", "GET", `id=eq.${id}&limit=1`) as any[];
  if (!item.length) return res.status(404).json({ error: "Tidak ditemukan" });
  if (!canAccessVilla(u, item[0].villa_id)) return res.status(403).json({ error: "Forbidden" });
  await sb("gallery", "PATCH", `id=eq.${id}`, { is_active: false });
  res.json({ success: true });
}));

// POST /upload/github  (multipart/form-data: file, villa_id, alt)
router.post("/upload/github", upload.single("file"), handle(async (req, res) => {
  const u = requireAuth(req);
  const { GITHUB_TOKEN, GITHUB_REPO, GITHUB_BRANCH, GITHUB_IMG_PATH } = getConfig();
  if (!GITHUB_TOKEN) return res.status(500).json({ error: "GitHub belum dikonfigurasi" });

  const file = req.file;
  const villaId = req.body.villa_id;
  const alt = req.body.alt || "";

  if (!file) return res.status(400).json({ error: "File tidak ada" });
  if (!villaId) return res.status(400).json({ error: "villa_id wajib diisi" });
  if (!canAccessVilla(u, villaId)) return res.status(403).json({ error: "Forbidden" });

  const ext = (file.originalname.split(".").pop() || "jpg").toLowerCase();
  const path = `${GITHUB_IMG_PATH}/${villaId}/${Date.now()}.${ext}`;
  const base64 = file.buffer.toString("base64");

  const ghRes = await fetch(`https://api.github.com/repos/${GITHUB_REPO}/contents/${path}`, {
    method: "PUT",
    headers: {
      Authorization: `Bearer ${GITHUB_TOKEN}`,
      "Content-Type": "application/json",
      "User-Agent": "VillaServer/1.0",
    },
    body: JSON.stringify({ message: `Upload ${path}`, content: base64, branch: GITHUB_BRANCH }),
  });

  if (!ghRes.ok) {
    const t = await ghRes.text();
    return res.status(500).json({ error: `GitHub upload gagal: ${t}` });
  }

  const ghData = await ghRes.json() as any;
  const rawUrl = ghData.content.download_url;
  const gallery = await sb("gallery", "POST", "", {
    villa_id: villaId, url: rawUrl, alt, sort_order: 0, is_active: true,
  }) as any[];
  res.status(201).json({ url: rawUrl, gallery: gallery[0] || gallery });
}));

// POST /inquiries (public — from SSR villa page form)
router.post("/inquiries", handle(async (req, res) => {
  const b = req.body;
  if (!b.name || !b.phone) return res.status(400).json({ error: "Nama dan nomor telepon wajib diisi" });
  const r = await sb("inquiries", "POST", "", {
    villa_id:      b.villa_id     || null,
    name:          b.name,
    phone:         b.phone,
    email:         b.email        || null,
    checkin_date:  b.checkin_date || null,
    checkout_date: b.checkout_date|| null,
    num_guests:    b.num_guests   || null,
    message:       b.message      || null,
    status:        "pending",
  }) as any[];
  res.status(201).json(r[0] || r);
}));

// GET /inquiries
router.get("/inquiries", handle(async (req, res) => {
  const u = requireAuth(req);
  let q = "select=*&order=created_at.desc";
  if (u.role !== "superadmin" && u.villa_id) q += `&villa_id=eq.${u.villa_id}`;
  if (req.query.status) q += `&status=eq.${req.query.status}`;
  res.json(await sb("inquiries", "GET", q));
}));

// PATCH /inquiries/:id
router.patch("/inquiries/:id", handle(async (req, res) => {
  const u = requireAuth(req);
  const { id } = req.params;
  const items = await sb("inquiries", "GET", `id=eq.${id}&limit=1`) as any[];
  if (!items.length) return res.status(404).json({ error: "Tidak ditemukan" });
  if (!canAccessVilla(u, items[0].villa_id)) return res.status(403).json({ error: "Forbidden" });
  const b = req.body;
  const upd: Record<string, unknown> = {};
  if ("status" in b) upd.status = b.status;
  if ("message" in b) upd.message = b.message;
  const r = await sb("inquiries", "PATCH", `id=eq.${id}`, upd) as any[];
  res.json(r[0] || r);
}));

// GET /users
router.get("/users", handle(async (req, res) => {
  requireSA(req);
  res.json(await sb("v_users", "GET",
    "select=id,username,email,role,villa_id,status,created_at,approved_at&order=created_at.desc"));
}));

// PATCH /users/:id/approve
router.patch("/users/:id/approve", handle(async (req, res) => {
  const admin = requireSA(req);
  const { id } = req.params;
  const r = await sb("v_users", "PATCH", `id=eq.${id}`, {
    status: "active", approved_at: new Date().toISOString(), approved_by: admin.sub,
  }) as any[];
  res.json(r[0] || r);
}));

// PATCH /users/:id/suspend
router.patch("/users/:id/suspend", handle(async (req, res) => {
  requireSA(req);
  const { id } = req.params;
  const r = await sb("v_users", "PATCH", `id=eq.${id}`, { status: "suspended" }) as any[];
  res.json(r[0] || r);
}));

// PATCH /users/:id/role
router.patch("/users/:id/role", handle(async (req, res) => {
  requireSA(req);
  const { id } = req.params;
  const b = req.body;
  if (!["admin", "superadmin"].includes(b.role)) return res.status(400).json({ error: "Role tidak valid" });
  const r = await sb("v_users", "PATCH", `id=eq.${id}`, { role: b.role, villa_id: b.villa_id || null }) as any[];
  res.json(r[0] || r);
}));

// DELETE /users/:id
router.delete("/users/:id", handle(async (req, res) => {
  requireSA(req);
  const { id } = req.params;
  await sb("v_users", "DELETE", `id=eq.${id}`);
  res.json({ success: true });
}));

export default router;
