// ================================================================
// Villa Management — Cloudflare Worker (single file)
// Deploy: npx wrangler deploy worker.js --name villa-admin
//
// Setup pertama: POST /setup  {"username":"superadmin","password":"xxx"}
// (hanya bisa jika belum ada user sama sekali)
// ================================================================

// ── CONFIG — ganti nilai di bawah sesuai kebutuhan ───────────────
const SUPABASE_URL    = 'https://bgwkwlrkvbspycqsdeif.supabase.co';
const SUPABASE_KEY    = 'eyJhbGciOiJIUzxxxxxxxxxxxc';
const JWT_SECRET      = 'ganti_dengan_string_acak_minimal_32_karakter_disini';
const GITHUB_TOKEN    = 'xxxxxx';
const GITHUB_REPO     = 'SAFELFAR05/Up';
const GITHUB_BRANCH   = 'main';
const GITHUB_IMG_PATH = 'images/villas';
const ALLOWED_ORIGIN  = '*';

// ── CORS ─────────────────────────────────────────────────────────
const CORS = {
  'Access-Control-Allow-Origin':  ALLOWED_ORIGIN,
  'Access-Control-Allow-Methods': 'GET, POST, PATCH, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Max-Age':       '86400',
};

function addCors(response) {
  const r = new Response(response.body, response);
  for (const [k, v] of Object.entries(CORS)) r.headers.set(k, v);
  return r;
}

function json(data, status = 200) {
  return addCors(new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  }));
}

function err(msg, status = 400) {
  return json({ error: msg }, status);
}

// ── JWT ──────────────────────────────────────────────────────────
function b64url(input) {
  const str = typeof input === 'string'
    ? input
    : String.fromCharCode(...new Uint8Array(input));
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function b64decode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return Uint8Array.from(atob(str), c => c.charCodeAt(0));
}

async function signJWT(payload) {
  const enc    = new TextEncoder();
  const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body   = b64url(JSON.stringify({ ...payload, iat: Math.floor(Date.now() / 1000) }));
  const data   = `${header}.${body}`;
  const key    = await crypto.subtle.importKey(
    'raw', enc.encode(JWT_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
  );
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(data));
  return `${data}.${b64url(sig)}`;
}

async function verifyJWT(token) {
  try {
    const [header, body, sig] = token.split('.');
    if (!header || !body || !sig) return null;
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw', enc.encode(JWT_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify'],
    );
    const valid = await crypto.subtle.verify('HMAC', key, b64decode(sig), enc.encode(`${header}.${body}`));
    if (!valid) return null;
    const payload = JSON.parse(atob(body.replace(/-/g, '+').replace(/_/g, '/')));
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch { return null; }
}

// ── Password (PBKDF2 + SHA-256) ───────────────────────────────────
async function hashPassword(password) {
  const enc     = new TextEncoder();
  const salt    = crypto.getRandomValues(new Uint8Array(16));
  const saltHex = [...salt].map(b => b.toString(16).padStart(2, '0')).join('');
  const km      = await crypto.subtle.importKey('raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveBits']);
  const bits    = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, km, 256);
  const hash    = [...new Uint8Array(bits)].map(b => b.toString(16).padStart(2, '0')).join('');
  return `${saltHex}:${hash}`;
}

async function verifyPassword(password, stored) {
  const [saltHex, storedHash] = stored.split(':');
  const salt = new Uint8Array(saltHex.match(/.{2}/g).map(h => parseInt(h, 16)));
  const enc  = new TextEncoder();
  const km   = await crypto.subtle.importKey('raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, km, 256);
  const hash = [...new Uint8Array(bits)].map(b => b.toString(16).padStart(2, '0')).join('');
  return hash === storedHash;
}

// ── Supabase REST helper ──────────────────────────────────────────
async function sb(table, method = 'GET', query = '', body = null) {
  const url     = `${SUPABASE_URL}/rest/v1/${table}${query ? '?' + query : ''}`;
  const headers = {
    apikey:         SUPABASE_KEY,
    Authorization:  `Bearer ${SUPABASE_KEY}`,
    'Content-Type': 'application/json',
  };
  if (method !== 'DELETE') headers['Prefer'] = 'return=representation';
  const opts = { method, headers };
  if (body) opts.body = JSON.stringify(body);
  const res  = await fetch(url, opts);
  if (method === 'DELETE' && res.status < 300) return [];
  const text = await res.text();
  if (!res.ok) throw new Error(`Supabase ${method} ${table} ${res.status}: ${text}`);
  return text ? JSON.parse(text) : [];
}

// ── Auth helpers ──────────────────────────────────────────────────
async function getUser(request) {
  const auth = request.headers.get('Authorization') || '';
  if (!auth.startsWith('Bearer ')) return null;
  return verifyJWT(auth.slice(7));
}

async function requireAuth(request) {
  const u = await getUser(request);
  if (!u) throw { status: 401, message: 'Unauthorized' };
  return u;
}

async function requireSA(request) {
  const u = await requireAuth(request);
  if (u.role !== 'superadmin') throw { status: 403, message: 'Superadmin only' };
  return u;
}

function canAccessVilla(user, villaId) {
  return user.role === 'superadmin' || user.villa_id === villaId;
}

// ── Route handlers ────────────────────────────────────────────────

// POST /setup
async function setup(request) {
  const count = await sb('v_users', 'GET', 'select=id&limit=1');
  if (count.length > 0) return err('Setup sudah dilakukan. Gunakan /auth/register.', 403);
  const { username, password } = await request.json();
  if (!username || !password) return err('username dan password wajib diisi');
  const password_hash = await hashPassword(password);
  const user = await sb('v_users', 'POST', '', {
    username, password_hash, role: 'superadmin', status: 'active',
  });
  return json({ message: 'Superadmin berhasil dibuat', user: { id: user[0]?.id, username } }, 201);
}

// POST /auth/login
async function login(request) {
  const { username, password } = await request.json();
  if (!username || !password) return err('username dan password wajib diisi');
  const rows = await sb('v_users', 'GET', `username=eq.${encodeURIComponent(username)}&select=*&limit=1`);
  const user = rows[0];
  if (!user) return err('Username atau password salah', 401);
  if (user.status === 'pending')   return err('Akun menunggu persetujuan superadmin', 403);
  if (user.status === 'suspended') return err('Akun disuspend', 403);
  if (!await verifyPassword(password, user.password_hash)) return err('Username atau password salah', 401);
  const exp   = Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 7;
  const token = await signJWT({ sub: user.id, username: user.username, role: user.role, villa_id: user.villa_id, exp });
  return json({ token, user: { id: user.id, username: user.username, role: user.role, villa_id: user.villa_id } });
}

// POST /auth/register
async function register(request) {
  const { username, password, email, villa_id } = await request.json();
  if (!username || !password) return err('username dan password wajib diisi');
  if (password.length < 6) return err('Password minimal 6 karakter');
  const existing = await sb('v_users', 'GET', `username=eq.${encodeURIComponent(username)}&limit=1`);
  if (existing.length) return err('Username sudah dipakai', 409);
  const password_hash = await hashPassword(password);
  await sb('v_users', 'POST', '', {
    username, password_hash,
    email:    email    || null,
    villa_id: villa_id || null,
    role: 'admin', status: 'pending',
  });
  return json({ message: 'Pendaftaran berhasil. Tunggu persetujuan superadmin.' }, 201);
}

// GET /auth/me
async function me(request) {
  const u    = await requireAuth(request);
  const rows = await sb('v_users', 'GET', `id=eq.${u.sub}&select=id,username,email,role,villa_id,status,created_at&limit=1`);
  return json(rows[0] || null);
}

// ── Villas ────────────────────────────────────────────────────────
async function getVillas(request) {
  const u = await requireAuth(request);
  let q = 'select=*&order=created_at.asc';
  if (u.role !== 'superadmin' && u.villa_id) q += `&id=eq.${u.villa_id}`;
  return json(await sb('villa_info', 'GET', q));
}

async function createVilla(request) {
  const u = await requireAuth(request);
  const b = await request.json();
  if (!b.name || !b.slug) return err('name dan slug wajib diisi');
  const ex = await sb('villa_info', 'GET', `slug=eq.${encodeURIComponent(b.slug)}&limit=1`);
  if (ex.length) return err('Slug sudah dipakai', 409);
  const r = await sb('villa_info', 'POST', '', {
    name: b.name, slug: b.slug, tagline: b.tagline || null,
    description: b.description || null, address: b.address || null,
    city: b.city || null, province: b.province || null,
    max_guests: b.max_guests || null, max_guests_note: b.max_guests_note || null,
    extra_bed_price: b.extra_bed_price || null, extra_bed_note: b.extra_bed_note || null,
    checkin_time: b.checkin_time || '14.00 WIB', checkout_time: b.checkout_time || '12.00 WIB',
  });
  const villa = r[0] || r;
  // Jika admin biasa, otomatis assign mereka ke villa yang baru dibuat
  if (u.role === 'admin') {
    await sb('v_users', 'PATCH', `id=eq.${u.id}`, { villa_id: villa.id });
  }
  return json(villa, 201);
}

async function deleteVilla(request, id) {
  await requireSA(request);
  if (!id) return err('ID villa wajib diisi');
  const ex = await sb('villa_info', 'GET', `id=eq.${id}&select=id&limit=1`);
  if (!ex.length) return err('Villa tidak ditemukan', 404);
  // Hapus semua data terkait dulu, baru villa-nya
  await sb('facilities', 'DELETE', `villa_id=eq.${id}`);
  await sb('policies',   'DELETE', `villa_id=eq.${id}`);
  await sb('contacts',   'DELETE', `villa_id=eq.${id}`);
  await sb('gallery',    'DELETE', `villa_id=eq.${id}`);
  await sb('inquiries',  'DELETE', `villa_id=eq.${id}`);
  await sb('villa_info', 'DELETE', `id=eq.${id}`);
  return json({ message: 'Villa berhasil dihapus' });
}

async function getVilla(request, id) {
  const u = await requireAuth(request);
  if (!canAccessVilla(u, id)) return err('Forbidden', 403);
  const r = await sb('villa_info', 'GET', `id=eq.${id}&select=*&limit=1`);
  if (!r.length) return err('Villa tidak ditemukan', 404);
  return json(r[0]);
}

async function updateVilla(request, id) {
  const u = await requireAuth(request);
  if (!canAccessVilla(u, id)) return err('Forbidden', 403);
  const b = await request.json();
  const allowed = ['name','slug','tagline','description','address','city','province',
    'max_guests','max_guests_note','extra_bed_price','extra_bed_note','checkin_time','checkout_time'];
  const upd = { updated_at: new Date().toISOString() };
  for (const k of allowed) if (k in b) upd[k] = b[k];
  const r = await sb('villa_info', 'PATCH', `id=eq.${id}`, upd);
  return json(r[0] || r);
}

// ── Facilities ────────────────────────────────────────────────────
async function getFacilities(request, villaId) {
  await requireAuth(request);
  return json(await sb('facilities', 'GET', `villa_id=eq.${villaId}&order=sort_order.asc`));
}

async function createFacility(request, villaId) {
  const u = await requireAuth(request);
  if (!canAccessVilla(u, villaId)) return err('Forbidden', 403);
  const b = await request.json();
  if (!b.name) return err('name wajib diisi');
  const r = await sb('facilities', 'POST', '', {
    villa_id: villaId, icon: b.icon || 'star', name: b.name,
    description: b.description || null, sort_order: b.sort_order ?? 0, is_active: true,
  });
  return json(r[0] || r, 201);
}

async function updateFacility(request, id) {
  const u   = await requireAuth(request);
  const fac = await sb('facilities', 'GET', `id=eq.${id}&limit=1`);
  if (!fac.length) return err('Tidak ditemukan', 404);
  if (!canAccessVilla(u, fac[0].villa_id)) return err('Forbidden', 403);
  const r = await sb('facilities', 'PATCH', `id=eq.${id}`, await request.json());
  return json(r[0] || r);
}

async function deleteFacility(request, id) {
  const u   = await requireAuth(request);
  const fac = await sb('facilities', 'GET', `id=eq.${id}&limit=1`);
  if (!fac.length) return err('Tidak ditemukan', 404);
  if (!canAccessVilla(u, fac[0].villa_id)) return err('Forbidden', 403);
  await sb('facilities', 'DELETE', `id=eq.${id}`);
  return json({ success: true });
}

// ── Policies ──────────────────────────────────────────────────────
async function getPolicies(request, villaId) {
  await requireAuth(request);
  return json(await sb('policies', 'GET', `villa_id=eq.${villaId}&order=sort_order.asc`));
}

async function createPolicy(request, villaId) {
  const u = await requireAuth(request);
  if (!canAccessVilla(u, villaId)) return err('Forbidden', 403);
  const b = await request.json();
  if (!b.content || !b.type) return err('content dan type wajib diisi');
  const r = await sb('policies', 'POST', '', {
    villa_id: villaId, type: b.type, content: b.content, sort_order: b.sort_order ?? 0,
  });
  return json(r[0] || r, 201);
}

async function updatePolicy(request, id) {
  const u    = await requireAuth(request);
  const item = await sb('policies', 'GET', `id=eq.${id}&limit=1`);
  if (!item.length) return err('Tidak ditemukan', 404);
  if (!canAccessVilla(u, item[0].villa_id)) return err('Forbidden', 403);
  const r = await sb('policies', 'PATCH', `id=eq.${id}`, await request.json());
  return json(r[0] || r);
}

async function deletePolicy(request, id) {
  const u    = await requireAuth(request);
  const item = await sb('policies', 'GET', `id=eq.${id}&limit=1`);
  if (!item.length) return err('Tidak ditemukan', 404);
  if (!canAccessVilla(u, item[0].villa_id)) return err('Forbidden', 403);
  await sb('policies', 'DELETE', `id=eq.${id}`);
  return json({ success: true });
}

// ── Contacts (per-villa) ──────────────────────────────────────────
async function getContacts(request, villaId) {
  await requireAuth(request);
  return json(await sb('contacts', 'GET', `villa_id=eq.${villaId}`));
}

async function createContact(request, villaId) {
  const u = await requireAuth(request);
  if (!canAccessVilla(u, villaId)) return err('Forbidden', 403);
  const b = await request.json();
  if (!b.value || !b.type) return err('type dan value wajib diisi');
  const r = await sb('contacts', 'POST', '', {
    villa_id: villaId, type: b.type, label: b.label || null,
    value: b.value, is_primary: b.is_primary ?? false,
  });
  return json(r[0] || r, 201);
}

async function deleteContact(request, id) {
  const u    = await requireAuth(request);
  const item = await sb('contacts', 'GET', `id=eq.${id}&limit=1`);
  if (!item.length) return err('Tidak ditemukan', 404);
  if (!canAccessVilla(u, item[0].villa_id)) return err('Forbidden', 403);
  await sb('contacts', 'DELETE', `id=eq.${id}`);
  return json({ success: true });
}

// ── Contacts Global (villa_id = null) ────────────────────────────
async function getGlobalContacts(request) {
  await requireAuth(request);
  return json(await sb('contacts', 'GET', 'villa_id=is.null&order=created_at.asc'));
}

async function createGlobalContact(request) {
  await requireAuth(request);
  const b = await request.json();
  if (!b.value || !b.type) return err('type dan value wajib diisi');
  const r = await sb('contacts', 'POST', '', {
    villa_id:   null,
    type:       b.type,
    label:      b.label || null,
    value:      b.value,
    is_primary: b.is_primary ?? false,
  });
  return json(r[0] || r, 201);
}

async function updateGlobalContact(request, id) {
  await requireAuth(request);
  const item = await sb('contacts', 'GET', `id=eq.${id}&villa_id=is.null&limit=1`);
  if (!item.length) return err('Kontak global tidak ditemukan', 404);
  const b = await request.json();
  const r = await sb('contacts', 'PATCH', `id=eq.${id}&villa_id=is.null`, {
    type:       b.type,
    label:      b.label ?? null,
    value:      b.value,
    is_primary: b.is_primary ?? false,
  });
  return json(r[0] || r);
}

async function deleteGlobalContact(request, id) {
  await requireAuth(request);
  const item = await sb('contacts', 'GET', `id=eq.${id}&villa_id=is.null&limit=1`);
  if (!item.length) return err('Kontak global tidak ditemukan', 404);
  await sb('contacts', 'DELETE', `id=eq.${id}&villa_id=is.null`);
  return json({ success: true });
}

// ── Gallery ───────────────────────────────────────────────────────
async function getGallery(request, villaId) {
  await requireAuth(request);
  return json(await sb('gallery', 'GET', `villa_id=eq.${villaId}&is_active=eq.true&order=sort_order.asc`));
}

async function deleteGallery(request, id) {
  const u    = await requireAuth(request);
  const item = await sb('gallery', 'GET', `id=eq.${id}&limit=1`);
  if (!item.length) return err('Tidak ditemukan', 404);
  if (!canAccessVilla(u, item[0].villa_id)) return err('Forbidden', 403);
  await sb('gallery', 'PATCH', `id=eq.${id}`, { is_active: false });
  return json({ success: true });
}

// POST /upload/github  (multipart/form-data: file, villa_id, alt)
async function uploadGithub(request) {
  const u = await requireAuth(request);
  if (!GITHUB_TOKEN || GITHUB_TOKEN.startsWith('ganti_')) return err('GitHub belum dikonfigurasi', 500);

  const form    = await request.formData();
  const file    = form.get('file');
  const villaId = form.get('villa_id');
  const alt     = form.get('alt') || '';

  if (!file)    return err('File tidak ada');
  if (!villaId) return err('villa_id wajib diisi');
  if (!canAccessVilla(u, villaId)) return err('Forbidden', 403);

  const ext    = (file.name.split('.').pop() || 'jpg').toLowerCase();
  const path   = `${GITHUB_IMG_PATH}/${villaId}/${Date.now()}.${ext}`;
  const ab     = await file.arrayBuffer();
  const bytes  = new Uint8Array(ab);
  let base64 = '';
  const chunk = 8192;
  for (let i = 0; i < bytes.length; i += chunk) {
    base64 += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  base64 = btoa(base64);

  const ghRes = await fetch(`https://api.github.com/repos/${GITHUB_REPO}/contents/${path}`, {
    method: 'PUT',
    headers: {
      Authorization:  `Bearer ${GITHUB_TOKEN}`,
      'Content-Type': 'application/json',
      'User-Agent':   'VillaWorker/1.0',
    },
    body: JSON.stringify({ message: `Upload ${path}`, content: base64, branch: GITHUB_BRANCH }),
  });

  if (!ghRes.ok) {
    const t = await ghRes.text();
    return err(`GitHub upload gagal: ${t}`, 500);
  }

  const rawUrl  = (await ghRes.json()).content.download_url;
  const gallery = await sb('gallery', 'POST', '', {
    villa_id: villaId, url: rawUrl, alt, sort_order: 0, is_active: true,
  });
  return json({ url: rawUrl, gallery: gallery[0] || gallery }, 201);
}

// ── Inquiries ─────────────────────────────────────────────────────
async function getInquiries(request) {
  const u      = await requireAuth(request);
  const params = new URL(request.url).searchParams;
  let q = 'select=*&order=created_at.desc';
  if (u.role !== 'superadmin' && u.villa_id) q += `&villa_id=eq.${u.villa_id}`;
  if (params.get('status')) q += `&status=eq.${params.get('status')}`;
  return json(await sb('inquiries', 'GET', q));
}

async function updateInquiry(request, id) {
  const u     = await requireAuth(request);
  const items = await sb('inquiries', 'GET', `id=eq.${id}&limit=1`);
  if (!items.length) return err('Tidak ditemukan', 404);
  if (!canAccessVilla(u, items[0].villa_id)) return err('Forbidden', 403);
  const b   = await request.json();
  const upd = {};
  if ('status'  in b) upd.status  = b.status;
  if ('message' in b) upd.message = b.message;
  const r = await sb('inquiries', 'PATCH', `id=eq.${id}`, upd);
  return json(r[0] || r);
}

// ── Users (superadmin) ────────────────────────────────────────────
async function getUsers(request) {
  await requireSA(request);
  return json(await sb('v_users', 'GET',
    'select=id,username,email,role,villa_id,status,created_at,approved_at&order=created_at.desc'));
}

async function approveUser(request, id) {
  const admin = await requireSA(request);
  const r = await sb('v_users', 'PATCH', `id=eq.${id}`, {
    status: 'active', approved_at: new Date().toISOString(), approved_by: admin.sub,
  });
  return json(r[0] || r);
}

async function suspendUser(request, id) {
  await requireSA(request);
  const r = await sb('v_users', 'PATCH', `id=eq.${id}`, { status: 'suspended' });
  return json(r[0] || r);
}

async function updateUserRole(request, id) {
  await requireSA(request);
  const b = await request.json();
  if (!['admin', 'superadmin'].includes(b.role)) return err('Role tidak valid');
  const r = await sb('v_users', 'PATCH', `id=eq.${id}`, { role: b.role, villa_id: b.villa_id || null });
  return json(r[0] || r);
}

async function deleteUser(request, id) {
  await requireSA(request);
  await sb('v_users', 'DELETE', `id=eq.${id}`);
  return json({ success: true });
}

// ── Router ────────────────────────────────────────────────────────
const ROUTES = [
  ['POST',   /^\/setup$/,                           r     => setup(r)],
  ['POST',   /^\/auth\/login$/,                     r     => login(r)],
  ['POST',   /^\/auth\/register$/,                  r     => register(r)],
  ['GET',    /^\/auth\/me$/,                        r     => me(r)],

  ['GET',    /^\/villas$/,                          r     => getVillas(r)],
  ['POST',   /^\/villas$/,                          r     => createVilla(r)],
  ['GET',    /^\/villas\/([^/]+)$/,                 (r,m) => getVilla(r, m[1])],
  ['PATCH',  /^\/villas\/([^/]+)$/,                 (r,m) => updateVilla(r, m[1])],
  ['DELETE', /^\/villas\/([^/]+)$/,                 (r,m) => deleteVilla(r, m[1])],

  ['GET',    /^\/villas\/([^/]+)\/facilities$/,     (r,m) => getFacilities(r, m[1])],
  ['POST',   /^\/villas\/([^/]+)\/facilities$/,     (r,m) => createFacility(r, m[1])],
  ['PATCH',  /^\/facilities\/([^/]+)$/,             (r,m) => updateFacility(r, m[1])],
  ['DELETE', /^\/facilities\/([^/]+)$/,             (r,m) => deleteFacility(r, m[1])],

  ['GET',    /^\/villas\/([^/]+)\/policies$/,       (r,m) => getPolicies(r, m[1])],
  ['POST',   /^\/villas\/([^/]+)\/policies$/,       (r,m) => createPolicy(r, m[1])],
  ['PATCH',  /^\/policies\/([^/]+)$/,               (r,m) => updatePolicy(r, m[1])],
  ['DELETE', /^\/policies\/([^/]+)$/,               (r,m) => deletePolicy(r, m[1])],

  ['GET',    /^\/villas\/([^/]+)\/contacts$/,       (r,m) => getContacts(r, m[1])],
  ['POST',   /^\/villas\/([^/]+)\/contacts$/,       (r,m) => createContact(r, m[1])],
  ['DELETE', /^\/contacts\/([^/]+)$/,               (r,m) => deleteContact(r, m[1])],

  // ── Kontak Global (villa_id = null) — butuh login admin ──────────
  ['GET',    /^\/contacts\/global$/,                r     => getGlobalContacts(r)],
  ['POST',   /^\/contacts\/global$/,                r     => createGlobalContact(r)],
  ['PATCH',  /^\/contacts\/global\/([^/]+)$/,       (r,m) => updateGlobalContact(r, m[1])],
  ['DELETE', /^\/contacts\/global\/([^/]+)$/,       (r,m) => deleteGlobalContact(r, m[1])],

  ['GET',    /^\/villas\/([^/]+)\/gallery$/,        (r,m) => getGallery(r, m[1])],
  ['DELETE', /^\/gallery\/([^/]+)$/,                (r,m) => deleteGallery(r, m[1])],

  ['POST',   /^\/upload\/github$/,                  r     => uploadGithub(r)],

  ['GET',    /^\/inquiries$/,                       r     => getInquiries(r)],
  ['PATCH',  /^\/inquiries\/([^/]+)$/,              (r,m) => updateInquiry(r, m[1])],

  ['GET',    /^\/users$/,                           r     => getUsers(r)],
  ['PATCH',  /^\/users\/([^/]+)\/approve$/,         (r,m) => approveUser(r, m[1])],
  ['PATCH',  /^\/users\/([^/]+)\/suspend$/,         (r,m) => suspendUser(r, m[1])],
  ['PATCH',  /^\/users\/([^/]+)\/role$/,            (r,m) => updateUserRole(r, m[1])],
  ['DELETE', /^\/users\/([^/]+)$/,                  (r,m) => deleteUser(r, m[1])],
];

export default {
  async fetch(request) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS });
    }

    const path   = new URL(request.url).pathname.replace(/\/$/, '') || '/';
    const method = request.method;

    try {
      for (const [rm, rp, handler] of ROUTES) {
        if (rm !== method) continue;
        const m = path.match(rp);
        if (m) return await handler(request, m);
      }
      return json({ error: 'Not found', path }, 404);
    } catch (e) {
      if (e.status) return json({ error: e.message }, e.status);
      console.error(e);
      return json({ error: 'Internal server error' }, 500);
    }
  },
};
