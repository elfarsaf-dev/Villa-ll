/**
 * Villa Tawangmangu — Cloudflare Worker
 * Handles: SSR public pages (/ and /villa/:slug) + full REST API + image upload
 *
 * Deploy:
 *   npx wrangler secret put SUPABASE_URL
 *   npx wrangler secret put SUPABASE_KEY
 *   npx wrangler secret put JWT_SECRET
 *   npx wrangler secret put GITHUB_TOKEN
 *   npx wrangler secret put GITHUB_REPO
 *   npx wrangler deploy worker.js --name villa-admin
 */

// ── Supabase REST helper ──────────────────────────────────────────────────────
async function sb(env, table, method = "GET", query = "", body = null) {
  const url = `${env.SUPABASE_URL}/rest/v1/${table}${query ? "?" + query : ""}`;
  const headers = {
    apikey: env.SUPABASE_KEY,
    Authorization: `Bearer ${env.SUPABASE_KEY}`,
    "Content-Type": "application/json",
  };
  if (method !== "DELETE") headers["Prefer"] = "return=representation";
  const opts = { method, headers };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(url, opts);
  if (method === "DELETE" && res.status < 300) return [];
  const text = await res.text();
  if (!res.ok) throw new Error(`Supabase ${method} ${table} ${res.status}: ${text}`);
  return text ? JSON.parse(text) : [];
}

// ── JWT (Web Crypto — available in CF Workers) ────────────────────────────────
function b64url(input) {
  const bytes = typeof input === "string" ? new TextEncoder().encode(input) : input;
  let str = "";
  for (const b of bytes) str += String.fromCharCode(b);
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

async function signJWT(payload, secret) {
  const header = b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body = b64url(JSON.stringify({ ...payload, iat: Math.floor(Date.now() / 1000) }));
  const data = `${header}.${body}`;
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  return `${data}.${b64url(new Uint8Array(sig))}`;
}

async function verifyJWT(token, secret) {
  try {
    const [header, body, sig] = token.split(".");
    if (!header || !body || !sig) return null;
    const data = `${header}.${body}`;
    const key = await crypto.subtle.importKey(
      "raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]
    );
    const sigBytes = Uint8Array.from(atob(sig.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
    const ok = await crypto.subtle.verify("HMAC", key, sigBytes, new TextEncoder().encode(data));
    if (!ok) return null;
    const payload = JSON.parse(atob(body.replace(/-/g, "+").replace(/_/g, "/")));
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch { return null; }
}

// ── Password (PBKDF2 via Web Crypto) ─────────────────────────────────────────
async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const saltHex = Array.from(salt).map(b => b.toString(16).padStart(2, "0")).join("");
  const keyMaterial = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" }, keyMaterial, 256);
  const hash = Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2, "0")).join("");
  return `${saltHex}:${hash}`;
}

async function verifyPassword(password, stored) {
  const [saltHex, storedHash] = stored.split(":");
  const salt = Uint8Array.from(saltHex.match(/.{2}/g).map(b => parseInt(b, 16)));
  const keyMaterial = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" }, keyMaterial, 256);
  const hash = Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2, "0")).join("");
  return hash === storedHash;
}

// ── Auth helpers ──────────────────────────────────────────────────────────────
async function getUser(req, env) {
  const auth = req.headers.get("Authorization") || "";
  if (!auth.startsWith("Bearer ")) return null;
  return await verifyJWT(auth.slice(7), env.JWT_SECRET);
}

async function requireAuth(req, env) {
  const u = await getUser(req, env);
  if (!u) throw { status: 401, message: "Unauthorized" };
  return u;
}

async function requireSA(req, env) {
  const u = await requireAuth(req, env);
  if (u.role !== "superadmin") throw { status: 403, message: "Superadmin only" };
  return u;
}

function canAccessVilla(user, villaId) {
  return user.role === "superadmin" || user.villa_id === villaId;
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function html(content, status = 200) {
  return new Response(content, {
    status,
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}

function esc(s) {
  if (s == null) return "";
  return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}

// ── SSR: Shared head ──────────────────────────────────────────────────────────
const COMMON_HEAD = `
  <meta charset="utf-8"/>
  <meta content="width=device-width, initial-scale=1.0" name="viewport"/>
  <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🏡</text></svg>"/>
  <script src="https://cdn.tailwindcss.com?plugins=forms,container-queries"></script>
  <link href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap" rel="stylesheet"/>
  <link href="https://fonts.googleapis.com/css2?family=Noto+Serif:ital,wght@0,400;0,700;1,400&family=Plus+Jakarta+Sans:wght@400;500;600&display=swap" rel="stylesheet"/>
`;

const TAILWIND_COLORS = `tailwind.config={darkMode:"class",theme:{extend:{colors:{"primary":"#1e3a2f","primary-container":"#2d4f3f","on-primary":"#ffffff","on-primary-container":"#a8c5b5","secondary":"#5c6b5e","secondary-container":"#dde8df","on-secondary":"#ffffff","background":"#f8faf8","surface":"#f8faf8","surface-container-lowest":"#ffffff","surface-container-low":"#f2f5f2","surface-container":"#ecefec","surface-container-high":"#e6eae6","surface-container-highest":"#e0e4e0","on-surface":"#191d1a","on-surface-variant":"#404944","outline":"#707973","outline-variant":"#bfc9c1"},borderRadius:{"DEFAULT":"0.125rem","lg":"0.375rem","xl":"0.5rem","2xl":"0.75rem","full":"9999px"},fontFamily:{"serif":["Noto Serif","Georgia","serif"],"sans":["Plus Jakarta Sans","sans-serif"]}}}}`;

const WA_SVG = `<svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor"><path d="M17.472 14.382c-.297-.149-1.758-.867-2.03-.967-.273-.099-.471-.148-.67.15-.197.297-.767.966-.94 1.164-.173.199-.347.223-.644.075-.297-.15-1.255-.463-2.39-1.475-.883-.788-1.48-1.761-1.653-2.059-.173-.297-.018-.458.13-.606.134-.133.298-.347.446-.52.149-.174.198-.298.298-.497.099-.198.05-.371-.025-.52-.075-.149-.669-1.612-.916-2.207-.242-.579-.487-.5-.669-.51-.173-.008-.371-.01-.57-.01-.198 0-.52.074-.792.372-.272.297-1.04 1.016-1.04 2.479 0 1.462 1.065 2.875 1.213 3.074.149.198 2.096 3.2 5.077 4.487.709.306 1.262.489 1.694.625.712.227 1.36.195 1.871.118.571-.085 1.758-.719 2.006-1.413.248-.694.248-1.289.173-1.413-.074-.124-.272-.198-.57-.347m-5.421 7.403h-.004a9.87 9.87 0 01-5.031-1.378l-.361-.214-3.741.982.998-3.648-.235-.374a9.86 9.86 0 01-1.51-5.26c.001-5.45 4.436-9.884 9.888-9.884 2.64 0 5.122 1.03 6.988 2.898a9.825 9.825 0 012.893 6.994c-.003 5.45-4.437 9.884-9.885 9.884m8.413-18.297A11.815 11.815 0 0012.05 0C5.495 0 .16 5.335.157 11.892c0 2.096.547 4.142 1.588 5.945L.057 24l6.305-1.654a11.882 11.882 0 005.683 1.448h.005c6.554 0 11.89-5.335 11.893-11.893a11.821 11.821 0 00-3.48-8.413z"/></svg>`;

function waHref(contact) {
  const num = contact?.value?.replace(/\D/g, "");
  return num ? `https://wa.me/62${num.replace(/^0/, "")}` : "#";
}

// ── SSR: Index page ───────────────────────────────────────────────────────────
function renderIndexPage(villas, coverMap, contactMap, globalWa) {
  const year = new Date().getFullYear();

  function villaCard(v) {
    const cover = coverMap[v.id];
    const waContact = contactMap[v.id] || globalWa;
    const location = [v.city, v.province].filter(Boolean).join(", ");
    const wa = waHref(waContact);
    const waNum = waContact?.value?.replace(/\D/g, "");
    const waLink = waNum ? `https://wa.me/62${waNum.replace(/^0/, "")}` : null;
    const href = v.slug ? `/villa/${encodeURIComponent(v.slug)}` : `/villa/?id=${v.id}`;
    return `<div class="villa-card">
      <a href="${href}" class="block overflow-hidden" style="height:220px;">
        ${cover ? `<img src="${esc(cover.url)}" alt="${esc(cover.alt || v.name)}" class="w-full h-full object-cover"/>` : `<div class="w-full h-full bg-surface-container-highest flex items-center justify-center"><span class="material-symbols-outlined text-outline" style="font-size:56px;">villa</span></div>`}
      </a>
      <div class="p-5">
        <div class="flex items-start justify-between gap-2 mb-2">
          <h3 class="font-serif text-xl text-primary leading-snug">${esc(v.name)}</h3>
          ${location ? `<span class="text-[9px] tracking-widest uppercase text-secondary bg-surface-container px-2 py-1 rounded-full whitespace-nowrap">${esc(location)}</span>` : ""}
        </div>
        ${v.tagline ? `<p class="text-[0.8125rem] text-on-surface-variant leading-relaxed mb-1">${esc(v.tagline)}</p>` : ""}
        <div class="flex flex-wrap gap-3 text-[0.75rem] text-secondary mt-2 mb-4">
          ${v.max_guests ? `<span class="flex items-center gap-1"><span class="material-symbols-outlined" style="font-size:14px;">groups</span>Maks. ${esc(v.max_guests)} orang</span>` : ""}
          ${v.checkin_time ? `<span class="flex items-center gap-1"><span class="material-symbols-outlined" style="font-size:14px;">schedule</span>CI ${esc(v.checkin_time)}</span>` : ""}
        </div>
        <div class="flex gap-2">
          <a href="${href}" class="flex-1 text-center py-2.5 rounded-xl text-[0.8rem] font-semibold text-white" style="background:#1e3a2f;letter-spacing:0.05em;">Lihat Detail</a>
          ${waLink ? `<a href="${waLink}" target="_blank" rel="noopener" class="flex items-center gap-1.5 px-3.5 py-2.5 rounded-xl text-[0.8rem] font-semibold" style="background:#dcfce7;color:#166534;"><svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M17.472 14.382c-.297-.149-1.758-.867-2.03-.967-.273-.099-.471-.148-.67.15-.197.297-.767.966-.94 1.164-.173.199-.347.223-.644.075-.297-.15-1.255-.463-2.39-1.475-.883-.788-1.48-1.761-1.653-2.059-.173-.297-.018-.458.13-.606.134-.133.298-.347.446-.52.149-.174.198-.298.298-.497.099-.198.05-.371-.025-.52-.075-.149-.669-1.612-.916-2.207-.242-.579-.487-.5-.669-.51-.173-.008-.371-.01-.57-.01-.198 0-.52.074-.792.372-.272.297-1.04 1.016-1.04 2.479 0 1.462 1.065 2.875 1.213 3.074.149.198 2.096 3.2 5.077 4.487.709.306 1.262.489 1.694.625.712.227 1.36.195 1.871.118.571-.085 1.758-.719 2.006-1.413.248-.694.248-1.289.173-1.413-.074-.124-.272-.198-.57-.347m-5.421 7.403h-.004a9.87 9.87 0 01-5.031-1.378l-.361-.214-3.741.982.998-3.648-.235-.374a9.86 9.86 0 01-1.51-5.26c.001-5.45 4.436-9.884 9.888-9.884 2.64 0 5.122 1.03 6.988 2.898a9.825 9.825 0 012.893 6.994c-.003 5.45-4.437 9.884-9.885 9.884m8.413-18.297A11.815 11.815 0 0012.05 0C5.495 0 .16 5.335.157 11.892c0 2.096.547 4.142 1.588 5.945L.057 24l6.305-1.654a11.882 11.882 0 005.683 1.448h.005c6.554 0 11.89-5.335 11.893-11.893a11.821 11.821 0 00-3.48-8.413z"/></svg>WA</a>` : ""}
        </div>
      </div>
    </div>`;
  }

  const cards = villas.length
    ? villas.map(villaCard).join("")
    : `<div class="md:col-span-3 text-center py-16 text-on-surface-variant"><span class="material-symbols-outlined text-5xl mb-4 block opacity-30">villa</span><p>Belum ada villa terdaftar.</p></div>`;

  return `<!DOCTYPE html>
<html class="light" lang="id">
<head>
  <title>Villa Tawangmangu — Villa Eksklusif Sekipan Tawangmangu</title>
  <meta name="description" content="Villa Tawangmangu — Sewa villa eksklusif di Sekipan, Tawangmangu, Karanganyar. Kolam renang privat, pemandangan pegunungan, cocok untuk keluarga, reuni &amp; gathering besar."/>
  <meta name="keywords" content="villa tawangmangu, sewa villa tawangmangu, villa sekipan, villa karanganyar, villa kolam renang tawangmangu"/>
  <meta property="og:title" content="Villa Tawangmangu — Villa Eksklusif Sekipan"/>
  <meta property="og:description" content="Sewa villa eksklusif di Sekipan, Tawangmangu."/>
  <meta property="og:type" content="website"/>
  <meta name="robots" content="index, follow"/>
  ${COMMON_HEAD}
  <script>${TAILWIND_COLORS}</script>
  <style>
    .material-symbols-outlined{font-variation-settings:'FILL' 0,'wght' 300,'GRAD' 0,'opsz' 24;font-size:24px}
    body{background:#f8faf8;color:#191d1a;-webkit-font-smoothing:antialiased;font-family:"Plus Jakarta Sans",sans-serif}
    html{scroll-behavior:smooth}
    .font-serif{font-family:"Noto Serif",Georgia,serif}
    .villa-card{background:#fff;border-radius:16px;overflow:hidden;border:1px solid #e0e4e0;transition:transform 0.25s ease,box-shadow 0.25s ease}
    .villa-card:hover{transform:translateY(-4px);box-shadow:0 12px 40px rgba(0,0,0,.10)}
    .villa-card img{transition:transform 0.5s ease}
    .villa-card:hover img{transform:scale(1.04)}
    nav.scrolled{background:rgba(248,250,248,.96)!important;border-bottom:1px solid #e0e4e0}
    .hero-bg{background:linear-gradient(135deg,#1e3a2f 0%,#2d4f3f 50%,#1a3329 100%);min-height:70vh;position:relative;overflow:hidden}
    .hero-bg::before{content:'';position:absolute;inset:0;background:url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23ffffff' fill-opacity='0.03'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E")}
    @keyframes fadeUp{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:translateY(0)}}
    .fade-up{animation:fadeUp .7s ease both}.fade-up-1{animation:fadeUp .7s ease .1s both}.fade-up-2{animation:fadeUp .7s ease .2s both}
  </style>
</head>
<body>
<nav id="navbar" class="fixed top-0 left-0 right-0 z-50 transition-all duration-300" style="background:transparent">
  <div class="max-w-6xl mx-auto px-6 h-16 flex items-center justify-between">
    <a href="/" class="font-serif text-lg tracking-widest text-white font-bold" id="nav-brand">VILLA TAWANGMANGU</a>
    <a href="https://villa-sayan.pages.dev/admin/" class="text-[10px] tracking-widest uppercase font-semibold text-white/60 hover:text-white transition-colors flex items-center gap-1.5">
      <span class="material-symbols-outlined" style="font-size:16px">admin_panel_settings</span>Admin
    </a>
  </div>
</nav>
<div class="hero-bg flex flex-col items-center justify-center text-center px-6 py-32 pt-40">
  <div class="relative z-10">
    <p class="fade-up text-[10px] tracking-[0.25em] uppercase font-semibold text-white/50 mb-4">Sekipan · Tawangmangu · Karanganyar</p>
    <h1 class="fade-up-1 font-serif text-5xl md:text-7xl text-white leading-tight mb-5">Villa Tawangmangu</h1>
    <p class="fade-up-2 text-base md:text-lg text-white/70 leading-relaxed max-w-lg mx-auto">Sewa villa eksklusif di Sekipan, Tawangmangu — kolam renang privat, pemandangan pegunungan, cocok untuk keluarga &amp; gathering besar</p>
    <div class="fade-up-2 flex items-center justify-center gap-3 mt-3 text-white/40 text-xs tracking-widest uppercase">
      <span>Kolam Renang Privat</span><span>·</span><span>Pemandangan Pegunungan</span><span>·</span><span>Kapasitas Besar</span>
    </div>
    <div class="mt-8"><a href="#villas" class="inline-flex items-center gap-2 px-7 py-3.5 rounded-full text-sm font-semibold text-primary bg-white hover:bg-white/90 transition-all shadow-lg" style="letter-spacing:.05em">
      <span class="material-symbols-outlined" style="font-size:18px">villa</span>Lihat Villa
    </a></div>
  </div>
</div>
<section id="villas" class="py-20 px-6 bg-surface">
  <div class="max-w-6xl mx-auto">
    <div class="text-center mb-14">
      <span class="text-[10px] tracking-[0.2em] uppercase font-semibold text-secondary block mb-3">Pilihan Villa Kami</span>
      <h2 class="font-serif text-3xl md:text-4xl text-primary">Temukan Villa Impian Anda</h2>
      <div class="flex items-center justify-center mt-4"><div class="w-12 h-[1px] bg-outline-variant"></div><div class="w-1.5 h-1.5 rounded-full bg-primary/30 mx-3"></div><div class="w-12 h-[1px] bg-outline-variant"></div></div>
    </div>
    <div class="grid md:grid-cols-2 lg:grid-cols-3 gap-6">${cards}</div>
  </div>
</section>
<section class="py-20 px-6" style="background:#1e3a2f">
  <div class="max-w-4xl mx-auto text-center text-white">
    <h2 class="font-serif text-3xl md:text-4xl mb-3">Kenapa Pilih Kami?</h2>
    <p class="text-white/50 text-sm mb-12">Kami menyediakan pengalaman menginap terbaik di kawasan Tawangmangu</p>
    <div class="grid md:grid-cols-3 gap-8">
      <div class="flex flex-col items-center gap-3"><span class="material-symbols-outlined text-white/60" style="font-size:36px">pool</span><h3 class="font-semibold text-sm tracking-wide">Kolam Renang Privat</h3><p class="text-white/40 text-xs leading-relaxed">Setiap villa memiliki kolam renang pribadi eksklusif untuk tamu</p></div>
      <div class="flex flex-col items-center gap-3"><span class="material-symbols-outlined text-white/60" style="font-size:36px">landscape</span><h3 class="font-semibold text-sm tracking-wide">Pemandangan Pegunungan</h3><p class="text-white/40 text-xs leading-relaxed">Nikmati udara segar dan panorama hutan Sekipan yang memukau</p></div>
      <div class="flex flex-col items-center gap-3"><span class="material-symbols-outlined text-white/60" style="font-size:36px">groups</span><h3 class="font-semibold text-sm tracking-wide">Kapasitas Besar</h3><p class="text-white/40 text-xs leading-relaxed">Ideal untuk keluarga besar, reuni, dan gathering perusahaan</p></div>
    </div>
  </div>
</section>
<footer class="px-6 py-10" style="background:#ecefec;border-top:1px solid #bfc9c1">
  <div class="max-w-6xl mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
    <div class="font-serif text-lg tracking-widest text-primary">VILLA TAWANGMANGU</div>
    <p class="text-[0.8125rem] text-on-surface-variant text-center">Villa eksklusif di Sekipan, Tawangmangu, Karanganyar</p>
    <a href="https://villa-sayan.pages.dev/admin/" class="text-[10px] tracking-widest uppercase text-on-surface-variant hover:text-primary transition-colors flex items-center gap-1"><span class="material-symbols-outlined" style="font-size:14px">settings</span>Admin Dashboard</a>
  </div>
  <div class="max-w-6xl mx-auto mt-6 pt-5 border-t border-outline-variant text-center">
    <p class="text-[9px] text-on-surface-variant tracking-widest uppercase">&copy; ${year} Villa Tawangmangu. All Rights Reserved.</p>
  </div>
</footer>
<script>
const nb=document.getElementById('navbar'),br=document.getElementById('nav-brand');
window.addEventListener('scroll',()=>{
  if(window.scrollY>60){nb.classList.add('scrolled');if(br)br.style.color='#1e3a2f';nb.querySelector('a:last-child').style.color='#5c6b5e';}
  else{nb.classList.remove('scrolled');if(br)br.style.color='';nb.querySelector('a:last-child').style.color='';}
});
</script>
</body></html>`;
}

// ── SSR: Villa detail page ────────────────────────────────────────────────────
function renderVillaPage(v, facilities, gallery, policies, contacts) {
  const location    = [v.address, v.city, v.province].filter(Boolean).join(", ");
  const waContact   = contacts.find(c => c.type === "whatsapp" && c.is_primary) || contacts.find(c => c.type === "whatsapp");
  const phoneContact = contacts.find(c => c.type === "phone");
  const wa          = waHref(waContact);
  const contactNum  = waContact?.value || phoneContact?.value;
  const year        = new Date().getFullYear();
  const price       = v.extra_bed_price ? new Intl.NumberFormat("id-ID").format(v.extra_bed_price) : null;

  const slides = gallery.slice(0, 5);
  const heroSlides = slides.length
    ? slides.map((img, i) => `<div class="flex-none w-full h-full snap-start relative"><img class="w-full h-full object-cover" src="${esc(img.url)}" alt="${esc(img.alt||"")}" ${i>0?'loading="lazy"':""}/><div class="absolute inset-0 bg-gradient-to-b from-black/40 via-black/10 to-black/70"></div></div>`).join("")
    : `<div class="flex-none w-full h-full snap-start relative bg-primary flex items-center justify-center"><span class="material-symbols-outlined text-white/20" style="font-size:100px">villa</span><div class="absolute inset-0 bg-gradient-to-b from-black/40 via-black/10 to-black/70"></div></div>`;

  const dots = slides.length > 1
    ? slides.map((_,i) => `<button class="dot-btn transition-all duration-300" style="width:${i===0?"20":"8"}px;height:3px;border-radius:2px;background:white;opacity:${i===0?"1":"0.4"};border:none;cursor:pointer" onclick="goToSlide(${i})"></button>`).join("")
    : "";

  const imgs = gallery.slice(0, 3);
  const aboutImages = imgs.length >= 3
    ? `<div class="img-zoom overflow-hidden rounded-xl row-span-2"><img src="${esc(imgs[0].url)}" alt="" class="w-full h-full object-cover" style="min-height:280px"/></div><div class="img-zoom overflow-hidden rounded-xl"><img src="${esc(imgs[1].url)}" alt="" class="w-full h-48 object-cover"/></div><div class="img-zoom overflow-hidden rounded-xl"><img src="${esc(imgs[2].url)}" alt="" class="w-full h-48 object-cover"/></div>`
    : imgs.length === 2
    ? `<div class="img-zoom overflow-hidden rounded-xl"><img src="${esc(imgs[0].url)}" alt="" class="w-full h-64 object-cover"/></div><div class="img-zoom overflow-hidden rounded-xl"><img src="${esc(imgs[1].url)}" alt="" class="w-full h-64 object-cover"/></div>`
    : imgs.length === 1
    ? `<div class="img-zoom overflow-hidden rounded-xl col-span-2"><img src="${esc(imgs[0].url)}" alt="" class="w-full h-80 object-cover"/></div>`
    : `<div class="col-span-2 bg-surface-container rounded-xl h-64 flex items-center justify-center"><span class="material-symbols-outlined text-outline" style="font-size:60px">villa</span></div>`;

  let aboutMeta = "";
  if (v.checkin_time)  aboutMeta += `<div class="border-l-2 border-primary/20 pl-4 py-1"><h4 class="text-[10px] tracking-widest uppercase font-semibold text-primary mb-1">Check-in</h4><p class="text-[0.875rem] text-on-surface-variant font-semibold">${esc(v.checkin_time)}</p></div>`;
  if (v.checkout_time) aboutMeta += `<div class="border-l-2 border-primary/20 pl-4 py-1"><h4 class="text-[10px] tracking-widest uppercase font-semibold text-primary mb-1">Check-out</h4><p class="text-[0.875rem] text-on-surface-variant font-semibold">${esc(v.checkout_time)}</p></div>`;
  if (price)           aboutMeta += `<div class="border-l-2 border-primary/20 pl-4 py-1"><h4 class="text-[10px] tracking-widest uppercase font-semibold text-primary mb-1">Extra Bed</h4><p class="text-[0.875rem] text-on-surface-variant font-semibold">Rp${price}/bed</p></div>`;

  const descHtml = (v.description || v.tagline || "")
    .split("\n").filter(Boolean).map(p => `<p>${esc(p)}</p>`).join("") || `<p>${esc(v.tagline || "")}</p>`;

  const facilitiesHtml = facilities.length
    ? facilities.map(f => `<div class="bg-white rounded-xl p-5 flex flex-col items-center text-center hover:shadow-md transition-shadow"><span class="material-symbols-outlined text-primary mb-3" style="font-size:30px">${esc(f.icon||"star")}</span><h5 class="text-[10px] tracking-widest uppercase font-semibold text-primary mb-2">${esc(f.name)}</h5><p class="text-[0.75rem] text-on-surface-variant leading-relaxed">${esc(f.description||"")}</p></div>`).join("")
    : `<div class="col-span-4 text-center py-10 text-on-surface-variant text-sm">Belum ada fasilitas.</div>`;

  const galleryHtml = !gallery.length
    ? `<div class="col-span-3 text-center py-16 text-on-surface-variant"><span class="material-symbols-outlined text-4xl mb-3 block opacity-40">photo_library</span><p class="text-sm">Foto galeri akan segera hadir.</p></div>`
    : gallery.map((img, i) => {
        const cls = i===0 ? "col-span-2 md:col-span-1 md:row-span-2" : (i===gallery.length-1&&gallery.length%2===0?"col-span-2":"");
        const h   = i===0 ? "h-60 md:h-full" : "h-52";
        return `<div class="img-zoom overflow-hidden rounded-xl ${cls}"><img src="${esc(img.url)}" alt="${esc(img.alt||"")}" class="w-full ${h} object-cover" loading="lazy"/></div>`;
      }).join("");

  const schedules    = policies.filter(p => p.type === "schedule");
  const notes        = policies.filter(p => p.type === "note");
  const prohibitions = policies.filter(p => p.type === "prohibition");
  const rules        = policies.filter(p => p.type === "rule");
  let polHtml = "";
  if (schedules.length)    polHtml += `<div class="bg-white rounded-xl p-6"><div class="flex items-center gap-3 mb-4"><span class="material-symbols-outlined text-primary">schedule</span><h3 class="font-semibold text-primary">Jadwal &amp; Waktu</h3></div><ul class="space-y-2 text-[0.875rem] text-on-surface-variant">${schedules.map(p=>`<li class="flex gap-2 items-start"><span class="material-symbols-outlined text-secondary" style="font-size:16px;margin-top:2px">circle</span>${esc(p.content)}</li>`).join("")}</ul></div>`;
  if (notes.length)        polHtml += `<div class="bg-white rounded-xl p-6"><div class="flex items-center gap-3 mb-4"><span class="material-symbols-outlined text-yellow-600">info</span><h3 class="font-semibold text-primary">Catatan Penting</h3></div><ul class="space-y-2 text-[0.875rem] text-on-surface-variant">${notes.map(p=>`<li class="flex gap-2 items-start"><span class="material-symbols-outlined text-yellow-500" style="font-size:16px;margin-top:2px">warning</span>${esc(p.content)}</li>`).join("")}</ul></div>`;
  if (rules.length)        polHtml += `<div class="bg-white rounded-xl p-6"><div class="flex items-center gap-3 mb-4"><span class="material-symbols-outlined text-primary">gavel</span><h3 class="font-semibold text-primary">Aturan Villa</h3></div><ul class="space-y-2 text-[0.875rem] text-on-surface-variant">${rules.map(p=>`<li class="flex gap-2 items-start"><span class="material-symbols-outlined text-primary" style="font-size:16px;margin-top:2px">check_circle</span>${esc(p.content)}</li>`).join("")}</ul></div>`;
  if (prohibitions.length) {
    const span = (schedules.length||notes.length||rules.length) ? " md:col-span-2" : "";
    polHtml += `<div class="bg-white rounded-xl p-6${span}"><div class="flex items-center gap-3 mb-4"><span class="material-symbols-outlined text-red-500">block</span><h3 class="font-semibold text-primary">Larangan</h3></div><div class="grid sm:grid-cols-2 gap-3">${prohibitions.map(p=>`<div class="flex items-start gap-2 p-3 rounded bg-red-50 border border-red-200"><span class="material-symbols-outlined text-red-400" style="font-size:18px;flex-shrink:0;margin-top:1px">cancel</span><span class="text-[0.8125rem] text-on-surface-variant">${esc(p.content)}</span></div>`).join("")}</div></div>`;
  }
  if (!polHtml) polHtml = `<div class="md:col-span-2 text-center py-10 text-on-surface-variant text-sm">Belum ada kebijakan.</div>`;

  let contactInfoHtml = "";
  if (contactNum) contactInfoHtml += `<div><span class="material-symbols-outlined opacity-40 block mb-1" style="font-size:20px">phone</span><p class="text-[9px] tracking-widest uppercase opacity-40 mb-1">Telepon / WA</p><a href="tel:${esc(contactNum)}" class="text-sm opacity-70 hover:opacity-100 transition-opacity">${esc(contactNum)}</a></div>`;
  if (location)   contactInfoHtml += `<div><span class="material-symbols-outlined opacity-40 block mb-1" style="font-size:20px">location_on</span><p class="text-[9px] tracking-widest uppercase opacity-40 mb-1">Lokasi</p><span class="text-sm opacity-70">${esc(location)}</span></div>`;
  if (v.checkin_time||v.checkout_time) contactInfoHtml += `<div><span class="material-symbols-outlined opacity-40 block mb-1" style="font-size:20px">schedule</span><p class="text-[9px] tracking-widest uppercase opacity-40 mb-1">Check-in / out</p><span class="text-sm opacity-70">${esc(v.checkin_time||"—")} / ${esc(v.checkout_time||"—")}</span></div>`;

  const footerContacts = contacts.filter(c=>c.value).map(c=>{
    const href = c.type==="whatsapp"||c.type==="phone"?`tel:${c.value}`:c.type==="email"?`mailto:${c.value}`:"#";
    const icon = c.type==="whatsapp"?"chat":c.type==="email"?"email":"phone";
    return `<li><a href="${href}" class="hover:text-primary transition-colors flex items-center gap-1"><span class="material-symbols-outlined" style="font-size:14px">${icon}</span>${esc(c.value)}</a></li>`;
  }).join("") || "<li>—</li>";

  return `<!DOCTYPE html>
<html class="light" lang="id">
<head>
  <title>${esc(v.name)} — Villa Tawangmangu</title>
  <meta name="description" content="${esc(v.tagline||v.description||"Sewa villa eksklusif di Tawangmangu")}"/>
  <meta name="keywords" content="villa tawangmangu, ${esc(v.name)}, sewa villa tawangmangu, villa sekipan"/>
  <meta property="og:title" content="${esc(v.name)} — Villa Tawangmangu"/>
  <meta property="og:description" content="${esc(v.tagline||v.description||"")}"/>
  ${gallery[0]?`<meta property="og:image" content="${esc(gallery[0].url)}"/>`:""}
  <meta property="og:type" content="website"/>
  <link rel="canonical" href="/villa/${esc(v.slug||"")}"/>
  <meta name="robots" content="index, follow"/>
  ${COMMON_HEAD}
  <script>${TAILWIND_COLORS}</script>
  <style>
    .material-symbols-outlined{font-variation-settings:'FILL' 0,'wght' 300,'GRAD' 0,'opsz' 24;font-size:24px}
    body{background-color:#f8faf8;color:#191d1a;-webkit-font-smoothing:antialiased;font-family:"Plus Jakarta Sans",sans-serif}
    .snap-x{scroll-snap-type:x mandatory;-webkit-overflow-scrolling:touch}.snap-start{scroll-snap-align:start}
    .no-scrollbar::-webkit-scrollbar{display:none}.no-scrollbar{-ms-overflow-style:none;scrollbar-width:none}
    .font-serif{font-family:"Noto Serif",Georgia,serif}html{scroll-behavior:smooth}
    @keyframes fadeUp{from{opacity:0;transform:translateY(24px)}to{opacity:1;transform:translateY(0)}}
    .fade-up{animation:fadeUp .8s ease forwards}.fade-up-delay-1{animation:fadeUp .8s ease .15s both}.fade-up-delay-2{animation:fadeUp .8s ease .3s both}.fade-up-delay-3{animation:fadeUp .8s ease .45s both}
    .img-zoom img{transition:transform .6s ease}.img-zoom:hover img{transform:scale(1.04)}
    nav.scrolled{background:rgba(248,250,248,.96)!important;border-bottom:1px solid #e0e4e0}
    input,textarea,select{background:#fff;border:1px solid #bfc9c1;border-radius:.375rem;padding:12px 16px;width:100%;font-family:"Plus Jakarta Sans",sans-serif;font-size:.9375rem;color:#191d1a;outline:none;transition:border-color .2s}
    input:focus,textarea:focus,select:focus{border-color:#1e3a2f}textarea{resize:vertical;min-height:110px}
    .btn-primary{background:#1e3a2f;color:#fff;padding:13px 28px;border-radius:.375rem;font-size:.7rem;letter-spacing:.12em;font-weight:600;text-transform:uppercase;transition:background .2s;cursor:pointer;border:none;display:inline-block;text-decoration:none}
    .btn-primary:hover{background:#2d4f3f}
    .btn-outline-white{background:transparent;color:rgba(255,255,255,.8);padding:12px 28px;border-radius:.375rem;font-size:.7rem;letter-spacing:.12em;font-weight:600;text-transform:uppercase;border:1.5px solid rgba(255,255,255,.4);transition:all .2s;cursor:pointer;display:inline-block;text-decoration:none}
    .btn-outline-white:hover{background:rgba(255,255,255,.15);color:#fff}
    .wa-float{position:fixed;bottom:24px;right:24px;z-index:100;width:56px;height:56px;border-radius:50%;background:#25D366;color:#fff;display:flex;align-items:center;justify-content:center;box-shadow:0 4px 20px rgba(37,211,102,.4);text-decoration:none;transition:transform .2s,box-shadow .2s}
    .wa-float:hover{transform:scale(1.08);box-shadow:0 6px 24px rgba(37,211,102,.5)}
  </style>
</head>
<body>
<a class="wa-float" href="${wa}" target="_blank" rel="noopener" title="Hubungi via WhatsApp">${WA_SVG}</a>
<nav id="navbar" class="fixed top-0 left-0 right-0 z-50 transition-all duration-300" style="background:transparent">
  <div class="max-w-6xl mx-auto px-6 h-16 flex items-center justify-between">
    <a href="/" class="font-serif text-lg tracking-widest text-white" id="nav-logo">${esc((v.name||"VILLA TAWANGMANGU").toUpperCase())}</a>
    <div class="hidden md:flex items-center gap-8" id="nav-links">
      <a href="#about"      class="text-[11px] tracking-widest uppercase font-semibold text-white/80 hover:text-white transition-colors">Villa</a>
      <a href="#facilities" class="text-[11px] tracking-widest uppercase font-semibold text-white/80 hover:text-white transition-colors">Fasilitas</a>
      <a href="#gallery"    class="text-[11px] tracking-widest uppercase font-semibold text-white/80 hover:text-white transition-colors">Galeri</a>
      <a href="#rules"      class="text-[11px] tracking-widest uppercase font-semibold text-white/80 hover:text-white transition-colors">Aturan</a>
      <a href="#contact"    class="btn-primary text-[11px] py-2 px-5">Reservasi</a>
    </div>
    <button id="menu-btn" class="md:hidden text-white" onclick="toggleMenu()"><span class="material-symbols-outlined">menu</span></button>
  </div>
  <div id="mobile-menu" class="hidden md:hidden px-6 py-4 space-y-4" style="background:rgba(248,250,248,.98);border-top:1px solid #e0e4e0">
    <a href="#about"      class="block text-[11px] tracking-widest uppercase font-semibold text-on-surface" onclick="toggleMenu()">Villa</a>
    <a href="#facilities" class="block text-[11px] tracking-widest uppercase font-semibold text-on-surface" onclick="toggleMenu()">Fasilitas</a>
    <a href="#gallery"    class="block text-[11px] tracking-widest uppercase font-semibold text-on-surface" onclick="toggleMenu()">Galeri</a>
    <a href="#rules"      class="block text-[11px] tracking-widest uppercase font-semibold text-on-surface" onclick="toggleMenu()">Aturan</a>
    <a href="#contact"    class="block text-[11px] tracking-widest uppercase font-semibold text-primary" onclick="toggleMenu()">Reservasi</a>
  </div>
</nav>
<section class="w-full relative overflow-hidden" id="hero">
  <div class="flex overflow-x-auto snap-x no-scrollbar h-screen" id="gallery-slider">${heroSlides}</div>
  <div class="absolute bottom-24 left-6 md:left-16 z-10 text-white max-w-xl">
    <p class="fade-up text-[10px] tracking-[0.2em] uppercase font-semibold mb-3 opacity-70">${esc(location)}</p>
    <h1 class="fade-up-delay-1 font-serif text-4xl md:text-6xl leading-tight mb-3">${esc(v.name)}</h1>
    <p class="fade-up-delay-2 text-sm md:text-base opacity-80 leading-relaxed max-w-sm">${esc(v.tagline||"")}</p>
    <div class="fade-up-delay-3 flex flex-wrap gap-3 mt-6">
      <a href="#contact" class="btn-primary">Hubungi Admin</a>
      <a href="#about"   class="btn-outline-white">Selengkapnya</a>
    </div>
  </div>
  <div class="absolute bottom-8 left-1/2 -translate-x-1/2 flex gap-2 z-10" id="dots">${dots}</div>
</section>
<section class="bg-primary text-white">
  <div class="max-w-6xl mx-auto px-6 py-7 grid grid-cols-2 md:grid-cols-4 gap-6 text-center">
    <div><div class="font-serif text-3xl mb-1">${esc(v.max_guests||"—")}</div><div class="text-[10px] tracking-widest uppercase opacity-60">${esc(v.max_guests_note||"Tamu Maksimal")}</div></div>
    <div><div class="font-serif text-xl mb-1">${esc(v.checkin_time||"—")}</div><div class="text-[10px] tracking-widest uppercase opacity-60">Check-in</div></div>
    <div><div class="font-serif text-xl mb-1">${esc(v.checkout_time||"—")}</div><div class="text-[10px] tracking-widest uppercase opacity-60">Check-out</div></div>
    <div><div class="font-serif text-xl mb-1">${esc(v.city||"—")}</div><div class="text-[10px] tracking-widest uppercase opacity-60">${esc(v.province||"Lokasi")}</div></div>
  </div>
</section>
<section id="about" class="py-24 px-6">
  <div class="max-w-6xl mx-auto grid md:grid-cols-2 gap-16 items-center">
    <div>
      <span class="text-[10px] tracking-[0.2em] uppercase font-semibold text-secondary block mb-4">Tentang Villa</span>
      <h2 class="font-serif text-3xl md:text-4xl text-primary leading-snug mb-6">${esc(v.name)}<br/>${esc([v.city,v.province].filter(Boolean).join(", "))}</h2>
      <div class="space-y-4 text-on-surface-variant text-[0.9375rem] leading-relaxed">${descHtml}</div>
      <div class="mt-8 flex flex-wrap gap-6">${aboutMeta}</div>
    </div>
    <div class="grid grid-cols-2 gap-3">${aboutImages}</div>
  </div>
</section>
<section id="facilities" class="py-24 px-6" style="background:#ecefec">
  <div class="max-w-6xl mx-auto">
    <div class="text-center mb-14">
      <span class="text-[10px] tracking-[0.2em] uppercase font-semibold text-secondary block mb-3">Yang Kami Sediakan</span>
      <h2 class="font-serif text-3xl md:text-4xl text-primary">Fasilitas Lengkap</h2>
      <div class="flex items-center justify-center mt-4"><div class="w-12 h-[1px] bg-outline-variant"></div><div class="w-1.5 h-1.5 rounded-full bg-primary/30 mx-3"></div><div class="w-12 h-[1px] bg-outline-variant"></div></div>
    </div>
    <div class="grid grid-cols-2 md:grid-cols-4 gap-4">${facilitiesHtml}</div>
  </div>
</section>
<section id="gallery" class="py-24 px-6">
  <div class="max-w-6xl mx-auto">
    <div class="text-center mb-14">
      <span class="text-[10px] tracking-[0.2em] uppercase font-semibold text-secondary block mb-3">Galeri Foto</span>
      <h2 class="font-serif text-3xl md:text-4xl text-primary">Lihat Sendiri Keindahannya</h2>
    </div>
    <div class="grid grid-cols-2 md:grid-cols-3 gap-3">${galleryHtml}</div>
  </div>
</section>
<section id="rules" class="py-24 px-6" style="background:#ecefec">
  <div class="max-w-4xl mx-auto">
    <div class="text-center mb-12">
      <span class="text-[10px] tracking-[0.2em] uppercase font-semibold text-secondary block mb-3">Ketentuan</span>
      <h2 class="font-serif text-3xl text-primary">Aturan &amp; Kebijakan Villa</h2>
      <p class="text-on-surface-variant text-sm mt-3">Demi kenyamanan bersama, mohon untuk diperhatikan</p>
    </div>
    <div class="grid md:grid-cols-2 gap-6">${polHtml}</div>
  </div>
</section>
<section id="contact" class="py-24 px-6" style="background:#1e3a2f">
  <div class="max-w-2xl mx-auto">
    <div class="text-center mb-12 text-white">
      <span class="text-[10px] tracking-[0.2em] uppercase font-semibold opacity-60 block mb-3">Reservasi</span>
      <h2 class="font-serif text-3xl md:text-4xl mb-4">Hubungi Admin Villa</h2>
      <p class="text-sm opacity-60 leading-relaxed">Kirim pesan WhatsApp atau isi formulir di bawah — kami akan membalas secepatnya</p>
    </div>
    <div class="text-center mb-10">
      <a href="${wa}" target="_blank" rel="noopener" class="inline-flex items-center gap-3 px-8 py-4 rounded-xl text-white font-semibold text-base hover:scale-105 transition-transform" style="background:#25D366;box-shadow:0 4px 20px rgba(37,211,102,.35)">
        ${WA_SVG}${waContact?`Chat WhatsApp — ${esc(waContact.value)}`:"Chat WhatsApp Sekarang"}
      </a>
      <p class="text-white/40 text-xs mt-3">Atau isi formulir di bawah dan kami akan menghubungi Anda</p>
    </div>
    <div class="flex items-center gap-4 mb-8"><div class="flex-1 h-[1px] bg-white/10"></div><span class="text-white/30 text-xs tracking-widest uppercase">Formulir Reservasi</span><div class="flex-1 h-[1px] bg-white/10"></div></div>
    <form class="space-y-4" id="inquiry-form">
      <div class="grid md:grid-cols-2 gap-4">
        <div><label class="block text-[10px] tracking-widest uppercase font-semibold text-white/50 mb-2">Nama Lengkap *</label><input id="f-name" type="text" placeholder="Nama Anda" required/></div>
        <div><label class="block text-[10px] tracking-widest uppercase font-semibold text-white/50 mb-2">Nomor WhatsApp *</label><input id="f-phone" type="tel" placeholder="08xxxxxxxxxx" required/></div>
      </div>
      <div><label class="block text-[10px] tracking-widest uppercase font-semibold text-white/50 mb-2">Email (opsional)</label><input id="f-email" type="email" placeholder="email@contoh.com"/></div>
      <div class="grid md:grid-cols-2 gap-4">
        <div><label class="block text-[10px] tracking-widest uppercase font-semibold text-white/50 mb-2">Tanggal Check-In *</label><input id="f-checkin" type="date" required/></div>
        <div><label class="block text-[10px] tracking-widest uppercase font-semibold text-white/50 mb-2">Tanggal Check-Out *</label><input id="f-checkout" type="date" required/></div>
      </div>
      <div><label class="block text-[10px] tracking-widest uppercase font-semibold text-white/50 mb-2">Jumlah Tamu</label>
        <select id="f-guests"><option value="1-10">1–10 Orang</option><option value="10-15">10–15 Orang</option><option value="15-20">15–20 Orang</option><option value="20-25">20–25 Orang</option><option value="25-30">25–30 Orang</option></select>
      </div>
      <div><label class="block text-[10px] tracking-widest uppercase font-semibold text-white/50 mb-2">Pesan / Kebutuhan Khusus</label>
        <textarea id="f-message" placeholder="Contoh: perlu catering, extra bed, atau pertanyaan lainnya..."></textarea></div>
      <button type="submit" id="submit-btn" class="btn-primary w-full text-center mt-2" style="background:#a8c5b5;color:#1e3a2f;font-weight:700">Kirim Permintaan Reservasi</button>
    </form>
    <div class="mt-10 pt-8 border-t border-white/10 flex flex-col sm:flex-row justify-center gap-8 text-center text-white">${contactInfoHtml}</div>
  </div>
</section>
<div id="toast" class="fixed bottom-6 left-1/2 -translate-x-1/2 bg-primary text-white px-6 py-3 rounded-lg text-sm shadow-xl transition-all duration-300 opacity-0 pointer-events-none translate-y-2 whitespace-nowrap z-50"></div>
<footer class="px-6" style="background:#ecefec;border-top:1px solid #bfc9c1">
  <div class="max-w-6xl mx-auto py-10">
    <div class="grid md:grid-cols-3 gap-8 mb-8">
      <div>
        <div class="font-serif text-xl tracking-widest text-primary mb-3">${esc((v.name||"VILLA TAWANGMANGU").toUpperCase())}</div>
        <p class="text-[0.8125rem] text-on-surface-variant leading-relaxed max-w-xs">${esc(v.tagline||(v.description||"").slice(0,120))}</p>
      </div>
      <div>
        <h6 class="text-[10px] tracking-widest uppercase font-semibold text-primary mb-4">Navigasi</h6>
        <ul class="space-y-2">
          <li><a href="#about"      class="text-[0.8125rem] text-on-surface-variant hover:text-primary transition-colors">Tentang Villa</a></li>
          <li><a href="#facilities" class="text-[0.8125rem] text-on-surface-variant hover:text-primary transition-colors">Fasilitas</a></li>
          <li><a href="#gallery"    class="text-[0.8125rem] text-on-surface-variant hover:text-primary transition-colors">Galeri</a></li>
          <li><a href="#rules"      class="text-[0.8125rem] text-on-surface-variant hover:text-primary transition-colors">Aturan Villa</a></li>
          <li><a href="#contact"    class="text-[0.8125rem] text-on-surface-variant hover:text-primary transition-colors">Reservasi</a></li>
          <li><a href="/"           class="text-[0.8125rem] text-on-surface-variant hover:text-primary transition-colors">← Semua Villa</a></li>
        </ul>
      </div>
      <div>
        <h6 class="text-[10px] tracking-widest uppercase font-semibold text-primary mb-4">Kontak</h6>
        <ul class="space-y-2 text-[0.8125rem] text-on-surface-variant">${footerContacts}</ul>
      </div>
    </div>
    <div class="pt-6 border-t border-outline-variant text-center">
      <p class="text-[9px] text-on-surface-variant tracking-widest uppercase">&copy; ${year} ${esc(v.name||"Villa Tawangmangu")}. All Rights Reserved.</p>
    </div>
  </div>
</footer>
<script>
const VILLA_ID = ${JSON.stringify(v.id)};
let currentSlide = 0;
function goToSlide(i) {
  currentSlide = i;
  const s = document.getElementById('gallery-slider');
  s.scrollTo({left: s.offsetWidth*i, behavior:'smooth'});
  document.querySelectorAll('.dot-btn').forEach((d,idx)=>{d.style.opacity=idx===i?'1':'0.4';d.style.width=idx===i?'20px':'8px';});
}
const dotBtns = document.querySelectorAll('.dot-btn');
if (dotBtns.length>1) setInterval(()=>goToSlide((currentSlide+1)%dotBtns.length),5000);
const navbar=document.getElementById('navbar'),navLogo=document.getElementById('nav-logo'),navLinks=document.querySelectorAll('#nav-links a:not(.btn-primary)');
window.addEventListener('scroll',()=>{
  if(window.scrollY>60){navbar.classList.add('scrolled');if(navLogo)navLogo.style.color='#1e3a2f';navLinks.forEach(l=>l.style.color='#404944');}
  else{navbar.classList.remove('scrolled');if(navLogo)navLogo.style.color='#fff';navLinks.forEach(l=>l.style.color='rgba(255,255,255,0.8)');}
});
function toggleMenu(){document.getElementById('mobile-menu').classList.toggle('hidden');}
function showToast(msg){const t=document.getElementById('toast');t.textContent=msg;t.style.opacity='1';t.style.pointerEvents='auto';setTimeout(()=>{t.style.opacity='0';t.style.pointerEvents='none';},5000);}
document.getElementById('inquiry-form').addEventListener('submit',async(e)=>{
  e.preventDefault();
  const btn=document.getElementById('submit-btn');
  btn.textContent='Mengirim...';btn.disabled=true;
  const payload={villa_id:VILLA_ID,name:document.getElementById('f-name').value,phone:document.getElementById('f-phone').value,email:document.getElementById('f-email').value||null,checkin_date:document.getElementById('f-checkin').value||null,checkout_date:document.getElementById('f-checkout').value||null,num_guests:document.getElementById('f-guests').value,message:document.getElementById('f-message').value||null,status:'pending'};
  try{const res=await fetch('/inquiries',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});if(res.ok)showToast('✓ Permintaan terkirim! Kami akan segera menghubungi Anda.');else showToast('✓ Terima kasih! Hubungi kami via WhatsApp untuk konfirmasi.');}
  catch{showToast('✓ Terima kasih! Hubungi kami via WhatsApp untuk konfirmasi.');}
  btn.textContent='Kirim Permintaan Reservasi';btn.disabled=false;e.target.reset();
});
</script>
</body></html>`;
}

// ── Main router ───────────────────────────────────────────────────────────────
export default {
  async fetch(request, env) {
    const url    = new URL(request.url);
    const method = request.method;
    const path   = url.pathname;

    const corsHeaders = {
      "Access-Control-Allow-Origin":  env.ALLOWED_ORIGIN || "*",
      "Access-Control-Allow-Methods": "GET,POST,PATCH,DELETE,OPTIONS",
      "Access-Control-Allow-Headers": "Authorization,Content-Type",
    };

    if (method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders });

    function withCors(res) {
      const r = new Response(res.body, res);
      for (const [k, v] of Object.entries(corsHeaders)) r.headers.set(k, v);
      return r;
    }

    async function run() {
      // ── Parse body ────────────────────────────────────────────────
      let body = {};
      if (method !== "GET" && method !== "HEAD") {
        const ct = request.headers.get("content-type") || "";
        if (ct.includes("application/json")) {
          try { body = await request.json(); } catch {}
        } else if (ct.includes("multipart/form-data")) {
          body = await request.formData();
        }
      }
      // ── ADMIN PAGE ──────────────────────────────────────────────
if (method === "GET" && (path === "/admin" || path === "/admin/")) {
  return Response.redirect("https://villa-sayan.pages.dev/admin/", 301);
}
      // ── ROBOTS.TXT ──────────────────────────────────────────────
      if (method === "GET" && path === "/robots.txt") {
        return new Response(
          `User-agent: *\nAllow: /\nDisallow: /api/\nSitemap: https://tawangmangu.biz.id/sitemap.xml`,
          { headers: { "Content-Type": "text/plain", "Cache-Control": "public, max-age=86400" } }
        );
      }

      // ── SITEMAP ─────────────────────────────────────────────────
      if (method === "GET" && path === "/sitemap.xml") {
        const origin = "https://tawangmangu.biz.id";
        const villas = await sb(env, "villa_info", "GET", "select=slug,updated_at&order=created_at.asc");
        const today = new Date().toISOString().split("T")[0];
        const urls = [
          `<url><loc>${origin}/</loc><changefreq>daily</changefreq><priority>1.0</priority><lastmod>${today}</lastmod></url>`,
          ...villas.filter(v => v.slug).map(v => {
            const lastmod = v.updated_at ? v.updated_at.split("T")[0] : today;
            return `<url><loc>${origin}/villa/${encodeURIComponent(v.slug)}</loc><changefreq>weekly</changefreq><priority>0.8</priority><lastmod>${lastmod}</lastmod></url>`;
          }),
        ];
        const xml = `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls.join("\n")}\n</urlset>`;
        return new Response(xml, { headers: { "Content-Type": "application/xml; charset=utf-8", "Cache-Control": "public, max-age=3600" } });
      }

      // ── SSR: GET / ──────────────────────────────────────────────
      if (method === "GET" && path === "/") {
        const villas = await sb(env, "villa_info", "GET", "select=*&order=created_at.asc");
        if (!villas.length) return html(renderIndexPage([], {}, {}, undefined));
        const ids = villas.map(v => v.id).join(",");
        const [gallery, villaContacts, globalContacts] = await Promise.all([
          sb(env, "gallery",  "GET", `villa_id=in.(${ids})&is_active=eq.true&order=sort_order.asc`),
          sb(env, "contacts", "GET", `villa_id=in.(${ids})&type=eq.whatsapp`),
          sb(env, "contacts", "GET", "villa_id=is.null&type=eq.whatsapp"),
        ]);
        const coverMap = {};
        for (const img of gallery) if (!coverMap[img.villa_id]) coverMap[img.villa_id] = img;
        const contactMap = {};
        for (const c of villaContacts) if (!contactMap[c.villa_id] || c.is_primary) contactMap[c.villa_id] = c;
        const globalWa = globalContacts.find(c => c.is_primary) || globalContacts[0];
        return html(renderIndexPage(villas, coverMap, contactMap, globalWa));
      }

      // ── SSR: GET /villa/:slug ────────────────────────────────────
      const villaMatch = path.match(/^\/villa\/([^/]+)$/);
      if (method === "GET" && villaMatch) {
        const slug = decodeURIComponent(villaMatch[1]);
        const rows = await sb(env, "villa_info", "GET", `slug=eq.${encodeURIComponent(slug)}&select=*&limit=1`);
        if (!rows.length) return html(`<!DOCTYPE html><html lang="id"><head><title>404</title></head><body style="font-family:sans-serif;text-align:center;padding:60px"><h1>Villa Tidak Ditemukan</h1><p><a href="/">← Kembali</a></p></body></html>`, 404);
        const v = rows[0];
        const [facilities, gallery, policies, villaContacts, globalContacts] = await Promise.all([
          sb(env, "facilities", "GET", `villa_id=eq.${v.id}&is_active=eq.true&order=sort_order.asc`),
          sb(env, "gallery",    "GET", `villa_id=eq.${v.id}&is_active=eq.true&order=sort_order.asc`),
          sb(env, "policies",   "GET", `villa_id=eq.${v.id}&order=sort_order.asc`),
          sb(env, "contacts",   "GET", `villa_id=eq.${v.id}`),
          sb(env, "contacts",   "GET", "villa_id=is.null"),
        ]);
        const merged = [...villaContacts];
        for (const gc of globalContacts) if (!merged.some(c => c.type === gc.type)) merged.push(gc);
        return html(renderVillaPage(v, facilities, gallery, policies, merged));
      }

      // ── Redirect: /villa.html?slug=X → /villa/X ─────────────────
      if (method === "GET" && path === "/villa.html") {
        const slug = url.searchParams.get("slug");
        const id   = url.searchParams.get("id");
        if (slug) return Response.redirect(`${url.origin}/villa/${encodeURIComponent(slug)}`, 301);
        if (id)   return Response.redirect(`${url.origin}/villa/?id=${id}`, 301);
        return Response.redirect(`${url.origin}/`, 301);
      }

      // ── API: POST /setup ─────────────────────────────────────────
      if (method === "POST" && path === "/setup") {
        const count = await sb(env, "v_users", "GET", "select=id&limit=1");
        if (count.length) return json({ error: "Setup sudah dilakukan." }, 403);
        const { username, password } = body;
        if (!username || !password) return json({ error: "username dan password wajib diisi" }, 400);
        const password_hash = await hashPassword(password);
        const u = await sb(env, "v_users", "POST", "", { username, password_hash, role: "superadmin", status: "active" });
        return json({ message: "Superadmin berhasil dibuat", user: { id: u[0]?.id, username } }, 201);
      }

      // ── API: POST /auth/login ────────────────────────────────────
      if (method === "POST" && path === "/auth/login") {
        const { username, password } = body;
        if (!username || !password) return json({ error: "username dan password wajib diisi" }, 400);
        const rows = await sb(env, "v_users", "GET", `username=eq.${encodeURIComponent(username)}&select=*&limit=1`);
        const user = rows[0];
        if (!user) return json({ error: "Username atau password salah" }, 401);
        if (user.status === "pending")   return json({ error: "Akun menunggu persetujuan superadmin" }, 403);
        if (user.status === "suspended") return json({ error: "Akun disuspend" }, 403);
        if (!await verifyPassword(password, user.password_hash)) return json({ error: "Username atau password salah" }, 401);
        const exp = Math.floor(Date.now()/1000) + 60*60*24*7;
        const token = await signJWT({ sub: user.id, username: user.username, role: user.role, villa_id: user.villa_id, exp }, env.JWT_SECRET);
        return json({ token, user: { id: user.id, username: user.username, role: user.role, villa_id: user.villa_id } });
      }

      // ── API: POST /auth/register ─────────────────────────────────
      if (method === "POST" && path === "/auth/register") {
        const { username, password, email, villa_id } = body;
        if (!username || !password) return json({ error: "username dan password wajib diisi" }, 400);
        if (password.length < 6) return json({ error: "Password minimal 6 karakter" }, 400);
        const ex = await sb(env, "v_users", "GET", `username=eq.${encodeURIComponent(username)}&limit=1`);
        if (ex.length) return json({ error: "Username sudah dipakai" }, 409);
        const password_hash = await hashPassword(password);
        await sb(env, "v_users", "POST", "", { username, password_hash, email: email||null, villa_id: villa_id||null, role: "admin", status: "pending" });
        return json({ message: "Pendaftaran berhasil. Tunggu persetujuan superadmin." }, 201);
      }

      // ── API: GET /auth/me ────────────────────────────────────────
      if (method === "GET" && path === "/auth/me") {
        const u = await requireAuth(request, env);
        const rows = await sb(env, "v_users", "GET", `id=eq.${u.sub}&select=id,username,email,role,villa_id,status,created_at&limit=1`);
        return json(rows[0] || null);
      }

      // ── API: GET /villas ─────────────────────────────────────────
      if (method === "GET" && path === "/villas") {
        const u = await requireAuth(request, env);
        let q = "select=*&order=created_at.asc";
        if (u.role !== "superadmin" && u.villa_id) q += `&id=eq.${u.villa_id}`;
        return json(await sb(env, "villa_info", "GET", q));
      }

      // ── API: POST /villas ────────────────────────────────────────
      if (method === "POST" && path === "/villas") {
        const u = await requireAuth(request, env);
        const b = body;
        if (!b.name || !b.slug) return json({ error: "name dan slug wajib diisi" }, 400);
        const ex = await sb(env, "villa_info", "GET", `slug=eq.${encodeURIComponent(b.slug)}&limit=1`);
        if (ex.length) return json({ error: "Slug sudah dipakai" }, 409);
        const r = await sb(env, "villa_info", "POST", "", { name:b.name, slug:b.slug, tagline:b.tagline||null, description:b.description||null, address:b.address||null, city:b.city||null, province:b.province||null, max_guests:b.max_guests||null, max_guests_note:b.max_guests_note||null, extra_bed_price:b.extra_bed_price||null, extra_bed_note:b.extra_bed_note||null, checkin_time:b.checkin_time||"14.00 WIB", checkout_time:b.checkout_time||"12.00 WIB" });
        const villa = r[0]||r;
        if (u.role === "admin") await sb(env, "v_users", "PATCH", `id=eq.${u.sub}`, { villa_id: villa.id });
        return json(villa, 201);
      }

      // ── API: GET /villas/:id ─────────────────────────────────────
      const villaById = path.match(/^\/villas\/([^/]+)$/);
      if (villaById) {
        const id = villaById[1];
        if (method === "GET") {
          const u = await requireAuth(request, env);
          if (!canAccessVilla(u, id)) return json({ error: "Forbidden" }, 403);
          const r = await sb(env, "villa_info", "GET", `id=eq.${id}&select=*&limit=1`);
          if (!r.length) return json({ error: "Villa tidak ditemukan" }, 404);
          return json(r[0]);
        }
        if (method === "PATCH") {
          const u = await requireAuth(request, env);
          if (!canAccessVilla(u, id)) return json({ error: "Forbidden" }, 403);
          const b = body, allowed = ["name","slug","tagline","description","address","city","province","max_guests","max_guests_note","extra_bed_price","extra_bed_note","checkin_time","checkout_time"];
          const upd = { updated_at: new Date().toISOString() };
          for (const k of allowed) if (k in b) upd[k] = b[k];
          const r = await sb(env, "villa_info", "PATCH", `id=eq.${id}`, upd);
          return json(r[0]||r);
        }
        if (method === "DELETE") {
          await requireSA(request, env);
          await Promise.all([
            sb(env,"facilities","DELETE",`villa_id=eq.${id}`), sb(env,"policies","DELETE",`villa_id=eq.${id}`),
            sb(env,"contacts","DELETE",`villa_id=eq.${id}`),   sb(env,"gallery","DELETE",`villa_id=eq.${id}`),
            sb(env,"inquiries","DELETE",`villa_id=eq.${id}`),
          ]);
          await sb(env, "villa_info", "DELETE", `id=eq.${id}`);
          return json({ message: "Villa berhasil dihapus" });
        }
      }

      // ── API: Villa sub-resources (/villas/:id/facilities etc.) ───
      const subMatch = path.match(/^\/villas\/([^/]+)\/(facilities|policies|contacts|gallery)$/);
      if (subMatch) {
        const [, villaId, resource] = subMatch;
        if (method === "GET") {
          await requireAuth(request, env);
          const q = resource === "gallery"
            ? `villa_id=eq.${villaId}&is_active=eq.true&order=sort_order.asc`
            : resource === "facilities" ? `villa_id=eq.${villaId}&order=sort_order.asc`
            : resource === "contacts"   ? `villa_id=eq.${villaId}`
            : `villa_id=eq.${villaId}&order=sort_order.asc`;
          return json(await sb(env, resource, "GET", q));
        }
        if (method === "POST") {
          const u = await requireAuth(request, env);
          if (!canAccessVilla(u, villaId)) return json({ error: "Forbidden" }, 403);
          const b = body;
          let payload;
          if (resource === "facilities") {
            if (!b.name) return json({ error: "name wajib diisi" }, 400);
            payload = { villa_id:villaId, icon:b.icon||"star", name:b.name, description:b.description||null, sort_order:b.sort_order??0, is_active:true };
          } else if (resource === "policies") {
            if (!b.content||!b.type) return json({ error: "content dan type wajib diisi" }, 400);
            payload = { villa_id:villaId, type:b.type, content:b.content, sort_order:b.sort_order??0 };
          } else if (resource === "contacts") {
            if (!b.value||!b.type) return json({ error: "type dan value wajib diisi" }, 400);
            payload = { villa_id:villaId, type:b.type, label:b.label||null, value:b.value, is_primary:b.is_primary??false };
          } else {
            return json({ error: "Upload via /upload/github" }, 400);
          }
          const r = await sb(env, resource, "POST", "", payload);
          return json(r[0]||r, 201);
        }
      }

      // ── API: PATCH/DELETE sub-resource items ─────────────────────
      const itemMatch = path.match(/^\/(facilities|policies|contacts|gallery)\/([^/]+)$/);
      if (itemMatch) {
        const [, resource, id] = itemMatch;
        if (method === "PATCH") {
          const u = await requireAuth(request, env);
          const item = await sb(env, resource, "GET", `id=eq.${id}&limit=1`);
          if (!item.length) return json({ error: "Tidak ditemukan" }, 404);
          if (!canAccessVilla(u, item[0].villa_id)) return json({ error: "Forbidden" }, 403);
          const r = resource === "gallery"
            ? await sb(env, resource, "PATCH", `id=eq.${id}`, body)
            : await sb(env, resource, "PATCH", `id=eq.${id}`, body);
          return json(r[0]||r);
        }
        if (method === "DELETE") {
          const u = await requireAuth(request, env);
          const item = await sb(env, resource, "GET", `id=eq.${id}&limit=1`);
          if (!item.length) return json({ error: "Tidak ditemukan" }, 404);
          if (!canAccessVilla(u, item[0].villa_id)) return json({ error: "Forbidden" }, 403);
          if (resource === "gallery") {
            await sb(env, resource, "PATCH", `id=eq.${id}`, { is_active: false });
          } else {
            await sb(env, resource, "DELETE", `id=eq.${id}`);
          }
          return json({ success: true });
        }
      }

      // ── API: Global contacts ─────────────────────────────────────
      if (path === "/contacts/global") {
        if (method === "GET") { await requireAuth(request, env); return json(await sb(env, "contacts", "GET", "villa_id=is.null&order=created_at.asc")); }
        if (method === "POST") {
          await requireAuth(request, env);
          const b = body;
          if (!b.value||!b.type) return json({ error: "type dan value wajib diisi" }, 400);
          const r = await sb(env, "contacts", "POST", "", { villa_id:null, type:b.type, label:b.label||null, value:b.value, is_primary:b.is_primary??false });
          return json(r[0]||r, 201);
        }
      }
      const globalContactMatch = path.match(/^\/contacts\/global\/([^/]+)$/);
      if (globalContactMatch) {
        const id = globalContactMatch[1];
        if (method === "PATCH") {
          await requireAuth(request, env);
          const b = body;
          const r = await sb(env, "contacts", "PATCH", `id=eq.${id}&villa_id=is.null`, { type:b.type, label:b.label??null, value:b.value, is_primary:b.is_primary??false });
          return json(r[0]||r);
        }
        if (method === "DELETE") {
          await requireAuth(request, env);
          await sb(env, "contacts", "DELETE", `id=eq.${id}&villa_id=is.null`);
          return json({ success: true });
        }
      }

      // ── API: POST /inquiries (public, from villa form) ───────────
      if (method === "POST" && path === "/inquiries") {
        const b = body;
        if (!b.name || !b.phone) return json({ error: "Nama dan nomor telepon wajib diisi" }, 400);
        const r = await sb(env, "inquiries", "POST", "", { villa_id:b.villa_id||null, name:b.name, phone:b.phone, email:b.email||null, checkin_date:b.checkin_date||null, checkout_date:b.checkout_date||null, num_guests:b.num_guests||null, message:b.message||null, status:"pending" });
        return json(r[0]||r, 201);
      }

      // ── API: GET /inquiries ──────────────────────────────────────
      if (method === "GET" && path === "/inquiries") {
        const u = await requireAuth(request, env);
        let q = "select=*&order=created_at.desc";
        if (u.role !== "superadmin" && u.villa_id) q += `&villa_id=eq.${u.villa_id}`;
        if (url.searchParams.get("status")) q += `&status=eq.${url.searchParams.get("status")}`;
        return json(await sb(env, "inquiries", "GET", q));
      }

      // ── API: PATCH /inquiries/:id ────────────────────────────────
      const inqMatch = path.match(/^\/inquiries\/([^/]+)$/);
      if (inqMatch && method === "PATCH") {
        const u = await requireAuth(request, env);
        const id = inqMatch[1];
        const items = await sb(env, "inquiries", "GET", `id=eq.${id}&limit=1`);
        if (!items.length) return json({ error: "Tidak ditemukan" }, 404);
        if (!canAccessVilla(u, items[0].villa_id)) return json({ error: "Forbidden" }, 403);
        const b = body, upd = {};
        if ("status" in b) upd.status = b.status;
        if ("message" in b) upd.message = b.message;
        const r = await sb(env, "inquiries", "PATCH", `id=eq.${id}`, upd);
        return json(r[0]||r);
      }

      // ── API: Users ───────────────────────────────────────────────
      if (method === "GET" && path === "/users") {
        await requireSA(request, env);
        return json(await sb(env, "v_users", "GET", "select=id,username,email,role,villa_id,status,created_at,approved_at&order=created_at.desc"));
      }
      const userAction = path.match(/^\/users\/([^/]+)\/(approve|suspend|role)$/);
      if (userAction && method === "PATCH") {
        const u = await requireSA(request, env);
        const [, id, action] = userAction;
        let upd;
        if (action === "approve") upd = { status: "active", approved_at: new Date().toISOString(), approved_by: u.sub };
        else if (action === "suspend") upd = { status: "suspended" };
        else if (action === "role") { const b = body; if (!["admin","superadmin"].includes(b.role)) return json({error:"Role tidak valid"},400); upd = { role: b.role, villa_id: b.villa_id||null }; }
        const r = await sb(env, "v_users", "PATCH", `id=eq.${id}`, upd);
        return json(r[0]||r);
      }
      const userDel = path.match(/^\/users\/([^/]+)$/);
      if (userDel && method === "DELETE") {
        await requireSA(request, env);
        await sb(env, "v_users", "DELETE", `id=eq.${userDel[1]}`);
        return json({ success: true });
      }

      // ── API: POST /upload/github ─────────────────────────────────
      if (method === "POST" && path === "/upload/github") {
        const u = await requireAuth(request, env);
        const fd   = body; // FormData
        const file = fd.get("file");
        const villaId = fd.get("villa_id");
        const alt  = fd.get("alt") || "";
        if (!file)    return json({ error: "File tidak ada" }, 400);
        if (!villaId) return json({ error: "villa_id wajib diisi" }, 400);
        if (!canAccessVilla(u, villaId)) return json({ error: "Forbidden" }, 403);
        const ext  = (file.name?.split(".").pop() || "jpg").toLowerCase();
        const imgPath = `${env.GITHUB_IMG_PATH||"images/villas"}/${villaId}/${Date.now()}.${ext}`;
        const buf  = await file.arrayBuffer();
        const b64  = btoa(String.fromCharCode(...new Uint8Array(buf)));
        const ghRes = await fetch(`https://api.github.com/repos/${env.GITHUB_REPO}/contents/${imgPath}`, {
          method: "PUT",
          headers: { Authorization: `Bearer ${env.GITHUB_TOKEN}`, "Content-Type": "application/json", "User-Agent": "VillaWorker/1.0" },
          body: JSON.stringify({ message: `Upload ${imgPath}`, content: b64, branch: env.GITHUB_BRANCH||"main" }),
        });
        if (!ghRes.ok) return json({ error: `GitHub upload gagal: ${await ghRes.text()}` }, 500);
        const ghData = await ghRes.json();
        const rawUrl = ghData.content.download_url;
        const gallery = await sb(env, "gallery", "POST", "", { villa_id:villaId, url:rawUrl, alt, sort_order:0, is_active:true });
        return json({ url: rawUrl, gallery: gallery[0]||gallery }, 201);
      }

      // ── 404 ──────────────────────────────────────────────────────
      return json({ error: "Not found" }, 404);
    }

    try {
      const res = await run();
      return withCors(res);
    } catch (e) {
      if (e?.status) return withCors(json({ error: e.message }, e.status));
      console.error(e);
      return withCors(json({ error: "Internal server error" }, 500));
    }
  },
};
