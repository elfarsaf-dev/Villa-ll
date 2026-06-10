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
  <meta name="google-site-verification" content="oW9Fqr-5Hy84zT9hcd9At460aCcqaoWD9iSpre6tESU" />
  <meta content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no" name="viewport"/>
  <link rel="icon" href="https://cdn.jsdelivr.net/gh/SAFELFAR05/Up@main/images/villas/a1b2c3d4-e5f6-7890-abcd-ef1234567890/1778673470866.jpg" type="image/jpeg"/>
  <link rel="manifest" href="/manifest.json"/>
  <meta name="theme-color" content="#1e3a2f"/>
  <meta name="apple-mobile-web-app-capable" content="yes"/>
  <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent"/>
  <meta name="apple-mobile-web-app-title" content="Villa Tawangmangu"/>
  <link rel="apple-touch-icon" href="https://cdn.jsdelivr.net/gh/SAFELFAR05/Up@main/images/villas/a1b2c3d4-e5f6-7890-abcd-ef1234567890/1778673470866.jpg"/>
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
  const villaJson = JSON.stringify(villas.map(v => ({
    name: v.name,
    slug: v.slug,
    id: v.id,
    kapasitas: v.max_guests || null,
    tagline: v.tagline || null,
    desc: (v.description || "").slice(0, 250) || null,
    checkin: v.checkin_time || null,
    checkout: v.checkout_time || null,
    url: v.slug ? "/villa/" + encodeURIComponent(v.slug) : "/villa/?id=" + v.id,
  }))).replace(/<\/script>/gi, "<\\/script>");

  function villaCard(v) {
    const cover = coverMap[v.id];
    const waContact = contactMap[v.id] || globalWa;
    const location = [v.city, v.province].filter(Boolean).join(", ");
    const wa = waHref(waContact);
    const waNum = waContact?.value?.replace(/\D/g, "");
    const waLink = waNum ? `https://wa.me/62${waNum.replace(/^0/, "")}` : null;
    const href = v.slug ? `/villa/${encodeURIComponent(v.slug)}` : `/villa/?id=${v.id}`;
    return `<div class="villa-card">
      <a href="${href}" class="card-img block overflow-hidden" style="height:220px;">
        ${cover ? `<img src="${esc(cover.url)}" alt="${esc(cover.alt || v.name + ' Tawangmangu')}" class="w-full h-full object-cover"/>` : `<div class="w-full h-full bg-surface-container-highest flex items-center justify-center"><span class="material-symbols-outlined text-outline" style="font-size:56px;">villa</span></div>`}
      </a>
      <div class="card-body p-5">
        <div class="flex items-start justify-between gap-2 mb-2">
          <h3 class="card-title font-serif text-xl text-primary leading-snug">${esc(v.name)}</h3>
          ${location ? `<span class="text-[9px] tracking-widest uppercase text-secondary bg-surface-container px-2 py-1 rounded-full whitespace-nowrap">${esc(location)}</span>` : ""}
        </div>
        ${v.tagline ? `<p class="card-meta text-[0.8125rem] text-on-surface-variant leading-relaxed mb-1">${esc(v.tagline)}</p>` : ""}
        <div class="card-meta flex flex-wrap gap-3 text-[0.75rem] text-secondary mt-2 mb-4">
          ${v.max_guests ? `<span class="flex items-center gap-1"><span class="material-symbols-outlined" style="font-size:14px;">groups</span>Maks. ${esc(v.max_guests)} orang</span>` : ""}
          ${v.checkin_time ? `<span class="flex items-center gap-1"><span class="material-symbols-outlined" style="font-size:14px;">schedule</span>CI ${esc(v.checkin_time)}</span>` : ""}
        </div>
        <div class="flex gap-2">
          <a href="${href}" class="card-btn flex-1 text-center py-2.5 rounded-xl text-[0.8rem] font-semibold text-white" style="background:#1e3a2f;letter-spacing:0.05em;">Lihat Detail</a>
          ${waLink ? `<a href="${waLink}" target="_blank" rel="noopener" class="card-wa flex items-center gap-1.5 px-3.5 py-2.5 rounded-xl text-[0.8rem] font-semibold" style="background:#dcfce7;color:#166534;"><svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M17.472 14.382c-.297-.149-1.758-.867-2.03-.967-.273-.099-.471-.148-.67.15-.197.297-.767.966-.94 1.164-.173.199-.347.223-.644.075-.297-.15-1.255-.463-2.39-1.475-.883-.788-1.48-1.761-1.653-2.059-.173-.297-.018-.458.13-.606.134-.133.298-.347.446-.52.149-.174.198-.298.298-.497.099-.198.05-.371-.025-.52-.075-.149-.669-1.612-.916-2.207-.242-.579-.487-.5-.669-.51-.173-.008-.371-.01-.57-.01-.198 0-.52.074-.792.372-.272.297-1.04 1.016-1.04 2.479 0 1.462 1.065 2.875 1.213 3.074.149.198 2.096 3.2 5.077 4.487.709.306 1.262.489 1.694.625.712.227 1.36.195 1.871.118.571-.085 1.758-.719 2.006-1.413.248-.694.248-1.289.173-1.413-.074-.124-.272-.198-.57-.347m-5.421 7.403h-.004a9.87 9.87 0 01-5.031-1.378l-.361-.214-3.741.982.998-3.648-.235-.374a9.86 9.86 0 01-1.51-5.26c.001-5.45 4.436-9.884 9.888-9.884 2.64 0 5.122 1.03 6.988 2.898a9.825 9.825 0 012.893 6.994c-.003 5.45-4.437 9.884-9.885 9.884m8.413-18.297A11.815 11.815 0 0012.05 0C5.495 0 .16 5.335.157 11.892c0 2.096.547 4.142 1.588 5.945L.057 24l6.305-1.654a11.882 11.882 0 005.683 1.448h.005c6.554 0 11.89-5.335 11.893-11.893a11.821 11.821 0 00-3.48-8.413z"/></svg>WA</a>` : ""}
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
  <meta property="og:url" content="https://tawangmangu.biz.id/"/>
  <meta property="og:site_name" content="Villa Tawangmangu"/>
  <meta property="og:image" content="https://cdn.jsdelivr.net/gh/SAFELFAR05/Up@main/images/villas/a1b2c3d4-e5f6-7890-abcd-ef1234567890/1778407511114.jpg"/><meta property="og:image:width" content="1200"/><meta property="og:image:height" content="630"/>
  <meta name="twitter:card" content="summary_large_image"/>
  <link rel="canonical" href="https://tawangmangu.biz.id/"/>
  <meta name="robots" content="index, follow"/>
  <link rel="manifest" href="/manifest.json"/>
  <meta name="theme-color" content="#1e3a2f"/>
  <meta name="apple-mobile-web-app-capable" content="yes"/>
  <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent"/>
  <meta name="apple-mobile-web-app-title" content="Villa Tawangmangu"/>
  <link rel="apple-touch-icon" href="https://cdn.jsdelivr.net/gh/SAFELFAR05/Up@main/images/villas/a1b2c3d4-e5f6-7890-abcd-ef1234567890/1778407511114.jpg"/>
  <script type="application/ld+json">${JSON.stringify({
    "@context":"https://schema.org",
    "@type":"WebSite",
    "name":"Villa Tawangmangu",
    "url":"https://tawangmangu.biz.id",
    "description":"Sewa villa eksklusif di Sekipan, Tawangmangu, Karanganyar. Kolam renang privat, pemandangan pegunungan.",
    "potentialAction":{"@type":"SearchAction","target":"https://tawangmangu.biz.id/#villas","query-input":"required name=search_term_string"}
  })}</script>
  ${villas.length?`<script type="application/ld+json">${JSON.stringify({
    "@context":"https://schema.org",
    "@type":"ItemList",
    "name":"Daftar Villa Tawangmangu",
    "url":"https://tawangmangu.biz.id",
    "itemListElement":villas.filter(v=>v.slug).map((v,i)=>({
      "@type":"ListItem",
      "position":i+1,
      "url":`https://tawangmangu.biz.id/villa/${encodeURIComponent(v.slug)}`,
      "name":v.name
    }))
  })}</script>`:``}
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
    @media(max-width:767px){
      .villa-card{border-radius:12px}
      .villa-card .card-img{height:140px!important}
      .villa-card .card-body{padding:10px!important}
      .villa-card .card-title{font-size:0.9rem!important}
      .villa-card .card-meta{display:none}
      .villa-card .card-btn{padding:7px 6px!important;font-size:0.72rem!important;border-radius:10px!important}
      .villa-card .card-wa{padding:7px 8px!important;font-size:0.72rem!important;border-radius:10px!important}
    }
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
    <a href="/" class="flex items-center gap-2.5" id="nav-brand">
        <img src="https://cdn.jsdelivr.net/gh/SAFELFAR05/Up@main/images/villas/a1b2c3d4-e5f6-7890-abcd-ef1234567890/1778673470866.jpg" alt="Logo Villa Tawangmangu" style="width:36px;height:36px;object-fit:cover;border-radius:50%;border:2px solid rgba(255,255,255,0.4);flex-shrink:0;"/>
        <span class="font-serif text-lg tracking-widest text-white font-bold">VILLA TAWANGMANGU</span>
      </a>
    <a href="/admin" class="text-[10px] tracking-widest uppercase font-semibold text-white/60 hover:text-white transition-colors flex items-center gap-1.5">
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
    <div class="grid grid-cols-2 md:grid-cols-2 lg:grid-cols-3 gap-3 md:gap-6">${cards}</div>
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
    <a href="/admin" class="text-[10px] tracking-widest uppercase text-on-surface-variant hover:text-primary transition-colors flex items-center gap-1"><span class="material-symbols-outlined" style="font-size:14px">settings</span>Admin Dashboard</a>
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

<!-- ── AI Chat Widget ────────────────────────────────────────── -->
<style>
  #ai-fab{position:fixed;bottom:24px;right:24px;z-index:9999;background:#1e3a2f;color:#fff;border:none;border-radius:50px;padding:11px 18px;display:flex;align-items:center;gap:8px;font-size:0.825rem;font-weight:600;cursor:pointer;box-shadow:0 4px 20px rgba(30,58,47,.4);transition:transform .2s,box-shadow .2s;font-family:"Plus Jakarta Sans",sans-serif;letter-spacing:.01em}
  #ai-fab:hover{transform:translateY(-2px);box-shadow:0 8px 28px rgba(30,58,47,.5)}
  #ai-fab svg{flex-shrink:0}
  #ai-panel{position:fixed;bottom:80px;right:24px;z-index:9998;
width:360px;
max-width:calc(100vw - 32px);
height:520px;
max-height:calc(100dvh - 100px);background:#fff;border-radius:20px;box-shadow:0 8px 48px rgba(0,0,0,.18);display:flex;flex-direction:column;overflow:hidden;transition:opacity .25s,transform .25s,visibility .25s;opacity:0;transform:translateY(14px) scale(.97);pointer-events:none;visibility:hidden}
  #ai-panel.open{opacity:1;transform:translateY(0) scale(1);pointer-events:auto;visibility:visible}
  #ai-chat-hd{background:#1e3a2f;padding:13px 14px;display:flex;align-items:center;justify-content:space-between;gap:10px;flex-shrink:0}
  #ai-msgs{flex:1 1 0;min-height:0;overflow-y:auto;padding:12px;display:flex;flex-direction:column;gap:9px;
overscroll-behavior:contain;-webkit-overflow-scrolling:touch;touch-action:pan-y}
  #ai-msgs::-webkit-scrollbar{width:4px}#ai-msgs::-webkit-scrollbar-thumb{background:#e2e8f0;border-radius:2px}
  .ai-b{padding:9px 12px;border-radius:14px;font-size:0.8rem;line-height:1.6;max-width:88%;word-break:break-word;font-family:"Plus Jakarta Sans",sans-serif}
  .ai-b.bot{background:#f1f5f9;color:#1e293b;align-self:flex-start;border-bottom-left-radius:4px}
  .ai-b.usr{background:#1e3a2f;color:#fff;align-self:flex-end;border-bottom-right-radius:4px}
  .ai-b a{color:#1e6e4a;font-weight:600;text-decoration:underline}
  #ai-typing{flex-shrink:0;padding:6px 12px 2px;display:none;align-items:center;gap:3px}
  .ai-dot{width:6px;height:6px;border-radius:50%;background:#94a3b8;display:inline-block;animation:aiDot 1.2s infinite}
  .ai-dot:nth-child(2){animation-delay:.2s}.ai-dot:nth-child(3){animation-delay:.4s}
  @keyframes aiDot{0%,80%,100%{transform:scale(.6);opacity:.4}40%{transform:scale(1);opacity:1}}
  #ai-iw{padding:9px 10px;border-top:1px solid #f1f5f9;display:flex;gap:7px;background:#fff;flex-shrink:0}
  #ai-in{flex:1;border:1.5px solid #e2e8f0;border-radius:10px;padding:8px 11px;font-size:0.8rem;outline:none;font-family:inherit;transition:border .15s}
  #ai-in:focus{border-color:#1e3a2f}
  #ai-go{background:#1e3a2f;color:#fff;border:none;border-radius:10px;width:34px;height:34px;display:flex;align-items:center;justify-content:center;cursor:pointer;flex-shrink:0;transition:opacity .15s}
  #ai-go:disabled{opacity:.4;cursor:not-allowed}
  @media(max-width:440px){#ai-panel{right:12px;width:calc(100vw - 24px)}#ai-fab{bottom:16px;right:16px}}
</style>

<button id="ai-fab" onclick="aiToggle()">
  <svg width="17" height="17" viewBox="0 0 24 24" fill="currentColor"><path d="M20 2H4c-1.1 0-2 .9-2 2v18l4-4h14c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zm-2 12H6v-2h12v2zm0-3H6V9h12v2zm0-3H6V6h12v2z"/></svg>
  Tanya AI
</button>

<div id="ai-panel">
  <div id="ai-chat-hd">
    <div style="display:flex;align-items:center;gap:9px">
      <div style="width:8px;height:8px;border-radius:50%;background:#4ade80;flex-shrink:0;box-shadow:0 0 6px #4ade8088"></div>
      <div>
        <div style="color:#fff;font-weight:700;font-size:0.85rem;font-family:Plus Jakarta Sans,sans-serif">Asisten Villa AI</div>
        <div style="color:rgba(255,255,255,.6);font-size:0.68rem;font-family:Plus Jakarta Sans,sans-serif">Cari villa yang pas untuk kamu</div>
      </div>
    </div>
    <button onclick="aiToggle()" style="background:rgba(255,255,255,.12);border:none;border-radius:8px;width:28px;height:28px;color:#fff;cursor:pointer;font-size:15px;display:flex;align-items:center;justify-content:center">✕</button>
  </div>
  <div id="ai-msgs"></div>
  <div id="ai-typing"><span class="ai-dot"></span><span class="ai-dot"></span><span class="ai-dot"></span></div>
  <div id="ai-iw">
    <input id="ai-in" placeholder="Cth: villa untuk 30 orang…"/>
    <button id="ai-go" onclick="aiSend()"><svg width="15" height="15" viewBox="0 0 24 24" fill="currentColor"><path d="M2.01 21L23 12 2.01 3 2 10l15 2-15 2z"/></svg></button>
  </div>
</div>

<script>
var __V=${villaJson};
var _aiHist=[];
var _aiOpen=false;

function aiPrompt(){
  var rows=__V.map(function(v,i){
    var s=(i+1)+'. '+v.name;
    if(v.kapasitas) s+=' | Kapasitas: '+v.kapasitas+' orang';
    if(v.tagline)   s+=' | '+v.tagline;
    if(v.checkin)   s+=' | Check-in: '+v.checkin;
    if(v.checkout)  s+=' | Check-out: '+v.checkout;
    if(v.desc)      s+=' | Info: '+v.desc;
    s+=' | Link: '+location.origin+v.url;
    return s;
  }).join('\\n');
  return 'Kamu adalah asisten AI ramah untuk Villa Tawangmangu.\\n\\nDATA VILLA:\\n'+rows+'\\n\\nATURAN:\\n- Jawab bahasa Indonesia yang ramah\\n- Rekomendasikan villa sesuai kebutuhan (kapasitas, dll)\\n- Sertakan link: [Nama Villa](url)\\n- Jangan mengarang info selain dari data\\n- WAJIB: Dalam setiap respons, selalu sebut "Villa Tawangmangu" atau "Glamping Tawangmangu" minimal satu kali di deskripsi atau rekomendasimu (contoh: "Di Villa Tawangmangu kami memiliki...")\\n- WAJIB: Akhiri setiap respons dengan kalimat penutup yang menyebut Villa Tawangmangu atau Glamping Tawangmangu';
}

function aiBubble(type, txt){
  var w=document.getElementById('ai-msgs');
  var d=document.createElement('div');
  d.className='ai-b '+type;
  var s=txt
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/villa tawangmangu/gi,'<a href="https://bosvillatawangmangu.my.id" target="_blank" rel="noopener" style="color:#1e6e4a;font-weight:600">Villa Tawangmangu</a>')
    .replace(/glamping tawangmangu/gi,'<a href="https://bosvillatawangmangu.my.id" target="_blank" rel="noopener" style="color:#1e6e4a;font-weight:600">Glamping Tawangmangu</a>')
    .replace(/\\[([^\\]]+)\\]\\(([^)]+)\\)/g,'<a href="$2" target="_blank" rel="noopener">$1</a>')
    .replace(/\\*\\*([^*]+)\\*\\*/g,'<strong>$1</strong>')
    .replace(/\\n/g,'<br>');
  d.innerHTML=s;
  w.appendChild(d);
  w.scrollTop=w.scrollHeight;
}

function aiToggle(){
  _aiOpen=!_aiOpen;
  var panel=document.getElementById('ai-panel');
  if(!panel) return;
  panel.classList.toggle('open',_aiOpen);
  if(_aiOpen){
    try{
      var msgs=document.getElementById('ai-msgs');
      if(msgs && msgs.children.length===0){
        var names=(Array.isArray(__V)?__V:[]).map(function(v){return v.name+(v.kapasitas?' ('+v.kapasitas+' org)':'');}).join(', ');
        aiBubble('bot','Halo! Saya asisten AI Villa Tawangmangu.\\n\\nVilla tersedia: '+(names||'—')+'\\n\\nContoh pertanyaan:\\n- Villa untuk 30 orang\\n- Villa dengan kolam renang\\n- Rekomendasi villa gathering');
      }
      setTimeout(function(){var inp=document.getElementById('ai-in');if(inp)inp.focus();},150);
    }catch(e){}
  }
}

async function aiSend(){
  var inp=document.getElementById('ai-in');
  var msg=inp.value.trim();
  if(!msg) return;
  inp.value='';
  document.getElementById('ai-go').disabled=true;
  aiBubble('usr',msg);
  var typing=document.getElementById('ai-typing');
  typing.style.display='flex';
  document.getElementById('ai-msgs').scrollTop=99999;

  var prevHist=_aiHist.slice();
  _aiHist.push({role:'user',content:msg});

  try{
    var p=new URLSearchParams({
      message:msg,
      logic:aiPrompt(),
      memory:JSON.stringify(prevHist.slice(-8))
    });
    var res=await fetch('/ai?'+p);
    var data=await res.json();
    var reply=data.reply||'Maaf, tidak dapat merespons saat ini.';
    typing.style.display='none';
    aiBubble('bot',reply);
    _aiHist.push({role:'assistant',content:reply});
    if(_aiHist.length>16) _aiHist=_aiHist.slice(-16);
  }catch(e){
    typing.style.display='none';
    aiBubble('bot','Maaf, ada gangguan. Coba lagi ya!');
  }
  document.getElementById('ai-go').disabled=false;
  inp.focus();
}

document.getElementById('ai-in').addEventListener('keydown',function(e){
  if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();aiSend();}
});

(function(){
  var panel=document.getElementById('ai-panel');
  if(!panel) return;
  panel.addEventListener('touchmove',function(e){
    if(e.touches.length>1) return;
    var msgs=document.getElementById('ai-msgs');
    if(msgs&&msgs.contains(e.target)){
      var dy=e.touches[0].clientY-(panel._sy||0);
      var atTop=msgs.scrollTop<=0;
      var atBot=msgs.scrollTop+msgs.clientHeight>=msgs.scrollHeight-1;
      if(!((atTop&&dy>0)||(atBot&&dy<0))) return;
    }
    e.preventDefault();
  },{passive:false});
  panel.addEventListener('touchstart',function(e){
    panel._sy=e.touches[0].clientY;
  },{passive:true});
})();
</script>
<script>if('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js');</script>
</body></html>`;
}

// ── SSR: Villa detail page ────────────────────────────────────────────────────
function renderVillaPage(v, facilities, gallery, policies, contacts, similarVillas = []) {
  const location    = [v.address, v.city, v.province].filter(Boolean).join(", ");
  const waContact   = contacts.find(c => c.type === "whatsapp" && c.is_primary) || contacts.find(c => c.type === "whatsapp");
  const phoneContact = contacts.find(c => c.type === "phone");
  const wa          = waHref(waContact);
  const contactNum  = waContact?.value || phoneContact?.value;
  const year        = new Date().getFullYear();
  const price       = v.extra_bed_price ? new Intl.NumberFormat("id-ID").format(v.extra_bed_price) : null;

  const slides = gallery.slice(0, 5);
  const heroSlides = slides.length
    ? slides.map((img, i) => `<div class="flex-none w-full h-full snap-start relative"><img class="w-full h-full object-cover" src="${esc(img.url)}" alt="${esc(img.alt||v.name+' — Tawangmangu')}" ${i>0?'loading="lazy"':""}/><div class="absolute inset-0 bg-gradient-to-b from-black/40 via-black/10 to-black/70"></div></div>`).join("")
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

  const linkVT = s => s
    .replace(/villa tawangmangu/gi, '<a href="https://bosvillatawangmangu.my.id" target="_blank" rel="noopener" style="color:#1e6e4a;font-weight:600;text-decoration:underline">Villa Tawangmangu</a>')
    .replace(/glamping tawangmangu/gi, '<a href="https://bosvillatawangmangu.my.id" target="_blank" rel="noopener" style="color:#1e6e4a;font-weight:600;text-decoration:underline">Glamping Tawangmangu</a>');
  const descHtml = (v.description || v.tagline || "")
    .split("\n").filter(Boolean).map(p => `<p>${linkVT(esc(p))}</p>`).join("") || `<p>${linkVT(esc(v.tagline || ""))}</p>`;

  const facilitiesHtml = facilities.length
    ? facilities.map(f => `<div class="bg-white rounded-xl p-5 flex flex-col items-center text-center hover:shadow-md transition-shadow"><span class="material-symbols-outlined text-primary mb-3" style="font-size:30px">${esc(f.icon||"star")}</span><h5 class="text-[10px] tracking-widest uppercase font-semibold text-primary mb-2">${esc(f.name)}</h5><p class="text-[0.75rem] text-on-surface-variant leading-relaxed">${esc(f.description||"")}</p></div>`).join("")
    : `<div class="col-span-4 text-center py-10 text-on-surface-variant text-sm">Belum ada fasilitas.</div>`;

  const galleryHtml = !gallery.length
    ? `<div class="col-span-3 text-center py-16 text-on-surface-variant"><span class="material-symbols-outlined text-4xl mb-3 block opacity-40">photo_library</span><p class="text-sm">Foto galeri akan segera hadir.</p></div>`
    : gallery.map((img, i) => {
        const cls = i===0 ? "col-span-2 md:col-span-1 md:row-span-2" : (i===gallery.length-1&&gallery.length%2===0?"col-span-2":"");
        const h   = i===0 ? "h-60 md:h-full" : "h-52";
        return `<div class="img-zoom overflow-hidden rounded-xl ${cls}"><img src="${esc(img.url)}" alt="${esc(img.alt||v.name+' — Tawangmangu')}" class="w-full ${h} object-cover" loading="lazy"/></div>`;
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
  <title>${esc(v.tagline || v.name)} — Villa Tawangmangu</title>
  <meta name="description" content="${esc(v.tagline||v.description||"Sewa villa eksklusif di Tawangmangu")}"/>
  <meta name="keywords" content="villa tawangmangu, ${esc(v.name)}, sewa villa tawangmangu, villa sekipan"/>
  <meta property="og:title" content="${esc(v.tagline || v.name)} — Villa Tawangmangu"/>
  <meta property="og:description" content="${esc(v.tagline||v.description||"")}"/>
  <meta property="og:type" content="website"/>
  <meta property="og:url" content="https://tawangmangu.biz.id/villa/${esc(v.slug||"")}"/>
  <meta property="og:site_name" content="Villa Tawangmangu"/>
  ${gallery[0]?`<meta property="og:image" content="${esc(gallery[0].url)}"/><meta property="og:image:width" content="1200"/><meta property="og:image:height" content="630"/>`:``}
  <meta name="twitter:card" content="summary_large_image"/>
  <meta name="twitter:title" content="${esc(v.tagline || v.name)} — Villa Tawangmangu"/>
  <meta name="twitter:description" content="${esc(v.tagline||v.description||"")}"/>
  ${gallery[0]?`<meta name="twitter:image" content="${esc(gallery[0].url)}"/>`:``}
  <link rel="canonical" href="https://tawangmangu.biz.id/villa/${esc(v.slug||"")}"/>
  <meta name="robots" content="index, follow"/>
  <script type="application/ld+json">${JSON.stringify({
    "@context":"https://schema.org",
    "@type":"LodgingBusiness",
    "name":v.name,
    "description":v.description||v.tagline||"",
    "url":`https://tawangmangu.biz.id/villa/${v.slug||""}`,
    ...(gallery[0]?{"image":gallery[0].url}:{}),
    ...(contactNum?{"telephone":contactNum}:{}),
    "address":{
      "@type":"PostalAddress",
      ...(v.address?{"streetAddress":v.address}:{}),
      ...(v.city?{"addressLocality":v.city}:{}),
      ...(v.province?{"addressRegion":v.province}:{}),
      "addressCountry":"ID"
    },
    ...(v.max_guests?{"amenityFeature":[{"@type":"LocationFeatureSpecification","name":"Kapasitas Tamu","value":`${v.max_guests} orang`}]}:{}),
    ...(facilities.length?{"amenityFeature":facilities.map(f=>({
      "@type":"LocationFeatureSpecification",
      "name":f.name,
      "value":f.description||true
    }))}:{})
  })}</script>
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
    <a href="/" class="flex items-center gap-2.5" id="nav-logo">
        <img src="https://cdn.jsdelivr.net/gh/SAFELFAR05/Up@main/images/villas/a1b2c3d4-e5f6-7890-abcd-ef1234567890/1778673470866.jpg" alt="Logo" style="width:36px;height:36px;object-fit:cover;border-radius:50%;border:2px solid rgba(255,255,255,0.4);flex-shrink:0;"/>
        <span class="font-serif text-lg tracking-widest text-white">${esc((v.name||"VILLA TAWANGMANGU").toUpperCase())}</span>
      </a>
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
<section class="py-10 px-6" style="background:#f0f4f0">
  <div class="max-w-2xl mx-auto text-center">
    <p class="text-[10px] tracking-[0.2em] uppercase font-semibold text-secondary mb-4">Bagikan Villa Ini</p>
    <div class="flex flex-wrap items-center justify-center gap-3" id="share-buttons">
      <a id="share-wa" href="#" target="_blank" rel="noopener"
        class="inline-flex items-center gap-2 px-5 py-2.5 rounded-full text-sm font-semibold text-white transition-transform hover:scale-105"
        style="background:#25D366">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M17.472 14.382c-.297-.149-1.758-.867-2.03-.967-.273-.099-.471-.148-.67.15-.197.297-.767.966-.94 1.164-.173.199-.347.223-.644.075-.297-.15-1.255-.463-2.39-1.475-.883-.788-1.48-1.761-1.653-2.059-.173-.297-.018-.458.13-.606.134-.133.298-.347.446-.52.149-.174.198-.298.298-.497.099-.198.05-.371-.025-.52-.075-.149-.669-1.612-.916-2.207-.242-.579-.487-.5-.669-.51-.173-.008-.371-.01-.57-.01-.198 0-.52.074-.792.372-.272.297-1.04 1.016-1.04 2.479 0 1.462 1.065 2.875 1.213 3.074.149.198 2.096 3.2 5.077 4.487.709.306 1.262.489 1.694.625.712.227 1.36.195 1.871.118.571-.085 1.758-.719 2.006-1.413.248-.694.248-1.289.173-1.413-.074-.124-.272-.198-.57-.347m-5.421 7.403h-.004a9.87 9.87 0 01-5.031-1.378l-.361-.214-3.741.982.998-3.648-.235-.374a9.86 9.86 0 01-1.51-5.26c.001-5.45 4.436-9.884 9.888-9.884 2.64 0 5.122 1.03 6.988 2.898a9.825 9.825 0 012.893 6.994c-.003 5.45-4.437 9.884-9.885 9.884m8.413-18.297A11.815 11.815 0 0012.05 0C5.495 0 .16 5.335.157 11.892c0 2.096.547 4.142 1.588 5.945L.057 24l6.305-1.654a11.882 11.882 0 005.683 1.448h.005c6.554 0 11.89-5.335 11.893-11.893a11.821 11.821 0 00-3.48-8.413z"/></svg>
        WhatsApp
      </a>
      <a id="share-fb" href="#" target="_blank" rel="noopener"
        class="inline-flex items-center gap-2 px-5 py-2.5 rounded-full text-sm font-semibold text-white transition-transform hover:scale-105"
        style="background:#1877F2">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M24 12.073c0-6.627-5.373-12-12-12s-12 5.373-12 12c0 5.99 4.388 10.954 10.125 11.854v-8.385H7.078v-3.47h3.047V9.43c0-3.007 1.792-4.669 4.533-4.669 1.312 0 2.686.235 2.686.235v2.953H15.83c-1.491 0-1.956.925-1.956 1.874v2.25h3.328l-.532 3.47h-2.796v8.385C19.612 23.027 24 18.062 24 12.073z"/></svg>
        Facebook
      </a>
      <a id="share-x" href="#" target="_blank" rel="noopener"
        class="inline-flex items-center gap-2 px-5 py-2.5 rounded-full text-sm font-semibold text-white transition-transform hover:scale-105"
        style="background:#000">
        <svg width="15" height="15" viewBox="0 0 24 24" fill="currentColor"><path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-4.714-6.231-5.401 6.231H2.746l7.73-8.835L1.254 2.25H8.08l4.253 5.622zm-1.161 17.52h1.833L7.084 4.126H5.117z"/></svg>
        X / Twitter
      </a>
      <button id="copy-link"
        class="inline-flex items-center gap-2 px-5 py-2.5 rounded-full text-sm font-semibold transition-transform hover:scale-105"
        style="background:#e0e4e0;color:#191d1a">
        <span class="material-symbols-outlined" style="font-size:16px">link</span>
        Salin Link
      </button>
    </div>
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
${similarVillas.length ? `
<section id="villa-serupa" class="py-20 px-6 bg-surface">
  <div class="max-w-6xl mx-auto">
    <div class="text-center mb-12">
      <span class="text-[10px] tracking-[0.2em] uppercase font-semibold text-secondary block mb-3">Rekomendasi</span>
      <h2 class="font-serif text-3xl text-primary">Villa Serupa yang Mungkin Anda Suka</h2>
      <p class="text-on-surface-variant text-sm mt-3 max-w-md mx-auto">Villa lain di Tawangmangu dengan kapasitas dan fasilitas serupa</p>
      <div class="flex items-center justify-center mt-4"><div class="w-12 h-[1px] bg-outline-variant"></div><div class="w-1.5 h-1.5 rounded-full bg-primary/30 mx-3"></div><div class="w-12 h-[1px] bg-outline-variant"></div></div>
    </div>
    <div class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3 md:gap-5">
      ${similarVillas.map(sv => {
        const href = `/villa/${encodeURIComponent(sv.slug)}`;
        const loc  = [sv.city, sv.province].filter(Boolean).join(", ");
        return `<a href="${href}" class="sim-card group bg-white rounded-2xl overflow-hidden border border-outline-variant hover:shadow-lg transition-all duration-300 hover:-translate-y-1 block">
          <div class="overflow-hidden" style="height:140px">
            ${sv.cover
              ? `<img src="${esc(sv.cover.url)}" alt="${esc(sv.cover.alt || sv.name + ' Tawangmangu')}" class="w-full h-full object-cover transition-transform duration-500 group-hover:scale-105"/>`
              : `<div class="w-full h-full bg-surface-container-highest flex items-center justify-center"><span class="material-symbols-outlined text-outline" style="font-size:40px">villa</span></div>`}
          </div>
          <div class="p-4">
            <h3 class="font-serif text-[0.9375rem] text-primary leading-snug mb-1 line-clamp-1">${esc(sv.name)}</h3>
            ${loc ? `<p class="text-[0.7rem] text-secondary tracking-wide mb-2">${esc(loc)}</p>` : ""}
            <div class="flex items-center gap-3 text-[0.72rem] text-on-surface-variant">
              ${sv.max_guests ? `<span class="flex items-center gap-1"><span class="material-symbols-outlined" style="font-size:12px">groups</span>Maks. ${esc(String(sv.max_guests))} orang</span>` : ""}
            </div>
            ${sv.tagline ? `<p class="text-[0.75rem] text-on-surface-variant mt-2 line-clamp-2 leading-relaxed">${esc(sv.tagline)}</p>` : ""}
            <div class="mt-3 text-[0.75rem] font-semibold text-primary flex items-center gap-1">Lihat Detail <span class="material-symbols-outlined" style="font-size:14px">arrow_forward</span></div>
          </div>
        </a>`;
      }).join("")}
    </div>
    <div class="text-center mt-10">
      <a href="/" class="inline-flex items-center gap-2 px-6 py-3 rounded-full border border-primary/30 text-primary text-sm font-semibold hover:bg-primary hover:text-white transition-all duration-200">
        <span class="material-symbols-outlined" style="font-size:18px">villa</span>Lihat Semua Villa
      </a>
    </div>
  </div>
</section>` : ""}
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
// ── Share buttons ──────────────────────────────────────────────
(function(){
  const pageUrl = encodeURIComponent("https://tawangmangu.biz.id/villa/${esc(v.slug||"")}");
  const pageTitle = encodeURIComponent("${esc(v.name)} — Villa Tawangmangu");
  const shareText = encodeURIComponent("Cek villa keren ini di Tawangmangu: ${esc(v.name)}");
  document.getElementById('share-wa').href = "https://api.whatsapp.com/send?text="+shareText+"%20"+pageUrl;
  document.getElementById('share-fb').href = "https://www.facebook.com/sharer/sharer.php?u="+pageUrl;
  document.getElementById('share-x').href  = "https://twitter.com/intent/tweet?text="+shareText+"&url="+pageUrl;
  document.getElementById('copy-link').addEventListener('click',function(){
    navigator.clipboard.writeText(decodeURIComponent(pageUrl)).then(()=>{
      this.innerHTML='<span class="material-symbols-outlined" style="font-size:16px">check</span> Tersalin!';
      setTimeout(()=>{this.innerHTML='<span class="material-symbols-outlined" style="font-size:16px">link</span> Salin Link';},2500);
    });
  });
})();
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
<script>if('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js');</script>
</body></html>`;
}

// ── Main router ───────────────────────────────────────────────────────────────
// ── Admin Dashboard HTML (embedded) ─────────────────────────────────────────
const ADMIN_HTML = `<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Admin Dashboard — Villa</title>
  <link rel="icon" href="https://cdn.jsdelivr.net/gh/SAFELFAR05/Up@main/images/villas/a1b2c3d4-e5f6-7890-abcd-ef1234567890/1778673470866.jpg" type="image/jpeg"/>
  <link rel="manifest" href="/manifest.json"/>
  <meta name="theme-color" content="#1e3a2f"/>
  <meta name="apple-mobile-web-app-capable" content="yes"/>
  <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent"/>
  <meta name="apple-mobile-web-app-title" content="Admin Villa"/>
  <link rel="apple-touch-icon" href="https://cdn.jsdelivr.net/gh/SAFELFAR05/Up@main/images/villas/a1b2c3d4-e5f6-7890-abcd-ef1234567890/1778673470866.jpg"/>
  <script src="https://cdn.tailwindcss.com"></script>
  <link href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap" rel="stylesheet"/>
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap" rel="stylesheet"/>
  <style>
    * { font-family: 'Plus Jakarta Sans', sans-serif; }
    .material-symbols-outlined { font-variation-settings: 'FILL' 0,'wght' 300,'GRAD' 0,'opsz' 24; font-size: 20px; vertical-align: middle; }
    .icon-fill { font-variation-settings: 'FILL' 1,'wght' 400,'GRAD' 0,'opsz' 24; }
    ::-webkit-scrollbar { width: 5px; height: 5px; }
    ::-webkit-scrollbar-track { background: #f1f5f9; }
    ::-webkit-scrollbar-thumb { background: #cbd5e1; border-radius: 3px; }
    .sidebar-link { display: flex; align-items: center; gap: 10px; padding: 9px 14px; border-radius: 8px; cursor: pointer; font-size: 0.875rem; font-weight: 500; color: #475569; transition: all 0.15s; white-space: nowrap; }
    .sidebar-link:hover { background: #f1f5f9; color: #1e293b; }
    .sidebar-link.active { background: #1e3a2f; color: #fff; }
    .badge { display: inline-flex; align-items: center; padding: 2px 8px; border-radius: 20px; font-size: 0.7rem; font-weight: 600; }
    .badge-pending  { background:#fef9c3; color:#854d0e; }
    .badge-active   { background:#dcfce7; color:#166534; }
    .badge-suspended{ background:#fee2e2; color:#991b1b; }
    .badge-confirmed{ background:#dbeafe; color:#1e40af; }
    .badge-replied  { background:#ede9fe; color:#5b21b6; }
    .badge-cancelled{ background:#f1f5f9; color:#64748b; }
    .btn { display:inline-flex;align-items:center;gap:6px;padding:8px 16px;border-radius:8px;font-size:0.8125rem;font-weight:600;cursor:pointer;transition:all .15s;border:none; }
    .btn-primary { background:#1e3a2f;color:#fff; }
    .btn-primary:hover { background:#2d4f3f; }
    .btn-danger  { background:#fee2e2;color:#991b1b; }
    .btn-danger:hover { background:#fecaca; }
    .btn-ghost   { background:#f1f5f9;color:#475569; }
    .btn-ghost:hover { background:#e2e8f0; }
    .btn-sm { padding:5px 10px;font-size:0.75rem; }
    input, textarea, select { border:1.5px solid #e2e8f0;border-radius:8px;padding:9px 12px;font-size:0.875rem;width:100%;outline:none;transition:border .15s;background:#fff; }
    input:focus, textarea:focus, select:focus { border-color:#1e3a2f; }
    label { font-size:0.75rem;font-weight:600;color:#64748b;display:block;margin-bottom:5px; }
    .card { background:#fff;border-radius:12px;border:1px solid #f1f5f9;box-shadow:0 1px 3px rgba(0,0,0,0.06); }
    table { width:100%;border-collapse:collapse; }
    th { text-align:left;font-size:0.7rem;font-weight:600;color:#94a3b8;text-transform:uppercase;letter-spacing:.08em;padding:10px 14px;border-bottom:1.5px solid #f1f5f9; }
    td { padding:10px 14px;font-size:0.8125rem;color:#334155;border-bottom:1px solid #f8fafc;vertical-align:middle; }
    tr:hover td { background:#f8fafc; }
    .modal-bg { position:fixed;inset:0;background:rgba(0,0,0,0.4);z-index:100;display:flex;align-items:flex-end;justify-content:center;padding:0; }
    .modal { background:#fff;border-radius:20px 20px 0 0;max-width:100%;width:100%;max-height:92vh;overflow-y:auto;padding:24px 20px 32px; }
    .toast { position:fixed;bottom:20px;left:50%;transform:translateX(-50%) translateY(8px);padding:11px 18px;border-radius:10px;font-size:0.8125rem;font-weight:600;z-index:200;opacity:0;transition:all .3s;pointer-events:none;white-space:nowrap;max-width:90vw;text-align:center; }
    .toast.show { transform:translateX(-50%) translateY(0);opacity:1; }
    .toast-success { background:#dcfce7;color:#166534;border:1px solid #bbf7d0; }
    .toast-error   { background:#fee2e2;color:#991b1b;border:1px solid #fecaca; }
    @keyframes spin { to { transform: rotate(360deg); } }

    /* ── Mobile sidebar drawer ─────────────────────────────────────── */
    #sidebar-overlay { display:none;position:fixed;inset:0;background:rgba(0,0,0,0.45);z-index:39;backdrop-filter:blur(1px); }
    #sidebar-overlay.show { display:block; }

    @media (max-width: 767px) {
      #sidebar {
        position: fixed; top: 0; left: -100%; width: 80%; max-width: 264px;
        height: 100dvh; z-index: 40; transition: left 0.25s cubic-bezier(.4,0,.2,1);
        box-shadow: 4px 0 24px rgba(0,0,0,0.12);
      }
      #sidebar.open { left: 0; }
      #mobile-topbar { display: flex !important; }
      #section-content { padding: 12px 10px 80px !important; }
      .modal { border-radius: 20px 20px 0 0; max-height: 88vh; }
      th { padding: 7px 8px !important; font-size: 0.67rem !important; }
      td { padding: 7px 8px !important; font-size: 0.74rem !important; }
      .hide-mobile { display: none !important; }
      .btn-sm { padding: 4px 7px !important; font-size: 0.68rem !important; }
      h1.page-title { font-size: 1rem !important; }
      .card { border-radius: 10px; }
    }
    @media (min-width: 768px) {
      #mobile-topbar { display: none !important; }
      #sidebar { position: relative; left: 0 !important; box-shadow: none; }
      #section-content { padding: 24px !important; }
      .modal { border-radius: 16px; max-width: 500px; margin: auto; }
      .modal-bg { align-items: center; padding: 16px; }
    }
  </style>
</head>
<body class="bg-slate-50 min-h-screen">

<!-- ─── TOAST ─── -->
<div id="toast" class="toast"></div>

<!-- ─── LOGIN SCREEN ─── -->
<div id="login-screen" class="min-h-screen flex items-center justify-center p-4">
  <div class="card w-full max-w-sm p-8">
    <div class="text-center mb-8">
      <div class="text-2xl font-bold text-slate-800 mb-1">Villa Admin</div>
      <div class="text-sm text-slate-400" id="login-subtitle">Login ke dashboard pengelola villa</div>
    </div>

    <!-- Login tab / Register tab -->
    <div class="flex border border-slate-200 rounded-xl p-1 mb-5 bg-slate-50">
      <button id="tab-login" class="flex-1 py-2 rounded-lg text-sm font-semibold bg-white shadow-sm text-slate-800" onclick="switchTab('login')">Login</button>
      <button id="tab-register" class="flex-1 py-2 rounded-lg text-sm font-semibold text-slate-400" onclick="switchTab('register')">Daftar</button>
    </div>

    <form id="login-form" onsubmit="doLogin(event)">
      <div class="space-y-4">
        <div><label>Username</label><input id="l-username" type="text" required/></div>
        <div><label>Password</label><input id="l-password" type="password" required/></div>
        <button type="submit" class="btn btn-primary w-full justify-center">
          <span class="material-symbols-outlined">login</span> Masuk
        </button>
      </div>
    </form>

    <form id="register-form" class="hidden" onsubmit="doRegister(event)">
      <div class="space-y-4">
        <div><label>Username</label><input id="r-username" type="text" required/></div>
        <div><label>Password</label><input id="r-password" type="password" required minlength="6"/></div>
        <div><label>Email (opsional)</label><input id="r-email" type="email"/></div>
        <p class="text-xs text-slate-500 bg-slate-50 p-3 rounded-lg">Akun baru memerlukan persetujuan superadmin sebelum bisa login.</p>
        <button type="submit" class="btn btn-primary w-full justify-center">
          <span class="material-symbols-outlined">person_add</span> Daftar
        </button>
      </div>
    </form>

  </div>
</div>

<!-- ─── DASHBOARD ─── -->
<div id="dashboard" class="hidden flex h-screen overflow-hidden">

  <!-- Mobile sidebar overlay -->
  <div id="sidebar-overlay" onclick="closeSidebar()"></div>

  <!-- Sidebar -->
  <aside id="sidebar" class="w-56 bg-white border-r border-slate-100 flex flex-col flex-shrink-0 h-screen overflow-y-auto">
    <div class="px-5 py-4 border-b border-slate-100 flex items-center justify-between">
      <div class="flex items-center gap-2.5">
        <img src="https://cdn.jsdelivr.net/gh/SAFELFAR05/Up@main/images/villas/a1b2c3d4-e5f6-7890-abcd-ef1234567890/1778673470866.jpg" alt="Logo" style="width:32px;height:32px;object-fit:cover;border-radius:50%;flex-shrink:0;"/>
        <div>
          <div class="font-bold text-slate-800 text-base">Villa Admin</div>
          <div id="sidebar-user" class="text-xs text-slate-400 mt-0.5"></div>
        </div>
      </div>
      <button onclick="closeSidebar()" class="md:hidden p-1.5 rounded-lg text-slate-400 hover:bg-slate-100">
        <span class="material-symbols-outlined" style="font-size:20px;">close</span>
      </button>
    </div>

    <!-- Villa selector (superadmin) -->
    <div id="villa-selector-wrap" class="hidden px-4 pt-3">
      <label>Villa Aktif</label>
      <input id="villa-search" type="search" placeholder="Cari nama villa…" oninput="filterVilla(this.value)" autocomplete="off" style="font-size:0.8rem;padding:6px 10px;margin-bottom:4px;width:100%;border:1.5px solid #e2e8f0;border-radius:8px;outline:none;"/>
      <select id="villa-selector" onchange="onVillaChange(this.value)" style="font-size:0.8rem;padding:6px 10px;"></select>
    </div>

    <nav class="flex-1 px-3 py-3 space-y-0.5">
      <div onclick="showSection('inquiries')"  class="sidebar-link" data-section="inquiries"><span class="material-symbols-outlined">inbox</span>Reservasi</div>
      <div onclick="showSection('info')"        class="sidebar-link" data-section="info"><span class="material-symbols-outlined">home</span>Info Villa</div>
      <div onclick="showSection('facilities')"  class="sidebar-link" data-section="facilities"><span class="material-symbols-outlined">pool</span>Fasilitas</div>
      <div onclick="showSection('policies')"    class="sidebar-link" data-section="policies"><span class="material-symbols-outlined">rule</span>Kebijakan</div>
      <div onclick="showSection('contacts')"    class="sidebar-link" data-section="contacts"><span class="material-symbols-outlined">contacts</span>Kontak Global</div>
      <div onclick="showSection('gallery')"     class="sidebar-link" data-section="gallery"><span class="material-symbols-outlined">photo_library</span>Galeri</div>
      <div id="nav-users"     onclick="showSection('users')"     class="sidebar-link hidden" data-section="users"><span class="material-symbols-outlined">group</span>Pengguna</div>
      <div id="nav-new-villa" onclick="showSection('new-villa')" class="sidebar-link hidden" data-section="new-villa"><span class="material-symbols-outlined">add_home</span>Villa Baru</div>
    </nav>

    <div class="px-3 pb-4">
      <button onclick="logout()" class="sidebar-link w-full" style="color:#ef4444;">
        <span class="material-symbols-outlined">logout</span>Keluar
      </button>
    </div>
  </aside>

  <!-- Main -->
  <main class="flex-1 overflow-y-auto bg-slate-50 flex flex-col min-h-0">

    <!-- Mobile top bar -->
    <div id="mobile-topbar" style="display:none;" class="sticky top-0 z-30 bg-white border-b border-slate-100 px-4 h-14 flex items-center gap-3 flex-shrink-0">
      <button onclick="openSidebar()" class="p-2 -ml-1 rounded-lg text-slate-500 hover:bg-slate-100">
        <span class="material-symbols-outlined" style="font-size:22px;">menu</span>
      </button>
      <span id="mobile-page-title" class="font-semibold text-slate-800 text-base flex-1">Reservasi</span>
      <button onclick="logout()" class="p-2 rounded-lg text-red-400 hover:bg-red-50">
        <span class="material-symbols-outlined" style="font-size:20px;">logout</span>
      </button>
    </div>

    <div id="section-content" class="p-6 max-w-5xl mx-auto w-full">
      <div class="text-slate-400 text-center pt-20">Memuat data...</div>
    </div>
  </main>
</div>


<script>
// ── App State ──────────────────────────────────────────────────────
const S = {
  token: localStorage.getItem('villa_token') || '',
  user: JSON.parse(localStorage.getItem('villa_user') || 'null'),
  currentVillaId: localStorage.getItem('villa_current_id') || '',
  currentSection: 'inquiries',
  villas: [],
};

// ── Worker URL ─────────────────────────────────────────────────────
const WORKER_URL = window.location.origin;
function getWorkerUrl() { return WORKER_URL; }

// ── API helper ─────────────────────────────────────────────────────
async function api(path, options = {}) {
  const base = getWorkerUrl();
  if (!base) throw new Error('Worker URL belum diatur!');
  const res = await fetch(base + path, {
    headers: {
      'Content-Type': 'application/json',
      ...(S.token ? { Authorization: \`Bearer \${S.token}\` } : {}),
      ...(options.headers || {}),
    },
    ...options,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || \`HTTP \${res.status}\`);
  return data;
}

// ── Toast ──────────────────────────────────────────────────────────
let toastTimer;
function showToast(msg, type = 'success') {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = \`toast toast-\${type} show\`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), 3500);
}

// ── Auth ───────────────────────────────────────────────────────────
function switchTab(tab) {
  document.getElementById('login-form').classList.toggle('hidden', tab !== 'login');
  document.getElementById('register-form').classList.toggle('hidden', tab !== 'register');
  document.getElementById('tab-login').className = tab === 'login'
    ? 'flex-1 py-2 rounded-lg text-sm font-semibold bg-white shadow-sm text-slate-800'
    : 'flex-1 py-2 rounded-lg text-sm font-semibold text-slate-400';
  document.getElementById('tab-register').className = tab === 'register'
    ? 'flex-1 py-2 rounded-lg text-sm font-semibold bg-white shadow-sm text-slate-800'
    : 'flex-1 py-2 rounded-lg text-sm font-semibold text-slate-400';
}

async function doLogin(e) {
  e.preventDefault();
  try {
    const data = await api('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username: document.getElementById('l-username').value, password: document.getElementById('l-password').value }),
    });
    S.token = data.token;
    S.user  = data.user;
    localStorage.setItem('villa_token', S.token);
    localStorage.setItem('villa_user', JSON.stringify(S.user));
    enterDashboard();
  } catch (err) { showToast(err.message, 'error'); }
}

async function doRegister(e) {
  e.preventDefault();
  try {
    await api('/auth/register', {
      method: 'POST',
      body: JSON.stringify({
        username: document.getElementById('r-username').value,
        password: document.getElementById('r-password').value,
        email:    document.getElementById('r-email').value || undefined,
      }),
    });
    showToast('Pendaftaran berhasil! Tunggu persetujuan superadmin.', 'success');
    switchTab('login');
  } catch (err) { showToast(err.message, 'error'); }
}

function logout() {
  S.token = ''; S.user = null;
  localStorage.removeItem('villa_token');
  localStorage.removeItem('villa_user');
  document.getElementById('dashboard').classList.add('hidden');
  document.getElementById('login-screen').classList.remove('hidden');
}

// ── Dashboard ──────────────────────────────────────────────────────
async function enterDashboard() {
  document.getElementById('login-screen').classList.add('hidden');
  document.getElementById('dashboard').classList.remove('hidden');
  document.getElementById('sidebar-user').textContent = \`\${S.user.username} · \${S.user.role}\`;

  // Semua role bisa tambah villa baru
  document.getElementById('nav-new-villa').classList.remove('hidden');

  if (S.user.role === 'superadmin') {
    document.getElementById('nav-users').classList.remove('hidden');
    document.getElementById('villa-selector-wrap').classList.remove('hidden');
    // Load all villas
    try {
      S.villas = await api('/villas');
      const sel = document.getElementById('villa-selector');
      sel.innerHTML = S.villas.map(v => \`<option value="\${v.id}">\${v.name}</option>\`).join('');
      S.currentVillaId = S.villas[0]?.id || '';
      sel.value = S.currentVillaId;
      localStorage.setItem('villa_current_id', S.currentVillaId);
    } catch {}
  } else {
    S.currentVillaId = S.user.villa_id || '';
  }

  showSection('inquiries');
}

function onVillaChange(id) {
  S.currentVillaId = id;
  localStorage.setItem('villa_current_id', id);
  showSection(S.currentSection);
}

function filterVilla(q) {
  const sel = document.getElementById('villa-selector');
  if (!sel) return;
  const lower = (q || '').toLowerCase().trim();
  const cur = sel.value;
  sel.innerHTML = S.villas
    .filter(v => !lower || v.name.toLowerCase().includes(lower))
    .map(v => \`<option value="\${v.id}"\${v.id === cur ? ' selected' : ''}>\${v.name}</option>\`)
    .join('');
  if (!sel.value && sel.options.length) {
    sel.value = sel.options[0].value;
    onVillaChange(sel.options[0].value);
  }
}

// ── Sidebar mobile ────────────────────────────────────────────────
function openSidebar() {
  document.getElementById('sidebar').classList.add('open');
  document.getElementById('sidebar-overlay').classList.add('show');
  document.body.style.overflow = 'hidden';
}
function closeSidebar() {
  document.getElementById('sidebar').classList.remove('open');
  document.getElementById('sidebar-overlay').classList.remove('show');
  document.body.style.overflow = '';
}

function showSection(name) {
  S.currentSection = name;
  document.querySelectorAll('.sidebar-link').forEach(el => {
    el.classList.toggle('active', el.dataset.section === name);
  });
  const titles = {
    inquiries: 'Reservasi', info: 'Info Villa', facilities: 'Fasilitas',
    policies: 'Kebijakan', contacts: 'Kontak Global', gallery: 'Galeri',
    users: 'Pengguna', 'new-villa': 'Villa Baru',
  };
  const titleEl = document.getElementById('mobile-page-title');
  if (titleEl) titleEl.textContent = titles[name] || 'Dashboard';
  closeSidebar();
  const sec = {
    inquiries:  renderInquiries,
    info:       renderInfo,
    facilities: renderFacilities,
    policies:   renderPolicies,
    contacts:   renderContacts,
    gallery:    renderGallery,
    users:      renderUsers,
    'new-villa': renderNewVilla,
  }[name];
  if (sec) sec();
}

// ── Shared helpers ─────────────────────────────────────────────────
function setContent(html) {
  document.getElementById('section-content').innerHTML = html;
}
function villaId() { return S.currentVillaId; }
function badgeHtml(status) {
  return \`<span class="badge badge-\${status}">\${status}</span>\`;
}
function iconBtn(icon, color, onclick, title='') {
  return \`<button class="p-1.5 rounded-lg hover:bg-slate-100 text-\${color}" onclick="\${onclick}" title="\${title}">
    <span class="material-symbols-outlined" style="font-size:16px;">\${icon}</span></button>\`;
}

// ── Section: Reservasi (Inquiries) ────────────────────────────────
async function renderInquiries() {
  setContent('<div class="text-slate-400 text-center pt-20">Memuat reservasi...</div>');
  try {
    const data = await api('/inquiries');
    const counts = { all: data.length, pending: 0, confirmed: 0, cancelled: 0 };
    data.forEach(i => { if (counts[i.status] !== undefined) counts[i.status]++; });
    const statusColor = { pending:'yellow', confirmed:'blue', replied:'purple', cancelled:'slate' };
    const rows = data.map(i => \`
      <tr>
        <td>\${i.name}</td>
        <td>\${i.phone || '-'}</td>
        <td>\${i.checkin_date || '-'}</td>
        <td class="hide-mobile">\${i.checkout_date || '-'}</td>
        <td class="hide-mobile">\${i.num_guests || '-'}</td>
        <td>\${badgeHtml(i.status)}</td>
        <td class="hide-mobile">\${i.message ? \`<span class="text-slate-400 text-xs">\${i.message.slice(0,40)}…</span>\` : '-'}</td>
        <td>
          <select class="text-xs py-1 px-2" style="width:auto;" onchange="updateInquiry('\${i.id}',this.value)">
            \${['pending','replied','confirmed','cancelled'].map(s => \`<option \${s===i.status?'selected':''}>\${s}</option>\`).join('')}
          </select>
        </td>
      </tr>\`).join('') || '<tr><td colspan="8" class="text-center text-slate-400 py-6">Belum ada reservasi</td></tr>';

    setContent(\`
      <div class="flex items-center justify-between mb-6">
        <div>
          <h1 class="text-xl font-bold text-slate-800 page-title">Permintaan Reservasi</h1>
          <p class="text-sm text-slate-400">\${counts.all} total · \${counts.pending} menunggu</p>
        </div>
      </div>
      <div class="card overflow-hidden">
        <div class="overflow-x-auto">
          <table>
            <thead><tr>
              <th>Nama</th><th>WA/Telp</th><th>Check-in</th><th class="hide-mobile">Check-out</th><th class="hide-mobile">Tamu</th>
              <th>Status</th><th class="hide-mobile">Pesan</th><th>Ubah Status</th>
            </tr></thead>
            <tbody>\${rows}</tbody>
          </table>
        </div>
      </div>\`);
  } catch (e) { setContent(\`<div class="text-red-500 text-center pt-20">\${e.message}</div>\`); }
}

async function updateInquiry(id, status) {
  try {
    await api(\`/inquiries/\${id}\`, { method: 'PATCH', body: JSON.stringify({ status }) });
    showToast('Status diperbarui', 'success');
  } catch (e) { showToast(e.message, 'error'); renderInquiries(); }
}

// ── Section: Info Villa ────────────────────────────────────────────
async function renderInfo() {
  if (!villaId()) return setContent('<div class="text-slate-400 text-center pt-20">Pilih villa terlebih dahulu</div>');
  setContent('<div class="text-slate-400 text-center pt-20">Memuat...</div>');
  try {
    const v = await api(\`/villas/\${villaId()}\`);
    setContent(\`
      <div class="flex items-center justify-between mb-6">
        <h1 class="text-xl font-bold text-slate-800 page-title">Info Villa</h1>
        <div class="text-xs text-slate-400">Slug: <code class="bg-slate-100 px-2 py-0.5 rounded">/&nbsp;\${v.slug || '-'}</code></div>
      </div>
      <div class="card p-6">
        <form onsubmit="saveInfo(event)" class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div class="md:col-span-2"><label>Nama Villa</label><input name="name" value="\${v.name||''}"/></div>
          <div><label>Slug (URL path)</label><input name="slug" value="\${v.slug||''}"/></div>
          <div><label>Tagline</label><input name="tagline" value="\${v.tagline||''}"/></div>
          <div class="md:col-span-2"><label>Deskripsi</label><textarea name="description" rows="3">\${v.description||''}</textarea></div>
          <div><label>Alamat</label><input name="address" value="\${v.address||''}"/></div>
          <div><label>Kota</label><input name="city" value="\${v.city||''}"/></div>
          <div><label>Provinsi</label><input name="province" value="\${v.province||''}"/></div>
          <div><label>Kapasitas Maks.</label><input name="max_guests" type="number" value="\${v.max_guests||''}"/></div>
          <div><label>Catatan Kapasitas</label><input name="max_guests_note" value="\${v.max_guests_note||''}"/></div>
          <div><label>Harga Extra Bed (Rp)</label><input name="extra_bed_price" type="number" value="\${v.extra_bed_price||''}"/></div>
          <div><label>Catatan Extra Bed</label><input name="extra_bed_note" value="\${v.extra_bed_note||''}"/></div>
          <div><label>Jam Check-in</label><input name="checkin_time" value="\${v.checkin_time||'14.00 WIB'}"/></div>
          <div><label>Jam Check-out</label><input name="checkout_time" value="\${v.checkout_time||'12.00 WIB'}"/></div>
          <div class="md:col-span-2"><button type="submit" class="btn btn-primary"><span class="material-symbols-outlined">save</span>Simpan Perubahan</button></div>
        </form>
      </div>
      \${S.user?.role === 'superadmin' ? \`
      <div class="card p-5 mt-5 border-red-100" style="border-color:#fee2e2;">
        <p class="font-semibold text-red-600 flex items-center gap-1.5 mb-1">
          <span class="material-symbols-outlined" style="font-size:18px;">warning</span>Zona Berbahaya
        </p>
        <p class="text-sm text-slate-500 mb-3">Menghapus villa akan menghapus <strong>semua data</strong> terkait (fasilitas, kebijakan, galeri, kontak, reservasi) secara permanen.</p>
        <button onclick="confirmDeleteVilla('\${v.id}','\${esc(v.name)}')" class="btn btn-sm" style="background:#dc2626;color:#fff;border:none;">
          <span class="material-symbols-outlined" style="font-size:16px;">delete_forever</span>Hapus Villa Ini
        </button>
      </div>\` : ''}
    \`);
  } catch (e) { setContent(\`<div class="text-red-500 text-center pt-20">\${e.message}</div>\`); }
}

function confirmDeleteVilla(id, name) {
  if (!confirm(\`Hapus villa "\${name}" beserta SEMUA data (fasilitas, galeri, kebijakan, kontak, reservasi)?\\n\\nTindakan ini tidak dapat dibatalkan!\`)) return;
  deleteVillaById(id, name);
}

async function deleteVillaById(id, name) {
  try {
    await api(\`/villas/\${id}\`, { method: 'DELETE' });
    showToast(\`Villa "\${name}" berhasil dihapus\`, 'success');
    // Hapus dari state lokal
    S.villas = S.villas.filter(v => v.id !== id);
    const sel = document.getElementById('villa-selector');
    if (sel) {
      sel.innerHTML = S.villas.map(v => \`<option value="\${v.id}">\${v.name}</option>\`).join('');
      S.currentVillaId = S.villas[0]?.id || '';
      sel.value = S.currentVillaId;
      localStorage.setItem('villa_current_id', S.currentVillaId);
    }
    showSection('info');
  } catch (e) { showToast(e.message, 'error'); }
}

async function saveInfo(e) {
  e.preventDefault();
  const fd = new FormData(e.target);
  const body = Object.fromEntries(fd.entries());
  if (body.max_guests) body.max_guests = parseInt(body.max_guests);
  if (body.extra_bed_price) body.extra_bed_price = parseInt(body.extra_bed_price);
  try {
    await api(\`/villas/\${villaId()}\`, { method: 'PATCH', body: JSON.stringify(body) });
    showToast('Info villa disimpan!', 'success');
  } catch (e) { showToast(e.message, 'error'); }
}

// ── Section: Fasilitas ────────────────────────────────────────────
async function renderFacilities() {
  if (!villaId()) return setContent('<div class="text-slate-400 text-center pt-20">Pilih villa</div>');
  try {
    const data = await api(\`/villas/\${villaId()}/facilities\`);
    const rows = data.map(f => \`
      <tr>
        <td><span class="material-symbols-outlined text-green-700" style="font-size:18px;">\${f.icon||'star'}</span></td>
        <td class="font-medium">\${f.name}</td>
        <td class="text-slate-400">\${f.description||'-'}</td>
        <td class="hide-mobile">\${f.sort_order}</td>
        <td class="hide-mobile">\${f.is_active ? badgeHtml('active') : badgeHtml('suspended')}</td>
        <td class="flex gap-1">
          \${iconBtn('edit','slate-500',\`editFacility('\${f.id}','\${esc(f.name)}','\${esc(f.icon||'star')}','\${esc(f.description||'')}',\${f.sort_order})\`,'Edit')}
          \${iconBtn('delete','red-400',\`deleteFacility('\${f.id}')\`,'Hapus')}
        </td>
      </tr>\`).join('') || '<tr><td colspan="6" class="text-center text-slate-400 py-6">Belum ada fasilitas</td></tr>';

    setContent(\`
      <div class="flex items-center justify-between mb-6">
        <h1 class="text-xl font-bold text-slate-800 page-title">Fasilitas</h1>
        <button class="btn btn-primary btn-sm" onclick="openFacilityModal()">
          <span class="material-symbols-outlined">add</span>Tambah</button>
      </div>
      <div class="card overflow-hidden">
        <div class="overflow-x-auto">
          <table><thead><tr><th>Ikon</th><th>Nama</th><th>Deskripsi</th><th class="hide-mobile">Urutan</th><th class="hide-mobile">Status</th><th>Aksi</th></tr></thead>
          <tbody>\${rows}</tbody></table>
        </div>
      </div>

      <!-- Modal -->
      <div id="fac-modal" class="hidden modal-bg" onclick="if(event.target===this)this.classList.add('hidden')">
        <div class="modal">
          <h3 class="text-lg font-bold text-slate-800 mb-5" id="fac-modal-title">Tambah Fasilitas</h3>
          <form onsubmit="saveFacility(event)" class="space-y-4">
            <input type="hidden" id="fac-id"/>
            <div class="grid grid-cols-2 gap-3">
              <div><label>Nama</label><input id="fac-name" required/></div>
              <div><label>Ikon (Material)</label><input id="fac-icon" placeholder="pool"/></div>
            </div>
            <div><label>Deskripsi</label><textarea id="fac-desc" rows="2"></textarea></div>
            <div><label>Urutan</label><input id="fac-order" type="number" value="0"/></div>
            <div class="flex gap-3">
              <button type="submit" class="btn btn-primary flex-1 justify-center">Simpan</button>
              <button type="button" class="btn btn-ghost" onclick="document.getElementById('fac-modal').classList.add('hidden')">Batal</button>
            </div>
          </form>
        </div>
      </div>\`);
  } catch (e) { setContent(\`<div class="text-red-500 text-center pt-20">\${e.message}</div>\`); }
}

function openFacilityModal(id='', name='', icon='', desc='', order=0) {
  document.getElementById('fac-id').value = id;
  document.getElementById('fac-name').value = name;
  document.getElementById('fac-icon').value = icon;
  document.getElementById('fac-desc').value = desc;
  document.getElementById('fac-order').value = order;
  document.getElementById('fac-modal-title').textContent = id ? 'Edit Fasilitas' : 'Tambah Fasilitas';
  document.getElementById('fac-modal').classList.remove('hidden');
}
function editFacility(id, name, icon, desc, order) { openFacilityModal(id, name, icon, desc, order); }

async function saveFacility(e) {
  e.preventDefault();
  const id   = document.getElementById('fac-id').value;
  const body = {
    name: document.getElementById('fac-name').value,
    icon: document.getElementById('fac-icon').value || 'star',
    description: document.getElementById('fac-desc').value,
    sort_order: parseInt(document.getElementById('fac-order').value) || 0,
  };
  try {
    if (id) await api(\`/facilities/\${id}\`, { method: 'PATCH', body: JSON.stringify(body) });
    else    await api(\`/villas/\${villaId()}/facilities\`, { method: 'POST', body: JSON.stringify(body) });
    showToast('Fasilitas disimpan!', 'success');
    renderFacilities();
  } catch (e) { showToast(e.message, 'error'); }
}

async function deleteFacility(id) {
  if (!confirm('Hapus fasilitas ini?')) return;
  try { await api(\`/facilities/\${id}\`, { method: 'DELETE' }); showToast('Dihapus', 'success'); renderFacilities(); }
  catch (e) { showToast(e.message, 'error'); }
}

// ── Section: Kebijakan ────────────────────────────────────────────
async function renderPolicies() {
  if (!villaId()) return setContent('<div class="text-slate-400 text-center pt-20">Pilih villa</div>');
  try {
    const data = await api(\`/villas/\${villaId()}/policies\`);
    const typeColor = { schedule:'bg-blue-50 text-blue-700', note:'bg-yellow-50 text-yellow-700', prohibition:'bg-red-50 text-red-700', rule:'bg-slate-50 text-slate-700' };
    const rows = data.map(p => \`
      <tr>
        <td><span class="badge \${typeColor[p.type]||''}">\${p.type}</span></td>
        <td>\${p.content}</td>
        <td class="hide-mobile">\${p.sort_order}</td>
        <td class="flex gap-1">
          \${iconBtn('edit','slate-500',\`editPolicy('\${p.id}','\${esc(p.type)}','\${esc(p.content)}',\${p.sort_order})\`,'Edit')}
          \${iconBtn('delete','red-400',\`deletePolicy('\${p.id}')\`,'Hapus')}
        </td>
      </tr>\`).join('') || '<tr><td colspan="4" class="text-center text-slate-400 py-6">Belum ada kebijakan</td></tr>';

    setContent(\`
      <div class="flex items-center justify-between mb-6">
        <h1 class="text-xl font-bold text-slate-800 page-title">Kebijakan & Aturan</h1>
        <button class="btn btn-primary btn-sm" onclick="openPolicyModal()"><span class="material-symbols-outlined">add</span>Tambah</button>
      </div>
      <div class="card overflow-hidden">
        <div class="overflow-x-auto">
          <table><thead><tr><th>Tipe</th><th>Isi</th><th class="hide-mobile">Urutan</th><th>Aksi</th></tr></thead>
          <tbody>\${rows}</tbody></table>
        </div>
      </div>

      <div id="pol-modal" class="hidden modal-bg" onclick="if(event.target===this)this.classList.add('hidden')">
        <div class="modal">
          <h3 class="text-lg font-bold text-slate-800 mb-5" id="pol-modal-title">Tambah Kebijakan</h3>
          <form onsubmit="savePolicy(event)" class="space-y-4">
            <input type="hidden" id="pol-id"/>
            <div><label>Tipe</label>
              <select id="pol-type">
                <option>schedule</option><option>note</option><option>prohibition</option><option>rule</option>
              </select>
            </div>
            <div><label>Isi</label><textarea id="pol-content" rows="2" required></textarea></div>
            <div><label>Urutan</label><input id="pol-order" type="number" value="0"/></div>
            <div class="flex gap-3">
              <button type="submit" class="btn btn-primary flex-1 justify-center">Simpan</button>
              <button type="button" class="btn btn-ghost" onclick="document.getElementById('pol-modal').classList.add('hidden')">Batal</button>
            </div>
          </form>
        </div>
      </div>\`);
  } catch (e) { setContent(\`<div class="text-red-500 text-center pt-20">\${e.message}</div>\`); }
}

function openPolicyModal(id='',type='note',content='',order=0) {
  document.getElementById('pol-id').value = id;
  document.getElementById('pol-type').value = type;
  document.getElementById('pol-content').value = content;
  document.getElementById('pol-order').value = order;
  document.getElementById('pol-modal-title').textContent = id ? 'Edit Kebijakan' : 'Tambah Kebijakan';
  document.getElementById('pol-modal').classList.remove('hidden');
}
function editPolicy(id, type, content, order) { openPolicyModal(id, type, content, order); }

async function savePolicy(e) {
  e.preventDefault();
  const id   = document.getElementById('pol-id').value;
  const body = { type: document.getElementById('pol-type').value, content: document.getElementById('pol-content').value, sort_order: parseInt(document.getElementById('pol-order').value)||0 };
  try {
    if (id) await api(\`/policies/\${id}\`, { method: 'PATCH', body: JSON.stringify(body) });
    else    await api(\`/villas/\${villaId()}/policies\`, { method: 'POST', body: JSON.stringify(body) });
    showToast('Kebijakan disimpan!', 'success'); renderPolicies();
  } catch (e) { showToast(e.message, 'error'); }
}
async function deletePolicy(id) {
  if (!confirm('Hapus kebijakan ini?')) return;
  try { await api(\`/policies/\${id}\`, { method: 'DELETE' }); showToast('Dihapus', 'success'); renderPolicies(); }
  catch (e) { showToast(e.message, 'error'); }
}

// ── Section: Kontak Global ─────────────────────────────────────────
async function renderContacts() {
  setContent('<div class="text-slate-400 text-center pt-20">Memuat kontak global...</div>');
  try {
    const data = await api('/contacts/global');
    const typeIcon = { whatsapp:'chat', phone:'phone', email:'email', instagram:'photo_camera' };
    const typeLabel = { whatsapp:'WhatsApp', phone:'Telepon', email:'Email', instagram:'Instagram' };
    const rows = data.map(c => \`
      <tr>
        <td>
          <span class="flex items-center gap-1.5">
            <span class="material-symbols-outlined text-green-700" style="font-size:16px;">\${typeIcon[c.type]||'contact_phone'}</span>
            <span class="badge bg-slate-100 text-slate-600">\${typeLabel[c.type]||c.type}</span>
          </span>
        </td>
        <td class="hide-mobile">\${c.label||'-'}</td>
        <td class="font-mono text-xs">\${c.value}</td>
        <td>\${c.is_primary ? '<span class="badge badge-active">Utama</span>' : ''}</td>
        <td class="flex gap-1">
          \${iconBtn('edit','slate-500',\`openEditContact('\${c.id}','\${esc(c.type)}','\${esc(c.label||'')}','\${esc(c.value)}',\${c.is_primary})\`,'Edit')}
          \${iconBtn('delete','red-400',\`deleteContact('\${c.id}')\`,'Hapus')}
        </td>
      </tr>\`).join('') || '<tr><td colspan="5" class="text-center text-slate-400 py-8">Belum ada kontak global. Klik "+ Tambah" untuk menambahkan.</td></tr>';

    setContent(\`
      <div class="flex items-center justify-between mb-2">
        <div>
          <h1 class="text-xl font-bold text-slate-800 page-title">Kontak Global</h1>
          <p class="text-sm text-slate-400 mt-0.5">Tampil otomatis di semua halaman villa</p>
        </div>
        <button class="btn btn-primary btn-sm" onclick="openAddContact()">
          <span class="material-symbols-outlined">add</span>Tambah
        </button>
      </div>
      <div class="card overflow-hidden mb-4">
        <div class="px-4 py-3 bg-green-50 border-b border-green-100 flex items-start gap-2">
          <span class="material-symbols-outlined text-green-600" style="font-size:18px;">info</span>
          <p class="text-xs text-green-700">Kontak di sini berlaku untuk <strong>semua halaman</strong> — tidak perlu diset per-villa. Nomor WhatsApp utama (is_primary) akan dipakai sebagai tombol WA di hero &amp; card villa.</p>
        </div>
        <div class="overflow-x-auto">
          <table>
            <thead><tr><th>Tipe</th><th class="hide-mobile">Label</th><th>Nomor / Alamat</th><th>Utama</th><th>Aksi</th></tr></thead>
            <tbody>\${rows}</tbody>
          </table>
        </div>
      </div>

      <!-- Modal tambah/edit kontak -->
      <div id="con-modal" class="hidden modal-bg" onclick="if(event.target===this)this.classList.add('hidden')">
        <div class="modal">
          <h3 class="text-lg font-bold text-slate-800 mb-5" id="con-modal-title">Tambah Kontak Global</h3>
          <form onsubmit="saveContact(event)" class="space-y-4">
            <input type="hidden" id="con-id"/>
            <div class="grid grid-cols-2 gap-3">
              <div><label>Tipe</label>
                <select id="con-type">
                  <option value="whatsapp">WhatsApp</option>
                  <option value="phone">Telepon</option>
                  <option value="email">Email</option>
                  <option value="instagram">Instagram</option>
                </select>
              </div>
              <div><label>Label</label><input id="con-label" placeholder="Admin Villa"/></div>
            </div>
            <div>
              <label>Nilai (nomor/alamat)</label>
              <input id="con-value" required placeholder="082228981345"/>
              <p class="text-xs text-slate-400 mt-1">Untuk WhatsApp/Telepon: isi nomor HP (tanpa +62). Untuk email: isi alamat email.</p>
            </div>
            <div class="flex items-center gap-2">
              <input id="con-primary" type="checkbox" style="width:auto;" class="rounded"/>
              <label style="margin:0">Kontak utama (dipakai untuk tombol WA utama)</label>
            </div>
            <div class="flex gap-3">
              <button type="submit" class="btn btn-primary flex-1 justify-center">Simpan</button>
              <button type="button" class="btn btn-ghost" onclick="document.getElementById('con-modal').classList.add('hidden')">Batal</button>
            </div>
          </form>
        </div>
      </div>\`);
  } catch (e) { setContent(\`<div class="text-red-500 text-center pt-20">\${e.message}</div>\`); }
}

function openAddContact() {
  document.getElementById('con-id').value = '';
  document.getElementById('con-type').value = 'whatsapp';
  document.getElementById('con-label').value = '';
  document.getElementById('con-value').value = '';
  document.getElementById('con-primary').checked = false;
  document.getElementById('con-modal-title').textContent = 'Tambah Kontak Global';
  document.getElementById('con-modal').classList.remove('hidden');
}
function openEditContact(id, type, label, value, isPrimary) {
  document.getElementById('con-id').value = id;
  document.getElementById('con-type').value = type;
  document.getElementById('con-label').value = label;
  document.getElementById('con-value').value = value;
  document.getElementById('con-primary').checked = isPrimary === true || isPrimary === 'true';
  document.getElementById('con-modal-title').textContent = 'Edit Kontak Global';
  document.getElementById('con-modal').classList.remove('hidden');
}

async function saveContact(e) {
  e.preventDefault();
  const id = document.getElementById('con-id').value;
  const body = {
    type:       document.getElementById('con-type').value,
    label:      document.getElementById('con-label').value,
    value:      document.getElementById('con-value').value,
    is_primary: document.getElementById('con-primary').checked,
  };
  try {
    if (!getWorkerUrl()) throw new Error('Worker URL belum diatur! Isi URL Cloudflare Worker di halaman login terlebih dahulu.');
    if (id) {
      await api(\`/contacts/global/\${id}\`, { method: 'PATCH', body: JSON.stringify(body) });
      showToast('Kontak diperbarui!', 'success');
    } else {
      await api('/contacts/global', { method: 'POST', body: JSON.stringify(body) });
      showToast('Kontak ditambah!', 'success');
    }
    document.getElementById('con-modal').classList.add('hidden');
    renderContacts();
  } catch (e) { showToast(e.message, 'error'); }
}

async function deleteContact(id) {
  if (!confirm('Hapus kontak ini?')) return;
  try {
    if (!getWorkerUrl()) throw new Error('Worker URL belum diatur!');
    await api(\`/contacts/global/\${id}\`, { method: 'DELETE' });
    showToast('Dihapus', 'success');
    renderContacts();
  } catch (e) { showToast(e.message, 'error'); }
}

// ── Section: Galeri ────────────────────────────────────────────────
async function renderGallery() {
  if (!villaId()) return setContent('<div class="text-slate-400 text-center pt-20">Pilih villa</div>');
  try {
    const data = await api(\`/villas/\${villaId()}/gallery\`);
    const photos = data.map(g => \`
      <div class="relative group overflow-hidden rounded-xl aspect-video bg-slate-100">
        <img src="\${g.url}" alt="\${g.alt||''}" class="w-full h-full object-cover"/>
        <div class="absolute inset-0 bg-black/0 group-hover:bg-black/30 transition-all flex items-center justify-center opacity-0 group-hover:opacity-100">
          <button onclick="deleteGallery('\${g.id}')" class="bg-red-500 text-white rounded-lg px-3 py-1.5 text-xs font-semibold">Hapus</button>
        </div>
        \${g.alt ? \`<div class="absolute bottom-0 inset-x-0 bg-black/40 text-white text-xs px-2 py-1">\${g.alt}</div>\` : ''}
      </div>\`).join('') || '<div class="col-span-3 text-center text-slate-400 py-10">Belum ada foto</div>';

    setContent(\`
      <div class="flex items-center justify-between mb-6">
        <h1 class="text-xl font-bold text-slate-800 page-title">Galeri Foto</h1>
        <button class="btn btn-primary btn-sm" onclick="document.getElementById('gal-upload').classList.remove('hidden')">
          <span class="material-symbols-outlined">upload</span>Upload Foto</button>
      </div>

      <!-- Upload panel -->
      <div id="gal-upload" class="hidden card p-5 mb-5">
        <h4 class="font-semibold text-slate-700 mb-3">Upload ke GitHub</h4>
        <div class="mb-3">
          <label>Pilih Foto <span class="text-slate-400 font-normal">(bisa pilih beberapa sekaligus)</span></label>
          <input id="gal-file" type="file" accept="image/*,image/heic,image/heif,image/bmp,image/tiff,image/svg+xml" multiple onchange="previewGalFiles(this)" style="padding:6px;"/>
        </div>
        <div id="gal-preview" class="hidden space-y-2 mb-4 max-h-72 overflow-y-auto pr-1"></div>
        <div class="flex gap-3">
          <button class="btn btn-primary" onclick="uploadPhoto()"><span class="material-symbols-outlined">cloud_upload</span>Upload Semua</button>
          <button class="btn btn-ghost" onclick="document.getElementById('gal-upload').classList.add('hidden');document.getElementById('gal-preview').classList.add('hidden');document.getElementById('gal-preview').innerHTML='';document.getElementById('gal-file').value=''">Batal</button>
        </div>
        <p id="gal-status" class="text-xs text-slate-400 mt-2 flex items-center gap-1"></p>
      </div>

      <div class="grid grid-cols-2 md:grid-cols-3 gap-3">\${photos}</div>\`);
  } catch (e) { setContent(\`<div class="text-red-500 text-center pt-20">\${e.message}</div>\`); }
}

function compressImage(file, maxPx = 1280, quality = 0.78) {
  return new Promise((resolve) => {
    const kb = (file.size / 1024).toFixed(0);
    console.log(\`[compress] START "\${file.name}" type=\${file.type} size=\${kb}KB\`);
    const url = URL.createObjectURL(file);
    const img = new Image();
    img.onerror = (e) => {
      URL.revokeObjectURL(url);
      console.warn(\`[compress] img.onerror — fallback ke file asli\`, e);
      resolve(file);
    };
    img.onload = () => {
      URL.revokeObjectURL(url);
      try {
        let w = img.naturalWidth, h = img.naturalHeight;
        console.log(\`[compress] dimensi asli \${w}x\${h}\`);
        if (w > maxPx || h > maxPx) {
          if (w >= h) { h = Math.round(h * maxPx / w); w = maxPx; }
          else        { w = Math.round(w * maxPx / h); h = maxPx; }
          console.log(\`[compress] resize → \${w}x\${h}\`);
        }
        const canvas = document.createElement('canvas');
        canvas.width = w; canvas.height = h;
        canvas.getContext('2d').drawImage(img, 0, 0, w, h);
        canvas.toBlob(blob => {
          if (!blob) {
            console.warn(\`[compress] toBlob null — fallback ke file asli\`);
            return resolve(file);
          }
          const name = file.name.replace(/\\.[^.]+$/, '.webp');
          const out  = new File([blob], name, { type: 'image/webp' });
          const kbOut = (out.size / 1024).toFixed(0);
          if (out.size < file.size) {
            console.log(\`[compress] OK \${kb}KB → \${kbOut}KB WebP (\${Math.round(100-out.size/file.size*100)}% lebih kecil)\`);
            resolve(out);
          } else {
            console.warn(\`[compress] WebP (\${kbOut}KB) >= asli (\${kb}KB) — pakai file asli\`);
            resolve(file);
          }
        }, 'image/webp', quality);
      } catch (e) {
        console.error(\`[compress] catch error\`, e);
        resolve(file);
      }
    };
    img.src = url;
  });
}

function previewGalFiles(input) {
  const preview = document.getElementById('gal-preview');
  if (!input.files.length) { preview.classList.add('hidden'); preview.innerHTML = ''; return; }
  const urls = [];
  preview.innerHTML = Array.from(input.files).map((f, i) => {
    const url = URL.createObjectURL(f);
    urls.push(url);
    const kb = (f.size / 1024).toFixed(0);
    return \`<div class="flex items-center gap-3 p-2 bg-slate-50 rounded-lg border border-slate-100">
      <img src="\${url}" class="w-14 h-14 object-cover rounded-lg flex-none bg-slate-200"/>
      <div class="flex-1 min-w-0">
        <p class="text-xs font-medium text-slate-700 truncate mb-1">\${f.name} <span class="text-slate-400 font-normal">\${kb}KB</span></p>
        <input id="gal-alt-\${i}" placeholder="Keterangan foto (opsional)" style="font-size:0.75rem;padding:4px 8px;width:100%;"/>
      </div>
    </div>\`;
  }).join('');
  preview.classList.remove('hidden');
}

async function uploadPhoto() {
  const fileInput = document.getElementById('gal-file');
  const statusEl  = document.getElementById('gal-status');
  if (!fileInput.files.length) return showToast('Pilih file terlebih dahulu', 'error');

  const files = Array.from(fileInput.files);
  let success = 0, failed = 0;
  const btn = document.querySelector('#gal-upload .btn-primary');
  if (btn) btn.disabled = true;

  for (let i = 0; i < files.length; i++) {
    const file = files[i];
    const altEl = document.getElementById(\`gal-alt-\${i}\`);
    const alt   = altEl ? altEl.value : '';
    statusEl.innerHTML = \`<span class="material-symbols-outlined" style="font-size:14px;animation:spin 1s linear infinite">progress_activity</span> Mengompresi foto \${i+1}/\${files.length}…\`;
    try {
      const compressed = await compressImage(file);
      const kbOri = (file.size/1024).toFixed(0), kbCmp = (compressed.size/1024).toFixed(0);
      console.log(\`[upload] foto \${i+1} — asli: \${kbOri}KB, setelah compress: \${kbCmp}KB (\${compressed.type})\`);
      const fd = new FormData();
      fd.append('file', compressed);
      fd.append('villa_id', villaId());
      fd.append('alt', alt);
      statusEl.innerHTML = \`<span class="material-symbols-outlined" style="font-size:14px;animation:spin 1s linear infinite">progress_activity</span> Mengupload foto \${i+1}/\${files.length} (\${kbCmp}KB)…\`;
      console.log(\`[upload] fetch POST /upload/github — file: \${compressed.name} \${kbCmp}KB\`);
      const res = await fetch(getWorkerUrl() + '/upload/github', {
        method: 'POST',
        headers: { Authorization: \`Bearer \${S.token}\` },
        body: fd,
      });
      const data = await res.json();
      console.log(\`[upload] response \${res.status}\`, data);
      if (!res.ok) throw new Error(data.error || \`HTTP \${res.status}\`);
      success++;
    } catch (e) {
      console.error(\`[upload] foto \${i+1} GAGAL:\`, e);
      failed++;
      statusEl.textContent = \`Foto \${i+1} gagal: \${e.message}\`;
      await new Promise(r => setTimeout(r, 1500));
    }
  }

  if (btn) btn.disabled = false;
  statusEl.textContent = '';
  if (success) showToast(\`\${success} foto berhasil diupload!\`, 'success');
  if (failed)  showToast(\`\${failed} foto gagal diupload\`, 'error');
  renderGallery();
}

async function deleteGallery(id) {
  if (!confirm('Hapus foto ini?')) return;
  try { await api(\`/gallery/\${id}\`, { method: 'DELETE' }); showToast('Foto dihapus', 'success'); renderGallery(); }
  catch (e) { showToast(e.message, 'error'); }
}

// ── Section: Pengguna (superadmin) ────────────────────────────────
async function renderUsers() {
  if (S.user?.role !== 'superadmin') return setContent('<div class="text-slate-400 text-center pt-20">Akses ditolak</div>');
  try {
    const [users, villas] = await Promise.all([api('/users'), S.villas.length ? Promise.resolve(S.villas) : api('/villas')]);
    const villaMap = Object.fromEntries(villas.map(v => [v.id, v.name]));
    const rows = users.map(u => \`
      <tr>
        <td class="font-medium">\${u.username}</td>
        <td class="hide-mobile">\${u.email||'-'}</td>
        <td><span class="badge \${u.role==='superadmin'?'bg-purple-100 text-purple-700':'bg-slate-100 text-slate-600'}">\${u.role}</span></td>
        <td class="hide-mobile">\${u.villa_id ? villaMap[u.villa_id]||u.villa_id.slice(0,8) : '-'}</td>
        <td>\${badgeHtml(u.status)}</td>
        <td class="hide-mobile">\${u.created_at?.slice(0,10)||'-'}</td>
        <td class="flex gap-1 flex-wrap">
          \${u.status === 'pending'    ? \`<button class="btn btn-sm bg-green-100 text-green-700" onclick="approveUser('\${u.id}')">Setujui</button>\` : ''}
          \${u.status === 'active'     ? \`<button class="btn btn-sm bg-orange-100 text-orange-700" onclick="suspendUser('\${u.id}')">Suspend</button>\` : ''}
          \${u.status === 'suspended'  ? \`<button class="btn btn-sm bg-green-100 text-green-700" onclick="approveUser('\${u.id}')">Aktifkan</button>\` : ''}
          <button class="btn btn-sm bg-slate-100 text-slate-600" onclick="editUserRole('\${u.id}','\${u.role}','\${u.villa_id||''}')">Peran</button>
          \${u.id !== S.user?.sub ? \`<button class="btn btn-sm btn-danger" onclick="deleteUser('\${u.id}')">Hapus</button>\` : ''}
        </td>
      </tr>\`).join('') || '<tr><td colspan="7" class="text-center text-slate-400 py-6">Belum ada pengguna</td></tr>';

    setContent(\`
      <div class="flex items-center justify-between mb-6">
        <div>
          <h1 class="text-xl font-bold text-slate-800 page-title">Pengguna</h1>
          <p class="text-sm text-slate-400">\${users.filter(u=>u.status==='pending').length} menunggu persetujuan</p>
        </div>
      </div>
      <div class="card overflow-hidden">
        <div class="overflow-x-auto">
          <table><thead><tr><th>Username</th><th class="hide-mobile">Email</th><th>Peran</th><th class="hide-mobile">Villa</th><th>Status</th><th class="hide-mobile">Daftar</th><th>Aksi</th></tr></thead>
          <tbody>\${rows}</tbody></table>
        </div>
      </div>

      <div id="role-modal" class="hidden modal-bg" onclick="if(event.target===this)this.classList.add('hidden')">
        <div class="modal">
          <h3 class="text-lg font-bold text-slate-800 mb-5">Edit Peran Pengguna</h3>
          <form onsubmit="saveUserRole(event)" class="space-y-4">
            <input type="hidden" id="ru-id"/>
            <div><label>Peran</label>
              <select id="ru-role"><option value="admin">admin</option><option value="superadmin">superadmin</option></select>
            </div>
            <div><label>Villa yang dikelola</label>
              <select id="ru-villa">
                <option value="">— Tidak ada —</option>
                \${villas.map(v => \`<option value="\${v.id}">\${v.name}</option>\`).join('')}
              </select>
            </div>
            <div class="flex gap-3">
              <button type="submit" class="btn btn-primary flex-1 justify-center">Simpan</button>
              <button type="button" class="btn btn-ghost" onclick="document.getElementById('role-modal').classList.add('hidden')">Batal</button>
            </div>
          </form>
        </div>
      </div>\`);
  } catch (e) { setContent(\`<div class="text-red-500 text-center pt-20">\${e.message}</div>\`); }
}

function editUserRole(id, role, villaId) {
  document.getElementById('ru-id').value   = id;
  document.getElementById('ru-role').value = role;
  document.getElementById('ru-villa').value = villaId;
  document.getElementById('role-modal').classList.remove('hidden');
}
async function saveUserRole(e) {
  e.preventDefault();
  const id = document.getElementById('ru-id').value;
  try {
    await api(\`/users/\${id}/role\`, { method: 'PATCH', body: JSON.stringify({ role: document.getElementById('ru-role').value, villa_id: document.getElementById('ru-villa').value || null }) });
    showToast('Peran diperbarui!', 'success'); renderUsers();
  } catch (e) { showToast(e.message, 'error'); }
}
async function approveUser(id) {
  try { await api(\`/users/\${id}/approve\`, { method: 'PATCH' }); showToast('Akun disetujui!', 'success'); renderUsers(); }
  catch (e) { showToast(e.message, 'error'); }
}
async function suspendUser(id) {
  try { await api(\`/users/\${id}/suspend\`, { method: 'PATCH' }); showToast('Akun disuspend', 'success'); renderUsers(); }
  catch (e) { showToast(e.message, 'error'); }
}
async function deleteUser(id) {
  if (!confirm('Hapus pengguna ini secara permanen?')) return;
  try { await api(\`/users/\${id}\`, { method: 'DELETE' }); showToast('Pengguna dihapus', 'success'); renderUsers(); }
  catch (e) { showToast(e.message, 'error'); }
}

// ── Section: Villa Baru ────────────────────────────────────────────
function renderNewVilla() {
  window._nvFacilities = [];
  window._nvPolicies   = [];
  setContent(\`
    <h1 class="text-xl font-bold text-slate-800 mb-6">Tambah Villa Baru</h1>

    <!-- Panel AI -->
    <div class="card p-4 mb-5 border-violet-100" style="border-color:#ede9fe;">
      <button onclick="document.getElementById('nv-ai-panel').classList.toggle('hidden')"
        class="flex items-center gap-2 w-full text-left">
        <span class="material-symbols-outlined icon-fill" style="color:#7c3aed;font-size:20px;">auto_awesome</span>
        <span class="font-semibold text-slate-700">Isi Otomatis dengan AI</span>
        <span class="text-xs text-slate-400 ml-1">— tempel data villa, AI isi formnya</span>
        <span class="material-symbols-outlined ml-auto text-slate-400" style="font-size:18px;">expand_more</span>
      </button>
      <div id="nv-ai-panel" class="mt-4">
        <textarea id="nv-ai-input" rows="8"
          placeholder="Tempel info villa di sini — dari WhatsApp, brosur, catatan, apapun...&#10;&#10;Contoh:&#10;VILLA DIANDRA 2 Tawangmangu&#10;🏊 Kolam renang privat&#10;🛏️ 3 kamar tidur, kapasitas 25 orang&#10;Check-in: 14.00 WIB | Check-out: 12.00 WIB&#10;☎️ 082228981345"></textarea>
        <div class="flex flex-wrap gap-3 mt-3">
          <button class="btn btn-primary" onclick="fillNewVillaWithAI()" id="nv-ai-btn" style="background:#7c3aed;">
            <span class="material-symbols-outlined icon-fill">auto_awesome</span>Analisa &amp; Isi Form
          </button>
          <button class="btn btn-ghost" onclick="document.getElementById('nv-ai-input').value=''">
            <span class="material-symbols-outlined">clear</span>Hapus
          </button>
        </div>
        <p id="nv-ai-status" class="text-xs text-slate-500 mt-2 flex items-center gap-1.5"></p>
        <div id="nv-ai-raw" class="hidden mt-3">
          <p class="text-xs font-semibold text-slate-400 uppercase tracking-wide mb-1">Respons Mentah AI</p>
          <pre id="nv-ai-raw-text" class="text-xs text-slate-600 bg-slate-50 rounded-lg p-3 overflow-x-auto whitespace-pre-wrap" style="max-height:160px;overflow-y:auto;"></pre>
        </div>
      </div>
    </div>

    <!-- Form manual -->
    <div class="card p-6 max-w-2xl mb-4">
      <form onsubmit="createVilla(event)" class="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div class="md:col-span-2"><label>Nama Villa *</label><input id="nv-name" required/></div>
        <div><label>Slug (URL path) *</label><input id="nv-slug" placeholder="diandra3" required/>
          <p class="text-xs text-slate-400 mt-1">Akan dapat diakses di /slug pada website</p></div>
        <div><label>Tagline</label><input id="nv-tagline"/></div>
        <div class="md:col-span-2"><label>Deskripsi</label><textarea id="nv-desc" rows="3"></textarea></div>
        <div><label>Alamat</label><input id="nv-address"/></div>
        <div><label>Kota</label><input id="nv-city"/></div>
        <div><label>Provinsi</label><input id="nv-prov"/></div>
        <div><label>Kapasitas Maks.</label><input id="nv-guests" type="number"/></div>
        <div><label>Jam Check-in</label><input id="nv-cin" value="14.00 WIB"/></div>
        <div><label>Jam Check-out</label><input id="nv-cout" value="12.00 WIB"/></div>
        <div class="md:col-span-2">
          <button type="submit" class="btn btn-primary"><span class="material-symbols-outlined">add_home</span>Buat Villa</button>
        </div>
      </form>
    </div>

    <!-- Fasilitas -->
    <div class="card p-5 max-w-2xl">
      <div class="flex items-center justify-between mb-3">
        <span class="font-semibold text-slate-700 flex items-center gap-1.5">
          <span class="material-symbols-outlined" style="font-size:18px;">pool</span>
          Fasilitas Villa <span id="nv-fac-count" class="badge bg-slate-100 text-slate-500 ml-1">0</span>
        </span>
        <span class="text-xs text-slate-400">Akan disimpan otomatis saat villa dibuat</span>
      </div>
      <div id="nv-fac-list" class="space-y-1.5 mb-4">
        <p class="text-slate-400 text-sm italic">Belum ada fasilitas — tambahkan manual di bawah atau gunakan AI di atas</p>
      </div>
      <div class="border-t border-slate-100 pt-3">
        <p class="text-xs font-semibold text-slate-400 uppercase tracking-wide mb-2">Tambah Fasilitas</p>
        <div class="grid grid-cols-1 sm:grid-cols-3 gap-2">
          <input id="nv-fac-name" placeholder="Nama (cth: Kolam Renang)" style="font-size:0.8125rem;padding:7px 10px;"/>
          <input id="nv-fac-icon" placeholder="Ikon Material (cth: pool)" style="font-size:0.8125rem;padding:7px 10px;"/>
          <input id="nv-fac-desc" placeholder="Deskripsi (opsional)" style="font-size:0.8125rem;padding:7px 10px;"/>
        </div>
        <button onclick="nvAddFacility()" class="btn btn-ghost btn-sm mt-2">
          <span class="material-symbols-outlined" style="font-size:15px;">add</span>Tambah ke List
        </button>
      </div>
    </div>

    <!-- Kebijakan -->
    <div class="card p-5 max-w-2xl mt-4">
      <div class="flex items-center justify-between mb-3">
        <span class="font-semibold text-slate-700 flex items-center gap-1.5">
          <span class="material-symbols-outlined" style="font-size:18px;">gavel</span>
          Kebijakan Villa <span id="nv-pol-count" class="badge bg-slate-100 text-slate-500 ml-1">0</span>
        </span>
        <button onclick="nvResetDefaultPolicies()" class="btn btn-ghost btn-sm text-xs">
          <span class="material-symbols-outlined" style="font-size:14px;">restart_alt</span>Default Syariah
        </button>
      </div>
      <div id="nv-pol-list" class="space-y-1.5 mb-4">
        <p class="text-slate-400 text-sm italic">Belum ada kebijakan — tambahkan manual, gunakan AI, atau klik "Default Syariah"</p>
      </div>
      <div class="border-t border-slate-100 pt-3">
        <p class="text-xs font-semibold text-slate-400 uppercase tracking-wide mb-2">Tambah Kebijakan</p>
        <div class="grid grid-cols-1 sm:grid-cols-3 gap-2">
          <select id="nv-pol-type" style="font-size:0.8125rem;padding:7px 10px;">
            <option value="prohibition">🚫 Larangan</option>
            <option value="rule">📋 Aturan</option>
            <option value="schedule">🕐 Jadwal</option>
            <option value="note">📝 Catatan</option>
          </select>
          <input id="nv-pol-content" placeholder="Isi kebijakan..." style="font-size:0.8125rem;padding:7px 10px;" class="sm:col-span-2"/>
        </div>
        <button onclick="nvAddPolicy()" class="btn btn-ghost btn-sm mt-2">
          <span class="material-symbols-outlined" style="font-size:15px;">add</span>Tambah ke List
        </button>
      </div>
    </div>\`);
}

async function fillNewVillaWithAI() {
  const rawText = (document.getElementById('nv-ai-input')?.value || '').trim();
  if (!rawText) return showToast('Tempel data villa terlebih dahulu', 'error');

  const btn    = document.getElementById('nv-ai-btn');
  const status = document.getElementById('nv-ai-status');
  btn.disabled = true;
  btn.innerHTML = '<span class="material-symbols-outlined" style="animation:spin 1s linear infinite">progress_activity</span>Menganalisa...';
  status.innerHTML = '<span class="material-symbols-outlined" style="font-size:14px;color:#7c3aed;">auto_awesome</span> AI sedang membaca data villa…';
  document.getElementById('nv-ai-raw').classList.add('hidden');

  const logic = \`Kamu adalah asisten ekstraksi data villa profesional. Tugasmu: baca teks bebas dan kembalikan HANYA JSON valid tanpa penjelasan, tanpa markdown, tanpa kode block.

OUTPUT WAJIB berisi 3 key: villa_info, facilities, dan policies.

Contoh output LENGKAP:
{
  "villa_info": {"name":"Villa Diandra 2","slug":"villa-diandra-2","tagline":"Villa eksklusif dengan kolam renang privat","description":"Villa Diandra 2 adalah salah satu villa terbaik di kawasan Villa Tawangmangu yang menawarkan pengalaman menginap yang mewah dan nyaman. Terletak di Sekipan Tawangmangu dengan udara sejuk pegunungan, villa ini sangat cocok untuk liburan keluarga maupun rombongan. Dilengkapi kolam renang privat, 3 kamar tidur luas, dan berbagai fasilitas modern. Nikmati keindahan alam Glamping Tawangmangu dari villa eksklusif kami.","address":"Sekipan, Tawangmangu","city":"Karanganyar","province":"Jawa Tengah","max_guests":25,"max_guests_note":"","extra_bed_price":150000,"extra_bed_note":"","checkin_time":"14.00 WIB","checkout_time":"12.00 WIB"},
  "facilities": [
    {"name":"Kolam Renang Privat","icon":"pool","description":"Kolam renang khusus tamu villa","sort_order":1},
    {"name":"WiFi","icon":"wifi","description":"Internet gratis seluruh area","sort_order":2},
    {"name":"3 Kamar Tidur","icon":"king_bed","description":"Kamar tidur dengan kasur nyaman","sort_order":3}
  ],
  "policies": [
    {"type":"prohibition","content":"Dilarang membawa atau mengkonsumsi minuman keras / alkohol","sort_order":1},
    {"type":"prohibition","content":"Dilarang melakukan tindakan asusila / mesum","sort_order":2},
    {"type":"rule","content":"Tamu wajib menjaga kebersihan villa","sort_order":3},
    {"type":"schedule","content":"Check-in 14.00 WIB, Check-out 12.00 WIB","sort_order":4}
  ]
}

ATURAN WAJIB:
1. villa_info.description WAJIB berupa ARTIKEL DESKRIPTIF PANJANG (minimal 4-5 kalimat), bukan kalimat pendek. Gabungkan SEMUA informasi: nama villa, lokasi, suasana alam, fasilitas unggulan, kapasitas, cocok untuk siapa, keunggulan villa. Tulis seperti artikel promosi wisata yang menarik dan informatif.
2. KEY "facilities" HARUS ADA dan DIISI — ekstrak SEMUA fasilitas dari teks (kolam renang, kamar tidur, dapur, wifi, AC, TV, parkir, bbq, dll)
3. Setiap fasilitas wajib punya "description" deskriptif dan spesifik
4. slug: huruf kecil, spasi jadi tanda hubung
5. facilities.icon: pool, wifi, local_parking, kitchen, tv, king_bed, shower, outdoor_grill, meeting_room, spa, fitness_center, ac_unit, balcony, restaurant, hot_tub, bed, living
6. max_guests dan extra_bed_price harus integer
7. LOKASI FALLBACK: Jika alamat/kota/provinsi tidak disebutkan atau tidak jelas, wajib isi: address="Tawangmangu", city="Karanganyar", province="Jawa Tengah"
8. WAJIB: villa_info.description HARUS menyebut "Villa Tawangmangu" atau "Glamping Tawangmangu" minimal satu kali secara alami dalam kalimat (contoh: "... berlokasi di kawasan Villa Tawangmangu yang sejuk..." atau "... tersedia pilihan Glamping Tawangmangu yang asri...")
9. HARGA/TARIF: Jika teks menyebut harga atau tarif sewa dalam bentuk apapun (harga per malam, tarif weekday, tarif weekend, tarif high season, paket, dll), WAJIB masukkan informasi harga tersebut secara NATURAL dan LENGKAP ke dalam villa_info.description agar mudah diindeks Google. Contoh: "...villa ini tersedia dengan harga sewa Rp 2.500.000 per malam (weekday) dan Rp 3.500.000 per malam (weekend)...". Tulis semua rentang harga yang disebutkan. Jangan hilangkan info harga dari deskripsi.
10. Jawab HANYA JSON mentah\`;

  const message = \`Ekstrak info villa dari teks ini:\\n\\n\${rawText}\`;

  try {
    const res = await fetch(\`\${AI_URL}?\${new URLSearchParams({ message, logic, memory: '[]' })}\`);
    if (!res.ok) throw new Error(\`HTTP \${res.status}\`);
    const envelope = await res.json();
    const rawReply = (envelope.reply || envelope.message || envelope.text || '').trim();

    document.getElementById('nv-ai-raw-text').textContent = rawReply;
    document.getElementById('nv-ai-raw').classList.remove('hidden');

    let text = rawReply.replace(/^\`\`\`json\\s*/i,'').replace(/^\`\`\`\\s*/i,'').replace(/\\s*\`\`\`$/i,'').trim();
    const raw = JSON.parse(text);

    // Normalisasi: handle flat atau nested
    const VILLA_KEYS = ['name','slug','tagline','description','address','city','province','max_guests','checkin_time','checkout_time'];
    let vi = raw.villa_info || {};
    let facs = raw.facilities || [];
    if (!raw.villa_info && VILLA_KEYS.some(k => k in raw)) {
      vi = {}; VILLA_KEYS.concat(['max_guests_note','extra_bed_price','extra_bed_note']).forEach(k => { if (k in raw) vi[k] = raw[k]; });
      facs = raw.facilities || [];
    }

    // Isi field form
    const f = (id, val) => { const el = document.getElementById(id); if (el && val !== undefined && val !== null) el.value = val; };
    f('nv-name',    vi.name);
    f('nv-slug',    vi.slug);
    f('nv-tagline', vi.tagline);
    f('nv-desc',    vi.description);
    f('nv-address', vi.address);
    f('nv-city',    vi.city);
    f('nv-prov',    vi.province);
    f('nv-cin',     vi.checkin_time);
    f('nv-cout',    vi.checkout_time);
    if (vi.max_guests) f('nv-guests', vi.max_guests);

    // Isi fasilitas
    window._nvFacilities = Array.isArray(facs) ? facs : [];
    nvRenderFacList();

    // Isi kebijakan (fallback ke default syariah jika kosong)
    const rawPols = Array.isArray(raw.policies) ? raw.policies : [];
    window._nvPolicies = rawPols.length > 0 ? rawPols : NV_DEFAULT_POLICIES.map((p, i) => ({ ...p, sort_order: i }));
    nvRenderPolList();

    const polSrc = rawPols.length > 0 ? \`\${rawPols.length} kebijakan dari teks\` : \`\${window._nvPolicies.length} kebijakan default syariah\`;
    status.innerHTML = \`<span class="material-symbols-outlined" style="font-size:14px;color:#16a34a;">check_circle</span> Form, \${window._nvFacilities.length} fasilitas, dan \${polSrc} berhasil diisi! Cek lalu klik Buat Villa.\`;
    document.getElementById('nv-name')?.scrollIntoView({ behavior: 'smooth', block: 'center' });
  } catch(e) {
    status.innerHTML = \`<span class="material-symbols-outlined" style="font-size:14px;color:#991b1b;">error</span> Gagal: \${e.message}\`;
    showToast('AI gagal menganalisa', 'error');
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<span class="material-symbols-outlined icon-fill">auto_awesome</span>Analisa &amp; Isi Form';
  }
}

async function createVilla(e) {
  e.preventDefault();
  const body = {
    name: document.getElementById('nv-name').value,
    slug: document.getElementById('nv-slug').value,
    tagline: document.getElementById('nv-tagline').value,
    description: document.getElementById('nv-desc').value,
    address: document.getElementById('nv-address').value,
    city: document.getElementById('nv-city').value,
    province: document.getElementById('nv-prov').value,
    max_guests: parseInt(document.getElementById('nv-guests').value)||null,
    checkin_time: document.getElementById('nv-cin').value,
    checkout_time: document.getElementById('nv-cout').value,
  };
  const submitBtn = e.target.querySelector('button[type="submit"]');
  try {
    submitBtn && (submitBtn.disabled = true);
    const v = await api('/villas', { method: 'POST', body: JSON.stringify(body) });

    // Simpan fasilitas ke DB satu per satu
    const facs = window._nvFacilities || [];
    let facOk = 0, facFail = 0;
    for (let i = 0; i < facs.length; i++) {
      const f = facs[i];
      try {
        await api(\`/villas/\${v.id}/facilities\`, { method: 'POST', body: JSON.stringify({
          name: f.name, icon: f.icon || 'star', description: f.description || '', sort_order: f.sort_order ?? i, is_active: true,
        })});
        facOk++;
      } catch { facFail++; }
    }

    // Simpan kebijakan ke DB satu per satu
    const pols = window._nvPolicies || [];
    let polOk = 0, polFail = 0;
    for (let i = 0; i < pols.length; i++) {
      const p = pols[i];
      try {
        await api(\`/villas/\${v.id}/policies\`, { method: 'POST', body: JSON.stringify({
          type: p.type || 'prohibition', content: p.content, sort_order: p.sort_order ?? i,
        })});
        polOk++;
      } catch { polFail++; }
    }

    window._nvFacilities = [];
    window._nvPolicies   = [];
    S.villas.push(v);
    // Jika admin biasa, update villa_id lokal agar navigasi berikutnya benar
    if (S.user.role === 'admin') S.user.villa_id = v.id;
    const sel = document.getElementById('villa-selector');
    if (sel) { sel.innerHTML += \`<option value="\${v.id}">\${v.name}</option>\`; sel.value = v.id; }
    S.currentVillaId = v.id;
    localStorage.setItem('villa_current_id', v.id);
    e.target.reset();

    const facMsg = facOk > 0 ? \` + \${facOk} fasilitas\` : '';
    const polMsg = polOk > 0 ? \` + \${polOk} kebijakan\` : '';
    const failMsg = (facFail + polFail) > 0 ? \` (\${facFail+polFail} item gagal)\` : '';
    showToast(\`Villa "\${v.name}" berhasil dibuat!\${facMsg}\${polMsg} disimpan\${failMsg}\`, 'success');
    showSection('policies');
  } catch (err) { showToast(err.message, 'error'); }
  finally { submitBtn && (submitBtn.disabled = false); }
}

// ── Helper: Fasilitas di form Villa Baru ───────────────────────────
window._nvFacilities = [];

function nvRenderFacList() {
  const facs = window._nvFacilities || [];
  const list = document.getElementById('nv-fac-list');
  const cnt  = document.getElementById('nv-fac-count');
  if (!list) return;
  if (cnt) cnt.textContent = facs.length;
  list.innerHTML = facs.length ? facs.map((f, i) => \`
    <div class="flex items-center gap-2 bg-slate-50 rounded-lg px-3 py-2">
      <span class="material-symbols-outlined text-green-600" style="font-size:16px;">\${f.icon || 'star'}</span>
      <span class="text-sm text-slate-700 flex-1 font-medium">\${f.name}</span>
      \${f.description ? \`<span class="text-slate-400 text-xs hidden sm:inline">— \${f.description}</span>\` : ''}
      <button onclick="nvRemoveFacility(\${i})" class="p-1 rounded hover:bg-red-100 text-red-400" title="Hapus">
        <span class="material-symbols-outlined" style="font-size:15px;">close</span>
      </button>
    </div>\`).join('') : '<p class="text-slate-400 text-sm italic">Belum ada fasilitas — tambahkan manual di bawah atau gunakan AI di atas</p>';
}

function nvAddFacility() {
  const name = document.getElementById('nv-fac-name')?.value.trim();
  const icon = document.getElementById('nv-fac-icon')?.value.trim() || 'star';
  const desc = document.getElementById('nv-fac-desc')?.value.trim() || '';
  if (!name) return showToast('Nama fasilitas wajib diisi', 'error');
  if (!window._nvFacilities) window._nvFacilities = [];
  window._nvFacilities.push({ name, icon, description: desc, sort_order: window._nvFacilities.length, is_active: true });
  document.getElementById('nv-fac-name').value = '';
  document.getElementById('nv-fac-icon').value = '';
  document.getElementById('nv-fac-desc').value = '';
  nvRenderFacList();
  showToast('Fasilitas ditambahkan', 'success');
}

function nvRemoveFacility(idx) {
  if (!window._nvFacilities) return;
  window._nvFacilities.splice(idx, 1);
  window._nvFacilities.forEach((f, i) => f.sort_order = i);
  nvRenderFacList();
}

// ── Helper: Kebijakan di form Villa Baru ───────────────────────────
const NV_DEFAULT_POLICIES = [
  { type: 'prohibition', content: 'Dilarang membawa atau mengkonsumsi minuman keras / alkohol' },
  { type: 'prohibition', content: 'Dilarang melakukan tindakan asusila / mesum di dalam villa' },
  { type: 'prohibition', content: 'Dilarang membawa atau menggunakan narkoba dan obat-obatan terlarang' },
  { type: 'prohibition', content: 'Dilarang membawa hewan peliharaan' },
  { type: 'prohibition', content: 'Dilarang mengadakan pesta atau kegiatan tidak bermoral lainnya' },
  { type: 'rule',        content: 'Tamu wajib menjaga kebersihan dan ketertiban villa selama menginap' },
  { type: 'schedule',    content: 'Check-in mulai pukul 14.00 WIB, Check-out pukul 12.00 WIB' },
];
window._nvPolicies = [];

const POL_LABELS = { prohibition: '🚫', rule: '📋', schedule: '🕐', note: '📝' };
const POL_COLORS = { prohibition: 'text-red-500', rule: 'text-blue-500', schedule: 'text-amber-500', note: 'text-slate-500' };

function nvRenderPolList() {
  const pols = window._nvPolicies || [];
  const list = document.getElementById('nv-pol-list');
  const cnt  = document.getElementById('nv-pol-count');
  if (!list) return;
  if (cnt) cnt.textContent = pols.length;
  list.innerHTML = pols.length ? pols.map((p, i) => \`
    <div class="flex items-start gap-2 bg-slate-50 rounded-lg px-3 py-2">
      <span class="\${POL_COLORS[p.type] || 'text-slate-400'} text-sm mt-0.5">\${POL_LABELS[p.type] || '•'}</span>
      <span class="text-sm text-slate-700 flex-1">\${p.content}</span>
      <button onclick="nvRemovePolicy(\${i})" class="p-1 rounded hover:bg-red-100 text-red-400 flex-shrink-0" title="Hapus">
        <span class="material-symbols-outlined" style="font-size:15px;">close</span>
      </button>
    </div>\`).join('') : '<p class="text-slate-400 text-sm italic">Belum ada kebijakan — tambahkan manual, gunakan AI, atau klik "Default Syariah"</p>';
}

function nvAddPolicy() {
  const type    = document.getElementById('nv-pol-type')?.value || 'prohibition';
  const content = document.getElementById('nv-pol-content')?.value.trim();
  if (!content) return showToast('Isi kebijakan wajib diisi', 'error');
  if (!window._nvPolicies) window._nvPolicies = [];
  window._nvPolicies.push({ type, content, sort_order: window._nvPolicies.length });
  document.getElementById('nv-pol-content').value = '';
  nvRenderPolList();
  showToast('Kebijakan ditambahkan', 'success');
}

function nvRemovePolicy(idx) {
  if (!window._nvPolicies) return;
  window._nvPolicies.splice(idx, 1);
  window._nvPolicies.forEach((p, i) => p.sort_order = i);
  nvRenderPolList();
}

function nvResetDefaultPolicies() {
  window._nvPolicies = NV_DEFAULT_POLICIES.map((p, i) => ({ ...p, sort_order: i }));
  nvRenderPolList();
  showToast('Kebijakan default syariah dimuat', 'success');
}

// ── Utils ──────────────────────────────────────────────────────────
function esc(str) { return (str||'').replace(/'/g, "\\\\'").replace(/"/g, '&quot;'); }

// ── Section: Import AI ─────────────────────────────────────────────
const AI_URL = window.location.origin + '/ai';

function renderAIImport() {
  if (!villaId()) return setContent('<div class="text-slate-400 text-center pt-20">Pilih villa terlebih dahulu</div>');
  setContent(\`
    <div class="mb-6">
      <h1 class="text-xl font-bold text-slate-800">Import Data Villa dengan AI</h1>
      <p class="text-sm text-slate-400 mt-1">Tempel teks bebas — dari WhatsApp, brosur, catatan, apapun. AI akan otomatis mengisi semua data.</p>
    </div>

    <div class="card p-5 mb-5">
      <label>Data Villa (tempel teks bebas di sini)</label>
      <textarea id="ai-input" rows="13" placeholder="Contoh:&#10;VILLA DIANDRA 2 sekipan Tawangmangu&#10;&#10;FASILITAS:&#10;🏊 Kolam renang privat&#10;🛏️ 3 kamar tidur...&#10;&#10;Check-in: 14.00 WIB | Check-out: 12.00 WIB&#10;☎️ 082228981345&#10;..."></textarea>
      <div class="flex flex-wrap gap-3 mt-4">
        <button class="btn btn-primary" onclick="doAIImport()" id="ai-btn">
          <span class="material-symbols-outlined icon-fill">auto_awesome</span>Analisa dengan AI
        </button>
        <button class="btn btn-ghost" onclick="document.getElementById('ai-input').value='';document.getElementById('ai-result').innerHTML=''">
          <span class="material-symbols-outlined">clear</span>Hapus
        </button>
      </div>
      <p id="ai-status" class="text-xs text-slate-500 mt-3 flex items-center gap-1.5"></p>
    </div>

    <div id="ai-result"></div>
  \`);
}

async function doAIImport() {
  const rawText = document.getElementById('ai-input').value.trim();
  if (!rawText) return showToast('Tempel data villa terlebih dahulu', 'error');

  const btn    = document.getElementById('ai-btn');
  const status = document.getElementById('ai-status');
  btn.disabled = true;
  btn.innerHTML = '<span class="material-symbols-outlined" style="animation:spin 1s linear infinite">progress_activity</span>Sedang menganalisa...';
  status.innerHTML = '<span class="material-symbols-outlined" style="font-size:14px;color:#7c3aed;">auto_awesome</span> AI sedang membaca dan mengekstrak data villa…';

  const logic = \`Kamu adalah asisten ekstraksi data villa profesional. Tugasmu: baca teks bebas tentang villa dan kembalikan HANYA JSON valid tanpa penjelasan, tanpa markdown, tanpa kode block.

OUTPUT WAJIB berisi 4 key: villa_info, facilities, policies, contacts.

Contoh output LENGKAP:
{
  "villa_info": {
    "name": "Villa Diandra 2",
    "slug": "villa-diandra-2",
    "tagline": "Villa eksklusif dengan kolam renang privat",
    "description": "Villa Diandra 2 adalah villa eksklusif di kawasan Villa Tawangmangu yang menawarkan kenyamanan premium di udara sejuk pegunungan. Cocok untuk keluarga dan rombongan yang ingin menikmati suasana Glamping Tawangmangu yang asri. Tersedia kolam renang privat, kamar tidur luas, dan berbagai fasilitas lengkap untuk pengalaman menginap yang tak terlupakan.",
    "address": "Sekipan, Tawangmangu",
    "city": "Karanganyar",
    "province": "Jawa Tengah",
    "max_guests": 25,
    "max_guests_note": "Dengan extra bed maks 30 orang",
    "extra_bed_price": 150000,
    "extra_bed_note": "Per malam per extra bed",
    "checkin_time": "14.00 WIB",
    "checkout_time": "12.00 WIB"
  },
  "facilities": [
    { "name": "Kolam Renang Privat", "icon": "pool", "description": "Kolam renang khusus tamu villa", "sort_order": 1 },
    { "name": "WiFi", "icon": "wifi", "description": "Internet gratis seluruh area", "sort_order": 2 },
    { "name": "Parkir Luas", "icon": "local_parking", "description": "Area parkir dalam", "sort_order": 3 }
  ],
  "policies": [
    { "type": "schedule", "content": "Check-in 14.00 WIB, Check-out 12.00 WIB", "sort_order": 1 },
    { "type": "prohibition", "content": "Dilarang membawa hewan peliharaan", "sort_order": 2 }
  ],
  "contacts": [
    { "type": "whatsapp", "label": "Admin Villa", "value": "082228981345", "is_primary": true }
  ]
}

ATURAN WAJIB:
1. villa_info.description WAJIB berupa ARTIKEL DESKRIPTIF PANJANG (minimal 4-5 kalimat), bukan kalimat pendek. Gabungkan SEMUA informasi dari teks: nama villa, lokasi, suasana alam, fasilitas unggulan, kapasitas, cocok untuk acara apa, keunggulan villa. Tulis seperti artikel promosi wisata yang menarik dan informatif.
2. KEY "facilities" HARUS ADA dan HARUS DIISI dari teks — ekstrak SEMUA fasilitas yang disebut (kolam renang, kamar tidur, dapur, wifi, AC, TV, parkir, bbq, dll)
3. Setiap fasilitas beri "description" yang deskriptif dan spesifik berdasarkan teks
4. slug: huruf kecil, spasi jadi tanda hubung, hapus karakter aneh
5. facilities.icon: gunakan nama ikon Material Symbols (pool, wifi, local_parking, kitchen, tv, king_bed, shower, outdoor_grill, meeting_room, spa, fitness_center, ac_unit, balcony, camera_outdoor, restaurant, hot_tub, forest, water, backyard, deck, fireplace, checkroom, bed, chair, counter_7, living)
6. policies.type harus salah satu: "schedule", "prohibition", "note", "rule"
7. max_guests dan extra_bed_price harus integer, bukan string
8. contacts.value: format 08xxx (tanpa +62 atau 62)
9. LOKASI FALLBACK: Jika alamat/kota/provinsi tidak disebutkan atau tidak jelas, wajib isi: address="Tawangmangu", city="Karanganyar", province="Jawa Tengah"
10. WAJIB: villa_info.description HARUS menyebut "Villa Tawangmangu" atau "Glamping Tawangmangu" minimal satu kali secara alami dalam kalimat (contoh: "... berlokasi di kawasan Villa Tawangmangu yang sejuk..." atau "... tersedia pilihan Glamping Tawangmangu yang asri...")
11. HARGA/TARIF: Jika teks menyebut harga atau tarif sewa dalam bentuk apapun (harga per malam, tarif weekday, tarif weekend, tarif high season, paket, dll), WAJIB masukkan informasi harga tersebut secara NATURAL dan LENGKAP ke dalam villa_info.description agar mudah diindeks Google. Contoh: "...villa ini tersedia dengan harga sewa Rp 2.500.000 per malam (weekday) dan Rp 3.500.000 per malam (weekend)...". Tulis semua rentang harga yang disebutkan. Jangan hilangkan info harga dari deskripsi.
12. Jawab HANYA JSON mentah, tidak ada teks lain sebelum atau sesudah JSON\`;

  const message = \`Ekstrak data villa dari teks berikut dan kembalikan JSON sesuai skema:\\n\\n\${rawText}\`;

  try {
    const res  = await fetch(\`\${AI_URL}?\${new URLSearchParams({ message, logic, memory: '[]' })}\`);
    if (!res.ok) throw new Error(\`AI error: HTTP \${res.status}\`);
    const envelope = await res.json();
    const rawReply = (envelope.reply || envelope.message || envelope.text || JSON.stringify(envelope)).trim();

    // Tampilkan raw response untuk debugging
    const resultEl = document.getElementById('ai-result');
    resultEl.innerHTML = \`
      <div class="card p-4 mb-4">
        <div class="flex items-center justify-between mb-2">
          <span class="text-xs font-semibold text-slate-400 uppercase tracking-wide">Respons Mentah AI</span>
          <button onclick="this.closest('.card').querySelector('pre').classList.toggle('hidden')" class="text-xs text-slate-400 hover:text-slate-600">tampilkan/sembunyikan</button>
        </div>
        <pre class="text-xs text-slate-600 bg-slate-50 rounded-lg p-3 overflow-x-auto whitespace-pre-wrap hidden" style="max-height:200px;overflow-y:auto">\${rawReply.replace(/</g,'&lt;').replace(/>/g,'&gt;')}</pre>
        <p class="text-xs text-slate-400 mt-1">Klik "tampilkan/sembunyikan" untuk lihat output mentah</p>
      </div>
      <div id="ai-parsed-result"></div>\`;

    // Bersihkan markdown code block jika ada
    let text = rawReply.replace(/^\`\`\`json\\s*/i,'').replace(/^\`\`\`\\s*/i,'').replace(/\\s*\`\`\`$/i,'').trim();
    const raw = JSON.parse(text);

    // Normalisasi: handle jika AI balik struktur flat (tanpa villa_info wrapper)
    const VILLA_INFO_KEYS = ['name','slug','tagline','description','address','city','province','max_guests','checkin_time','checkout_time'];
    let data = raw;
    if (!raw.villa_info && VILLA_INFO_KEYS.some(k => k in raw)) {
      // AI returned flat — lift villa fields into villa_info
      const villa_info = {};
      VILLA_INFO_KEYS.concat(['max_guests_note','extra_bed_price','extra_bed_note']).forEach(k => { if (k in raw) villa_info[k] = raw[k]; });
      data = {
        villa_info,
        facilities: raw.facilities || [],
        policies:   raw.policies   || [],
        contacts:   raw.contacts   || [],
      };
    }
    // Pastikan semua array ada
    data.facilities = data.facilities || [];
    data.policies   = data.policies   || [];
    data.contacts   = data.contacts   || [];

    showAIResult(data);
    status.innerHTML = '<span class="material-symbols-outlined" style="font-size:14px;color:#16a34a;">check_circle</span> Selesai! Cek hasil di bawah lalu simpan.';
  } catch (e) {
    status.innerHTML = \`<span class="material-symbols-outlined" style="font-size:14px;color:#991b1b;">error</span> Gagal: \${e.message}\`;
    showToast('AI gagal menganalisa, coba lagi', 'error');
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<span class="material-symbols-outlined icon-fill">auto_awesome</span>Analisa dengan AI';
  }
}

function showAIResult(data) {
  const vi = data.villa_info || {};
  const facilities = data.facilities || [];
  const policies   = data.policies   || [];
  const contacts   = data.contacts   || [];

  const policyTypeColor = { schedule:'bg-blue-50 text-blue-700', note:'bg-yellow-50 text-yellow-700', prohibition:'bg-red-50 text-red-700', rule:'bg-slate-100 text-slate-600' };
  const contactIcon = { whatsapp:'chat', phone:'phone', email:'email', instagram:'photo_camera' };

  const target = document.getElementById('ai-parsed-result') || document.getElementById('ai-result');
  target.innerHTML = \`
    <div class="mb-4 p-4 rounded-xl bg-violet-50 border border-violet-100 text-sm text-violet-700 flex items-start gap-2">
      <span class="material-symbols-outlined icon-fill" style="font-size:18px;color:#7c3aed;flex-shrink:0">info</span>
      <span>Periksa hasil ekstraksi AI di bawah. Klik <strong>Simpan Semua ke Villa</strong> untuk menyimpan sekaligus, atau simpan per-bagian.</span>
    </div>

    <div id="ai-save-err" class="hidden mb-4 p-3 rounded-xl bg-red-50 border border-red-100 text-sm text-red-700"></div>

    <div class="grid md:grid-cols-2 gap-4 mb-4">
      <!-- Info Villa -->
      <div class="card p-4 md:col-span-2">
        <div class="flex items-center justify-between mb-3">
          <span class="font-semibold text-slate-700 flex items-center gap-1.5"><span class="material-symbols-outlined" style="font-size:18px;">home</span>Info Villa</span>
          <button class="btn btn-ghost btn-sm" onclick="aiSaveInfo()"><span class="material-symbols-outlined" style="font-size:15px;">save</span>Simpan</button>
        </div>
        <div class="grid grid-cols-2 gap-x-6 gap-y-1 text-sm">
          \${Object.entries({ Nama: vi.name, Slug: vi.slug, Tagline: vi.tagline, Kota: vi.city, Provinsi: vi.province, 'Check-in': vi.checkin_time, 'Check-out': vi.checkout_time, 'Kapasitas': vi.max_guests, 'Extra Bed': vi.extra_bed_price ? \`Rp\${Number(vi.extra_bed_price).toLocaleString('id')}\` : '-' })
            .map(([k,v]) => \`<div class="text-slate-400 py-0.5">\${k}</div><div class="text-slate-700 py-0.5 font-medium">\${v||'-'}</div>\`).join('')}
        </div>
        \${vi.description ? \`<div class="mt-2 text-xs text-slate-500 border-t border-slate-100 pt-2">\${vi.description}</div>\` : ''}
      </div>

      <!-- Fasilitas -->
      <div class="card p-4 md:col-span-2">
        <div class="flex items-center justify-between mb-3">
          <span class="font-semibold text-slate-700 flex items-center gap-1.5"><span class="material-symbols-outlined" style="font-size:18px;">pool</span>Fasilitas <span id="ai-fac-count" class="badge bg-slate-100 text-slate-500 ml-1">\${facilities.length}</span></span>
          <button class="btn btn-ghost btn-sm" onclick="aiSaveFacilities()"><span class="material-symbols-outlined" style="font-size:15px;">save</span>Simpan</button>
        </div>
        <div id="ai-fac-list" class="space-y-1.5 mb-4">
          \${facilities.length ? facilities.map((f,i)=>\`
            <div class="flex items-center gap-2 bg-slate-50 rounded-lg px-3 py-2">
              <span class="material-symbols-outlined text-green-600" style="font-size:16px;">\${f.icon||'star'}</span>
              <span class="text-sm text-slate-700 flex-1 font-medium">\${f.name}</span>
              \${f.description?\`<span class="text-slate-400 text-xs hidden sm:inline">— \${f.description}</span>\`:''}
              <button onclick="aiRemoveFacility(\${i})" class="p-1 rounded hover:bg-red-100 text-red-400" title="Hapus">
                <span class="material-symbols-outlined" style="font-size:15px;">close</span>
              </button>
            </div>\`).join('') : '<p class="text-slate-400 text-sm italic">Belum ada fasilitas — tambahkan manual di bawah</p>'}
        </div>
        <div class="border-t border-slate-100 pt-3">
          <p class="text-xs font-semibold text-slate-400 uppercase tracking-wide mb-2">Tambah Fasilitas</p>
          <div class="grid grid-cols-1 sm:grid-cols-3 gap-2">
            <input id="ai-fac-name" placeholder="Nama (cth: Kolam Renang)" style="font-size:0.8125rem;padding:7px 10px;"/>
            <input id="ai-fac-icon" placeholder="Ikon Material (cth: pool)" style="font-size:0.8125rem;padding:7px 10px;"/>
            <input id="ai-fac-desc" placeholder="Deskripsi (opsional)" style="font-size:0.8125rem;padding:7px 10px;"/>
          </div>
          <button onclick="aiAddFacility()" class="btn btn-ghost btn-sm mt-2">
            <span class="material-symbols-outlined" style="font-size:15px;">add</span>Tambah ke List
          </button>
        </div>
      </div>

      <!-- Kebijakan -->
      <div class="card p-4">
        <div class="flex items-center justify-between mb-3">
          <span class="font-semibold text-slate-700 flex items-center gap-1.5"><span class="material-symbols-outlined" style="font-size:18px;">rule</span>Kebijakan <span class="badge bg-slate-100 text-slate-500 ml-1">\${policies.length}</span></span>
          <button class="btn btn-ghost btn-sm" onclick="aiSavePolicies()"><span class="material-symbols-outlined" style="font-size:15px;">save</span>Simpan</button>
        </div>
        <div class="space-y-1.5">
          \${policies.map(p=>\`<div class="flex items-start gap-2 text-sm"><span class="badge \${policyTypeColor[p.type]||'bg-slate-100 text-slate-600'} flex-shrink-0 mt-0.5">\${p.type}</span><span class="text-slate-700">\${p.content}</span></div>\`).join('') || '<p class="text-slate-400 text-sm">Tidak ada kebijakan terdeteksi</p>'}
        </div>
      </div>

      <!-- Kontak -->
      <div class="card p-4 md:col-span-2">
        <div class="flex items-center justify-between mb-3">
          <span class="font-semibold text-slate-700 flex items-center gap-1.5"><span class="material-symbols-outlined" style="font-size:18px;">contacts</span>Kontak <span class="badge bg-slate-100 text-slate-500 ml-1">\${contacts.length}</span></span>
          <button class="btn btn-ghost btn-sm" onclick="aiSaveContacts()"><span class="material-symbols-outlined" style="font-size:15px;">save</span>Simpan</button>
        </div>
        <div class="flex flex-wrap gap-2">
          \${contacts.map(c=>\`<div class="flex items-center gap-1.5 bg-slate-50 border border-slate-100 rounded-lg px-3 py-1.5 text-sm"><span class="material-symbols-outlined text-green-600" style="font-size:15px;">\${contactIcon[c.type]||'phone'}</span><span class="text-slate-700">\${c.label||c.type}: <strong>\${c.value}</strong></span>\${c.is_primary?'<span class="badge badge-active ml-1">Utama</span>':''}</div>\`).join('') || '<p class="text-slate-400 text-sm">Tidak ada kontak terdeteksi</p>'}
        </div>
      </div>
    </div>

    <!-- Simpan Semua -->
    <div class="flex flex-wrap gap-3">
      <button class="btn btn-primary" onclick="aiSaveAll()" id="ai-save-all-btn">
        <span class="material-symbols-outlined">save</span>Simpan Semua ke Villa
      </button>
      <button class="btn btn-ghost" onclick="renderAIImport()">
        <span class="material-symbols-outlined">restart_alt</span>Mulai Ulang
      </button>
    </div>
  \`;
  window._aiData = data;
}

function aiRenderFacList() {
  const facs = window._aiData?.facilities || [];
  const list = document.getElementById('ai-fac-list');
  const cnt  = document.getElementById('ai-fac-count');
  if (!list) return;
  cnt && (cnt.textContent = facs.length);
  list.innerHTML = facs.length ? facs.map((f,i) => \`
    <div class="flex items-center gap-2 bg-slate-50 rounded-lg px-3 py-2">
      <span class="material-symbols-outlined text-green-600" style="font-size:16px;">\${f.icon||'star'}</span>
      <span class="text-sm text-slate-700 flex-1 font-medium">\${f.name}</span>
      \${f.description?\`<span class="text-slate-400 text-xs hidden sm:inline">— \${f.description}</span>\`:''}
      <button onclick="aiRemoveFacility(\${i})" class="p-1 rounded hover:bg-red-100 text-red-400" title="Hapus">
        <span class="material-symbols-outlined" style="font-size:15px;">close</span>
      </button>
    </div>\`).join('') : '<p class="text-slate-400 text-sm italic">Belum ada fasilitas — tambahkan manual di bawah</p>';
}

function aiAddFacility() {
  const name = document.getElementById('ai-fac-name')?.value.trim();
  const icon = document.getElementById('ai-fac-icon')?.value.trim() || 'star';
  const desc = document.getElementById('ai-fac-desc')?.value.trim() || '';
  if (!name) return showToast('Nama fasilitas wajib diisi', 'error');
  if (!window._aiData) window._aiData = {};
  if (!window._aiData.facilities) window._aiData.facilities = [];
  window._aiData.facilities.push({ name, icon, description: desc, sort_order: window._aiData.facilities.length });
  document.getElementById('ai-fac-name').value = '';
  document.getElementById('ai-fac-icon').value = '';
  document.getElementById('ai-fac-desc').value = '';
  aiRenderFacList();
  showToast('Fasilitas ditambahkan', 'success');
}

function aiRemoveFacility(idx) {
  if (!window._aiData?.facilities) return;
  window._aiData.facilities.splice(idx, 1);
  window._aiData.facilities.forEach((f, i) => f.sort_order = i);
  aiRenderFacList();
}

async function aiSaveInfo() {
  const vi = window._aiData?.villa_info;
  if (!vi) return showToast('Tidak ada data', 'error');
  try {
    const body = { ...vi };
    if (body.max_guests) body.max_guests = parseInt(body.max_guests);
    if (body.extra_bed_price) body.extra_bed_price = parseInt(body.extra_bed_price);
    await api(\`/villas/\${villaId()}\`, { method: 'PATCH', body: JSON.stringify(body) });
    showToast('Info villa disimpan!', 'success');
  } catch(e) { showToast(e.message, 'error'); }
}

async function aiSaveFacilities() {
  const facs = window._aiData?.facilities;
  if (!facs?.length) return showToast('Tidak ada fasilitas', 'error');
  try {
    for (const f of facs) {
      await api(\`/villas/\${villaId()}/facilities\`, { method: 'POST', body: JSON.stringify({ name: f.name, icon: f.icon||'star', description: f.description||'', sort_order: f.sort_order||0 }) });
    }
    showToast(\`\${facs.length} fasilitas disimpan!\`, 'success');
  } catch(e) { showToast(e.message, 'error'); }
}

async function aiSavePolicies() {
  const pols = window._aiData?.policies;
  if (!pols?.length) return showToast('Tidak ada kebijakan', 'error');
  try {
    for (const p of pols) {
      await api(\`/villas/\${villaId()}/policies\`, { method: 'POST', body: JSON.stringify({ type: p.type, content: p.content, sort_order: p.sort_order||0 }) });
    }
    showToast(\`\${pols.length} kebijakan disimpan!\`, 'success');
  } catch(e) { showToast(e.message, 'error'); }
}

async function aiSaveContacts() {
  const cons = window._aiData?.contacts;
  if (!cons?.length) return showToast('Tidak ada kontak', 'error');
  try {
    for (const c of cons) {
      await api('/contacts/global', { method: 'POST', body: JSON.stringify({ type: c.type, label: c.label||'', value: c.value, is_primary: !!c.is_primary }) });
    }
    showToast(\`\${cons.length} kontak disimpan!\`, 'success');
  } catch(e) { showToast(e.message, 'error'); }
}

async function aiSaveAll() {
  const d = window._aiData;
  if (!d) return showToast('Tidak ada data AI', 'error');
  const btn   = document.getElementById('ai-save-all-btn');
  const errEl = document.getElementById('ai-save-err');
  btn.disabled = true;
  btn.innerHTML = '<span class="material-symbols-outlined" style="animation:spin 1s linear infinite">progress_activity</span>Menyimpan...';
  errEl.classList.add('hidden');

  const errors = [];

  // Info villa
  try {
    const body = { ...(d.villa_info||{}) };
    if (body.max_guests) body.max_guests = parseInt(body.max_guests);
    if (body.extra_bed_price) body.extra_bed_price = parseInt(body.extra_bed_price);
    await api(\`/villas/\${villaId()}\`, { method: 'PATCH', body: JSON.stringify(body) });
  } catch(e) { errors.push('Info villa: ' + e.message); }

  // Fasilitas
  for (const f of (d.facilities||[])) {
    try { await api(\`/villas/\${villaId()}/facilities\`, { method: 'POST', body: JSON.stringify({ name: f.name, icon: f.icon||'star', description: f.description||'', sort_order: f.sort_order||0 }) }); }
    catch(e) { errors.push(\`Fasilitas "\${f.name}": \${e.message}\`); }
  }

  // Kebijakan
  for (const p of (d.policies||[])) {
    try { await api(\`/villas/\${villaId()}/policies\`, { method: 'POST', body: JSON.stringify({ type: p.type, content: p.content, sort_order: p.sort_order||0 }) }); }
    catch(e) { errors.push(\`Kebijakan: \${e.message}\`); }
  }

  // Kontak
  for (const c of (d.contacts||[])) {
    try { await api('/contacts/global', { method: 'POST', body: JSON.stringify({ type: c.type, label: c.label||'', value: c.value, is_primary: !!c.is_primary }) }); }
    catch(e) { errors.push(\`Kontak \${c.value}: \${e.message}\`); }
  }

  btn.disabled = false;
  btn.innerHTML = '<span class="material-symbols-outlined">save</span>Simpan Semua ke Villa';

  if (errors.length) {
    errEl.textContent = 'Beberapa gagal: ' + errors.join(' · ');
    errEl.classList.remove('hidden');
    showToast('Ada beberapa item yang gagal disimpan', 'error');
  } else {
    showToast('Semua data villa berhasil disimpan!', 'success');
  }
}

// ── Init ───────────────────────────────────────────────────────────
if (S.token && S.user) {
  enterDashboard();
}
</script>
<script>if('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js');</script>
</body>
</html>
`;

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
        return html(ADMIN_HTML);
      }
      // ── AI: GET /ai ─────────────────────────────────────────────
      if (method === "GET" && path === "/ai") {
        const message = url.searchParams.get("message") || "";
        const logic   = url.searchParams.get("logic")   || "";
        const memory  = url.searchParams.get("memory")  || "[]";
        if (!env.OPENROUTER_KEY) return json({ error: "OPENROUTER_KEY belum diset" }, 500);
        let history = [];
        try { history = JSON.parse(memory); } catch {}
        const messages = [
          { role: "system",  content: logic },
          ...history,
          { role: "user",    content: message },
        ];
        const aiRes = await fetch("https://openrouter.ai/api/v1/chat/completions", {
          method: "POST",
          headers: {
            "Authorization": `Bearer ${env.OPENROUTER_KEY}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            model: "openai/gpt-4o-mini",
            messages,
            temperature: 0.7,
          }),
        });
        const aiData = await aiRes.json();
        if (!aiRes.ok) return json({ error: aiData.error?.message || "OpenRouter error" }, 502);
        return json({ reply: aiData.choices?.[0]?.message?.content ?? "" });
      }

      // ── MANIFEST.JSON ───────────────────────────────────────────
      if (method === "GET" && path === "/manifest.json") {
        const manifest = {
          name: "Villa Tawangmangu",
          short_name: "Villa TWM",
          description: "Sewa villa eksklusif di Sekipan, Tawangmangu, Karanganyar",
          start_url: "/",
          scope: "/",
          display: "standalone",
          background_color: "#f8faf8",
          theme_color: "#1e3a2f",
          orientation: "portrait-primary",
          icons: [
            { src: "https://cdn.jsdelivr.net/gh/SAFELFAR05/Up@main/images/villas/a1b2c3d4-e5f6-7890-abcd-ef1234567890/1778673470866.jpg", sizes: "192x192", type: "image/jpeg", purpose: "any" },
            { src: "https://cdn.jsdelivr.net/gh/SAFELFAR05/Up@main/images/villas/a1b2c3d4-e5f6-7890-abcd-ef1234567890/1778673470866.jpg", sizes: "512x512", type: "image/jpeg", purpose: "any maskable" },
          ],
          shortcuts: [
            { name: "Lihat Villa", url: "/", icons: [] },
            { name: "Admin", url: "/admin/", icons: [] },
          ],
        };
        return new Response(JSON.stringify(manifest), {
          headers: { "Content-Type": "application/manifest+json", "Cache-Control": "public, max-age=86400" }
        });
      }

      // ── SERVICE WORKER ───────────────────────────────────────────
      if (method === "GET" && path === "/sw.js") {
        const sw = `const CACHE='villa-twm-v1';const SHELL=['/'];
self.addEventListener('install',e=>{e.waitUntil(caches.open(CACHE).then(c=>c.addAll(SHELL)).then(()=>self.skipWaiting()));});
self.addEventListener('activate',e=>{e.waitUntil(caches.keys().then(keys=>Promise.all(keys.filter(k=>k!==CACHE).map(k=>caches.delete(k)))).then(()=>self.clients.claim()));});
self.addEventListener('fetch',e=>{
  if(e.request.method!=='GET')return;
  const u=new URL(e.request.url);
  const skip=['/api/','/auth/','/villas','/inquiries','/upload','/admin','/sw.js','/manifest.json'];
  if(skip.some(s=>u.pathname.startsWith(s)))return;
  e.respondWith(
    fetch(e.request).then(res=>{
      if(res.ok&&(u.pathname==='/'||u.pathname.startsWith('/villa/'))){
        caches.open(CACHE).then(c=>c.put(e.request,res.clone()));
      }
      return res;
    }).catch(()=>caches.match(e.request).then(r=>r||caches.match('/')))
  );
});`;
        return new Response(sw, {
          headers: { "Content-Type": "application/javascript", "Cache-Control": "no-cache, no-store" }
        });
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
        const [facilities, gallery, policies, villaContacts, globalContacts, allVillas] = await Promise.all([
          sb(env, "facilities", "GET", `villa_id=eq.${v.id}&is_active=eq.true&order=sort_order.asc`),
          sb(env, "gallery",    "GET", `villa_id=eq.${v.id}&is_active=eq.true&order=sort_order.asc`),
          sb(env, "policies",   "GET", `villa_id=eq.${v.id}&order=sort_order.asc`),
          sb(env, "contacts",   "GET", `villa_id=eq.${v.id}`),
          sb(env, "contacts",   "GET", "villa_id=is.null"),
          sb(env, "villa_info", "GET", `id=neq.${v.id}&select=id,name,slug,tagline,max_guests,city,province&order=created_at.asc`),
        ]);
        const merged = [...villaContacts];
        for (const gc of globalContacts) if (!merged.some(c => c.type === gc.type)) merged.push(gc);

        // Similar villas: sort by capacity proximity, max 8
        const cap = v.max_guests || 0;
        const topSimilar = allVillas
          .filter(x => x.slug)
          .sort((a, b) => Math.abs((a.max_guests||0) - cap) - Math.abs((b.max_guests||0) - cap))
          .slice(0, 8);

        // Fetch one cover image per similar villa in a single query
        let similarVillas = topSimilar;
        if (topSimilar.length) {
          const ids = topSimilar.map(x => x.id).join(",");
          const covers = await sb(env, "gallery", "GET", `villa_id=in.(${ids})&is_active=eq.true&order=sort_order.asc`);
          const coverMap = {};
          for (const img of covers) if (!coverMap[img.villa_id]) coverMap[img.villa_id] = img;
          similarVillas = topSimilar.map(x => ({ ...x, cover: coverMap[x.id] || null }));
        }

        return html(renderVillaPage(v, facilities, gallery, policies, merged, similarVillas));
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
        const mimeToExt = { "image/webp": "webp", "image/png": "png", "image/gif": "gif", "image/jpeg": "jpg", "image/jpg": "jpg" };
        const ext = mimeToExt[file.type] || (file.name?.split(".").pop() || "jpg").toLowerCase().replace("jpeg","jpg");
        const imgPath = `${env.GITHUB_IMG_PATH||"images/villas"}/${villaId}/${Date.now()}.${ext}`;
        const buf  = await file.arrayBuffer();
        // chunk-based base64 — aman untuk file besar (hindari stack overflow saat spread)
        const bytes = new Uint8Array(buf);
        let b64 = "";
        const CHUNK = 8192;
        for (let i = 0; i < bytes.length; i += CHUNK) {
          b64 += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
        }
        b64 = btoa(b64);
        const branch = env.GITHUB_BRANCH || "main";
        const ghRes = await fetch(`https://api.github.com/repos/${env.GITHUB_REPO}/contents/${imgPath}`, {
          method: "PUT",
          headers: { Authorization: `Bearer ${env.GITHUB_TOKEN}`, "Content-Type": "application/json", "User-Agent": "VillaWorker/1.0" },
          body: JSON.stringify({ message: `Upload ${imgPath}`, content: b64, branch }),
        });
        if (!ghRes.ok) return json({ error: `GitHub upload gagal: ${await ghRes.text()}` }, 500);
        // pakai jsDelivr sebagai CDN — lebih cepat & tidak ada rate limit GitHub raw
        const cdnUrl = `https://cdn.jsdelivr.net/gh/${env.GITHUB_REPO}@${branch}/${imgPath}`;
        const gallery = await sb(env, "gallery", "POST", "", { villa_id:villaId, url:cdnUrl, alt, sort_order:0, is_active:true });
        return json({ url: cdnUrl, gallery: gallery[0]||gallery }, 201);
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
