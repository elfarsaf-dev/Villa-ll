import { COMMON_HEAD, TAILWIND_COLORS } from "./styles.js";

type Villa = Record<string, any>;
type FacilityItem = Record<string, any>;
type GalleryItem = Record<string, any>;
type PolicyItem = Record<string, any>;
type Contact = Record<string, any>;

function escape(s: unknown): string {
  if (s == null) return "";
  return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}

function escapeAttr(s: unknown): string {
  if (s == null) return "";
  return String(s).replace(/&/g,"&amp;").replace(/"/g,"&quot;");
}

function waHref(contact?: Contact): string {
  const num = contact?.value?.replace(/\D/g,"");
  return num ? `https://wa.me/62${num.replace(/^0/,"")}` : "#";
}

function renderHeroSlider(gallery: GalleryItem[]): string {
  if (!gallery.length) {
    return `<div class="flex-none w-full h-full snap-start relative bg-primary flex items-center justify-center">
      <span class="material-symbols-outlined text-white/20" style="font-size:100px;">villa</span>
      <div class="absolute inset-0 bg-gradient-to-b from-black/40 via-black/10 to-black/70"></div>
    </div>`;
  }
  const slides = gallery.slice(0, 5);
  return slides.map((img, i) =>
    `<div class="flex-none w-full h-full snap-start relative">
      <img class="w-full h-full object-cover" src="${escapeAttr(img.url)}" alt="${escapeAttr(img.alt || "")}" ${i > 0 ? 'loading="lazy"' : ''}/>
      <div class="absolute inset-0 bg-gradient-to-b from-black/40 via-black/10 to-black/70"></div>
    </div>`
  ).join("");
}

function renderDots(count: number): string {
  if (count <= 1) return "";
  return Array.from({ length: count }, (_, i) =>
    `<button class="dot-btn transition-all duration-300" style="width:${i===0?"20":"8"}px;height:3px;border-radius:2px;background:white;opacity:${i===0?"1":"0.4"};border:none;cursor:pointer;" onclick="goToSlide(${i})"></button>`
  ).join("");
}

function renderAboutImages(gallery: GalleryItem[]): string {
  const imgs = gallery.slice(0, 3);
  if (imgs.length >= 3) return `
    <div class="img-zoom overflow-hidden rounded-xl row-span-2"><img src="${escapeAttr(imgs[0].url)}" alt="${escapeAttr(imgs[0].alt||"")}" class="w-full h-full object-cover" style="min-height:280px;"/></div>
    <div class="img-zoom overflow-hidden rounded-xl"><img src="${escapeAttr(imgs[1].url)}" alt="${escapeAttr(imgs[1].alt||"")}" class="w-full h-48 object-cover"/></div>
    <div class="img-zoom overflow-hidden rounded-xl"><img src="${escapeAttr(imgs[2].url)}" alt="${escapeAttr(imgs[2].alt||"")}" class="w-full h-48 object-cover"/></div>`;
  if (imgs.length === 2) return `
    <div class="img-zoom overflow-hidden rounded-xl"><img src="${escapeAttr(imgs[0].url)}" alt="" class="w-full h-64 object-cover"/></div>
    <div class="img-zoom overflow-hidden rounded-xl"><img src="${escapeAttr(imgs[1].url)}" alt="" class="w-full h-64 object-cover"/></div>`;
  if (imgs.length === 1) return `
    <div class="img-zoom overflow-hidden rounded-xl col-span-2"><img src="${escapeAttr(imgs[0].url)}" alt="" class="w-full h-80 object-cover"/></div>`;
  return `<div class="col-span-2 bg-surface-container rounded-xl h-64 flex items-center justify-center"><span class="material-symbols-outlined text-outline" style="font-size:60px;">villa</span></div>`;
}

function renderGalleryGrid(gallery: GalleryItem[]): string {
  if (!gallery.length) return `<div class="col-span-3 text-center py-16 text-on-surface-variant">
    <span class="material-symbols-outlined text-4xl mb-3 block opacity-40">photo_library</span>
    <p class="text-sm">Foto galeri akan segera hadir.</p>
  </div>`;
  return gallery.map((img, i) => {
    const cls = i === 0 ? "col-span-2 md:col-span-1 md:row-span-2" : (i === gallery.length - 1 && gallery.length % 2 === 0 ? "col-span-2" : "");
    const h = i === 0 ? "h-60 md:h-full" : "h-52";
    return `<div class="img-zoom overflow-hidden rounded-xl ${cls}"><img src="${escapeAttr(img.url)}" alt="${escapeAttr(img.alt||"")}" class="w-full ${h} object-cover" loading="lazy"/></div>`;
  }).join("");
}

function renderFacilities(facilities: FacilityItem[]): string {
  if (!facilities.length) return `<div class="col-span-4 text-center py-10 text-on-surface-variant text-sm">Belum ada fasilitas.</div>`;
  return facilities.map(f => `
    <div class="bg-white rounded-xl p-5 flex flex-col items-center text-center hover:shadow-md transition-shadow">
      <span class="material-symbols-outlined text-primary mb-3" style="font-size:30px;">${escape(f.icon || "star")}</span>
      <h5 class="text-[10px] tracking-widest uppercase font-semibold text-primary mb-2">${escape(f.name)}</h5>
      <p class="text-[0.75rem] text-on-surface-variant leading-relaxed">${escape(f.description || "")}</p>
    </div>`).join("");
}

function renderPolicies(policies: PolicyItem[]): string {
  const schedules    = policies.filter(p => p.type === "schedule");
  const notes        = policies.filter(p => p.type === "note");
  const prohibitions = policies.filter(p => p.type === "prohibition");
  const rules        = policies.filter(p => p.type === "rule");
  let html = "";
  if (schedules.length) html += `<div class="bg-white rounded-xl p-6"><div class="flex items-center gap-3 mb-4"><span class="material-symbols-outlined text-primary">schedule</span><h3 class="font-semibold text-primary">Jadwal &amp; Waktu</h3></div><ul class="space-y-2 text-[0.875rem] text-on-surface-variant">${schedules.map(p=>`<li class="flex gap-2 items-start"><span class="material-symbols-outlined text-secondary" style="font-size:16px;margin-top:2px;">circle</span>${escape(p.content)}</li>`).join("")}</ul></div>`;
  if (notes.length)     html += `<div class="bg-white rounded-xl p-6"><div class="flex items-center gap-3 mb-4"><span class="material-symbols-outlined text-yellow-600">info</span><h3 class="font-semibold text-primary">Catatan Penting</h3></div><ul class="space-y-2 text-[0.875rem] text-on-surface-variant">${notes.map(p=>`<li class="flex gap-2 items-start"><span class="material-symbols-outlined text-yellow-500" style="font-size:16px;margin-top:2px;">warning</span>${escape(p.content)}</li>`).join("")}</ul></div>`;
  if (rules.length)     html += `<div class="bg-white rounded-xl p-6"><div class="flex items-center gap-3 mb-4"><span class="material-symbols-outlined text-primary">gavel</span><h3 class="font-semibold text-primary">Aturan Villa</h3></div><ul class="space-y-2 text-[0.875rem] text-on-surface-variant">${rules.map(p=>`<li class="flex gap-2 items-start"><span class="material-symbols-outlined text-primary" style="font-size:16px;margin-top:2px;">check_circle</span>${escape(p.content)}</li>`).join("")}</ul></div>`;
  if (prohibitions.length) {
    const span = (schedules.length || notes.length || rules.length) ? " md:col-span-2" : "";
    html += `<div class="bg-white rounded-xl p-6${span}"><div class="flex items-center gap-3 mb-4"><span class="material-symbols-outlined text-red-500">block</span><h3 class="font-semibold text-primary">Larangan</h3></div><div class="grid sm:grid-cols-2 gap-3">${prohibitions.map(p=>`<div class="flex items-start gap-2 p-3 rounded bg-red-50 border border-red-200"><span class="material-symbols-outlined text-red-400" style="font-size:18px;flex-shrink:0;margin-top:1px;">cancel</span><span class="text-[0.8125rem] text-on-surface-variant">${escape(p.content)}</span></div>`).join("")}</div></div>`;
  }
  return html || `<div class="md:col-span-2 text-center py-10 text-on-surface-variant text-sm">Belum ada kebijakan.</div>`;
}

function renderContacts(contacts: Contact[]): string {
  return contacts.filter(c => c.value).map(c => {
    const href = c.type === "whatsapp" || c.type === "phone" ? `tel:${c.value}` : c.type === "email" ? `mailto:${c.value}` : "#";
    const icon = c.type === "whatsapp" ? "chat" : c.type === "email" ? "email" : "phone";
    return `<li><a href="${href}" class="hover:text-primary transition-colors flex items-center gap-1"><span class="material-symbols-outlined" style="font-size:14px;">${icon}</span>${escape(c.value)}</a></li>`;
  }).join("") || "<li>—</li>";
}

export function renderVillaPage(
  v: Villa,
  facilities: FacilityItem[],
  gallery: GalleryItem[],
  policies: PolicyItem[],
  contacts: Contact[]
): string {
  const location    = [v.address, v.city, v.province].filter(Boolean).join(", ");
  const waContact   = contacts.find(c => c.type === "whatsapp" && c.is_primary) || contacts.find(c => c.type === "whatsapp");
  const phoneContact = contacts.find(c => c.type === "phone");
  const wa          = waHref(waContact);
  const contactNum  = waContact?.value || phoneContact?.value;
  const year        = new Date().getFullYear();
  const price       = v.extra_bed_price ? new Intl.NumberFormat("id-ID").format(v.extra_bed_price) : null;
  const slugPath    = v.slug ? `/villa/${encodeURIComponent(v.slug)}` : `/villa/?id=${v.id}`;

  const slides     = gallery.slice(0, 5);
  const dotsHtml   = renderDots(slides.length);
  const heroSlides = renderHeroSlider(gallery);

  let aboutMeta = "";
  if (v.checkin_time)    aboutMeta += `<div class="border-l-2 border-primary/20 pl-4 py-1"><h4 class="text-[10px] tracking-widest uppercase font-semibold text-primary mb-1">Check-in</h4><p class="text-[0.875rem] text-on-surface-variant font-semibold">${escape(v.checkin_time)}</p></div>`;
  if (v.checkout_time)   aboutMeta += `<div class="border-l-2 border-primary/20 pl-4 py-1"><h4 class="text-[10px] tracking-widest uppercase font-semibold text-primary mb-1">Check-out</h4><p class="text-[0.875rem] text-on-surface-variant font-semibold">${escape(v.checkout_time)}</p></div>`;
  if (price)             aboutMeta += `<div class="border-l-2 border-primary/20 pl-4 py-1"><h4 class="text-[10px] tracking-widest uppercase font-semibold text-primary mb-1">Extra Bed</h4><p class="text-[0.875rem] text-on-surface-variant font-semibold">Rp${price}/bed</p>${v.extra_bed_note?`<p class="text-[10px] text-on-surface-variant">${escape(v.extra_bed_note)}</p>`:""}</div>`;

  const descHtml = (v.description || v.tagline || "")
    .split("\n").filter(Boolean).map((p: string) => `<p>${escape(p)}</p>`).join("") || `<p>${escape(v.tagline || "")}</p>`;

  let contactInfoHtml = "";
  if (contactNum) contactInfoHtml += `<div><span class="material-symbols-outlined opacity-40 block mb-1" style="font-size:20px;">phone</span><p class="text-[9px] tracking-widest uppercase opacity-40 mb-1">Telepon / WA</p><a href="tel:${escape(contactNum)}" class="text-sm opacity-70 hover:opacity-100 transition-opacity">${escape(contactNum)}</a></div>`;
  if (location)   contactInfoHtml += `<div><span class="material-symbols-outlined opacity-40 block mb-1" style="font-size:20px;">location_on</span><p class="text-[9px] tracking-widest uppercase opacity-40 mb-1">Lokasi</p><span class="text-sm opacity-70">${escape(location)}</span></div>`;
  if (v.checkin_time || v.checkout_time) contactInfoHtml += `<div><span class="material-symbols-outlined opacity-40 block mb-1" style="font-size:20px;">schedule</span><p class="text-[9px] tracking-widest uppercase opacity-40 mb-1">Check-in / out</p><span class="text-sm opacity-70">${escape(v.checkin_time || "—")} / ${escape(v.checkout_time || "—")}</span></div>`;

  return `<!DOCTYPE html>
<html class="light" lang="id">
<head>
  <title>${escapeAttr(v.name)} — Villa Tawangmangu</title>
  <meta name="description" content="${escapeAttr(v.tagline || v.description || "Sewa villa eksklusif di Tawangmangu")}"/>
  <meta name="keywords" content="villa tawangmangu, ${escapeAttr(v.name)}, sewa villa tawangmangu, villa sekipan"/>
  <meta property="og:title" content="${escapeAttr(v.name)} — Villa Tawangmangu"/>
  <meta property="og:description" content="${escapeAttr(v.tagline || v.description || "")}"/>
  ${gallery[0] ? `<meta property="og:image" content="${escapeAttr(gallery[0].url)}"/>` : ""}
  <meta property="og:type" content="website"/>
  <link rel="canonical" href="${slugPath}"/>
  <meta name="robots" content="index, follow"/>
  ${COMMON_HEAD}
  <script>${TAILWIND_COLORS}</script>
  <style>
    .material-symbols-outlined { font-variation-settings:'FILL' 0,'wght' 300,'GRAD' 0,'opsz' 24; font-size:24px; }
    body { background-color:#f8faf8; color:#191d1a; -webkit-font-smoothing:antialiased; font-family:"Plus Jakarta Sans",sans-serif; }
    .snap-x { scroll-snap-type:x mandatory; -webkit-overflow-scrolling:touch; }
    .snap-start { scroll-snap-align:start; }
    .no-scrollbar::-webkit-scrollbar { display:none; }
    .no-scrollbar { -ms-overflow-style:none; scrollbar-width:none; }
    .font-serif { font-family:"Noto Serif",Georgia,serif; }
    html { scroll-behavior:smooth; }
    @keyframes fadeUp { from{opacity:0;transform:translateY(24px)} to{opacity:1;transform:translateY(0)} }
    .fade-up { animation:fadeUp 0.8s ease forwards; }
    .fade-up-delay-1 { animation:fadeUp 0.8s ease 0.15s both; }
    .fade-up-delay-2 { animation:fadeUp 0.8s ease 0.3s both; }
    .fade-up-delay-3 { animation:fadeUp 0.8s ease 0.45s both; }
    .img-zoom img { transition:transform 0.6s ease; }
    .img-zoom:hover img { transform:scale(1.04); }
    nav.scrolled { background:rgba(248,250,248,0.96)!important; border-bottom:1px solid #e0e4e0; }
    input,textarea,select { background:#fff; border:1px solid #bfc9c1; border-radius:0.375rem; padding:12px 16px; width:100%; font-family:"Plus Jakarta Sans",sans-serif; font-size:0.9375rem; color:#191d1a; outline:none; transition:border-color 0.2s; }
    input:focus,textarea:focus,select:focus { border-color:#1e3a2f; }
    textarea { resize:vertical; min-height:110px; }
    .btn-primary { background:#1e3a2f; color:#fff; padding:13px 28px; border-radius:0.375rem; font-size:0.7rem; letter-spacing:0.12em; font-weight:600; text-transform:uppercase; transition:background 0.2s; cursor:pointer; border:none; display:inline-block; text-decoration:none; }
    .btn-primary:hover { background:#2d4f3f; }
    .btn-outline-white { background:transparent; color:rgba(255,255,255,0.8); padding:12px 28px; border-radius:0.375rem; font-size:0.7rem; letter-spacing:0.12em; font-weight:600; text-transform:uppercase; border:1.5px solid rgba(255,255,255,0.4); transition:all 0.2s; cursor:pointer; display:inline-block; text-decoration:none; }
    .btn-outline-white:hover { background:rgba(255,255,255,0.15); color:#fff; }
    .wa-float { position:fixed; bottom:24px; right:24px; z-index:100; width:56px; height:56px; border-radius:50%; background:#25D366; color:#fff; display:flex; align-items:center; justify-content:center; box-shadow:0 4px 20px rgba(37,211,102,0.4); text-decoration:none; transition:transform 0.2s,box-shadow 0.2s; }
    .wa-float:hover { transform:scale(1.08); box-shadow:0 6px 24px rgba(37,211,102,0.5); }
  </style>
</head>
<body>

<a class="wa-float" href="${wa}" target="_blank" rel="noopener" title="Hubungi via WhatsApp">
  <svg width="28" height="28" viewBox="0 0 24 24" fill="currentColor"><path d="M17.472 14.382c-.297-.149-1.758-.867-2.03-.967-.273-.099-.471-.148-.67.15-.197.297-.767.966-.94 1.164-.173.199-.347.223-.644.075-.297-.15-1.255-.463-2.39-1.475-.883-.788-1.48-1.761-1.653-2.059-.173-.297-.018-.458.13-.606.134-.133.298-.347.446-.52.149-.174.198-.298.298-.497.099-.198.05-.371-.025-.52-.075-.149-.669-1.612-.916-2.207-.242-.579-.487-.5-.669-.51-.173-.008-.371-.01-.57-.01-.198 0-.52.074-.792.372-.272.297-1.04 1.016-1.04 2.479 0 1.462 1.065 2.875 1.213 3.074.149.198 2.096 3.2 5.077 4.487.709.306 1.262.489 1.694.625.712.227 1.36.195 1.871.118.571-.085 1.758-.719 2.006-1.413.248-.694.248-1.289.173-1.413-.074-.124-.272-.198-.57-.347m-5.421 7.403h-.004a9.87 9.87 0 01-5.031-1.378l-.361-.214-3.741.982.998-3.648-.235-.374a9.86 9.86 0 01-1.51-5.26c.001-5.45 4.436-9.884 9.888-9.884 2.64 0 5.122 1.03 6.988 2.898a9.825 9.825 0 012.893 6.994c-.003 5.45-4.437 9.884-9.885 9.884m8.413-18.297A11.815 11.815 0 0012.05 0C5.495 0 .16 5.335.157 11.892c0 2.096.547 4.142 1.588 5.945L.057 24l6.305-1.654a11.882 11.882 0 005.683 1.448h.005c6.554 0 11.89-5.335 11.893-11.893a11.821 11.821 0 00-3.48-8.413z"/></svg>
</a>

<nav id="navbar" class="fixed top-0 left-0 right-0 z-50 transition-all duration-300" style="background:transparent;">
  <div class="max-w-6xl mx-auto px-6 h-16 flex items-center justify-between">
    <a href="/" class="font-serif text-lg tracking-widest text-white" id="nav-logo">${escape(v.name || "VILLA TAWANGMANGU").toUpperCase()}</a>
    <div class="hidden md:flex items-center gap-8" id="nav-links">
      <a href="#about"      class="text-[11px] tracking-widest uppercase font-semibold text-white/80 hover:text-white transition-colors">Villa</a>
      <a href="#facilities" class="text-[11px] tracking-widest uppercase font-semibold text-white/80 hover:text-white transition-colors">Fasilitas</a>
      <a href="#gallery"    class="text-[11px] tracking-widest uppercase font-semibold text-white/80 hover:text-white transition-colors">Galeri</a>
      <a href="#rules"      class="text-[11px] tracking-widest uppercase font-semibold text-white/80 hover:text-white transition-colors">Aturan</a>
      <a href="#contact"    class="btn-primary text-[11px] py-2 px-5">Reservasi</a>
    </div>
    <button id="menu-btn" class="md:hidden text-white" onclick="toggleMenu()">
      <span class="material-symbols-outlined">menu</span>
    </button>
  </div>
  <div id="mobile-menu" class="hidden md:hidden px-6 py-4 space-y-4" style="background:rgba(248,250,248,0.98);border-top:1px solid #e0e4e0;">
    <a href="#about"      class="block text-[11px] tracking-widest uppercase font-semibold text-on-surface" onclick="toggleMenu()">Villa</a>
    <a href="#facilities" class="block text-[11px] tracking-widest uppercase font-semibold text-on-surface" onclick="toggleMenu()">Fasilitas</a>
    <a href="#gallery"    class="block text-[11px] tracking-widest uppercase font-semibold text-on-surface" onclick="toggleMenu()">Galeri</a>
    <a href="#rules"      class="block text-[11px] tracking-widest uppercase font-semibold text-on-surface" onclick="toggleMenu()">Aturan</a>
    <a href="#contact"    class="block text-[11px] tracking-widest uppercase font-semibold text-primary" onclick="toggleMenu()">Reservasi</a>
  </div>
</nav>

<!-- HERO -->
<section class="w-full relative overflow-hidden" id="hero">
  <div class="flex overflow-x-auto snap-x no-scrollbar h-screen" id="gallery-slider">
    ${heroSlides}
  </div>
  <div class="absolute bottom-24 left-6 md:left-16 z-10 text-white max-w-xl">
    <p class="fade-up text-[10px] tracking-[0.2em] uppercase font-semibold mb-3 opacity-70">${escape(location)}</p>
    <h1 class="fade-up-delay-1 font-serif text-4xl md:text-6xl leading-tight mb-3">${escape(v.name)}</h1>
    <p class="fade-up-delay-2 text-sm md:text-base opacity-80 leading-relaxed max-w-sm">${escape(v.tagline || "")}</p>
    <div class="fade-up-delay-3 flex flex-wrap gap-3 mt-6">
      <a href="#contact" class="btn-primary">Hubungi Admin</a>
      <a href="#about"   class="btn-outline-white">Selengkapnya</a>
    </div>
  </div>
  <div class="absolute bottom-8 left-1/2 -translate-x-1/2 flex gap-2 z-10" id="dots">${dotsHtml}</div>
</section>

<!-- STATS -->
<section class="bg-primary text-white">
  <div class="max-w-6xl mx-auto px-6 py-7 grid grid-cols-2 md:grid-cols-4 gap-6 text-center">
    <div><div class="font-serif text-3xl mb-1">${escape(v.max_guests || "—")}</div><div class="text-[10px] tracking-widest uppercase opacity-60">${escape(v.max_guests_note || "Tamu Maksimal")}</div></div>
    <div><div class="font-serif text-xl mb-1">${escape(v.checkin_time || "—")}</div><div class="text-[10px] tracking-widest uppercase opacity-60">Check-in</div></div>
    <div><div class="font-serif text-xl mb-1">${escape(v.checkout_time || "—")}</div><div class="text-[10px] tracking-widest uppercase opacity-60">Check-out</div></div>
    <div><div class="font-serif text-xl mb-1">${escape(v.city || "—")}</div><div class="text-[10px] tracking-widest uppercase opacity-60">${escape(v.province || "Lokasi")}</div></div>
  </div>
</section>

<!-- ABOUT -->
<section id="about" class="py-24 px-6">
  <div class="max-w-6xl mx-auto grid md:grid-cols-2 gap-16 items-center">
    <div>
      <span class="text-[10px] tracking-[0.2em] uppercase font-semibold text-secondary block mb-4">Tentang Villa</span>
      <h2 class="font-serif text-3xl md:text-4xl text-primary leading-snug mb-6">${escape(v.name)}<br/>${escape([v.city, v.province].filter(Boolean).join(", "))}</h2>
      <div class="space-y-4 text-on-surface-variant text-[0.9375rem] leading-relaxed">${descHtml}</div>
      <div class="mt-8 flex flex-wrap gap-6">${aboutMeta}</div>
    </div>
    <div class="grid grid-cols-2 gap-3">${renderAboutImages(gallery)}</div>
  </div>
</section>

<!-- FACILITIES -->
<section id="facilities" class="py-24 px-6" style="background:#ecefec;">
  <div class="max-w-6xl mx-auto">
    <div class="text-center mb-14">
      <span class="text-[10px] tracking-[0.2em] uppercase font-semibold text-secondary block mb-3">Yang Kami Sediakan</span>
      <h2 class="font-serif text-3xl md:text-4xl text-primary">Fasilitas Lengkap</h2>
      <div class="flex items-center justify-center mt-4">
        <div class="w-12 h-[1px] bg-outline-variant"></div>
        <div class="w-1.5 h-1.5 rounded-full bg-primary/30 mx-3"></div>
        <div class="w-12 h-[1px] bg-outline-variant"></div>
      </div>
    </div>
    <div class="grid grid-cols-2 md:grid-cols-4 gap-4">${renderFacilities(facilities)}</div>
  </div>
</section>

<!-- GALLERY -->
<section id="gallery" class="py-24 px-6">
  <div class="max-w-6xl mx-auto">
    <div class="text-center mb-14">
      <span class="text-[10px] tracking-[0.2em] uppercase font-semibold text-secondary block mb-3">Galeri Foto</span>
      <h2 class="font-serif text-3xl md:text-4xl text-primary">Lihat Sendiri Keindahannya</h2>
    </div>
    <div class="grid grid-cols-2 md:grid-cols-3 gap-3">${renderGalleryGrid(gallery)}</div>
  </div>
</section>

<!-- RULES -->
<section id="rules" class="py-24 px-6" style="background:#ecefec;">
  <div class="max-w-4xl mx-auto">
    <div class="text-center mb-12">
      <span class="text-[10px] tracking-[0.2em] uppercase font-semibold text-secondary block mb-3">Ketentuan</span>
      <h2 class="font-serif text-3xl text-primary">Aturan &amp; Kebijakan Villa</h2>
      <p class="text-on-surface-variant text-sm mt-3">Demi kenyamanan bersama, mohon untuk diperhatikan</p>
    </div>
    <div class="grid md:grid-cols-2 gap-6">${renderPolicies(policies)}</div>
  </div>
</section>

<!-- CONTACT -->
<section id="contact" class="py-24 px-6" style="background:#1e3a2f;">
  <div class="max-w-2xl mx-auto">
    <div class="text-center mb-12 text-white">
      <span class="text-[10px] tracking-[0.2em] uppercase font-semibold opacity-60 block mb-3">Reservasi</span>
      <h2 class="font-serif text-3xl md:text-4xl mb-4">Hubungi Admin Villa</h2>
      <p class="text-sm opacity-60 leading-relaxed">Kirim pesan WhatsApp atau isi formulir di bawah — kami akan membalas secepatnya</p>
    </div>
    <div class="text-center mb-10">
      <a href="${wa}" target="_blank" rel="noopener"
         class="inline-flex items-center gap-3 px-8 py-4 rounded-xl text-white font-semibold text-base transition-transform hover:scale-105"
         style="background:#25D366;box-shadow:0 4px 20px rgba(37,211,102,0.35);">
        <svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor"><path d="M17.472 14.382c-.297-.149-1.758-.867-2.03-.967-.273-.099-.471-.148-.67.15-.197.297-.767.966-.94 1.164-.173.199-.347.223-.644.075-.297-.15-1.255-.463-2.39-1.475-.883-.788-1.48-1.761-1.653-2.059-.173-.297-.018-.458.13-.606.134-.133.298-.347.446-.52.149-.174.198-.298.298-.497.099-.198.05-.371-.025-.52-.075-.149-.669-1.612-.916-2.207-.242-.579-.487-.5-.669-.51-.173-.008-.371-.01-.57-.01-.198 0-.52.074-.792.372-.272.297-1.04 1.016-1.04 2.479 0 1.462 1.065 2.875 1.213 3.074.149.198 2.096 3.2 5.077 4.487.709.306 1.262.489 1.694.625.712.227 1.36.195 1.871.118.571-.085 1.758-.719 2.006-1.413.248-.694.248-1.289.173-1.413-.074-.124-.272-.198-.57-.347m-5.421 7.403h-.004a9.87 9.87 0 01-5.031-1.378l-.361-.214-3.741.982.998-3.648-.235-.374a9.86 9.86 0 01-1.51-5.26c.001-5.45 4.436-9.884 9.888-9.884 2.64 0 5.122 1.03 6.988 2.898a9.825 9.825 0 012.893 6.994c-.003 5.45-4.437 9.884-9.885 9.884m8.413-18.297A11.815 11.815 0 0012.05 0C5.495 0 .16 5.335.157 11.892c0 2.096.547 4.142 1.588 5.945L.057 24l6.305-1.654a11.882 11.882 0 005.683 1.448h.005c6.554 0 11.89-5.335 11.893-11.893a11.821 11.821 0 00-3.48-8.413z"/></svg>
        ${waContact ? `Chat WhatsApp — ${escape(waContact.value)}` : "Chat WhatsApp Sekarang"}
      </a>
      <p class="text-white/40 text-xs mt-3">Atau isi formulir di bawah dan kami akan menghubungi Anda</p>
    </div>
    <div class="flex items-center gap-4 mb-8">
      <div class="flex-1 h-[1px] bg-white/10"></div>
      <span class="text-white/30 text-xs tracking-widest uppercase">Formulir Reservasi</span>
      <div class="flex-1 h-[1px] bg-white/10"></div>
    </div>
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
        <select id="f-guests">
          <option value="1-10">1–10 Orang</option><option value="10-15">10–15 Orang</option>
          <option value="15-20">15–20 Orang</option><option value="20-25">20–25 Orang</option>
          <option value="25-30">25–30 Orang</option>
        </select>
      </div>
      <div><label class="block text-[10px] tracking-widest uppercase font-semibold text-white/50 mb-2">Pesan / Kebutuhan Khusus</label>
        <textarea id="f-message" placeholder="Contoh: perlu catering, extra bed, atau pertanyaan lainnya..."></textarea></div>
      <button type="submit" id="submit-btn" class="btn-primary w-full text-center mt-2" style="background:#a8c5b5;color:#1e3a2f;font-weight:700;">
        Kirim Permintaan Reservasi
      </button>
    </form>
    <div class="mt-10 pt-8 border-t border-white/10 flex flex-col sm:flex-row justify-center gap-8 text-center text-white">
      ${contactInfoHtml}
    </div>
  </div>
</section>

<div id="toast" class="fixed bottom-6 left-1/2 -translate-x-1/2 bg-primary text-white px-6 py-3 rounded-lg text-sm shadow-xl transition-all duration-300 opacity-0 pointer-events-none translate-y-2 whitespace-nowrap z-50"></div>

<footer class="px-6" style="background:#ecefec;border-top:1px solid #bfc9c1;">
  <div class="max-w-6xl mx-auto py-10">
    <div class="grid md:grid-cols-3 gap-8 mb-8">
      <div>
        <div class="font-serif text-xl tracking-widest text-primary mb-3">${escape((v.name || "VILLA TAWANGMANGU").toUpperCase())}</div>
        <p class="text-[0.8125rem] text-on-surface-variant leading-relaxed max-w-xs">${escape(v.tagline || (v.description || "").slice(0, 120))}</p>
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
        <ul class="space-y-2 text-[0.8125rem] text-on-surface-variant">${renderContacts(contacts)}</ul>
      </div>
    </div>
    <div class="pt-6 border-t border-outline-variant text-center">
      <p class="text-[9px] text-on-surface-variant tracking-widest uppercase">&copy; ${year} ${escape(v.name || "Villa Tawangmangu")}. All Rights Reserved.</p>
    </div>
  </div>
</footer>

<script>
const VILLA_ID = ${JSON.stringify(v.id)};
let currentSlide = 0;

function goToSlide(i) {
  currentSlide = i;
  const s = document.getElementById('gallery-slider');
  s.scrollTo({ left: s.offsetWidth * i, behavior: 'smooth' });
  document.querySelectorAll('.dot-btn').forEach((d, idx) => {
    d.style.opacity = idx === i ? '1' : '0.4';
    d.style.width   = idx === i ? '20px' : '8px';
  });
}

const dotBtns = document.querySelectorAll('.dot-btn');
if (dotBtns.length > 1) setInterval(() => goToSlide((currentSlide + 1) % dotBtns.length), 5000);

const navbar = document.getElementById('navbar');
const navLogo = document.getElementById('nav-logo');
const navLinks = document.querySelectorAll('#nav-links a:not(.btn-primary)');
window.addEventListener('scroll', () => {
  if (window.scrollY > 60) {
    navbar.classList.add('scrolled');
    if (navLogo) navLogo.style.color = '#1e3a2f';
    navLinks.forEach(l => l.style.color = '#404944');
  } else {
    navbar.classList.remove('scrolled');
    if (navLogo) navLogo.style.color = '#fff';
    navLinks.forEach(l => l.style.color = 'rgba(255,255,255,0.8)');
  }
});

function toggleMenu() { document.getElementById('mobile-menu').classList.toggle('hidden'); }

function showToast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg; t.style.opacity = '1'; t.style.pointerEvents = 'auto';
  setTimeout(() => { t.style.opacity = '0'; t.style.pointerEvents = 'none'; }, 5000);
}

document.getElementById('inquiry-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const btn = document.getElementById('submit-btn');
  btn.textContent = 'Mengirim...'; btn.disabled = true;
  const payload = {
    villa_id: VILLA_ID,
    name: document.getElementById('f-name').value,
    phone: document.getElementById('f-phone').value,
    email: document.getElementById('f-email').value || null,
    checkin_date: document.getElementById('f-checkin').value || null,
    checkout_date: document.getElementById('f-checkout').value || null,
    num_guests: document.getElementById('f-guests').value,
    message: document.getElementById('f-message').value || null,
    status: 'pending',
  };
  try {
    const res = await fetch('/api/inquiries', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
    if (res.ok) showToast('✓ Permintaan terkirim! Kami akan segera menghubungi Anda.');
    else showToast('✓ Terima kasih! Hubungi kami via WhatsApp untuk konfirmasi.');
  } catch { showToast('✓ Terima kasih! Hubungi kami via WhatsApp untuk konfirmasi.'); }
  btn.textContent = 'Kirim Permintaan Reservasi'; btn.disabled = false; e.target.reset();
});
</script>
</body>
</html>`;
}
