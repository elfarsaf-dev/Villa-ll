import { Router } from "express";
import { renderIndexPage } from "../ssr/index-page.js";
import { renderVillaPage } from "../ssr/villa-page.js";

const router = Router();

async function sb(table: string, method = "GET", query = "", body: unknown = null) {
  const SUPABASE_URL = process.env.SUPABASE_URL;
  const SUPABASE_KEY = process.env.SUPABASE_KEY;
  if (!SUPABASE_URL || !SUPABASE_KEY) throw new Error("Supabase belum dikonfigurasi");
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
  const text = await res.text();
  if (!res.ok) throw new Error(`Supabase ${res.status}: ${text}`);
  return text ? JSON.parse(text) : [];
}

// GET / — SSR villa listing
router.get("/", async (req, res) => {
  try {
    const villas = await sb("villa_info", "GET", "select=*&order=created_at.asc") as any[];

    if (!villas.length) {
      const html = renderIndexPage([], {}, {}, undefined);
      return res.type("html").send(html);
    }

    const villaIds = villas.map((v: any) => v.id).join(",");

    const [gallery, villaContacts, globalContacts] = await Promise.all([
      sb("gallery", "GET", `villa_id=in.(${villaIds})&is_active=eq.true&order=sort_order.asc`) as Promise<any[]>,
      sb("contacts", "GET", `villa_id=in.(${villaIds})&type=eq.whatsapp`) as Promise<any[]>,
      sb("contacts", "GET", "villa_id=is.null&type=eq.whatsapp") as Promise<any[]>,
    ]);

    // Build cover map (first image per villa)
    const coverMap: Record<string, any> = {};
    for (const img of gallery as any[]) {
      if (!coverMap[img.villa_id]) coverMap[img.villa_id] = img;
    }

    // Build contact map (primary WA per villa)
    const contactMap: Record<string, any> = {};
    for (const c of villaContacts as any[]) {
      if (!contactMap[c.villa_id] || c.is_primary) contactMap[c.villa_id] = c;
    }

    const gc = globalContacts as any[];
    const globalWa = gc.find((c: any) => c.is_primary) || gc[0];

    const html = renderIndexPage(villas, coverMap, contactMap, globalWa);
    res.type("html").send(html);
  } catch (e: any) {
    res.type("html").send(`<!DOCTYPE html><html><body><h1>Error</h1><p>${e.message}</p></body></html>`);
  }
});

// GET /villa/:slug — SSR villa detail page
router.get("/villa/:slug", async (req, res) => {
  const { slug } = req.params;
  try {
    const rows = await sb("villa_info", "GET", `slug=eq.${encodeURIComponent(slug)}&select=*&limit=1`) as any[];
    if (!rows.length) {
      return res.status(404).type("html").send(`<!DOCTYPE html><html lang="id"><head><title>Villa Tidak Ditemukan</title></head><body style="font-family:sans-serif;text-align:center;padding:60px"><h1>404 — Villa Tidak Ditemukan</h1><p><a href="/">← Kembali ke halaman utama</a></p></body></html>`);
    }
    const v = rows[0];

    const [facilities, gallery, policies, villaContacts, globalContacts] = await Promise.all([
      sb("facilities", "GET", `villa_id=eq.${v.id}&is_active=eq.true&order=sort_order.asc`),
      sb("gallery",    "GET", `villa_id=eq.${v.id}&is_active=eq.true&order=sort_order.asc`),
      sb("policies",   "GET", `villa_id=eq.${v.id}&order=sort_order.asc`),
      sb("contacts",   "GET", `villa_id=eq.${v.id}`),
      sb("contacts",   "GET", "villa_id=is.null"),
    ]) as [any[], any[], any[], any[], any[]];

    // Merge contacts: villa-specific first, global fills missing types
    const merged = [...villaContacts];
    for (const gc of globalContacts) {
      if (!merged.some(c => c.type === gc.type)) merged.push(gc);
    }

    const html = renderVillaPage(v, facilities, gallery, policies, merged);
    res.type("html").send(html);
  } catch (e: any) {
    res.status(500).type("html").send(`<!DOCTYPE html><html><body><h1>Error</h1><p>${e.message}</p></body></html>`);
  }
});

// Legacy redirect: /villa.html?slug=X → /villa/X
router.get("/villa.html", (req, res) => {
  const slug = req.query.slug as string;
  const id   = req.query.id   as string;
  if (slug) return res.redirect(301, `/villa/${encodeURIComponent(slug)}`);
  if (id)   return res.redirect(301, `/villa/?id=${encodeURIComponent(id)}`);
  res.redirect(301, "/");
});

// GET /villa/ with ?id param (fallback for villas without slug)
router.get("/villa/", async (req, res) => {
  const id = req.query.id as string;
  if (!id) return res.redirect("/");
  try {
    const rows = await sb("villa_info", "GET", `id=eq.${encodeURIComponent(id)}&select=*&limit=1`) as any[];
    if (!rows.length) return res.status(404).type("html").send(`<!DOCTYPE html><html><body><h1>Villa Tidak Ditemukan</h1><a href="/">← Kembali</a></body></html>`);
    const v = rows[0];
    if (v.slug) return res.redirect(301, `/villa/${encodeURIComponent(v.slug)}`);

    const [facilities, gallery, policies, villaContacts, globalContacts] = await Promise.all([
      sb("facilities", "GET", `villa_id=eq.${v.id}&is_active=eq.true&order=sort_order.asc`),
      sb("gallery",    "GET", `villa_id=eq.${v.id}&is_active=eq.true&order=sort_order.asc`),
      sb("policies",   "GET", `villa_id=eq.${v.id}&order=sort_order.asc`),
      sb("contacts",   "GET", `villa_id=eq.${v.id}`),
      sb("contacts",   "GET", "villa_id=is.null"),
    ]) as [any[], any[], any[], any[], any[]];
    const merged = [...villaContacts];
    for (const gc of globalContacts) {
      if (!merged.some(c => c.type === gc.type)) merged.push(gc);
    }
    res.type("html").send(renderVillaPage(v, facilities, gallery, policies, merged));
  } catch (e: any) {
    res.status(500).type("html").send(`<h1>Error</h1><p>${e.message}</p>`);
  }
});

export default router;
