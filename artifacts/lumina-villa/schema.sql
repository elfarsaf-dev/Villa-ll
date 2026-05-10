-- ================================================================
-- VILLA DIANDRA 2 — Supabase Database Schema
-- Jalankan seluruh file ini di Supabase SQL Editor
-- ================================================================

-- ── 1. Villa info ───────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS villa_info (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name            text NOT NULL,
  tagline         text,
  description     text,
  address         text,
  city            text,
  province        text,
  max_guests      integer,
  max_guests_note text,
  extra_bed_price integer,
  extra_bed_note  text,
  checkin_time    text,
  checkout_time   text,
  created_at      timestamptz DEFAULT now(),
  updated_at      timestamptz DEFAULT now()
);

-- ── 2. Fasilitas ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS facilities (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  villa_id    uuid REFERENCES villa_info(id) ON DELETE CASCADE,
  icon        text,
  name        text NOT NULL,
  description text,
  sort_order  integer DEFAULT 0,
  is_active   boolean DEFAULT true
);

-- ── 3. Galeri foto ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS gallery (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  villa_id   uuid REFERENCES villa_info(id) ON DELETE CASCADE,
  url        text NOT NULL,
  alt        text,
  sort_order integer DEFAULT 0,
  is_active  boolean DEFAULT true
);

-- ── 4. Kebijakan & aturan ────────────────────────────────────────
CREATE TABLE IF NOT EXISTS policies (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  villa_id   uuid REFERENCES villa_info(id) ON DELETE CASCADE,
  type       text CHECK (type IN ('rule','note','prohibition','schedule')),
  content    text NOT NULL,
  sort_order integer DEFAULT 0
);

-- ── 5. Kontak admin ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS contacts (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  villa_id   uuid REFERENCES villa_info(id) ON DELETE CASCADE,
  type       text CHECK (type IN ('whatsapp','phone','email','instagram')),
  label      text,
  value      text NOT NULL,
  is_primary boolean DEFAULT false
);

-- ── 6. Inquiry / permintaan reservasi ───────────────────────────
CREATE TABLE IF NOT EXISTS inquiries (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  villa_id      uuid REFERENCES villa_info(id) ON DELETE SET NULL,
  name          text NOT NULL,
  phone         text,
  email         text,
  checkin_date  date,
  checkout_date date,
  num_guests    text,
  message       text,
  status        text DEFAULT 'pending' CHECK (status IN ('pending','replied','confirmed','cancelled')),
  created_at    timestamptz DEFAULT now()
);

-- ================================================================
-- ROW LEVEL SECURITY — agar anon key bisa akses
-- ================================================================

ALTER TABLE villa_info  ENABLE ROW LEVEL SECURITY;
ALTER TABLE facilities  ENABLE ROW LEVEL SECURITY;
ALTER TABLE gallery     ENABLE ROW LEVEL SECURITY;
ALTER TABLE policies    ENABLE ROW LEVEL SECURITY;
ALTER TABLE contacts    ENABLE ROW LEVEL SECURITY;
ALTER TABLE inquiries   ENABLE ROW LEVEL SECURITY;

-- Public: bisa baca semua data villa (tanpa login)
CREATE POLICY "public read villa_info"  ON villa_info  FOR SELECT USING (true);
CREATE POLICY "public read facilities"  ON facilities  FOR SELECT USING (true);
CREATE POLICY "public read gallery"     ON gallery     FOR SELECT USING (true);
CREATE POLICY "public read policies"    ON policies    FOR SELECT USING (true);
CREATE POLICY "public read contacts"    ON contacts    FOR SELECT USING (true);

-- Public: bisa kirim inquiry (tanpa login)
CREATE POLICY "public insert inquiries" ON inquiries   FOR INSERT WITH CHECK (true);

-- Admin: bisa baca semua inquiry (pakai service role / dashboard)
CREATE POLICY "admin read inquiries"    ON inquiries   FOR SELECT USING (true);
CREATE POLICY "admin update inquiries"  ON inquiries   FOR UPDATE USING (true);

-- ================================================================
-- CATATAN: Global Contacts (kontak site-wide, villa_id = NULL)
-- Write (INSERT/UPDATE/DELETE) dilakukan melalui Cloudflare Worker
-- yang menggunakan service_role key — BUKAN anon key.
-- Tidak perlu menambah policy write di sini.
-- Lihat file: cloudflare-worker-additions.js
-- ================================================================

-- ================================================================
-- SEED DATA — Villa Diandra 2
-- ================================================================

INSERT INTO villa_info (
  id, name, tagline, description, address, city, province,
  max_guests, max_guests_note, extra_bed_price, extra_bed_note,
  checkin_time, checkout_time
) VALUES (
  'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
  'Villa Diandra 2',
  'Private Villa Eksklusif di Sekipan, Tawangmangu',
  'Villa 2 lantai eksklusif dengan bangunan dan furniture serba baru, terletak di kawasan Sekipan yang asri. Nikmati udara pegunungan yang segar dan pemandangan hutan hijau yang memanjakan mata. Dilengkapi kolam renang privat, balkon dengan panorama pegunungan Sekipan, serta berbagai fasilitas lengkap.',
  'Sekipan, Tawangmangu',
  'Karanganyar',
  'Jawa Tengah',
  25,
  'Boleh diisi hingga 30 orang',
  100000,
  'Hari weekday free extra bed',
  '14.00 WIB',
  '12.00 WIB'
)
ON CONFLICT (id) DO NOTHING;

INSERT INTO facilities (villa_id, icon, name, description, sort_order) VALUES
  ('a1b2c3d4-e5f6-7890-abcd-ef1234567890', 'home',            'Villa 2 Lantai',        'Bangunan dan furniture serba baru, desain modern dan nyaman', 1),
  ('a1b2c3d4-e5f6-7890-abcd-ef1234567890', 'pool',            'Kolam Renang Privat',   'Private pool eksklusif hanya untuk tamu villa', 2),
  ('a1b2c3d4-e5f6-7890-abcd-ef1234567890', 'landscape',       'Balkon Panorama',       'Balkon lantai atas dengan panorama hutan dan pegunungan Sekipan', 3),
  ('a1b2c3d4-e5f6-7890-abcd-ef1234567890', 'weekend',         'Ruang Keluarga',        'Ruang tamu & keluarga luas dengan sofa bed yang nyaman', 4),
  ('a1b2c3d4-e5f6-7890-abcd-ef1234567890', 'bed',             '3 Kamar Tidur',         '3 kamar tidur dengan total 4 tempat tidur', 5),
  ('a1b2c3d4-e5f6-7890-abcd-ef1234567890', 'shower',          '3 Kamar Mandi',         'Dilengkapi fasilitas air panas di semua kamar mandi', 6),
  ('a1b2c3d4-e5f6-7890-abcd-ef1234567890', 'kitchen',         'Dapur Lengkap',         'Dapur + minibar: kulkas, rice cooker, dispenser, dan peralatan masak lengkap', 7),
  ('a1b2c3d4-e5f6-7890-abcd-ef1234567890', 'tv',              '2 Smart TV',            'Dilengkapi karaoke & sound system untuk hiburan keluarga', 8),
  ('a1b2c3d4-e5f6-7890-abcd-ef1234567890', 'videogame_asset', 'Free PS3',              'PlayStation 3 tersedia gratis untuk hiburan selama menginap', 9),
  ('a1b2c3d4-e5f6-7890-abcd-ef1234567890', 'outdoor_grill',   'Fasilitas BBQ',         'Peralatan bakar lengkap untuk momen bersama yang berkesan', 10),
  ('a1b2c3d4-e5f6-7890-abcd-ef1234567890', 'wifi',            'WiFi Seluruh Area',     'Akses internet cepat di semua area, termasuk lantai 1 dan 2', 11),
  ('a1b2c3d4-e5f6-7890-abcd-ef1234567890', 'local_parking',   'Parkir Luas',           'Area parkir menampung hingga 5 mobil', 12),
  ('a1b2c3d4-e5f6-7890-abcd-ef1234567890', 'restaurant',      'Layanan Catering',      'Catering tersedia dengan berbagai pilihan menu sesuai selera', 13),
  ('a1b2c3d4-e5f6-7890-abcd-ef1234567890', 'groups',          'Kapasitas 25–30 Orang', 'Cocok untuk family gathering, reuni, atau acara besar', 14)
ON CONFLICT DO NOTHING;

INSERT INTO policies (villa_id, type, content, sort_order) VALUES
  ('a1b2c3d4-e5f6-7890-abcd-ef1234567890', 'schedule',    'Check-in: 14.00 WIB', 1),
  ('a1b2c3d4-e5f6-7890-abcd-ef1234567890', 'schedule',    'Check-out: 12.00 WIB', 2),
  ('a1b2c3d4-e5f6-7890-abcd-ef1234567890', 'schedule',    'Jam malam: maksimal aktivitas luar hingga pukul 23.30 WIB', 3),
  ('a1b2c3d4-e5f6-7890-abcd-ef1234567890', 'note',        'Harga dapat berubah sewaktu-waktu tanpa pemberitahuan', 4),
  ('a1b2c3d4-e5f6-7890-abcd-ef1234567890', 'note',        'Weekday: free extra bed', 5),
  ('a1b2c3d4-e5f6-7890-abcd-ef1234567890', 'note',        'Extra bed weekend: Rp100.000/bed', 6),
  ('a1b2c3d4-e5f6-7890-abcd-ef1234567890', 'prohibition', 'Minuman keras / alkohol', 7),
  ('a1b2c3d4-e5f6-7890-abcd-ef1234567890', 'prohibition', 'Narkoba / obat terlarang', 8),
  ('a1b2c3d4-e5f6-7890-abcd-ef1234567890', 'prohibition', 'Aktivitas pacaran atau asusila', 9),
  ('a1b2c3d4-e5f6-7890-abcd-ef1234567890', 'prohibition', 'Dangdutan, orgen tunggal, atau live music sejenis', 10)
ON CONFLICT DO NOTHING;

INSERT INTO contacts (villa_id, type, label, value, is_primary) VALUES
  ('a1b2c3d4-e5f6-7890-abcd-ef1234567890', 'whatsapp', 'Admin Villa', '082228981345', true),
  ('a1b2c3d4-e5f6-7890-abcd-ef1234567890', 'phone',    'Telepon',     '082228981345', false)
ON CONFLICT DO NOTHING;
