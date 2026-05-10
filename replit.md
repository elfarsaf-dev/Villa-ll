# Villa Admin — Lumina Villa

Multi-villa management system: static villa landing pages + Cloudflare Worker backend + admin dashboard.

## Run & Operate

- `pnpm --filter @workspace/lumina-villa run dev` — serve villa frontend (Vite, reads PORT env)
- Villa site: `/` — Halaman utama listing semua villa
- Villa detail: `/villa.html?id=VILLA_ID` — Halaman detail villa (generic, semua data dari DB)
- Admin dashboard: `/admin/` — login required

## Stack

- **Frontend**: Plain HTML + Tailwind CDN + Supabase JS CDN (no bundled JS)
- **Backend**: Cloudflare Worker (`worker.js` — single file, deploy with `npx wrangler deploy`)
- **Database**: Supabase (PostgreSQL) — 7 tables
- **Image storage**: GitHub API (photos uploaded to a GitHub repo, URL saved in gallery table)
- **Auth**: Username + password (PBKDF2 hash), JWT (HS256 via Web Crypto)

## Where things live

| Path | Description |
|---|---|
| `artifacts/lumina-villa/index.html` | Halaman utama — listing semua villa dari DB |
| `artifacts/lumina-villa/villa.html` | Halaman detail villa (generic, load semua data dari DB via ?id=) |
| `artifacts/lumina-villa/admin/index.html` | Admin dashboard (all roles) |
| `artifacts/lumina-villa/vite.config.ts` | Vite config + `injectEnvPlugin` for `%VITE_*%` tokens |
| `worker.js` | Cloudflare Worker — all API, auth, upload logic |
| `wrangler.toml` | Cloudflare Worker deploy config |
| `artifacts/lumina-villa/schema.sql` | Supabase DB schema + seed data |

## Database Tables (Supabase)

| Table | Purpose |
|---|---|
| `villa_info` | Villa metadata (name, slug, checkin/out, description…) |
| `facilities` | Villa facilities list |
| `gallery` | Photo URLs (uploaded via GitHub API) |
| `policies` | Rules & notes (type: schedule/note/prohibition/rule) |
| `contacts` | WhatsApp / phone numbers per villa |
| `inquiries` | Guest reservation requests |
| `v_users` | Admin users (role: admin/superadmin, status: pending/active/suspended) |

Supabase project ref: `bgwkwlrkvbspycqsdeif`
Villa Diandra 2 ID: `a1b2c3d4-e5f6-7890-abcd-ef1234567890`, slug: `diandra2`

## Cloudflare Worker API

Base URL: set in admin dashboard localStorage (`villa_worker_url`).

### Auth
| Method | Path | Description |
|---|---|---|
| POST | `/setup` | Create first superadmin (one-time) |
| POST | `/auth/login` | Login → returns JWT |
| POST | `/auth/register` | Register (status=pending, needs SA approval) |
| GET  | `/auth/me` | Current user info |

### Villas
| Method | Path | Auth |
|---|---|---|
| GET    | `/villas` | admin/superadmin |
| POST   | `/villas` | superadmin only |
| GET    | `/villas/:id` | own villa |
| PATCH  | `/villas/:id` | own villa |

### Content (Facilities / Policies / Contacts / Gallery)
Pattern: `GET/POST /villas/:id/{facilities,policies,contacts,gallery}` and `PATCH/DELETE /{facilities,policies,contacts,gallery}/:id`

### Upload
| Method | Path | Notes |
|---|---|---|
| POST | `/upload/github` | multipart: `file`, `villa_id`, `alt` — uploads to GitHub repo |

### Inquiries
| Method | Path |
|---|---|
| GET | `/inquiries` |
| PATCH | `/inquiries/:id` |

### Users (superadmin)
| Method | Path |
|---|---|
| GET | `/users` |
| PATCH | `/users/:id/approve` |
| PATCH | `/users/:id/suspend` |
| PATCH | `/users/:id/role` |
| DELETE | `/users/:id` |

## Worker Environment Variables (Cloudflare Secrets)

```
SUPABASE_URL       = https://bgwkwlrkvbspycqsdeif.supabase.co
SUPABASE_KEY       = <service_role key>
JWT_SECRET         = <random ≥32 chars>
GITHUB_TOKEN       = <PAT with repo write scope>
GITHUB_REPO        = owner/repo
GITHUB_BRANCH      = main
GITHUB_IMG_PATH    = images/villas
ALLOWED_ORIGIN     = * (or your domain)
```

Deploy commands:
```bash
npx wrangler secret put SUPABASE_URL
npx wrangler secret put SUPABASE_KEY
npx wrangler secret put JWT_SECRET
npx wrangler secret put GITHUB_TOKEN
npx wrangler secret put GITHUB_REPO
npx wrangler deploy worker.js --name villa-admin
```

## Role System

| Role | Can do |
|---|---|
| `superadmin` | Manage all villas, all users, approve/suspend/delete users, create new villas |
| `admin` | Manage only their assigned villa (content, facilities, gallery, policies, contacts, inquiries) |

New users register → status=`pending` → superadmin approves → status=`active` → can login.

## Architecture Decisions

- **Single worker file**: All backend logic in `worker.js` — no npm dependencies, deploys instantly to Cloudflare edge
- **PBKDF2 passwords**: Uses Web Crypto API (available in CF Workers) — 100k iterations, SHA-256, random salt
- **JWT with HMAC-SHA256**: Stateless auth, 7-day expiry, signed with `JWT_SECRET`
- **GitHub as image CDN**: Photos uploaded to GitHub repo via Contents API; `raw.githubusercontent.com` URLs stored in gallery table
- **Vite env injection**: Custom `injectEnvPlugin` in `vite.config.ts` replaces `%VITE_*%` tokens in HTML at serve time (not at build time, so secrets stay server-side)
- **Supabase service_role**: Worker uses service_role key for full DB access; RLS still enabled for defense in depth

## User Preferences

- Plain HTML + Tailwind CDN (no React, no bundler for frontend)
- Indonesian language UI
- Single-file Cloudflare Worker for backend
- GitHub API for photo storage

## Gotchas

- After deploying worker, paste the worker URL into admin dashboard settings (saved to localStorage)
- Run `/setup` endpoint once (via curl or admin dashboard) to create first superadmin before anyone can login
- `VITE_SUPABASE_ANON_KEY` env var is actually the service_role key — don't expose publicly in production
- Supabase direct pg connection blocked from Replit; use Management API at `https://api.supabase.com/v1/projects/{ref}/database/query`
