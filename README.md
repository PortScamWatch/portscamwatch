# PortScamWatch

Static, zero-backend consumer triage and open IOC hub for fake GTA 6 PC ports, ClickFix clipboard hijacks, keygens, trojanized Android APKs, and Web3 wallet drainers.

Live site: [https://portscamwatch.com](https://portscamwatch.com)  
Repository: [https://github.com/PortScamWatch/portscamwatch](https://github.com/PortScamWatch/portscamwatch)

---

## Scope & Non-Goals

PortScamWatch is intentionally narrow:
- Tracks vendor-cited IOCs targeting **Grand Theft Auto VI** port scams and distributes a fast 60-second exposure triage checklist.
- **Not a VirusTotal or sandbox replacement** — it does not detonate binaries, scan arbitrary executables heuristically, or certify any unofficial PC/mobile GTA 6 file or domain as safe.
- Official releases of GTA 6 are for PlayStation 5 and Xbox Series X|S only (`rockstargames.com`).

---

## Architecture & Privacy Model

1. **Client-Side 3-Tier Static Lookup (`src/lib/threatLookup.ts`, `public/data/threats.json`)**
   - Normalizes submitted indicators (`hxxps://` / `hxxp://`, `[.]`, `(.)`, trailing slashes, default `:80`/`:443`, and whitespace-padded/uppercase 64-char SHA-256 hashes) entirely in browser memory (`src/utils/normalizeInput.ts`).
   - Supports shareable deep links via `?q=<indicator>` query permalinks (`/` focuses search, `Escape` clears).
   - Assigns one of three explicit tiers:
     - `CONFIRMED_THREAT` — exact match against vendor-published `indicators[]` or `hostArtifacts[]`.
     - `ESTABLISHED_DOMAIN` — match on known established platforms (`rockstargames.com`, `take2games.com`, `store.steampowered.com`, `epicgames.com`, `playstation.com`, `xbox.com`, `google.com`, `youtube.com`, `github.com`, `microsoft.com`) or domains aged >365 days via live RDAP with zero threat hits.
     - `NOT_LISTED` — unlisted files, hashes, paths, or domains (flagging domains registered <90 days ago via RDAP as high-risk lures).

2. **Browser Web Crypto SHA-256 Hasher (`src/utils/fileHash.ts`)**
   - Computes SHA-256 digests strictly locally via `crypto.subtle.digest('SHA-256', ...)` so **zero file bytes leave the device**.
   - Enforces a **256 MB RAM safety guard** (`MAX_BROWSER_HASH_BYTES`) to avoid tab crashes on padded multi-GB decoy installers, falling back cleanly to native `Get-FileHash -Algorithm SHA256` (PowerShell) and `shasum -a 256` (macOS/Linux) commands.

3. **Live Browser RDAP & Honest Privacy Boundary (`src/lib/rdap.ts`, `src/components/MethodologySection.tsx`)**
   - Domain/URL checks issue a direct client-side request from the user's browser to public `https://rdap.org/domain/<registrable-domain>` to inspect registration age.
   - Because PortScamWatch has no backend proxy, queries are never logged by PortScamWatch servers, while `rdap.org` receives the queried registrable domain directly from the client.

4. **Open Intel Exports & Read-Only Host Check (`src/components/OpenIntelExports.tsx`, `src/utils/iocExports.ts`)**
   - Generates client-side exports from `/data/threats.json`:
     - **Domain Blocklist (`.txt`)** — `0.0.0.0 <domain>` for Pi-hole / AdGuard / hosts (strictly excluding established platforms and vendor domains).
     - **Structured IOC Feed (`.csv`)** — RFC-4180 CSV with indicator type, campaign, vendor, advisory date, and source URL.
     - **Raw Dataset (`.json`)** — full validated `threats.json`.
   - Includes a copyable, strictly read-only Windows PowerShell check (`Test-Path -LiteralPath` and `Get-ItemProperty` only — zero writes, zero downloads, zero deletions).

5. **Static Deployment Security Headers (`public/_headers`)**
   - Configured for Cloudflare Pages with `Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Permissions-Policy`, and `Strict-Transport-Security`.
   - Applies `X-Robots-Tag: noindex` across `*.pages.dev` preview URLs so only `https://portscamwatch.com/` (`public/robots.txt`, `public/sitemap.xml`) is indexed.

6. **Automated 6-Hour Threat Scout (`.github/workflows/scout.yml`, `scripts/update-threats.mjs`)**
   - Polls public RSS/Atom feeds with a 10s per-feed timeout from **Bitdefender Labs**, **Bitdefender Hot for Security**, **Malwarebytes**, **Darktrace**, **ESET WeLiveSecurity**, and **BleepingComputer**.
   - Matches candidates mentioning `GTA 6`, `GTA VI`, `Grand Theft Auto 6` / `Grand Theft Auto VI`, or `ClickFix` + `GTA` (case-insensitive) and, when `GEMINI_API_KEY` is configured in GitHub Secrets, extracts strictly vendor-published IOCs append-only.
   - Leaves `public/data/threats.json` and `meta.lastVerifiedUtc` untouched on disk when 0 new advisories are appended (preventing no-op commits), and enforces `scripts/validate-data.mjs` (URL allowlist, strict `YYYY-MM-DD` dates, unique 64-char SHA-256 formatting, protected-domain blocklist) before committing.

---

## Local Development, Verification & Build

Requires **Node.js 20+** (tested on Node 24).

```bash
npm install
npm run dev                              # Start local Vite dev server
node scripts/update-threats.mjs --check-feeds  # Probe all RSS feeds cleanly (no Gemini, no disk writes)
npm run validate:data                    # Enforce JSON schema, vendor URL allowlist & protected domains
npm test                                 # Run Vitest unit & React component suites (non-interactive)
npm run test:e2e                         # Build & run Playwright Chromium E2E (desktop 1440x900 + mobile 390x844)
npm run build                            # Type-check with tsc -b and build dist/
npm run audit:prelaunch                  # Verify vendor URLs, PNG dimensions & gitignore hygiene
```

---

## Monetization & Transparency

PortScamWatch has zero ads, zero cookies, and zero tracking pixels. When configured at build time via `VITE_*` environment variables (never hardcoded in source or committed to `.env`), clearly labeled `rel="noopener noreferrer sponsored"` outbound links may render for **NordPass**, **NordVPN**, **Coveron (US)**, **Malwarebytes**, and **Bitdefender** (`src/config/env.ts`, `.env.example`).

- `VITE_SITE_DOMAIN` (default: `portscamwatch.com`)
- `VITE_NORDPASS_URL`
- `VITE_NORDVPN_URL`
- `VITE_COVERON_URL`
- `VITE_MALWAREBYTES_URL`
- `VITE_BITDEFENDER_URL`

Affiliate URLs require strict `https://` validation, never influence threat verdicts or vendor citations, and are never shown inside benign or established domain lookup verdicts.

---

## Non-Affiliation Notice & License

PortScamWatch is an independent consumer security resource and is not affiliated with, endorsed by, or sponsored by Rockstar Games, Take-Two Interactive, or any listed security vendor.

Released under the [MIT License](LICENSE).
