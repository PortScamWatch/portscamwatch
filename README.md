# PortScamWatch

Consumer threat lookup and 60-second exposure triage for fake GTA 6 PC ports, ClickFix clipboard hijacks, keygens, malicious Android APKs, and Web3 wallet drainers.

Live site: [https://portscamwatch.com](https://portscamwatch.com)
Repository: [https://github.com/PortScamWatch/portscamwatch](https://github.com/PortScamWatch/portscamwatch)

---

## Threat Lookup Architecture (3-Tier + Live RDAP)

PortScamWatch evaluates submitted URLs, domains, filenames, Windows paths, and SHA-256 hashes entirely client-side against static vendor intelligence (`/data/threats.json`) and live RDAP domain registration records (`https://rdap.org/domain/<registrable-domain>`):

1. **Confirmed Threat (`MATCHED IN VENDOR ADVISORIES`)** — Triggered only when the normalized input matches an explicit indicator in `indicators[]` or `hostArtifacts[]` from published vendor advisories. Displays malware family, vendor attribution, advisory link, targeted data, and a jump button to the 60-second exposure triage checklist.
2. **Established / Official Domain (`ESTABLISHED DOMAIN — NOT IN THREAT LISTS`)** — Triggered for known established platforms (`rockstargames.com`, `take2games.com`, `store.steampowered.com`, `epicgames.com`, `playstation.com`, `xbox.com`, `google.com`, `youtube.com`, `github.com`, `microsoft.com`) or domains verified via live RDAP as registered more than 365 days ago with zero threat matches. Legitimate domains such as `google.com` or `rockstargames.com` are never falsely labeled malicious.
3. **Not Found in Vendor Advisories (`NOT FOUND IN VENDOR ADVISORIES`)** — Triggered for unlisted executables, archives, hashes, or unrecognized domains. Highlights `Newly Registered Domain (<90 days old)` when RDAP shows recent registration, states honestly that vendor feeds only cover confirmed campaigns, and notes that official GTA 6 releases exist only on PlayStation 5 and Xbox Series X|S (`rockstargames.com`). PortScamWatch never certifies any unofficial GTA 6 PC or mobile file as safe.

---

## Privacy Posture

- **Zero cookies** and zero user accounts or authentication.
- **Zero query logging** — indicator normalization and threat matching run 100% in your browser; RDAP lookups are direct client-side requests to `rdap.org`.
- **Zero third-party ad trackers** — designed for privacy-first Cloudflare Web Analytics only.

---

## Local Setup & Commands

Requires **Node.js 20+**.

```bash
npm install
npm run dev              # Start local Vite dev server
npm run validate:data    # Run strict schema, allowlist & anti-false-positive checks
npm test                 # Run Vitest unit & contract suite
npm run build            # Type-check and build production dist/
npm run audit:prelaunch  # Check vendor advisory links, asset dimensions & gitignore hygiene
```

---

## Environment-Variable Affiliate Routing

No affiliate IDs or tracking query parameters are stored in the repository. Outbound security tool links read `VITE_*` variables at build time and default to clean official vendor homepages:

- `VITE_SITE_DOMAIN` (default: `portscamwatch.com`)
- `VITE_MALWAREBYTES_URL` (default: `https://www.malwarebytes.com/`)
- `VITE_BITDEFENDER_URL` (default: `https://www.bitdefender.com/`)
- `VITE_NORDVPN_URL` (default: `https://nordvpn.com/`)
- `VITE_NORDPASS_URL` (default: `https://nordpass.com/`)

See [`.env.example`](.env.example). Local `.env` files are excluded via `.gitignore`.

---

## Automated 6-Hour Vendor Threat Scout

The repository includes an append-only automated threat scout (`.github/workflows/scout.yml`, running every 6 hours via `0 */6 * * *` and `workflow_dispatch`):

1. `scripts/update-threats.mjs` polls public RSS/Atom feeds from Bitdefender Labs, Malwarebytes, Darktrace, ESET WeLiveSecurity, and McAfee Labs.
2. New articles mentioning GTA 6 / GTA VI / ClickFix + GTA are optionally analyzed via Google AI Studio's Gemini REST API (using repository secret `GEMINI_API_KEY`) strictly to extract vendor-published IOCs.
3. Deterministic post-processing normalizes indicators, enforces the vendor URL allowlist, strips any protected legitimate domains, deduplicates against existing IOCs, updates `public/data/threats.json` append-only, and runs `scripts/validate-data.mjs` (rolling back automatically on any validation failure).

### Strict Vendor-Sourcing Policy

Every entry in `public/data/threats.json` must cite an explicit published advisory from an allowlisted security vendor or threat publication (`bitdefender.com`, `malwarebytes.com`, `darktrace.com`, `welivesecurity.com`, `eset.com`, `mcafee.com`, `netcraft.com`, `cynet.com`, `huntress.com`, `techradar.com`, `bleepingcomputer.com`, `kaspersky.com`, `securelist.com`).

---

## Non-Affiliation Notice

PortScamWatch is an independent consumer cybersecurity resource. It is not affiliated with, endorsed by, or sponsored by Rockstar Games, Take-Two Interactive, or any listed security vendor.

---

## License

Released under the [MIT License](LICENSE).
