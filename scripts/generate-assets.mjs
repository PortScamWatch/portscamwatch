import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Resvg } from '@resvg/resvg-js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.resolve(__dirname, '..');

const THREATS_DATA = JSON.parse(
  fs.readFileSync(path.join(ROOT_DIR, 'public/data/threats.json'), 'utf-8'),
);

const TOTAL_ADVISORIES = THREATS_DATA.threats.length;
const TOTAL_INDICATORS = THREATS_DATA.threats.reduce(
  (sum, t) => sum + (Array.isArray(t.indicators) ? t.indicators.length : 0),
  0,
);

const CANDIDATE_FONT_FILES = [
  'C:\\Windows\\Fonts\\segoeui.ttf',
  'C:\\Windows\\Fonts\\segoeuib.ttf',
  'C:\\Windows\\Fonts\\segoeuisl.ttf',
  'C:\\Windows\\Fonts\\consola.ttf',
  'C:\\Windows\\Fonts\\consolab.ttf',
  'C:\\Windows\\Fonts\\arial.ttf',
  'C:\\Windows\\Fonts\\arialbd.ttf',
  '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf',
  '/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf',
  '/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf',
  '/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf',
  '/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf',
  '/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf',
];

const EXISTING_FONT_FILES = CANDIDATE_FONT_FILES.filter((p) => fs.existsSync(p));

const SANS_FAMILY = process.platform === 'win32' ? 'Segoe UI, Arial, sans-serif' : 'DejaVu Sans, Liberation Sans, sans-serif';
const MONO_FAMILY = process.platform === 'win32' ? 'Consolas, monospace' : 'DejaVu Sans Mono, monospace';

function escapeXml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

function wrapTextLines(text, maxChars) {
  const words = String(text).trim().split(/\s+/);
  const lines = [];
  let current = '';

  for (const word of words) {
    if (!current) {
      current = word;
      continue;
    }
    if (`${current} ${word}`.length <= maxChars) {
      current = `${current} ${word}`;
    } else {
      lines.push(current);
      current = word;
    }
  }
  if (current) lines.push(current);
  return lines;
}

function renderTextLines({
  lines,
  x,
  y,
  lineHeight,
  fontSize,
  fontWeight = '600',
  fill = '#f8fafc',
  fontFamily = SANS_FAMILY,
  textAnchor = 'start',
}) {
  return lines
    .map(
      (line, idx) =>
        `<text x="${x}" y="${y + idx * lineHeight}" font-family="${escapeXml(
          fontFamily,
        )}" font-size="${fontSize}" font-weight="${fontWeight}" fill="${fill}" text-anchor="${textAnchor}">${escapeXml(
          line,
        )}</text>`,
    )
    .join('\n');
}

function buildGridSvg(width, height, step = 48) {
  const lines = [];
  for (let x = step; x < width; x += step) {
    lines.push(`<line x1="${x}" y1="0" x2="${x}" y2="${height}" stroke="#1e293b" stroke-opacity="0.35" stroke-width="1" />`);
  }
  for (let y = step; y < height; y += step) {
    lines.push(`<line x1="0" y1="${y}" x2="${width}" y2="${y}" stroke="#1e293b" stroke-opacity="0.35" stroke-width="1" />`);
  }
  return lines.join('\n');
}

function shieldMarkSvg(cx, cy, scale = 1, accent = '#38bdf8') {
  return `
  <g transform="translate(${cx}, ${cy}) scale(${scale})">
    <path d="M 0 -54 L 46 -34 L 46 8 C 46 36 25 56 0 68 C -25 56 -46 36 -46 8 L -46 -34 Z"
          fill="#111827" stroke="${accent}" stroke-width="4" stroke-linejoin="round"/>
    <path d="M 0 -38 L 31 -24 L 31 6 C 31 26 16 40 0 49 C -16 40 -31 26 -31 6 L -31 -24 Z"
          fill="#0b0f17" stroke="#334155" stroke-width="1.5"/>
    <circle cx="0" cy="4" r="14" fill="none" stroke="${accent}" stroke-width="2.5"/>
    <line x1="-22" y1="4" x2="22" y2="4" stroke="#64748b" stroke-width="1.5"/>
    <line x1="0" y1="-18" x2="0" y2="26" stroke="#64748b" stroke-width="1.5"/>
    <circle cx="0" cy="4" r="4.5" fill="#ef4444"/>
  </g>`;
}

function renderSvgToPng(svg, outPath) {
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  const resvg = new Resvg(svg, {
    font: {
      fontFiles: EXISTING_FONT_FILES,
      loadSystemFonts: true,
      defaultFontFamily: process.platform === 'win32' ? 'Segoe UI' : 'DejaVu Sans',
      sansSerifFamily: process.platform === 'win32' ? 'Segoe UI' : 'DejaVu Sans',
      monospaceFamily: process.platform === 'win32' ? 'Consolas' : 'DejaVu Sans Mono',
    },
  });
  const pngData = resvg.render();
  const pngBuffer = pngData.asPng();
  fs.writeFileSync(outPath, pngBuffer);
  return { width: pngData.width, height: pngData.height, path: outPath };
}

// ---------------------------------------------------------------------------
// A. Public OG Image (1200x630)
// ---------------------------------------------------------------------------
function generateOgImage() {
  const width = 1200;
  const height = 630;
  const headlineLines = wrapTextLines(
    'GTA 6 Fake-Port, ClickFix & Infostealer Lookup',
    36,
  );

  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}">
    <rect width="${width}" height="${height}" fill="#0b0f17"/>
    ${buildGridSvg(width, height, 60)}
    <rect x="44" y="42" width="1112" height="546" rx="16" fill="#111827" stroke="#1e293b" stroke-width="2"/>
    <rect x="44" y="42" width="1112" height="6" rx="3" fill="#38bdf8"/>

    ${shieldMarkSvg(124, 128, 0.72, '#38bdf8')}
    <text x="188" y="122" font-family="${MONO_FAMILY}" font-size="22" font-weight="700" fill="#f8fafc">PortScamWatch.com</text>
    <text x="188" y="150" font-family="${MONO_FAMILY}" font-size="15" font-weight="400" fill="#94a3b8">CONSUMER THREAT VERIFIER · CLIENT-SIDE RDAP</text>

    <rect x="892" y="92" width="220" height="38" rx="6" fill="#0b0f17" stroke="#334155" stroke-width="1.5"/>
    <text x="1002" y="117" font-family="${MONO_FAMILY}" font-size="14" font-weight="700" fill="#38bdf8" text-anchor="middle">LIVE VENDOR FEED</text>

    ${renderTextLines({
      lines: headlineLines,
      x: 84,
      y: 236,
      lineHeight: 54,
      fontSize: 42,
      fontWeight: '700',
      fill: '#f8fafc',
    })}

    <rect x="84" y="340" width="1032" height="140" rx="10" fill="#0b0f17" stroke="#1e293b" stroke-width="1.5"/>
    <text x="116" y="388" font-family="${MONO_FAMILY}" font-size="23" font-weight="700" fill="#38bdf8">${TOTAL_ADVISORIES} Vendor Advisories  ·  ${TOTAL_INDICATORS} Verified Indicators  ·  Live Client-Side RDAP</text>
    <text x="116" y="426" font-family="${SANS_FAMILY}" font-size="20" font-weight="400" fill="#cbd5e1">Bitdefender Labs · Malwarebytes · Netcraft · Darktrace · NordVPN · ESET · Cynet</text>
    <text x="116" y="458" font-family="${MONO_FAMILY}" font-size="16" font-weight="400" fill="#94a3b8">3-Tier Lookup: Confirmed Threat  |  Established Domain  |  Not Found in Vendor Feeds</text>

    <line x1="84" y1="516" x2="1116" y2="516" stroke="#1e293b" stroke-width="1"/>
    <text x="84" y="554" font-family="${MONO_FAMILY}" font-size="18" font-weight="700" fill="#e2e8f0">https://portscamwatch.com</text>
    <text x="1116" y="554" font-family="${MONO_FAMILY}" font-size="16" font-weight="400" fill="#94a3b8" text-anchor="end">ZERO COOKIES · NO QUERY LOGGING</text>
  </svg>`;

  return renderSvgToPng(svg, path.join(ROOT_DIR, 'public/og-image.png'));
}

// ---------------------------------------------------------------------------
// B. Profile Branding Pack
// ---------------------------------------------------------------------------
function generateProfileAssets() {
  const results = [];

  // 1. Avatar 800x800 (generous padding for circular crops)
  const avatarSvg = `<svg xmlns="http://www.w3.org/2000/svg" width="800" height="800" viewBox="0 0 800 800">
    <rect width="800" height="800" fill="#0b0f17"/>
    <circle cx="400" cy="400" r="320" fill="none" stroke="#1e293b" stroke-width="2" stroke-dasharray="10 10"/>
    <circle cx="400" cy="400" r="260" fill="#111827" stroke="#1e293b" stroke-width="2"/>
    ${shieldMarkSvg(400, 380, 2.5, '#38bdf8')}
    <text x="400" y="600" font-family="${MONO_FAMILY}" font-size="22" font-weight="700" fill="#94a3b8" text-anchor="middle" letter-spacing="3">PORTSCAMWATCH</text>
  </svg>`;
  results.push(
    renderSvgToPng(avatarSvg, path.join(ROOT_DIR, 'launch-assets/profile/avatar-800x800.png')),
  );

  // 2. X Banner 1500x500 (full-bleed dark gradient/grid, clear of top/bottom 60px and lower-left avatar)
  const xBannerSvg = `<svg xmlns="http://www.w3.org/2000/svg" width="1500" height="500" viewBox="0 0 1500 500">
    <defs>
      <radialGradient id="xGlow" cx="72%" cy="50%" r="55%">
        <stop offset="0%" stop-color="#38bdf8" stop-opacity="0.14"/>
        <stop offset="55%" stop-color="#111827" stop-opacity="0.45"/>
        <stop offset="100%" stop-color="#0b0f17" stop-opacity="0"/>
      </radialGradient>
    </defs>
    <rect width="1500" height="500" fill="#0b0f17"/>
    ${buildGridSvg(1500, 500, 50)}
    <rect width="1500" height="500" fill="url(#xGlow)"/>
    <circle cx="1360" cy="250" r="210" fill="none" stroke="#1e293b" stroke-width="1.5"/>
    <circle cx="1360" cy="250" r="145" fill="none" stroke="#334155" stroke-width="1.5" stroke-dasharray="6 6"/>

    <!-- Right-aligned typography + shield mark clear of top/bottom 60px and lower-left avatar -->
    ${shieldMarkSvg(1340, 212, 1.15, '#38bdf8')}
    <text x="1248" y="210" font-family="${SANS_FAMILY}" font-size="64" font-weight="700" fill="#f8fafc" text-anchor="end">PortScamWatch</text>
    <text x="1248" y="262" font-family="${MONO_FAMILY}" font-size="22" font-weight="600" fill="#38bdf8" text-anchor="end">Vendor-Verified Threat Lookup · portscamwatch.com</text>
    <text x="1400" y="330" font-family="${SANS_FAMILY}" font-size="21" font-weight="400" fill="#cbd5e1" text-anchor="end">${TOTAL_ADVISORIES} Vendor Advisories  ·  ${TOTAL_INDICATORS} Verified Indicators  ·  Live Client-Side RDAP</text>
    <text x="1400" y="366" font-family="${MONO_FAMILY}" font-size="16" font-weight="400" fill="#94a3b8" text-anchor="end">Bitdefender · Malwarebytes · Netcraft · Darktrace · NordVPN · ESET · Cynet</text>
  </svg>`;
  results.push(
    renderSvgToPng(xBannerSvg, path.join(ROOT_DIR, 'launch-assets/profile/x-banner-1500x500.png')),
  );

  // 3. YouTube Banner 2560x1440 (full-bleed grid + radial glow; bold typography filling 1546x423 safe zone naturally)
  const ytBannerSvg = `<svg xmlns="http://www.w3.org/2000/svg" width="2560" height="1440" viewBox="0 0 2560 1440">
    <defs>
      <radialGradient id="ytGlow" cx="50%" cy="50%" r="48%">
        <stop offset="0%" stop-color="#38bdf8" stop-opacity="0.16"/>
        <stop offset="50%" stop-color="#111827" stop-opacity="0.4"/>
        <stop offset="100%" stop-color="#0b0f17" stop-opacity="0"/>
      </radialGradient>
    </defs>
    <rect width="2560" height="1440" fill="#0b0f17"/>
    ${buildGridSvg(2560, 1440, 64)}
    <rect width="2560" height="1440" fill="url(#ytGlow)"/>
    <circle cx="1280" cy="720" r="640" fill="none" stroke="#1e293b" stroke-width="1.5"/>
    <circle cx="1280" cy="720" r="470" fill="none" stroke="#1e293b" stroke-width="1.5" stroke-dasharray="10 10"/>

    <!-- Centered branding sized boldly inside 1546x423 safe zone (x: 507..2053, y: 509..931) -->
    ${shieldMarkSvg(712, 718, 1.72, '#38bdf8')}
    <text x="840" y="692" font-family="${SANS_FAMILY}" font-size="96" font-weight="700" fill="#f8fafc">PortScamWatch</text>
    <text x="844" y="762" font-family="${MONO_FAMILY}" font-size="35" font-weight="600" fill="#38bdf8">Vendor-Verified Threat Lookup · portscamwatch.com</text>
    <text x="844" y="822" font-family="${SANS_FAMILY}" font-size="28" font-weight="400" fill="#cbd5e1">${TOTAL_ADVISORIES} Published Vendor Advisories  ·  ${TOTAL_INDICATORS} Verified Indicators  ·  Live RDAP</text>
  </svg>`;
  results.push(
    renderSvgToPng(
      ytBannerSvg,
      path.join(ROOT_DIR, 'launch-assets/profile/youtube-banner-2560x1440.png'),
    ),
  );

  return results;
}

// ---------------------------------------------------------------------------
// C. 6 X (Twitter) Reply & Thread Cards (1200x675)
// ---------------------------------------------------------------------------
function generateXCards() {
  const cards = [
    {
      filename: '01-overview-9-advisories.png',
      accent: '#38bdf8',
      badge: 'LAUNCH-WEEK THREAT SNAPSHOT',
      title: 'GTA 6 Launch-Week Threat Snapshot',
      subtitle: `${TOTAL_ADVISORIES} Vendor Advisories  |  ${TOTAL_INDICATORS} Verified Indicators  |  Live Client-Side RDAP`,
      bullets: [
        'Official Release: PS5 & Xbox Series X|S only (rockstargames.com)',
        'Tracked Vendors: Bitdefender, Malwarebytes, Netcraft, Darktrace, NordVPN, ESET, Cynet',
        'Top Vectors: ClickFix Win+R hijacks, Vidar/WARDEN infostealers, fake APKs & drainers',
        '3-Tier Check: Vendor IOC match + live client-side RDAP domain age',
      ],
      footerNote: 'Free lookup & 60-second exposure triage',
    },
    {
      filename: '02-bitdefender-clickfix.png',
      accent: '#ef4444',
      badge: 'CONFIRMED THREAT · BITDEFENDER LABS (NOV 20)',
      title: 'CONFIRMED: GTA6Cloud.exe / ClickFix Rust Infostealer',
      subtitle: 'Fake GTA VI cloud-streaming portals trick users into Win+R execution',
      bullets: [
        'Lure & Delivery Domains: gta6cloud[.]nexus  |  velmontriq[.]net',
        'Exfiltration C2 Domain: nimbuskeep[.]com (steals cookies, wallets & API keys)',
        'Side-Loading Chain: unlodctr.exe + loadperf.dll -> PhotoCache.exe injection',
        'Host Artifact: %LOCALAPPDATA%\\Temp\\ls_trace.txt & IconCacheToDelete\\0a3f2c91',
      ],
      footerNote: 'Inspect files read-only in Explorer — never run Win+R prompts',
    },
    {
      filename: '03-vidar-infostealer.png',
      accent: '#ef4444',
      badge: 'CONFIRMED THREAT · MALWAREBYTES & DARKTRACE',
      title: 'CONFIRMED: gta6_installer.exe & gta6demo[.]asia — Vidar Infostealer',
      subtitle: 'Cloned Rockstar demo portals serving a 1.1 MB Vidar payload',
      bullets: [
        'Indicators: gta6_installer.exe, gta6demo[.]asia, rockstar-gta-6[.]com',
        'Browser Bypass: Spawns headless Chrome, Edge & Firefox to decrypt cookies',
        'Targeted Data: 19 browsers, FTP/Thunderbird profiles & Roblox WebView2 sessions',
        'Enterprise Telemetry: Darktrace observed gta6demo[.]asia across 12 networks',
      ],
      footerNote: 'Rotate passwords & sign out of all active browser sessions',
    },
    {
      filename: '04-nordvpn-scam-kit.png',
      accent: '#ef4444',
      badge: 'CONFIRMED THREAT · NORDVPN THREAT INTEL (NOV 18)',
      title: 'CONFIRMED: $200 Dark-Web Kit — GTA6 Keygen.exe + XMRig + Wallet Drainer',
      subtitle: 'Automated YouTube Shorts bots promote a bundled 3-in-1 infection kit',
      bullets: [
        'Primary Lure File: GTA6 Keygen.exe (distributed via automated Shorts spam)',
        'Session Hijack: Extracts browser session cookies to bypass 2FA protections',
        'Multi-Chain Drainer: Targets Ethereum, BSC, Solana & Polygon balances',
        'Resource Hijack: Installs a silent background XMRig cryptocurrency miner',
      ],
      footerNote: 'No official GTA 6 PC keygen, beta, or crack exists',
    },
    {
      filename: '05-fake-apk-oauth.png',
      accent: '#ef4444',
      badge: 'CONFIRMED THREAT · MALWAREBYTES (NOV 18)',
      title: 'CONFIRMED: com.gta6.apkrate (1,700+ Uploads) & Cloned Google OAuth',
      subtitle: 'Fake mobile download sites distribute adware APKs & OAuth phishing',
      bullets: [
        'Android Package: com.gta6.apkrate (36.8 MB Unity APK under 90+ filenames)',
        'Mobile Risk: Aggressive ad SDKs, debugger checks & SIM/app enumeration',
        'OAuth Phishing: Fake "Continue with Google" pages steal Gmail & YouTube logins',
        'Console Only: Zero official GTA 6 Android or iOS builds have been released',
      ],
      footerNote: 'Uninstall unknown APKs & revoke suspicious OAuth access',
    },
    {
      filename: '06-4-step-containment.png',
      accent: '#f59e0b',
      badge: 'INCIDENT RESPONSE CHECKLIST',
      title: 'Ran a Fake GTA 6 Installer? 4-Step Containment Order',
      subtitle: 'Infostealers copy cookies & tokens within seconds — order matters',
      bullets: [
        '1. Disconnect Wi-Fi & unplug Ethernet immediately to halt exfiltration/C2',
        '2. From ANOTHER clean device: rotate passwords & click "Sign out of all sessions"',
        '3. Revoke suspicious Web3 wallet token approvals & move funds to a new wallet',
        '4. Run a deep offline AV scan; for ClickFix persistence, perform a clean OS reset',
      ],
      footerNote: 'Interactive 60-second exposure wizard available online',
    },
  ];

  const width = 1200;
  const height = 675;

  return cards.map((card) => {
    const titleLines = wrapTextLines(card.title, 48);
    const titleStartY = 172;
    const afterTitleY = titleStartY + titleLines.length * 46;
    const subtitleY = afterTitleY + 4;
    const panelY = subtitleY + 26;
    const panelH = 574 - panelY;
    const badgeW = Math.round(card.badge.length * 8.6 + 38);

    let bulletCursorY = panelY + 46;
    const bulletStep = Math.floor((panelH - 54) / card.bullets.length);
    const bulletLinesSvg = card.bullets
      .map((b) => {
        const y = bulletCursorY;
        const wrapped = wrapTextLines(b, 92);
        bulletCursorY += Math.max(bulletStep, wrapped.length * 24 + 16);
        return wrapped
          .map(
            (line, lineIdx) =>
              `<text x="114" y="${y + lineIdx * 24}" font-family="${SANS_FAMILY}" font-size="19" font-weight="${
                lineIdx === 0 ? '600' : '400'
              }" fill="${lineIdx === 0 ? '#f1f5f9' : '#cbd5e1'}">${
                lineIdx === 0 ? '•  ' : '   '
              }${escapeXml(line)}</text>`,
          )
          .join('\n');
      })
      .join('\n');

    const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}">
      <rect width="${width}" height="${height}" fill="#0b0f17"/>
      ${buildGridSvg(width, height, 60)}
      <rect x="44" y="40" width="1112" height="595" rx="14" fill="#111827" stroke="#1e293b" stroke-width="2"/>
      <rect x="44" y="40" width="1112" height="6" rx="3" fill="${card.accent}"/>

      <rect x="84" y="76" width="${badgeW}" height="34" rx="6" fill="#0b0f17" stroke="${card.accent}" stroke-width="1.5"/>
      <text x="103" y="99" font-family="${MONO_FAMILY}" font-size="14" font-weight="700" fill="${card.accent}">${escapeXml(card.badge)}</text>

      ${renderTextLines({
        lines: titleLines,
        x: 84,
        y: titleStartY,
        lineHeight: 46,
        fontSize: 36,
        fontWeight: '700',
        fill: '#f8fafc',
      })}

      <text x="84" y="${subtitleY}" font-family="${SANS_FAMILY}" font-size="20" font-weight="400" fill="#94a3b8">${escapeXml(card.subtitle)}</text>

      <rect x="84" y="${panelY}" width="1032" height="${panelH}" rx="10" fill="#0b0f17" stroke="#1e293b" stroke-width="1.5"/>
      ${bulletLinesSvg}

      <text x="84" y="608" font-family="${SANS_FAMILY}" font-size="16" font-weight="400" fill="#94a3b8">${escapeXml(card.footerNote)}</text>
      <text x="1116" y="608" font-family="${MONO_FAMILY}" font-size="18" font-weight="700" fill="#f8fafc" text-anchor="end">portscamwatch.com</text>
    </svg>`;

    return renderSvgToPng(svg, path.join(ROOT_DIR, 'launch-assets/x-cards', card.filename));
  });
}

// ---------------------------------------------------------------------------
// D. 5 Silent TikTok Photo Mode Carousels (1080x1920, strict safe zone)
// ---------------------------------------------------------------------------
// Safe zone: top 260px, bottom 380px, sides 100px => x: 100..980 (w=880), y: 260..1540 (h=1280)
function generateTikTokCarousels() {
  const carousels = [
    {
      dir: 'carousel-1',
      tag: 'BITDEFENDER LABS · CLICKFIX ALERT',
      accent: '#ef4444',
      slides: [
        {
          headline: 'GTA6Cloud.exe is a Rust infostealer.',
          body: 'Bitdefender Labs flagged this ClickFix trap on Nov 20, 2026.',
        },
        {
          headline: 'The lure domain gta6cloud[.]nexus',
          body: 'Prompts Windows users to paste a PowerShell command into Win + R.',
        },
        {
          headline: 'Trailer Decoy + DLL Side-Loading',
          body: 'GTA6Cloud.exe fetches unlodctr.exe & malicious loadperf.dll from velmontriq[.]net.',
        },
        {
          headline: 'Process Injection -> C2 Exfiltration',
          body: 'Injects PhotoCache.exe into Windows processes, sending data to nimbuskeep[.]com.',
        },
        {
          headline: 'What It Steals',
          body: 'Browser cookies, Steam & Discord sessions, crypto wallets, and developer API keys.',
        },
        {
          headline: 'Read-Only File Explorer Check',
          body: 'Turn on Hidden items. Inspect %LOCALAPPDATA%\\Temp\\ls_trace.txt & IconCacheToDelete\\0a3f2c91.',
        },
        {
          headline: 'Verify Before You Download',
          body: 'Check filenames, hashes & domains at portscamwatch.com — Save this post.',
        },
      ],
    },
    {
      dir: 'carousel-2',
      tag: 'WEEKLY VENDOR THREAT ROUNDUP',
      accent: '#38bdf8',
      slides: [
        {
          headline: '5 Confirmed Fake GTA 6 Lures',
          body: 'Active ClickFix, Vidar, WARDEN, and APK campaigns flagged by security vendors.',
        },
        {
          headline: 'Bitdefender Labs (Nov 20)',
          body: 'gta6cloud[.]nexus & GTA6Cloud.zip drop a ClickFix Rust infostealer.',
        },
        {
          headline: 'Netcraft (Nov 18)',
          body: 'gta6download[.]club, gta6downloadforpc[.]com & GTAVI.exe push fake PC cracks.',
        },
        {
          headline: 'Darktrace (Nov 17)',
          body: 'gta6-play[.]ru pushed InstallRex; gta6demo[.]asia hit 12 enterprise networks.',
        },
        {
          headline: 'Malwarebytes (Aug & Nov 2026)',
          body: 'gta6_installer.exe drops Vidar infostealer; com.gta6.apkrate spreads Android adware.',
        },
        {
          headline: 'Cynet (Nov 13)',
          body: 'Gta_6_Exe_File_Download.zip via Google Colab drops WARDEN Stealer to uroker[.]casa.',
        },
        {
          headline: 'Check Against Vendor Feeds',
          body: `Live RDAP & ${TOTAL_INDICATORS} vendor IOCs at portscamwatch.com — Save this post.`,
        },
      ],
    },
    {
      dir: 'carousel-3',
      tag: 'NORDVPN THREAT INTELLIGENCE',
      accent: '#ef4444',
      slides: [
        {
          headline: 'A $200 Dark-Web GTA 6 Scam Kit',
          body: 'NordVPN Threat Intel tracked this bundle targeting PC crack hunters.',
        },
        {
          headline: 'Automated YouTube Shorts Bots',
          body: 'Attackers use bots to flood Shorts with fake GTA 6 PC download links.',
        },
        {
          headline: 'GTA6 Keygen.exe',
          body: 'Steals browser session cookies—hijacking accounts even with 2FA enabled.',
        },
        {
          headline: 'Multi-Chain Wallet Drainer',
          body: 'Targets Ethereum, BSC, Solana, and Polygon wallet balances.',
        },
        {
          headline: 'Hidden XMRig Cryptominer',
          body: 'Runs silently in the background to burn your CPU and GPU.',
        },
        {
          headline: 'Verify First, Download Never',
          body: 'Check GTA 6 filenames against vendor feeds at portscamwatch.com.',
        },
      ],
    },
    {
      dir: 'carousel-4',
      tag: 'MOBILE & OAUTH PHISHING ALERT',
      accent: '#f59e0b',
      slides: [
        {
          headline: '1,700+ Fake GTA 6 Android APKs',
          body: 'No official mobile app exists. Package com.gta6.apkrate uses 90+ fake names.',
        },
        {
          headline: '36.8 MB Unity Adware Shell',
          body: "Malwarebytes flagged 'GTA 6 Mod APK Beta V8.0.9' running aggressive ad SDKs.",
        },
        {
          headline: 'Device & App Recon',
          body: 'Enumerates installed apps, SIM/network data, and checks for debuggers/ADB.',
        },
        {
          headline: "Cloned 'Continue with Google' Traps",
          body: "Fake 'Free GTA VI' pages reload a cloned Google login form on the scam domain.",
        },
        {
          headline: 'Netcraft Mobile Scam Domains',
          body: 'Flagged: gta6thapk[.]com, gta6world[.]live, and gta6mobile[.]app.',
        },
        {
          headline: 'Run a 60-Second Check',
          body: 'Verify domains & follow removal steps at portscamwatch.com.',
        },
      ],
    },
    {
      dir: 'carousel-5',
      tag: 'EMERGENCY CONTAINMENT GUIDE',
      accent: '#f59e0b',
      slides: [
        {
          headline: 'Already Ran a Fake GTA 6 File?',
          body: 'Password changes on the same PC are not enough. Follow these 4 steps.',
        },
        {
          headline: 'Step 1: Disconnect Immediately',
          body: 'Turn off Wi-Fi and unplug Ethernet to halt data theft & hidden mining.',
        },
        {
          headline: 'Step 2: Rotate From Another Device',
          body: "Use a clean phone/PC to change passwords AND click 'Sign out of all sessions'.",
        },
        {
          headline: 'Step 3: Revoke Crypto Approvals',
          body: 'Revoke Web3 token allowances and move funds to a brand-new wallet.',
        },
        {
          headline: 'Step 4: Deep Scan or OS Reset',
          body: 'Confirmed ClickFix persistence (HKCU Run keys) warrants a clean OS reinstall.',
        },
        {
          headline: 'Free 5-Question Triage Wizard',
          body: 'Step-by-step read-only checklist at portscamwatch.com — Save this.',
        },
      ],
    },
  ];

  const width = 1080;
  const height = 1920;
  const generated = [];

  for (const carousel of carousels) {
    const total = carousel.slides.length;
    carousel.slides.forEach((slide, idx) => {
      const slideNum = idx + 1;
      const filename = `${String(slideNum).padStart(2, '0')}.png`;
      const headlineLines = wrapTextLines(slide.headline, 21);
      const bodyLines = wrapTextLines(slide.body, 31);

      // All content strictly inside x: 100..980 (880px), y: 260..1540 (1280px)
      const cardX = 112;
      const cardY = 340;
      const cardW = 856;
      const cardH = 1140;

      const headlineStartY = 560;
      const headlineLineHeight = 76;
      const bodyStartY = headlineStartY + headlineLines.length * headlineLineHeight + 52;
      const bodyLineHeight = 52;

      const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}">
        <rect width="${width}" height="${height}" fill="#0b0f17"/>
        ${buildGridSvg(width, height, 60)}

        <!-- Top-center slide counter inside safe zone (y >= 260) -->
        <rect x="476" y="276" width="128" height="42" rx="21" fill="#111827" stroke="#334155" stroke-width="1.5"/>
        <text x="540" y="304" font-family="${MONO_FAMILY}" font-size="22" font-weight="700" fill="#e2e8f0" text-anchor="middle">${slideNum}/${total}</text>

        <!-- Main safe-zone card -->
        <rect x="${cardX}" y="${cardY}" width="${cardW}" height="${cardH}" rx="22" fill="#111827" stroke="#1e293b" stroke-width="2.5"/>
        <rect x="${cardX}" y="${cardY}" width="${cardW}" height="10" rx="5" fill="${carousel.accent}"/>

        <!-- Tag pill -->
        <rect x="164" y="406" width="${Math.min(752, carousel.tag.length * 14 + 48)}" height="46" rx="8" fill="#0b0f17" stroke="${carousel.accent}" stroke-width="1.5"/>
        <text x="188" y="436" font-family="${MONO_FAMILY}" font-size="20" font-weight="700" fill="${carousel.accent}">${escapeXml(carousel.tag)}</text>

        <!-- Headline -->
        ${renderTextLines({
          lines: headlineLines,
          x: 164,
          y: headlineStartY,
          lineHeight: headlineLineHeight,
          fontSize: 60,
          fontWeight: '700',
          fill: '#f8fafc',
        })}

        <!-- Divider -->
        <line x1="164" y1="${bodyStartY - 32}" x2="916" y2="${bodyStartY - 32}" stroke="#1e293b" stroke-width="2"/>

        <!-- Body -->
        ${renderTextLines({
          lines: bodyLines,
          x: 164,
          y: bodyStartY + 14,
          lineHeight: bodyLineHeight,
          fontSize: 36,
          fontWeight: '400',
          fill: '#cbd5e1',
        })}

        <!-- Bottom safe-zone footer (inside y <= 1480) -->
        <line x1="164" y1="1352" x2="916" y2="1352" stroke="#1e293b" stroke-width="1.5"/>
        ${shieldMarkSvg(194, 1412, 0.44, carousel.accent)}
        <text x="234" y="1408" font-family="${MONO_FAMILY}" font-size="24" font-weight="700" fill="#f8fafc">portscamwatch.com</text>
        <text x="234" y="1436" font-family="${MONO_FAMILY}" font-size="16" font-weight="400" fill="#94a3b8">VENDOR-VERIFIED THREAT LOOKUP</text>
      </svg>`;

      generated.push(
        renderSvgToPng(
          svg,
          path.join(ROOT_DIR, 'launch-assets/tiktok-carousels', carousel.dir, filename),
        ),
      );
    });
  }

  return generated;
}

// ---------------------------------------------------------------------------
// E. Single-Tab Preview Gallery (launch-assets/PREVIEW_ALL.html)
// ---------------------------------------------------------------------------
function generatePreviewHtml({ og, profile, xCards, tiktokSlides }) {
  const tiktokGroups = ['carousel-1', 'carousel-2', 'carousel-3', 'carousel-4', 'carousel-5'].map(
    (dir) => ({
      dir,
      items: tiktokSlides.filter((s) => s.path.includes(dir)),
    }),
  );

  const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>PortScamWatch — Visual Asset Preview Gallery</title>
  <style>
    * { box-sizing: border-box; }
    body {
      margin: 0;
      padding: 28px;
      background: #0b0f17;
      color: #f1f5f9;
      font-family: system-ui, -apple-system, Segoe UI, sans-serif;
    }
    h1, h2, h3 { margin: 0 0 12px; }
    h1 { font-size: 26px; }
    h2 { font-size: 18px; margin-top: 32px; border-bottom: 1px solid #1e293b; padding-bottom: 8px; color: #38bdf8; }
    .toolbar {
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      align-items: center;
      margin-bottom: 20px;
      padding: 12px 16px;
      background: #111827;
      border: 1px solid #1e293b;
      border-radius: 10px;
    }
    label { font-size: 13px; display: inline-flex; align-items: center; gap: 6px; cursor: pointer; }
    .card {
      background: #111827;
      border: 1px solid #1e293b;
      border-radius: 10px;
      padding: 14px;
    }
    .meta {
      font-family: ui-monospace, Consolas, monospace;
      font-size: 12px;
      color: #94a3b8;
      margin-top: 8px;
    }
    .grid-profile { display: grid; gap: 16px; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); }
    .grid-x { display: grid; gap: 16px; grid-template-columns: repeat(auto-fit, minmax(360px, 1fr)); }
    .strip-tiktok { display: grid; gap: 12px; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); margin-bottom: 20px; }
    img { display: block; width: 100%; height: auto; border-radius: 6px; border: 1px solid #1e293b; }
    .avatar-pair { display: flex; gap: 16px; align-items: center; }
    .avatar-pair img { width: 150px; height: 150px; }
    .avatar-circle { border-radius: 50% !important; }
    .yt-wrap, .tt-wrap { position: relative; }
    .yt-safe {
      display: none;
      position: absolute;
      left: 19.80%;
      top: 35.31%;
      width: 60.39%;
      height: 29.38%;
      border: 1.5px dashed rgba(255, 255, 255, 0.25);
      background: rgba(255, 255, 255, 0.04);
      pointer-events: none;
    }
    .tt-safe {
      display: none;
      position: absolute;
      left: 9.26%;
      top: 13.54%;
      width: 81.48%;
      height: 66.67%;
      border: 1.5px dashed rgba(255, 255, 255, 0.25);
      background: rgba(255, 255, 255, 0.04);
      pointer-events: none;
    }
    body.show-safe .yt-safe,
    body.show-safe .tt-safe { display: block; }
  </style>
</head>
<body>
  <h1>PortScamWatch — Local Launch Asset Gallery</h1>
  <div class="toolbar">
    <label><input type="checkbox" id="toggleSafe" /> Show YouTube &amp; TikTok safe-zone guide</label>
    <span class="meta">Total rendered: 1 OG image + 3 profile assets + ${xCards.length} X cards + ${tiktokSlides.length} TikTok slides</span>
  </div>

  <h2>1. Public OG Card (public/og-image.png)</h2>
  <div class="card" style="max-width: 720px;">
    <img src="../public/og-image.png" alt="OG Image" />
    <div class="meta">public/og-image.png (${og.width}x${og.height})</div>
  </div>

  <h2>2. Profile Branding Pack</h2>
  <div class="grid-profile">
    <div class="card">
      <div class="avatar-pair">
        <img src="profile/avatar-800x800.png" alt="Square Avatar" />
        <img src="profile/avatar-800x800.png" alt="Circle Crop Preview" class="avatar-circle" />
      </div>
      <div class="meta">profile/avatar-800x800.png (Square + Circle Crop Preview)</div>
    </div>
    <div class="card">
      <img src="profile/x-banner-1500x500.png" alt="X Banner" />
      <div class="meta">profile/x-banner-1500x500.png (1500x500)</div>
    </div>
    <div class="card">
      <div class="yt-wrap">
        <img src="profile/youtube-banner-2560x1440.png" alt="YouTube Banner" />
        <div class="yt-safe" title="1546x423 YouTube Safe Zone"></div>
      </div>
      <div class="meta">profile/youtube-banner-2560x1440.png (dashed box = 1546x423 safe zone)</div>
    </div>
  </div>

  <h2>3. X (Twitter) Thread &amp; Reply Cards (1200x675)</h2>
  <div class="grid-x">
    ${xCards
      .map(
        (c) => `
    <div class="card">
      <img src="x-cards/${path.basename(c.path)}" alt="${path.basename(c.path)}" />
      <div class="meta">x-cards/${path.basename(c.path)} (${c.width}x${c.height})</div>
    </div>`,
      )
      .join('')}
  </div>

  <h2>4. TikTok Photo Mode Carousels (1080x1920, center safe zone)</h2>
  ${tiktokGroups
    .map(
      (group) => `
  <h3>${group.dir} (${group.items.length} slides)</h3>
  <div class="strip-tiktok">
    ${group.items
      .map(
        (item) => `
    <div class="card">
      <div class="tt-wrap">
        <img src="tiktok-carousels/${group.dir}/${path.basename(item.path)}" alt="${group.dir} ${path.basename(item.path)}" />
        <div class="tt-safe" title="TikTok Safe Zone"></div>
      </div>
      <div class="meta">${group.dir}/${path.basename(item.path)}</div>
    </div>`,
      )
      .join('')}
  </div>`,
    )
    .join('')}

  <script>
    document.getElementById('toggleSafe').addEventListener('change', (e) => {
      document.body.classList.toggle('show-safe', e.target.checked);
    });
  </script>
</body>
</html>`;

  const outPath = path.join(ROOT_DIR, 'launch-assets/PREVIEW_ALL.html');
  fs.writeFileSync(outPath, html, 'utf-8');
  return outPath;
}

function main() {
  const og = generateOgImage();
  const profile = generateProfileAssets();
  const xCards = generateXCards();
  const tiktokSlides = generateTikTokCarousels();
  const previewPath = generatePreviewHtml({ og, profile, xCards, tiktokSlides });

  const totalPngs = 1 + profile.length + xCards.length + tiktokSlides.length;
  console.log(`Generated ${totalPngs} PNG assets + preview gallery:`);
  console.log(`  - public/og-image.png (${og.width}x${og.height})`);
  console.log(`  - launch-assets/profile/ (${profile.length} files)`);
  console.log(`  - launch-assets/x-cards/ (${xCards.length} files)`);
  console.log(`  - launch-assets/tiktok-carousels/ (${tiktokSlides.length} slides across 5 carousels)`);
  console.log(`  - ${path.relative(ROOT_DIR, previewPath)}`);
}

main();
