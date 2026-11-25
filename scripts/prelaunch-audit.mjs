import { execSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.resolve(__dirname, '..');

const HTTP_TIMEOUT_MS = 10_000;
const BROWSER_UA =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';

function readPngDimensions(filePath) {
  const buf = fs.readFileSync(filePath);
  const pngSig = '89504e470d0a1a0a';
  if (buf.length < 24 || buf.subarray(0, 8).toString('hex') !== pngSig) {
    throw new Error(`Not a valid PNG file: ${filePath}`);
  }
  return {
    width: buf.readUInt32BE(16),
    height: buf.readUInt32BE(20),
  };
}

function collectVendorUrls() {
  const threatsData = JSON.parse(
    fs.readFileSync(path.join(ROOT_DIR, 'public/data/threats.json'), 'utf-8'),
  );
  const envTs = fs.readFileSync(path.join(ROOT_DIR, 'src/lib/env.ts'), 'utf-8');
  const fallbackMatches = envTs.match(/https:\/\/[^\s'"`]+/g) || [];

  const entries = [];
  const seen = new Set();

  for (const threat of threatsData.threats) {
    if (!seen.has(threat.advisoryUrl)) {
      seen.add(threat.advisoryUrl);
      entries.push({ source: threat.vendorName, url: threat.advisoryUrl });
    }
  }
  for (const url of fallbackMatches) {
    if (!seen.has(url)) {
      seen.add(url);
      entries.push({ source: 'src/lib/env.ts fallback', url });
    }
  }
  return entries;
}

async function checkSingleUrl(url) {
  const attempt = async (method) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), HTTP_TIMEOUT_MS);
    try {
      return await fetch(url, {
        method,
        redirect: 'follow',
        signal: controller.signal,
        headers: {
          'User-Agent': BROWSER_UA,
          Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'Accept-Language': 'en-US,en;q=0.9',
        },
      });
    } finally {
      clearTimeout(timer);
    }
  };

  try {
    let res = await attempt('HEAD');
    if (res.status === 405 || res.status === 403 || res.status === 501) {
      res = await attempt('GET');
    }
    if (res.status >= 200 && res.status < 400) {
      return { status: res.status, category: 'OK' };
    }
    if (res.status === 403 || res.status === 429) {
      return { status: res.status, category: 'BOT_BLOCK_SPOT_CHECK' };
    }
    return { status: res.status, category: 'BROKEN' };
  } catch (err) {
    return {
      status: 'ERR',
      category: 'NETWORK_ERROR',
      detail: err instanceof Error ? err.message : String(err),
    };
  }
}

function verifyAssets() {
  const expectedAssets = [
    { rel: 'public/og-image.png', w: 1200, h: 630 },
    { rel: 'launch-assets/profile/avatar-800x800.png', w: 800, h: 800 },
    { rel: 'launch-assets/profile/x-banner-1500x500.png', w: 1500, h: 500 },
    { rel: 'launch-assets/profile/youtube-banner-2560x1440.png', w: 2560, h: 1440 },
  ];

  const xCards = [
    '01-overview-9-advisories.png',
    '02-bitdefender-clickfix.png',
    '03-vidar-infostealer.png',
    '04-nordvpn-scam-kit.png',
    '05-fake-apk-oauth.png',
    '06-4-step-containment.png',
  ];
  for (const name of xCards) {
    expectedAssets.push({ rel: `launch-assets/x-cards/${name}`, w: 1200, h: 675 });
  }

  const carouselCounts = {
    'carousel-1': 7,
    'carousel-2': 7,
    'carousel-3': 6,
    'carousel-4': 6,
    'carousel-5': 6,
  };
  for (const [dir, count] of Object.entries(carouselCounts)) {
    for (let i = 1; i <= count; i += 1) {
      expectedAssets.push({
        rel: `launch-assets/tiktok-carousels/${dir}/${String(i).padStart(2, '0')}.png`,
        w: 1080,
        h: 1920,
      });
    }
  }

  const failures = [];
  for (const item of expectedAssets) {
    const abs = path.join(ROOT_DIR, item.rel);
    if (!fs.existsSync(abs)) {
      failures.push(`Missing PNG: ${item.rel}`);
      continue;
    }
    const dims = readPngDimensions(abs);
    if (dims.width !== item.w || dims.height !== item.h) {
      failures.push(
        `Wrong dimensions for ${item.rel}: got ${dims.width}x${dims.height}, expected ${item.w}x${item.h}`,
      );
    }
  }

  const previewHtml = path.join(ROOT_DIR, 'launch-assets/PREVIEW_ALL.html');
  if (!fs.existsSync(previewHtml)) {
    failures.push('Missing launch-assets/PREVIEW_ALL.html');
  }

  return { checkedPngs: expectedAssets.length, failures };
}

function verifyGitignoreHygiene() {
  const failures = [];
  for (const target of ['launch-assets/', '.env']) {
    try {
      execSync(`git check-ignore -q ${target}`, { cwd: ROOT_DIR, stdio: 'pipe' });
    } catch {
      failures.push(`"${target}" is NOT ignored by .gitignore`);
    }
  }

  const statusOut = execSync('git status --short', { cwd: ROOT_DIR, encoding: 'utf-8' });
  const lines = statusOut.split(/\r?\n/).filter(Boolean);
  for (const line of lines) {
    if (line.includes('launch-assets') || /\s\.env$/.test(line)) {
      failures.push(`Ignored path appears in git status: "${line}"`);
    }
  }

  return failures;
}

async function main() {
  console.log('=== 1. URL & Advisory Link Check ===');
  const urlEntries = collectVendorUrls();
  const linkResults = [];
  for (const entry of urlEntries) {
    const res = await checkSingleUrl(entry.url);
    linkResults.push({ ...entry, ...res });
  }

  console.table(
    linkResults.map((r) => ({
      Source: r.source,
      Status: r.status,
      Result: r.category,
      URL: r.url,
    })),
  );

  const brokenLinks = linkResults.filter((r) => r.category === 'BROKEN');
  const networkErrors = linkResults.filter((r) => r.category === 'NETWORK_ERROR');
  const botBlocked = linkResults.filter((r) => r.category === 'BOT_BLOCK_SPOT_CHECK');
  if (botBlocked.length > 0) {
    console.log(
      `Note: ${botBlocked.length} URL(s) returned HTTP 403/429 (bot protection — spot-check manually in browser).`,
    );
  }
  if (networkErrors.length > 0) {
    console.warn(`Warning: ${networkErrors.length} URL(s) experienced network/timeout errors.`);
  }

  console.log('\n=== 2. PNG Asset & Dimension Verification ===');
  const assetCheck = verifyAssets();
  console.log(`Checked ${assetCheck.checkedPngs} PNG files + launch-assets/PREVIEW_ALL.html.`);
  if (assetCheck.failures.length > 0) {
    assetCheck.failures.forEach((f) => console.error(`  - ${f}`));
  }

  console.log('\n=== 3. Gitignore & Staging Hygiene ===');
  const gitFailures = verifyGitignoreHygiene();
  if (gitFailures.length === 0) {
    console.log('Verified launch-assets/ and .env are strictly gitignored and unstaged.');
  } else {
    gitFailures.forEach((f) => console.error(`  - ${f}`));
  }

  console.log('\n=== 4. Data Validation, Tests & Production Build ===');
  execSync('npm run validate:data', { cwd: ROOT_DIR, stdio: 'inherit' });
  execSync('npm test', { cwd: ROOT_DIR, stdio: 'inherit' });
  execSync('npm run build', { cwd: ROOT_DIR, stdio: 'inherit' });

  if (brokenLinks.length > 0 || assetCheck.failures.length > 0 || gitFailures.length > 0) {
    console.error('\n❌ Pre-launch audit failed.');
    process.exit(1);
  }

  console.log('\n✅ Pre-launch audit passed.');
}

main().catch((err) => {
  console.error('Fatal prelaunch audit error:', err);
  process.exit(1);
});
