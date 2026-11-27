import assert from 'node:assert/strict';
import { execSync } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.resolve(__dirname, '..');
const DIST_DIR = path.join(ROOT_DIR, 'dist');
const E2E_DIST_DIR = path.join(ROOT_DIR, '.playwright-tmp/dist-e2e');

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.txt': 'text/plain; charset=utf-8',
  '.xml': 'application/xml; charset=utf-8',
};

function parseAndValidateHeadersFile() {
  const headersPath = path.join(DIST_DIR, '_headers');
  assert.ok(fs.existsSync(headersPath), 'dist/_headers must exist');
  const raw = fs.readFileSync(headersPath, 'utf-8');
  const lines = raw.split(/\r?\n/);

  for (let i = 0; i < lines.length; i += 1) {
    assert.ok(
      lines[i].length <= 2000,
      `dist/_headers line ${i + 1} exceeds Cloudflare 2,000-char limit`,
    );
  }

  assert.ok(raw.includes('pages.dev/*'), 'dist/_headers must configure *.pages.dev rule');
  assert.ok(raw.includes('X-Robots-Tag: noindex'), 'dist/_headers must set noindex on pages.dev');
  assert.ok(raw.includes('X-Frame-Options: DENY'), 'dist/_headers must set X-Frame-Options: DENY');
  assert.ok(raw.includes('Strict-Transport-Security:'), 'dist/_headers must set HSTS');
  assert.ok(raw.includes('Content-Security-Policy:'), 'dist/_headers must set CSP');

  // Extract global /* headers to inject on local E2E HTTP responses
  const globalBlockMatch = raw.match(/\/\*\r?\n([\s\S]*)$/);
  assert.ok(globalBlockMatch, 'dist/_headers must define /* global block');
  const responseHeaders = {};
  for (const line of globalBlockMatch[1].split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const colonIdx = trimmed.indexOf(':');
    if (colonIdx === -1) continue;
    const name = trimmed.slice(0, colonIdx).trim();
    const val = trimmed.slice(colonIdx + 1).trim();
    // Skip HSTS over plain http://127.0.0.1 in local E2E test server
    if (name.toLowerCase() === 'strict-transport-security') continue;
    responseHeaders[name] = val;
  }
  return responseHeaders;
}

function startDistServer(serveDir, securityHeaders) {
  return new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      const reqPath = (req.url || '/').split('?')[0];
      const relPath = reqPath === '/' ? 'index.html' : reqPath.replace(/^\/+/, '');
      let filePath = path.join(serveDir, relPath);
      if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
        filePath = path.join(serveDir, 'index.html');
      }

      const ext = path.extname(filePath).toLowerCase();
      res.writeHead(200, {
        'Content-Type': MIME_TYPES[ext] || 'application/octet-stream',
        ...securityHeaders,
      });
      fs.createReadStream(filePath).pipe(res);
    });

    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      resolve({ server, baseUrl: `http://127.0.0.1:${addr.port}` });
    });
  });
}

async function setupRdapMocks(page) {
  await page.route('https://rdap.org/domain/**', async (route) => {
    const url = route.request().url().toLowerCase();
    if (url.endsWith('/rockstargames.com')) {
      await route.fulfill({
        status: 200,
        contentType: 'application/rdap+json',
        body: JSON.stringify({
          events: [{ eventAction: 'registration', eventDate: '1998-03-10T05:00:00Z' }],
        }),
      });
      return;
    }
    if (url.endsWith('/velmontriq.net')) {
      await route.fulfill({
        status: 200,
        contentType: 'application/rdap+json',
        body: JSON.stringify({
          events: [{ eventAction: 'registration', eventDate: '2026-11-18T00:00:00Z' }],
        }),
      });
      return;
    }
    await route.fulfill({ status: 200, contentType: 'application/json', body: '{}' });
  });
}

function attachTelemetryListeners(page, baseUrl) {
  const consoleErrors = [];
  const pageErrors = [];
  const badLocalResponses = [];

  page.on('console', (msg) => {
    if (msg.type() === 'error') {
      consoleErrors.push(msg.text());
    }
  });
  page.on('pageerror', (err) => {
    pageErrors.push(err.message);
  });
  page.on('response', (res) => {
    const url = res.url();
    if (url.startsWith(baseUrl) && res.status() >= 400) {
      badLocalResponses.push(`${res.status()} ${url}`);
    }
  });

  return { consoleErrors, pageErrors, badLocalResponses };
}

async function runDesktopChecks(browser, baseUrl) {
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await context.newPage();
  const telemetry = attachTelemetryListeners(page, baseUrl);
  await setupRdapMocks(page);

  try {
    // 1. Homepage & Recommended Protection Stack
    await page.goto(baseUrl, { waitUntil: 'networkidle' });
    const homeLinks = page.locator(
      '[data-testid="defense-tools-full-homepage"] a[rel="noopener noreferrer sponsored"]',
    );
    const homeLinkCount = await homeLinks.count();
    assert.equal(homeLinkCount, 2, 'Expected 2 configured Nord links on homepage');
    for (let i = 0; i < homeLinkCount; i += 1) {
      const href = await homeLinks.nth(i).getAttribute('href');
      assert.ok(href?.includes('aff_id=162042'), 'Expected aff_id=162042');
      assert.ok(href?.includes('aff_sub=psw_homepage'), 'Expected aff_sub=psw_homepage');
    }

    // 2. Confirmed Threat lookup (GTA6Cloud.exe)
    const input = page.locator('input[aria-label*="Suspicious URL"]');
    const submitBtn = page.getByRole('button', { name: /Inspect Indicator/i });
    await input.fill('GTA6Cloud.exe');
    await submitBtn.click();
    await page.getByText('MATCHED IN VENDOR ADVISORIES').waitFor({ timeout: 5000 });

    const verdictLinks = page.locator(
      '[data-testid="defense-tools-compact-verdict"] a[rel="noopener noreferrer sponsored"]',
    );
    assert.equal(await verdictLinks.count(), 2);
    assert.ok((await verdictLinks.first().getAttribute('href'))?.includes('aff_sub=psw_verdict'));
    await page.getByRole('button', { name: /Copy verdict link/i }).waitFor();

    // 3. Defanged malicious domain lookup (velmontriq[.]net)
    await input.fill('velmontriq[.]net');
    await submitBtn.click();
    await page.getByText('Normalized input →').waitFor({ timeout: 5000 });
    await page.getByText('MATCHED IN VENDOR ADVISORIES').waitFor({ timeout: 5000 });

    // 4. Benign lookup (rockstargames.com) -> 0 affiliate links inside verdict
    await input.fill('rockstargames.com');
    await submitBtn.click();
    await page.getByText('ESTABLISHED DOMAIN — NOT IN THREAT LISTS').waitFor({ timeout: 5000 });
    assert.equal(await page.locator('[data-testid="defense-tools-compact-verdict"]').count(), 0);

    // 5. Deep link hydration (/?q=GTA6Cloud.exe)
    await page.goto(`${baseUrl}/?q=GTA6Cloud.exe`, { waitUntil: 'networkidle' });
    await page.getByText('MATCHED IN VENDOR ADVISORIES').waitFor({ timeout: 5000 });

    // 6. Client-side SHA-256 file hashing with ZERO outbound network requests
    const tmpFile = path.join(os.tmpdir(), 'portscamwatch-e2e-sample.bin');
    fs.writeFileSync(tmpFile, 'abc', 'utf-8');
    try {
      await page.getByRole('button', { name: /Hash a Local File/i }).click();
      const outboundDuringHash = [];
      const reqListener = (req) => {
        if (!req.url().startsWith(baseUrl)) {
          outboundDuringHash.push(req.url());
        } else if (!req.url().includes('/data/')) {
          outboundDuringHash.push(req.url());
        }
      };
      page.on('request', reqListener);
      await page.locator('input[aria-label="Choose a local file to hash SHA-256"]').setInputFiles(tmpFile);
      await page
        .getByText('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
        .first()
        .waitFor({ timeout: 5000 });
      page.off('request', reqListener);
      assert.equal(
        outboundDuringHash.length,
        0,
        `Expected 0 outbound requests during local file hashing, saw: ${outboundDuringHash.join(', ')}`,
      );
    } finally {
      fs.rmSync(tmpFile, { force: true });
    }

    // 7. Removal guide expanded -> aff_sub=psw_guide
    await page.locator('#removal-guides summary').click();
    const guideLink = page
      .locator('#guide-gta6cloud-lstrace [data-testid="defense-tools-compact-guide"] a')
      .first();
    assert.ok((await guideLink.getAttribute('href'))?.includes('aff_sub=psw_guide'));

    // 8. Open Intel exports tab
    await page.getByRole('button', { name: 'Open Intel', exact: true }).click();
    await page.getByText('Confirmed Domain Blocklist (.txt)').waitFor();
    await page.getByText('Structured IOC Feed (.csv)').waitFor();
    await page.getByText('Test-Path -LiteralPath').waitFor();

    const [downloadTxt] = await Promise.all([
      page.waitForEvent('download'),
      page.getByRole('button', { name: /Download \.txt/i }).click(),
    ]);
    assert.equal(downloadTxt.suggestedFilename(), 'portscamwatch-domains.txt');

    // 9. Exposure Triage wizard -> Q1 YES -> aff_sub=psw_triage
    await page.getByRole('button', { name: 'Exposure Triage', exact: true }).click();
    await page.getByRole('button', { name: 'YES', exact: true }).first().click();
    await page.getByText('HIGH LIKELIHOOD OF COMPROMISE').waitFor();
    const triageLink = page.locator('[data-testid="defense-tools-full-triage"] a').first();
    assert.ok((await triageLink.getAttribute('href'))?.includes('aff_sub=psw_triage'));

    // 10. Methodology section
    await page.getByRole('button', { name: 'Methodology', exact: true }).click();
    await page.getByText('Static & Zero-Logging Lookup').waitFor();

    assert.deepEqual(telemetry.consoleErrors, [], `Console errors: ${telemetry.consoleErrors.join('; ')}`);
    assert.deepEqual(telemetry.pageErrors, [], `Page errors: ${telemetry.pageErrors.join('; ')}`);
    assert.deepEqual(
      telemetry.badLocalResponses,
      [],
      `Bad local responses: ${telemetry.badLocalResponses.join('; ')}`,
    );
  } finally {
    await context.close();
  }
}

async function runMobileChecks(browser, baseUrl) {
  const context = await browser.newContext({ viewport: { width: 390, height: 844 } });
  const page = await context.newPage();
  const telemetry = attachTelemetryListeners(page, baseUrl);
  await setupRdapMocks(page);

  try {
    for (const hash of ['', '#triage', '#advisories', '#exports']) {
      await page.goto(`${baseUrl}/${hash}`, { waitUntil: 'networkidle' });
      const overflow = await page.evaluate(() => ({
        scrollWidth: document.documentElement.scrollWidth,
        innerWidth: window.innerWidth,
      }));
      assert.ok(
        overflow.scrollWidth <= overflow.innerWidth,
        `Mobile horizontal overflow on "${hash || '/'}": ${overflow.scrollWidth} > ${overflow.innerWidth}`,
      );
    }

    const inspectBox = await page.goto(baseUrl, { waitUntil: 'networkidle' }).then(() =>
      page.getByRole('button', { name: /Inspect Indicator/i }).boundingBox(),
    );
    assert.ok(inspectBox && inspectBox.height >= 40, 'Mobile Inspect CTA must be >= 40px tall');

    assert.deepEqual(telemetry.consoleErrors, [], `Mobile console errors: ${telemetry.consoleErrors.join('; ')}`);
    assert.deepEqual(telemetry.pageErrors, [], `Mobile page errors: ${telemetry.pageErrors.join('; ')}`);
    assert.deepEqual(telemetry.badLocalResponses, []);
  } finally {
    await context.close();
  }
}

async function main() {
  const securityHeaders = parseAndValidateHeadersFile();
  let serveDir = DIST_DIR;
  let builtTempDir = false;

  if (process.env.VITE_NORDVPN_URL && process.env.VITE_NORDPASS_URL) {
    fs.rmSync(E2E_DIST_DIR, { recursive: true, force: true });
    execSync(`npx vite build --outDir "${E2E_DIST_DIR}"`, {
      cwd: ROOT_DIR,
      stdio: 'pipe',
      env: process.env,
    });
    serveDir = E2E_DIST_DIR;
    builtTempDir = true;
  }

  const { server, baseUrl } = await startDistServer(serveDir, securityHeaders);
  const browser = await chromium.launch({ headless: true });

  try {
    console.log(`Running Playwright E2E checks (Desktop 1440x900 + Mobile 390x844) against ${baseUrl}...`);
    await runDesktopChecks(browser, baseUrl);
    console.log('  ✅ Desktop 1440x900 E2E checks passed (0 console/page/CSP errors).');
    await runMobileChecks(browser, baseUrl);
    console.log('  ✅ Mobile 390x844 E2E checks passed (0 overflow, readable touch targets).');
    console.log('  ✅ dist/_headers CSP, HSTS, X-Frame-Options, and pages.dev noindex verified.');
  } finally {
    await browser.close();
    server.close();
    if (builtTempDir) {
      fs.rmSync(E2E_DIST_DIR, { recursive: true, force: true });
    }
  }
}

main().catch((err) => {
  console.error('❌ E2E suite failed:', err);
  process.exit(1);
});
