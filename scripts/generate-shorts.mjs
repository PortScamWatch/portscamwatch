import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import ffmpegPath from 'ffmpeg-static';
import { chromium } from 'playwright';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.resolve(__dirname, '..');
const DIST_DIR = path.join(ROOT_DIR, 'dist');
const SHORTS_DIR = path.join(ROOT_DIR, 'launch-assets/shorts');
const TMP_WEBM_DIR = path.join(os.tmpdir(), 'portscamwatch-shorts-webm');

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

const EXPLORER_DEMO_HTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Windows File Explorer</title>
  <style>
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: #141820;
      color: #e2e8f0;
      font-family: "Segoe UI", system-ui, sans-serif;
      font-size: 13px;
      user-select: none;
    }
    .win-chrome {
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      background: #181c24;
    }
    .titlebar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 10px 14px;
      background: #10141c;
      border-bottom: 1px solid #262d3b;
      font-weight: 600;
      font-size: 13px;
    }
    .toolbar {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 8px 12px;
      background: #1c222e;
      border-bottom: 1px solid #2a3242;
      position: relative;
    }
    .tb-btn {
      background: #252d3d;
      border: 1px solid #334155;
      color: #f1f5f9;
      border-radius: 6px;
      padding: 6px 12px;
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
    }
    .tb-btn.active {
      border-color: #38bdf8;
      background: #0f2942;
      color: #7dd3fc;
    }
    .menu-dropdown {
      position: absolute;
      top: 44px;
      left: 12px;
      width: 220px;
      background: #1e2533;
      border: 1px solid #334155;
      border-radius: 8px;
      padding: 6px;
      box-shadow: 0 12px 30px rgba(0, 0, 0, 0.65);
      display: none;
      z-index: 50;
    }
    .menu-dropdown.open { display: block; }
    .menu-item {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 8px 10px;
      border-radius: 5px;
      font-size: 12px;
      color: #cbd5e1;
    }
    .menu-item.highlight {
      background: #2a3447;
      color: #ffffff;
    }
    .submenu {
      position: absolute;
      top: 108px;
      left: 176px;
      width: 184px;
      background: #1e2533;
      border: 1px solid #38bdf8;
      border-radius: 8px;
      padding: 6px;
      box-shadow: 0 12px 30px rgba(0, 0, 0, 0.75);
      display: none;
      z-index: 60;
    }
    .submenu.open { display: block; }
    .check-pill {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      margin-left: auto;
      font-size: 11px;
      padding: 4px 10px;
      border-radius: 999px;
      background: #0f172a;
      border: 1px solid #334155;
      color: #94a3b8;
    }
    .check-pill.on {
      border-color: #38bdf8;
      color: #7dd3fc;
      background: rgba(56, 189, 248, 0.12);
    }
    .addr-bar {
      padding: 10px 12px;
      background: #141820;
      border-bottom: 1px solid #262d3b;
    }
    .addr-input {
      width: 100%;
      background: #0b0f17;
      border: 1px solid #334155;
      border-radius: 6px;
      padding: 8px 10px;
      color: #f8fafc;
      font-family: Consolas, monospace;
      font-size: 12px;
      outline: none;
    }
    .addr-input:focus {
      border-color: #38bdf8;
    }
    .file-list {
      padding: 10px 12px;
      display: flex;
      flex-direction: column;
      gap: 6px;
    }
    .file-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 9px 10px;
      border-radius: 6px;
      border: 1px solid #232b3a;
      background: #11161f;
      font-family: Consolas, monospace;
      font-size: 12px;
    }
    .file-row.hidden-item {
      opacity: 0.42;
      display: none;
    }
    body.show-hidden .file-row.hidden-item {
      display: flex;
      opacity: 0.96;
    }
    .file-row.danger-row {
      border-color: rgba(239, 68, 68, 0.7);
      background: rgba(127, 29, 29, 0.25);
    }
    .badge-danger {
      background: #dc2626;
      color: #ffffff;
      font-weight: 700;
      font-size: 10px;
      padding: 3px 8px;
      border-radius: 4px;
      letter-spacing: 0.04em;
    }
    .meta-size {
      color: #64748b;
      font-size: 11px;
    }
  </style>
</head>
<body>
  <div class="win-chrome">
    <div class="titlebar">
      <span>File Explorer — Read-Only Inspection</span>
      <span style="color:#64748b;font-family:Consolas,monospace;font-size:11px;">Windows 11</span>
    </div>

    <div class="toolbar">
      <button id="btnView" class="tb-btn" type="button">View ▾</button>
      <span id="hiddenPill" class="check-pill">Hidden items: OFF</span>

      <div id="viewMenu" class="menu-dropdown">
        <div class="menu-item"><span>List</span><span>Ctrl+Shift+5</span></div>
        <div class="menu-item"><span>Details</span><span>Ctrl+Shift+6</span></div>
        <div id="menuShow" class="menu-item highlight"><span>Show</span><span>▸</span></div>
      </div>

      <div id="showSubmenu" class="submenu">
        <div class="menu-item"><span>File name extensions</span><span id="extTick">✓</span></div>
        <div id="menuHiddenItems" class="menu-item highlight">
          <span>Hidden items</span><span id="hiddenTick"></span>
        </div>
      </div>
    </div>

    <div class="addr-bar">
      <input id="explorerAddr" class="addr-input" type="text" value="This PC > Local Disk (C:)" aria-label="Explorer address bar" />
    </div>

    <div id="fileList" class="file-list">
      <div class="file-row"><span>Users</span><span class="meta-size">Folder</span></div>
      <div class="file-row"><span>Windows</span><span class="meta-size">Folder</span></div>
      <div class="file-row"><span>Program Files</span><span class="meta-size">Folder</span></div>
      <div class="file-row hidden-item"><span>ProgramData</span><span class="meta-size">Hidden folder</span></div>
    </div>
  </div>

  <script>
    const btnView = document.getElementById('btnView');
    const viewMenu = document.getElementById('viewMenu');
    const menuShow = document.getElementById('menuShow');
    const showSubmenu = document.getElementById('showSubmenu');
    const menuHiddenItems = document.getElementById('menuHiddenItems');
    const hiddenTick = document.getElementById('hiddenTick');
    const hiddenPill = document.getElementById('hiddenPill');
    const addr = document.getElementById('explorerAddr');
    const fileList = document.getElementById('fileList');

    btnView.addEventListener('click', () => {
      viewMenu.classList.toggle('open');
      btnView.classList.toggle('active');
    });

    menuShow.addEventListener('mouseenter', () => showSubmenu.classList.add('open'));
    menuShow.addEventListener('click', () => showSubmenu.classList.add('open'));

    menuHiddenItems.addEventListener('click', () => {
      document.body.classList.add('show-hidden');
      hiddenTick.textContent = '✓';
      hiddenPill.textContent = 'Hidden items: ON';
      hiddenPill.classList.add('on');
      viewMenu.classList.remove('open');
      showSubmenu.classList.remove('open');
      btnView.classList.remove('active');
    });

    addr.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && addr.value.toLowerCase().includes('temp')) {
        fileList.innerHTML = [
          '<div class="file-row"><span>aria-debug-4192.log</span><span class="meta-size">12 KB</span></div>',
          '<div class="file-row hidden-item"><span>GTA6Cloud</span><span class="meta-size">Hidden folder</span></div>',
          '<div id="lsTraceRow" class="file-row hidden-item danger-row"><span>ls_trace.txt</span><span class="badge-danger">DO NOT OPEN</span></div>',
          '<div class="file-row"><span>msedge_installer.log</span><span class="meta-size">48 KB</span></div>',
        ].join('');
      }
    });
  </script>
</body>
</html>`;

function startStaticServer() {
  return new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      const reqPath = (req.url || '/').split('?')[0];
      if (reqPath === '/__explorer-demo.html') {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(EXPLORER_DEMO_HTML);
        return;
      }

      const relPath = reqPath === '/' ? 'index.html' : reqPath.replace(/^\/+/, '');
      let filePath = path.join(DIST_DIR, relPath);
      if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
        filePath = path.join(DIST_DIR, 'index.html');
      }

      const ext = path.extname(filePath).toLowerCase();
      res.writeHead(200, {
        'Content-Type': MIME_TYPES[ext] || 'application/octet-stream',
      });
      fs.createReadStream(filePath).pipe(res);
    });

    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      resolve({ server, baseUrl: `http://127.0.0.1:${address.port}` });
    });
  });
}

function getOverlayInitScript() {
  return () => {
    const ensureUi = () => {
      if (!document.body) return null;
      let root = document.getElementById('__psw-video-overlay');
      if (root) return root;

      root = document.createElement('div');
      root.id = '__psw-video-overlay';
      root.style.cssText =
        'position:fixed;inset:0;pointer-events:none;z-index:2147483647;';

      const caption = document.createElement('div');
      caption.id = '__psw-caption';
      caption.style.cssText = [
        'position:fixed',
        'left:18px',
        'right:52px',
        'bottom:136px',
        'padding:10px 14px',
        'border-radius:12px',
        'background:rgba(11,15,23,0.92)',
        'border:1.5px solid rgba(56,189,248,0.55)',
        'box-shadow:0 10px 28px rgba(0,0,0,0.65)',
        'color:#f8fafc',
        'font-family:"Segoe UI",system-ui,sans-serif',
        'font-size:17px',
        'font-weight:700',
        'line-height:1.25',
        'text-align:center',
        'letter-spacing:-0.01em',
        'opacity:0',
        'transition:opacity 180ms ease',
      ].join(';');

      const cursor = document.createElement('div');
      cursor.id = '__psw-cursor';
      cursor.style.cssText = [
        'position:fixed',
        'left:216px',
        'top:320px',
        'width:18px',
        'height:18px',
        'margin-left:-9px',
        'margin-top:-9px',
        'border-radius:50%',
        'background:rgba(248,250,252,0.95)',
        'border:2.5px solid #38bdf8',
        'box-shadow:0 0 0 4px rgba(56,189,248,0.22)',
        'transition:left 360ms cubic-bezier(0.22,1,0.36,1), top 360ms cubic-bezier(0.22,1,0.36,1), transform 120ms ease',
        'opacity:0',
      ].join(';');

      root.appendChild(caption);
      root.appendChild(cursor);
      document.body.appendChild(root);
      return root;
    };

    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', ensureUi);
    } else {
      ensureUi();
    }

    window.__pswUi = {
      setCaption(text, tone = 'default') {
        ensureUi();
        const el = document.getElementById('__psw-caption');
        if (!el) return;
        if (!text) {
          el.style.opacity = '0';
          return;
        }
        if (tone === 'alert') {
          el.style.borderColor = 'rgba(239,68,68,0.8)';
          el.style.color = '#fef2f2';
        } else if (tone === 'warn') {
          el.style.borderColor = 'rgba(245,158,11,0.8)';
          el.style.color = '#fef3c7';
        } else {
          el.style.borderColor = 'rgba(56,189,248,0.65)';
          el.style.color = '#f8fafc';
        }
        el.textContent = text;
        el.style.opacity = '1';
      },
      moveCursor(x, y) {
        ensureUi();
        const el = document.getElementById('__psw-cursor');
        if (!el) return;
        el.style.opacity = '1';
        el.style.left = `${x}px`;
        el.style.top = `${y}px`;
      },
      pulseClick() {
        const el = document.getElementById('__psw-cursor');
        if (!el) return;
        el.style.transform = 'scale(0.76)';
        setTimeout(() => {
          el.style.transform = 'scale(1)';
        }, 140);
      },
      smoothScrollTo(targetY, durationMs = 900) {
        return new Promise((resolve) => {
          const startY = window.scrollY;
          const delta = targetY - startY;
          const start = performance.now();
          const step = (now) => {
            const p = Math.min(1, (now - start) / durationMs);
            const eased = p < 0.5 ? 2 * p * p : 1 - Math.pow(-2 * p + 2, 2) / 2;
            window.scrollTo(0, startY + delta * eased);
            if (p < 1) requestAnimationFrame(step);
            else resolve();
          };
          requestAnimationFrame(step);
        });
      },
    };
  };
}

async function moveCursorToLocator(page, locator) {
  const box = await locator.boundingBox();
  if (!box) return;
  const cx = Math.round(box.x + box.width / 2);
  const cy = Math.round(box.y + box.height / 2);
  await page.evaluate(({ x, y }) => window.__pswUi?.moveCursor(x, y), { x: cx, y: cy });
  await page.waitForTimeout(380);
}

async function clickWithCursor(page, locator) {
  await locator.scrollIntoViewIfNeeded();
  await page.waitForTimeout(180);
  await moveCursorToLocator(page, locator);
  await page.evaluate(() => window.__pswUi?.pulseClick());
  await locator.click();
  await page.waitForTimeout(160);
}

async function typeHuman(page, locator, text, delayMs = 72) {
  await clickWithCursor(page, locator);
  await locator.fill('');
  await locator.pressSequentially(text, { delay: delayMs });
}

async function setCaption(page, text, tone = 'default') {
  await page.evaluate(({ t, tn }) => window.__pswUi?.setCaption(t, tn), { t: text, tn: tone });
}

async function smoothScroll(page, targetY, durationMs = 1000) {
  await page.evaluate(
    ({ y, d }) => window.__pswUi?.smoothScrollTo(y, d),
    { y: targetY, d: durationMs },
  );
  await page.waitForTimeout(durationMs + 80);
}

async function setupRdapRoute(page) {
  await page.route('https://rdap.org/domain/**', async (route) => {
    const url = route.request().url().toLowerCase();
    if (url.endsWith('/gta6download.club')) {
      await route.fulfill({
        status: 200,
        contentType: 'application/rdap+json',
        body: JSON.stringify({
          events: [{ eventAction: 'registration', eventDate: '2026-11-12T00:00:00Z' }],
        }),
      });
      return;
    }
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
    await route.fulfill({ status: 404, contentType: 'application/json', body: '{}' });
  });
}

async function recordScenario(browser, baseUrl, filename, scenarioFn) {
  fs.mkdirSync(TMP_WEBM_DIR, { recursive: true });
  const context = await browser.newContext({
    viewport: { width: 432, height: 768 },
    deviceScaleFactor: 1,
    recordVideo: {
      dir: TMP_WEBM_DIR,
      size: { width: 432, height: 768 },
    },
  });

  let webmPath = null;
  try {
    const page = await context.newPage();
    await page.addInitScript(getOverlayInitScript());
    await setupRdapRoute(page);

    await scenarioFn(page, baseUrl);
    const video = page.video();
    await context.close();
    webmPath = await video.path();
  } catch (err) {
    try {
      await context.close();
    } catch {
      // ignore close error
    }
    throw err;
  }

  const outMp4 = path.join(SHORTS_DIR, filename);
  execFileSync(
    ffmpegPath,
    [
      '-y',
      '-i',
      webmPath,
      '-c:v',
      'libx264',
      '-pix_fmt',
      'yuv420p',
      '-r',
      '30',
      '-vf',
      'scale=1080:1920:flags=lanczos',
      '-movflags',
      '+faststart',
      '-an',
      outMp4,
    ],
    { stdio: 'pipe' },
  );

  try {
    fs.rmSync(webmPath, { force: true });
  } catch {
    // ignore temp cleanup lock
  }
  return probeMp4(outMp4);
}

function probeMp4(mp4Path) {
  let stderr = '';
  try {
    execFileSync(ffmpegPath, ['-i', mp4Path], { stdio: ['ignore', 'pipe', 'pipe'] });
  } catch (err) {
    stderr = err.stderr ? err.stderr.toString('utf-8') : '';
  }

  const durMatch = stderr.match(/Duration:\s*(\d+):(\d+):(\d+(?:\.\d+)?)/);
  const resMatch = stderr.match(/Video:.*?(\d{3,4}x\d{3,4})/);
  const durationSeconds = durMatch
    ? Number(durMatch[1]) * 3600 + Number(durMatch[2]) * 60 + Number(durMatch[3])
    : 0;
  const stat = fs.statSync(mp4Path);

  return {
    file: path.basename(mp4Path),
    path: mp4Path,
    resolution: resMatch ? resMatch[1] : 'unknown',
    durationSeconds: Number(durationSeconds.toFixed(1)),
    sizeBytes: stat.size,
  };
}

// ---------------------------------------------------------------------------
// 5 Short Scenarios
// ---------------------------------------------------------------------------
async function short01(page, baseUrl) {
  await page.goto(baseUrl, { waitUntil: 'networkidle' });
  const input = page.locator('input[aria-label*="Suspicious URL"]');
  const submitBtn = page.getByRole('button', { name: /Inspect Indicator/i });

  // Beat 1 (0-2.5s)
  await setCaption(page, 'Downloaded GTA6Cloud.exe?', 'alert');
  await clickWithCursor(page, input);
  await page.waitForTimeout(900);

  // Beat 2 (2.5-7s)
  await setCaption(page, 'Confirmed Rust infostealer.', 'alert');
  await typeHuman(page, input, 'GTA6Cloud.exe', 70);
  await clickWithCursor(page, submitBtn);
  await page.getByText('MATCHED IN VENDOR ADVISORIES').waitFor({ timeout: 5000 });
  await page.waitForTimeout(1000);

  // Beat 3 (7-15s)
  await setCaption(page, 'Steals cookies, Steam, crypto, API keys.', 'warn');
  await smoothScroll(page, 460, 1100);
  await page.waitForTimeout(1500);
  await smoothScroll(page, 720, 1000);
  await page.waitForTimeout(1300);

  // Beat 4 (15-20s)
  await setCaption(page, 'Verify first at portscamwatch.com', 'default');
  await smoothScroll(page, 240, 800);
  await page.waitForTimeout(800);
  await smoothScroll(page, 0, 700);
  const clearBtn = page.getByRole('button', { name: /^Clear$/i });
  await clickWithCursor(page, clearBtn);
  await page.waitForTimeout(700);
}

async function short02(page, baseUrl) {
  await page.goto(baseUrl, { waitUntil: 'networkidle' });
  const input = page.locator('input[aria-label*="Suspicious URL"]');
  const submitBtn = page.getByRole('button', { name: /Inspect Indicator/i });

  // Beat 1 (0-3s)
  await setCaption(page, '800+ fake GTA 6 domains weekly.', 'warn');
  await typeHuman(page, input, 'gta6download.club', 68);
  await clickWithCursor(page, submitBtn);

  // Beat 2 (3-9s)
  await setCaption(page, 'Flagged by Netcraft. Check RDAP age.', 'alert');
  await page.getByText('MATCHED IN VENDOR ADVISORIES').waitFor({ timeout: 5000 });
  await smoothScroll(page, 210, 650);
  await page.waitForTimeout(1600);

  // Beat 3 (9-16s)
  await smoothScroll(page, 0, 500);
  await setCaption(page, 'Established domain. Not in threat lists.', 'default');
  await clickWithCursor(page, page.getByRole('button', { name: /^Clear$/i }));
  await typeHuman(page, input, 'rockstargames.com', 68);
  await clickWithCursor(page, submitBtn);
  await page.getByText('ESTABLISHED DOMAIN — NOT IN THREAT LISTS').waitFor({ timeout: 5000 });
  await smoothScroll(page, 210, 600);
  await page.waitForTimeout(1400);

  // Beat 4 (16-24s)
  await smoothScroll(page, 0, 500);
  await setCaption(page, 'Free RDAP check: portscamwatch.com', 'default');
  await clickWithCursor(page, page.getByRole('button', { name: /^Clear$/i }));
  await typeHuman(page, input, 'random-unlisted-port.exe', 65);
  await clickWithCursor(page, submitBtn);
  await page.getByText('NOT FOUND IN VENDOR ADVISORIES').waitFor({ timeout: 5000 });
  await smoothScroll(page, 210, 600);
  await page.waitForTimeout(1400);
}

async function short03(page, baseUrl) {
  await page.goto(`${baseUrl}/__explorer-demo.html`, { waitUntil: 'networkidle' });

  // Beat 1 (0-4s)
  await setCaption(page, 'Turn on Hidden Items first.', 'default');
  await clickWithCursor(page, page.locator('#btnView'));
  await page.waitForTimeout(300);
  await clickWithCursor(page, page.locator('#menuShow'));
  await page.waitForTimeout(300);
  await clickWithCursor(page, page.locator('#menuHiddenItems'));
  await page.waitForTimeout(700);

  // Beat 2 (4-11s)
  await setCaption(page, 'Look for ls_trace.txt (do not open).', 'alert');
  const addr = page.locator('#explorerAddr');
  await typeHuman(page, addr, '%LOCALAPPDATA%\\Temp', 70);
  await addr.press('Enter');
  await page.locator('#lsTraceRow').waitFor({ timeout: 3000 });
  await moveCursorToLocator(page, page.locator('#lsTraceRow'));
  await page.waitForTimeout(2800);

  // Beat 3 (11-17s)
  await page.goto(`${baseUrl}/#triage`, { waitUntil: 'networkidle' });
  await setCaption(page, 'Found it? Disconnect Wi-Fi immediately.', 'alert');
  const q2Prompt = page.getByText(/IconCacheToDelete/i).first();
  await q2Prompt.scrollIntoViewIfNeeded();
  await smoothScroll(page, 290, 800);
  const yesButtons = page.getByRole('button', { name: 'YES', exact: true });
  await clickWithCursor(page, yesButtons.nth(1));
  await page.waitForTimeout(2000);

  // Beat 4 (17-22s)
  await setCaption(page, '5-step checklist at portscamwatch.com', 'warn');
  await smoothScroll(page, 940, 1200);
  await page.waitForTimeout(2600);
}

async function short04(page, baseUrl) {
  await page.goto(baseUrl, { waitUntil: 'networkidle' });
  const input = page.locator('input[aria-label*="Suspicious URL"]');
  const submitBtn = page.getByRole('button', { name: /Inspect Indicator/i });
  const hash = 'a8f19d598e6a49d8510d73d41fc445246755ed321c2f76985a463a9fef537eb0';

  // Beat 1 (0-3s)
  await setCaption(page, 'A 1.1 MB GTA 6 installer?', 'warn');
  await clickWithCursor(page, input);
  await input.fill(hash);
  await page.waitForTimeout(900);
  await clickWithCursor(page, submitBtn);

  // Beat 2 (3-8s)
  await setCaption(page, 'Confirmed Vidar infostealer.', 'alert');
  await page.getByText('MATCHED IN VENDOR ADVISORIES').waitFor({ timeout: 5000 });
  await smoothScroll(page, 240, 800);
  await page.waitForTimeout(2200);

  // Beat 3 (8-15s)
  await setCaption(page, 'Spawns headless browsers to steal cookies.', 'alert');
  await smoothScroll(page, 560, 1100);
  await page.waitForTimeout(2000);
  await smoothScroll(page, 760, 1000);
  await page.waitForTimeout(1800);

  // Beat 4 (15-20s)
  await setCaption(page, 'Check hashes at portscamwatch.com', 'default');
  await smoothScroll(page, 0, 850);
  await clickWithCursor(page, page.getByRole('button', { name: /^Clear$/i }));
  await page.waitForTimeout(1400);
}

async function short05(page, baseUrl) {
  await page.goto(baseUrl, { waitUntil: 'networkidle' });
  const input = page.locator('input[aria-label*="Suspicious URL"]');
  const submitBtn = page.getByRole('button', { name: /Inspect Indicator/i });

  // Beat 1 (0-3s)
  await setCaption(page, 'GTA 6 keygen or mobile APK?', 'warn');
  await typeHuman(page, input, 'GTA6 Keygen.exe', 70);
  await clickWithCursor(page, submitBtn);

  // Beat 2 (3-8s)
  await setCaption(page, 'Cookie stealer, XMRig, wallet drainer.', 'alert');
  await page.getByText('MATCHED IN VENDOR ADVISORIES').waitFor({ timeout: 5000 });
  await smoothScroll(page, 260, 750);
  await page.waitForTimeout(1600);

  // Beat 3 (8-15s)
  await smoothScroll(page, 0, 600);
  await setCaption(page, 'Fake Android APK: 1,700+ uploads.', 'alert');
  await clickWithCursor(page, page.getByRole('button', { name: /^Clear$/i }));
  await typeHuman(page, input, 'com.gta6.apkrate', 68);
  await clickWithCursor(page, submitBtn);
  await page.getByText('MATCHED IN VENDOR ADVISORIES').waitFor({ timeout: 5000 });
  await smoothScroll(page, 280, 750);
  await page.waitForTimeout(1500);

  // Beat 4 (15-20s)
  await setCaption(page, 'Free triage tool: portscamwatch.com', 'default');
  await smoothScroll(page, 0, 550);
  await clickWithCursor(page, page.getByRole('button', { name: 'Exposure Triage', exact: true }));
  await page.waitForTimeout(1800);
}

function updatePreviewHtmlWithShorts(shortsMeta) {
  const previewPath = path.join(ROOT_DIR, 'launch-assets/PREVIEW_ALL.html');
  if (!fs.existsSync(previewPath)) return;

  let html = fs.readFileSync(previewPath, 'utf-8');
  // Remove any previously injected shorts section
  html = html.replace(/<!-- SHORTS_SECTION_START -->[\s\S]*?<!-- SHORTS_SECTION_END -->\s*/g, '');

  const shortsBlock = `<!-- SHORTS_SECTION_START -->
  <h2>5. Silent Shorts (1080x1920 MP4)</h2>
  <div class="strip-tiktok">
    ${shortsMeta
      .map(
        (s) => `
    <div class="card">
      <video src="shorts/${s.file}" controls muted loop playsinline style="width:100%;border-radius:6px;border:1px solid #1e293b;background:#000;display:block;"></video>
      <div class="meta">${s.file} (${s.resolution} · ${s.durationSeconds}s · ${(s.sizeBytes / 1024).toFixed(0)} KB)</div>
    </div>`,
      )
      .join('')}
  </div>
  <!-- SHORTS_SECTION_END -->\n\n`;

  html = html.replace('<script>', `${shortsBlock}  <script>`);
  fs.writeFileSync(previewPath, html, 'utf-8');
}

async function main() {
  if (!fs.existsSync(path.join(DIST_DIR, 'index.html'))) {
    throw new Error('dist/index.html not found. Run "npm run build" first.');
  }

  fs.mkdirSync(SHORTS_DIR, { recursive: true });
  fs.rmSync(TMP_WEBM_DIR, { recursive: true, force: true });

  const { server, baseUrl } = await startStaticServer();
  const browser = await chromium.launch({ headless: true });

  const scenarios = [
    ['short-01-gta6cloud-clickfix.mp4', short01],
    ['short-02-live-rdap-check.mp4', short02],
    ['short-03-readonly-ls-trace.mp4', short03],
    ['short-04-vidar-hash-check.mp4', short04],
    ['short-05-keygen-and-apk.mp4', short05],
  ];

  const results = [];
  try {
    for (const [filename, fn] of scenarios) {
      console.log(`Recording ${filename}...`);
      const meta = await recordScenario(browser, baseUrl, filename, fn);
      results.push(meta);
      console.log(
        `  -> ${meta.file}: ${meta.resolution}, ${meta.durationSeconds}s, ${(meta.sizeBytes / 1024).toFixed(1)} KB`,
      );
    }
  } finally {
    await browser.close();
    server.close();
    try {
      fs.rmSync(TMP_WEBM_DIR, { recursive: true, force: true });
    } catch {
      // ignore temp cleanup lock
    }
  }

  updatePreviewHtmlWithShorts(results);
  console.log('\nUpdated launch-assets/PREVIEW_ALL.html with Silent Shorts players.');
  console.table(
    results.map((r) => ({
      File: r.file,
      Resolution: r.resolution,
      Duration: `${r.durationSeconds}s`,
      Size: `${(r.sizeBytes / 1024).toFixed(1)} KB`,
    })),
  );
}

main().catch((err) => {
  console.error('generate-shorts failed:', err);
  process.exit(1);
});
