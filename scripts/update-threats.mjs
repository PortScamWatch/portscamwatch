import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import {
  isAllowedVendorUrl,
  isProtectedDomain,
  normalizeIndicator,
} from './lib/constants.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.resolve(__dirname, '..');
const THREATS_PATH = path.join(ROOT_DIR, 'public/data/threats.json');
const VALIDATOR_PATH = path.join(__dirname, 'validate-data.mjs');

const FEED_TIMEOUT_MS = 10_000;
const ARTICLE_TIMEOUT_MS = 10_000;
const MAX_ARTICLES_PER_RUN = 3;
const MAX_ARTICLE_CHARS = 14_000;

export const VENDOR_FEEDS = [
  {
    vendorName: 'Bitdefender Labs',
    url: 'https://www.bitdefender.com/nuxt/api/en-us/rss/labs/',
  },
  {
    vendorName: 'Bitdefender',
    url: 'https://www.bitdefender.com/blog/api/rss/hotforsecurity/',
  },
  {
    vendorName: 'Malwarebytes',
    url: 'https://www.malwarebytes.com/blog/feed/index.xml',
  },
  {
    vendorName: 'Darktrace',
    url: 'https://www.darktrace.com/blog/rss.xml',
  },
  {
    vendorName: 'ESET',
    url: 'https://www.welivesecurity.com/en/rss/feed/',
  },
  {
    vendorName: 'BleepingComputer',
    url: 'https://www.bleepingcomputer.com/feed/',
  },
];

function decodeXmlEntities(str) {
  return str
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;|&apos;/g, "'")
    .replace(/&#(\d+);/g, (_, num) => String.fromCharCode(Number(num)))
    .replace(/&#x([0-9a-f]+);/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
}

function extractTagValue(xmlChunk, tagNames) {
  for (const tag of tagNames) {
    const escaped = tag.replace(':', '\\:');
    const re = new RegExp(`<${escaped}[^>]*>([\\s\\S]*?)<\\/${escaped}>`, 'i');
    const match = xmlChunk.match(re);
    if (match && match[1]) {
      return decodeXmlEntities(match[1]).trim();
    }
  }
  return '';
}

function extractLink(xmlChunk) {
  const textLink = extractTagValue(xmlChunk, ['link']);
  if (textLink && /^https?:\/\//i.test(textLink)) {
    return textLink;
  }
  const atomHref =
    xmlChunk.match(/<link[^>]+rel=["']alternate["'][^>]+href=["']([^"']+)["'][^>]*\/?>/i) ||
    xmlChunk.match(/<link[^>]+href=["']([^"']+)["'][^>]+rel=["']alternate["'][^>]*\/?>/i) ||
    xmlChunk.match(/<link[^>]+href=["']([^"']+)["'][^>]*\/?>/i);
  if (atomHref && atomHref[1]) {
    return decodeXmlEntities(atomHref[1]).trim();
  }
  return '';
}

export function parseFeedItems(xmlText, vendorName) {
  const items = [];
  const blockRegex = /<(item|entry)\b[^>]*>([\s\S]*?)<\/\1>/gi;
  let match;
  while ((match = blockRegex.exec(xmlText)) !== null) {
    const block = match[2];
    const title = extractTagValue(block, ['title']);
    const link = extractLink(block);
    const pubDate = extractTagValue(block, ['pubDate', 'published', 'updated', 'dc:date']);
    const description = extractTagValue(block, [
      'content:encoded',
      'description',
      'summary',
      'content',
    ]);

    if (title && link) {
      items.push({ vendorName, title, link, pubDate, description });
    }
  }
  return items;
}

export function stripHtmlToPlainText(html, maxChars = MAX_ARTICLE_CHARS) {
  const plain = decodeXmlEntities(
    String(html ?? '')
      .replace(/<script\b[\s\S]*?<\/script>/gi, ' ')
      .replace(/<style\b[\s\S]*?<\/style>/gi, ' ')
      .replace(/<noscript\b[\s\S]*?<\/noscript>/gi, ' ')
      .replace(/<svg\b[\s\S]*?<\/svg>/gi, ' ')
      .replace(/<\/(p|div|li|h[1-6]|tr|br)>/gi, '\n')
      .replace(/<[^>]+>/g, ' '),
  )
    .replace(/[ \t]+/g, ' ')
    .replace(/\n{3,}/g, '\n\n')
    .trim();

  return Number.isFinite(maxChars) ? plain.slice(0, maxChars) : plain;
}

export function matchesGta6Topic(title, description = '') {
  const text = stripHtmlToPlainText(`${title ?? ''}\n${description ?? ''}`, Infinity);
  const directMatch =
    /\b(?:gta[\s:-]*(?:6|vi)|grand\s+theft\s+auto[\s:-]*(?:6|vi)|leonida|gta6cloud)\b/i.test(
      text,
    );
  const clickFixGtaMatch = /\bclickfix\b/i.test(text) && /\bgta\b/i.test(text);
  return directMatch || clickFixGtaMatch;
}

function normalizeUrlForDedup(rawUrl) {
  try {
    const u = new URL(rawUrl.trim());
    return `${u.hostname.toLowerCase().replace(/^www\./, '')}${u.pathname.replace(/\/+$/, '')}`;
  } catch {
    return rawUrl.trim().toLowerCase().replace(/\/+$/, '');
  }
}

async function fetchWithTimeout(url, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, {
      signal: controller.signal,
      headers: {
        'User-Agent': 'PortScamWatch-ThreatScout/1.0 (+https://portscamwatch.com)',
        Accept: 'application/rss+xml, application/atom+xml, application/xml, text/html, */*',
      },
    });
  } finally {
    clearTimeout(timer);
  }
}

async function fetchFeedResult(feed) {
  const startedAt = Date.now();
  try {
    const res = await fetchWithTimeout(feed.url, FEED_TIMEOUT_MS);
    const elapsedMs = Date.now() - startedAt;
    if (!res.ok) {
      return {
        feed,
        httpOk: false,
        status: res.status,
        items: [],
        elapsedMs,
        error: `HTTP ${res.status}`,
      };
    }
    const xml = await res.text();
    const items = parseFeedItems(xml, feed.vendorName);
    return {
      feed,
      httpOk: true,
      status: res.status,
      items,
      elapsedMs,
      error: items.length === 0 ? 'HTTP 200 but 0 <item>/<entry> blocks parsed' : null,
    };
  } catch (err) {
    return {
      feed,
      httpOk: false,
      status: null,
      items: [],
      elapsedMs: Date.now() - startedAt,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

function defangIndicator(indicator) {
  const trimmed = indicator.trim();
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(trimmed)) {
    return trimmed.replace(/\./g, '[.]');
  }
  const lower = trimmed.toLowerCase();
  if (/^[a-f0-9]{32,128}$/i.test(trimmed)) {
    return trimmed.toUpperCase();
  }
  // Defang domain names (excluding file extensions like .exe, .zip, .apk, .dll, .txt)
  if (
    /^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(lower) &&
    !/\.(exe|zip|apk|dll|txt|msi|ps1|bat|cmd|lnk|js|vbs|pdf|iso|rar|7z)$/i.test(lower)
  ) {
    return trimmed.replace(/\./g, '[.]');
  }
  return trimmed;
}

function formatAdvisoryDate(pubDate) {
  if (pubDate) {
    const d = new Date(pubDate);
    if (!Number.isNaN(d.getTime())) {
      return d.toISOString().slice(0, 10);
    }
  }
  return new Date().toISOString().slice(0, 10);
}

function buildUniqueId(vendorName, title, advisoryDate, seenIds) {
  const baseSlug = `${vendorName}-${title}-${advisoryDate}`
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 64);
  let candidate = baseSlug || `advisory-${advisoryDate}`;
  let suffix = 2;
  while (seenIds.has(candidate)) {
    candidate = `${baseSlug.slice(0, 58)}-${suffix}`;
    suffix += 1;
  }
  return candidate;
}

/**
 * Prevents no-op timestamp commits by updating `meta.lastVerifiedUtc`
 * only when at least one new verified threat advisory was appended.
 */
export function finalizeThreatsUpdate(
  threatsData,
  appendedCount,
  nowIso = new Date().toISOString(),
) {
  if (appendedCount <= 0) {
    return { shouldWrite: false, data: threatsData };
  }
  const cleanUtc = nowIso.replace(/\.\d{3}Z$/, 'Z');
  return {
    shouldWrite: true,
    data: {
      ...threatsData,
      meta: {
        ...threatsData.meta,
        lastVerifiedUtc: cleanUtc,
      },
    },
  };
}

async function extractThreatWithGemini(candidate, plainText) {
  const apiKey = process.env.GEMINI_API_KEY;
  const model = process.env.GEMINI_MODEL || 'gemini-3.5-flash-lite';
  const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent`;

  const prompt = `You are a cybersecurity threat-intelligence extractor for PortScamWatch.com.
Analyze the security vendor article below and determine whether it contains explicit, concrete, vendor-published Indicators of Compromise (IOCs) such as malicious domains, IP addresses, installer filenames, Android package names, or SHA-256 hashes targeting GTA 6 / GTA VI fake ports, ClickFix lures, keygens, or wallet drainers.

RULES:
1. ONLY extract IOCs explicitly stated as malicious/lure indicators in the article. NEVER invent IOCs.
2. NEVER include legitimate domains (google.com, youtube.com, rockstargames.com, take2games.com, github.com, microsoft.com, steampowered.com, epicgames.com, playstation.com, xbox.com, cloudflare.com, portscamwatch.com) in indicators[].
3. If the article only discusses general news, rumors, or advice WITHOUT concrete IOCs targeting GTA 6 / GTA VI, return ONLY:
{"skip": true, "reason": "short explanation"}
4. Otherwise return ONLY a single JSON object matching this exact schema:
{
  "skip": false,
  "title": "Concise campaign title",
  "severity": "CRITICAL" | "HIGH",
  "malwareFamily": "Malware family or threat type",
  "lureType": "Fake Cloud Client" | "Fake PC Demo" | "Keygen" | "Fake APK" | "Crypto Drainer" | "ClickFix",
  "indicators": ["lowercase domain, filename, package name, or sha256"],
  "targetedData": ["list of targeted credentials/assets"],
  "hostArtifacts": ["observed host paths, registry keys, or process behaviors"],
  "summary": "2-3 factual sentences summarizing the vendor report."
}

Vendor: ${candidate.vendorName}
Article Title: ${candidate.title}
Article URL: ${candidate.link}
Published: ${candidate.pubDate || 'Unknown'}

Article Text:
${plainText}`;

  const res = await fetch(endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-goog-api-key': apiKey,
    },
    body: JSON.stringify({
      contents: [{ role: 'user', parts: [{ text: prompt }] }],
      generationConfig: {
        responseMimeType: 'application/json',
      },
    }),
  });

  if (!res.ok) {
    const errBody = await res.text().catch(() => '');
    throw new Error(`Gemini API HTTP ${res.status}: ${errBody.slice(0, 240)}`);
  }

  const data = await res.json();
  const rawText = data?.candidates?.[0]?.content?.parts?.[0]?.text;
  if (!rawText) {
    throw new Error('Gemini API returned empty content');
  }

  const cleaned = rawText
    .trim()
    .replace(/^```json\s*/i, '')
    .replace(/```$/i, '')
    .trim();
  return JSON.parse(cleaned);
}

async function main() {
  const isCheckFeeds = process.argv.includes('--check-feeds');
  const isDryRun = process.argv.includes('--dry-run');
  const originalRaw = fs.readFileSync(THREATS_PATH, 'utf-8');
  const threatsData = JSON.parse(originalRaw);

  const existingAdvisoryUrls = new Set(
    threatsData.threats.map((t) => normalizeUrlForDedup(t.advisoryUrl)),
  );
  const existingIds = new Set(threatsData.threats.map((t) => t.id));
  const existingIndicators = new Set();
  for (const threat of threatsData.threats) {
    for (const ind of threat.indicators || []) {
      existingIndicators.add(normalizeIndicator(ind));
    }
  }

  const feedResults = await Promise.all(VENDOR_FEEDS.map(fetchFeedResult));

  let healthyFeeds = 0;
  let reachableFeeds = 0;
  const candidates = [];
  const seenCandidateUrls = new Set();

  for (const result of feedResults) {
    const { feed, httpOk, status, items, elapsedMs, error } = result;
    if (httpOk) {
      reachableFeeds += 1;
    }

    let feedNewMatches = 0;
    for (const item of items) {
      if (!isAllowedVendorUrl(item.link)) continue;
      const normLink = normalizeUrlForDedup(item.link);
      if (existingAdvisoryUrls.has(normLink) || seenCandidateUrls.has(normLink)) {
        continue;
      }
      if (matchesGta6Topic(item.title, item.description)) {
        seenCandidateUrls.add(normLink);
        candidates.push(item);
        feedNewMatches += 1;
      }
    }

    const isHealthy = httpOk && items.length > 0;
    if (isHealthy) {
      healthyFeeds += 1;
    }

    if (isCheckFeeds) {
      if (isHealthy) {
        console.log(
          `[scout] CHECK OK | ${feed.vendorName} | HTTP ${status} | ${items.length} items | ${feedNewMatches} new GTA 6 candidate(s) | ${elapsedMs}ms`,
        );
      } else {
        console.error(
          `[scout] CHECK FAIL | ${feed.vendorName} | ${error || 'unknown error'} | ${elapsedMs}ms`,
        );
      }
    } else if (!httpOk) {
      console.warn(`[scout] Feed ${feed.vendorName} failed gracefully (${error}); skipping.`);
    } else {
      console.log(`[scout] ${feed.vendorName}: parsed ${items.length} feed items.`);
    }
  }

  if (isCheckFeeds) {
    console.log(
      `[scout] --check-feeds summary: ${healthyFeeds}/${VENDOR_FEEDS.length} feeds reachable with >0 parsed items (${candidates.length} new GTA 6 candidate(s)). Skipped Gemini and disk writes.`,
    );
    if (healthyFeeds !== VENDOR_FEEDS.length) {
      process.exitCode = 1;
    }
    return;
  }

  const cappedCandidates = candidates.slice(0, MAX_ARTICLES_PER_RUN);
  console.log(
    `[scout] Feeds reachable: ${reachableFeeds}/${VENDOR_FEEDS.length}. New GTA 6 candidates: ${cappedCandidates.length}.`,
  );

  let appendedCount = 0;
  const apiKey = process.env.GEMINI_API_KEY?.trim();

  if (!apiKey) {
    console.log(
      '[scout] GEMINI_API_KEY is not set; skipping LLM IOC extraction cleanly (dry-run safe mode).',
    );
  } else if (cappedCandidates.length > 0) {
    for (const candidate of cappedCandidates) {
      try {
        console.log(`[scout] Inspecting candidate: ${candidate.title} (${candidate.link})`);
        const articleRes = await fetchWithTimeout(candidate.link, ARTICLE_TIMEOUT_MS);
        if (!articleRes.ok) {
          console.warn(`[scout] Candidate fetch HTTP ${articleRes.status}; skipping.`);
          continue;
        }
        const html = await articleRes.text();
        const plainText = stripHtmlToPlainText(html);
        const extracted = await extractThreatWithGemini(candidate, plainText);

        if (!extracted || extracted.skip) {
          console.log(
            `[scout] Skipped candidate (${extracted?.reason || 'no concrete IOCs'}).`,
          );
          continue;
        }

        if (!isAllowedVendorUrl(candidate.link)) {
          console.warn(`[scout] Rejected non-allowlisted URL: ${candidate.link}`);
          continue;
        }

        const rawIndicators = Array.isArray(extracted.indicators) ? extracted.indicators : [];
        const cleanIndicators = [];
        const cleanDisplayIndicators = [];
        const batchSeen = new Set();

        for (const rawInd of rawIndicators) {
          if (typeof rawInd !== 'string') continue;
          const norm = normalizeIndicator(rawInd);
          if (norm.length < 4) continue;
          if (isProtectedDomain(norm)) continue;
          if (existingIndicators.has(norm) || batchSeen.has(norm)) continue;

          batchSeen.add(norm);
          cleanIndicators.push(norm);
          cleanDisplayIndicators.push(defangIndicator(rawInd));
        }

        if (cleanIndicators.length === 0) {
          console.log(
            '[scout] Skipped candidate after deterministic IOC filtering (0 valid new IOCs).',
          );
          continue;
        }

        const advisoryDate = formatAdvisoryDate(candidate.pubDate);
        const newEntry = {
          id: buildUniqueId(
            candidate.vendorName,
            extracted.title || candidate.title,
            advisoryDate,
            existingIds,
          ),
          title: String(extracted.title || candidate.title).trim(),
          severity: extracted.severity === 'HIGH' ? 'HIGH' : 'CRITICAL',
          malwareFamily: String(extracted.malwareFamily || 'Infostealer / Fake Port Lure').trim(),
          lureType: String(extracted.lureType || 'Fake PC Demo').trim(),
          displayIndicators: cleanDisplayIndicators,
          indicators: cleanIndicators,
          targetedData:
            Array.isArray(extracted.targetedData) && extracted.targetedData.length > 0
              ? extracted.targetedData.map((s) => String(s).trim()).filter(Boolean)
              : ['Browser credentials & session cookies'],
          hostArtifacts:
            Array.isArray(extracted.hostArtifacts) && extracted.hostArtifacts.length > 0
              ? extracted.hostArtifacts.map((s) => String(s).trim()).filter(Boolean)
              : cleanDisplayIndicators.slice(0, 3),
          summary: String(extracted.summary || candidate.title).trim(),
          vendorName: candidate.vendorName,
          advisoryDate,
          advisoryUrl: candidate.link,
        };

        threatsData.threats.push(newEntry);
        existingIds.add(newEntry.id);
        for (const norm of cleanIndicators) {
          existingIndicators.add(norm);
        }
        appendedCount += 1;
        console.log(
          `[scout] Appended new advisory: ${newEntry.id} (${cleanIndicators.length} IOCs)`,
        );
      } catch (err) {
        console.warn(
          `[scout] Error processing candidate "${candidate.link}": ${err instanceof Error ? err.message : String(err)}`,
        );
      }
    }
  }

  const finalized = finalizeThreatsUpdate(threatsData, appendedCount);
  if (!finalized.shouldWrite) {
    console.log(
      '[scout] No new verified threat advisories appended (0 added); leaving public/data/threats.json untouched.',
    );
    return;
  }

  if (isDryRun) {
    console.log(
      `[scout] --dry-run enabled: skipping disk write (${appendedCount} candidate(s) would have been appended).`,
    );
    return;
  }

  const nextRaw = `${JSON.stringify(finalized.data, null, 2)}\n`;
  fs.writeFileSync(THREATS_PATH, nextRaw, 'utf-8');

  try {
    execFileSync(process.execPath, [VALIDATOR_PATH], { stdio: 'inherit' });
    console.log(`[scout] Completed cleanly. Appended ${appendedCount} new threat advisory(ies).`);
  } catch {
    console.error('[scout] Validation failed after update; reverting public/data/threats.json.');
    fs.writeFileSync(THREATS_PATH, originalRaw, 'utf-8');
    process.exit(1);
  }
}

let isDirectRun = false;
try {
  isDirectRun =
    Boolean(process.argv[1]) &&
    pathToFileURL(fs.realpathSync(process.argv[1])).href === import.meta.url;
} catch {
  isDirectRun = false;
}

if (isDirectRun) {
  main().catch((err) => {
    console.error('[scout] Fatal error:', err);
    process.exit(1);
  });
}
