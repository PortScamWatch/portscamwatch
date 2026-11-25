export const ALLOWED_VENDOR_DOMAINS = [
  'bitdefender.com',
  'malwarebytes.com',
  'darktrace.com',
  'welivesecurity.com',
  'eset.com',
  'mcafee.com',
  'netcraft.com',
  'cynet.com',
  'huntress.com',
  'techradar.com',
  'bleepingcomputer.com',
  'kaspersky.com',
  'securelist.com',
];

export const PROTECTED_DOMAIN_BLOCKLIST = [
  'google.com',
  'youtube.com',
  'rockstargames.com',
  'take2games.com',
  'github.com',
  'microsoft.com',
  'steampowered.com',
  'store.steampowered.com',
  'epicgames.com',
  'playstation.com',
  'xbox.com',
  'cloudflare.com',
  'portscamwatch.com',
];

export function normalizeIndicator(raw) {
  return String(raw)
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/^www\./, '')
    .replace(/\[\.\]/g, '.')
    .replace(/\/+$/, '');
}

export function extractHostnameFromCandidate(raw) {
  const normalized = normalizeIndicator(raw);
  if (!normalized || normalized.includes('\\') || normalized.includes(' ')) {
    return null;
  }
  const hostPart = normalized.split(/[/?#]/)[0]?.replace(/:\d+$/, '') ?? '';
  if (!hostPart.includes('.')) return null;
  return hostPart;
}

export function isProtectedDomain(rawIndicator) {
  const normalized = normalizeIndicator(rawIndicator);
  const host = extractHostnameFromCandidate(normalized);

  return PROTECTED_DOMAIN_BLOCKLIST.some((blocked) => {
    if (normalized === blocked) return true;
    if (!host) return false;
    return host === blocked || host.endsWith(`.${blocked}`);
  });
}

export function isAllowedVendorUrl(rawUrl) {
  try {
    const parsed = new URL(rawUrl);
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
      return false;
    }
    const host = parsed.hostname.toLowerCase();
    return ALLOWED_VENDOR_DOMAINS.some(
      (allowed) => host === allowed || host.endsWith(`.${allowed}`),
    );
  } catch {
    return false;
  }
}
