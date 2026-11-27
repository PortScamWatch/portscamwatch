export interface NormalizedInputDetails {
  raw: string;
  normalized: string;
  wasTransformed: boolean;
}

/**
 * Normalizes analyst/consumer IOCs:
 * - Trims outer whitespace
 * - Converts defanged schemes (hxxps://, hxxp://) and defanged dots ([.], (.))
 * - Strips protocol (http://, https://) and leading www.
 * - Normalizes whitespace-padded/uppercase 64-char SHA-256 hex strings
 * - Strips trailing slashes and strips default port suffixes (:80 / :443)
 */
export function normalizeIndicator(raw: string): string {
  let cleaned = raw
    .trim()
    .replace(/^hxxps?:\/\//i, (m) => (m.toLowerCase().startsWith('hxxps') ? 'https://' : 'http://'))
    .replace(/\[\.\]/g, '.')
    .replace(/\(\.\)/g, '.');

  const compactHex = cleaned.replace(/\s+/g, '');
  if (/^[a-f0-9]{64}$/i.test(compactHex)) {
    return compactHex.toLowerCase();
  }

  cleaned = cleaned
    .toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/^www\./, '')
    .replace(/\/+$/, '');

  // Strip :80 or :443 only on host authority when there is no Windows path
  if (!cleaned.includes('\\')) {
    cleaned = cleaned.replace(/^([^/?#]+):(?:80|443)(?=$|[/?#])/, '$1');
  }

  return cleaned;
}

export function inspectNormalizedInput(raw: string): NormalizedInputDetails {
  const trimmed = raw.trim();
  const normalized = normalizeIndicator(raw);
  const wasTransformed = trimmed.length > 0 && normalized !== trimmed;

  return {
    raw: trimmed,
    normalized,
    wasTransformed,
  };
}
