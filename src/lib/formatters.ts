const MONTHS_SHORT = [
  'Jan',
  'Feb',
  'Mar',
  'Apr',
  'May',
  'Jun',
  'Jul',
  'Aug',
  'Sep',
  'Oct',
  'Nov',
  'Dec',
];

/**
 * Formats an ISO-8601 UTC timestamp into a concise clinical label,
 * e.g. "Nov 25, 2026 · 19:52 UTC".
 */
export function formatUtcTimestamp(isoString: string): string {
  const date = new Date(isoString);
  if (Number.isNaN(date.getTime())) {
    return isoString;
  }

  const month = MONTHS_SHORT[date.getUTCMonth()];
  const day = date.getUTCDate();
  const year = date.getUTCFullYear();
  const hh = String(date.getUTCHours()).padStart(2, '0');
  const mm = String(date.getUTCMinutes()).padStart(2, '0');

  return `${month} ${day}, ${year} · ${hh}:${mm} UTC`;
}

export function formatReleaseStatus(status: string, platforms: string[]): string {
  if (status === 'UNRELEASED_CONSOLE_ONLY') {
    return `None (${platforms.join(' & ')} Only)`;
  }
  return status;
}

export function formatDomainAge(ageDays: number): string {
  if (ageDays < 30) {
    return `${ageDays} day${ageDays === 1 ? '' : 's'} old`;
  }
  if (ageDays < 365) {
    const months = Math.floor(ageDays / 30);
    return `${months} month${months === 1 ? '' : 's'} old (${ageDays} days)`;
  }
  const years = Math.floor(ageDays / 365);
  return `${years}+ year${years === 1 ? '' : 's'} old (${ageDays.toLocaleString('en-US')} days)`;
}

/**
 * Formats raw triage outcome badges cleanly for display (zero snake_case underscores).
 */
export function formatOutcomeBadge(badge: string): string {
  if (badge === 'UNVERIFIED_HIGH_RISK') {
    return 'UNVERIFIED · HIGH RISK';
  }
  return badge.replace(/_/g, ' ').trim();
}

/**
 * Shortens long SHA-256 hashes or long strings for compact table chip previews.
 */
export function truncateIndicator(indicator: string, maxLength = 28): string {
  if (indicator.length <= maxLength) return indicator;
  if (/^[a-f0-9]{40,128}$/i.test(indicator)) {
    return `${indicator.slice(0, 10)}…${indicator.slice(-8)}`;
  }
  return `${indicator.slice(0, maxLength - 1)}…`;
}
