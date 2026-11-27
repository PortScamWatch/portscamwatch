import type { RdapDomainInfo } from '../types/data';
import { normalizeIndicator } from '../utils/normalizeInput';

export const KNOWN_ESTABLISHED_DOMAINS = [
  'rockstargames.com',
  'take2games.com',
  'store.steampowered.com',
  'epicgames.com',
  'playstation.com',
  'xbox.com',
  'google.com',
  'youtube.com',
  'github.com',
  'microsoft.com',
] as const;

const FILE_EXTENSIONS = new Set([
  'exe',
  'msi',
  'zip',
  'rar',
  '7z',
  'iso',
  'bat',
  'cmd',
  'ps1',
  'vbs',
  'js',
  'lnk',
  'dll',
  'txt',
  'pdf',
  'bin',
  'dmg',
  'apk',
  'scr',
]);

const TWO_LABEL_SUFFIXES = new Set([
  'co.uk',
  'org.uk',
  'ac.uk',
  'com.au',
  'net.au',
  'co.jp',
  'com.br',
  'co.nz',
  'co.in',
  'com.mx',
]);

export interface DomainParts {
  hostname: string;
  registrableDomain: string;
}

/**
 * Extracts hostname and registrable domain if the input represents a URL or domain.
 * Returns null for filenames (.exe, .zip, etc.), Windows paths, or hashes.
 */
export function extractDomainParts(rawInput: string): DomainParts | null {
  const trimmed = rawInput.trim();
  if (!trimmed || /\s/.test(trimmed)) return null;

  // Reject Windows paths, environment variables, and hex hashes
  if (
    trimmed.includes('\\') ||
    trimmed.includes('%') ||
    /^[a-z]:/i.test(trimmed) ||
    /^[a-f0-9]{32,128}$/i.test(trimmed)
  ) {
    return null;
  }

  const cleaned = normalizeIndicator(trimmed);
  const authority = cleaned.split(/[/?#]/)[0]?.trim() ?? '';
  const hostname = authority.replace(/:\d+$/, '');

  if (!hostname || hostname.length > 253) return null;
  if (!/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(hostname)) return null;

  const labels = hostname.split('.');
  const tld = labels[labels.length - 1] ?? '';
  if (!/^[a-z]{2,24}$/.test(tld) || FILE_EXTENSIONS.has(tld)) {
    return null;
  }

  let registrableDomain = hostname;
  if (labels.length >= 3) {
    const lastTwo = `${labels[labels.length - 2]}.${tld}`;
    registrableDomain = TWO_LABEL_SUFFIXES.has(lastTwo)
      ? labels.slice(-3).join('.')
      : lastTwo;
  }

  return { hostname, registrableDomain };
}

export function isKnownEstablishedDomain(parts: DomainParts | null): boolean {
  if (!parts) return false;
  return KNOWN_ESTABLISHED_DOMAINS.some(
    (allowed) =>
      parts.hostname === allowed ||
      parts.hostname.endsWith(`.${allowed}`) ||
      parts.registrableDomain === allowed,
  );
}

interface RdapEvent {
  eventAction?: string;
  eventDate?: string;
}

interface RdapResponse {
  events?: RdapEvent[];
}

export async function fetchRdapDomainInfo(
  registrableDomain: string,
  timeoutMs = 3000,
): Promise<RdapDomainInfo> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(
      `https://rdap.org/domain/${encodeURIComponent(registrableDomain)}`,
      {
        signal: controller.signal,
        headers: {
          Accept: 'application/rdap+json, application/json',
        },
      },
    );

    if (!res.ok) {
      return {
        domain: registrableDomain,
        status: 'unavailable',
        registeredDateIso: null,
        registeredYear: null,
        ageDays: null,
      };
    }

    const payload = (await res.json()) as RdapResponse;
    const regEvent = payload.events?.find((ev) =>
      (ev.eventAction ?? '').toLowerCase().includes('registration'),
    );

    if (!regEvent?.eventDate) {
      return {
        domain: registrableDomain,
        status: 'unavailable',
        registeredDateIso: null,
        registeredYear: null,
        ageDays: null,
      };
    }

    const parsed = new Date(regEvent.eventDate);
    if (Number.isNaN(parsed.getTime())) {
      return {
        domain: registrableDomain,
        status: 'unavailable',
        registeredDateIso: null,
        registeredYear: null,
        ageDays: null,
      };
    }

    const ageDays = Math.max(0, Math.floor((Date.now() - parsed.getTime()) / 86_400_000));

    return {
      domain: registrableDomain,
      status: 'ok',
      registeredDateIso: parsed.toISOString(),
      registeredYear: parsed.getUTCFullYear(),
      ageDays,
    };
  } catch {
    return {
      domain: registrableDomain,
      status: 'unavailable',
      registeredDateIso: null,
      registeredYear: null,
      ageDays: null,
    };
  } finally {
    clearTimeout(timer);
  }
}
