import type { RecommendedToolKey } from '../types/data';

export type ActiveToolKey = Exclude<RecommendedToolKey, 'none'>;
export type AffiliatePlacement = 'verdict' | 'homepage' | 'guide' | 'triage';

export interface ToolInfo {
  key: ActiveToolKey;
  name: string;
  shortLabel: string;
  actionLabel: string;
  category: string;
  description: string;
  url: string;
}

const DEFAULT_SITE_DOMAIN = 'portscamwatch.com';

const NORD_TRACKING_HOSTS = new Set(['go.nordvpn.net', 'go.nordpass.io']);

const TOOL_CATALOG: Record<ActiveToolKey, Omit<ToolInfo, 'key' | 'url'>> = {
  nordpass: {
    name: 'NordPass',
    shortLabel: 'Rotate Compromised Passwords & Isolate Vault',
    actionLabel: 'Rotate Compromised Passwords & Isolate Vault',
    category: 'Credential & Breach Scanner',
    description:
      'Infostealers like Vidar and ClickFix Rust payloads extract browser-saved credentials; move logins out of browser stores and monitor breach exposure.',
  },
  nordvpn: {
    name: 'NordVPN',
    shortLabel: 'Block Phishing Domains & Scan Downloads',
    actionLabel: 'Block Phishing Domains & Scan Downloads',
    category: 'Phishing & Download Shield',
    description:
      'Threat Protection Pro blocks newly registered scam domains and scans downloaded binaries before execution, even without an active VPN tunnel.',
  },
  malwarebytes: {
    name: 'Malwarebytes',
    shortLabel: 'Run Malwarebytes Scan',
    actionLabel: 'Run Deep Infostealer & Adware Scan',
    category: 'Infostealer & Adware Removal',
    description: 'Deep Windows & Android infostealer/adware remediation scan.',
  },
  bitdefender: {
    name: 'Bitdefender',
    shortLabel: 'Enable Bitdefender Shield',
    actionLabel: 'Enable ClickFix & Script-Shield Protection',
    category: 'ClickFix & Script Protection',
    description:
      'Real-time ClickFix, script-shield & behavioral infostealer protection.',
  },
};

const TOOL_ENV_KEY: Record<ActiveToolKey, string> = {
  nordpass: 'VITE_NORDPASS_URL',
  nordvpn: 'VITE_NORDVPN_URL',
  malwarebytes: 'VITE_MALWAREBYTES_URL',
  bitdefender: 'VITE_BITDEFENDER_URL',
};

const TOOL_ORDER: ActiveToolKey[] = ['nordpass', 'nordvpn', 'malwarebytes', 'bitdefender'];

function readEnvString(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

export function isValidHttpsUrl(value: unknown): string | undefined {
  const trimmed = readEnvString(value);
  if (!trimmed) return undefined;
  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol === 'https:') {
      return trimmed;
    }
    return undefined;
  } catch {
    return undefined;
  }
}

/**
 * Validates strict https:// URLs and injects per-placement aff_sub attribution
 * on Nord partner tracking hosts while preserving existing query parameters.
 */
export function buildAffiliateUrl(
  rawUrl: unknown,
  placement: AffiliatePlacement,
): string | null {
  const valid = isValidHttpsUrl(rawUrl);
  if (!valid) return null;

  const parsed = new URL(valid);
  if (NORD_TRACKING_HOSTS.has(parsed.hostname.toLowerCase())) {
    parsed.searchParams.set('aff_sub', `psw_${placement}`);
  }
  return parsed.toString();
}

function readRawEnvValue(
  envKey: string,
  envOverride?: Record<string, string | undefined>,
): unknown {
  if (envOverride) {
    return envOverride[envKey];
  }
  switch (envKey) {
    case 'VITE_NORDPASS_URL':
      return import.meta.env.VITE_NORDPASS_URL;
    case 'VITE_NORDVPN_URL':
      return import.meta.env.VITE_NORDVPN_URL;
    case 'VITE_MALWAREBYTES_URL':
      return import.meta.env.VITE_MALWAREBYTES_URL;
    case 'VITE_BITDEFENDER_URL':
      return import.meta.env.VITE_BITDEFENDER_URL;
    default:
      return undefined;
  }
}

export function getSiteDomain(metaFallback?: string): string {
  const fromEnv = readEnvString(import.meta.env.VITE_SITE_DOMAIN);
  if (fromEnv) return fromEnv;
  const fromMeta = readEnvString(metaFallback);
  return fromMeta ?? DEFAULT_SITE_DOMAIN;
}

export function getToolInfo(
  key: RecommendedToolKey | string | null | undefined,
  placement: AffiliatePlacement = 'triage',
  envOverride?: Record<string, string | undefined>,
): ToolInfo | null {
  if (!key || key === 'none') return null;
  if (!(key in TOOL_CATALOG)) return null;

  const activeKey = key as ActiveToolKey;
  const url = buildAffiliateUrl(
    readRawEnvValue(TOOL_ENV_KEY[activeKey], envOverride),
    placement,
  );
  if (!url) return null;

  const meta = TOOL_CATALOG[activeKey];
  return {
    key: activeKey,
    ...meta,
    url,
  };
}

export function getConfiguredTools(
  placement: AffiliatePlacement = 'homepage',
  envOverride?: Record<string, string | undefined>,
): ToolInfo[] {
  return TOOL_ORDER.map((key) => getToolInfo(key, placement, envOverride)).filter(
    (tool): tool is ToolInfo => tool !== null,
  );
}
