import type { RecommendedToolKey } from '../types/data';

export interface ToolInfo {
  key: Exclude<RecommendedToolKey, 'none'>;
  name: string;
  actionLabel: string;
  url: string;
  category: string;
}

type ActiveToolKey = Exclude<RecommendedToolKey, 'none'>;

const DEFAULT_SITE_DOMAIN = 'portscamwatch.com';

const TOOL_FALLBACKS: Record<
  ActiveToolKey,
  Omit<ToolInfo, 'key' | 'url'> & { fallbackUrl: string }
> = {
  malwarebytes: {
    name: 'Malwarebytes',
    actionLabel: 'Scan with Malwarebytes',
    category: 'On-Demand Infostealer Removal',
    fallbackUrl: 'https://www.malwarebytes.com/',
  },
  bitdefender: {
    name: 'Bitdefender',
    actionLabel: 'Protect with Bitdefender',
    category: 'Real-Time Endpoint Protection',
    fallbackUrl: 'https://www.bitdefender.com/',
  },
  nordvpn: {
    name: 'NordVPN',
    actionLabel: 'Secure Traffic with NordVPN',
    category: 'Threat & Malicious Domain Blocking',
    fallbackUrl: 'https://nordvpn.com/',
  },
  nordpass: {
    name: 'NordPass',
    actionLabel: 'Rotate Passwords in NordPass',
    category: 'Credential & Password Rotation',
    fallbackUrl: 'https://nordpass.com/',
  },
};

function readEnvString(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

export function getSiteDomain(metaFallback?: string): string {
  const fromEnv = readEnvString(import.meta.env.VITE_SITE_DOMAIN);
  if (fromEnv) return fromEnv;
  const fromMeta = readEnvString(metaFallback);
  return fromMeta ?? DEFAULT_SITE_DOMAIN;
}

export function getToolInfo(key: RecommendedToolKey | string | null | undefined): ToolInfo | null {
  if (!key || key === 'none') return null;
  if (!(key in TOOL_FALLBACKS)) return null;

  const activeKey = key as ActiveToolKey;
  const meta = TOOL_FALLBACKS[activeKey];
  let envUrl: string | undefined;

  switch (activeKey) {
    case 'malwarebytes':
      envUrl = readEnvString(import.meta.env.VITE_MALWAREBYTES_URL);
      break;
    case 'bitdefender':
      envUrl = readEnvString(import.meta.env.VITE_BITDEFENDER_URL);
      break;
    case 'nordvpn':
      envUrl = readEnvString(import.meta.env.VITE_NORDVPN_URL);
      break;
    case 'nordpass':
      envUrl = readEnvString(import.meta.env.VITE_NORDPASS_URL);
      break;
  }

  return {
    key: activeKey,
    name: meta.name,
    actionLabel: meta.actionLabel,
    category: meta.category,
    url: envUrl ?? meta.fallbackUrl,
  };
}

export function getAllTools(): ToolInfo[] {
  return (['malwarebytes', 'bitdefender', 'nordpass', 'nordvpn'] as ActiveToolKey[])
    .map((key) => getToolInfo(key))
    .filter((tool): tool is ToolInfo => tool !== null);
}
