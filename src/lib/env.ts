import type { RecommendedToolKey } from '../types/data';

export type ActiveToolKey = Exclude<RecommendedToolKey, 'none'>;

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

const TOOL_CATALOG: Record<ActiveToolKey, Omit<ToolInfo, 'key' | 'url'>> = {
  nordpass: {
    name: 'NordPass',
    shortLabel: 'Rotate Logins in NordPass',
    actionLabel: 'Open NordPass',
    category: 'Credential & Breach Scanner',
    description:
      'Zero-knowledge password manager & Data Breach Scanner for rotating stolen logins/sessions after infostealer exposure.',
  },
  nordvpn: {
    name: 'NordVPN',
    shortLabel: 'Block Scam Domains (NordVPN)',
    actionLabel: 'Open NordVPN',
    category: 'Phishing & Download Shield',
    description:
      'Real-time phishing/scam domain blocker & automatic malicious download scanning via Next-gen antivirus / Threat Protection.',
  },
  malwarebytes: {
    name: 'Malwarebytes',
    shortLabel: 'Run Malwarebytes Scan',
    actionLabel: 'Open Malwarebytes',
    category: 'Infostealer & Adware Removal',
    description: 'Deep Windows & Android infostealer/adware remediation scan.',
  },
  bitdefender: {
    name: 'Bitdefender',
    shortLabel: 'Enable Bitdefender Shield',
    actionLabel: 'Open Bitdefender',
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
  envOverride?: Record<string, string | undefined>,
): ToolInfo | null {
  if (!key || key === 'none') return null;
  if (!(key in TOOL_CATALOG)) return null;

  const activeKey = key as ActiveToolKey;
  const url = isValidHttpsUrl(readRawEnvValue(TOOL_ENV_KEY[activeKey], envOverride));
  if (!url) return null;

  const meta = TOOL_CATALOG[activeKey];
  return {
    key: activeKey,
    ...meta,
    url,
  };
}

export function getConfiguredTools(
  envOverride?: Record<string, string | undefined>,
): ToolInfo[] {
  return TOOL_ORDER.map((key) => getToolInfo(key, envOverride)).filter(
    (tool): tool is ToolInfo => tool !== null,
  );
}
