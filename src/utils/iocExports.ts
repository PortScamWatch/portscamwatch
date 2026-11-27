import { extractDomainParts, isKnownEstablishedDomain } from '../lib/rdap';
import type { ThreatEntry, ThreatsData, ThreatsMeta } from '../types/data';
import { normalizeIndicator } from './normalizeInput';

const VENDOR_SAFE_DOMAINS = new Set([
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
  'portscamwatch.com',
]);

function isVendorOrSafeDomain(hostname: string): boolean {
  for (const safe of VENDOR_SAFE_DOMAINS) {
    if (hostname === safe || hostname.endsWith(`.${safe}`)) {
      return true;
    }
  }
  return false;
}

export function classifyIndicatorType(indicator: string): string {
  const norm = normalizeIndicator(indicator);
  if (/^[a-f0-9]{64}$/i.test(norm)) return 'sha256';
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(norm)) return 'ipv4';
  if (/^(com|org|net|io)\.[a-z0-9._-]+$/i.test(norm)) return 'android_package';
  if (extractDomainParts(norm) !== null) return 'domain';
  if (/\.(exe|msi|zip|rar|7z|iso|bat|cmd|ps1|dll|apk|txt|lnk)$/i.test(norm)) {
    return 'filename';
  }
  return 'other';
}

export function extractMaliciousDomains(threats: ThreatEntry[]): string[] {
  const seen = new Set<string>();
  for (const threat of threats) {
    for (const rawInd of threat.indicators) {
      const parts = extractDomainParts(rawInd);
      if (!parts) continue;
      if (isKnownEstablishedDomain(parts)) continue;
      if (isVendorOrSafeDomain(parts.hostname)) continue;
      seen.add(parts.hostname);
    }
  }
  return Array.from(seen).sort();
}

export function buildDomainBlocklistTxt(threats: ThreatEntry[], meta: ThreatsMeta): string {
  const domains = extractMaliciousDomains(threats);
  const header = [
    '# PortScamWatch Confirmed Malicious Domain Blocklist (Pi-hole / AdGuard / hosts)',
    `# Source: https://${meta.siteDomain || 'portscamwatch.com'}/data/threats.json`,
    `# Advisories: ${threats.length} | Domains: ${domains.length}`,
    `# Last Verified UTC: ${meta.lastVerifiedUtc}`,
    '# Notice: Strictly derived from published vendor advisories; excludes benign/vendor domains.',
    '',
  ];
  const entries = domains.map((domain) => `0.0.0.0 ${domain}`);
  return `${[...header, ...entries].join('\n')}\n`;
}

export function escapeCsvField(value: string): string {
  const str = String(value);
  if (/[",\r\n]/.test(str)) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

export function buildIocCsv(threats: ThreatEntry[]): string {
  const rows = ['indicator,type,campaign,vendor,advisory_date,source_url'];
  const seen = new Set<string>();

  for (const threat of threats) {
    for (const rawInd of threat.indicators) {
      const norm = normalizeIndicator(rawInd);
      if (!norm || seen.has(norm)) continue;
      seen.add(norm);

      rows.push(
        [
          norm,
          classifyIndicatorType(norm),
          threat.title,
          threat.vendorName,
          threat.advisoryDate,
          threat.advisoryUrl,
        ]
          .map(escapeCsvField)
          .join(','),
      );
    }
  }

  return `${rows.join('\n')}\n`;
}

export function buildThreatsExportJson(data: ThreatsData): string {
  return `${JSON.stringify(data, null, 2)}\n`;
}

export function buildReadOnlyPowerShellCheck(): string {
  return [
    '# PortScamWatch Read-Only Artifact Check (Test-Path only — zero writes, zero downloads)',
    '# Review every line before pasting into PowerShell.',
    '$paths = @(',
    '  "$env:LOCALAPPDATA\\Temp\\ls_trace.txt",',
    '  "$env:LOCALAPPDATA\\GTA6Cloud",',
    '  "$env:LOCALAPPDATA\\Microsoft\\Windows\\Explorer\\IconCacheToDelete\\0a3f2c91"',
    ')',
    'foreach ($p in $paths) {',
    '  $exists = Test-Path -LiteralPath $p',
    '  [PSCustomObject]@{ Path = $p; Found = $exists }',
    '}',
    'Get-ItemProperty "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" -ErrorAction SilentlyContinue',
  ].join('\n');
}
