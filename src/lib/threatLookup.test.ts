import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import {
  buildAffiliateUrl,
  getConfiguredTools,
  getSiteDomain,
  getToolInfo,
  isValidHttpsUrl,
} from '../config/env';
import { formatOutcomeBadge, formatUtcTimestamp, truncateIndicator } from './formatters';
import { extractDomainParts } from './rdap';
import {
  computeTriageOutcomeKey,
  countTrackedIocs,
  lookupThreat,
} from './threatLookup';
import type { DisclaimersData, RdapDomainInfo, ThreatsData, TriageTreeData } from '../types/data';
import {
  buildNativeHashCommands,
  computeBufferSha256,
  computeFileSha256,
  MAX_BROWSER_HASH_BYTES,
} from '../utils/fileHash';
import {
  buildDomainBlocklistTxt,
  buildIocCsv,
  buildReadOnlyPowerShellCheck,
  buildThreatsExportJson,
  extractMaliciousDomains,
} from '../utils/iocExports';
import { inspectNormalizedInput, normalizeIndicator } from '../utils/normalizeInput';

const ROOT = path.resolve(__dirname, '../..');

function loadJson<T>(relativePath: string): T {
  const fullPath = path.join(ROOT, relativePath);
  return JSON.parse(fs.readFileSync(fullPath, 'utf-8')) as T;
}

function collectFiles(dir: string): string[] {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  const files: string[] = [];
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...collectFiles(full));
    } else {
      files.push(full);
    }
  }
  return files;
}

describe('PortScamWatch unit & integration suite', () => {
  const threatsData = loadJson<ThreatsData>('public/data/threats.json');
  const triageTree = loadJson<TriageTreeData>('public/data/triage-tree.json');
  const disclaimers = loadJson<DisclaimersData>('public/data/disclaimers.json');

  describe('normalizeInput & defanged IOC parsing', () => {
    it('normalizes defanged protocols, dots, www., ports, and trailing slashes', () => {
      expect(normalizeIndicator('  HTTPS://www.velmontriq[.]net/download/  ')).toBe(
        'velmontriq.net/download',
      );
      expect(normalizeIndicator('hxxps://GTA6Download[.]club/setup?ref=1')).toBe(
        'gta6download.club/setup?ref=1',
      );
      expect(normalizeIndicator('GTA6Cloud[.]exe')).toBe('gta6cloud.exe');
      expect(normalizeIndicator('http://gta6demo(.)asia:80///')).toBe('gta6demo.asia');
    });

    it('normalizes uppercase and whitespace-padded SHA-256 hashes', () => {
      const padded =
        '  A8F1 9D59 8E6A 49D8 510D 73D4 1FC4 4524 6755 ED32 1C2F 7698 5A46 3A9F EF53 7EB0  ';
      expect(normalizeIndicator(padded)).toBe(
        'a8f19d598e6a49d8510d73d41fc445246755ed321c2f76985a463a9fef537eb0',
      );
      const details = inspectNormalizedInput('velmontriq[.]net');
      expect(details.wasTransformed).toBe(true);
      expect(details.normalized).toBe('velmontriq.net');
    });

    it('handles XSS strings, unicode, empty strings, and huge inputs safely', () => {
      expect(normalizeIndicator('')).toBe('');
      expect(normalizeIndicator('<script>alert(1)</script>')).toBe('<script>alert(1)</script>');
      expect(normalizeIndicator('  🔥gta6🔥  ')).toBe('🔥gta6🔥');
      const huge = 'a'.repeat(5000);
      expect(normalizeIndicator(huge)).toHaveLength(5000);
      expect(lookupThreat('<script>alert(1)</script>', threatsData.threats).tier).toBe('NOT_LISTED');
    });
  });

  describe('RDAP domain extraction & 3-tier lookup engine', () => {
    it('extracts registrable domains and ignores files, paths, and hashes', () => {
      expect(extractDomainParts('https://store.steampowered.com/app/123')).toEqual({
        hostname: 'store.steampowered.com',
        registrableDomain: 'steampowered.com',
      });
      expect(extractDomainParts('hxxps://GTA6Download[.]club/setup?ref=1')).toEqual({
        hostname: 'gta6download.club',
        registrableDomain: 'gta6download.club',
      });
      expect(extractDomainParts('random-unlisted-port.exe')).toBeNull();
      expect(extractDomainParts('GTA6Cloud[.]exe')).toBeNull();
      expect(extractDomainParts('%LOCALAPPDATA%\\Temp\\GTA6Cloud.exe')).toBeNull();
      expect(
        extractDomainParts('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'),
      ).toBeNull();
    });

    it('matches exact SHA-256 hashes, filenames, domains, and subdomains', () => {
      const hashRes = lookupThreat(
        'A8F19D598E6A49D8510D73D41FC445246755ED321C2F76985A463A9FEF537EB0',
        threatsData.threats,
      );
      expect(hashRes.tier).toBe('CONFIRMED_THREAT');
      expect(hashRes.matches[0]?.vendorName).toBe('Malwarebytes');

      const exeRes = lookupThreat('GTA6Cloud[.]exe', threatsData.threats);
      expect(exeRes.tier).toBe('CONFIRMED_THREAT');

      const subRes = lookupThreat('cdn.velmontriq[.]net', threatsData.threats);
      expect(subRes.tier).toBe('CONFIRMED_THREAT');

      const urlRes = lookupThreat('hxxps://GTA6Download[.]club/setup?ref=1', threatsData.threats);
      expect(urlRes.tier).toBe('CONFIRMED_THREAT');

      const nkrnlRes = lookupThreat('nkrnl[.]cfd', threatsData.threats);
      expect(nkrnlRes.tier).toBe('CONFIRMED_THREAT');
      expect(nkrnlRes.matches[0]?.vendorName).toBe('Bitdefender');
    });

    it('resolves established/benign domains without false positives on lookalikes', () => {
      for (const domain of ['google.com', 'rockstargames.com']) {
        const res = lookupThreat(domain, threatsData.threats);
        expect(res.tier).toBe('ESTABLISHED_DOMAIN');
        expect(res.verdictLabel).toBe('ESTABLISHED DOMAIN — NOT IN THREAT LISTS');
        expect(res.verdictLabel.toUpperCase()).not.toContain('MALICIOUS');
        expect(res.isKnownEstablishedDomain).toBe(true);
        expect(res.matches).toHaveLength(0);
      }

      const lookalike = lookupThreat('contact-rockstargames.com', threatsData.threats);
      expect(lookalike.tier).toBe('CONFIRMED_THREAT');

      const agedRdap: RdapDomainInfo = {
        domain: 'example-old-site.org',
        status: 'ok',
        registeredDateIso: '2018-04-12T00:00:00.000Z',
        registeredYear: 2018,
        ageDays: 3000,
      };
      expect(lookupThreat('example-old-site.org', threatsData.threats, agedRdap).tier).toBe(
        'ESTABLISHED_DOMAIN',
      );
    });

    it('resolves unlisted indicators and newly registered domains cleanly', () => {
      const res = lookupThreat('random-unlisted-port.exe', threatsData.threats);
      expect(res.tier).toBe('NOT_LISTED');
      expect(res.verdictLabel).toBe('NOT FOUND IN VENDOR ADVISORIES');
      expect(res.verdictLabel.toUpperCase()).not.toContain('SAFE');

      const freshRdap: RdapDomainInfo = {
        domain: 'brand-new-lure.xyz',
        status: 'ok',
        registeredDateIso: '2026-11-10T00:00:00.000Z',
        registeredYear: 2026,
        ageDays: 15,
      };
      const freshRes = lookupThreat('brand-new-lure.xyz', threatsData.threats, freshRdap);
      expect(freshRes.tier).toBe('NOT_LISTED');
      expect(freshRes.isNewlyRegisteredDomain).toBe(true);
    });
  });

  describe('client-side SHA-256 fileHash helper', () => {
    it('computes NIST SHA-256 test vectors accurately', async () => {
      expect(await computeBufferSha256(new Uint8Array([]))).toBe(
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      );
      const abc = new TextEncoder().encode('abc');
      expect(await computeBufferSha256(abc)).toBe(
        'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
      );
    });

    it('rejects oversized files (>256 MB) without reading file buffer into RAM', async () => {
      const arrayBufferSpy = vi.fn();
      const fakeGiantFile = {
        name: 'GTA6_100GB_Decoy.iso',
        size: MAX_BROWSER_HASH_BYTES + 1024,
        arrayBuffer: arrayBufferSpy,
      } as unknown as File;

      const result = await computeFileSha256(fakeGiantFile);
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.reason).toBe('OVERSIZED');
        expect(result.message).toContain('256');
      }
      expect(arrayBufferSpy).not.toHaveBeenCalled();

      const cmds = buildNativeHashCommands('fake"file;rm.exe');
      expect(cmds.powershell).toBe('Get-FileHash -Algorithm SHA256 "fakefilerm.exe"');
      expect(cmds.unix).toBe('shasum -a 256 "fakefilerm.exe"');
    });
  });

  describe('IOC exports & read-only PowerShell generator', () => {
    it('generates valid Pi-hole/hosts domain blocklist excluding benign/vendor domains', () => {
      const domains = extractMaliciousDomains(threatsData.threats);
      expect(domains.length).toBeGreaterThan(10);
      expect(domains).toContain('velmontriq.net');
      expect(domains).not.toContain('rockstargames.com');
      expect(domains).not.toContain('google.com');
      expect(domains).not.toContain('bitdefender.com');

      const txt = buildDomainBlocklistTxt(threatsData.threats, threatsData.meta);
      const nonCommentLines = txt
        .split(/\r?\n/)
        .map((l) => l.trim())
        .filter((l) => l && !l.startsWith('#'));

      const seen = new Set<string>();
      for (const line of nonCommentLines) {
        expect(line).toMatch(/^0\.0\.0\.0 [a-z0-9-]+(\.[a-z0-9-]+)+$/);
        const domain = line.replace(/^0\.0\.0\.0 /, '');
        expect(seen.has(domain)).toBe(false);
        seen.add(domain);
      }
    });

    it('builds RFC-4180 escaped CSV, valid JSON, and read-only PowerShell script', () => {
      const csv = buildIocCsv(threatsData.threats);
      const lines = csv.trim().split('\n');
      expect(lines[0]).toBe('indicator,type,campaign,vendor,advisory_date,source_url');
      expect(lines.length).toBeGreaterThan(20);
      // Comma-containing campaign titles must be quoted
      expect(csv).toContain('"');

      const parsedJson = JSON.parse(buildThreatsExportJson(threatsData)) as ThreatsData;
      expect(parsedJson.threats.length).toBe(threatsData.threats.length);

      const ps = buildReadOnlyPowerShellCheck();
      expect(ps).toContain('Test-Path');
      expect(ps).not.toMatch(/\b(Remove-Item|Invoke-WebRequest|Invoke-Expression|iex|curl)\b/i);
    });
  });

  describe('affiliate URL builder, formatting & data contracts', () => {
    it('validates https:// and sets per-placement aff_sub on Nord tracking domains', () => {
      expect(buildAffiliateUrl('http://go.nordvpn.net/aff_c?offer_id=15', 'verdict')).toBeNull();
      expect(buildAffiliateUrl('javascript:alert(1)', 'homepage')).toBeNull();
      expect(buildAffiliateUrl('', 'guide')).toBeNull();

      const vpnUrl = buildAffiliateUrl(
        'https://go.nordvpn.net/aff_c?offer_id=15&aff_id=162042&url_id=902',
        'verdict',
      );
      expect(vpnUrl).toBe(
        'https://go.nordvpn.net/aff_c?offer_id=15&aff_id=162042&url_id=902&aff_sub=psw_verdict',
      );

      const passUrl = buildAffiliateUrl(
        'https://go.nordpass.io/aff_c?offer_id=488&aff_id=162042&url_id=9356',
        'triage',
      );
      expect(passUrl).toBe(
        'https://go.nordpass.io/aff_c?offer_id=488&aff_id=162042&url_id=9356&aff_sub=psw_triage',
      );

      const coveronUrl = buildAffiliateUrl(
        'https://go.coveron.net/aff_c?offer_id=77&aff_id=162042&url_id=555',
        'homepage',
      );
      expect(coveronUrl).toBe(
        'https://go.coveron.net/aff_c?offer_id=77&aff_id=162042&url_id=555&aff_sub=psw_homepage',
      );

      // Non-Nord URLs are preserved unmodified
      expect(buildAffiliateUrl('https://www.malwarebytes.com/?partner=1', 'guide')).toBe(
        'https://www.malwarebytes.com/?partner=1',
      );

      expect(getConfiguredTools('homepage', {})).toEqual([]);
      expect(getToolInfo('nordvpn', 'verdict', {})).toBeNull();
      expect(getToolInfo('coveron', 'verdict', {})).toBeNull();
      expect(isValidHttpsUrl('http://insecure.example.com')).toBeUndefined();

      const configured = getConfiguredTools('guide', {
        VITE_NORDPASS_URL: 'https://go.nordpass.io/aff_c?offer_id=488&aff_id=162042&url_id=9356',
        VITE_NORDVPN_URL: 'https://go.nordvpn.net/aff_c?offer_id=15&aff_id=162042&url_id=902',
        VITE_COVERON_URL: 'https://go.coveron.net/aff_c?offer_id=77&aff_id=162042&url_id=555',
      });
      expect(configured.map((t) => t.key)).toEqual(['nordpass', 'nordvpn', 'coveron']);
      expect(configured[2]?.badgeTag).toBe('(US)');
      expect(configured[0]?.url).toContain('aff_sub=psw_guide');
      expect(configured[1]?.url).toContain('aff_sub=psw_guide');
      expect(configured[2]?.url).toContain('aff_sub=psw_guide');
    });

    it('formats timestamps, badges, and computes triage severity safely', () => {
      expect(formatUtcTimestamp('2026-11-25T19:00:00Z')).toBe('Nov 25, 2026 · 19:00 UTC');
      expect(formatOutcomeBadge('UNVERIFIED_HIGH_RISK')).toBe('UNVERIFIED · HIGH RISK');
      expect(
        truncateIndicator('3A0C4760DEC4FED3E822DB9A630107DA266AAEFFEA8A0CCF506DFAA5847BD922'),
      ).toBe('3A0C4760DE…847BD922');

      expect(triageTree.questions).toHaveLength(5);
      expect(countTrackedIocs(threatsData.threats)).toBeGreaterThan(0);

      const allNo = Object.fromEntries(triageTree.questions.map((q) => [q.id, false]));
      expect(computeTriageOutcomeKey(triageTree.questions, allNo)).toBe('UNVERIFIED_CAUTION');

      const highQ = triageTree.questions.find((q) => q.yesTriggersSeverity === 'HIGH_EXPOSURE');
      const critQ = triageTree.questions.find((q) => q.yesTriggersSeverity === 'CRITICAL_INFECTED');
      expect(
        computeTriageOutcomeKey(triageTree.questions, { ...allNo, [highQ!.id]: true }),
      ).toBe('HIGH_EXPOSURE');
      expect(
        computeTriageOutcomeKey(triageTree.questions, { ...allNo, [critQ!.id]: true }),
      ).toBe('CRITICAL_INFECTED');
    });

    it('enforces zero hardcoded affiliate IDs and clean gitignore hygiene', () => {
      expect(getSiteDomain()).toBe('portscamwatch.com');
      expect(disclaimers.siteName).toBeTruthy();

      const files = [
        ...collectFiles(path.join(ROOT, 'src')),
        ...collectFiles(path.join(ROOT, 'public')),
      ].filter((filePath) => !filePath.endsWith('.test.ts') && !filePath.endsWith('.test.tsx'));

      const affiliatePatterns = [
        /[?&](aff_id|affiliate_id|subid|clickid|partner_id)=/i,
        /162042/,
        /https?:\/\/go\.(nordvpn\.net|nordpass\.io|coveron\.net)/i,
      ];

      for (const file of files) {
        const content = fs.readFileSync(file, 'utf-8');
        for (const pattern of affiliatePatterns) {
          expect(content, `Unexpected hardcoded affiliate pattern in ${file}`).not.toMatch(pattern);
        }
      }

      const gitignore = fs.readFileSync(path.join(ROOT, '.gitignore'), 'utf-8');
      expect(gitignore.split(/\r?\n/)).toContain('.env');
      expect(gitignore.split(/\r?\n/)).toContain('launch-assets/');
    });
  });
});
