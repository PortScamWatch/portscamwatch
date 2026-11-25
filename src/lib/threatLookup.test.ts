import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { getAllTools, getSiteDomain } from './env';
import { formatOutcomeBadge, formatUtcTimestamp, truncateIndicator } from './formatters';
import { extractDomainParts } from './rdap';
import {
  computeTriageOutcomeKey,
  countTrackedIocs,
  lookupThreat,
  normalizeIndicator,
} from './threatLookup';
import type { DisclaimersData, RdapDomainInfo, ThreatsData, TriageTreeData } from '../types/data';

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

describe('PortScamWatch 3-tier lookup, RDAP helpers & data contracts', () => {
  const threatsData = loadJson<ThreatsData>('public/data/threats.json');
  const triageTree = loadJson<TriageTreeData>('public/data/triage-tree.json');
  const disclaimers = loadJson<DisclaimersData>('public/data/disclaimers.json');

  it('normalizes protocols, www., defanged dots, and trailing slashes', () => {
    expect(normalizeIndicator('  HTTPS://www.velmontriq[.]net/download/  ')).toBe(
      'velmontriq.net/download',
    );
    expect(normalizeIndicator('http://gta6demo[.]asia///')).toBe('gta6demo.asia');
  });

  it('extracts registrable domains for URLs/domains and ignores files, paths, and hashes', () => {
    expect(extractDomainParts('https://store.steampowered.com/app/123')).toEqual({
      hostname: 'store.steampowered.com',
      registrableDomain: 'steampowered.com',
    });
    expect(extractDomainParts('google.com')).toEqual({
      hostname: 'google.com',
      registrableDomain: 'google.com',
    });
    expect(extractDomainParts('random-unlisted-port.exe')).toBeNull();
    expect(extractDomainParts('%LOCALAPPDATA%\\Temp\\GTA6Cloud.exe')).toBeNull();
    expect(extractDomainParts('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')).toBeNull();
  });

  it('formats ISO UTC timestamp, outcome badges without underscores, and long hashes cleanly', () => {
    expect(formatUtcTimestamp('2026-11-25T19:00:00Z')).toBe('Nov 25, 2026 · 19:00 UTC');
    const formattedBadge = formatOutcomeBadge('UNVERIFIED_HIGH_RISK');
    expect(formattedBadge).toBe('UNVERIFIED · HIGH RISK');
    expect(formattedBadge).not.toContain('_');
    expect(
      truncateIndicator('3A0C4760DEC4FED3E822DB9A630107DA266AAEFFEA8A0CCF506DFAA5847BD922'),
    ).toBe('3A0C4760DE…847BD922');
  });

  it('VERDICT A: velmontriq.net and GTA6Cloud.exe -> Confirmed Threat', () => {
    const domainRes = lookupThreat('velmontriq.net', threatsData.threats);
    expect(domainRes.tier).toBe('CONFIRMED_THREAT');
    expect(domainRes.verdictLabel).toBe('MATCHED IN VENDOR ADVISORIES');
    expect(domainRes.matches.length).toBeGreaterThan(0);

    const urlRes = lookupThreat('https://velmontriq.net/download', threatsData.threats);
    expect(urlRes.tier).toBe('CONFIRMED_THREAT');

    const exeRes = lookupThreat('GTA6Cloud.exe', threatsData.threats);
    expect(exeRes.tier).toBe('CONFIRMED_THREAT');
    expect(exeRes.verdictLabel).toBe('MATCHED IN VENDOR ADVISORIES');
  });

  it('VERDICT B: google.com -> Established Domain (never labeled Malicious)', () => {
    const res = lookupThreat('google.com', threatsData.threats);
    expect(res.tier).toBe('ESTABLISHED_DOMAIN');
    expect(res.verdictLabel).toBe('ESTABLISHED DOMAIN — NOT IN THREAT LISTS');
    expect(res.verdictLabel.toUpperCase()).not.toContain('MALICIOUS');
    expect(res.isKnownEstablishedDomain).toBe(true);
    expect(res.matches).toHaveLength(0);

    const agedRdap: RdapDomainInfo = {
      domain: 'example-old-site.org',
      status: 'ok',
      registeredDateIso: '2018-04-12T00:00:00.000Z',
      registeredYear: 2018,
      ageDays: 3000,
    };
    const agedRes = lookupThreat('example-old-site.org', threatsData.threats, agedRdap);
    expect(agedRes.tier).toBe('ESTABLISHED_DOMAIN');
  });

  it('VERDICT C: random-unlisted-port.exe -> Not Found in Vendor Advisories', () => {
    const res = lookupThreat('random-unlisted-port.exe', threatsData.threats);
    expect(res.tier).toBe('NOT_LISTED');
    expect(res.verdictLabel).toBe('NOT FOUND IN VENDOR ADVISORIES');
    expect(res.verdictLabel.toUpperCase()).not.toContain('MALICIOUS');
    expect(res.verdictLabel.toUpperCase()).not.toContain('SAFE');
    expect(res.matches).toHaveLength(0);

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

  it('computes highest triage severity and counts tracked IOCs', () => {
    expect(triageTree.questions).toHaveLength(5);
    expect(countTrackedIocs(threatsData.threats)).toBeGreaterThan(0);

    const allNo = Object.fromEntries(triageTree.questions.map((q) => [q.id, false]));
    const cautionKey = computeTriageOutcomeKey(triageTree.questions, allNo);
    expect(cautionKey).toBe('UNVERIFIED_CAUTION');
    expect(triageTree.outcomes[cautionKey].badge.toUpperCase()).not.toMatch(/\bSAFE\b/);

    const highExposureQuestion = triageTree.questions.find(
      (q) => q.yesTriggersSeverity === 'HIGH_EXPOSURE',
    );
    const criticalQuestion = triageTree.questions.find(
      (q) => q.yesTriggersSeverity === 'CRITICAL_INFECTED',
    );
    expect(highExposureQuestion).toBeDefined();
    expect(criticalQuestion).toBeDefined();

    const highAns = { ...allNo, [highExposureQuestion!.id]: true };
    expect(computeTriageOutcomeKey(triageTree.questions, highAns)).toBe('HIGH_EXPOSURE');

    const critAns = { ...highAns, [criticalQuestion!.id]: true };
    expect(computeTriageOutcomeKey(triageTree.questions, critAns)).toBe('CRITICAL_INFECTED');
  });

  it('enforces exact JSON schema contracts and zero hardcoded affiliate tracking IDs', () => {
    expect(threatsData.meta.officialPcReleaseStatus).toBeTruthy();
    expect(threatsData.meta.officialPlatforms).toEqual(['PlayStation 5', 'Xbox Series X|S']);
    expect(Object.keys(triageTree.outcomes)).toEqual(
      expect.arrayContaining([
        'CRITICAL_INFECTED',
        'HIGH_EXPOSURE',
        'UNVERIFIED_CAUTION',
      ]),
    );
    expect(disclaimers.siteName).toBeTruthy();
    expect(disclaimers.affiliateDisclosure).toBeTruthy();

    expect(getSiteDomain()).toBe('portscamwatch.com');
    const tools = getAllTools();
    expect(tools.map((t) => t.url)).toEqual([
      'https://www.malwarebytes.com/',
      'https://www.bitdefender.com/',
      'https://nordpass.com/',
      'https://nordvpn.com/',
    ]);

    const files = [
      ...collectFiles(path.join(ROOT, 'src')),
      ...collectFiles(path.join(ROOT, 'public')),
    ].filter((filePath) => !filePath.endsWith('.test.ts'));

    const affiliatePatterns = [
      /[?&](ref|aff|aff_id|affiliate|affiliate_id|subid|clickid|partner_id|tag|utm_source)=/i,
      /irclickid/i,
      /tkqlhce\.com|dpbolvw\.net|anrdoezrs\.net|kqzyfj\.com/i,
    ];

    for (const file of files) {
      const content = fs.readFileSync(file, 'utf-8');
      for (const pattern of affiliatePatterns) {
        expect(content, `Unexpected affiliate pattern in ${file}`).not.toMatch(pattern);
      }
    }

    const gitignore = fs.readFileSync(path.join(ROOT, '.gitignore'), 'utf-8');
    expect(gitignore.split(/\r?\n/)).toContain('.env');
  });
});
