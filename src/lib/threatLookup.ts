import { extractDomainParts, isKnownEstablishedDomain } from './rdap';
import type {
  LookupResult,
  RdapDomainInfo,
  ThreatEntry,
  TriageOutcomeKey,
  TriageQuestion,
} from '../types/data';

/**
 * Normalizes URLs, defanged domains, Windows paths, filenames, and hashes
 * for deterministic indicator matching.
 */
export function normalizeIndicator(raw: string): string {
  return raw
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/^www\./, '')
    .replace(/\[\.\]/g, '.')
    .replace(/\/+$/, '');
}

function isDescriptiveProse(rawTarget: string): boolean {
  const wordCount = rawTarget.trim().split(/\s+/).length;
  return (
    wordCount >= 4 &&
    !rawTarget.includes('\\') &&
    !/\.(exe|dll|zip|apk|txt|ps1|bat|msi|js|lnk)$/i.test(rawTarget)
  );
}

function isIndicatorMatch(normalizedQuery: string, rawTarget: string): boolean {
  const normalizedTarget = normalizeIndicator(rawTarget);
  if (!normalizedQuery || !normalizedTarget) return false;

  if (normalizedQuery === normalizedTarget) {
    return true;
  }

  if (isDescriptiveProse(rawTarget)) {
    return false;
  }

  if (normalizedTarget.length >= 5 && normalizedQuery.includes(normalizedTarget)) {
    return true;
  }

  if (normalizedQuery.length >= 6 && normalizedTarget.includes(normalizedQuery)) {
    return true;
  }

  return false;
}

export function countTrackedIocs(threats: ThreatEntry[]): number {
  const unique = new Set<string>();
  for (const entry of threats) {
    for (const ind of entry.indicators) {
      unique.add(normalizeIndicator(ind));
    }
    for (const art of entry.hostArtifacts) {
      unique.add(normalizeIndicator(art));
    }
  }
  return unique.size;
}

/**
 * Evaluates a user-supplied URL, domain, filename, Windows path, or SHA-256 hash
 * against vendor advisories and optional live RDAP registration info.
 * Returns one of three clinical verdicts: CONFIRMED_THREAT, ESTABLISHED_DOMAIN, or NOT_LISTED.
 */
export function lookupThreat(
  query: string,
  threats: ThreatEntry[],
  rdap: RdapDomainInfo | null = null,
): LookupResult {
  const normalizedQuery = normalizeIndicator(query);
  const domainParts = extractDomainParts(query);
  const knownEstablished = isKnownEstablishedDomain(domainParts);
  const rdapAgeDays = rdap?.status === 'ok' ? rdap.ageDays : null;
  const isNewlyRegisteredDomain = rdapAgeDays !== null && rdapAgeDays <= 90;

  if (normalizedQuery.length < 3) {
    return {
      tier: 'NOT_LISTED',
      verdictLabel: 'NOT FOUND IN VENDOR ADVISORIES',
      query,
      normalizedQuery,
      matches: [],
      rdap,
      isKnownEstablishedDomain: false,
      isNewlyRegisteredDomain: false,
    };
  }

  const matches = threats.filter((entry) => {
    const candidates = [...entry.indicators, ...entry.hostArtifacts];
    return candidates.some((candidate) => isIndicatorMatch(normalizedQuery, candidate));
  });

  if (matches.length > 0) {
    return {
      tier: 'CONFIRMED_THREAT',
      verdictLabel: 'MATCHED IN VENDOR ADVISORIES',
      query,
      normalizedQuery,
      matches,
      rdap,
      isKnownEstablishedDomain: knownEstablished,
      isNewlyRegisteredDomain,
    };
  }

  const isAgedEstablishedViaRdap = rdapAgeDays !== null && rdapAgeDays > 365;

  if (knownEstablished || isAgedEstablishedViaRdap) {
    return {
      tier: 'ESTABLISHED_DOMAIN',
      verdictLabel: 'ESTABLISHED DOMAIN — NOT IN THREAT LISTS',
      query,
      normalizedQuery,
      matches: [],
      rdap,
      isKnownEstablishedDomain: knownEstablished,
      isNewlyRegisteredDomain: false,
    };
  }

  return {
    tier: 'NOT_LISTED',
    verdictLabel: 'NOT FOUND IN VENDOR ADVISORIES',
    query,
    normalizedQuery,
    matches: [],
    rdap,
    isKnownEstablishedDomain: false,
    isNewlyRegisteredDomain,
  };
}

const SEVERITY_RANK: Record<TriageOutcomeKey, number> = {
  UNVERIFIED_CAUTION: 0,
  UNVERIFIED_HIGH_RISK: 0,
  HIGH_EXPOSURE: 1,
  CRITICAL_INFECTED: 2,
};

/**
 * Computes the highest severity outcome triggered by the triage questions.
 * Defaults to UNVERIFIED_CAUTION if all answers are No or unanswered.
 */
export function computeTriageOutcomeKey(
  questions: TriageQuestion[],
  answers: Record<string, boolean | null>,
): TriageOutcomeKey {
  let highest: TriageOutcomeKey = 'UNVERIFIED_CAUTION';

  for (const question of questions) {
    if (answers[question.id] === true) {
      if (SEVERITY_RANK[question.yesTriggersSeverity] > SEVERITY_RANK[highest]) {
        highest = question.yesTriggersSeverity;
      }
    }
  }

  return highest;
}
