export type ThreatSeverity = 'CONFIRMED' | 'HIGH' | 'UNVERIFIED';

export interface ThreatsMeta {
  siteDomain: string;
  lastVerifiedUtc: string;
  officialPcReleaseStatus: string;
  officialPlatforms: string[];
}

export interface ThreatEntry {
  id: string;
  title: string;
  severity: ThreatSeverity | string;
  malwareFamily: string;
  lureType: string;
  displayIndicators: string[];
  indicators: string[];
  targetedData: string[];
  hostArtifacts: string[];
  summary: string;
  vendorName: string;
  advisoryDate: string;
  advisoryUrl: string;
}

export interface ThreatsData {
  meta: ThreatsMeta;
  threats: ThreatEntry[];
}

export type TriageOutcomeKey =
  | 'CRITICAL_INFECTED'
  | 'HIGH_EXPOSURE'
  | 'UNVERIFIED_CAUTION'
  | 'UNVERIFIED_HIGH_RISK';

export type RecommendedToolKey =
  | 'malwarebytes'
  | 'bitdefender'
  | 'nordvpn'
  | 'nordpass'
  | 'none';

export interface TriageQuestion {
  id: string;
  prompt: string;
  helperText: string;
  riskWeight: number;
  yesTriggersSeverity: TriageOutcomeKey;
}

export interface TriageStep {
  order: number;
  title: string;
  detail: string;
  recommendedToolKey: RecommendedToolKey | null;
}

export interface TriageOutcome {
  badge: string;
  headline: string;
  summary: string;
  steps: TriageStep[];
}

export interface TriageTreeData {
  questions: TriageQuestion[];
  outcomes: Record<TriageOutcomeKey, TriageOutcome>;
}

export interface DisclaimersData {
  siteName: string;
  affiliateDisclosure: string;
  asIsDisclaimer: string;
  nonAffiliationNotice: string;
}

export interface RdapDomainInfo {
  domain: string;
  status: 'ok' | 'unavailable';
  registeredDateIso: string | null;
  registeredYear: number | null;
  ageDays: number | null;
}

export type LookupVerdictTier =
  | 'CONFIRMED_THREAT'
  | 'ESTABLISHED_DOMAIN'
  | 'NOT_LISTED';

export interface LookupResult {
  tier: LookupVerdictTier;
  verdictLabel:
    | 'MATCHED IN VENDOR ADVISORIES'
    | 'ESTABLISHED DOMAIN — NOT IN THREAT LISTS'
    | 'NOT FOUND IN VENDOR ADVISORIES';
  query: string;
  normalizedQuery: string;
  matches: ThreatEntry[];
  rdap: RdapDomainInfo | null;
  isKnownEstablishedDomain: boolean;
  isNewlyRegisteredDomain: boolean;
}
