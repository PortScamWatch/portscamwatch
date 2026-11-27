import { useEffect, useRef, useState, type FormEvent } from 'react';
import {
  AlertOctagon,
  AlertTriangle,
  ArrowRight,
  Clock,
  ExternalLink,
  FileImage,
  Globe,
  Info,
  ListFilter,
  Loader2,
  Search,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';
import { formatDomainAge, formatUtcTimestamp } from '../lib/formatters';
import { extractDomainParts, fetchRdapDomainInfo } from '../lib/rdap';
import type { LookupResult, RdapDomainInfo, ThreatsMeta } from '../types/data';
import { DefenseToolsPanel } from './DefenseToolsPanel';

export type AppPage = 'lookup' | 'triage' | 'advisories' | 'export';

interface StatusAndVerifierProps {
  meta: ThreatsMeta;
  totalAdvisories: number;
  totalIocs: number;
  lookupResult: LookupResult | null;
  pendingQuery?: string | null;
  onConsumePendingQuery?: () => void;
  onCompleteLookup: (rawQuery: string, rdap: RdapDomainInfo | null) => void;
  onClear: () => void;
  onNavigate: (page: AppPage) => void;
}

const SAMPLE_INDICATORS = [
  'velmontriq.net',
  'google.com',
  'GTA6Cloud.exe',
  'random-unlisted-port.exe',
];

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function StatusAndVerifier({
  meta,
  totalAdvisories,
  totalIocs,
  lookupResult,
  pendingQuery,
  onConsumePendingQuery,
  onCompleteLookup,
  onClear,
  onNavigate,
}: StatusAndVerifierProps) {
  const [inputValue, setInputValue] = useState(lookupResult?.query ?? '');
  const [isInspecting, setIsInspecting] = useState(false);
  const [inspectionStep, setInspectionStep] = useState('');
  const activeRunId = useRef(0);

  const runInspection = async (rawQuery: string) => {
    const trimmed = rawQuery.trim();
    if (!trimmed) return;

    const runId = ++activeRunId.current;
    setIsInspecting(true);
    setInspectionStep('Normalizing indicator...');

    const domainParts = extractDomainParts(trimmed);
    const rdapPromise: Promise<RdapDomainInfo | null> = domainParts
      ? fetchRdapDomainInfo(domainParts.registrableDomain, 3000)
      : Promise.resolve(null);

    await sleep(220);
    if (activeRunId.current !== runId) return;
    setInspectionStep(
      `Checking ${totalIocs} vendor-confirmed IOCs across ${totalAdvisories} advisories...`,
    );

    await sleep(230);
    if (activeRunId.current !== runId) return;
    setInspectionStep(
      domainParts
        ? `Querying live RDAP domain registration (${domainParts.registrableDomain})...`
        : 'Evaluating filename & artifact signatures...',
    );

    const [, rdap] = await Promise.all([sleep(220), rdapPromise]);
    if (activeRunId.current !== runId) return;

    setIsInspecting(false);
    setInspectionStep('');
    onCompleteLookup(trimmed, rdap);
  };

  useEffect(() => {
    if (pendingQuery) {
      setInputValue(pendingQuery);
      onConsumePendingQuery?.();
      void runInspection(pendingQuery);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pendingQuery]);

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    void runInspection(inputValue);
  };

  const handleSampleClick = (sample: string) => {
    setInputValue(sample);
    void runInspection(sample);
  };

  const handleReset = () => {
    activeRunId.current += 1;
    setIsInspecting(false);
    setInspectionStep('');
    setInputValue('');
    onClear();
  };

  return (
    <section aria-label="Threat Lookup" className="space-y-5">
      {/* Main Centered Checker Panel */}
      <div className="rounded-xl border border-slate-800 bg-[#111827] p-5 sm:p-8">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-4 font-mono text-xs text-slate-400">
          <span>
            Feed: <strong className="text-slate-200">{totalAdvisories} Vendor Advisories</strong>
            <span className="mx-2 text-slate-600">·</span>
            <strong className="text-slate-200">{totalIocs} Tracked IOCs</strong>
          </span>
          <span>Updated: {formatUtcTimestamp(meta.lastVerifiedUtc)}</span>
        </div>

        <div className="mt-5">
          <h1 className="text-2xl font-bold tracking-tight text-slate-50 sm:text-3xl">
            GTA 6 Fake-Port &amp; ClickFix Threat Lookup
          </h1>
          <p className="mt-2 max-w-3xl text-sm leading-relaxed text-slate-300 sm:text-base">
            Check suspicious domains, installers, or SHA-256 hashes against published cybersecurity
            vendor advisories and live domain registration records.
          </p>
        </div>

        <form onSubmit={handleSubmit} className="mt-6 flex flex-col gap-2.5 sm:flex-row">
          <div className="relative flex-1">
            <Search className="pointer-events-none absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
            <input
              type="text"
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
              placeholder="Enter domain, URL, filename (e.g. GTA6Cloud.exe), Windows path, or SHA-256"
              aria-label="Suspicious URL, domain, filename, Windows path, or SHA-256 hash"
              className="w-full rounded-lg border border-slate-700/90 bg-[#0b0f17] py-3.5 pl-10 pr-4 font-mono text-sm text-slate-100 placeholder:text-slate-500 focus:border-sky-400 focus:outline-none focus:ring-1 focus:ring-sky-400/40"
            />
          </div>
          <button
            type="submit"
            disabled={isInspecting}
            className="inline-flex items-center justify-center gap-2 rounded-lg border border-sky-500/40 bg-sky-600 px-6 py-3.5 text-sm font-semibold text-white transition hover:bg-sky-500 disabled:opacity-60 cursor-pointer"
          >
            {isInspecting ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" />
                Checking...
              </>
            ) : (
              'Inspect Indicator'
            )}
          </button>
        </form>

        {/* Quick examples */}
        <div className="mt-3.5 flex flex-wrap items-center gap-2 text-xs">
          <span className="text-slate-400">Examples:</span>
          {SAMPLE_INDICATORS.map((sample) => (
            <button
              key={sample}
              type="button"
              disabled={isInspecting}
              onClick={() => handleSampleClick(sample)}
              className="rounded border border-slate-800 bg-[#0b0f17] px-2.5 py-1 font-mono text-xs text-slate-300 transition hover:border-slate-600 hover:text-white disabled:opacity-50 cursor-pointer"
            >
              {sample}
            </button>
          ))}
          {(lookupResult || isInspecting) && (
            <button
              type="button"
              onClick={handleReset}
              className="ml-auto font-mono text-xs text-slate-400 underline hover:text-slate-200 cursor-pointer"
            >
              Clear
            </button>
          )}
        </div>

        {/* Progressive Inspection Status */}
        {isInspecting && (
          <div
            role="status"
            aria-live="polite"
            className="mt-6 flex items-center gap-3 rounded-lg border border-slate-800 bg-[#0b0f17] px-4 py-4"
          >
            <Loader2 className="h-4 w-4 shrink-0 animate-spin text-sky-400" />
            <span className="font-mono text-xs text-slate-200 sm:text-sm">{inspectionStep}</span>
          </div>
        )}

        {/* VERDICT A — CONFIRMED THREAT */}
        {!isInspecting && lookupResult?.tier === 'CONFIRMED_THREAT' && (
          <div
            role="alert"
            className="mt-6 rounded-xl border border-red-500/60 bg-red-950/20 p-5"
          >
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="inline-flex items-center gap-1.5 rounded bg-red-600 px-2.5 py-1 font-mono text-xs font-bold tracking-wide text-white">
                <AlertOctagon className="h-3.5 w-3.5" />
                {lookupResult.verdictLabel}
              </span>
              <span className="font-mono text-xs text-slate-300">
                Indicator: {lookupResult.normalizedQuery.replace(/\./g, '[.]')}
              </span>
            </div>

            {lookupResult.rdap?.status === 'ok' &&
              lookupResult.rdap.registeredYear !== null &&
              lookupResult.rdap.ageDays !== null && (
                <div className="mt-3 flex flex-wrap gap-2 font-mono text-xs text-slate-300">
                  <span className="inline-flex items-center gap-1.5 rounded border border-red-500/30 bg-[#0b0f17] px-2.5 py-1">
                    <Globe className="h-3.5 w-3.5 text-red-400" />
                    RDAP Registered: {lookupResult.rdap.registeredYear} (
                    {formatDomainAge(lookupResult.rdap.ageDays)})
                  </span>
                </div>
              )}

            <div className="mt-4 space-y-4">
              {lookupResult.matches.map((match) => (
                <div
                  key={match.id}
                  className="rounded-lg border border-slate-800 bg-[#0b0f17] p-4 space-y-3"
                >
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div>
                      <h2 className="text-base font-bold text-slate-50 sm:text-lg">{match.title}</h2>
                      <p className="mt-0.5 font-mono text-xs text-red-400">
                        Malware Family: {match.malwareFamily}
                      </p>
                    </div>
                    <a
                      href={match.advisoryUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1.5 rounded-md border border-slate-700 bg-[#111827] px-3 py-1.5 font-mono text-xs text-slate-200 transition hover:border-slate-500 hover:text-white"
                    >
                      {match.vendorName} ({match.advisoryDate})
                      <ExternalLink className="h-3.5 w-3.5" />
                    </a>
                  </div>

                  <p className="text-sm leading-relaxed text-slate-300">{match.summary}</p>

                  <div className="grid gap-3 sm:grid-cols-2">
                    <div className="rounded-lg border border-slate-800 bg-[#111827]/70 p-3">
                      <p className="font-mono text-[11px] uppercase tracking-wider text-slate-400">
                        Targeted Data
                      </p>
                      <ul className="mt-1.5 space-y-1 text-xs text-slate-300">
                        {match.targetedData.map((item) => (
                          <li key={item}>• {item}</li>
                        ))}
                      </ul>
                    </div>

                    <div className="rounded-lg border border-slate-800 bg-[#111827]/70 p-3">
                      <p className="font-mono text-[11px] uppercase tracking-wider text-slate-400">
                        Observed Host Artifacts
                      </p>
                      <ul className="mt-1.5 space-y-1 font-mono text-xs text-slate-200">
                        {match.hostArtifacts.map((artifact) => (
                          <li key={artifact} className="break-all">
                            {artifact}
                          </li>
                        ))}
                      </ul>
                    </div>
                  </div>
                </div>
              ))}
            </div>

            <DefenseToolsPanel
              variant="compact"
              heading="Immediate Containment & Protection Tools"
              className="mt-4"
            />

            <div className="mt-4 flex flex-wrap items-center justify-between gap-3 border-t border-slate-800/80 pt-4">
              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  onClick={() => onNavigate('triage')}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-red-500/50 bg-red-600 px-4 py-2 text-xs font-semibold text-white transition hover:bg-red-500 cursor-pointer"
                >
                  Open 60-second exposure check
                  <ArrowRight className="h-3.5 w-3.5" />
                </button>
                <button
                  type="button"
                  onClick={() => onNavigate('export')}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-[#0b0f17] px-3.5 py-2 text-xs font-medium text-slate-200 transition hover:border-slate-500 cursor-pointer"
                >
                  <FileImage className="h-3.5 w-3.5" />
                  Export PNG Card
                </button>
              </div>
              <span className="text-xs text-slate-400">
                Matched against published vendor telemetry
              </span>
            </div>
          </div>
        )}

        {/* VERDICT B — ESTABLISHED / OFFICIAL DOMAIN */}
        {!isInspecting && lookupResult?.tier === 'ESTABLISHED_DOMAIN' && (
          <div
            role="status"
            className="mt-6 rounded-xl border border-sky-500/40 bg-sky-950/15 p-5"
          >
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="inline-flex items-center gap-1.5 rounded border border-sky-500/40 bg-sky-500/15 px-2.5 py-1 font-mono text-xs font-semibold tracking-wide text-sky-200">
                <ShieldCheck className="h-3.5 w-3.5" />
                {lookupResult.verdictLabel}
              </span>
              <span className="font-mono text-xs text-slate-300">
                Domain: {lookupResult.normalizedQuery}
              </span>
            </div>

            <div className="mt-4 space-y-3 rounded-lg border border-slate-800 bg-[#0b0f17] p-4">
              <p className="text-sm leading-relaxed text-slate-200">
                <strong>{lookupResult.rdap?.domain ?? lookupResult.normalizedQuery}</strong> does not
                appear in our tracked GTA 6 fake-port or ClickFix malware advisories.
              </p>

              <div className="flex flex-wrap gap-3 font-mono text-xs text-slate-300">
                <span className="inline-flex items-center gap-1.5 rounded border border-slate-800 bg-[#111827] px-2.5 py-1">
                  <Globe className="h-3.5 w-3.5 text-sky-400" />
                  {lookupResult.rdap?.status === 'ok' &&
                  lookupResult.rdap.registeredYear !== null &&
                  lookupResult.rdap.ageDays !== null
                    ? `RDAP Registered: ${lookupResult.rdap.registeredYear} (${formatDomainAge(lookupResult.rdap.ageDays)})`
                    : lookupResult.isKnownEstablishedDomain
                      ? 'Verified Established Platform Domain'
                      : 'RDAP Age: >365 days'}
                </span>
              </div>

              <div className="flex items-start gap-2 rounded-md border border-slate-800 bg-[#111827]/70 p-3 text-xs text-slate-300">
                <Info className="mt-0.5 h-4 w-4 shrink-0 text-sky-400" />
                <p>
                  Official GTA 6 releases are listed only on{' '}
                  <span className="font-mono text-slate-100">rockstargames.com</span> (currently PS5
                  &amp; Xbox Series X|S only).
                </p>
              </div>
            </div>
          </div>
        )}

        {/* VERDICT C — NOT LISTED IN VENDOR ADVISORIES */}
        {!isInspecting && lookupResult?.tier === 'NOT_LISTED' && (
          <div
            role="status"
            className="mt-6 rounded-xl border border-slate-700 bg-[#0b0f17] p-5"
          >
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span
                className={`inline-flex items-center gap-1.5 rounded border px-2.5 py-1 font-mono text-xs font-semibold tracking-wide ${
                  lookupResult.isNewlyRegisteredDomain
                    ? 'border-amber-500/50 bg-amber-500/15 text-amber-200'
                    : 'border-slate-600 bg-slate-800 text-slate-200'
                }`}
              >
                <AlertTriangle className="h-3.5 w-3.5" />
                {lookupResult.verdictLabel}
              </span>
              {lookupResult.normalizedQuery && (
                <span className="font-mono text-xs text-slate-400">
                  Checked: {lookupResult.normalizedQuery.replace(/\./g, '[.]')}
                </span>
              )}
            </div>

            <div className="mt-4 space-y-3">
              <p className="text-sm leading-relaxed text-slate-200">
                This indicator does not currently appear in our tracked cybersecurity vendor
                advisories (Bitdefender, Malwarebytes, Netcraft, Darktrace, NordVPN, ESET, Cynet).
              </p>

              {lookupResult.isNewlyRegisteredDomain &&
                lookupResult.rdap?.status === 'ok' &&
                lookupResult.rdap.ageDays !== null && (
                  <div className="flex items-start gap-2.5 rounded-lg border border-amber-500/40 bg-amber-500/10 p-3 text-xs text-amber-100">
                    <Clock className="mt-0.5 h-4 w-4 shrink-0 text-amber-400" />
                    <div>
                      <p className="font-semibold">Newly Registered Domain (&lt;90 days old)</p>
                      <p className="mt-0.5 text-amber-200/90">
                        Live RDAP records show{' '}
                        <span className="font-mono">{lookupResult.rdap.domain}</span> was registered{' '}
                        {lookupResult.rdap.ageDays} day{lookupResult.rdap.ageDays === 1 ? '' : 's'}{' '}
                        ago ({lookupResult.rdap.registeredYear}). Recently registered domains
                        advertising early PC access are a common campaign indicator.
                      </p>
                    </div>
                  </div>
                )}

              {!lookupResult.isNewlyRegisteredDomain &&
                lookupResult.rdap?.status === 'ok' &&
                lookupResult.rdap.registeredYear !== null &&
                lookupResult.rdap.ageDays !== null && (
                  <p className="font-mono text-xs text-slate-400">
                    RDAP registration: {lookupResult.rdap.registeredYear} (
                    {formatDomainAge(lookupResult.rdap.ageDays)})
                  </p>
                )}

              <p className="text-xs leading-relaxed text-slate-400">
                Vendor threat feeds only publish confirmed campaigns, and no official PC or mobile
                GTA 6 build exists ({meta.officialPlatforms.join(' / ')} only).
              </p>

              <DefenseToolsPanel
                variant="compact"
                heading="Stay Protected Against Unlisted Lures"
              />

              <div className="flex flex-wrap items-center justify-between gap-2 border-t border-slate-800 pt-3">
                <span className="text-xs text-slate-400">
                  Already downloaded or opened a file from this source?
                </span>
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => onNavigate('triage')}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-[#111827] px-3.5 py-2 text-xs font-medium text-slate-200 transition hover:border-slate-500 hover:text-white cursor-pointer"
                  >
                    Run 60-second self-check
                    <ArrowRight className="h-3.5 w-3.5" />
                  </button>
                  <button
                    type="button"
                    onClick={() => onNavigate('export')}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-slate-800 bg-[#111827] px-3 py-2 text-xs font-medium text-slate-300 transition hover:border-slate-600 cursor-pointer"
                  >
                    <FileImage className="h-3.5 w-3.5" />
                    Export Card
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Compact Page Navigation Cards (links to dedicated tools without crowding Lookup) */}
      <div className="grid gap-3 sm:grid-cols-3">
        <button
          type="button"
          onClick={() => onNavigate('triage')}
          className="flex flex-col justify-between rounded-xl border border-slate-800 bg-[#111827] p-4 text-left transition hover:border-slate-600 cursor-pointer"
        >
          <div>
            <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
              <ShieldAlert className="h-3.5 w-3.5 text-slate-300" />
              <span>EXPOSURE TRIAGE</span>
            </div>
            <p className="mt-1.5 text-sm font-semibold text-slate-100">
              60-Second &ldquo;Did I Run a Fake Port?&rdquo; Check
            </p>
          </div>
          <span className="mt-3 inline-flex items-center gap-1 font-mono text-xs text-sky-400">
            Open triage wizard <ArrowRight className="h-3 w-3" />
          </span>
        </button>

        <button
          type="button"
          onClick={() => onNavigate('advisories')}
          className="flex flex-col justify-between rounded-xl border border-slate-800 bg-[#111827] p-4 text-left transition hover:border-slate-600 cursor-pointer"
        >
          <div>
            <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
              <ListFilter className="h-3.5 w-3.5 text-slate-300" />
              <span>THREAT FEED</span>
            </div>
            <p className="mt-1.5 text-sm font-semibold text-slate-100">
              {totalAdvisories} Vendor Advisories · {totalIocs} Tracked IOCs
            </p>
          </div>
          <span className="mt-3 inline-flex items-center gap-1 font-mono text-xs text-sky-400">
            Browse advisory table <ArrowRight className="h-3 w-3" />
          </span>
        </button>

        <button
          type="button"
          onClick={() => onNavigate('export')}
          className="flex flex-col justify-between rounded-xl border border-slate-800 bg-[#111827] p-4 text-left transition hover:border-slate-600 cursor-pointer"
        >
          <div>
            <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
              <FileImage className="h-3.5 w-3.5 text-slate-300" />
              <span>EXPORT REPORT</span>
            </div>
            <p className="mt-1.5 text-sm font-semibold text-slate-100">
              Download 1200×630 PNG Advisory Card
            </p>
          </div>
          <span className="mt-3 inline-flex items-center gap-1 font-mono text-xs text-sky-400">
            Open PNG exporter <ArrowRight className="h-3 w-3" />
          </span>
        </button>
      </div>

      {/* Homepage Recommended Protection Stack (above Removal Guides accordion) */}
      <DefenseToolsPanel
        variant="full"
        heading="Recommended Protection Stack"
        subheading="Rotate compromised logins and active sessions, block lookalike scam domains, and scan suspicious downloads."
      />
    </section>
  );
}
