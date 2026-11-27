import { useEffect, useMemo, useRef, useState, type DragEvent, type FormEvent } from 'react';
import {
  AlertOctagon,
  AlertTriangle,
  ArrowRight,
  Check,
  Clock,
  Copy,
  Database,
  ExternalLink,
  FileImage,
  FileSearch,
  Globe,
  Info,
  Link2,
  ListFilter,
  Loader2,
  Search,
  ShieldAlert,
  ShieldCheck,
  Upload,
} from 'lucide-react';
import { formatDomainAge, formatUtcTimestamp } from '../lib/formatters';
import { extractDomainParts, fetchRdapDomainInfo } from '../lib/rdap';
import type { LookupResult, RdapDomainInfo, ThreatEntry, ThreatsMeta } from '../types/data';
import {
  buildNativeHashCommands,
  computeFileSha256,
  formatBytes,
  type FileHashResult,
} from '../utils/fileHash';
import { inspectNormalizedInput } from '../utils/normalizeInput';
import { DefenseToolsPanel } from './DefenseToolsPanel';

export type AppPage = 'lookup' | 'triage' | 'advisories' | 'exports' | 'export';

interface StatusAndVerifierProps {
  meta: ThreatsMeta;
  threats: ThreatEntry[];
  totalAdvisories: number;
  totalIocs: number;
  lookupResult: LookupResult | null;
  pendingQuery?: string | null;
  onConsumePendingQuery?: () => void;
  onCompleteLookup: (rawQuery: string, rdap: RdapDomainInfo | null) => void;
  onClear: () => void;
  onNavigate: (page: AppPage) => void;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function syncQueryParam(rawQuery: string | null) {
  if (typeof window === 'undefined') return;
  const url = new URL(window.location.href);
  if (rawQuery && rawQuery.trim()) {
    url.searchParams.set('q', rawQuery.trim());
  } else {
    url.searchParams.delete('q');
  }
  window.history.replaceState(null, '', `${url.pathname}${url.search}${url.hash}`);
}

export function StatusAndVerifier({
  meta,
  threats,
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
  const [showFileHasher, setShowFileHasher] = useState(false);
  const [isDraggingFile, setIsDraggingFile] = useState(false);
  const [isHashingFile, setIsHashingFile] = useState(false);
  const [fileHashResult, setFileHashResult] = useState<FileHashResult | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const activeRunId = useRef(0);
  const inputRef = useRef<HTMLInputElement | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const sampleChips = useMemo(() => {
    const allDisplay = threats.flatMap((t) => t.displayIndicators);
    const allNorm = new Set(threats.flatMap((t) => t.indicators.map((i) => i.toLowerCase())));
    const candidates = [
      allDisplay.find((d) => d.toLowerCase() === 'gta6cloud.exe'),
      allDisplay.find((d) => d.toLowerCase().includes('velmontriq')),
      allNorm.has('gta6download.club') ? 'gta6download.club' : undefined,
      'rockstargames.com',
    ].filter((v): v is string => Boolean(v));
    return Array.from(new Set(candidates));
  }, [threats]);

  const runInspection = async (rawQuery: string) => {
    const trimmed = rawQuery.trim();
    if (!trimmed) return;

    const runId = ++activeRunId.current;
    syncQueryParam(trimmed);
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

  const handleReset = () => {
    activeRunId.current += 1;
    setIsInspecting(false);
    setInspectionStep('');
    setInputValue('');
    setFileHashResult(null);
    syncQueryParam(null);
    onClear();
  };

  // Keyboard shortcuts: "/" focuses search input, "Escape" clears/blurs cleanly
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement | null;
      const tag = target?.tagName?.toUpperCase();
      const isEditing =
        tag === 'INPUT' ||
        tag === 'TEXTAREA' ||
        tag === 'SELECT' ||
        Boolean(target?.isContentEditable);

      if (e.key === '/' && !isEditing && !e.metaKey && !e.ctrlKey && !e.altKey) {
        e.preventDefault();
        inputRef.current?.focus();
        inputRef.current?.select();
      } else if (e.key === 'Escape') {
        if (document.activeElement === inputRef.current || inputValue || lookupResult) {
          handleReset();
          inputRef.current?.blur();
        }
      }
    };

    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [inputValue, lookupResult]);

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    void runInspection(inputValue);
  };

  const handleSampleClick = (sample: string) => {
    setFileHashResult(null);
    setInputValue(sample);
    void runInspection(sample);
  };

  const handleCopy = async (id: string, value: string) => {
    try {
      await navigator.clipboard.writeText(value);
      setCopiedId(id);
      setTimeout(() => setCopiedId((prev) => (prev === id ? null : prev)), 2200);
    } catch {
      // Clipboard unavailable in restricted contexts
    }
  };

  const handleCopyPermalink = (query: string) => {
    if (typeof window === 'undefined') return;
    const shareUrl = `${window.location.origin}/?q=${encodeURIComponent(query.trim())}`;
    void handleCopy('permalink', shareUrl);
  };

  const processLocalFile = async (file: File | null | undefined) => {
    if (!file) return;
    setIsHashingFile(true);
    setFileHashResult(null);
    const result = await computeFileSha256(file);
    setIsHashingFile(false);
    setFileHashResult(result);

    if (result.ok) {
      setInputValue(result.sha256);
      void runInspection(result.sha256);
    }
  };

  const handleDrop = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDraggingFile(false);
    const file = e.dataTransfer.files?.[0];
    void processLocalFile(file);
  };

  const normalizationInfo = lookupResult ? inspectNormalizedInput(lookupResult.query) : null;

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
              ref={inputRef}
              type="text"
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
              placeholder="Enter domain, URL, filename (e.g. GTA6Cloud.exe), Windows path, or SHA-256"
              aria-label="Suspicious URL, domain, filename, Windows path, or SHA-256 hash"
              className="w-full rounded-lg border border-slate-700/90 bg-[#0b0f17] py-3.5 pl-10 pr-12 font-mono text-sm text-slate-100 placeholder:text-slate-500 focus:border-sky-400 focus:outline-none focus:ring-1 focus:ring-sky-400/40"
            />
            <kbd
              title="Press / to focus search"
              className="pointer-events-none absolute right-3 top-1/2 hidden -translate-y-1/2 rounded border border-slate-700 bg-[#111827] px-1.5 py-0.5 font-mono text-[11px] text-slate-400 sm:inline-block"
            >
              /
            </kbd>
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

        {/* Quick examples + Local File SHA-256 Toggle */}
        <div className="mt-3.5 flex flex-wrap items-center gap-2 text-xs">
          <span className="text-slate-400">Try:</span>
          {sampleChips.map((sample) => (
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

          <button
            type="button"
            onClick={() => setShowFileHasher((prev) => !prev)}
            aria-expanded={showFileHasher}
            className={`inline-flex items-center gap-1.5 rounded border px-2.5 py-1 font-mono text-xs transition cursor-pointer ${
              showFileHasher
                ? 'border-sky-500/50 bg-sky-500/15 text-sky-200'
                : 'border-slate-700 bg-[#0b0f17] text-slate-200 hover:border-slate-500'
            }`}
          >
            <FileSearch className="h-3.5 w-3.5 text-sky-400" />
            Hash a Local File (Never Uploaded)
          </button>

          {(lookupResult || isInspecting || fileHashResult) && (
            <button
              type="button"
              onClick={handleReset}
              className="ml-auto font-mono text-xs text-slate-400 underline hover:text-slate-200 cursor-pointer"
            >
              Clear
            </button>
          )}
        </div>

        {/* Client-Side SHA-256 Local File Hasher */}
        {showFileHasher && (
          <div className="mt-4 rounded-xl border border-slate-800 bg-[#0b0f17] p-4 space-y-3">
            <div
              onDragOver={(e) => {
                e.preventDefault();
                setIsDraggingFile(true);
              }}
              onDragLeave={() => setIsDraggingFile(false)}
              onDrop={handleDrop}
              className={`flex flex-col items-center justify-center gap-2 rounded-lg border border-dashed px-4 py-5 text-center transition ${
                isDraggingFile
                  ? 'border-sky-400 bg-sky-500/10'
                  : 'border-slate-700 bg-[#111827]/60'
              }`}
            >
              <Upload className="h-5 w-5 text-sky-400" />
              <p className="text-xs font-medium text-slate-200 sm:text-sm">
                Drop a suspicious file here or select it to compute SHA-256 in your browser
              </p>
              <p className="text-[11px] text-slate-400">
                Computed locally via Web Crypto API — zero bytes ever leave your device (max 256 MB
                in-browser guard).
              </p>
              <input
                ref={fileInputRef}
                type="file"
                aria-label="Choose a local file to hash SHA-256"
                onChange={(e) => {
                  const f = e.target.files?.[0];
                  void processLocalFile(f);
                  e.target.value = '';
                }}
                className="sr-only"
              />
              <button
                type="button"
                disabled={isHashingFile}
                onClick={() => fileInputRef.current?.click()}
                className="mt-1 inline-flex items-center gap-1.5 rounded-md border border-slate-600 bg-[#0b0f17] px-3.5 py-1.5 font-mono text-xs font-semibold text-slate-100 transition hover:border-sky-400 cursor-pointer"
              >
                {isHashingFile ? (
                  <>
                    <Loader2 className="h-3.5 w-3.5 animate-spin" /> Hashing...
                  </>
                ) : (
                  'Select Local File'
                )}
              </button>
            </div>

            {fileHashResult?.ok && (
              <div className="rounded-lg border border-slate-800 bg-[#111827] p-3.5 space-y-2">
                <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
                  <span className="font-mono text-slate-300">
                    File: <strong className="text-slate-100">{fileHashResult.fileName}</strong> (
                    {formatBytes(fileHashResult.fileSize)})
                  </span>
                  <div className="flex flex-wrap items-center gap-2">
                    <button
                      type="button"
                      onClick={() => handleCopy('sha256', fileHashResult.sha256)}
                      className="inline-flex items-center gap-1 rounded border border-slate-700 bg-[#0b0f17] px-2.5 py-1 font-mono text-[11px] text-slate-200 hover:border-slate-500 cursor-pointer"
                    >
                      {copiedId === 'sha256' ? (
                        <>
                          <Check className="h-3 w-3 text-sky-400" /> Copied SHA-256
                        </>
                      ) : (
                        <>
                          <Copy className="h-3 w-3" /> Copy SHA-256
                        </>
                      )}
                    </button>
                    <a
                      href={`https://www.virustotal.com/gui/file/${fileHashResult.sha256}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 rounded border border-slate-700 bg-[#0b0f17] px-2.5 py-1 font-mono text-[11px] text-sky-300 hover:border-sky-500/60"
                    >
                      Check on VirusTotal <ExternalLink className="h-3 w-3" />
                    </a>
                  </div>
                </div>
                <p className="break-all font-mono text-xs text-sky-300">{fileHashResult.sha256}</p>
              </div>
            )}

            {fileHashResult && !fileHashResult.ok && (
              <div
                role="alert"
                className="rounded-lg border border-amber-500/50 bg-amber-500/10 p-3.5 space-y-2.5 text-xs text-amber-100"
              >
                <p className="font-medium leading-relaxed">{fileHashResult.message}</p>
                {(() => {
                  const cmds = buildNativeHashCommands(fileHashResult.fileName);
                  return (
                    <div className="grid gap-2 sm:grid-cols-2">
                      <div className="rounded border border-slate-800 bg-[#0b0f17] p-2.5">
                        <div className="flex items-center justify-between gap-2 font-mono text-[10px] text-slate-400">
                          <span>WINDOWS POWERSHELL</span>
                          <button
                            type="button"
                            onClick={() => handleCopy('ps-hash', cmds.powershell)}
                            className="text-sky-300 hover:underline cursor-pointer"
                          >
                            {copiedId === 'ps-hash' ? 'Copied' : 'Copy'}
                          </button>
                        </div>
                        <code className="mt-1 block break-all font-mono text-[11px] text-slate-200">
                          {cmds.powershell}
                        </code>
                      </div>
                      <div className="rounded border border-slate-800 bg-[#0b0f17] p-2.5">
                        <div className="flex items-center justify-between gap-2 font-mono text-[10px] text-slate-400">
                          <span>MACOS / LINUX</span>
                          <button
                            type="button"
                            onClick={() => handleCopy('unix-hash', cmds.unix)}
                            className="text-sky-300 hover:underline cursor-pointer"
                          >
                            {copiedId === 'unix-hash' ? 'Copied' : 'Copy'}
                          </button>
                        </div>
                        <code className="mt-1 block break-all font-mono text-[11px] text-slate-200">
                          {cmds.unix}
                        </code>
                      </div>
                    </div>
                  );
                })()}
              </div>
            )}
          </div>
        )}

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
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-xs text-slate-300">
                  Indicator: {lookupResult.normalizedQuery.replace(/\./g, '[.]')}
                </span>
                <button
                  type="button"
                  onClick={() => handleCopyPermalink(lookupResult.query)}
                  className="inline-flex items-center gap-1 rounded border border-slate-700 bg-[#0b0f17] px-2 py-1 font-mono text-[11px] text-slate-200 transition hover:border-slate-500 cursor-pointer"
                >
                  {copiedId === 'permalink' ? (
                    <>
                      <Check className="h-3 w-3 text-sky-400" /> Copied link
                    </>
                  ) : (
                    <>
                      <Link2 className="h-3 w-3" /> Copy verdict link
                    </>
                  )}
                </button>
              </div>
            </div>

            {normalizationInfo?.wasTransformed && (
              <p className="mt-2 font-mono text-[11px] text-slate-300">
                Normalized input →{' '}
                <code className="rounded bg-[#0b0f17] px-1.5 py-0.5 text-sky-300">
                  {normalizationInfo.normalized}
                </code>
              </p>
            )}

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
              placement="verdict"
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
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-xs text-slate-300">
                  Domain: {lookupResult.normalizedQuery}
                </span>
                <button
                  type="button"
                  onClick={() => handleCopyPermalink(lookupResult.query)}
                  className="inline-flex items-center gap-1 rounded border border-slate-700 bg-[#0b0f17] px-2 py-1 font-mono text-[11px] text-slate-200 transition hover:border-slate-500 cursor-pointer"
                >
                  {copiedId === 'permalink' ? (
                    <>
                      <Check className="h-3 w-3 text-sky-400" /> Copied link
                    </>
                  ) : (
                    <>
                      <Link2 className="h-3 w-3" /> Copy verdict link
                    </>
                  )}
                </button>
              </div>
            </div>

            {normalizationInfo?.wasTransformed && (
              <p className="mt-2 font-mono text-[11px] text-slate-300">
                Normalized input →{' '}
                <code className="rounded bg-[#0b0f17] px-1.5 py-0.5 text-sky-300">
                  {normalizationInfo.normalized}
                </code>
              </p>
            )}

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
              <div className="flex flex-wrap items-center gap-2">
                {lookupResult.normalizedQuery && (
                  <span className="font-mono text-xs text-slate-400">
                    Checked: {lookupResult.normalizedQuery.replace(/\./g, '[.]')}
                  </span>
                )}
                <button
                  type="button"
                  onClick={() => handleCopyPermalink(lookupResult.query)}
                  className="inline-flex items-center gap-1 rounded border border-slate-700 bg-[#111827] px-2 py-1 font-mono text-[11px] text-slate-200 transition hover:border-slate-500 cursor-pointer"
                >
                  {copiedId === 'permalink' ? (
                    <>
                      <Check className="h-3 w-3 text-sky-400" /> Copied link
                    </>
                  ) : (
                    <>
                      <Link2 className="h-3 w-3" /> Copy verdict link
                    </>
                  )}
                </button>
              </div>
            </div>

            {normalizationInfo?.wasTransformed && (
              <p className="mt-2 font-mono text-[11px] text-slate-300">
                Normalized input →{' '}
                <code className="rounded bg-[#111827] px-1.5 py-0.5 text-sky-300">
                  {normalizationInfo.normalized}
                </code>
              </p>
            )}

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
                placement="verdict"
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

      {/* Compact Page Navigation Cards */}
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
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
          onClick={() => onNavigate('exports')}
          className="flex flex-col justify-between rounded-xl border border-slate-800 bg-[#111827] p-4 text-left transition hover:border-slate-600 cursor-pointer"
        >
          <div>
            <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
              <Database className="h-3.5 w-3.5 text-slate-300" />
              <span>OPEN DATA</span>
            </div>
            <p className="mt-1.5 text-sm font-semibold text-slate-100">
              Pi-hole Blocklist, CSV, JSON &amp; PowerShell Check
            </p>
          </div>
          <span className="mt-3 inline-flex items-center gap-1 font-mono text-xs text-sky-400">
            Open IOC exports <ArrowRight className="h-3 w-3" />
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
        placement="homepage"
        heading="Recommended Protection Stack"
        subheading="Rotate compromised logins and active sessions, block lookalike scam domains, and scan suspicious downloads."
      />
    </section>
  );
}
