import { useMemo, useState } from 'react';
import { Check, Copy, Download, ExternalLink, FileCode2, FileSpreadsheet, FileText, Terminal } from 'lucide-react';
import type { ThreatsData } from '../types/data';
import {
  buildDomainBlocklistTxt,
  buildIocCsv,
  buildReadOnlyPowerShellCheck,
  buildThreatsExportJson,
  extractMaliciousDomains,
} from '../utils/iocExports';

interface OpenIntelExportsProps {
  threatsData: ThreatsData;
}

function triggerDownload(filename: string, content: string, mimeType: string) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function OpenIntelExports({ threatsData }: OpenIntelExportsProps) {
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const maliciousDomains = useMemo(
    () => extractMaliciousDomains(threatsData.threats),
    [threatsData.threats],
  );
  const blocklistTxt = useMemo(
    () => buildDomainBlocklistTxt(threatsData.threats, threatsData.meta),
    [threatsData],
  );
  const iocCsv = useMemo(
    () => buildIocCsv(threatsData.threats),
    [threatsData.threats],
  );
  const rawJson = useMemo(() => buildThreatsExportJson(threatsData), [threatsData]);
  const psSnippet = useMemo(() => buildReadOnlyPowerShellCheck(), []);

  const handleCopy = async (id: string, text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedId(id);
      setTimeout(() => setCopiedId((prev) => (prev === id ? null : prev)), 2200);
    } catch {
      // Clipboard may be restricted; fail gracefully.
    }
  };

  return (
    <section aria-label="Open Threat-Intel Exports" className="space-y-5">
      <div className="rounded-xl border border-slate-800 bg-[#111827] p-5 sm:p-7">
        <p className="font-mono text-xs uppercase tracking-wider text-slate-400">
          Open Threat Data · Client-Side Generation
        </p>
        <h1 className="mt-1 text-xl font-bold text-slate-50 sm:text-2xl">
          Open IOC Exports &amp; Read-Only Diagnostics
        </h1>
        <p className="mt-2 max-w-3xl text-sm leading-relaxed text-slate-300">
          All exports below are generated 100% in your browser directly from{' '}
          <a
            href="/data/threats.json"
            target="_blank"
            rel="noopener noreferrer"
            className="font-mono text-sky-400 underline hover:text-sky-300"
          >
            /data/threats.json
          </a>
          . No benign or vendor reference domains are included in the DNS blocklist.
        </p>

        {/* Export Cards */}
        <div className="mt-6 grid gap-4 md:grid-cols-3">
          {/* 1. Domain Blocklist */}
          <div className="flex flex-col justify-between rounded-lg border border-slate-800 bg-[#0b0f17] p-4">
            <div>
              <div className="flex items-center gap-2 font-mono text-xs text-sky-400">
                <FileText className="h-4 w-4" />
                <span>PI-HOLE / ADGUARD / HOSTS</span>
              </div>
              <h2 className="mt-2 text-sm font-bold text-slate-100">
                Confirmed Domain Blocklist (.txt)
              </h2>
              <p className="mt-1 text-xs leading-relaxed text-slate-400">
                {maliciousDomains.length} deduplicated malicious domains formatted as{' '}
                <code className="text-slate-300">0.0.0.0 domain</code>.
              </p>
            </div>
            <div className="mt-4 flex flex-wrap gap-2">
              <button
                type="button"
                onClick={() =>
                  triggerDownload(
                    'portscamwatch-domains.txt',
                    blocklistTxt,
                    'text/plain;charset=utf-8',
                  )
                }
                className="inline-flex items-center gap-1.5 rounded-md border border-slate-700 bg-[#111827] px-3 py-1.5 font-mono text-xs font-semibold text-slate-100 transition hover:border-sky-500/60 cursor-pointer"
              >
                <Download className="h-3.5 w-3.5 text-sky-400" />
                Download .txt
              </button>
              <button
                type="button"
                onClick={() => handleCopy('txt', blocklistTxt)}
                className="inline-flex items-center gap-1.5 rounded-md border border-slate-800 bg-[#111827] px-3 py-1.5 font-mono text-xs text-slate-300 transition hover:border-slate-600 cursor-pointer"
              >
                {copiedId === 'txt' ? (
                  <>
                    <Check className="h-3.5 w-3.5 text-sky-400" /> Copied
                  </>
                ) : (
                  <>
                    <Copy className="h-3.5 w-3.5" /> Copy
                  </>
                )}
              </button>
            </div>
          </div>

          {/* 2. Structured IOCs CSV */}
          <div className="flex flex-col justify-between rounded-lg border border-slate-800 bg-[#0b0f17] p-4">
            <div>
              <div className="flex items-center gap-2 font-mono text-xs text-sky-400">
                <FileSpreadsheet className="h-4 w-4" />
                <span>RFC-4180 CSV</span>
              </div>
              <h2 className="mt-2 text-sm font-bold text-slate-100">
                Structured IOC Feed (.csv)
              </h2>
              <p className="mt-1 text-xs leading-relaxed text-slate-400">
                All normalized domains, filenames, packages &amp; SHA-256 hashes with campaign and
                vendor source URLs.
              </p>
            </div>
            <div className="mt-4 flex flex-wrap gap-2">
              <button
                type="button"
                onClick={() =>
                  triggerDownload('portscamwatch-iocs.csv', iocCsv, 'text/csv;charset=utf-8')
                }
                className="inline-flex items-center gap-1.5 rounded-md border border-slate-700 bg-[#111827] px-3 py-1.5 font-mono text-xs font-semibold text-slate-100 transition hover:border-sky-500/60 cursor-pointer"
              >
                <Download className="h-3.5 w-3.5 text-sky-400" />
                Download .csv
              </button>
              <button
                type="button"
                onClick={() => handleCopy('csv', iocCsv)}
                className="inline-flex items-center gap-1.5 rounded-md border border-slate-800 bg-[#111827] px-3 py-1.5 font-mono text-xs text-slate-300 transition hover:border-slate-600 cursor-pointer"
              >
                {copiedId === 'csv' ? (
                  <>
                    <Check className="h-3.5 w-3.5 text-sky-400" /> Copied
                  </>
                ) : (
                  <>
                    <Copy className="h-3.5 w-3.5" /> Copy
                  </>
                )}
              </button>
            </div>
          </div>

          {/* 3. Raw JSON */}
          <div className="flex flex-col justify-between rounded-lg border border-slate-800 bg-[#0b0f17] p-4">
            <div>
              <div className="flex items-center gap-2 font-mono text-xs text-sky-400">
                <FileCode2 className="h-4 w-4" />
                <span>STATIC DATASET</span>
              </div>
              <h2 className="mt-2 text-sm font-bold text-slate-100">
                Raw Advisory JSON (.json)
              </h2>
              <p className="mt-1 text-xs leading-relaxed text-slate-400">
                Full validated dataset ({threatsData.threats.length} vendor-cited advisories) as
                served to the static app.
              </p>
            </div>
            <div className="mt-4 flex flex-wrap gap-2">
              <button
                type="button"
                onClick={() =>
                  triggerDownload(
                    'portscamwatch-threats.json',
                    rawJson,
                    'application/json;charset=utf-8',
                  )
                }
                className="inline-flex items-center gap-1.5 rounded-md border border-slate-700 bg-[#111827] px-3 py-1.5 font-mono text-xs font-semibold text-slate-100 transition hover:border-sky-500/60 cursor-pointer"
              >
                <Download className="h-3.5 w-3.5 text-sky-400" />
                Download .json
              </button>
              <a
                href="/data/threats.json"
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1.5 rounded-md border border-slate-800 bg-[#111827] px-3 py-1.5 font-mono text-xs text-slate-300 transition hover:border-slate-600"
              >
                Inspect <ExternalLink className="h-3 w-3" />
              </a>
            </div>
          </div>
        </div>

        {/* Auditable Read-Only Local Check (PowerShell) */}
        <div className="mt-6 rounded-xl border border-slate-800 bg-[#0b0f17] p-4 sm:p-5">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <Terminal className="h-4 w-4 text-sky-400" />
              <h2 className="text-sm font-bold text-slate-100 sm:text-base">
                Auditable Read-Only Local Check (Windows PowerShell)
              </h2>
            </div>

            <button
              type="button"
              onClick={() => handleCopy('ps', psSnippet)}
              className="inline-flex items-center gap-1.5 rounded-md border border-slate-700 bg-[#111827] px-3 py-1.5 font-mono text-xs font-semibold text-slate-100 transition hover:border-sky-500/60 cursor-pointer"
            >
              {copiedId === 'ps' ? (
                <>
                  <Check className="h-3.5 w-3.5 text-sky-400" /> Copied Snippet
                </>
              ) : (
                <>
                  <Copy className="h-3.5 w-3.5" /> Copy PowerShell Check
                </>
              )}
            </button>
          </div>

          <p className="mt-1.5 text-xs leading-relaxed text-slate-400">
            Strictly read-only (<code className="text-slate-300">Test-Path</code> and{' '}
            <code className="text-slate-300">Get-ItemProperty</code> only—zero file writes, zero
            downloads, zero deletions). Inspect every line before running locally.
          </p>

          <pre className="mt-3 max-w-full overflow-x-auto rounded-lg border border-slate-800 bg-[#111827] p-3.5 font-mono text-xs leading-relaxed text-slate-200">
            <code>{psSnippet}</code>
          </pre>
        </div>
      </div>
    </section>
  );
}
